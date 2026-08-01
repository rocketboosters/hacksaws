"""Offline behavior coverage for policy, AWS configuration, and ECR leaf modules."""

from __future__ import annotations

import argparse
import base64
import configparser
import io
import json
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from functools import partial
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

import hacksaws
from hacksaws import _aws
from hacksaws import _cli
from hacksaws import _configs
from hacksaws import _duration
from hacksaws import _ecr
from hacksaws import _policies
from hacksaws import _state

ACCOUNT = "123456789012"
DOCUMENT = {"Version": "2012-10-17", "Statement": []}


def policy_file(path: Path, suffix: str = ".json", contents: str | None = None) -> Path:
    path = path.with_suffix(suffix)
    path.write_text(contents or json.dumps(DOCUMENT), encoding="utf-8")
    return path


def context(directory: Path, *, podman: bool = False) -> _configs.Context:
    return _configs.Context(
        argparse.Namespace(
            profile="dev",
            directory=str(directory),
            aws_account_name=None,
            podman=podman,
            lifespan=900,
            mfa_code="123456",
            ecr_region=None,
        )
    )


def write_ini(path: Path, sections: dict[str, dict[str, str]]) -> None:
    parser = configparser.ConfigParser()
    parser.read_dict(sections)
    with path.open("w", encoding="utf-8") as stream:
        parser.write(stream)


def record_engine_call(
    calls: list[list[str]], _engine: str, command: list[str], **_kwargs: object
) -> None:
    calls.append(command)


@pytest.mark.parametrize(
    ("raw", "kind", "message"),
    [
        (b"{bad", "json", "Invalid JSON"),
        (b"[broken", "yaml", "Invalid YAML"),
        (b"Version =", "toml", "Invalid TOML"),
        (b"[]", "json", "must be an object"),
        (b'{"Version":"1"}', "json", "requires Version"),
        (b'{"Version":"1","Statement":"no"}', "json", "Statement"),
    ],
)
def test_policy_parsing_reports_format_and_schema_failures(
    raw: bytes, kind: str, message: str
) -> None:
    with pytest.raises(_configs.OperationalError, match=message):
        _policies.parse_policy_bytes(raw, kind=kind, source="inline")
    with pytest.raises(_configs.OperationalError, match="Unsupported"):
        _policies.parse_policy_bytes(b"{}", kind="ini", source="inline")
    with pytest.raises(_configs.OperationalError, match="UTF-8"):
        _policies.parse_policy_bytes(b"\xff", kind="json", source="inline")


def test_stored_policy_crud_rename_and_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    source = policy_file(tmp_path / "read")
    changed = policy_file(
        tmp_path / "changed", ".toml", 'Version = "2012-10-17"\nStatement = []'
    )
    _policies.add_stored("Read", source, "initial")
    _policies.update_stored("read", changed, "changed")
    data = _state.load_config()
    assert data["policies"]["Read"]["description"] == "changed"
    assert (
        _policies.parse_policy(_policies.stored_directory() / "Read.yaml")[0]
        == DOCUMENT
    )

    def rename_in_memory(
        data: dict[str, object], kind: str, old: str, new: str
    ) -> None:
        policies = data["policies"]
        assert kind == "policy"
        assert isinstance(policies, dict)
        policies[new] = policies.pop(old)

    with patch(
        "hacksaws._policies._state.rename_resource", side_effect=rename_in_memory
    ):
        _policies.rename_stored("Read", "Renamed")
    assert (_policies.stored_directory() / "Renamed.yaml").exists()
    _policies.remove_stored("renamed")
    assert not (_policies.stored_directory() / "Renamed.yaml").exists()

    _policies.add_stored("One", source)
    with (
        patch(
            "hacksaws._policies._state.rename_resource", side_effect=rename_in_memory
        ),
        patch(
            "hacksaws._policies._state.save_config", side_effect=OSError("disk full")
        ),
        pytest.raises(OSError, match="disk full"),
    ):
        _policies.rename_stored("One", "Two")
    assert (_policies.stored_directory() / "One.yaml").exists()
    assert "One" in _state.load_config()["policies"]


def test_policy_resolution_local_stored_and_explicit_arns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    source = policy_file(tmp_path / "local")
    local = _policies.resolve(str(source), account_id=ACCOUNT, partition="aws")
    assert local.origin == "local"
    assert local.document == _policies.minify(DOCUMENT)
    _policies.add_stored("Read", source)
    stored = _policies.resolve("read", account_id=ACCOUNT, partition="aws")
    assert stored.origin == "stored"
    assert stored.identity == "Read"
    arn = f"arn:aws:iam::{ACCOUNT}:policy/Read"
    assert _policies.resolve(arn, account_id=ACCOUNT, partition="aws").arn == arn
    with pytest.raises(_configs.OperationalError, match="target role account"):
        _policies.resolve(
            "arn:aws:iam::999999999999:policy/X", account_id=ACCOUNT, partition="aws"
        )
    with pytest.raises(_configs.OperationalError, match="does not exist"):
        _policies.resolve(
            str(tmp_path / "missing.json"), account_id=ACCOUNT, partition="aws"
        )
    with pytest.raises(_configs.OperationalError, match="2048"):
        _policies.enforce_inline_limit("x" * 2049)


def test_policy_cache_fresh_expired_corrupt_and_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    _policies.cache_write(
        "fresh", DOCUMENT, origin="local", resolver="file", source_identity="x"
    )
    assert _policies.cache_read("fresh", 60) is not None
    assert _policies.cache_read("fresh", 0) is None
    path = _policies._cache_path("fresh")
    record = json.loads(path.read_text())
    record["fetched_at"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    path.write_text(json.dumps(record), encoding="utf-8")
    assert _policies.cache_read("fresh", 1) is None
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="Invalid policy cache"):
        _policies.cache_read("fresh", 10)


def test_policy_storage_cleanup_and_read_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    source = policy_file(
        tmp_path / "source", ".yaml", "Version: '2012-10-17'\nStatement: []\n"
    )
    with (
        patch("hacksaws._policies._state.save_config", side_effect=OSError("full")),
        pytest.raises(OSError, match="full"),
    ):
        _policies.add_stored("Temporary", source)
    assert not (_policies.stored_directory() / "Temporary.yaml").exists()
    with (
        patch.object(Path, "read_bytes", side_effect=OSError("denied")),
        pytest.raises(_configs.OperationalError, match="Unable to read"),
    ):
        _policies.parse_policy(source)


def test_remote_resolution_name_collisions_fetch_and_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    session = MagicMock()
    sts = MagicMock()
    sts.get_caller_identity.return_value = {
        "Account": ACCOUNT,
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/me",
    }
    iam = MagicMock()
    session.client.side_effect = lambda service: {"sts": sts, "iam": iam}[service]
    local = {
        "PolicyName": "Same",
        "Arn": f"arn:aws:iam::{ACCOUNT}:policy/Same",
        "DefaultVersionId": "v1",
    }
    aws = {
        "PolicyName": "Same",
        "Arn": "arn:aws:iam::aws:policy/Same",
        "DefaultVersionId": "v1",
    }
    local_paginator = MagicMock()
    aws_paginator = MagicMock()
    local_paginator.paginate.return_value = [{"Policies": [local]}]
    aws_paginator.paginate.return_value = [{"Policies": [aws]}]
    iam.get_paginator.side_effect = [local_paginator, aws_paginator]
    with pytest.raises(_configs.OperationalError, match="ambiguous"):
        _policies.resolve("Same", account_id=ACCOUNT, partition="aws", session=session)

    iam.get_paginator.side_effect = [local_paginator, MagicMock()]
    iam.get_paginator.return_value.paginate.return_value = [{"Policies": []}]
    iam.get_policy_version.return_value = {"PolicyVersion": {"Document": DOCUMENT}}
    resolved = _policies.resolve(
        "Same", account_id=ACCOUNT, partition="aws", session=session
    )
    assert resolved.arn == local["Arn"]
    assert resolved.origin == "remote-customer"
    cached = _policies.resolve(
        "Same", account_id=ACCOUNT, partition="aws", session=session
    )
    assert cached.cached
    assert cached.arn == local["Arn"]


def test_remote_policy_account_and_list_failure_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    session = MagicMock()
    sts = MagicMock()
    sts.get_caller_identity.return_value = {
        "Account": "999999999999",
        "Arn": "arn:aws-us-gov:iam::999999999999:user/me",
    }
    session.client.return_value = sts
    with pytest.raises(_configs.OperationalError, match="authenticated resolver"):
        _policies.resolve("X", account_id=ACCOUNT, partition="aws", session=session)

    sts.get_caller_identity.return_value = {
        "Account": ACCOUNT,
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/me",
    }
    iam = MagicMock()
    iam.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "Denied", "Message": "no"}}, "ListPolicies"
    )
    session.client.side_effect = lambda service: {"sts": sts, "iam": iam}[service]
    result = _policies.resolve(
        "X", account_id=ACCOUNT, partition="aws", session=session
    )
    assert result.arn == f"arn:aws:iam::{ACCOUNT}:policy/X"

    iam.get_paginator.side_effect = None
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Policies": []}]
    iam.get_paginator.return_value = paginator
    with pytest.raises(_configs.OperationalError, match="does not exist"):
        _policies.resolve(
            "Absent", account_id=ACCOUNT, partition="aws", session=session
        )
    sts.get_caller_identity.side_effect = ClientError(
        {"Error": {"Code": "Bad", "Message": "no"}}, "GetCallerIdentity"
    )
    with pytest.raises(_configs.OperationalError, match="Unable to verify"):
        _policies.resolve(
            "Absent", account_id=ACCOUNT, partition="aws", max_age=0, session=session
        )


def test_aws_managed_fetch_handles_cached_and_service_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    client = MagicMock()
    client.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    client.get_policy_version.return_value = {
        "PolicyVersion": {"Document": json.dumps(DOCUMENT)}
    }
    session = MagicMock()
    session.client.return_value = client
    first = _policies.resolve(
        arn, account_id=ACCOUNT, partition="aws", max_age=60, session=session
    )
    assert first.origin == "aws-managed"
    assert not first.cached
    second = _policies.resolve(
        arn, account_id=ACCOUNT, partition="aws", max_age=60, session=session
    )
    assert second.cached
    client.get_policy.side_effect = ClientError(
        {"Error": {"Code": "No", "Message": "bad"}}, "GetPolicy"
    )
    with pytest.raises(_configs.OperationalError, match="Unable to fetch"):
        _policies.resolve(
            arn, account_id=ACCOUNT, partition="aws", max_age=0, session=session
        )


def test_remote_aws_name_and_customer_inspection_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    session = MagicMock()
    sts = MagicMock()
    sts.get_caller_identity.return_value = {
        "Account": ACCOUNT,
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/me",
    }
    iam = MagicMock()
    session.client.side_effect = lambda service: {"sts": sts, "iam": iam}[service]
    customer = {
        "PolicyName": "Customer",
        "Arn": f"arn:aws:iam::{ACCOUNT}:policy/Customer",
        "DefaultVersionId": "v1",
    }
    local_pages = MagicMock()
    local_pages.paginate.return_value = [{"Policies": [customer]}]
    aws_pages = MagicMock()
    aws_pages.paginate.return_value = [{"Policies": []}]
    iam.get_paginator.side_effect = [local_pages, aws_pages]
    iam.get_policy_version.side_effect = ClientError(
        {"Error": {"Code": "Bad", "Message": "no"}}, "GetPolicyVersion"
    )
    with pytest.raises(_configs.OperationalError, match="Unable to inspect"):
        _policies.resolve(
            "Customer", account_id=ACCOUNT, partition="aws", session=session
        )

    aws_item = {
        "PolicyName": "Aws",
        "Arn": "arn:aws:iam::aws:policy/Aws",
        "DefaultVersionId": "v1",
    }
    local_pages.paginate.return_value = [{"Policies": []}]
    aws_pages.paginate.return_value = [{"Policies": [aws_item]}]
    iam.get_paginator.side_effect = [local_pages, aws_pages]
    iam.get_policy.side_effect = None
    iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    iam.get_policy_version.side_effect = None
    iam.get_policy_version.return_value = {"PolicyVersion": {"Document": DOCUMENT}}
    assert (
        _policies.resolve(
            "Aws", account_id=ACCOUNT, partition="aws", session=session
        ).origin
        == "aws-managed"
    )


@pytest.mark.parametrize(
    ("value", "expected"), [(".5m", 30), ("1hr", 3600), ("1.5s", 2)]
)
def test_duration_aliases_rounding_and_errors(value: str, expected: int) -> None:
    assert _duration.parse_duration(value) == expected
    assert _duration.parse_count("1.5", 60) == 90
    assert _duration.session_duration(htl="1") == 3600
    assert _duration.session_duration(mtl="1") == 60
    assert _duration.session_duration(stl="2") == 2
    assert _duration.session_duration(default=42) == 42
    with pytest.raises(_configs.OperationalError):
        _duration.parse_duration("1fortnight")
    with pytest.raises(_configs.OperationalError):
        _duration.parse_count("NaN", 1)
    with pytest.raises(_configs.OperationalError):
        _duration.parse_count("not-a-number", 1)
    with pytest.raises(_configs.OperationalError, match="Only one"):
        _duration.session_duration(duration="1h", mtl="1")


def test_context_account_and_result_leaf_behavior(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    args = argparse.Namespace(
        profile=None, directory="~/custom", aws_account_name=None, podman=True
    )
    ctx = _configs.Context(args)
    assert ctx.profile == "default"
    assert ctx.container_engine == "podman"
    assert ctx.aws_directory == Path("~/custom").expanduser().absolute()
    account = _configs.AwsAccount(
        {"Account": ACCOUNT, "Arn": f"arn:aws-cn:iam::{ACCOUNT}:root"},
        "cn-north-1",
        ("cn-north-1", "cn-northwest-1"),
    )
    assert account.ecr_registries == [
        f"{ACCOUNT}.dkr.ecr.cn-north-1.amazonaws.com.cn",
        f"{ACCOUNT}.dkr.ecr.cn-northwest-1.amazonaws.com.cn",
    ]
    assert _configs.AwsAccount({}, "us-east-1", ()).partition == "aws"
    with pytest.raises(_configs.OperationalError, match="account ID"):
        _ = _configs.AwsAccount({}, "us-east-1", ()).id
    assert _configs.Result("X", "hello", stream="stderr").echo().code == "X"
    assert capsys.readouterr().err == "hello\n"


def test_aws_login_logout_and_configuration_errors(tmp_path: Path) -> None:
    aws_dir = tmp_path / "aws"
    aws_dir.mkdir()
    ctx = context(aws_dir)
    write_ini(aws_dir / "config", {"profile dev": {"mfa_serial": "serial"}})
    write_ini(
        aws_dir / "credentials",
        {"dev": {"aws_access_key_id": "old", "aws_secret_access_key": "secret"}},
    )
    session = MagicMock()
    session.client.return_value.get_session_token.return_value = {
        "Credentials": {
            "AccessKeyId": "new",
            "SecretAccessKey": "newsecret",
            "SessionToken": "token",
        }
    }
    with patch("hacksaws._aws.boto3.Session", return_value=session):
        _aws.login(ctx)
    assert ctx.storage_path.exists()
    _aws.logout(ctx)
    restored = configparser.ConfigParser()
    restored.read(ctx.credentials_path)
    assert restored["dev"]["aws_access_key_id"] == "old"
    with pytest.raises(_configs.OperationalError, match="does not exist"):
        _aws._read_config(tmp_path / "none", description="credentials")
    write_ini(aws_dir / "config", {"profile dev": {}})
    with pytest.raises(_configs.OperationalError, match="mfa_serial"):
        _aws.login(ctx)


def test_ecr_engine_login_errors_and_partitioned_logout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path)
    account = _configs.AwsAccount(
        {"Account": ACCOUNT, "Arn": f"arn:aws-cn:iam::{ACCOUNT}:root"},
        "cn-north-1",
        ("cn-northwest-1",),
    )
    token = base64.b64encode(b"AWS:password").decode()
    session = MagicMock()
    session.client.return_value.get_authorization_token.return_value = {
        "authorizationData": [
            {
                "authorizationToken": token,
                "expiresAt": datetime.now(UTC) + timedelta(hours=12),
            }
        ]
    }
    calls: list[list[str]] = []
    real_run_engine = _ecr._run_container_engine
    monkeypatch.setattr(
        _ecr,
        "_run_container_engine",
        partial(record_engine_call, calls),
    )
    logged = _ecr.login_with_session(ctx, account, session)
    assert logged == account.ecr_registries
    assert all("amazonaws.com.cn" in item[-1] for item in calls)
    _ecr.logout(ctx, account)
    assert calls[-1][:2] == ["docker", "logout"]
    with (
        patch("hacksaws._ecr.subprocess.run", side_effect=FileNotFoundError),
        pytest.raises(_configs.OperationalError, match="not installed"),
    ):
        real_run_engine("podman", ["podman", "login"])
    session.client.return_value.get_authorization_token.return_value = {
        "authorizationData": [
            {"authorizationToken": "%%", "expiresAt": datetime.now(UTC)}
        ]
    }
    with pytest.raises(_configs.OperationalError, match="invalid ECR token"):
        _ecr._do_login(
            ctx, account_id=ACCOUNT, region_name="us-east-1", session=session
        )


def test_cli_operational_error_stdin_helper_and_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    args = argparse.Namespace(file="-", format="json")
    fake_stdin = MagicMock()
    fake_stdin.buffer = io.BytesIO(json.dumps(DOCUMENT).encode())
    with patch("hacksaws._cli.sys.stdin", fake_stdin):
        path = _cli._stdin_policy(args)
    assert _policies.parse_policy(path)[0] == DOCUMENT
    with pytest.raises(_configs.OperationalError, match="requires --format"):
        _cli._stdin_policy(argparse.Namespace(file="-", format=None))
    with patch(
        "hacksaws._cli._sessions.recover_journal",
        side_effect=_configs.OperationalError("broken"),
    ):
        assert _cli.console_main(["status"]).exit_code == 1
    with patch("hacksaws.console_main", return_value=_configs.Result("OK", "", 7)):
        assert hacksaws.main() == 7
