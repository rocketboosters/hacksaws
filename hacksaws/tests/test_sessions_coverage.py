"""Behavioral coverage for transactional session security workflows."""

from __future__ import annotations

import argparse
import configparser
import json
import os
import subprocess
import tomllib
import zipfile
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from hacksaws import _configs
from hacksaws import _policies
from hacksaws import _sessions
from hacksaws import _state

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/Guard"
POLICY = b'Version: "2012-10-17"\nStatement: []\n'
RESTORE_ERROR = "restore warning"
INJECTED_ERROR = "injected after config write"


def _args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "target": None,
        "directory": ".",
        "profile": "default",
        "aws_account_name": None,
        "to": None,
        "to_directory": None,
        "to_profile": "default",
        "boundary": None,
        "role": None,
        "policy": None,
        "external_id": None,
        "account": None,
        "session_name": None,
        "region": None,
        "duration": None,
        "htl": None,
        "mtl": None,
        "stl": None,
        "mfa_code": "123456",
        "lifespan": 3600,
        "ecr": False,
        "ecr_region": None,
        "podman": False,
        "remote": False,
        "probe": False,
        "yes": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "state"
    monkeypatch.setenv("HACKSAWS_HOME", str(root))
    _state.save_config(_state.default_config())
    return root


def _configured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    boundary: bool = True,
) -> tuple[Path, dict[str, object]]:
    root = _home(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    data = _state.default_config()
    data["accounts"]["Prod"] = {"id": ACCOUNT, "partition": "aws"}
    if boundary:
        data["boundaries"]["Guard"] = {
            "role_arn": ROLE,
            "account": "Prod",
            "duration": 3600,
            "verified": False,
        }
    data["targets"]["Prod"] = {
        "source_account": "Prod",
        "source_profile": "dev",
        "source_directory": str(aws),
        "destination_directory": str(aws),
        "destination_profile": "out",
        **({"boundary": "Guard"} if boundary else {}),
    }
    _state.save_config(data)
    return root, data


def _credentials(*, expiration: datetime | None = None) -> dict[str, object]:
    return {
        "AccessKeyId": "ASIAFINAL",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": expiration or datetime.now(UTC) + timedelta(hours=1),
    }


def _identity(account: str = ACCOUNT, partition: str = "aws") -> dict[str, str]:
    return {
        "Account": account,
        "Arn": f"arn:{partition}:iam::{account}:user/test",
    }


def _write_source(aws: Path) -> None:
    aws.mkdir(parents=True, exist_ok=True)
    (aws / "credentials").write_text(
        "[dev]\naws_access_key_id = AKIAORIGINAL\n"
        "aws_secret_access_key = original-secret\n",
        encoding="utf-8",
    )
    (aws / "config").write_text(
        f"[profile dev]\nregion = us-west-2\noutput = json\n"
        f"mfa_serial = arn:aws:iam::{ACCOUNT}:mfa/dev\n",
        encoding="utf-8",
    )


def _archive(path: Path, config: dict[str, object], files: dict[str, bytes]) -> Path:
    config_bytes = (json.dumps(config, indent=2) + "\n").encode()
    payloads = {"config.json": config_bytes, **files}
    manifest = {
        "schema_version": 1,
        "files": {name: _state.digest(content) for name, content in payloads.items()},
    }
    with zipfile.ZipFile(path, "w") as output:
        for name, content in payloads.items():
            output.writestr(name, content)
        output.writestr("manifest.json", json.dumps(manifest))
    return path


def test_journal_commit_and_crash_recovery_restore_files_and_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    original = tmp_path / "credentials"
    created = tmp_path / "config"
    cache = tmp_path / "cache"
    old_cache = cache / "old.json"
    preexisting_directory = cache / "keep" / "empty"
    original.write_bytes(b"original")
    preexisting_directory.mkdir(parents=True)
    old_cache.write_bytes(b"cached")

    journal = _sessions._begin([original, created], cache_roots=[cache])
    assert _sessions._journal_path().exists()
    original.write_bytes(b"changed")
    created.write_bytes(b"new")
    old_cache.write_bytes(b"changed-cache")
    (cache / "new.json").write_bytes(b"new-cache")
    nested_cache = cache / "created" / "nested" / "new.json"
    nested_cache.parent.mkdir(parents=True)
    nested_cache.write_bytes(b"nested-cache")

    _sessions.recover_journal()
    assert original.read_bytes() == b"original"
    assert not created.exists()
    assert old_cache.read_bytes() == b"cached"
    assert not (cache / "new.json").exists()
    assert not (cache / "created").exists()
    assert preexisting_directory.is_dir()
    assert not _sessions._journal_path().exists()

    _sessions._begin([])
    _sessions._commit()
    assert not _sessions._journal_path().exists()
    assert journal["safe_to_rollback"] is True


def test_cache_rollback_removes_an_entire_new_nested_cache_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    cache = tmp_path / "absent-before"
    assert not cache.exists()
    journal = _sessions._begin([], cache_roots=[cache])
    token = cache / "provider" / "nested" / "token.json"
    token.parent.mkdir(parents=True)
    token.write_text("broad", encoding="utf-8")
    _sessions._rollback(journal)
    assert not cache.exists()
    assert not _sessions._journal_path().exists()


def test_recovery_rejects_corrupt_or_unsafe_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _home(tmp_path, monkeypatch)
    journal = root / "transaction.json"
    journal.write_text("not-json", encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="unreadable"):
        _sessions.recover_journal()
    journal.write_text(json.dumps({"safe_to_rollback": False, "files": []}))
    with pytest.raises(_configs.OperationalError, match="unsafe"):
        _sessions.recover_journal()


def test_rollback_reports_ecr_cache_and_file_cleanup_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    path = tmp_path / "credential"
    path.write_bytes(b"before")
    journal = _sessions._begin([path])
    journal.update(ecr_engine="docker", ecr_created=["one", "two"])
    path.write_bytes(b"after")
    real_restore = _sessions._restore

    def fail_file(snapshot: dict[str, object]) -> None:
        real_restore(snapshot)
        raise OSError(RESTORE_ERROR)

    with (
        patch(
            "hacksaws._ecr._run_container_engine",
            side_effect=_configs.OperationalError("logout warning"),
        ) as engine,
        patch("hacksaws._sessions._restore", side_effect=fail_file),
        pytest.raises(
            _configs.OperationalError, match=r"automatic recovery.*incomplete"
        ),
    ):
        _sessions._rollback(journal)
    assert engine.call_args_list[0].args[1][-1] == "two"
    assert path.read_bytes() == b"before"
    assert _sessions._journal_path().exists()


def test_ini_snapshot_and_parser_errors_are_operational(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    path = tmp_path / "config"
    path.write_text("[broken", encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="Unable to parse AWS file"):
        _sessions._read_ini(path)
    with pytest.raises(_configs.OperationalError, match="original AWS file"):
        _sessions._parser_from_bytes(b"\xff", path)
    assert _sessions._section("default", config=True) == "default"
    assert _sessions._section("dev", config=True) == "profile dev"


@pytest.mark.parametrize("arn", ["nope", "arn:moon:iam::123:user/x"])
def test_identity_rejects_invalid_arn_partition(arn: str) -> None:
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": ACCOUNT, "Arn": arn}
    session = MagicMock()
    session.client.return_value = sts
    with pytest.raises(_configs.OperationalError, match="invalid ARN"):
        _sessions._identity(session, label="source")


def test_identity_rejects_client_and_account_errors() -> None:
    session = MagicMock()
    session.client.side_effect = ClientError(
        {"Error": {"Code": "Denied", "Message": "no"}}, "GetCallerIdentity"
    )
    with pytest.raises(_configs.OperationalError, match="Unable to verify"):
        _sessions._identity(session, label="source")
    session.client.side_effect = None
    session.client.return_value.get_caller_identity.return_value = {
        "Account": "12",
        "Arn": "arn:aws:iam::12:user/x",
    }
    with pytest.raises(_configs.OperationalError, match="invalid account"):
        _sessions._identity(session, label="source")


def test_path_resolution_supports_presets_locations_and_raw_destinations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configured(tmp_path, monkeypatch, boundary=False)
    source, profile, destination, out_profile = _sessions._paths(_args(target="+prod"))
    assert (source, profile, destination, out_profile) == (
        tmp_path / "aws",
        "dev",
        tmp_path / "aws",
        "out",
    )
    with patch(
        "hacksaws._state.aws_directory", side_effect=lambda value: tmp_path / str(value)
    ):
        assert _sessions._paths(_args(directory=".", to="backup:out"))[2:] == (
            tmp_path / "backup",
            "out",
        )
        assert (
            _sessions._paths(_args(aws_account_name="named"))[0] == tmp_path / "named"
        )
    raw = _sessions._paths(
        _args(
            directory=str(tmp_path / "raw"),
            to_directory=str(tmp_path / "dest"),
            to_profile="x",
        )
    )
    assert raw[2:] == ((tmp_path / "dest").absolute(), "x")
    with pytest.raises(_configs.OperationalError, match="LOCATION:PROFILE"):
        _sessions._paths(_args(to="invalid"))


def test_target_identity_and_role_account_partition_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configured(tmp_path, monkeypatch)
    with pytest.raises(_configs.OperationalError, match="Source identity"):
        _sessions._target_details(_args(target="Prod"), OTHER_ACCOUNT, "aws")

    target = _sessions._target_details(_args(target="Prod"), ACCOUNT, "aws")
    assert target["boundary_name"] == "Guard"
    role, _, _, boundary = _sessions._role_details(
        _args(target="Prod"), target, ACCOUNT, "aws"
    )
    assert role == ROLE
    assert boundary == "Guard"

    data = _state.load_config()
    data["accounts"]["Other"] = {"id": OTHER_ACCOUNT, "partition": "aws-cn"}
    _state.save_config(data)
    role, *_ = _sessions._role_details(
        _args(account="Other", role="Worker"), {}, ACCOUNT, "aws"
    )
    assert role == f"arn:aws-cn:iam::{OTHER_ACCOUNT}:role/Worker"
    with pytest.raises(_configs.OperationalError, match="conflicts with --account"):
        _sessions._role_details(_args(account="Other", role=ROLE), {}, ACCOUNT, "aws")

    target["boundary_data"]["role_arn"] = f"arn:aws:iam::{OTHER_ACCOUNT}:role/Guard"
    target["boundary_data"]["account"] = "Prod"
    with pytest.raises(_configs.OperationalError, match="Boundary role account"):
        _sessions._role_details(_args(), target, ACCOUNT, "aws")


@pytest.mark.parametrize(
    ("role", "message"),
    [("arn:invalid", "Invalid role ARN"), (None, "require a concrete role")],
)
def test_role_validation_rejects_invalid_or_missing_operands(
    role: str | None, message: str
) -> None:
    if role:
        with pytest.raises(_configs.OperationalError, match=message):
            _sessions._role_details(_args(role=role), {}, ACCOUNT, "aws")
    else:
        with pytest.raises(_configs.OperationalError, match=message):
            _sessions._require_concrete_role(_args(policy="Read"), role)
    _sessions._require_concrete_role(_args(), None)


def test_configured_role_and_session_name_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configured(tmp_path, monkeypatch)
    assert _sessions._configured_role_before_auth(_args(role=ROLE)) == ROLE
    assert _sessions._configured_role_before_auth(_args(target="Prod")) == ROLE
    assert _sessions._configured_role_before_auth(_args()) is None
    assert _sessions._session_name(ROLE, None, " ! ").startswith("hacksaws-")
    assert len(_sessions._session_name(ROLE, "Guard", "x" * 100)) == 64


@pytest.mark.parametrize(
    ("duration", "token", "message"),
    [("10m", None, "at least 900"), ("2h", "chained", "at most 3600")],
)
def test_assume_duration_security_limits(
    duration: str, token: str | None, message: str
) -> None:
    session = MagicMock()
    session.get_credentials.return_value.token = token
    with pytest.raises(_configs.OperationalError, match=message):
        _sessions._assume(
            session,
            ROLE,
            policy=None,
            source_profile="default",
            args=_args(duration=duration),
            target={},
            external_id=None,
            boundary_name=None,
        )


@pytest.mark.parametrize("document_policy", [False, True])
def test_assume_builds_policy_request_and_verifies_final_identity(
    document_policy: bool,
) -> None:
    source = MagicMock()
    source.get_credentials.return_value.token = None
    iam = MagicMock()
    iam.get_role.return_value = {"Role": {"MaxSessionDuration": "7200"}}
    sts = MagicMock()
    response = {"Credentials": _credentials()}
    sts.assume_role.return_value = response
    source.client.side_effect = lambda service: {"iam": iam, "sts": sts}[service]
    resolved = SimpleNamespace(
        arn=None if document_policy else f"arn:aws:iam::{ACCOUNT}:policy/Read",
        document='{"Version":"2012-10-17","Statement":[]}' if document_policy else None,
        identity="Read",
        provenance="stored",
        origin="stored",
        cached=document_policy,
        source_arn=(None if document_policy else f"arn:aws:iam::{ACCOUNT}:policy/Read"),
    )
    final = MagicMock()
    with (
        patch("hacksaws._policies.resolve", return_value=resolved),
        patch("hacksaws._sessions.boto3.Session", return_value=final) as factory,
        patch("hacksaws._sessions._identity", return_value=(ACCOUNT, "aws", "arn")),
    ):
        credentials, metadata = _sessions._assume(
            source,
            ROLE,
            policy="Read",
            source_profile="dev",
            args=_args(duration="1h", session_name="session"),
            target={},
            external_id="external",
            boundary_name="Guard",
        )
    request = sts.assume_role.call_args.kwargs
    expected_policy_key = "Policy" if document_policy else "PolicyArns"
    assert expected_policy_key in request
    assert request["ExternalId"] == "external"
    assert credentials == response["Credentials"]
    assert metadata["policy_provenance"] == "stored"
    assert metadata["policy_reference"] == "Read"
    assert metadata["policy_origin"] == "stored"
    assert metadata["policy_arn"] == resolved.source_arn
    assert metadata["policy_cached"] is document_policy
    assert metadata["policy_display"] == "Read"
    assert metadata["session_schema_version"] == 2
    assert metadata["target_partition"] == "aws"
    assert factory.call_args.kwargs["aws_access_key_id"] == "ASIAFINAL"


def test_assume_wraps_sts_error_and_rejects_final_identity() -> None:
    source = MagicMock()
    source.get_credentials.return_value.token = None
    source.client.return_value.get_role.side_effect = ValueError("unknown maximum")
    source.client.return_value.assume_role.side_effect = ClientError(
        {"Error": {"Code": "Denied", "Message": "no"}}, "AssumeRole"
    )
    with pytest.raises(_configs.OperationalError, match="Unable to assume"):
        _sessions._assume(
            source,
            ROLE,
            policy=None,
            source_profile="dev",
            args=_args(),
            target={},
            external_id=None,
            boundary_name=None,
        )

    source.client.return_value.assume_role.side_effect = None
    source.client.return_value.assume_role.return_value = {
        "Credentials": _credentials()
    }
    with (
        patch("hacksaws._sessions.boto3.Session"),
        patch(
            "hacksaws._sessions._identity",
            return_value=(OTHER_ACCOUNT, "aws", "arn"),
        ),
        pytest.raises(_configs.OperationalError, match="identity mismatch"),
    ):
        _sessions._assume(
            source,
            ROLE,
            policy=None,
            source_profile="dev",
            args=_args(),
            target={},
            external_id=None,
            boundary_name=None,
        )


def test_persistent_source_and_mfa_session_validate_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    aws.mkdir()
    with pytest.raises(_configs.OperationalError, match="missing"):
        _sessions._persistent_source(aws, "dev")
    (aws / "credentials").write_text("[dev]\naws_access_key_id=x\n")
    with pytest.raises(_configs.OperationalError, match="readable access keys"):
        _sessions._persistent_source(aws, "dev")

    source = MagicMock(region_name="us-east-1")
    config = configparser.ConfigParser()
    with pytest.raises(_configs.OperationalError, match="mfa_serial"):
        _sessions._mfa_session(source, config, "dev", "123456", 3600)
    config.read_dict({"profile dev": {"mfa_serial": "arn:mfa"}})
    source.client.return_value.get_session_token.side_effect = ClientError(
        {"Error": {"Code": "Denied", "Message": "bad code"}}, "GetSessionToken"
    )
    with pytest.raises(_configs.OperationalError, match="Unable to start MFA"):
        _sessions._mfa_session(source, config, "dev", "000000", 3600)


def test_mfa_session_and_raw_login_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    _write_source(aws)
    raw = MagicMock(region_name="us-west-2")
    sts = raw.client.return_value
    sts.get_session_token.return_value = {"Credentials": _credentials()}
    intermediate = MagicMock(region_name="us-west-2")
    frozen = (
        intermediate.get_credentials.return_value.get_frozen_credentials.return_value
    )
    frozen.access_key = "ASIAMFA"
    frozen.secret_key = "mfa-" + "secret"
    frozen.token = "mfa-" + "token"
    with patch(
        "hacksaws._sessions.boto3.Session", return_value=intermediate
    ) as factory:
        config = _sessions._read_ini(aws / "config")
        assert (
            _sessions._mfa_session(raw, config, "dev", "123456", 3600) is intermediate
        )
    assert factory.call_args.kwargs["region_name"] == "us-west-2"

    with (
        patch("hacksaws._sessions._persistent_source", return_value=(raw, config)),
        patch("hacksaws._sessions._identity", return_value=(ACCOUNT, "aws", "arn")),
        patch("hacksaws._sessions._mfa_session", return_value=intermediate),
    ):
        result = _sessions.mfa_login(
            _configs.Context(_args(directory=str(aws), profile="dev"))
        )
    assert result.code == "MFA_LOGIN"
    parser = _sessions._read_ini(aws / "credentials")
    assert parser["dev"]["aws_access_key_id"] == "ASIAMFA"
    assert _state.load_sessions()[f"{aws.absolute()}::dev"]["auth_method"] == "mfa"
    assert not _sessions._journal_path().exists()


def test_bounded_mfa_login_records_ecr_and_final_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configured(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    _write_source(aws)
    raw = MagicMock()
    intermediate = MagicMock(region_name="us-west-2")
    final = _credentials()
    registry = f"{ACCOUNT}.dkr.ecr.us-west-2.amazonaws.com"

    def login(*args: object, on_success: object, **kwargs: object) -> list[str]:
        on_success(registry)  # type: ignore[operator]
        return [registry]

    with (
        patch("hacksaws._sessions._persistent_source", return_value=(raw, MagicMock())),
        patch("hacksaws._sessions._identity", return_value=(ACCOUNT, "aws", "arn")),
        patch("hacksaws._sessions._mfa_session", return_value=intermediate),
        patch(
            "hacksaws._sessions._assume",
            return_value=(final, {"target_account": ACCOUNT, "expires_at": None}),
        ) as assume,
        patch("hacksaws._ecr.login_with_session", side_effect=login),
    ):
        result = _sessions.mfa_login(
            _configs.Context(_args(target="Prod", ecr=True, ecr_region=["us-east-1"]))
        )
    assert result.code == "MFA_LOGIN"
    assume.assert_called_once()
    saved = _state.load_sessions()[f"{aws.absolute()}::out"]
    assert saved["ecr"] == [registry]
    assert saved["target"] == "Prod"


@pytest.mark.parametrize(
    ("output", "error"),
    [
        ("aws-cli/2.32.0 Python/3", None),
        ("aws-cli/2.31.9 Python/3", "newer"),
        ("aws-cli/1.99.0 Python/3", "newer"),
        ("garbage", "unknown version"),
    ],
)
def test_aws_cli_version_validation(output: str, error: str | None) -> None:
    completed = subprocess.CompletedProcess(["aws"], 0, stdout=output, stderr="")
    with patch("hacksaws._sessions.subprocess.run", return_value=completed):
        if error:
            with pytest.raises(_configs.OperationalError, match=error):
                _sessions._aws_cli_version()
        else:
            assert _sessions._aws_cli_version() == (2, 32, 0)
    with (
        patch(
            "hacksaws._sessions.subprocess.run", side_effect=FileNotFoundError("aws")
        ),
        pytest.raises(_configs.OperationalError, match="required for browser"),
    ):
        _sessions._aws_cli_version()


def test_aws_environment_scrubs_and_restores_all_conflicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for key in _sessions._CONFLICTING_ENV:
        monkeypatch.setenv(key, f"old-{key}")
    config = tmp_path / "config"
    credentials = tmp_path / "credentials"
    login_cache = tmp_path / "login-cache"
    cleaned = _sessions._clean_env(config, credentials, login_cache)
    assert cleaned["AWS_CONFIG_FILE"] == str(config)
    assert cleaned["AWS_LOGIN_CACHE_DIRECTORY"] == str(login_cache)
    assert "AWS_PROFILE" not in cleaned
    with _sessions._aws_environment(config, credentials, login_cache):
        assert os.environ["AWS_CONFIG_FILE"] == str(config)
        assert os.environ["AWS_LOGIN_CACHE_DIRECTORY"] == str(login_cache)
        assert "AWS_PROFILE" not in os.environ
    for key in _sessions._CONFLICTING_ENV:
        assert os.environ[key] == f"old-{key}"


def test_aws_login_passes_remote_and_wraps_subprocess_errors(tmp_path: Path) -> None:
    config = tmp_path / "nested" / "config"
    credentials = tmp_path / "nested" / "credentials"
    login_cache = tmp_path / "login-cache"
    with (
        patch("hacksaws._sessions._aws_cli_version"),
        patch("hacksaws._sessions.subprocess.run") as run,
    ):
        _sessions._aws_login(
            config,
            credentials,
            "dev",
            remote=True,
            login_cache=login_cache,
        )
    assert run.call_args.args[0] == ["aws", "login", "--profile", "dev", "--remote"]
    assert run.call_args.kwargs["env"]["AWS_CONFIG_FILE"] == str(config)
    assert run.call_args.kwargs["env"]["AWS_LOGIN_CACHE_DIRECTORY"] == str(login_cache)
    with (
        patch("hacksaws._sessions._aws_cli_version"),
        patch(
            "hacksaws._sessions.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "aws"),
        ),
        pytest.raises(_configs.OperationalError, match="browser login failed"),
    ):
        _sessions._aws_login(
            config,
            credentials,
            "dev",
            remote=False,
            login_cache=login_cache,
        )


def test_browser_runtime_dependency_is_declared_and_preflight_is_actionable() -> None:
    project = tomllib.loads(
        (Path(__file__).parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert "boto3[crt]>=1.41,<2" in project["project"]["dependencies"]
    with (
        patch(
            "hacksaws._sessions.importlib.import_module",
            side_effect=ImportError("missing CRT"),
        ),
        pytest.raises(_configs.OperationalError, match=r"CRT.*uv sync"),
    ):
        _sessions._require_browser_runtime()


def test_native_browser_remote_cache_ecr_success_and_logout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configured(tmp_path, monkeypatch, boundary=False)
    aws = tmp_path / "aws"
    old_cache = aws / "login" / "cache" / "old.json"
    old_cache.parent.mkdir(parents=True)
    old_cache.write_text("old")
    new_cache = old_cache.with_name("new.json")
    monkeypatch.setenv("AWS_LOGIN_CACHE_DIRECTORY", str(old_cache.parent))
    native = MagicMock(region_name="us-west-2")
    registry = f"{ACCOUNT}.dkr.ecr.us-west-2.amazonaws.com"

    def login(*args: object, **kwargs: object) -> None:
        new_cache.write_text("new")

    with (
        patch("hacksaws._sessions._aws_login", side_effect=login) as aws_login,
        patch("hacksaws._sessions.boto3.Session", return_value=native),
        patch("hacksaws._sessions._identity", return_value=(ACCOUNT, "aws", "arn")),
        patch("hacksaws._ecr.login_with_session", return_value=[registry]),
    ):
        result = _sessions.browser_login(
            _configs.Context(_args(target="Prod", remote=True, ecr=True))
        )
    assert result.code == "BROWSER_LOGIN"
    assert aws_login.call_args.kwargs["remote"] is True
    saved = _state.load_sessions()[f"{aws.absolute()}::out"]
    assert saved["login_cache_files"] == [str(new_cache.absolute())]
    assert old_cache.exists()

    with patch("hacksaws._ecr._run_container_engine") as engine:
        assert (
            _sessions.logout(_configs.Context(_args(target="Prod", ecr=True))) is True
        )
    assert not new_cache.exists()
    assert old_cache.exists()
    engine.assert_called_once()


def test_native_browser_logout_preserves_a_later_same_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    aws = tmp_path / "alternate-aws"
    cache = tmp_path / "shared-login-cache"
    old_cache = cache / "old.json"
    new_cache = cache / "debug.json"
    old_cache.parent.mkdir(parents=True)
    old_cache.write_text("old", encoding="utf-8")
    monkeypatch.setenv("AWS_LOGIN_CACHE_DIRECTORY", str(cache))
    native = MagicMock(region_name="us-west-2")

    def login(
        config: Path,
        credentials: Path,
        profile: str,
        *,
        remote: bool,
        login_cache: Path,
    ) -> None:
        del credentials, remote
        assert profile == "debug"
        assert login_cache == cache.absolute()
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            "[profile debug]\nregion=us-west-2\nlogin_session=x\n",
            encoding="utf-8",
        )
        new_cache.write_text("new", encoding="utf-8")

    args = _args(directory=str(aws), profile="debug")
    with (
        patch("hacksaws._sessions._aws_login", side_effect=login),
        patch("hacksaws._sessions.boto3.Session", return_value=native),
        patch("hacksaws._sessions._identity", return_value=(ACCOUNT, "aws", "arn")),
    ):
        _sessions.browser_login(_configs.Context(args))
    saved = _state.load_sessions()[f"{aws.absolute()}::debug"]
    assert saved["login_cache_files"] == [str(new_cache.absolute())]
    assert saved["login_cache_directories"] == [str(cache.absolute())]
    assert old_cache.read_text(encoding="utf-8") == "old"
    new_cache.write_text("independent replacement", encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="changed after login"):
        _sessions.logout(_configs.Context(args))
    assert new_cache.read_text(encoding="utf-8") == "independent replacement"
    assert old_cache.read_text(encoding="utf-8") == "old"
    assert f"{aws.absolute()}::debug" in _state.load_sessions()


def test_native_browser_post_login_failure_reports_complete_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    config = aws / "config"
    config.parent.mkdir(parents=True)
    config.write_bytes(b"[default]\nregion=us-east-1\n")
    cache = tmp_path / "cache"
    old_cache = cache / "old.json"
    new_cache = cache / "new.json"
    cache.mkdir()
    old_cache.write_text("old", encoding="utf-8")
    monkeypatch.setenv("AWS_LOGIN_CACHE_DIRECTORY", str(cache))

    def login(
        config_path: Path,
        credentials: Path,
        profile: str,
        *,
        remote: bool,
        login_cache: Path,
    ) -> None:
        del credentials, profile, remote
        assert login_cache == cache.absolute()
        config_path.write_text("[profile debug]\nlogin_session=x\n", encoding="utf-8")
        new_cache.write_text("broad", encoding="utf-8")

    args = _args(directory=str(aws), profile="debug")
    with (
        patch("hacksaws._sessions._aws_login", side_effect=login),
        patch("hacksaws._sessions.boto3.Session", return_value=MagicMock()),
        patch(
            "hacksaws._sessions._identity",
            side_effect=_configs.OperationalError("identity failed"),
        ),
        pytest.raises(
            _configs.OperationalError,
            match=r"identity failed.*profile 'debug' were rolled back",
        ),
    ):
        _sessions.browser_login(_configs.Context(args))
    assert config.read_bytes() == b"[default]\nregion=us-east-1\n"
    assert old_cache.read_text(encoding="utf-8") == "old"
    assert not new_cache.exists()
    assert not _sessions._journal_path().exists()


def test_bounded_browser_success_removes_login_session_and_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _ = _configured(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    intermediate = MagicMock(region_name="us-west-2")

    inherited_cache = tmp_path / "global-cache"
    inherited_cache.mkdir()
    unrelated = inherited_cache / "unrelated.json"
    unrelated.write_text("old", encoding="utf-8")
    monkeypatch.setenv("AWS_LOGIN_CACHE_DIRECTORY", str(inherited_cache))

    def login(
        config: Path,
        credentials: Path,
        *args: object,
        login_cache: Path,
        **kwargs: object,
    ) -> None:
        assert root / "staging" in login_cache.parents
        assert login_cache != inherited_cache
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("[profile dev]\nregion=us-west-2\nlogin_session=x\n")
        credentials.write_text("[dev]\na=x\n")
        login_cache.mkdir(parents=True)
        (login_cache / "broad.json").write_text("broad", encoding="utf-8")

    with (
        patch("hacksaws._sessions._aws_login", side_effect=login),
        patch("hacksaws._sessions.boto3.Session", return_value=intermediate),
        patch("hacksaws._sessions._identity", return_value=(ACCOUNT, "aws", "arn")),
        patch(
            "hacksaws._sessions._assume",
            return_value=(_credentials(), {"target_account": ACCOUNT}),
        ),
    ):
        result = _sessions.browser_login(_configs.Context(_args(target="Prod")))
    assert result.code == "BROWSER_LOGIN"
    config = _sessions._read_ini(aws / "config")
    assert "login_session" not in config["profile out"]
    assert config["profile out"]["region"] == "us-west-2"
    assert not (root / "staging").exists() or not any((root / "staging").iterdir())
    assert unrelated.read_text(encoding="utf-8") == "old"


def test_bounded_browser_restores_environment_when_assume_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configured(tmp_path, monkeypatch)
    monkeypatch.setenv("AWS_CONFIG_FILE", "original-config")
    monkeypatch.delenv("AWS_SHARED_CREDENTIALS_FILE", raising=False)
    inherited_cache = tmp_path / "inherited-cache"
    inherited_cache.mkdir()
    unrelated = inherited_cache / "unrelated.json"
    unrelated.write_text("old", encoding="utf-8")
    monkeypatch.setenv("AWS_LOGIN_CACHE_DIRECTORY", str(inherited_cache))

    def login(
        config: Path,
        credentials: Path,
        profile: str,
        *,
        remote: bool,
        login_cache: Path,
    ) -> None:
        del config, credentials, profile, remote
        assert inherited_cache not in login_cache.parents
        login_cache.mkdir(parents=True)
        (login_cache / "broad.json").write_text("broad", encoding="utf-8")

    with (
        patch("hacksaws._sessions._aws_login", side_effect=login),
        patch("hacksaws._sessions.boto3.Session", return_value=MagicMock()),
        patch("hacksaws._sessions._identity", return_value=(ACCOUNT, "aws", "arn")),
        patch("hacksaws._sessions._assume", side_effect=RuntimeError("after-auth")),
        pytest.raises(RuntimeError, match="after-auth"),
    ):
        _sessions.browser_login(_configs.Context(_args(target="Prod")))
    assert os.environ["AWS_CONFIG_FILE"] == "original-config"
    assert "AWS_SHARED_CREDENTIALS_FILE" not in os.environ
    assert os.environ["AWS_LOGIN_CACHE_DIRECTORY"] == str(inherited_cache)
    assert unrelated.read_text(encoding="utf-8") == "old"
    staging = _state.root() / "staging"
    assert not staging.exists() or not any(staging.iterdir())


def test_record_preserves_original_backup_and_merges_cache_and_ecr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    destination = tmp_path / "aws"
    key = f"{destination.absolute()}::dev"
    old_backup = [{"path": "old", "exists": False}]
    _state.save_sessions(
        {
            key: {
                "backup": old_backup,
                "ecr": ["old-registry"],
                "login_cache_files": ["old-cache"],
            }
        }
    )
    _sessions._record(
        destination,
        "dev",
        {"login_cache_files": ["new-cache"]},
        {"files": [{"path": "new", "exists": False}]},
        method="browser-native",
        ecr=["old-registry", "new-registry"],
    )
    saved = _state.load_sessions()[key]
    assert saved["backup"] == old_backup
    assert saved["login_cache_files"] == ["old-cache", "new-cache"]
    assert saved["ecr"] == ["old-registry", "new-registry"]


def test_logout_missing_snapshot_ecr_only_and_cache_path_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    outside = tmp_path / "outside.json"
    outside.write_text("keep")
    cache = aws / "login" / "cache" / "owned.json"
    cache.parent.mkdir(parents=True)
    cache.write_text("delete")
    key = f"{aws.absolute()}::dev"
    _state.save_sessions(
        {
            key: {
                "destination": str(aws.absolute()),
                "profile": "dev",
                "auth_method": "browser-native",
                "backup": [{"path": str(_state.sessions_path()), "exists": False}],
                "login_cache_files": [str(cache), str(outside)],
                "login_cache_fingerprints": {
                    str(cache.absolute()): _state.digest(cache.read_bytes()),
                    str(outside.absolute()): _state.digest(outside.read_bytes()),
                },
                "ecr": [],
            }
        }
    )
    context = _configs.Context(_args(directory=str(aws), profile="dev", force=True))
    assert _sessions.logout(context) is True
    assert not cache.exists()
    assert outside.exists()
    saved = _state.load_sessions()[key]
    assert saved["auth_method"] == "browser-cache-residue"
    assert saved["login_cache_residue"][0]["path"] == str(outside.absolute())


def test_logout_conservatively_preserves_legacy_unfingerprinted_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    cache = aws / "login" / "cache" / "legacy.json"
    cache.parent.mkdir(parents=True)
    cache.write_text("unknown owner", encoding="utf-8")
    key = f"{aws.absolute()}::dev"
    _state.save_sessions(
        {
            key: {
                "destination": str(aws.absolute()),
                "profile": "dev",
                "auth_method": "browser-native",
                "backup": [],
                "login_cache_files": [str(cache)],
                "ecr": [],
            }
        }
    )
    context = _configs.Context(_args(directory=str(aws), profile="dev"))
    with pytest.raises(_configs.OperationalError, match="changed after login"):
        _sessions.logout(context)
    assert cache.read_text(encoding="utf-8") == "unknown owner"
    assert _sessions.logout(
        _configs.Context(_args(directory=str(aws), profile="dev", force=True))
    )
    assert not cache.exists()


def test_status_is_secret_free_and_handles_expiry_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    future = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    _state.save_sessions(
        {
            "a": {"backup": ["secret"], "expires_at": future, "profile": "a"},
            "b": {"backup": ["secret"], "expires_at": "bad", "profile": "b"},
        }
    )
    result = _sessions.status()
    assert "backup" not in result[0]
    assert result[0]["remaining_seconds"] > 0
    assert result[1]["remaining_seconds"] is None
    assert result[1]["state"] == "legacy-unverified"
    assert result[1]["warnings"] == [
        {
            "code": "INVALID_EXPIRY",
            "source": "expires_at",
            "message": "Session expiry metadata is invalid.",
        }
    ]


def test_status_scope_uses_validated_cache_and_safe_fallbacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    document = {
        "Version": "2012-10-17",
        "Statement": [{"Resource": "POLICY-DOCUMENT-SENTINEL"}],
    }
    arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
    identity = _policies._cache_identity(arn, account=ACCOUNT, partition="aws")
    _policies.cache_write(
        identity,
        document,
        origin="aws-managed",
        resolver="arn",
        source_identity=arn,
    )
    local_source = str((tmp_path / "policies" / "debug.yaml").absolute())
    local_identity = "local-" + _state.digest(local_source.casefold().encode())[:24]
    _policies.cache_write(
        local_identity,
        document,
        origin="local",
        resolver="file",
        source_identity=local_source,
    )
    customer_arn = f"arn:aws:iam::{ACCOUNT}:policy/team/CustomerDebug"
    customer_identity = _policies._cache_identity(
        "name:CustomerDebug", account=ACCOUNT, partition="aws"
    )
    _policies.cache_write(
        customer_identity,
        document,
        origin="remote-customer",
        resolver="name",
        source_identity=customer_arn,
    )
    wrong_arn = f"arn:aws:iam::{OTHER_ACCOUNT}:policy/CustomerDebug"
    wrong_identity = _policies._cache_identity(
        "name:CustomerDebug", account=OTHER_ACCOUNT, partition="aws"
    )
    _policies.cache_write(
        wrong_identity,
        document,
        origin="remote-customer",
        resolver="name",
        source_identity=wrong_arn,
    )
    corrupt_identity = "local-" + _state.digest(b"c:/policies/debug.yaml")[:24]
    _policies.cache_write(
        corrupt_identity,
        document,
        origin="local",
        resolver="file",
        source_identity="c:/policies/debug.yaml",
    )
    corrupt_path = _policies.cache_root() / f"{corrupt_identity}.json"
    corrupt = json.loads(corrupt_path.read_text(encoding="utf-8"))
    corrupt["digest"] = "corrupt"
    corrupt_path.write_text(json.dumps(corrupt), encoding="utf-8")
    base = {
        "destination": str(tmp_path / "aws"),
        "auth_method": "assume-role",
        "target_account": ACCOUNT,
        "role": f"arn:aws:iam::{ACCOUNT}:role/team/AgentSession",
        "backup": ["BACKUP-SECRET-SENTINEL"],
        "login_cache_files": ["BROWSER-BYTES-SENTINEL"],
    }
    _state.save_sessions(
        {
            "valid": {**base, "profile": "valid", "policy": identity},
            "local": {**base, "profile": "local", "policy": local_identity},
            "stored": {
                **base,
                "profile": "stored",
                "policy": "Investigate",
                "policy_provenance": "stored policy Investigate",
            },
            "customer": {
                **base,
                "profile": "customer",
                "policy": customer_identity,
            },
            "missing": {**base, "profile": "missing", "policy": "missing-cache"},
            "corrupt": {
                **base,
                "profile": "corrupt",
                "policy": corrupt_identity,
            },
            "mismatch": {
                **base,
                "profile": "mismatch",
                "policy": wrong_identity,
            },
        }
    )
    report = _sessions.status_report()
    sessions = {item["profile"]: item for item in report["sessions"]}
    valid = sessions["valid"]["effective_scope"]
    assert valid == {
        "kind": "role-session",
        "role_label": "team/AgentSession",
        "boundary_label": None,
        "policy_label": "CloudWatchReadOnlyAccess",
        "policy_source": {
            "origin": "aws-managed",
            "reference": arn,
            "arn": arn,
            "cached": True,
        },
        "policy_known": True,
    }
    expected_cache_labels = {
        "local": ("debug.yaml", "local"),
        "stored": ("Investigate", "stored"),
        "customer": ("team/CustomerDebug", "remote-customer"),
    }
    for name, (label, origin) in expected_cache_labels.items():
        scope = sessions[name]["effective_scope"]
        assert scope["policy_label"] == label
        assert scope["policy_source"]["origin"] == origin
        assert scope["policy_known"] is True
    for name in ("missing", "corrupt", "mismatch"):
        scope = sessions[name]["effective_scope"]
        assert scope["policy_label"] == "session policy"
        assert scope["policy_source"] is None
        assert scope["policy_known"] is False
    serialized = json.dumps(report)
    for sentinel in (
        "POLICY-DOCUMENT-SENTINEL",
        "BACKUP-SECRET-SENTINEL",
        "BROWSER-BYTES-SENTINEL",
    ):
        assert sentinel not in serialized


def test_status_scope_kinds_and_fractional_expiry_are_honest() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    cases: dict[str, tuple[dict[str, object], str]] = {
        "browser": ({"auth_method": "browser-native", "policy": None}, "account-login"),
        "mfa": ({"auth_method": "mfa", "policy": None}, "mfa-session"),
        "ecr": ({"auth_method": "ecr-only"}, "ecr-only"),
        "residue": ({"auth_method": "browser-cache-residue"}, "logout-residue"),
        "legacy": ({}, "legacy-unknown"),
    }
    for session, expected in cases.values():
        public = _sessions._public_session(session, now=now)
        assert public["effective_scope"]["kind"] == expected
    fractional = _sessions._public_session(
        {
            "auth_method": "mfa",
            "policy": None,
            "expires_at": (now + timedelta(microseconds=1)).isoformat(),
        },
        now=now,
    )
    assert fractional["remaining_seconds"] == 1


def test_scope_projection_covers_persisted_metadata_and_rejects_bad_cache_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    persisted = _sessions._effective_scope(
        {
            "auth_method": "assume-role",
            "role": ROLE,
            "boundary": "Guardrail",
            "policy": "opaque",
            "policy_display": "ReadLogs",
            "policy_origin": "stored",
            "policy_reference": "ReadLogs",
            "policy_cached": False,
        }
    )
    assert persisted["role_label"] == "Guard"
    assert persisted["boundary_label"] == "Guardrail"
    assert persisted["policy_label"] == "ReadLogs"
    assert persisted["policy_source"] == {
        "origin": "stored",
        "reference": "ReadLogs",
        "arn": None,
        "cached": False,
    }
    explicit = _sessions._policy_scope(
        {"policy": f"arn:aws:iam::{ACCOUNT}:policy/team/Direct"}
    )
    assert explicit["label"] == "team/Direct"
    assert explicit["source"]["origin"] == "remote-customer"
    assert _sessions._role_display_name("Guard") == "Guard"
    assert (
        _sessions._role_display_name("arn:aws:iam::123456789012:user/not-role") is None
    )

    document = {"Version": "2012-10-17", "Statement": []}
    _policies.cache_write(
        "stored-debug",
        document,
        origin="stored",
        resolver="stored",
        source_identity="Debug",
    )
    assert _sessions._cached_policy_source("stored-debug", target_account=ACCOUNT) == {
        "origin": "stored",
        "reference": "Debug",
        "arn": None,
        "cached": True,
        "display": "Debug",
    }
    _policies.cache_write(
        "stored-wrong",
        document,
        origin="stored",
        resolver="stored",
        source_identity="Debug",
    )
    assert (
        _sessions._cached_policy_source("stored-wrong", target_account=ACCOUNT) is None
    )
    _policies.cache_write(
        "invalid-source",
        document,
        origin="aws-managed",
        resolver="arn",
        source_identity="not-an-arn",
    )
    assert (
        _sessions._cached_policy_source("invalid-source", target_account=ACCOUNT)
        is None
    )

    naive_expiry = _sessions._public_session(
        {
            "auth_method": "mfa",
            "policy": None,
            "expires_at": "2026-01-01T01:00:00",
        },
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert naive_expiry["remaining_seconds"] is None
    assert naive_expiry["warnings"][0]["source"] == "expires_at"


def test_public_status_allowlist_rejects_hostile_top_level_and_nested_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    sentinels = {
        "ACCESS-KEY-SENTINEL",
        "SECRET-KEY-SENTINEL",
        "TOKEN-SENTINEL",
        "PASSWORD-SENTINEL",
        "PRIVATE-KEY-SENTINEL",
        "POLICY-DOCUMENT-SENTINEL",
    }
    _state.save_sessions(
        {
            "hostile": {
                "destination": str(tmp_path / "aws"),
                "profile": "safe",
                "auth_method": "assume-role",
                "target_account": ACCOUNT,
                "target_partition": "aws",
                "aws_access_key_id": "ACCESS-KEY-SENTINEL",
                "aws_secret_access_key": "SECRET-KEY-SENTINEL",
                "aws_session_token": "TOKEN-SENTINEL",
                "password": "PASSWORD-SENTINEL",
                "metadata": {"private_key": "PRIVATE-KEY-SENTINEL"},
                "policy_document": {"Statement": "POLICY-DOCUMENT-SENTINEL"},
                "role": {"password": "PASSWORD-SENTINEL"},
                "boundary": {"token": "TOKEN-SENTINEL"},
                "policy": {"document": "POLICY-DOCUMENT-SENTINEL"},
                "policy_reference": {"secret": "SECRET-KEY-SENTINEL"},
                "ecr": ["safe", {"password": "PASSWORD-SENTINEL"}],
                "backup": [{"token": "TOKEN-SENTINEL"}],
                "section_backup": {
                    "credentials": {"private_key": "PRIVATE-KEY-SENTINEL"}
                },
            }
        }
    )
    report = _sessions.status_report()
    public = report["sessions"][0]
    assert public["profile"] == "safe"
    assert public["target_account"] == ACCOUNT
    assert public["target_partition"] == "aws"
    assert public["effective_scope"]["policy_label"] == "session policy"
    serialized = json.dumps(report)
    assert all(sentinel not in serialized for sentinel in sentinels)


def test_public_status_preserves_documented_raw_scalar_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    destination = str((tmp_path / "aws").absolute())
    raw = {
        "session_schema_version": 2,
        "source_account": OTHER_ACCOUNT,
        "source_partition": "aws",
        "target_account": ACCOUNT,
        "target_partition": "aws",
        "role": ROLE,
        "boundary": "Guardrail",
        "policy": "Investigate",
        "policy_provenance": "stored policy Investigate",
        "policy_reference": "Investigate",
        "policy_origin": "stored",
        "policy_arn": None,
        "policy_cached": False,
        "policy_display": "Investigate",
        "expires_at": None,
        "target": "prod",
        "destination": destination,
        "profile": "debug",
        "auth_method": "assume-role",
        "started_at": "2026-01-01T00:00:00+00:00",
        "ecr": ["123456789012.dkr.ecr.us-east-1.amazonaws.com"],
        "ecr_engine": "docker",
        "source_profile": "admin",
        "source_destination": str(tmp_path / "source"),
        "source_auth_method": "mfa",
        "source_logged_out": True,
        "cache_cleanup_incomplete": True,
        "login_cache_residue": [
            {"path": str(tmp_path / "cache.json"), "reason": "outside cache root"}
        ],
    }
    public = _sessions._public_session(raw, now=datetime(2026, 1, 1, tzinfo=UTC))
    for key, value in raw.items():
        assert public[key] == value
    assert public["effective_scope"]["role_label"] == "Guard"
    assert public["effective_scope"]["boundary_label"] == "Guardrail"


def test_public_status_sanitizes_login_cache_residue_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    session = {
        "profile": "debug",
        "cache_cleanup_incomplete": True,
        "login_cache_residue": [
            {
                "path": "safe-cache.json",
                "reason": "file changed",
                "password": "PASSWORD-SENTINEL",
                "nested": {"token": "TOKEN-SENTINEL"},
            },
            {
                "path": {"private_key": "PRIVATE-KEY-SENTINEL"},
                "reason": "invalid path",
            },
            {
                "path": "invalid-reason.json",
                "reason": {"policy_document": "POLICY-DOCUMENT-SENTINEL"},
            },
            "ACCESS-KEY-SENTINEL",
        ],
    }
    public = _sessions._public_session(session, now=datetime(2026, 1, 1, tzinfo=UTC))
    assert public["cache_cleanup_incomplete"] is True
    assert public["login_cache_residue"] == [
        {"path": "safe-cache.json", "reason": "file changed"}
    ]
    serialized = json.dumps(public)
    for sentinel in (
        "PASSWORD-SENTINEL",
        "TOKEN-SENTINEL",
        "PRIVATE-KEY-SENTINEL",
        "POLICY-DOCUMENT-SENTINEL",
        "ACCESS-KEY-SENTINEL",
    ):
        assert sentinel not in serialized


def test_status_verification_fails_closed_on_identity_mismatch_and_bad_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    base = {
        "state": "active",
        "destination": str(tmp_path / "aws"),
        "profile": "debug",
        "target_account": ACCOUNT,
        "target_partition": "aws",
    }
    with (
        patch("hacksaws._sessions.boto3.Session"),
        patch(
            "hacksaws._sessions._identity",
            return_value=(
                OTHER_ACCOUNT,
                "aws-us-gov",
                f"arn:aws-us-gov:iam::{OTHER_ACCOUNT}:user/debug",
            ),
        ),
    ):
        mismatch = _sessions._verify_status(base)
    assert mismatch == {
        "status": "mismatch",
        "reason": "account, partition mismatch",
        "expected_account": ACCOUNT,
        "actual_account": OTHER_ACCOUNT,
        "expected_partition": "aws",
        "actual_partition": "aws-us-gov",
        "actual_arn": f"arn:aws-us-gov:iam::{OTHER_ACCOUNT}:user/debug",
    }

    role_item = {
        **base,
        "role": f"arn:aws:iam::{ACCOUNT}:role/team/AgentSession",
    }
    with (
        patch("hacksaws._sessions.boto3.Session"),
        patch(
            "hacksaws._sessions._identity",
            return_value=(
                ACCOUNT,
                "aws",
                f"arn:aws:sts::{ACCOUNT}:assumed-role/OtherRole/status",
            ),
        ),
    ):
        role_mismatch = _sessions._verify_status(role_item)
    assert role_mismatch["status"] == "mismatch"
    assert role_mismatch["reason"] == "role mismatch"
    assert role_mismatch["expected_role"] == "AgentSession"
    assert role_mismatch["actual_role"] == "OtherRole"

    assert _sessions._verify_status(
        {"state": "active", "destination": str(tmp_path), "profile": "legacy"}
    ) == {
        "status": "error",
        "message": (
            "Session metadata does not contain a consistent expected AWS account "
            "and partition."
        ),
    }
    with (
        patch("hacksaws._sessions.boto3.Session"),
        patch(
            "hacksaws._sessions._identity",
            return_value=(ACCOUNT, "aws", f"arn:aws:iam::{ACCOUNT}:user/bad?TOKEN"),
        ),
    ):
        unsafe_arn = _sessions._verify_status(base)
    assert unsafe_arn == {
        "status": "error",
        "message": "AWS returned an invalid caller ARN during status verification.",
        "actual_account": ACCOUNT,
        "actual_partition": "aws",
    }


def test_explain_target_resolves_locations_defaults_and_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configured(tmp_path, monkeypatch)
    explained = _sessions.explain_target("+prod")
    assert explained["source"]["account_id"] == ACCOUNT
    assert explained["destination"]["profile"] == "out"
    assert explained["boundary"]["duration"] == 3600
    data = _state.load_config()
    data["targets"]["Prod"].pop("boundary")
    data["targets"]["Prod"].pop("source_directory")
    data["targets"]["Prod"].pop("destination_directory")
    data["targets"]["Prod"]["source_location"] = "source"
    data["targets"]["Prod"]["destination_location"] = "destination"
    _state.save_config(data)
    with patch(
        "hacksaws._state.aws_directory", side_effect=lambda value: tmp_path / str(value)
    ):
        explained = _sessions.explain_target("Prod")
    assert explained["boundary"] is None
    assert explained["destination"]["directory"] == str(tmp_path / "destination")


def test_check_config_local_parse_error_and_load_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    with patch(
        "hacksaws._state.load_config",
        side_effect=_configs.OperationalError("bad config"),
    ):
        assert _sessions.check_config(_args())["errors"] == ["bad config"]
    data = _state.default_config()
    data["policies"]["Bad"] = {"file": "stored_session_policies/Bad.yaml"}
    _state.save_config(data)
    with patch(
        "hacksaws._policies.parse_policy",
        side_effect=_configs.OperationalError("bad policy"),
    ):
        report = _sessions.check_config(_args())
    assert report == {"ok": False, "errors": ["bad policy"], "warnings": []}


def test_remote_check_scopes_roles_probes_and_restores_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configured(tmp_path, monkeypatch)
    data = _state.load_config()
    data["accounts"]["Other"] = {"id": OTHER_ACCOUNT, "partition": "aws"}
    data["boundaries"]["Other"] = {
        "role_arn": f"arn:aws:iam::{OTHER_ACCOUNT}:role/Other",
        "account": "Other",
        "verified": False,
    }
    data["boundaries"]["Guard"]["external_id"] = "external"
    _state.save_config(data)
    monkeypatch.setenv("AWS_PROFILE", "original")
    session = MagicMock()
    iam = MagicMock()
    iam.get_role.side_effect = ClientError(
        {"Error": {"Code": "NoSuchEntity", "Message": "missing"}}, "GetRole"
    )
    sts = MagicMock()
    session.client.side_effect = lambda service: {"iam": iam, "sts": sts}[service]
    with (
        patch("hacksaws._sessions.boto3.Session", return_value=session),
        patch("hacksaws._sessions._identity", return_value=(ACCOUNT, "aws", "arn")),
    ):
        report = _sessions.check_config(
            _args(target="Prod", account="Prod", remote=True, probe=True)
        )
    assert any("Using target Prod" in warning for warning in report["warnings"])
    assert any("deny-all" in warning for warning in report["warnings"])
    assert any("Boundary Guard: missing" in error for error in report["errors"])
    assert iam.get_role.call_count == 1
    assert sts.assume_role.call_args.kwargs["ExternalId"] == "external"
    assert os.environ["AWS_PROFILE"] == "original"


def test_remote_check_account_mismatch_role_and_probe_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configured(tmp_path, monkeypatch)
    session = MagicMock()
    iam = MagicMock()
    iam.get_role.side_effect = ClientError(
        {"Error": {"Code": "Denied", "Message": "no"}}, "GetRole"
    )
    sts = MagicMock()
    sts.assume_role.side_effect = ClientError(
        {"Error": {"Code": "Denied", "Message": "no"}}, "AssumeRole"
    )
    session.client.side_effect = lambda service: {"iam": iam, "sts": sts}[service]
    with (
        patch("hacksaws._sessions.boto3.Session", return_value=session),
        patch("hacksaws._sessions._identity", return_value=(ACCOUNT, "aws", "arn")),
    ):
        report = _sessions.check_config(_args(account="Prod", remote=True, probe=True))
    assert any("unverifiable" in error for error in report["errors"])
    assert any("probe failed" in error for error in report["errors"])


@pytest.mark.parametrize(
    ("answers", "expected_code", "exists"),
    [(["l"], "CONFIG_FIX_UNRESOLVED", True), (["x"], "CONFIG_FIX", False)],
)
def test_fix_config_leave_or_remove_orphan_policy(
    answers: list[str],
    expected_code: str,
    exists: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _home(tmp_path, monkeypatch)
    data = _state.load_config()
    data["policies"]["Bad"] = {"file": "stored_session_policies/Bad.yaml"}
    _state.save_config(data)
    policy = _policies.stored_directory() / "Bad.yaml"
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("bad")
    with (
        patch("hacksaws._sessions.sys.stdin.isatty", return_value=True),
        patch("builtins.input", side_effect=answers),
        patch(
            "hacksaws._policies.parse_policy",
            side_effect=_configs.OperationalError("invalid"),
        ),
    ):
        result = _sessions.fix_config(_args())
    assert result.code == expected_code
    assert policy.exists() is exists
    assert bool(_state.load_config()["policies"]) is exists
    assert list((_state.root() / "backups").glob("config-*.json"))


def test_fix_config_repairs_policy_and_scopes_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configured(tmp_path, monkeypatch)
    data = _state.load_config()
    data["policies"]["Bad"] = {"file": "stored_session_policies/Bad.yaml"}
    data["policies"]["Ignored"] = {"file": "stored_session_policies/Ignored.yaml"}
    data["boundaries"]["Guard"]["policy"] = "Bad"
    _state.save_config(data)
    replacement = tmp_path / "replacement.json"
    replacement.write_text('{"Version":"2012-10-17","Statement":[]}')

    def parse(path: Path) -> tuple[dict[str, object], bytes]:
        if path == replacement:
            return {"Version": "2012-10-17", "Statement": []}, path.read_bytes()
        raise _configs.OperationalError("invalid")

    with (
        patch("hacksaws._sessions.sys.stdin.isatty", return_value=True),
        patch("builtins.input", side_effect=["r", str(replacement)]),
        patch("hacksaws._policies.parse_policy", side_effect=parse),
    ):
        result = _sessions.fix_config(_args(account="Prod"))
    assert result.code == "CONFIG_FIX"
    repaired = (_policies.stored_directory() / "Bad.yaml").read_text()
    assert "Version" in repaired


def test_fix_config_failed_repair_is_unresolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    data = _state.load_config()
    data["policies"]["Bad"] = {"file": "stored_session_policies/Bad.yaml"}
    _state.save_config(data)
    with (
        patch("hacksaws._sessions.sys.stdin.isatty", return_value=True),
        patch("builtins.input", side_effect=["r", "missing.yaml"]),
        patch(
            "hacksaws._policies.parse_policy",
            side_effect=_configs.OperationalError("still invalid"),
        ),
    ):
        result = _sessions.fix_config(_args())
    assert result.exit_code == 1
    assert "remain unresolved" in result.message


def test_export_import_stored_and_external_policies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configured(tmp_path, monkeypatch)
    stored = _policies.stored_directory() / "Stored.yaml"
    stored.parent.mkdir(parents=True, exist_ok=True)
    stored.write_bytes(POLICY)
    external = tmp_path / "external.json"
    external.write_text('{"Version":"2012-10-17","Statement":[]}')
    data = _state.load_config()
    data["policies"]["Stored"] = {"file": "stored_session_policies/Stored.yaml"}
    data["boundaries"]["Guard"]["policy"] = str(external)
    _state.save_config(data)
    archive = _sessions.export_config(str(tmp_path / "portable.zip"))
    with zipfile.ZipFile(archive) as zipped:
        names = zipped.namelist()
        assert "stored_session_policies/Stored.yaml" in names
        assert any(name.startswith("external_policies/") for name in names)

    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "imported"))
    _state.save_config(_state.default_config())
    message = _sessions.import_config(archive, replace=False, yes=False)
    imported = _state.load_config()
    promoted = imported["boundaries"]["Guard"]["policy"]
    assert message.endswith("Imported portable configuration.")
    assert promoted.startswith("imported-")
    assert (_policies.stored_directory() / f"{promoted}.yaml").exists()


def test_export_rejects_missing_external_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configured(tmp_path, monkeypatch)
    data = _state.load_config()
    data["boundaries"]["Guard"]["policy"] = str(tmp_path / "missing.json")
    _state.save_config(data)
    with pytest.raises(_configs.OperationalError, match="does not exist"):
        _sessions.export_config(None)


def test_import_conflict_cancel_and_noninteractive_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _state.default_config()
    source["accounts"]["Prod"] = {"id": ACCOUNT, "partition": "aws"}
    archive = _archive(tmp_path / "config.zip", source, {})
    _home(tmp_path, monkeypatch)
    current = _state.load_config()
    current["accounts"]["prod"] = {"id": OTHER_ACCOUNT, "partition": "aws"}
    _state.save_config(current)
    with pytest.raises(_configs.OperationalError, match="require --replace"):
        _sessions.import_config(archive, replace=False, yes=False)
    with (
        patch("hacksaws._sessions.sys.stdin.isatty", return_value=False),
        pytest.raises(_configs.OperationalError, match="requires --yes"),
    ):
        _sessions.import_config(archive, replace=True, yes=False)
    with (
        patch("hacksaws._sessions.sys.stdin.isatty", return_value=True),
        patch("builtins.input", return_value="n"),
        pytest.raises(_configs.OperationalError, match="cancelled"),
    ):
        _sessions.import_config(archive, replace=True, yes=False)


@pytest.mark.parametrize(
    ("members", "message"),
    [
        ({"../config.json": b"{}"}, "unsafe path"),
        ({"config.json": b"{}"}, "missing manifest"),
    ],
)
def test_import_rejects_unsafe_or_incomplete_archives(
    members: dict[str, bytes],
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _home(tmp_path, monkeypatch)
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as output:
        for name, content in members.items():
            output.writestr(name, content)
    with pytest.raises(_configs.OperationalError, match=message):
        _sessions.import_config(archive, replace=False, yes=False)


def test_import_wraps_bad_zip_and_rolls_back_after_policy_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    bad = tmp_path / "bad.zip"
    bad.write_text("not zip")
    with pytest.raises(_configs.OperationalError, match="Unable to import archive"):
        _sessions.import_config(bad, replace=False, yes=False)

    config = _state.default_config()
    config["policies"]["Read"] = {"file": "stored_session_policies/Read.yaml"}
    archive = _archive(
        tmp_path / "policy.zip",
        config,
        {"stored_session_policies/Read.yaml": POLICY},
    )
    original = (_state.root() / "config.json").read_bytes()
    real_save = _state.save_config

    def fail_after_write(data: dict[str, object]) -> None:
        real_save(data)  # side effect that rollback must undo
        raise RuntimeError(INJECTED_ERROR)

    with (
        patch("hacksaws._state.save_config", side_effect=fail_after_write),
        pytest.raises(RuntimeError, match="injected"),
    ):
        _sessions.import_config(archive, replace=False, yes=False)
    assert (_state.root() / "config.json").read_bytes() == original
    assert not (_policies.stored_directory() / "Read.yaml").exists()


def test_shared_test_runner_preserves_pytest_exit_code() -> None:
    from hacksaws import _test_runner

    completed: subprocess.CompletedProcess[str] = subprocess.CompletedProcess(
        ["pytest"], 7
    )
    with (
        patch("hacksaws._test_runner.find_spec", return_value=object()),
        patch("hacksaws._test_runner.subprocess.run", return_value=completed) as run,
    ):
        assert _test_runner.main(["-k", "focused"]) == 7
    assert run.call_args.args[0][1:3] == ["-m", "pytest"]
    assert "--cov-fail-under=95" in run.call_args.args[0]
    assert run.call_args.args[0][-2:] == ["-k", "focused"]


def test_shared_test_runner_explains_missing_development_dependencies(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from hacksaws import _test_runner

    with patch("hacksaws._test_runner.find_spec", return_value=None):
        assert _test_runner.main([]) == 2
    assert "requires development dependencies" in capsys.readouterr().err
