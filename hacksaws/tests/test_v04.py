"""Focused offline coverage for the v0.4 configuration and grammar contract."""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from hacksaws import _cli
from hacksaws import _configs
from hacksaws import _duration
from hacksaws import _ecr
from hacksaws import _policies
from hacksaws import _regions
from hacksaws import _sessions
from hacksaws import _state


@pytest.mark.parametrize(
    ("value", "seconds"),
    [("1s", 1), ("1.5minutes", 90), (".5h", 1800), ("2 HR", 7200)],
)
def test_exact_duration_parser(value: str, seconds: int) -> None:
    assert _duration.parse_duration(value) == seconds


@pytest.mark.parametrize("value", ["1h30m", "1", "-1h", "0s", "infinityh"])
def test_duration_rejects_compound_or_nonpositive(value: str) -> None:
    with pytest.raises(_configs.OperationalError):
        _duration.parse_duration(value)


def test_cache_duration_uniquely_allows_zero() -> None:
    assert _duration.parse_duration("0s", allow_zero=True) == 0


def test_parser_supports_target_shorthand_and_web_alias() -> None:
    mfa = _cli._create_parser().parse_args(["mfa", "in", "+prod", "123456"])
    web = _cli._create_parser().parse_args(["web", "login", "--remote"])
    assert mfa.profile == "+prod"
    assert web.access_type == "web"
    assert web.remote is True


def _minimal_target(home: Path, *, boundary: bool = False) -> None:
    data = _state.default_config()
    data["aws"]["region"] = "us-east-1"
    data["accounts"]["Prod"] = {"id": "123456789012", "partition": "aws"}
    if boundary:
        data["boundaries"]["Guard"] = {
            "role_arn": "arn:aws:iam::123456789012:role/guard",
            "account": "Prod",
            "verified": False,
        }
    data["targets"]["Prod"] = {
        "source_account": "Prod",
        "source_profile": "default",
        "source_directory": str(home / "aws"),
        **({"boundary": "Guard"} if boundary else {}),
    }
    _state.save_config(data)


def _browser_login_files(config: Path, cache: Path, profile: str) -> Path:
    login_session = "arn:aws:iam::123456789012:user/dev"
    parser = _sessions._read_ini(config)
    parser[_sessions._section(profile, config=True)] = {
        "login_session": login_session,
        "region": "us-east-1",
    }
    _sessions._write_ini(config, parser)
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / f"{_state.digest(login_session.encode())}.json"
    path.write_text(
        json.dumps(
            {
                "accessToken": {
                    "accessKeyId": "access",
                    "secretAccessKey": "secret",
                    "sessionToken": "token",
                    "accountId": "123456789012",
                    "expiresAt": "2030-01-01T00:00:00Z",
                },
                "refreshToken": "refresh",
                "clientId": "client",
                "dpopKey": "dpop-generation",
            }
        ),
        encoding="utf-8",
    )
    return path


def test_remote_name_listing_failure_is_only_same_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    session = MagicMock()
    sts = MagicMock()
    sts.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/test",
    }
    iam = MagicMock()
    iam.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "no list"}}, "ListPolicies"
    )
    session.client.side_effect = lambda service: {"sts": sts, "iam": iam}[service]
    resolved = _policies.resolve(
        "Named",
        account_id="123456789012",
        partition="aws",
        session=session,
    )
    assert resolved.arn == "arn:aws:iam::123456789012:policy/Named"
    with pytest.raises(_configs.OperationalError, match="authenticated resolver"):
        _policies.resolve(
            "Other",
            account_id="999999999999",
            partition="aws",
            session=session,
        )


def test_explicit_policy_arn_partition_must_match_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    with pytest.raises(_configs.OperationalError, match="partition"):
        _policies.resolve(
            "arn:aws-cn:iam::123456789012:policy/X",
            account_id="123456789012",
            partition="aws",
        )


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--policy", "Read"),
        ("--duration", "1h"),
        ("--account", "Prod"),
        ("--external-id", "id"),
        ("--session-name", "name"),
    ],
)
def test_unbounded_target_role_operands_fail_before_browser_auth(
    flag: str,
    value: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    _minimal_target(tmp_path)
    with patch("hacksaws._sessions._aws_login") as aws_login:
        result = _cli.console_main(["web", "in", "+Prod", flag, value])
    if flag == "--duration":
        assert result.exit_code == 1
    else:
        assert result.code == "ARGUMENT_ERROR"
        assert result.exit_code == _configs.EXIT_USAGE
    aws_login.assert_not_called()


@pytest.mark.parametrize(
    "arguments",
    [
        ["--role", "Other"],
        ["--policy", "Read"],
        ["--account", "Prod"],
        ["--external-id", "id"],
        ["--session-name", "name"],
        ["--to", "default:other"],
        ["--boundary", "Other"],
    ],
)
def test_bounded_target_rejects_security_overrides(
    arguments: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    _minimal_target(tmp_path, boundary=True)
    result = _cli.console_main(["web", "in", "+Prod", *arguments])
    assert result.code == "ARGUMENT_ERROR"
    assert result.exit_code == _configs.EXIT_USAGE


def test_unbounded_target_may_add_named_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    _minimal_target(tmp_path, boundary=True)
    data = _state.load_config()
    data["targets"]["Prod"].pop("boundary")
    _state.save_config(data)
    namespace = _cli._create_parser().parse_args(
        ["web", "in", "+Prod", "--boundary", "Guard"]
    )
    _cli._validate_login(namespace)


def test_ecr_partial_success_is_journaled_and_rolled_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    journal = _sessions._begin([])
    context = MagicMock()
    context.container_engine = "docker"
    account = _configs.AwsAccount(
        {"Account": "123456789012"}, "us-east-1", ("us-west-2",)
    )
    first = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
    with (
        patch(
            "hacksaws._ecr._do_login",
            side_effect=[first, _configs.OperationalError("second failed")],
        ),
        patch("hacksaws._ecr._run_container_engine") as engine,
    ):
        try:
            with pytest.raises(_configs.OperationalError, match="second failed"):
                _ecr.login_with_session(
                    context,
                    account,
                    MagicMock(),
                    on_success=lambda registry: _sessions._record_ecr_in_journal(
                        journal, "docker", registry
                    ),
                )
        finally:
            _sessions._rollback(journal)
    engine.assert_called_once_with("docker", ["docker", "logout", first], check=False)


def test_relogin_reads_original_source_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    aws_dir = tmp_path / "aws"
    aws_dir.mkdir()
    original_credentials = (
        b"[dev]\naws_access_key_id = ORIGINAL\naws_secret_access_key = secret\n"
    )
    original_config = b"[profile dev]\nmfa_serial = arn:aws:iam::123456789012:mfa/dev\n"
    (aws_dir / "credentials").write_text(
        "[dev]\naws_access_key_id = CURRENT\naws_secret_access_key = boundary\n",
        encoding="utf-8",
    )
    (aws_dir / "config").write_bytes(original_config)
    _state.save_sessions(
        {
            f"{aws_dir.absolute()}::dev": {
                "backup": [
                    {
                        "path": str(aws_dir / "credentials"),
                        "exists": True,
                        "data": __import__("base64")
                        .b64encode(original_credentials)
                        .decode(),
                    },
                    {
                        "path": str(aws_dir / "config"),
                        "exists": True,
                        "data": __import__("base64")
                        .b64encode(original_config)
                        .decode(),
                    },
                ]
            }
        }
    )
    with patch("boto3.Session") as session_factory:
        _sessions._persistent_source(aws_dir, "dev")
    assert session_factory.call_args.kwargs["aws_access_key_id"] == "ORIGINAL"


def test_native_browser_cache_is_removed_after_identity_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    _minimal_target(tmp_path)
    cache_root = tmp_path / "aws" / "login" / "cache"
    cache_file = cache_root / (
        f"{_state.digest(b'arn:aws:iam::123456789012:user/dev')}.json"
    )
    monkeypatch.setenv("AWS_LOGIN_CACHE_DIRECTORY", str(cache_root))

    def fake_login(
        config: Path,
        _credentials: Path,
        profile: str,
        *,
        remote: bool,
        login_cache: Path,
        region_name: str,
    ) -> None:
        del remote
        assert region_name == "us-east-1"
        assert _browser_login_files(config, login_cache, profile) == cache_file

    namespace = _cli._create_parser().parse_args(["web", "in", "+Prod"])
    _cli._validate_login(namespace)
    with (
        patch("hacksaws._sessions._aws_login", side_effect=fake_login),
        patch("boto3.Session", return_value=MagicMock()),
        patch(
            "hacksaws._sessions._identity",
            side_effect=_configs.OperationalError("identity failed"),
        ),
        pytest.raises(_configs.OperationalError, match="identity failed"),
    ):
        _sessions.browser_login(_configs.Context(namespace))
    assert not cache_file.exists()


def test_import_rejects_extra_and_corrupt_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    _state.save_config(_state.default_config())
    archive = _sessions.export_config(str(tmp_path / "export.zip"))
    with zipfile.ZipFile(archive, "a") as zipped:
        zipped.writestr("unexpected.txt", b"extra")
    with pytest.raises(_configs.OperationalError, match="member set"):
        _sessions.import_config(archive, replace=False, yes=False)

    clean = _sessions.export_config(str(tmp_path / "clean.zip"))
    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(clean, "a") as zipped,
    ):
        zipped.writestr("config.json", b"{}")
    with pytest.raises(_configs.OperationalError, match="duplicate"):
        _sessions.import_config(clean, replace=False, yes=False)


def _archive_payloads(archive: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(archive) as zipped:
        return {name: zipped.read(name) for name in zipped.namelist()}


def _write_archive(archive: Path, payloads: dict[str, bytes]) -> None:
    with zipfile.ZipFile(archive, "w") as zipped:
        for name, content in payloads.items():
            zipped.writestr(name, content)


def test_import_manifest_schema_version_rejects_boolean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    _state.save_config(_state.default_config())
    payloads = _archive_payloads(_sessions.export_config(str(tmp_path / "clean.zip")))
    manifest = json.loads(payloads["manifest.json"])
    manifest["schema_version"] = True
    payloads["manifest.json"] = json.dumps(manifest).encode()
    attack = tmp_path / "boolean-version.zip"
    _write_archive(attack, payloads)

    with pytest.raises(_configs.OperationalError, match="manifest schema"):
        _sessions.import_config(attack, replace=False, yes=False)


def test_import_rejects_ambient_absolute_boundary_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    _state.save_config(_state.default_config())
    payloads = _archive_payloads(_sessions.export_config(str(tmp_path / "clean.zip")))
    imported = json.loads(payloads["config.json"])
    imported["accounts"]["Prod"] = {"id": "123456789012", "partition": "aws"}
    imported["boundaries"]["Ambient"] = {
        "role_arn": "arn:aws:iam::123456789012:role/ambient",
        "account": "Prod",
        "policy": "C:/preexisting/ambient-policy.yaml",
        "verified": False,
    }
    payloads["config.json"] = json.dumps(imported).encode()
    manifest = json.loads(payloads["manifest.json"])
    manifest["files"]["config.json"] = _state.digest(payloads["config.json"])
    payloads["manifest.json"] = json.dumps(manifest).encode()
    attack = tmp_path / "ambient-policy.zip"
    _write_archive(attack, payloads)

    with pytest.raises(_configs.OperationalError, match="non-portable policy"):
        _sessions.import_config(attack, replace=False, yes=False)


def test_import_policy_content_conflict_is_atomic_and_replaceable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    allow = tmp_path / "allow.yaml"
    allow.write_text(
        'Version: "2012-10-17"\nStatement:\n- Effect: Allow\n'
        '  Action: s3:GetObject\n  Resource: "*"\n',
        encoding="utf-8",
    )
    deny = tmp_path / "deny.yaml"
    deny.write_text(
        'Version: "2012-10-17"\nStatement:\n- Effect: Deny\n'
        '  Action: s3:GetObject\n  Resource: "*"\n',
        encoding="utf-8",
    )

    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "source"))
    _policies.add_stored("Guard", allow)
    archive = _sessions.export_config(str(tmp_path / "policies.zip"))
    imported_policy = _archive_payloads(archive)["stored_session_policies/Guard.yaml"]

    destination = tmp_path / "destination"
    monkeypatch.setenv("HACKSAWS_HOME", str(destination))
    _policies.add_stored("Guard", deny)
    destination_policy = _policies.stored_directory() / "Guard.yaml"
    original_policy = destination_policy.read_bytes()
    original_config = (destination / "config.json").read_bytes()

    with pytest.raises(_configs.OperationalError, match="policy-content:Guard"):
        _sessions.import_config(archive, replace=False, yes=False)
    assert destination_policy.read_bytes() == original_policy
    assert (destination / "config.json").read_bytes() == original_config

    with (
        patch("hacksaws._state.save_config", side_effect=OSError("injected")),
        pytest.raises(OSError, match="injected"),
    ):
        _sessions.import_config(archive, replace=True, yes=True)
    assert destination_policy.read_bytes() == original_policy
    assert (destination / "config.json").read_bytes() == original_config

    _sessions.import_config(archive, replace=True, yes=True)
    assert destination_policy.read_bytes() == imported_policy
    assert _state.load_config()["policies"]["Guard"] == {
        "file": "stored_session_policies/Guard.yaml"
    }


def test_import_write_failure_rolls_back_config_and_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_home = tmp_path / "source"
    monkeypatch.setenv("HACKSAWS_HOME", str(source_home))
    policy = tmp_path / "p.yaml"
    policy.write_text('Version: "2012-10-17"\nStatement: []\n', encoding="utf-8")
    _policies.add_stored("Read", policy)
    archive = _sessions.export_config(str(tmp_path / "export.zip"))

    destination = tmp_path / "destination"
    monkeypatch.setenv("HACKSAWS_HOME", str(destination))
    _state.save_config(_state.default_config())
    original = (destination / "config.json").read_bytes()
    real_write = _state.atomic_write
    failed = False

    def fail_config_once(path: Path, data: bytes) -> None:
        nonlocal failed
        if path.name == "config.json" and not failed:
            failed = True
            raise OSError("injected")
        real_write(path, data)

    with (
        patch("hacksaws._state.atomic_write", side_effect=fail_config_once),
        pytest.raises(OSError, match="injected"),
    ):
        _sessions.import_config(archive, replace=False, yes=False)
    assert (destination / "config.json").read_bytes() == original
    assert not (_policies.stored_directory() / "Read.yaml").exists()


def test_remote_check_restores_environment_and_fails_unverifiable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("AWS_CONFIG_FILE", "original-config")
    _minimal_target(tmp_path)
    args = argparse.Namespace(
        remote=True,
        probe=False,
        profile="default",
        target="+Prod",
        account=None,
    )
    with (
        patch(
            "hacksaws._sessions._identity",
            side_effect=_configs.OperationalError("offline"),
        ),
        patch("boto3.Session", return_value=MagicMock()),
    ):
        report = _sessions.check_config(args)
    assert report["ok"] is False
    assert "unverifiable" in report["errors"][0]
    assert __import__("os").environ["AWS_CONFIG_FILE"] == "original-config"


def test_cascade_yes_deletes_dependents_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    _minimal_target(tmp_path, boundary=True)
    result = _cli.console_main(["account", "remove", "Prod", "--cascade", "--yes"])
    assert result.exit_code == 0
    data = _state.load_config()
    assert data["accounts"] == {}
    assert data["boundaries"] == {}
    assert data["targets"] == {}


def test_schema_rejects_unknown_policy_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    data = _state.default_config()
    data["policies"]["Read"] = {
        "file": "stored_session_policies/Read.yaml",
        "injected": True,
    }
    with pytest.raises(_configs.OperationalError, match="Unknown policy"):
        _state.save_config(data)


def test_resource_rename_rolls_back_session_on_config_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    data = _state.default_config()
    data["accounts"]["Prod"] = {"id": "123456789012", "partition": "aws"}
    _state.save_config(data)
    _state.save_sessions({"dest": {"target_account": "Prod", "backup": [], "ecr": []}})
    with (
        patch("hacksaws._state.save_config", side_effect=OSError("injected")),
        pytest.raises(OSError, match="injected"),
    ):
        _cli._run_resource(
            argparse.Namespace(
                access_type="account",
                resource_action="rename",
                resource_name="Prod",
                new_name="Production",
            )
        )
    assert "Prod" in _state.load_config()["accounts"]
    assert _state.load_sessions()["dest"]["target_account"] == "Prod"


def test_assume_role_enforces_known_role_maximum() -> None:
    session = MagicMock()
    session.get_credentials.return_value = MagicMock(token=None)
    iam = MagicMock()
    iam.get_role.return_value = {"Role": {"MaxSessionDuration": 1800}}
    session.client.return_value = iam
    args = argparse.Namespace(
        duration="1h",
        htl=None,
        mtl=None,
        stl=None,
        session_name=None,
    )
    with pytest.raises(_configs.OperationalError, match="MaxSessionDuration"):
        _sessions._assume(
            session,
            "arn:aws:iam::123456789012:role/read",
            policy=None,
            source_profile="default",
            args=args,
            target={},
            external_id=None,
            boundary_name=None,
        )


def test_expanded_mfa_write_failure_restores_existing_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    aws_dir = tmp_path / "aws"
    aws_dir.mkdir()
    credentials = aws_dir / "credentials"
    config = aws_dir / "config"
    credentials.write_text(
        "[dev]\naws_access_key_id = ORIGINAL\naws_secret_access_key = secret\n",
        encoding="utf-8",
    )
    config.write_text(
        "[profile dev]\nmfa_serial = arn:aws:iam::123456789012:mfa/dev\n",
        encoding="utf-8",
    )
    original_credentials = credentials.read_bytes()
    original_config = config.read_bytes()
    namespace = _cli._create_parser().parse_args(
        [
            "mfa",
            "in",
            "dev",
            "123456",
            "--directory",
            str(aws_dir),
            "--role",
            "arn:aws:iam::123456789012:role/read",
            "--region",
            "us-east-1",
        ]
    )
    _cli._validate_login(namespace)
    raw = MagicMock()
    intermediate = MagicMock(region_name="us-east-1")
    final = {
        "AccessKeyId": "FINAL",
        "SecretAccessKey": "final-secret",
        "SessionToken": "final-token",
    }
    with (
        patch("hacksaws._sessions._persistent_source", return_value=(raw, MagicMock())),
        patch(
            "hacksaws._sessions._identity",
            return_value=("123456789012", "aws", "arn:aws:iam::123456789012:user/dev"),
        ),
        patch("hacksaws._sessions._mfa_session", return_value=intermediate),
        patch(
            "hacksaws._sessions._assume",
            return_value=(final, {"target_account": "123456789012"}),
        ),
        patch(
            "hacksaws._sessions._copy_region",
            side_effect=_configs.OperationalError("config write failed"),
        ),
        pytest.raises(_configs.OperationalError, match="config write failed"),
    ):
        _sessions.mfa_login(_configs.Context(namespace))
    assert credentials.read_bytes() == original_credentials
    assert config.read_bytes() == original_config
    assert not _sessions._journal_path().exists()


def test_bounded_browser_ecr_is_cleaned_when_assume_role_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    _minimal_target(tmp_path, boundary=True)
    namespace = _cli._create_parser().parse_args(["web", "in", "+Prod", "--ecr"])
    _cli._validate_login(namespace)
    registry = "123456789012.dkr.ecr.us-east-1.amazonaws.com"

    def ecr_login(
        context: object,
        account: object,
        session: object,
        *,
        on_success: object,
    ) -> list[str]:
        on_success(registry)  # type: ignore[operator]
        return [registry]

    def browser_login(
        config: Path,
        _credentials: Path,
        profile: str,
        *,
        remote: bool,
        login_cache: Path,
        region_name: str,
    ) -> None:
        del remote
        assert region_name == "us-east-1"
        _browser_login_files(config, login_cache, profile)

    with (
        patch("hacksaws._sessions._aws_login", side_effect=browser_login),
        patch("boto3.Session", return_value=MagicMock(region_name="us-east-1")),
        patch(
            "hacksaws._sessions._identity",
            return_value=("123456789012", "aws", "arn:aws:iam::123456789012:user/dev"),
        ),
        patch("hacksaws._ecr.login_with_session", side_effect=ecr_login),
        patch(
            "hacksaws._sessions._assume",
            side_effect=_configs.OperationalError("assume failed"),
        ),
        patch("hacksaws._ecr._run_container_engine") as engine,
        pytest.raises(_configs.OperationalError, match="assume failed"),
    ):
        _sessions.browser_login(_configs.Context(namespace))
    engine.assert_called_once_with(
        "docker", ["docker", "logout", registry], check=False
    )


def test_logout_cleans_ecr_by_default_and_keep_ecr_retains_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    aws_dir = tmp_path / "aws"
    registry = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
    key = f"{aws_dir.absolute()}::dev"
    _state.save_sessions(
        {
            key: {
                "destination": str(aws_dir.absolute()),
                "profile": "dev",
                "auth_method": "mfa",
                "backup": [],
                "ecr": [registry],
            }
        }
    )
    args = argparse.Namespace(
        target=None,
        directory=str(aws_dir),
        profile="dev",
        aws_account_name=None,
        to=None,
        to_directory=None,
        ecr=False,
        podman=False,
        keep_ecr=True,
    )
    assert _sessions.logout(_configs.Context(args)) is True
    assert _state.load_sessions()[key]["auth_method"] == "ecr-only"
    args.keep_ecr = False
    with patch("hacksaws._ecr._run_container_engine") as engine:
        assert _sessions.logout(_configs.Context(args)) is True
    engine.assert_called_once_with("docker", ["docker", "logout", registry])
    assert _state.load_sessions() == {}


@pytest.mark.parametrize(
    ("mutator", "match"),
    [
        (lambda data: data["cache"].update(max_age=True), "max_age"),
        (
            lambda data: data["accounts"].update(
                Prod={"id": 123456789012, "partition": "aws"}
            ),
            "12-digit",
        ),
        (
            lambda data: data["accounts"].update(
                Prod={"id": "123456789012", "partition": 7}
            ),
            "partition",
        ),
        (
            lambda data: data.update(
                accounts={"Prod": {"id": "123456789012", "partition": "aws"}},
                targets={
                    "Bad": {
                        "source_account": "Prod",
                        "source_profile": "default",
                        "source_location": 7,
                    }
                },
            ),
            "source_location",
        ),
        (
            lambda data: data.update(
                accounts={"Prod": {"id": "123456789012", "partition": "aws"}},
                boundaries={
                    "Bad": {
                        "role_arn": "arn:aws:iam::123456789012:role/read",
                        "account": "Prod",
                        "duration": True,
                    }
                },
            ),
            "duration",
        ),
    ],
)
def test_schema_rejects_coerced_or_boolean_types(
    mutator: object,
    match: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    data = _state.default_config()
    mutator(data)  # type: ignore[operator]
    with pytest.raises(_configs.OperationalError, match=match):
        _state.save_config(data)


def test_boundary_role_arn_must_match_referenced_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    data = _state.default_config()
    data["accounts"]["China"] = {
        "id": "123456789012",
        "partition": "aws-cn",
    }
    data["boundaries"]["Bad"] = {
        "role_arn": "arn:aws:iam::123456789012:role/team/read",
        "account": "China",
    }
    with pytest.raises(_configs.OperationalError, match="does not match"):
        _state.save_config(data)
    data["boundaries"]["Bad"]["role_arn"] = (
        "arn:aws-cn:iam::123456789012:role/team/read"
    )
    _state.save_config(data)
    data["accounts"]["Other"] = {"id": "999999999999", "partition": "aws-cn"}
    with pytest.raises(_configs.OperationalError, match="does not match"):
        _state.update_resource(data, "boundary", "Bad", {"account": "Other"})


def test_remote_check_does_not_scope_same_id_other_partition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    data = _state.default_config()
    data["accounts"]["China"] = {
        "id": "123456789012",
        "partition": "aws-cn",
    }
    data["boundaries"]["ChinaRole"] = {
        "role_arn": "arn:aws-cn:iam::123456789012:role/read",
        "account": "China",
    }
    _state.save_config(data)
    session = MagicMock()
    iam = MagicMock()
    session.client.return_value = iam
    args = argparse.Namespace(
        remote=True, probe=False, profile="default", target=None, account=None
    )
    with (
        patch("boto3.Session", return_value=session),
        patch(
            "hacksaws._sessions._identity",
            return_value=(
                "123456789012",
                "aws",
                "arn:aws:iam::123456789012:user/test",
            ),
        ),
    ):
        report = _sessions.check_config(args)
    assert report["ok"] is True
    iam.get_role.assert_not_called()


def test_generic_rollback_does_not_snapshot_or_rewrite_cache_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    cache = tmp_path / "cache"
    cache.mkdir()
    modified = cache / "modified.json"
    deleted = cache / "deleted.json"
    created = cache / "created.json"
    modified.write_bytes(b"original-modified")
    deleted.write_bytes(b"original-deleted")
    journal = _sessions._begin([])
    modified.write_bytes(b"changed")
    deleted.unlink()
    created.write_bytes(b"new")
    _sessions._rollback(journal)
    assert modified.read_bytes() == b"changed"
    assert not deleted.exists()
    assert created.read_bytes() == b"new"


def test_import_rejects_manifest_declared_unused_junk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    _state.save_config(_state.default_config())
    clean = _sessions.export_config(str(tmp_path / "clean.zip"))
    with zipfile.ZipFile(clean) as archive:
        payloads = {name: archive.read(name) for name in archive.namelist()}
    manifest = json.loads(payloads["manifest.json"])
    payloads["junk.bin"] = b"attacker controlled"
    manifest["files"]["junk.bin"] = _state.digest(payloads["junk.bin"])
    payloads["manifest.json"] = json.dumps(manifest).encode()
    attack = tmp_path / "attack.zip"
    with zipfile.ZipFile(attack, "w") as archive:
        for name, content in payloads.items():
            archive.writestr(name, content)
    with pytest.raises(_configs.OperationalError, match="not referenced"):
        _sessions.import_config(attack, replace=False, yes=False)


def test_config_fix_repairs_policy_from_user_selected_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    data = _state.default_config()
    data["policies"]["Read"] = {"file": "stored_session_policies/Read.yaml"}
    _state.save_config(data)
    replacement = tmp_path / "replacement.yaml"
    replacement.write_text(
        '# preserved\nVersion: "2012-10-17"\nStatement: []\n', encoding="utf-8"
    )
    args = argparse.Namespace(account=None, yes=False)
    with (
        patch("sys.stdin.isatty", return_value=True),
        patch("builtins.input", side_effect=["repair", str(replacement)]),
    ):
        result = _sessions.fix_config(args)
    assert result.exit_code == 0
    assert (
        _policies.stored_directory() / "Read.yaml"
    ).read_bytes() == replacement.read_bytes()


@pytest.mark.parametrize(
    ("partition", "suffix"),
    [
        ("aws", "amazonaws.com"),
        ("aws-us-gov", "amazonaws.com"),
        ("aws-cn", "amazonaws.com.cn"),
    ],
)
def test_ecr_registry_dns_suffix_is_partition_aware(
    partition: str, suffix: str
) -> None:
    account = _configs.AwsAccount(
        {
            "Account": "123456789012",
            "Arn": f"arn:{partition}:iam::123456789012:user/test",
        },
        "cn-north-1" if partition == "aws-cn" else "us-east-1",
        (),
    )
    assert account.ecr_registries[0].endswith(suffix)


def test_ecr_regions_use_effective_primary_alias_and_ordered_canonical_dedupe() -> None:
    context = _configs.Context(
        argparse.Namespace(
            region="pacific",
            allow_unknown_region=False,
        )
    )
    account = _configs.AwsAccount(
        {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test",
        },
        "us-east-1",
        ("oregon", "virginia", "us-east-1"),
    )
    aliases = {"pacific": {"region": "us-west-2"}}

    with (
        patch("hacksaws._ecr._configured_region_aliases", return_value=aliases),
        patch(
            "hacksaws._ecr._regions.canonicalize_regions",
            wraps=_regions.canonicalize_regions,
        ) as canonicalize,
    ):
        assert _ecr._ecr_regions(context, account) == ("us-west-2", "us-east-1")

    assert canonicalize.call_args.kwargs["partition"] == "aws"
    assert canonicalize.call_args.kwargs["service"] == "ecr"


def test_ecr_region_partition_and_unknown_escape_are_strict(
    capsys: pytest.CaptureFixture[str],
) -> None:
    account = _configs.AwsAccount(
        {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test",
        },
        "us-east-1",
        (),
    )
    args = argparse.Namespace(region="future-west", allow_unknown_region=True)
    context = _configs.Context(args)
    with pytest.raises(_regions.RegionError, match="Unknown AWS region or alias"):
        _ecr._ecr_regions(context, account)

    args.region = "us-future-1"
    assert _ecr._ecr_regions(context, account) == ("us-future-1",)
    assert "service support cannot be verified" in capsys.readouterr().err

    args.region = "beijing"
    with pytest.raises(_regions.RegionError, match="Unknown AWS region or alias"):
        _ecr._ecr_regions(context, account)


def test_direct_policy_requires_role(capsys: pytest.CaptureFixture[str]) -> None:
    result = _cli.console_main(["mfa", "in", "dev", "123456", "--policy", "x"])
    assert result.code == "ARGUMENT_ERROR"
    assert result.exit_code == _configs.EXIT_USAGE
    assert "requires --role" in capsys.readouterr().err


def test_schema_crud_rename_and_ref_integrity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    data = _state.default_config()
    _state.add_resource(
        data, "account", "Prod", {"id": "123456789012", "partition": "aws"}
    )
    _state.add_resource(
        data,
        "boundary",
        "ReadOnly",
        {
            "role_arn": "arn:aws:iam::123456789012:role/read",
            "account": "Prod",
            "verified": False,
        },
    )
    _state.add_resource(
        data,
        "target",
        "Main",
        {
            "source_account": "Prod",
            "source_profile": "dev",
            "source_location": "default",
            "boundary": "ReadOnly",
        },
    )
    _state.rename_resource(data, "account", "prod", "Production")
    _state.rename_resource(data, "boundary", "readonly", "Audit")
    _state.save_config(data)
    loaded = _state.load_config()
    assert loaded["targets"]["Main"]["source_account"] == "Production"
    assert loaded["targets"]["Main"]["boundary"] == "Audit"
    with pytest.raises(_configs.OperationalError, match="referenced"):
        _state.remove_resource(loaded, "account", "Production")


def test_unknown_schema_fields_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    (tmp_path / "config.json").write_text(
        '{"schema_version":1,"surprise":true}', encoding="utf-8"
    )
    with pytest.raises(_configs.OperationalError, match="Unknown config"):
        _state.load_config()


@pytest.mark.parametrize("suffix", ["json", "yaml", "toml"])
def test_policy_formats_and_inline_size(
    suffix: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "home"))
    values = {
        "json": '{"Version":"2012-10-17","Statement":[]}',
        "yaml": 'Version: "2012-10-17"\nStatement: []\n',
        "toml": 'Version = "2012-10-17"\nStatement = []\n',
    }
    path = tmp_path / f"policy.{suffix}"
    path.write_text(values[suffix], encoding="utf-8")
    document, _ = _policies.parse_policy(path)
    assert document["Version"] == "2012-10-17"
    with pytest.raises(_configs.OperationalError, match="2048"):
        _policies.enforce_inline_limit("x" * 2049)


def test_export_import_promotes_external_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_home = tmp_path / "source"
    monkeypatch.setenv("HACKSAWS_HOME", str(source_home))
    external = tmp_path / "external.json"
    external.write_text('{"Version":"2012-10-17","Statement":[]}', encoding="utf-8")
    data = _state.default_config()
    data["accounts"]["Prod"] = {"id": "123456789012", "partition": "aws"}
    data["boundaries"]["Read"] = {
        "role_arn": "arn:aws:iam::123456789012:role/read",
        "account": "Prod",
        "policy": str(external),
        "verified": False,
    }
    _state.save_config(data)
    archive = _sessions.export_config(str(tmp_path / "portable.zip"))
    with zipfile.ZipFile(archive) as zipped:
        assert any(name.startswith("external_policies/") for name in zipped.namelist())

    destination_home = tmp_path / "destination"
    monkeypatch.setenv("HACKSAWS_HOME", str(destination_home))
    _sessions.import_config(archive, replace=False, yes=False)
    imported = _state.load_config()
    policy_name = imported["boundaries"]["Read"]["policy"]
    assert policy_name in imported["policies"]
    assert (_policies.stored_directory() / f"{policy_name}.yaml").is_file()


def test_status_never_exposes_backup_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    _state.save_sessions(
        {
            "dest": {
                "profile": "prod",
                "auth_method": "mfa",
                "backup": [{"data": "SECRET"}],
            }
        }
    )
    assert "SECRET" not in json.dumps(_sessions.status())
