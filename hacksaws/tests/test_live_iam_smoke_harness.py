"""Safety coverage for the non-CI live IAM smoke harness."""

from __future__ import annotations

import runpy
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.mark.parametrize(
    "missing",
    [
        "HACKSAWS_LIVE_AWS",
        "HACKSAWS_LIVE_AWS_ACCOUNT_ID",
        "HACKSAWS_LIVE_AWS_CLEANUP",
        "HACKSAWS_LIVE_AWS_TARGET",
    ],
)
def test_live_smoke_refuses_without_every_required_environment_guard(
    missing: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HACKSAWS_LIVE_AWS", "1")
    monkeypatch.setenv("HACKSAWS_LIVE_AWS_ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("HACKSAWS_LIVE_AWS_CLEANUP", "1")
    monkeypatch.setenv("HACKSAWS_LIVE_AWS_TARGET", "smoke")
    monkeypatch.delenv(missing)
    script = Path(__file__).parent / "scripts" / "live_iam_smoke.py"
    namespace = runpy.run_path(str(script))
    with pytest.raises(SystemExit, match="Refusing live AWS smoke test"):
        namespace["main"]()


def test_live_smoke_refuses_malformed_or_mismatched_account_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key, value in {
        "HACKSAWS_LIVE_AWS": "1",
        "HACKSAWS_LIVE_AWS_ACCOUNT_ID": "invalid",
        "HACKSAWS_LIVE_AWS_CLEANUP": "1",
        "HACKSAWS_LIVE_AWS_TARGET": "smoke",
    }.items():
        monkeypatch.setenv(key, value)
    namespace = runpy.run_path(
        str(Path(__file__).parent / "scripts" / "live_iam_smoke.py")
    )
    with pytest.raises(SystemExit, match="12-digit"):
        namespace["main"]()

    monkeypatch.setenv("HACKSAWS_LIVE_AWS_ACCOUNT_ID", "123456789012")
    monkeypatch.setattr(
        namespace["_iam_cli"].IamCommandContext,
        "create",
        lambda _args: SimpleNamespace(account_id="210987654321"),
    )
    with pytest.raises(SystemExit, match="Refusing account"):
        namespace["main"]()


def test_live_smoke_resolves_guarded_source_and_secret_free_fingerprints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = runpy.run_path(
        str(Path(__file__).parent / "scripts" / "live_iam_smoke.py")
    )
    configured = {"source_location": "horizon", "source_profile": "."}
    monkeypatch.setattr(namespace["_state"], "load_config", dict)
    monkeypatch.setattr(
        namespace["_state"],
        "get_resource",
        lambda _data, _kind, name: (name, configured),
    )
    monkeypatch.setattr(
        namespace["_state"], "aws_directory", lambda _name: tmp_path / "logical"
    )
    assert namespace["_guarded_source"]("+smoke") == (
        tmp_path / "logical",
        "default",
    )

    configured.clear()
    configured.update(
        source_directory=str(tmp_path / "explicit"), source_profile="admin"
    )
    assert namespace["_guarded_source"]("smoke") == (
        (tmp_path / "explicit").absolute(),
        "admin",
    )
    missing = tmp_path / "missing"
    assert namespace["_fingerprint"](missing) == (False, None)
    monkeypatch.setattr(
        namespace["_state"],
        "load_sessions",
        lambda: {
            f"{tmp_path.absolute()}::admin": {
                "profile": "admin",
                "destination": str(tmp_path),
            }
        },
    )
    assert namespace["_session_fingerprint"](tmp_path, "admin") is not None


def test_live_smoke_executes_account_scoped_lifecycle_and_valid_cleanup_selector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HACKSAWS_LIVE_AWS", "1")
    monkeypatch.setenv("HACKSAWS_LIVE_AWS_ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("HACKSAWS_LIVE_AWS_CLEANUP", "1")
    monkeypatch.setenv("HACKSAWS_LIVE_AWS_TARGET", "smoke")
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "hacksaws"))
    script = Path(__file__).parent / "scripts" / "live_iam_smoke.py"
    namespace = runpy.run_path(str(script))
    commands: list[list[str]] = []

    class Iam:
        def tag_role(self, **_kwargs: object) -> None:
            return None

        def tag_policy(self, **_kwargs: object) -> None:
            return None

        def get_role(self, **_kwargs: object) -> None:
            raise namespace["ClientError"](
                {"Error": {"Code": "NoSuchEntity", "Message": "gone"}}, "GetRole"
            )

        def get_policy(self, **_kwargs: object) -> None:
            raise namespace["ClientError"](
                {"Error": {"Code": "NoSuchEntity", "Message": "gone"}},
                "GetPolicy",
            )

    def run(arguments: list[str]) -> None:
        commands.append(arguments)

    monkeypatch.setitem(namespace["main"].__globals__, "_run", run)
    source = tmp_path / "source"
    source.mkdir()
    (source / "credentials").write_text("source-credentials", encoding="utf-8")
    (source / "config").write_text("source-config", encoding="utf-8")
    source_before = {
        path: path.read_bytes() for path in (source / "credentials", source / "config")
    }
    monkeypatch.setitem(
        namespace["main"].__globals__,
        "_guarded_source",
        lambda _target: (source, "admin"),
    )
    monkeypatch.setitem(
        namespace["main"].__globals__,
        "_verify_assumed_identity",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        namespace["_iam_cli"].IamCommandContext,
        "create",
        lambda _args: SimpleNamespace(
            account_id="123456789012", partition="aws", iam=Iam()
        ),
    )
    assert namespace["main"]() == 0
    output = capsys.readouterr().out
    cleanup_commands = [command for command in commands if command[0] == "cleanup"]
    assume = next(command for command in commands if command[0] == "assume")
    logout = next(command for command in commands if command[0] == "logout")
    assert len(commands) == 9
    assert len(cleanup_commands) == 2
    assert cleanup_commands[0][1:3] == ["--smoke-run", cleanup_commands[1][2]]
    assert "--dry-run" in cleanup_commands[0]
    assert "--yes" in cleanup_commands[1]
    guarded_commands = [
        command for command in commands if command[0] in {"iam", "cleanup"}
    ]
    assert all(
        "--target" in command and "smoke" in command for command in guarded_commands
    )
    assert assume[1:4] == ["admin", "--directory", str(source)]
    assert "--to-directory" in assume
    assert "--to-profile" in assume
    assert "--keep-source" in assume
    assert "--duration" in assume
    assert assume[assume.index("--duration") + 1] == "15m"
    assert assume[assume.index("--role") + 1].startswith(
        "arn:aws:iam::123456789012:role/hacksaws-test/HacksawsSmokeRole"
    )
    assert assume[assume.index("--policy") + 1].endswith("inline-policy.json")
    destination = assume[assume.index("--to-directory") + 1]
    profile = assume[assume.index("--to-profile") + 1]
    assert logout == ["logout", profile, "--directory", destination]
    assert {
        path: path.read_bytes() for path in (source / "credentials", source / "config")
    } == source_before
    assert "Verified lifecycle and absence" in output


def test_live_smoke_failure_logs_out_destination_and_still_cleans_iam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_LIVE_AWS", "1")
    monkeypatch.setenv("HACKSAWS_LIVE_AWS_ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("HACKSAWS_LIVE_AWS_CLEANUP", "1")
    monkeypatch.setenv("HACKSAWS_LIVE_AWS_TARGET", "smoke")
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "hacksaws"))
    namespace = runpy.run_path(
        str(Path(__file__).parent / "scripts" / "live_iam_smoke.py")
    )
    commands: list[list[str]] = []
    source = tmp_path / "source"
    source.mkdir()
    (source / "credentials").write_text("source-credentials", encoding="utf-8")
    (source / "config").write_text("source-config", encoding="utf-8")

    class Iam:
        def tag_role(self, **_kwargs: object) -> None:
            return None

        def tag_policy(self, **_kwargs: object) -> None:
            return None

        def get_role(self, **_kwargs: object) -> None:
            raise namespace["ClientError"](
                {"Error": {"Code": "NoSuchEntity", "Message": "gone"}}, "GetRole"
            )

        def get_policy(self, **_kwargs: object) -> None:
            raise namespace["ClientError"](
                {"Error": {"Code": "NoSuchEntity", "Message": "gone"}},
                "GetPolicy",
            )

    def run(arguments: list[str]) -> None:
        commands.append(arguments)

    monkeypatch.setitem(namespace["main"].__globals__, "_run", run)
    monkeypatch.setitem(
        namespace["main"].__globals__,
        "_guarded_source",
        lambda _target: (source, "admin"),
    )
    monkeypatch.setitem(
        namespace["main"].__globals__,
        "_verify_assumed_identity",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("identity mismatch")),
    )
    monkeypatch.setattr(
        namespace["_iam_cli"].IamCommandContext,
        "create",
        lambda _args: SimpleNamespace(
            account_id="123456789012", partition="aws", iam=Iam()
        ),
    )

    with pytest.raises(RuntimeError, match="identity mismatch"):
        namespace["main"]()

    assume_index = next(
        i for i, command in enumerate(commands) if command[0] == "assume"
    )
    logout_index = next(
        i for i, command in enumerate(commands) if command[0] == "logout"
    )
    emergency = commands[-1]
    assert assume_index < logout_index
    assert emergency[0:1] == ["cleanup"]
    assert "--cascade" in emergency
    assert "--yes" in emergency
    assert any(value.startswith("HacksawsSmokeRole") for value in emergency)
    assert (source / "credentials").read_text(encoding="utf-8") == "source-credentials"
    assert (source / "config").read_text(encoding="utf-8") == "source-config"


def test_live_smoke_assumed_identity_verification_is_exact_and_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = runpy.run_path(
        str(Path(__file__).parent / "scripts" / "live_iam_smoke.py")
    )
    destination = tmp_path / "destination"
    sts = MagicMock()
    sts.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": ("arn:aws:sts::123456789012:assumed-role/HacksawsSmokeRoleabc/session"),
    }
    session = MagicMock()
    session.client.return_value = sts
    environment = MagicMock(return_value=nullcontext())
    monkeypatch.setattr(namespace["boto3"], "Session", MagicMock(return_value=session))
    monkeypatch.setattr(namespace["_sessions"], "_aws_environment", environment)

    namespace["_verify_assumed_identity"](
        destination,
        "assumed",
        "123456789012",
        "aws",
        "HacksawsSmokeRoleabc",
    )
    environment.assert_called_once_with(
        destination / "config",
        destination / "credentials",
        destination / "login" / "cache",
    )

    sts.get_caller_identity.return_value["Arn"] = (
        "arn:aws:sts::123456789012:assumed-role/Other/session"
    )
    with pytest.raises(RuntimeError, match="identity mismatch"):
        namespace["_verify_assumed_identity"](
            destination,
            "assumed",
            "123456789012",
            "aws",
            "HacksawsSmokeRoleabc",
        )
