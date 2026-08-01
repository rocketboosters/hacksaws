"""Safety coverage for the non-CI live IAM smoke harness."""

from __future__ import annotations

import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_live_smoke_refuses_without_both_required_environment_guards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HACKSAWS_LIVE_AWS", raising=False)
    monkeypatch.delenv("HACKSAWS_LIVE_AWS_ACCOUNT_ID", raising=False)
    script = Path(__file__).parent / "scripts" / "live_iam_smoke.py"
    namespace = runpy.run_path(str(script))
    with pytest.raises(SystemExit, match="Refusing live AWS smoke test"):
        namespace["main"]()


def test_live_smoke_executes_account_scoped_lifecycle_and_valid_cleanup_selector(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HACKSAWS_LIVE_AWS", "1")
    monkeypatch.setenv("HACKSAWS_LIVE_AWS_ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("HACKSAWS_LIVE_AWS_CLEANUP", "1")
    monkeypatch.setenv("HACKSAWS_LIVE_AWS_TARGET", "smoke")
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
    assert len(commands) == 7
    assert len(cleanup_commands) == 2
    assert cleanup_commands[0][1:3] == ["--smoke-run", cleanup_commands[1][2]]
    assert "--dry-run" in cleanup_commands[0]
    assert "--yes" in cleanup_commands[1]
    assert all("--target" in command and "smoke" in command for command in commands)
    assert "Verified lifecycle and absence" in output
