"""Focused coverage for shared presentation and schema-one UX foundations."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from hacksaws import _cli
from hacksaws import _configs
from hacksaws import _output
from hacksaws import _state


class _NotATerminal:
    def isatty(self) -> bool:
        return False


class _Terminal:
    @staticmethod
    def isatty() -> bool:
        return True


def test_color_policy_handles_windows_style_non_tty_no_color_and_json() -> None:
    automatic = _output.OutputOptions(color="auto")
    assert not _output.color_enabled(automatic, stream=_NotATerminal(), environ={})
    assert not _output.color_enabled(
        automatic, stream=object(), environ={"NO_COLOR": "1"}
    )
    assert _output.color_enabled(
        _output.OutputOptions(color="always"), stream=_NotATerminal(), environ={}
    )
    assert not _output.color_enabled(
        _output.OutputOptions(color="always", json=True),
        stream=_NotATerminal(),
        environ={},
    )
    table = _output.compact_table(["name"], [["value"]], title="Items")
    assert table.columns[0].header == "name"
    assert "ready" in _output.legend([("ready", "usable")]).plain
    with patch("builtins.input", return_value="yes"):
        assert _output.confirm("Continue?", stdin=_Terminal())
    assert not _output.confirm("Continue?", stdin=_NotATerminal())


def test_global_output_flags_work_anywhere_and_emit_a_stable_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    result = _cli.console_main(["status", "--no-color", "--json"])
    rendered = json.loads(capsys.readouterr().out)
    assert result.code == "STATUS"
    assert rendered == {
        "schemaVersion": 1,
        "ok": True,
        "code": "STATUS",
        "data": {"sessions": [], "counts": {}, "warnings": []},
    }


def test_global_json_wraps_argument_errors(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = _cli.console_main(["unknown-command", "--json"])
    rendered = json.loads(capsys.readouterr().err)
    assert result.exit_code == _configs.EXIT_USAGE
    assert rendered["schemaVersion"] == 1
    assert rendered["ok"] is False
    assert rendered["code"] == "ARGUMENT_ERROR"


def test_json_prescan_wraps_every_early_exit_once_and_preserves_human_help(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cases = [
        (["--color", "bogus", "--json"], "ARGUMENT_ERROR", False),
        (["--json", "--definitely-invalid"], "ARGUMENT_ERROR", False),
        (["--json"], "ACCESS_TYPE_HELP", False),
        (["mfa", "login", "--json"], "ARGUMENT_ERROR", False),
        (["--help", "--json"], "HELP", True),
    ]
    for arguments, code, ok in cases:
        result = _cli.console_main(arguments)
        captured = capsys.readouterr()
        assert captured.out == ""
        envelope = json.loads(captured.err)
        assert envelope["schemaVersion"] == 1
        assert envelope["ok"] is ok
        assert envelope["code"] == code
        assert result.code == code
        if arguments == ["--json"]:
            assert "usage: hacksaws" in envelope["error"]["data"]["help"]
        if arguments[:2] == ["mfa", "login"]:
            assert "usage: hacksaws" in envelope["error"]["data"]["usage"]
        if code == "HELP":
            assert "usage: hacksaws" in envelope["data"]["help"]

    human = _cli.console_main(["--help"])
    captured = capsys.readouterr()
    assert human.code == "HELP"
    assert captured.err == ""
    assert captured.out.startswith("usage: hacksaws")


def test_schema_one_foundation_defaults_and_naming_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    data = _state.default_config()
    assert data["schema_version"] == 1
    assert data["iam"]["path"] == "/hacksaws/"
    assert data["session"]["packed_policy_warning"] == 80
    assert data["session"]["packed_policy_enforcement"] == "off"
    data["naming"]["resources"]["role"] = {"prefix": "role-"}
    data["naming"]["accounts"]["Prod"] = {"case": "snake"}
    data["naming"]["account_resources"]["Prod"] = {"role": {"suffix": "-x"}}
    _state.save_config(data)
    assert _state.resolve_naming(
        _state.load_config(),
        resource="role",
        account="Prod",
        explicit={"prefix": "manual-"},
    ) == {
        "case": "snake",
        "prefix": "manual-",
        "suffix": "-x",
        "enforcement": "off",
    }


def test_config_option_commands_and_credential_selector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    assert (
        _cli.console_main(["config", "option", "set", "output.color", "never"]).code
        == "CONFIG_OPTION_SET"
    )
    result = _cli.console_main(["config", "option", "get", "output.color", "--json"])
    assert result.message == '"never"'
    assert (
        _cli.console_main(["config", "option", "reset", "output.color"]).code
        == "CONFIG_OPTION_RESET"
    )
    assert (
        _cli.console_main(
            ["config", "set", "naming.resources.role.prefix", "managed-"]
        ).code
        == "CONFIG_OPTION_SET"
    )
    assert _state.load_config()["naming"]["resources"]["role"]["prefix"] == "managed-"
    assert (
        _cli.console_main(["config", "reset", "naming.resources.role.prefix"]).code
        == "CONFIG_OPTION_RESET"
    )
    selector = _configs.resolve_credential_selector(
        argparse.Namespace(
            profile=None, location="west", directory=str(tmp_path), target="+Prod"
        )
    )
    assert selector.profile == "default"
    assert selector.location == "west"
    assert selector.directory == tmp_path.absolute()
    assert selector.target == "+Prod"


def test_remote_dry_run_skips_automatic_local_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    recovered: list[bool] = []
    monkeypatch.setattr(
        _cli._sessions, "recover_journal", lambda: recovered.append(True)
    )
    monkeypatch.setattr(
        _cli._iam_cli,
        "dispatch_root_cleanup",
        lambda _args: _configs.Result("IAM_CLEANUP_PLAN", "dry run"),
    )

    result = _cli.console_main(["cleanup", "--all", "--dry-run", "--no-color"])

    assert result.code == "IAM_CLEANUP_PLAN"
    assert recovered == []


def test_config_show_text_uses_domain_tables() -> None:
    data = _state.default_config()
    data["accounts"]["Prod"] = {"id": "123456789012", "partition": "aws"}
    data["boundaries"]["Read"] = {
        "account": "Prod",
        "role_arn": "arn:aws:iam::123456789012:role/Read",
        "policy": "Logs",
    }

    text = _cli._config_text(data)

    assert "Accounts\nNAME" in text
    assert "Boundaries\nNAME" in text
    assert "{'Prod':" not in text


def test_global_option_and_login_validation_edge_cases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _cli._extract_global_options(["status", "--", "--json"]) == (
        ["status", "--", "--json"],
        None,
        False,
    )
    assert _cli._extract_global_options(["--color=always", "status"]) == (
        ["status"],
        "always",
        False,
    )
    assert not _cli._json_requested(["status", "--", "--json"])
    for arguments in (
        ["--color", "sometimes"],
        ["--color=sometimes"],
        ["--color", "always", "--color", "never"],
        ["--color=always", "--no-color"],
    ):
        with pytest.raises(_configs.OperationalError):
            _cli._extract_global_options(arguments)

    defaults = {
        "profile": None,
        "target": None,
        "policy": None,
        "role": None,
        "boundary": None,
        "external_id": None,
        "session_name": None,
        "to": None,
        "to_directory": None,
        "to_profile": None,
        "aws_account_name": None,
        "account": None,
    }
    default_profile = argparse.Namespace(**{**defaults, "profile": "."})
    _cli._validate_login(default_profile)
    assert default_profile.profile == "default"
    invalid = (
        {"profile": "+x", "target": "+other"},
        {"profile": "+"},
        {"external_id": "secret"},
        {"to": "west:agent", "to_directory": str(tmp_path)},
        {"to_directory": str(tmp_path)},
        {"role": "Agent", "boundary": "Read"},
    )
    for changes in invalid:
        with pytest.raises(_configs.OperationalError):
            _cli._validate_login(argparse.Namespace(**{**defaults, **changes}))

    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    data = _state.default_config()
    data["accounts"]["Prod"] = {"id": "123456789012", "partition": "aws"}
    data["targets"]["Prod"] = {
        "source_account": "Prod",
        "source_profile": "admin",
        "source_location": "west",
    }
    _state.save_config(data)
    target = argparse.Namespace(**{**defaults, "target": "Prod"})
    _cli._validate_login(target)
    assert target.target == "+Prod"


def test_target_credential_session_and_scoped_config_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    source = tmp_path / "aws-source"
    data = _state.default_config()
    data["accounts"]["Prod"] = {"id": "123456789012", "partition": "aws"}
    data["policies"]["Logs"] = {"file": "stored_session_policies/Logs.yaml"}
    data["boundaries"]["Read"] = {
        "account": "Prod",
        "role_arn": "arn:aws:iam::123456789012:role/Read",
        "policy": "Logs",
    }
    data["targets"]["Agent"] = {
        "source_account": "Prod",
        "source_profile": "admin",
        "source_directory": str(source),
        "boundary": "Read",
    }
    _state.save_config(data)
    sentinel = object()
    calls: list[dict[str, object]] = []

    def session(**kwargs: object) -> object:
        calls.append(kwargs)
        assert Path(os.environ["AWS_CONFIG_FILE"]) == source / "config"
        return sentinel

    monkeypatch.setattr(_cli.boto3, "Session", session)
    args = argparse.Namespace(
        profile="default", location="default", directory=None, target="+Agent"
    )
    with _cli._selected_credential_session(args) as selected:
        assert selected is sentinel
    assert calls == [{"profile_name": "admin"}]
    text = _cli._config_text(data, account="Prod")
    assert "Agent" in text
    assert "Logs" in text
    with pytest.raises(_configs.OperationalError, match="Unknown configured account"):
        _cli._config_text(data, account="Missing")


def test_cache_filters_confirmation_and_help_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    entry = {
        "identity": "aws-CloudWatchReadOnly",
        "state": "stale",
        "origin": "remote",
        "source_identity": "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess",
        "age_seconds": 5000,
        "size": 120,
    }
    inventory = {
        "root": str(tmp_path),
        "max_age": 3600,
        "entries": [entry],
        "counts": {"fresh": 0, "stale": 1, "invalid": 0},
        "total_bytes": 120,
    }
    monkeypatch.setattr(_cli._policies, "cache_inventory", lambda: inventory)
    listed = _cli._run_cache(
        argparse.Namespace(
            cache_action="list",
            patterns=["*cloudwatch*"],
            fresh=False,
            stale=True,
            invalid=False,
            origin="remote",
        )
    )
    assert listed.data["count"] == 1  # type: ignore[index]

    with pytest.raises(_configs.OperationalError, match="cannot be combined"):
        _cli._run_cache(
            argparse.Namespace(
                cache_action="clear",
                entries=["*"],
                stale=True,
                all=False,
                yes=True,
            )
        )
    monkeypatch.setattr(_cli._output, "confirm", lambda *_args, **_kwargs: False)
    cancelled = _cli._run_cache(
        argparse.Namespace(
            cache_action="clear",
            entries=["*CloudWatch*"],
            stale=False,
            all=False,
            yes=False,
        )
    )
    assert cancelled.code == "CACHE_CLEAR_CANCELLED"
    monkeypatch.setattr(
        _cli._policies,
        "clear_cache_entries",
        lambda _entries, *, stale_only: (
            ["aws-CloudWatchReadOnly"] if stale_only else []
        ),
    )
    cleared = _cli._run_cache(
        argparse.Namespace(
            cache_action="clear",
            entries=[],
            stale=True,
            all=False,
            yes=True,
        )
    )
    assert cleared.data == {"removed": ["aws-CloudWatchReadOnly"], "count": 1}
    assert _cli._run_cache(argparse.Namespace(cache_action=None)).code == "CACHE_HELP"
