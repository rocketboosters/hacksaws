"""Behavioral coverage for human history, status, and configuration surfaces."""

from __future__ import annotations

import argparse
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import pytest

from hacksaws import _cli
from hacksaws import _configs
from hacksaws import _history
from hacksaws import _state


def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))


def _history_args(*arguments: str) -> argparse.Namespace:
    parsed = _cli._create_parser().parse_args(["history", *arguments])
    parsed.json = False
    return parsed


def _command_args(*arguments: str) -> argparse.Namespace:
    parsed = _cli._create_parser().parse_args(list(arguments))
    parsed.json = bool(getattr(parsed, "json", False))
    return parsed


def _result_data(result: _configs.Result) -> dict[str, object]:
    assert isinstance(result.data, dict)
    return result.data


def _record_parse_failure() -> str:
    handle = _history.begin(json_mode=False, interactive=False)
    observation = _history.observe_arguments(
        _cli._create_parser(), ["web", "in", "debug", "--save-name"]
    )
    _history.note_parse_failure(
        handle, observation, phase="argparse", kind="missing-option-value"
    )
    _history.finish(handle, _configs.Result("ARGUMENT_ERROR", "ignored", 2))
    assert handle.id is not None
    return handle.id


def _record_save(status: str = "saved") -> str:
    handle = _history.begin(json_mode=False, interactive=True)
    _history.note_session_save(
        status=status,
        target="DebugAgent",
        boundary="AgentBoundary",
        requested=True,
        credentials_active=True,
    )
    _history.finish(handle, _configs.Result("OK", "ignored"))
    assert handle.id is not None
    return handle.id


def test_history_terminal_commands_cover_safe_inspection_and_export(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolated(monkeypatch, tmp_path)
    parse_id = _record_parse_failure()
    _record_save()

    listed = _cli._run_history(
        _history_args(
            "list",
            "--wide",
            "--failure",
            "missing-option-value",
            "--phase",
            "argparse",
        )
    )
    assert listed.code == "HISTORY_LIST"
    assert "missing-option-value" in listed.message

    searched = _cli._run_history(
        _history_args("search", "session-save.saved", "--wide")
    )
    assert searched.code == "HISTORY_SEARCH"
    assert _result_data(searched)["count"] == 1

    shown = _cli._run_history(_history_args("show", parse_id[:8]))
    assert shown.code == "HISTORY_SHOW"
    assert "Safe attempted shape:" in shown.message

    report = _cli._run_history(_history_args("report"))
    assert report.code == "HISTORY_REPORT"
    assert "Argument failures" in report.message
    assert "Session saves" in report.message

    exported = _cli._run_history(_history_args("export", "--format", "json"))
    assert exported.code == "HISTORY_EXPORT"
    assert len(json.loads(exported.message)) == 2

    output = tmp_path / "history.jsonl"
    written = _cli._run_history(
        _history_args("export", "--format", "jsonl", "--output", str(output))
    )
    assert written.code == "HISTORY_EXPORT"
    assert _result_data(written)["output"] == str(output.absolute())
    assert len(output.read_text(encoding="utf-8").splitlines()) == 2

    status = _cli._run_history(_history_args("status"))
    assert status.code == "HISTORY_STATUS"
    assert (
        "1 parse failures; 1 session saves; 0 account registrations" in status.message
    )

    checked = _cli._run_history(_history_args("check"))
    assert checked.code == "HISTORY_CHECK_OK"
    assert checked.exit_code == 0


def test_history_check_reports_corrupt_record_and_event(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolated(monkeypatch, tmp_path)
    identifier = _record_save()
    with closing(sqlite3.connect(_history.database_path())) as connection:
        connection.execute(
            "UPDATE invocations SET safe_json = '[]' WHERE id = ?", (identifier,)
        )
        connection.execute(
            "INSERT INTO events (invocation_id, occurred_at, kind, data_json) "
            "VALUES (?, '2026-01-01T00:00:00Z', 'session-save.saved', '{}')",
            (identifier,),
        )
        connection.commit()

    result = _cli._run_history(_history_args("check"))
    assert result.code == "HISTORY_CHECK_FAILED"
    assert result.exit_code == 1
    assert "1 corrupt records and 1 corrupt events" in result.message


def test_history_clear_plan_confirmation_cancel_and_apply(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolated(monkeypatch, tmp_path)
    _record_save()
    dry_run = _cli._run_history(_history_args("clear", "--all", "--dry-run"))
    assert dry_run.code == "HISTORY_CLEAR_PLAN"
    assert _result_data(dry_run)["applied"] is False

    with patch("hacksaws._cli.sys.stdin.isatty", return_value=False):
        required = _cli._run_history(_history_args("clear", "--all"))
    assert required.code == "CONFIRMATION_REQUIRED"
    assert required.exit_code == _configs.EXIT_CANCELLED

    with (
        patch("hacksaws._cli.sys.stdin.isatty", return_value=True),
        patch("builtins.input", return_value="no"),
    ):
        cancelled = _cli._run_history(_history_args("clear", "--all"))
    assert cancelled.code == "HISTORY_CLEAR_CANCELLED"

    applied = _cli._run_history(_history_args("clear", "--all", "--yes"))
    assert applied.code == "HISTORY_CLEAR"
    assert _result_data(applied)["count"] == 1

    empty = _cli._run_history(_history_args("clear", "--all"))
    assert empty.code == "HISTORY_CLEAR_PLAN"
    assert _result_data(empty)["count"] == 0


def test_history_help_and_rendering_edge_states(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated(monkeypatch, tmp_path)
    help_result = _cli._run_history(_history_args())
    assert help_result.code == "HISTORY_HELP"
    help_text = capsys.readouterr().out
    assert "Inspect" in help_text
    assert "list,search,show,report,export,status,check,clear" in help_text

    records = [
        {
            "id": "a" * 32,
            "startedAt": "2026-01-01T00:00:00Z",
            "outcome": outcome,
            "command": "pk.login",
            "profile": "debug",
            "durationMs": 1,
            "events": [],
        }
        for outcome in _cli._HISTORY_OUTCOMES
    ]
    records.append(
        {
            "id": "b" * 32,
            "startedAt": "2026-01-01T00:00:00Z",
            "outcome": None,
            "command": "unknown",
            "profile": None,
            "events": [],
        }
    )
    rendered = _cli._history_list_text(records, wide=True)
    assert "running/unknown" in rendered
    assert _cli._history_list_text([], wide=False) == "(none)"

    legacy = {
        "id": "c" * 32,
        "command": "unknown",
        "state": "completed",
        "outcome": "usage-error",
        "resultCode": "ARGUMENT_ERROR",
        "exitCode": 2,
        "startedAt": "2026-01-01T00:00:00Z",
        "endedAt": "2026-01-01T00:00:01Z",
        "durationMs": 1,
        "confirmation": "not-requested",
        "safe": {
            "inputKinds": [{"role": "policy", "format": "yaml"}],
            "secretPresence": {"mfaCode": True, "externalId": True},
        },
        "events": [],
        "recoveryUnresolved": True,
        "profile": "debug",
        "accountId": "123456789012",
    }
    detail = _cli._history_show_text(legacy)
    assert "Inputs: policy (yaml)" in detail
    assert "MFA code, external ID" in detail
    assert "Recovery: unresolved" in detail
    assert "Parse detail: unavailable" in detail


def test_status_human_rendering_teaches_dynamic_fields() -> None:
    sessions = [
        {
            "location": "default",
            "profile": "native",
            "profile_region": "us-east-1",
            "state": "active",
            "auth_method": "browser-native",
            "source_account": "111111111111",
            "effective_scope": {"kind": "account-login"},
            "remaining_seconds": 30,
            "verification": {"status": "verified"},
        },
        {
            "location": "horizon",
            "profile": "bounded",
            "region": "us-west-2",
            "state": "expiring",
            "auth_method": "mfa",
            "role": "arn:aws:iam::222222222222:role/path/AgentRole",
            "target_account": "222222222222",
            "effective_scope": {
                "kind": "role-session",
                "role_label": "AgentRole",
                "boundary_label": "Logs",
                "policy_label": "ReadOnly",
            },
            "remaining_seconds": 5400,
            "verification": {
                "status": "mismatch",
                "expected_role": "AgentRole",
                "actual_role": "OtherRole",
            },
        },
        {
            "location": "horizon",
            "profile": "odd",
            "state": "new-state",
            "auth_method": "new-auth",
            "effective_scope": {"kind": "new-kind"},
            "remaining_seconds": "bad",
            "verification": {"status": "mismatch", "actual_account": "333"},
        },
    ]
    rendered = _cli._status_text({"sessions": sessions})
    assert "LOCATION" in rendered
    assert "TTL" in rendered
    assert "VERIFY" in rendered
    assert "AgentRole (@Logs)" in rendered
    assert "mismatch (role OtherRole)" in rendered
    assert "mismatch (333)" in rendered
    assert "unknown/inconclusive" in rendered

    assert _cli._status_text({"sessions": []}) == "(none)"
    assert _cli._status_ttl({"state": "expired", "remaining_seconds": 20}) == ""
    assert _cli._status_ttl({"state": "active", "remaining_seconds": 0}) == ""
    assert _cli._status_ttl({"state": "active", "remaining_seconds": 90}) == "2m"
    assert _cli._status_ttl({"state": "active", "remaining_seconds": 8000}) == "2h"
    assert _cli._status_verification({}) == ""
    assert _cli._status_verification({"verification": {"status": "error"}}) == "error"


def test_config_human_account_scope_and_terminal_adapters(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolated(monkeypatch, tmp_path)
    data = _state.default_config()
    data["accounts"] = {
        "Prod": {
            "id": "111111111111",
            "partition": "aws",
            "region": "us-west-2",
            "description": "Production",
        },
        "Dev": {
            "id": "222222222222",
            "partition": "aws",
            "unverified": True,
        },
    }
    data["policies"] = {
        "Logs": {
            "file": "stored_session_policies/Logs.yaml",
            "description": "Read logs",
        },
        "Unused": {"file": "stored_session_policies/Unused.yaml"},
    }
    data["boundaries"] = {
        "Guard": {
            "role_arn": "arn:aws:iam::111111111111:role/Agent",
            "account": "Prod",
            "policy": "Logs",
            "duration": 900,
            "verified": True,
        }
    }
    data["targets"] = {
        "Debug": {
            "source_account": "Prod",
            "source_profile": "admin",
            "source_location": "horizon",
            "destination_profile": "debug",
            "destination_location": "default",
            "boundary": "Guard",
            "region": "us-west-2",
        }
    }
    _state.save_config(data)

    all_text = _cli._config_text(data)
    assert "Settings" in all_text
    assert "Unused" in all_text
    prod_text = _cli._config_text(data, account="prod")
    assert "Production" in prod_text
    assert "Debug" in prod_text
    assert "Unused" not in prod_text
    assert "Settings" not in prod_text
    with pytest.raises(_configs.OperationalError, match="Unknown configured account"):
        _cli._config_text(data, account="Missing")

    assert "error: denied" in _cli._logout_report_text(
        {
            "outcomes": [
                {"profile": "debug", "destination": "C:/aws", "state": "cleared"}
            ],
            "errors": [{"key": "C:/other", "message": "denied"}],
        }
    )
    assert "fresh" in _cli._cache_list_text(
        [
            {
                "identity": "aws-ReadOnly",
                "state": "fresh",
                "origin": "aws-managed",
                "source_identity": "ReadOnly",
                "age_seconds": 12,
                "size": 100,
            }
        ]
    )
    assert "1 fresh, 2 stale, 3 invalid" in _cli._cache_status_text(
        {
            "root": str(tmp_path),
            "max_age": 3600,
            "counts": {"fresh": 1, "stale": 2, "invalid": 3},
            "total_bytes": 100,
        }
    )


def test_config_terminal_commands_cover_human_and_machine_management(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated(monkeypatch, tmp_path)
    data = _state.default_config()
    data["accounts"]["Prod"] = {
        "id": "111111111111",
        "partition": "aws",
    }
    data["boundaries"]["Guard"] = {
        "role_arn": "arn:aws:iam::111111111111:role/Agent",
        "account": "Prod",
        "verified": True,
    }
    data["targets"]["Debug"] = {
        "source_account": "Prod",
        "source_profile": "admin",
        "source_location": "default",
        "boundary": "Guard",
    }
    _state.save_config(data)

    shown = _cli._run_config(_command_args("config", "show", "--account", "Prod"))
    assert shown.code == "CONFIG_SHOW"
    assert "Debug" in shown.message
    shown_json = _cli._run_config(_command_args("config", "show", "--json"))
    assert json.loads(shown_json.message)["accounts"]["Prod"]["id"] == "111111111111"

    options = _cli._run_config(_command_args("config", "option", "list"))
    assert options.code == "CONFIG_OPTION_LIST"
    explained = _cli._run_config(
        _command_args("config", "option", "explain", "history.max_age")
    )
    assert explained.code == "CONFIG_OPTION_EXPLAIN"
    with pytest.raises(_configs.OperationalError, match="Unknown config option"):
        _cli._run_config(_command_args("config", "option", "explain", "not.real"))

    nested_set = _cli._run_config(
        _command_args("config", "option", "set", "history.max_entries", "123")
    )
    assert _result_data(nested_set)["value"] == 123
    nested_reset = _cli._run_config(
        _command_args("config", "option", "reset", "history.max_entries")
    )
    assert nested_reset.code == "CONFIG_OPTION_RESET"

    direct_set = _cli._run_config(
        _command_args("config", "set", "output.color", "never")
    )
    assert _result_data(direct_set)["value"] == "never"
    direct_get = _cli._run_config(
        _command_args("config", "get", "output.color", "--json")
    )
    assert _result_data(direct_get)["value"] == "never"
    direct_reset = _cli._run_config(_command_args("config", "reset", "output.color"))
    assert direct_reset.code == "CONFIG_OPTION_RESET"

    no_option_action = _cli._run_config(_command_args("config", "option"))
    assert no_option_action.code == "CONFIG_OPTION_HELP"
    no_action = _cli._run_config(_command_args("config"))
    assert no_action.code == "CONFIG_HELP"
    assert "hacksaws config" in capsys.readouterr().out


def test_config_terminal_adapters_dispatch_without_exposing_backend_details(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolated(monkeypatch, tmp_path)
    _state.save_config(_state.default_config())
    with (
        patch("hacksaws._sessions.explain_target", return_value={"target": "Debug"}),
        patch(
            "hacksaws._sessions.check_config",
            side_effect=({"errors": [], "warnings": []}, {"errors": ["bad"]}),
        ),
        patch(
            "hacksaws._sessions.fix_config",
            return_value=_configs.Result("CONFIG_FIXED", "fixed"),
        ),
        patch("hacksaws._sessions.export_config", return_value=tmp_path / "backup.zip"),
        patch("hacksaws._sessions.import_config", return_value="Imported safely."),
    ):
        explained = _cli._run_config(
            _command_args("config", "explain", "Debug", "--json")
        )
        checked = _cli._run_config(_command_args("config", "check"))
        failed = _cli._run_config(_command_args("config", "check"))
        fixed = _cli._run_config(_command_args("config", "fix"))
        exported = _cli._run_config(
            _command_args("config", "export", str(tmp_path / "backup.zip"))
        )
        imported = _cli._run_config(
            _command_args("config", "import", str(tmp_path / "backup.zip"), "--yes")
        )
    assert explained.code == "CONFIG_EXPLAIN"
    assert checked.exit_code == 0
    assert failed.exit_code == 1
    assert fixed.code == "CONFIG_FIXED"
    assert exported.code == "CONFIG_EXPORT"
    assert imported.message == "Imported safely."


def test_named_target_resource_dispatch_and_recovery_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated(monkeypatch, tmp_path)
    data = _state.default_config()
    data["accounts"]["Prod"] = {"id": "111111111111", "partition": "aws"}
    _state.save_config(data)

    added = _cli._run_resource(
        _command_args(
            "target",
            "add",
            "Debug",
            "--source-account",
            "Prod",
            "--source-profile",
            "admin",
            "--source-location",
            "horizon",
            "--to",
            "default:debug",
            "--description",
            "Agent debug target",
        )
    )
    assert added.code == "RESOURCE_SAVED"
    listed = _cli._run_resource(_command_args("target", "list"))
    assert listed.code == "RESOURCE_LIST"
    fetched = _cli._run_resource(_command_args("target", "get", "Debug"))
    assert fetched.code == "RESOURCE_GET"
    renamed = _cli._run_resource(_command_args("target", "rename", "Debug", "Agent"))
    assert renamed.code == "RESOURCE_RENAME"
    removed = _cli._run_resource(_command_args("target", "remove", "Agent"))
    assert removed.code == "RESOURCE_REMOVE"

    help_result = _cli._run_resource(_command_args("target"))
    assert help_result.code == "RESOURCE_HELP"
    assert "saved login" in capsys.readouterr().out

    with pytest.raises(_configs.OperationalError, match="requires --source-account"):
        _cli._run_resource(_command_args("target", "add", "Missing"))
    with pytest.raises(_configs.OperationalError, match="require --from-session"):
        _cli._run_resource(
            _command_args(
                "target",
                "add",
                "Missing",
                "--source-account",
                "Prod",
                "--store-policy-as",
                "Stored",
            )
        )


def test_target_from_session_dispatches_complete_recovery_namespace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolated(monkeypatch, tmp_path)
    expected = _configs.Result("TARGET_FROM_SESSION", "saved")
    parsed = _command_args(
        "target",
        "add",
        "Recovered",
        "--from-session",
        "debug",
        "--directory",
        str(tmp_path / "aws"),
        "--save-source-account",
        "Prod",
        "--save-role-account",
        "Tools",
        "--save-boundary",
        "Guard",
        "--policy",
        "ReadOnly",
    )
    with patch(
        "hacksaws._sessions.save_target_from_session", return_value=expected
    ) as save:
        assert _cli._run_resource(parsed) is expected
    save.assert_called_once_with(parsed)


@pytest.mark.parametrize(
    ("arguments", "phase"),
    [
        (["--color", "rainbow", "status"], "global"),
        (["web", "in", "debug", "--save=One", "--save-name", "Two"], "semantic"),
        (["web", "in", "debug", "--not-a-real-option"], "argparse"),
        (["mfa", "in", "debug", "--json"], "semantic"),
    ],
)
def test_console_usage_failures_are_recorded_by_phase(
    arguments: list[str],
    phase: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated(monkeypatch, tmp_path)
    result = _cli.console_main(arguments)
    assert result.exit_code == _configs.EXIT_USAGE
    capsys.readouterr()
    assert _history.list_records(phase=phase)
