"""Security and lifecycle tests for local command history."""

from __future__ import annotations

import argparse
import contextlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from typing import cast
from unittest.mock import MagicMock

import pytest

from hacksaws import _cli
from hacksaws import _configs
from hacksaws import _history
from hacksaws import _state

if TYPE_CHECKING:
    from collections.abc import Iterator


def _isolate(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(path))


def _result(
    *,
    code: str = "TEST_OK",
    exit_code: int = 0,
    data: object | None = None,
    message: str = "",
) -> _configs.Result:
    return _configs.Result(code, message, exit_code=exit_code, data=data)


def test_schema_is_versioned_two_table_wal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)

    handle = _history.begin(json_mode=False, interactive=False)
    _history.finish(handle, _result())

    with closing(sqlite3.connect(_history.database_path())) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
            if not str(row[0]).startswith("sqlite_")
        }
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
    assert tables == {"invocations", "events"}
    assert version == _history.SCHEMA_VERSION
    assert str(journal).casefold() == "wal"


def test_allowlist_never_persists_sensitive_or_free_form_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    canary = "SUPER-SECRET-CANARY"
    handle = _history.begin(json_mode=True, interactive=False)
    _history.enrich(
        handle,
        argparse.Namespace(
            access_type="mfa",
            action="in",
            profile="admin",
            aws_account_name="horizon",
            policy=f"C:\\private\\{canary}.yaml",
            file=f"C:\\private\\{canary}.json",
            mfa_code=canary,
            external_id=canary,
            tag=[f"secret={canary}"],
            role=f"/private/{canary}",
            resource_name=f"/private/{canary}",
            dry_run=False,
            yes=False,
        ),
    )
    _history.finish(
        handle,
        _result(
            code=canary,
            message=canary,
            data={
                "message": canary,
                "document": {"secret": canary},
                "role": f"/private/{canary}",
                "name": f"/private/{canary}",
            },
        ),
    )

    raw_database = _history.database_path().read_bytes()
    record = _history.list_records()[0]
    assert canary.encode() not in raw_database
    assert record["command"] == "mfa.in"
    assert record["profile"] == "admin"
    assert record["location"] == "horizon"
    assert record["resultCode"] == "UNKNOWN"
    safe = cast("dict[str, object]", record["safe"])
    assert safe["secretPresence"] == {
        "externalId": True,
        "mfaCode": True,
    }
    assert safe["inputKinds"] == [
        {"format": "json", "role": "file"},
        {"format": "yaml", "role": "policy-file"},
    ]


def test_unknown_path_extensions_are_not_persisted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    canary = "private-extension-canary"
    handle = _history.begin(json_mode=False, interactive=False)
    _history.enrich(
        handle,
        argparse.Namespace(
            access_type="iam",
            iam_action="policy",
            policy_action="add",
            file=f"C:\\private\\policy.{canary}",
            policy=f"C:\\private\\boundary.{canary}",
        ),
    )
    _history.finish(handle, _result())

    record = _history.list_records()[0]
    exported = _history.export_records([record], format_name="json")
    assert canary not in exported
    assert canary.encode() not in _history.database_path().read_bytes()
    safe = cast("dict[str, object]", record["safe"])
    assert safe["inputKinds"] == [
        {"format": "other", "role": "file"},
        {"format": "other", "role": "policy-file"},
    ]


def test_argument_observer_failure_is_safe_and_does_not_block_cli(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    canary = "OBSERVER-FAILURE-CANARY"

    def fail_observer(
        _parser: argparse.ArgumentParser, _arguments: list[str]
    ) -> dict[str, object]:
        raise RuntimeError(canary)

    monkeypatch.setattr(_history, "observe_arguments", fail_observer)
    result = _cli.console_main(["--help"])

    assert result.exit_code == 0
    raw_database = _history.database_path().read_bytes()
    assert canary.encode() not in raw_database
    record = _history.list_records()[0]
    assert record["command"] == "unknown"


def test_finish_preserves_safe_parser_metadata_and_result_metrics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    handle = _history.begin(json_mode=False, interactive=True)
    _history.enrich(
        handle,
        argparse.Namespace(
            access_type="iam",
            iam_action="policy",
            policy_action="list",
            profile="admin",
            account="production",
            dry_run=True,
            wide=True,
        ),
    )
    _history.finish(
        handle,
        _result(data={"count": 3, "name": "CloudWatchReadOnlyAccess"}),
    )

    record = _history.list_records()[0]
    assert record["command"] == "iam.policy.list"
    assert record["dryRun"] is True
    safe = cast("dict[str, object]", record["safe"])
    assert safe["flags"] == ["dry-run", "wide"]
    assert safe["metrics"] == {"count": 3}
    assert record["resourceName"] == "CloudWatchReadOnlyAccess"


def test_post_prompt_mfa_enrichment_records_presence_and_source_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    handle = _history.begin(json_mode=False, interactive=True)
    _history.enrich(
        handle,
        argparse.Namespace(
            access_type="mfa", action="in", profile="admin", mfa_code=None
        ),
    )
    _history.note_mfa_code(source="not-allowed")
    _history.note_mfa_code(source="prompt")
    _history.finish(handle, _result())

    safe = cast("dict[str, object]", _history.list_records()[0]["safe"])
    assert safe["mfaCodeProvided"] is True
    assert safe["mfaCodeSource"] == "prompt"
    assert "mfaCode" not in safe


def test_account_registration_history_is_separate_and_count_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    handle = _history.begin(json_mode=False, interactive=False)
    _history.note_account_registration(
        status="completed", created=1, reused=1, refreshed=0
    )
    _history.finish(handle, _result())

    record = _history.list_records()[0]
    event = _history.account_registration_event(record)
    assert event is not None
    assert event["kind"] == "account-registration.completed"
    assert event["data"] == {
        "eventSchemaVersion": _history.EVENT_SCHEMA_VERSION,
        "redactionVersion": _history.REDACTION_VERSION,
        "status": "completed",
        "created": 1,
        "reused": 1,
        "refreshed": 0,
    }
    report = _history.status()
    assert report["accountRegistrations"] == 1
    assert _history.check()["ok"] is True


@pytest.mark.parametrize(
    ("error", "state", "outcome", "exit_code"),
    [
        (RuntimeError("do not store this"), "crashed", "crashed", 1),
        (KeyboardInterrupt(), "interrupted", "interrupted", 130),
    ],
)
def test_failure_lifecycle_stores_no_exception_detail(  # noqa: PLR0917
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    error: BaseException,
    state: str,
    outcome: str,
    exit_code: int,
) -> None:
    _isolate(monkeypatch, tmp_path)
    handle = _history.begin(json_mode=False, interactive=False)
    _history.fail(handle, error)

    record = _history.list_records()[0]
    assert record["state"] == state
    assert record["outcome"] == outcome
    assert record["exitCode"] == exit_code
    assert record["safe"] == {}
    assert b"do not store this" not in _history.database_path().read_bytes()


def test_concurrent_writers_complete_atomically(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)

    def record_one(index: int) -> None:
        handle = _history.begin(json_mode=bool(index % 2), interactive=False)
        _history.finish(handle, _result(data={"count": index}))

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(record_one, range(32)))

    records = _history.list_records(limit=100)
    assert len(records) == 32
    assert {record["state"] for record in records} == {"completed"}


def test_retention_abandons_old_runs_and_preserves_unresolved_recovery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    old = (datetime.now(UTC) - timedelta(days=100)).isoformat()
    stale_running = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    handle = _history.begin(json_mode=False, interactive=False)
    assert handle.id is not None
    with closing(sqlite3.connect(_history.database_path())) as connection, connection:
        connection.execute(
            "UPDATE invocations SET started_at = ?, updated_at = ? WHERE id = ?",
            (stale_running, stale_running, handle.id),
        )
        connection.execute(
            "INSERT INTO invocations (id, started_at, ended_at, state, command, "
            "json_mode, interactive, outcome, safe_json, recovery_unresolved, "
            "updated_at) VALUES ('resolved-old', ?, ?, 'completed', 'iam.cleanup', "
            "0, 0, 'success', '{}', 0, ?)",
            (old, old, old),
        )
        connection.execute(
            "INSERT INTO invocations (id, started_at, ended_at, state, command, "
            "json_mode, interactive, outcome, safe_json, recovery_unresolved, "
            "updated_at) VALUES ('recovery-old', ?, ?, 'completed', 'iam.cleanup', "
            "0, 0, 'operational-error', '{}', 1, ?)",
            (old, old, old),
        )
    _history._maintain()

    with closing(sqlite3.connect(_history.database_path())) as connection:
        rows = {
            row[0]: row[1]
            for row in connection.execute("SELECT id, state FROM invocations")
        }
    assert rows[handle.id] == "abandoned"
    assert "resolved-old" not in rows
    assert rows["recovery-old"] == "completed"


def test_clear_never_removes_running_or_unresolved_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    running = _history.begin(json_mode=False, interactive=False)
    unresolved = _history.begin(json_mode=False, interactive=False)
    _history.finish(
        unresolved,
        _result(
            code="IAM_RECOVERY_REQUIRED",
            exit_code=1,
            data={"classification": "recovery-required"},
        ),
    )
    resolved = _history.begin(json_mode=False, interactive=False)
    _history.finish(resolved, _result())

    plan = _history.clear(before=None, all_records=True, apply=False)
    applied = _history.clear(before=None, all_records=True, apply=True)

    assert plan["count"] == 1
    assert cast("int", plan["logicalBytes"]) > 0
    assert plan["applied"] is False
    assert applied["count"] == 1
    assert {record["id"] for record in _history.list_records(include_running=True)} == {
        running.id,
        unresolved.id,
    }


def test_export_and_time_parsing_are_deterministic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    handle = _history.begin(json_mode=False, interactive=False)
    _history.finish(handle, _result())
    records = _history.list_records()

    exported = _history.export_records(records, format_name="jsonl")
    assert json.loads(exported) == records[0]
    anchor = datetime(2026, 8, 2, 12, tzinfo=UTC)
    assert _history.parse_time("15m", now=anchor) == anchor - timedelta(minutes=15)
    assert _history.parse_time("7d", now=anchor) == anchor - timedelta(days=7)
    assert _history.parse_time("2026-08-01T12:00:00Z") == datetime(
        2026, 8, 1, 12, tzinfo=UTC
    )


def test_history_config_defaults_and_validation() -> None:
    config = _state.default_config()
    assert config["history"] == {
        "enabled": True,
        "max_age": _history.DEFAULT_MAX_AGE,
        "max_entries": _history.DEFAULT_MAX_ENTRIES,
        "max_bytes": _history.DEFAULT_MAX_BYTES,
    }
    config["history"]["max_entries"] = 0
    with pytest.raises(_configs.OperationalError, match="positive integer"):
        _state._validate_config(config)


def test_universal_cli_interception_preserves_one_json_envelope(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate(monkeypatch, tmp_path)

    result = _cli.console_main(["config", "options", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert result.exit_code == 0
    assert payload["code"] == "CONFIG_OPTIONS"
    records = _history.list_records()
    assert len(records) == 1
    assert records[0]["command"] == "config.options"
    assert records[0]["outcome"] == "success"


def test_parse_failure_is_recorded_without_raw_arguments(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate(monkeypatch, tmp_path)
    canary = "DO-NOT-STORE-THIS"

    result = _cli.console_main([canary, "--json"])

    assert result.exit_code == _configs.EXIT_USAGE
    assert json.loads(capsys.readouterr().err)["code"] == "ARGUMENT_ERROR"
    assert canary.encode() not in _history.database_path().read_bytes()
    assert _history.list_records()[0]["command"] == "unknown"


def test_history_list_show_report_status_and_check_are_human_friendly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate(monkeypatch, tmp_path)
    handle = _history.begin(json_mode=False, interactive=False)
    _history.enrich(
        handle,
        argparse.Namespace(
            access_type="iam",
            iam_action="role",
            role_command="get",
            profile="admin",
            role="AgentSession",
        ),
    )
    _history.finish(handle, _result(data={"name": "AgentSession"}))
    identifier = str(_history.list_records()[0]["id"])

    assert _cli.console_main(["history", "list"]).exit_code == 0
    list_output = capsys.readouterr().out
    assert "ID" in list_output
    assert "iam.role.get" in list_output
    assert "Key: OK success" in list_output

    assert _cli.console_main(["history", "show", identifier[:8]]).exit_code == 0
    show_output = capsys.readouterr().out
    assert "Safe template: hacksaws iam role get" in show_output
    assert "profile=admin" in show_output

    assert _cli.console_main(["history", "report"]).exit_code == 0
    report_output = capsys.readouterr().out
    assert "Outcomes" in report_output
    assert "Command families" in report_output

    assert _cli.console_main(["history", "status"]).exit_code == 0
    status_output = capsys.readouterr().out
    assert "History database:" in status_output
    assert "Retention:" in status_output

    assert _cli.console_main(["history", "check"]).exit_code == 0
    assert "valid" in capsys.readouterr().out


def test_history_search_and_export_support_safe_machine_workflows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate(monkeypatch, tmp_path)
    for command in ("policy", "role"):
        handle = _history.begin(json_mode=False, interactive=False)
        command_fields = (
            {"policy_action": "list"}
            if command == "policy"
            else {"role_command": "list"}
        )
        _history.enrich(
            handle,
            argparse.Namespace(access_type="iam", iam_action=command, **command_fields),
        )
        _history.finish(handle, _result())

    search = _cli.console_main(
        ["history", "search", "*policy*", "--json", "--limit", "10"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert search.exit_code == 0
    assert payload["data"]["count"] == 1
    assert payload["data"]["records"][0]["command"] == "iam.policy.list"

    destination = tmp_path / "safe-history.jsonl"
    exported = _cli.console_main(
        [
            "history",
            "export",
            "--format",
            "jsonl",
            "--output",
            str(destination),
        ]
    )
    capsys.readouterr()
    assert exported.exit_code == 0
    lines = destination.read_text(encoding="utf-8").splitlines()
    assert lines
    assert all(isinstance(json.loads(line), dict) for line in lines)


class _InteractiveInput:
    def isatty(self) -> bool:
        return True


def test_history_clear_requires_exact_yes_and_records_semantics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate(monkeypatch, tmp_path)
    handle = _history.begin(json_mode=False, interactive=False)
    _history.finish(handle, _result())
    monkeypatch.setattr(_cli.sys, "stdin", _InteractiveInput())
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")

    declined = _cli.console_main(["history", "clear", "--all"])

    assert declined.exit_code == _configs.EXIT_CANCELLED
    assert "cancelled" in capsys.readouterr().err.casefold()
    records = _history.list_records(limit=10)
    assert any(record["confirmation"] == "exact-yes:declined" for record in records)

    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    accepted = _cli.console_main(["history", "clear", "--all"])
    assert accepted.exit_code == 0
    assert "Removed" in capsys.readouterr().out


def test_history_storage_failure_never_changes_command_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate(monkeypatch, tmp_path)

    unavailable_error = sqlite3.OperationalError("history unavailable")

    def unavailable() -> sqlite3.Connection:
        raise unavailable_error

    monkeypatch.setattr(_history, "_connect", unavailable)
    result = _cli.console_main(["config", "options", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert result.exit_code == 0
    assert payload["code"] == "CONFIG_OPTIONS"


def test_partial_database_initialization_always_closes_connection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Close a sqlite handle when an initialization PRAGMA fails."""
    _isolate(monkeypatch, tmp_path)
    connection = MagicMock()
    connection.execute.side_effect = sqlite3.DatabaseError("corrupt database")
    monkeypatch.setattr(sqlite3, "connect", MagicMock(return_value=connection))

    with pytest.raises(sqlite3.DatabaseError, match="corrupt database"):
        _history._connect()

    connection.close.assert_called_once_with()


def test_unexpected_cli_exception_is_finalized_as_crashed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)

    crash_error = RuntimeError("private crash detail")

    def crash(*_args: object, **_kwargs: object) -> _configs.Result:
        raise crash_error

    monkeypatch.setattr(_cli, "_console_main_invocation", crash)
    with pytest.raises(RuntimeError, match="private crash detail"):
        _cli.console_main(["config", "options"])
    record = _history.list_records()[0]
    assert record["state"] == "crashed"
    assert b"private crash detail" not in _history.database_path().read_bytes()


def test_defensive_schema_settings_alias_and_disabled_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(
        _state,
        "load_config",
        lambda: {
            "history": {
                "enabled": "invalid",
                "max_age": "invalid",
                "max_entries": "invalid",
                "max_bytes": "invalid",
            }
        },
    )
    assert _history._settings() == {
        "enabled": True,
        "max_age": _history.DEFAULT_MAX_AGE,
        "max_entries": _history.DEFAULT_MAX_ENTRIES,
        "max_bytes": _history.DEFAULT_MAX_BYTES,
    }
    monkeypatch.setattr(
        _state,
        "load_config",
        lambda: (_ for _ in ()).throw(_configs.OperationalError("invalid config")),
    )
    assert _history._settings()["enabled"] is True
    monkeypatch.setattr(
        _state,
        "load_config",
        lambda: {"history": {"enabled": False}},
    )
    assert _history.begin(json_mode=False, interactive=False).enabled is False
    with _history.disabled():
        assert _history.begin(json_mode=False, interactive=False).enabled is False

    assert _history._canonical_command(
        argparse.Namespace(access_type="remote", iam_action="list")
    ) == ("iam.list", "remote")
    assert _history._canonical_command(
        argparse.Namespace(access_type="web", action="in")
    ) == ("pk.in", "web")
    assert _history._canonical_command(argparse.Namespace(access_type="not safe!")) == (
        "unknown",
        None,
    )

    schema_home = tmp_path / "future"
    monkeypatch.setenv("HACKSAWS_HOME", str(schema_home))
    schema_home.joinpath("history").mkdir(parents=True)
    future_database = schema_home / "history" / "history.db"
    with closing(sqlite3.connect(future_database)) as connection, connection:
        connection.execute("PRAGMA user_version = 99")
    _history._initialized_databases.discard(future_database)
    monkeypatch.setattr(_state, "load_config", _state.default_config)
    assert _history.begin(json_mode=False, interactive=False).enabled is False


def test_filters_templates_errors_and_confirmation_branches(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    handle = _history.begin(json_mode=False, interactive=False)
    _history.enrich(
        handle,
        argparse.Namespace(
            access_type="iam",
            iam_action="policy",
            policy_action="create",
            profile="admin",
            account="123456789012",
            role="AgentSession",
            external_id="secret",
            mfa_code="secret",
            file=Path("policy.yaml"),
            yes=True,
        ),
    )
    assert _history.current_id() == handle.id
    _history.finish(
        handle,
        _result(
            code="IAM_POLICY_CREATED",
            data={
                "arn": "arn:aws:iam::123456789012:policy/hacksaws/Agent",
                "accountId": "123456789012",
                "partition": "aws",
                "journalId": "safe-journal-1",
                "classification": "recovery-required",
                "changed": 2,
                "failed": -1,
            },
        ),
    )
    record = _history.list_records()[0]
    assert record["confirmation"] == "yes-flag:bypassed"
    assert record["accountId"] == "123456789012"
    assert record["partition"] == "aws"
    template = _history.command_template(record)
    assert "--file <file>" in template
    assert "--external-id <redacted>" in template
    assert "<mfa-code>" in template

    started = datetime.fromisoformat(str(record["startedAt"]))
    assert _history.list_records(
        since=started - timedelta(seconds=1),
        until=started + timedelta(seconds=1),
        command="iam.policy",
        outcome="success",
        account="123456789012",
        resource="Agent",
    ) == [record]
    assert _history.list_records(patterns=("policy",)) == [record]
    assert _history.list_records(patterns=("*missing*",)) == []
    assert json.loads(_history.export_records([record], format_name="json")) == [record]

    with pytest.raises(_configs.OperationalError, match="4-32"):
        _history.get_record("bad")
    with pytest.raises(_configs.OperationalError, match="not found"):
        _history.get_record("deadbeef")
    with pytest.raises(_configs.OperationalError, match="requires --before"):
        _history.clear(before=None, all_records=False, apply=False)
    assert _history.parse_time("1week", now=started) == started - timedelta(days=7)
    assert _history.parse_time("2026-08-02", now=started).tzinfo is UTC

    _history.note_confirmation("yes-no", "accepted")
    assert _history.current_id() is None


def test_history_error_translation_corruption_and_bounded_retention(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    handles = []
    for _index in range(3):
        handle = _history.begin(json_mode=False, interactive=False)
        _history.finish(handle, _result())
        handles.append(handle)
    with _history._database() as connection:
        connection.execute(
            "UPDATE invocations SET safe_json = '[]' WHERE id = ?", (handles[0].id,)
        )
        connection.execute(
            "UPDATE invocations SET safe_json = '{broken' WHERE id = ?",
            (handles[1].id,),
        )
    report = _history.check()
    assert report["ok"] is False
    assert report["corruptRecords"] == 2

    monkeypatch.setattr(
        _history,
        "_settings",
        lambda: {
            "enabled": True,
            "max_age": _history.DEFAULT_MAX_AGE,
            "max_entries": 1,
            "max_bytes": _history.DEFAULT_MAX_BYTES,
        },
    )
    with _history._database() as connection:
        connection.execute("DELETE FROM events")
        connection.execute(
            "UPDATE invocations SET safe_json = '{}', recovery_unresolved = 0"
        )
    _history._maintain()
    assert len(_history.list_records(limit=10)) == 1
    _history._maintain()

    database_error = sqlite3.OperationalError("unavailable")

    @contextlib.contextmanager
    def unavailable() -> Iterator[sqlite3.Connection]:
        raise database_error
        yield  # pragma: no cover

    monkeypatch.setattr(_history, "_database", unavailable)
    with pytest.raises(_configs.OperationalError, match="read command history"):
        _history.list_records()
    with pytest.raises(_configs.OperationalError, match="inspect command history"):
        _history.status()
    disabled = _history.HistoryHandle(id=None, started_monotonic=0.0, enabled=False)
    _history.enrich(disabled, argparse.Namespace())
    _history.finish(disabled, _result())
    _history.fail(disabled, RuntimeError())
