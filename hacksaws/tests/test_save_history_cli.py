"""Save grammar and redacted parse-history contracts."""

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


def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))


def test_save_equals_and_explicit_name_have_one_namespace_contract() -> None:
    parser = _cli._create_parser()
    equals = parser.parse_args(
        _cli._normalize_login_save_options(["web", "in", "debug", "--save=Agent"])
    )
    explicit = parser.parse_args(["web", "in", "debug", "--save-name", "Agent"])
    assert equals.save is False
    assert equals.save_name == "Agent"
    assert explicit.save is False
    assert explicit.save_name == "Agent"

    assumed = parser.parse_args(
        _cli._normalize_login_save_options(
            [
                "assume",
                "debug",
                "--role",
                "AgentRole",
                "--self",
                "--save=Agent",
                "--save-source-account",
                "Prod",
                "--save-role-account",
                "Tools",
                "--save-boundary",
                "Guard",
            ]
        )
    )
    assert assumed.save_name == "Agent"
    assert assumed.save_source_account == "Prod"
    assert assumed.save_role_account == "Tools"
    assert assumed.save_boundary == "Guard"


def test_ambiguous_save_and_orphaned_overrides_are_usage_errors() -> None:
    with pytest.raises(_configs.OperationalError, match="Ambiguous"):
        _cli._normalize_login_save_options(["web", "in", "debug", "--save", "Agent"])
    namespace = argparse.Namespace(
        save=False,
        save_name=None,
        save_source_account="Prod",
        save_role_account=None,
        save_boundary=None,
        save_external_id=False,
        store_policy_as=None,
        external_id=None,
    )
    with pytest.raises(_configs.OperationalError, match="require --save"):
        _cli._validate_save_arguments(namespace)


def test_bare_save_in_json_fails_before_browser_authentication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated(monkeypatch, tmp_path)
    with patch("hacksaws._sessions.browser_login") as login:
        result = _cli.console_main(["web", "in", "debug", "--save", "--json"])
    assert result.code == "SAVE_NAME_REQUIRED"
    assert result.exit_code == _configs.EXIT_USAGE
    login.assert_not_called()
    payload = json.loads(capsys.readouterr().err)
    assert payload["code"] == "SAVE_NAME_REQUIRED"


def test_target_from_session_dispatches_and_manual_shape_conflicts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolated(monkeypatch, tmp_path)
    expected = _configs.Result("TARGET_SAVED", "saved")
    with patch(
        "hacksaws._sessions.save_target_from_session",
        return_value=expected,
        create=True,
    ) as save:
        parsed = _cli._create_parser().parse_args(
            [
                "target",
                "add",
                "Agent",
                "--from-session",
                "debug",
                "--location",
                "horizon",
            ]
        )
        assert _cli._run_resource(parsed) is expected
    save.assert_called_once_with(parsed)

    conflicting = _cli._create_parser().parse_args(
        [
            "target",
            "add",
            "Agent",
            "--from-session",
            "debug",
            "--source-account",
            "Prod",
        ]
    )
    with pytest.raises(_configs.OperationalError, match="reconstructs"):
        _cli._run_resource(conflicting)

    explicit_default = _cli._create_parser().parse_args(
        [
            "target",
            "add",
            "Agent",
            "--from-session",
            "debug",
            "--source-profile",
            "default",
        ]
    )
    with pytest.raises(_configs.OperationalError, match="--source-profile"):
        _cli._run_resource(explicit_default)


def test_parse_failure_event_is_structural_searchable_and_cp1252_safe(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated(monkeypatch, tmp_path)
    result = _cli.console_main(["web", "in", "debug", "--save-name", "--json"])
    assert result.code == "ARGUMENT_ERROR"
    capsys.readouterr()
    record = _history.list_records(failure="missing-option-value")[0]
    assert record["command"] == "pk.login"
    event = _history.parse_failure_event(record)
    assert event is not None
    assert event["kind"] == "parse.missing-option-value"
    rendered = _cli._history_show_text(record)
    rendered.encode("cp1252")
    assert "Safe attempted shape:" in rendered
    assert "raw arguments and values were never stored" in rendered
    assert "debug" not in rendered


def test_parse_observer_never_stores_unknown_tokens_paths_or_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated(monkeypatch, tmp_path)
    canary = "DO-NOT-STORE-PARSE-CANARY"
    result = _cli.console_main(
        [
            "web",
            "in",
            "debug",
            f"--{canary}",
            str(tmp_path / f"{canary}.yaml"),
            "--external-id",
            canary,
            "--json",
        ]
    )
    assert result.exit_code == _configs.EXIT_USAGE
    capsys.readouterr()
    _history.list_records()
    files = [
        _history.database_path(),
        *_history.database_path().parent.glob("history.db-*"),
    ]
    assert all(
        canary.encode() not in path.read_bytes() for path in files if path.exists()
    )
    exported = _history.export_records(_history.list_records(), format_name="json")
    assert canary not in exported


@pytest.mark.parametrize(
    "arguments",
    [
        ["web", "in", "profile-canary", "--directory", "/var/path-canary"],
        [
            "web",
            "in",
            "profile-canary",
            "--directory",
            r"C:\Users\name\path-canary",
        ],
        ["web", "in", "profile-canary", "--", "tail-canary", "secret-canary"],
    ],
)
def test_parse_observer_redacts_platform_paths_and_literal_tail(
    arguments: list[str],
) -> None:
    observed = _history.observe_arguments(_cli._create_parser(), arguments)
    encoded = json.dumps(observed, sort_keys=True)
    assert "profile-canary" not in encoded
    assert "path-canary" not in encoded
    assert "tail-canary" not in encoded
    assert "secret-canary" not in encoded
    assert int(observed["opaque"]["tail"]) <= 255  # type: ignore[index]


def test_parse_observer_caps_opaque_input_without_retaining_tokens() -> None:
    canary = "never-store-long-token"
    arguments = ["web", "in", *[f"--{canary}-{index}" for index in range(400)]]
    observed = _history.observe_arguments(_cli._create_parser(), arguments)
    encoded = json.dumps(observed, sort_keys=True)
    assert canary not in encoded
    assert observed["opaque"] == {
        "options": 255,
        "positionals": 0,
        "tail": 0,
        "truncated": True,
    }


def test_parse_event_edge_cases_remain_bounded_and_typed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolated(monkeypatch, tmp_path)
    parser = _cli._create_parser()
    extra = _history.observe_arguments(parser, ["web", "in", "debug", "extra"])
    assert extra["inferredKind"] == "extra-positional"

    disabled = _history.HistoryHandle(id=None, started_monotonic=0, enabled=False)
    _history.note_parse_failure(disabled, extra, phase="not-a-phase")

    handle = _history.begin(json_mode=False, interactive=False)
    oversized = {
        **extra,
        "options": [
            {
                "name": f"known-option-{index}",
                "count": 1,
                "valueClass": "identifier",
                "valueState": "present",
            }
            for index in range(256)
        ],
    }
    _history.note_parse_failure(
        handle, oversized, phase="not-a-phase", kind="INVALID KIND"
    )
    _history.note_session_save(
        status="not-a-status",
        requested=True,
        credentials_active=True,
    )
    _history.finish(handle, _configs.Result("ARGUMENT_ERROR", "", 2))

    record = _history.list_records()[0]
    event = _history.parse_failure_event(record)
    assert event is not None
    assert event["kind"] == "parse.invalid-syntax"
    event_data = event["data"]
    assert isinstance(event_data, dict)
    assert event_data["phase"] == "argparse"
    assert event_data["structure"] == {
        "opaque": extra["opaque"],
        "truncated": True,
    }


def test_semantic_shape_error_is_classified_as_usage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated(monkeypatch, tmp_path)
    result = _cli.console_main(["mfa", "in", "debug", "123456", "--policy", "ReadOnly"])
    assert result.code == "ARGUMENT_ERROR"
    assert result.exit_code == _configs.EXIT_USAGE
    capsys.readouterr()
    record = _history.list_records(phase="semantic")[0]
    event = _history.parse_failure_event(record)
    assert event is not None
    assert event["kind"] == "parse.invalid-combination"


def test_session_save_event_is_safe_visible_and_health_checked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolated(monkeypatch, tmp_path)
    canary = "do-not-store-save-path"
    handle = _history.begin(json_mode=False, interactive=True)
    _history.note_session_save(
        status="failed",
        target=str(tmp_path / f"{canary}.yaml"),
        boundary="AgentBoundary",
        requested=True,
        credentials_active=True,
    )
    _history.finish(handle, _configs.Result("PARTIAL_SUCCESS", "ignored", 1))

    record = _history.list_records()[0]
    event = _history.session_save_event(record)
    assert event is not None
    assert event["kind"] == "session-save.failed"
    assert event["data"] == {
        "eventSchemaVersion": 1,
        "redactionVersion": 2,
        "status": "failed",
        "target": None,
        "boundary": "AgentBoundary",
        "requested": True,
        "credentialsActive": True,
    }
    assert canary not in _history.export_records([record], format_name="json")
    assert _history.status()["sessionSaves"] == 1
    assert _history.check()["ok"] is True
    rendered = _cli._history_show_text(record)
    assert "Session save: failed" in rendered
    rendered.encode("cp1252")


def test_schema_two_indexes_parse_events(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolated(monkeypatch, tmp_path)
    handle = _history.begin(json_mode=False, interactive=False)
    _history.finish(handle, _configs.Result("OK", ""))
    with closing(sqlite3.connect(_history.database_path())) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(events)")}
    assert "event_invocation_kind" in indexes


def test_schema_one_is_migrated_stepwise_to_schema_two(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolated(monkeypatch, tmp_path)
    handle = _history.begin(json_mode=False, interactive=False)
    _history.finish(handle, _configs.Result("OK", ""))
    path = _history.database_path()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("DROP INDEX event_invocation_kind")
        connection.execute("PRAGMA user_version = 1")
        connection.commit()
    _history._initialized_databases.discard(path)

    assert _history.status()["integrity"] == "ok"
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(events)")}
    assert "event_invocation_kind" in indexes
