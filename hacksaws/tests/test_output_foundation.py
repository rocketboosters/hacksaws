"""Focused coverage for shared presentation and schema-one UX foundations."""

from __future__ import annotations

import argparse
import io
import json
import os
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from rich.text import Text

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


class _TerminalStream(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_color_policy_handles_windows_style_non_tty_no_color_and_json() -> None:
    automatic = _output.OutputOptions(color="auto")
    assert not _output.color_enabled(automatic, stream=_NotATerminal(), environ={})
    assert not _output.color_enabled(
        automatic, stream=object(), environ={"NO_COLOR": "1"}
    )
    assert not _output.color_enabled(
        automatic, stream=_Terminal(), environ={"TERM": "dumb"}
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


def test_progress_is_stderr_only_and_json_always_suppresses_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with _output.ProgressReporter(
        _output.OutputOptions(), mode="always", delay=0
    ) as progress:
        progress.start("Discovering roles…")
        time.sleep(0.02)
        progress.update("Inspecting roles… 2 found")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Discovering roles" in captured.err
    assert "Inspecting roles" in captured.err

    stdout = io.StringIO()
    stderr = io.StringIO()
    with _output.ProgressReporter(
        _output.OutputOptions(json=True),
        mode="always",
        stream=stderr,
        delay=0,
    ) as progress:
        progress.start("must not render")
        progress.update("still hidden")
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == ""


def test_plain_progress_sanitizes_terminal_controls_and_honors_delay() -> None:
    stream = io.StringIO()
    progress = _output.ProgressReporter(
        _output.OutputOptions(color="never"),
        mode="always",
        stream=stream,
        delay=0.05,
    )
    progress.start("Inspecting\x1b[31m roles\r\n")
    progress.close()
    assert stream.getvalue() == ""

    with _output.ProgressReporter(
        _output.OutputOptions(color="never"),
        mode="always",
        stream=stream,
        delay=0,
    ) as visible:
        visible.start("Inspecting\x1b[31m roles\r\n")
        time.sleep(0.02)
    rendered = stream.getvalue()
    assert "Inspecting roles" in rendered
    assert "\x1b" not in rendered
    assert "\r" not in rendered


def test_progress_auto_mode_respects_terminal_and_plain_output_policies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redirected = io.StringIO()
    with _output.ProgressReporter(
        _output.OutputOptions(), mode="auto", stream=redirected, delay=0
    ) as quiet:
        quiet.start("must remain quiet")
        time.sleep(0.02)
    assert redirected.getvalue() == ""

    for environment in ({"NO_COLOR": "1"}, {"TERM": "dumb"}):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)
        for key, value in environment.items():
            monkeypatch.setenv(key, value)
        terminal = _TerminalStream()
        with _output.ProgressReporter(
            _output.OutputOptions(), mode="auto", stream=terminal, delay=0
        ) as plain:
            plain.start("Validating ownership…")
            time.sleep(0.02)
        assert "Validating ownership" in terminal.getvalue()
        assert "\x1b" not in terminal.getvalue()

    terminal = _TerminalStream()
    with _output.ProgressReporter(
        _output.OutputOptions(color="never"),
        mode="auto",
        stream=terminal,
        delay=0,
    ) as no_color:
        no_color.start("Applying filters…")
        time.sleep(0.02)
    assert "Applying filters" in terminal.getvalue()
    assert "\x1b" not in terminal.getvalue()


def test_rich_progress_lifecycle_updates_elapsed_status_and_clears() -> None:
    terminal = _TerminalStream()
    reporter = _output.ProgressReporter(
        _output.OutputOptions(color="always"),
        mode="auto",
        stream=terminal,
        delay=0,
    )
    assert reporter.enabled is True
    with reporter:
        assert reporter.start("Discovering roles…") is reporter
        time.sleep(0.03)
        reporter.update("Validating ownership… 1/2")
        assert reporter.message == "Validating ownership… 1/2"
        time.sleep(0.52)
    assert "Validating ownership" in terminal.getvalue()


def test_plain_progress_deduplicates_milestones_and_confirmation_shortcut() -> None:
    stream = io.StringIO()
    reporter = _output.ProgressReporter(
        _output.OutputOptions(color="never"),
        mode="always",
        stream=stream,
        delay=0,
    )
    with reporter:
        reporter.start("Applying filters…")
        time.sleep(0.02)
        reporter.update("Applying filters…")
    assert stream.getvalue().count("Applying filters") == 1
    assert _output.confirm("Continue?", assume_yes=True) is True


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


def test_status_help_teaches_compact_auth_and_scope_semantics(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = _cli.console_main(["status", "--help"])
    rendered = capsys.readouterr().out
    assert result.exit_code == 0
    assert "AUTH values:" in rendered
    assert "web→role" in rendered
    assert "SCOPE examples:" in rendered
    assert "AgentSession (@Guardrail) → ReadLogs" in rendered
    assert "Hacksaws boundary preset" in rendered


def test_status_text_golden_is_compact_and_self_explaining() -> None:
    rendered = _cli._status_text(
        {
            "sessions": [
                {
                    "location": "default",
                    "profile": "debug",
                    "state": "active",
                    "auth_method": "browser-boundary",
                    "target_account": "123456789012",
                    "expires_at": "future",
                    "remaining_seconds": 3583,
                    "effective_scope": {
                        "kind": "role-session",
                        "role_label": "TerraformUnlimited",
                        "boundary": None,
                        "policy_label": "CloudWatchReadOnlyAccess",
                    },
                }
            ]
        }
    )
    assert rendered == (
        "PROFILE  REGION  STATE  AUTH      ACCOUNT       SCOPE"
        "                                          TTL\n"
        "-------  ------  -----  --------  ------------  "
        "---------------------------------------------  ---\n"
        "debug            🟢     web→role  123456789012  "
        "TerraformUnlimited → CloudWatchReadOnlyAccess  60m\n"
        "\n"
        "State: 1 🟢active"
    )
    assert "LOCATION" not in rendered
    assert "arn:" not in rendered
    assert "\x1b" not in rendered
    assert max(Text.from_ansi(line).cell_len for line in rendered.splitlines()) <= 100


def test_status_text_empty_and_stable_mixed_state_counts() -> None:
    assert _cli._status_text({"sessions": []}) == "(none)"
    sessions = [
        {"state": "future", "profile": "unknown"},
        {"state": "expired", "profile": "old"},
        {"state": "active", "profile": "one"},
        {"state": "missing", "profile": "gone"},
        {"state": "active", "profile": "two"},
    ]
    rendered = _cli._status_text({"sessions": sessions})
    assert rendered.endswith(
        "State: 2 🟢active | 1 🔴expired | 1 ❌missing | 1 ❔unknown/inconclusive"
    )
    assert rendered.count("\n\nState:") == 1
    assert "Auth  " not in rendered
    assert "Scope  " not in rendered


def test_status_text_recomputes_optional_columns_and_state_counts() -> None:
    report = {
        "sessions": [
            {
                "location": "default",
                "destination": "ignored",
                "profile": "dev",
                "state": "expiring",
                "auth_method": "mfa",
                "role": "arn:aws:iam::123456789012:role/team/Agent",
                "source_account": "123456789012",
                "expires_at": "future",
                "remaining_seconds": 900,
                "effective_scope": {
                    "kind": "role-session",
                    "role_label": "team/Agent",
                    "boundary": None,
                    "policy_label": None,
                },
                "verification": {"status": "verified"},
            },
            {
                "location": "horizon",
                "profile": "admin",
                "state": "drifted",
                "auth_method": "legacy-mfa",
                "source_account": "210987654321",
                "expires_at": "future",
                "remaining_seconds": 7200,
                "effective_scope": {
                    "kind": "legacy-unknown",
                    "role_label": None,
                    "boundary": None,
                    "policy_label": None,
                },
                "verification": {"status": "skipped"},
            },
        ]
    }
    rendered = _cli._status_text(report)
    lines = rendered.splitlines()
    assert "LOCATION" in lines[0]
    assert "TTL" in lines[0]
    assert "VERIFY" in lines[0]
    assert "default" in lines[2]
    assert "15m" in lines[2]
    assert "verified" in lines[2]
    assert "horizon" in lines[3]
    assert "unknown (legacy)" in lines[3]
    assert "skipped" not in rendered
    assert rendered.endswith("State: 1 🟡expiring | 1 ⚠️drifted")
    assert "Auth  " not in rendered
    assert "Scope  " not in rendered
    assert all(" - " not in line for line in lines[2:4])

    filtered = _cli._status_text({"sessions": [report["sessions"][1]]})
    assert "LOCATION" in filtered
    assert "TTL" not in filtered
    assert "VERIFY" not in filtered
    assert "🟡" not in filtered
    assert "mfa→role" not in filtered
    assert filtered.endswith("State: 1 ⚠️drifted")


@pytest.mark.parametrize(
    ("state", "seconds", "expected"),
    [
        ("active", None, ""),
        ("active", "not-a-duration", ""),
        ("active", 0.25, "<1m"),
        ("active", 59.99, "<1m"),
        ("active", 60, "1m"),
        ("expiring", 89, "1m"),
        ("expiring", 90, "2m"),
        ("expiring", 900, "15m"),
        ("active", 3583, "60m"),
        ("active", 7199, "120m"),
        ("active", 7200, "2h"),
        ("active", 8999, "2h"),
        ("active", 9000, "3h"),
        ("active", 0, ""),
        ("expiring", -1, ""),
        ("expired", 0, ""),
        ("expired", 3583, ""),
        ("invalid", 3583, ""),
        ("missing", 3583, ""),
        ("drifted", 3583, ""),
        ("legacy-unverified", 3583, ""),
        ("logout-residue", 3583, ""),
        ("ecr-only", 3583, ""),
    ],
)
def test_status_ttl_boundaries_are_deterministic(
    state: str, seconds: float | None, expected: str
) -> None:
    assert _cli._status_ttl({"state": state, "remaining_seconds": seconds}) == expected


def test_status_ttl_column_requires_a_positive_active_or_expiring_value() -> None:
    sessions = [
        {
            "location": "default",
            "profile": state,
            "state": state,
            "expires_at": "present",
            "remaining_seconds": 3600,
        }
        for state in (
            "expired",
            "invalid",
            "logout-residue",
            "ecr-only",
            "missing",
            "drifted",
            "legacy-unverified",
            "future",
        )
    ]
    sessions.append(
        {
            "location": "default",
            "profile": "zero",
            "state": "active",
            "expires_at": "present",
            "remaining_seconds": 0,
        }
    )
    rendered = _cli._status_text({"sessions": sessions})
    assert "TTL" not in rendered.splitlines()[0]
    assert rendered.endswith(
        "State: 1 🟢active | 1 🔴expired | 1 ⚠️drifted | "
        "1 ⚠️legacy-unverified | 1 ❌missing | 1 ❌invalid | "
        "1 🧹logout-residue | 1 🧹ECR-only | 1 ❔unknown/inconclusive"
    )


@pytest.mark.parametrize(
    ("method", "role", "expected"),
    [
        ("browser-native", None, "web"),
        ("browser-boundary", "role", "web→role"),
        ("mfa", None, "mfa"),
        ("mfa", "role", "mfa→role"),
        ("assume-role", "role", "role"),
        ("legacy-mfa", None, "legacy"),
        ("new-method", None, "unknown"),
    ],
)
def test_status_auth_mapping_is_stable(
    method: str, role: str | None, expected: str
) -> None:
    assert _cli._status_auth({"auth_method": method, "role": role})[0] == expected


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("active", "🟢"),
        ("expiring", "🟡"),
        ("expired", "🔴"),
        ("drifted", "⚠️"),
        ("legacy-unverified", "⚠️"),
        ("missing", "❌"),
        ("invalid", "❌"),
        ("logout-residue", "🧹"),
        ("ecr-only", "🧹"),
        ("future-state", "❔"),
    ],
)
def test_status_state_mapping_is_stable(state: str, expected: str) -> None:
    assert _cli._status_state({"state": state})[0] == expected


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("account-login", "account login"),
        ("mfa-session", "MFA session"),
        ("ecr-only", "ECR only"),
        ("logout-residue", "logout residue"),
        ("legacy-unknown", "unknown (legacy)"),
        ("unknown", "unknown session"),
        ("future-kind", "unknown session"),
    ],
)
def test_status_scope_non_role_kinds_are_honest(kind: str, expected: str) -> None:
    assert (
        _cli._status_scope(
            {
                "effective_scope": {
                    "kind": kind,
                    "role_label": None,
                    "policy_label": None,
                }
            }
        )
        == expected
    )


def test_status_scope_has_honest_malformed_role_fallback() -> None:
    assert (
        _cli._status_scope(
            {
                "effective_scope": {
                    "kind": "role-session",
                    "role_label": None,
                    "policy_label": "session policy",
                }
            }
        )
        == "role session → session policy"
    )


def test_status_scope_distinguishes_iam_role_from_hacksaws_boundary() -> None:
    item = {
        "effective_scope": {
            "kind": "role-session",
            "role_label": "AgentSession",
            "boundary_label": "Guardrail",
            "policy_label": "ReadLogs",
        }
    }
    assert _cli._status_scope(item) == "AgentSession (@Guardrail) → ReadLogs"
    rendered = _cli._status_text(
        {
            "sessions": [
                {
                    **item,
                    "location": "default",
                    "profile": "agent",
                    "state": "active",
                    "auth_method": "assume-role",
                    "target_account": "123456789012",
                }
            ]
        }
    )
    assert "AgentSession (@Guardrail) → ReadLogs" in rendered
    assert "@name = Hacksaws boundary preset" not in rendered
    assert "→ = restrictive session policy" not in rendered
    assert rendered.endswith("State: 1 🟢active")


def test_status_scope_supports_legacy_records_without_leaking_arns() -> None:
    assert (
        _cli._status_scope(
            {
                "boundary": None,
                "role": "arn:aws:iam::123456789012:role/team/Agent",
                "policy": "arn:aws:iam::aws:policy/ReadOnlyAccess",
            }
        )
        == "team/Agent → ReadOnlyAccess"
    )


def test_status_text_sanitizes_hostile_untrusted_cells_before_layout() -> None:
    escape = "\x1b"
    rendered = _cli._status_text(
        {
            "sessions": [
                {
                    "location": f"{escape}]0;owned\x07horizon\rnext",
                    "profile": f"{escape}[31mprod{escape}[0m\nforged\tcell\u202e",
                    "state": "active",
                    "auth_method": "assume-role",
                    "target_account": "123456789012\x00",
                    "effective_scope": {
                        "kind": "role-session",
                        "role_label": "界e\u0301Agent\x00",
                        "boundary_label": f"Guard{escape}[2J",
                        "policy_label": (
                            f"Read{escape}]8;;https://invalid.example\x07Logs"
                            f"{escape}]8;;\x07\nInjected"
                        ),
                    },
                }
            ]
        }
    )
    assert "\x1b" not in rendered
    assert "\x00" not in rendered
    assert "\u202e" not in rendered
    assert "https://invalid.example" not in rendered
    assert "horizon next" in rendered
    assert "prod forged cell" in rendered
    assert "界e\u0301Agent (@Guard) → ReadLogs Injected" in rendered
    assert len(rendered.splitlines()) == 5
    assert _cli._safe_terminal_text("safe\x1b]0;unterminated") == "safe"
    assert _cli._safe_terminal_text("safe\x9d0;owned\x9ctext") == "safetext"


def test_status_verification_uses_only_meaningful_results() -> None:
    assert _cli._status_verification({"verification": {"status": "error"}}) == "error"
    assert (
        _cli._status_verification({"verification": {"status": "mismatch"}})
        == "mismatch (unknown)"
    )
    assert _cli._status_verification({"verification": {"status": "skipped"}}) == ""
    assert _cli._status_verification({}) == ""


def test_status_verification_distinguishes_match_mismatch_and_error() -> None:
    base = {
        "location": "default",
        "state": "active",
        "auth_method": "browser-native",
        "target_account": "123456789012",
        "effective_scope": {
            "kind": "account-login",
            "role_label": None,
            "boundary_label": None,
            "policy_label": None,
        },
    }
    rendered = _cli._status_text(
        {
            "sessions": [
                {
                    **base,
                    "profile": "matched",
                    "verification": {"status": "verified"},
                },
                {
                    **base,
                    "profile": "mismatch\nforged",
                    "verification": {
                        "status": "mismatch",
                        "expected_account": "123456789012",
                        "actual_account": "210987654321\x1b[31m",
                    },
                },
                {
                    **base,
                    "profile": "error",
                    "verification": {"status": "error", "message": "denied"},
                },
                {
                    **base,
                    "profile": "not-applicable",
                    "verification": {"status": "skipped"},
                },
            ]
        }
    )
    assert "verified" in rendered
    assert "mismatch" in rendered
    assert "error" in rendered
    assert "skipped" not in rendered
    assert "mismatch (210987654321)" in rendered
    assert "Verify  " not in rendered
    assert "mismatch forged" in rendered
    assert rendered.endswith("State: 4 🟢active")
    assert "\x1b" not in rendered


def test_text_table_aligns_terminal_cells_and_strips_controls() -> None:
    rendered = _cli._text_table(
        ["STATE", "VALUE"],
        [
            ["🟢", "emoji"],
            ["界", "wide"],
            ["e\u0301", "combining"],
            ["\x1b[31mred\x1b[0m", "ansi"],
        ],
    )
    expected_column = None
    for line, value in zip(
        rendered.splitlines()[2:], ["emoji", "wide", "combining", "ansi"], strict=True
    ):
        plain = Text.from_ansi(line).plain
        offset = Text(plain[: plain.index(value)]).cell_len
        expected_column = expected_column or offset
        assert offset == expected_column
    assert "\x1b" not in rendered
    assert "red" in rendered


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


def test_target_list_text_is_empty_placeholder_for_no_targets() -> None:
    assert _cli._target_list_text({}) == "(none)"


def test_target_list_text_renders_dynamic_columns_order_and_legend() -> None:
    items = {
        "Deploy": {
            "source_account": "Prod",
            "source_profile": "admin",
            "source_directory": "/abs/source",
            "destination_location": "west",
            "destination_profile": "release",
            "boundary": "Guard",
            "region": "us-east-1",
            "description": "deploy   target\nnotes",
        },
        "Simple": {
            "source_account": "Dev",
            "source_profile": "dev",
            "source_location": "default",
        },
    }
    rendered = _cli._target_list_text(items)

    assert rendered == (
        "NAME    ACCOUNT  PROFILE  LOCATION        →PROFILE  →LOCATION  "
        "BOUNDARY  REGION     DESC\n"
        "------  -------  -------  --------------  --------  ---------  "
        "--------  ---------  -------------------\n"
        "Deploy  Prod     admin    📁 /abs/source  release   ⌖ west     "
        "Guard     us-east-1  deploy target notes\n"
        "Simple  Dev      dev      ⌖ default       -         -          "
        "-         -          -\n\n"
        "Key: ⌖ location  📁 directory  → destination"
    )
    lines = rendered.splitlines()
    # Fixed then dynamic column order, headers uppercase.
    assert lines[0].split() == [
        "NAME",
        "ACCOUNT",
        "PROFILE",
        "LOCATION",
        "→PROFILE",
        "→LOCATION",
        "BOUNDARY",
        "REGION",
        "DESC",
    ]
    # Configured insertion order is preserved (Deploy before Simple).
    assert lines[2].startswith("Deploy")
    assert lines[3].startswith("Simple")
    # Missing optional cells on the second row render '-', and description
    # whitespace (including embedded newlines) is collapsed, not truncated.
    assert "deploy target notes" in rendered
    # Legend appears exactly once, after exactly one blank line, with
    # deterministic symbol order and only symbols actually used.
    assert "\n\nKey: ⌖ location  📁 directory  → destination" in rendered
    assert rendered.count("Key:") == 1


def test_target_list_text_omits_unused_optional_columns_and_destination_key() -> None:
    items = {
        "Solo": {
            "source_account": "Prod",
            "source_profile": "admin",
            "source_location": "default",
        }
    }
    rendered = _cli._target_list_text(items)
    header = rendered.splitlines()[0]
    assert header.split() == ["NAME", "ACCOUNT", "PROFILE", "LOCATION"]
    assert "→" not in rendered
    assert "📁" not in rendered
    assert "Key: ⌖ location" in rendered
    assert "destination" not in rendered


def test_boundary_list_text_is_empty_placeholder_for_no_boundaries() -> None:
    assert _cli._boundary_list_text({"policies": {}}, {}) == "(none)"


def test_boundary_list_text_role_suffix_covers_full_path_after_role() -> None:
    items = {
        "Guard": {
            "role_arn": "arn:aws:iam::123456789012:role/team/nested/Read",
            "account": "Prod",
        }
    }
    rendered = _cli._boundary_list_text({"policies": {}}, items)
    lines = rendered.splitlines()
    assert lines[0].split() == ["NAME", "ACCOUNT", "ROLE"]
    assert "team/nested/Read" in lines[2]


def test_boundary_list_text_dynamic_columns_ttl_masking_and_verified() -> None:
    data = {"policies": {"Custom.json": {"file": "stored_session_policies/x.yaml"}}}
    items: dict[str, dict[str, Any]] = {
        "Guard": {
            "role_arn": "arn:aws:iam::123456789012:role/Read",
            "account": "Prod",
            "policy": "custom.json",
            "external_id": "abcdef123456",
            "duration": 5430,
            "verified": True,
            "description": "guard   boundary",
        },
        "Bare": {
            "role_arn": "arn:aws:iam::123456789012:role/Bare",
            "account": "Prod",
        },
    }
    rendered = _cli._boundary_list_text(data, items)

    assert rendered == (
        "NAME   ACCOUNT  ROLE  POLICY       TTL       EXT ID  VERIFIED  DESC\n"
        "-----  -------  ----  -----------  --------  ------  --------  "
        "--------------\n"
        "Guard  Prod     Read  custom.json  1h30m30s  ab…56   ✓         "
        "guard boundary\n"
        "Bare   Prod     Bare  -            -         -       ?         -\n\n"
        "Key: ✓ verified  ? unverified"
    )
    lines = rendered.splitlines()
    assert lines[0].split() == [
        "NAME",
        "ACCOUNT",
        "ROLE",
        "POLICY",
        "TTL",
        "EXT",
        "ID",
        "VERIFIED",
        "DESC",
    ]
    # Configured order preserved.
    assert lines[2].startswith("Guard")
    assert lines[3].startswith("Bare")
    # Case-insensitive configured-name precedence keeps the raw boundary
    # reference unmarked, even though it ends in .json.
    assert "custom.json 📄" not in rendered
    assert "custom.json ☁" not in rendered
    # External id masking: never the raw secret.
    assert "abcdef123456" not in rendered
    # Legend has exactly one blank line then Key:, deterministic used-only
    # order, omitting unused policy-classification symbols.
    assert rendered.count("Key:") == 1
    assert "☁" not in rendered
    assert "📄" not in rendered


def test_boundary_policy_precedence_configured_name_beats_arn_and_file_forms() -> None:
    data = {"policies": {"Custom.json": {"file": "x.yaml"}}}
    # Configured name wins case-insensitively and is preserved unmarked, even
    # though the stored reference casing differs and it ends in .json.
    assert _cli._boundary_policy_display(data["policies"], "custom.json") == (
        "custom.json"
    )
    assert _cli._boundary_policy_display(data["policies"], "CUSTOM.JSON") == (
        "CUSTOM.JSON"
    )
    # A managed-policy ARN not matching any configured name is marked with the
    # cloud symbol, keyed off capture group 3 of _policies.POLICY_ARN.
    assert (
        _cli._boundary_policy_display({}, "arn:aws:iam::aws:policy/ReadOnlyAccess")
        == "ReadOnlyAccess ☁"
    )
    # A persisted-schema-valid suffix file that matches neither is marked with
    # the file symbol and its reference is preserved unmarked otherwise.
    assert (
        _cli._boundary_policy_display({}, "local-policy.yaml") == "local-policy.yaml 📄"
    )


def test_format_ttl_preserves_exact_duration() -> None:
    assert _cli._format_ttl(900) == "15m"
    assert _cli._format_ttl(3600) == "1h"
    assert _cli._format_ttl(5400) == "1h30m"
    assert _cli._format_ttl(3630) == "1h0m30s"
    assert _cli._format_ttl(45) == "45s"


def test_mask_external_id_never_exposes_raw_value() -> None:
    assert _cli._mask_external_id("abcdef123456") == "ab…56"
    assert _cli._mask_external_id("abcde") == "••••"
    assert _cli._mask_external_id("abcdef") == "ab…ef"
    for masked in ("ab…56", "••••", "ab…ef"):
        assert "abcdef123456" not in masked


def test_collapse_whitespace_normalizes_without_truncating() -> None:
    long_text = "word " * 200
    collapsed = _cli._collapse_whitespace(f"  {long_text}\n\t trailing  ")
    assert collapsed == f"{'word ' * 200}trailing".strip()
    assert "  " not in collapsed
    assert len(collapsed) > 100
