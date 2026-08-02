"""Command-surface coverage for explicit post-login role assumption."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from hacksaws import _cli
from hacksaws import _configs
from hacksaws import _state


class _Terminal:
    """Minimal interactive stream used by exact-confirmation tests."""

    @staticmethod
    def isatty() -> bool:
        return True


def _direct_arguments(*extra: str) -> argparse.Namespace:
    return _cli._create_parser().parse_args(
        [
            "assume",
            "admin",
            "--name",
            "horizon",
            "--role",
            "AgentSession",
            "--to",
            "default:agent",
            *extra,
        ]
    )


def _seed_presets(home: Path) -> None:
    data = _state.default_config()
    data["accounts"]["Prod"] = {"id": "123456789012", "partition": "aws"}
    data["boundaries"]["Read"] = {
        "role_arn": "arn:aws:iam::123456789012:role/AgentSession",
        "account": "Prod",
        "verified": False,
    }
    data["targets"]["Bounded"] = {
        "source_account": "Prod",
        "source_profile": "admin",
        "source_location": "horizon",
        "destination_location": "default",
        "destination_profile": "agent",
        "boundary": "Read",
    }
    data["targets"]["Open"] = {
        "source_account": "Prod",
        "source_profile": "admin",
        "source_directory": str((home / "aws-source").absolute()),
        "destination_location": "default",
        "destination_profile": "agent",
    }
    _state.save_config(data)


def test_assume_parser_exposes_explicit_grammar_and_teaching_help(
    capsys: pytest.CaptureFixture[str],
) -> None:
    direct = _direct_arguments(
        "--policy",
        "CloudWatchReadOnlyAccess",
        "--ttl",
        "45m",
        "--keep-ecr",
        "--replace",
        "--yes",
    )
    assert direct.access_type == "assume"
    assert direct.profile == "admin"
    assert direct.aws_account_name == "horizon"
    assert direct.role == "AgentSession"
    assert direct.to == "default:agent"
    assert direct.duration == "45m"
    assert direct.keep_ecr
    assert direct.replace
    assert direct.yes

    boundary = _cli._create_parser().parse_args(
        ["assume", "admin", "--as", "Read", "--to-profile", "agent"]
    )
    assert boundary.profile == "admin"
    assert boundary.boundary == "Read"
    assert boundary.to_profile == "agent"
    directory = _cli._create_parser().parse_args(
        [
            "assume",
            "admin",
            "--role",
            "AgentSession",
            "--to-directory",
            "./agent-aws",
            "--to-profile",
            "debug",
        ]
    )
    assert directory.to_directory == "./agent-aws"
    assert directory.to_profile == "debug"

    result = _cli.console_main(["assume", "--help"])
    help_text = capsys.readouterr().out
    assert result.code == "HELP"
    assert "existing AWS profile" in help_text
    assert "--self" in help_text
    assert "same endpoint" in help_text
    assert "--force" not in help_text


def test_assume_validation_normalizes_shorthand_and_rejects_unsafe_combinations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    _seed_presets(tmp_path)

    target = _cli._create_parser().parse_args(["assume", "!Bounded"])
    _cli._validate_assume(target)
    assert target.target == "+Bounded"
    assert target.profile is None

    open_target = _cli._create_parser().parse_args(
        [
            "assume",
            "--target",
            "Open",
            "--boundary",
            "Read",
            "--ttl",
            "45m",
            "--keep-source",
            "--keep-ecr",
            "--replace",
            "--yes",
        ]
    )
    _cli._validate_assume(open_target)
    assert open_target.target == "+Open"
    assert open_target.duration == "45m"
    assert open_target.keep_source
    default_source = _cli._create_parser().parse_args(
        ["assume", ".", "--role", "AgentSession", "--self"]
    )
    _cli._validate_assume(default_source)
    assert default_source.profile == "default"

    invalid = (
        ["assume", "--role", "AgentSession", "--self"],
        ["assume", "+", "--self"],
        ["assume", "+Open", "--target", "Bounded", "--self"],
        ["assume", "admin", "--role", "AgentSession"],
        ["assume", "admin", "--role", "AgentSession", "--self", "--keep-source"],
        ["assume", "admin", "--role", "AgentSession", "--to", "missing-colon"],
        [
            "assume",
            "admin",
            "--role",
            "AgentSession",
            "--to-directory",
            str(tmp_path / "agent"),
        ],
        [
            "assume",
            "admin",
            "--role",
            "AgentSession",
            "--to",
            "default:agent",
            "--to-profile",
            "other",
        ],
        [
            "assume",
            "admin",
            "--role",
            "AgentSession",
            "--self",
            "--to-profile",
            "other",
        ],
        ["assume", "+Bounded", "--policy", "Other"],
        ["assume", "+Bounded", "--name", "horizon"],
        ["assume", "+Bounded", "--to-profile", "other"],
        ["assume", "+Bounded", "--self"],
        ["assume", "+Open", "--role", "AgentSession"],
        ["assume", "+Open", "--policy", "Other"],
        ["assume", "+Open", "--account", "Prod"],
        ["assume", "+Open", "--external-id", "secret"],
        ["assume", "+Open", "--session-name", "agent"],
        ["assume", "+Open", "--region", "us-west-2"],
        ["assume", "+Open", "--self", "--boundary", "Read"],
        ["assume", "+Open"],
        ["assume", "admin", "--boundary", "Missing", "--self"],
    )
    for arguments in invalid:
        with pytest.raises(_configs.OperationalError):
            _cli._validate_assume(_cli._create_parser().parse_args(arguments))


def test_assume_noninteractive_requires_yes_without_executing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    executed: list[bool] = []
    preview = {
        "source": "horizon:admin",
        "destination": "default:agent",
        "role": "arn:aws:iam::123456789012:role/AgentSession",
        "account": "123456789012",
        "partition": "aws",
    }
    prepared = object()
    monkeypatch.setattr(_cli._sessions, "prepare_assume_role", lambda _ctx: prepared)
    monkeypatch.setattr(
        _cli._sessions,
        "assume_role_preview",
        lambda plan: preview if plan is prepared else pytest.fail("plan changed"),
    )
    monkeypatch.setattr(
        _cli._sessions,
        "assume_role",
        lambda _ctx, _plan: executed.append(True),
    )

    result = _cli._run_assume(_configs.Context(args=_direct_arguments()))

    assert result.code == "ASSUME_CONFIRMATION_REQUIRED"
    assert result.exit_code == _configs.EXIT_CANCELLED
    assert result.data == {"preview": preview}
    assert executed == []


def test_assume_exact_confirmation_and_yes_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    preview = {
        "source": "horizon:admin",
        "destination": "default:agent",
        "role": "AgentSession",
        "warnings": ["The source and destination identify the same endpoint."],
    }
    prepared = object()
    executed: list[bool] = []
    monkeypatch.setattr(_cli._sessions, "prepare_assume_role", lambda _ctx: prepared)
    monkeypatch.setattr(
        _cli._sessions,
        "assume_role_preview",
        lambda plan: preview if plan is prepared else pytest.fail("plan changed"),
    )
    monkeypatch.setattr(sys, "stdin", _Terminal())
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")
    monkeypatch.setattr(
        _cli._sessions,
        "assume_role",
        lambda _ctx, _plan: executed.append(True),
    )
    declined = _cli._run_assume(_configs.Context(args=_direct_arguments()))
    assert declined.code == "ASSUME_CANCELLED"
    assert executed == []
    assert "WARNING" in _cli._assume_preview_text(preview)

    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")

    def execute(context: _configs.Context, plan: object) -> _configs.Result:
        assert plan is prepared
        executed.append(context.args.yes)
        return _configs.Result(
            "ASSUME_ROLE",
            "Assumed AgentSession into default:agent.",
            data={"destination": "default:agent"},
        )

    monkeypatch.setattr(_cli._sessions, "assume_role", execute)
    accepted = _cli._run_assume(_configs.Context(args=_direct_arguments()))
    assert accepted.code == "ASSUME_ROLE"
    assert accepted.data == {"destination": "default:agent", "preview": preview}
    assert executed == [True]


def test_assume_json_is_secret_free_and_requires_yes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    preview = {
        "source": "horizon:admin",
        "destination": "default:agent",
        "role": "AgentSession",
        "account": "123456789012",
        "partition": "aws",
    }
    prepared = object()
    monkeypatch.setattr(_cli._sessions, "recover_journal", lambda: None)
    monkeypatch.setattr(_cli._sessions, "prepare_assume_role", lambda _ctx: prepared)
    monkeypatch.setattr(
        _cli._sessions,
        "assume_role_preview",
        lambda plan: preview if plan is prepared else pytest.fail("plan changed"),
    )
    monkeypatch.setattr(
        _cli._sessions,
        "assume_role",
        lambda _ctx, _plan: pytest.fail("AssumeRole must not execute without --yes."),
    )

    result = _cli.console_main(
        [
            "assume",
            "admin",
            "--name",
            "horizon",
            "--role",
            "AgentSession",
            "--to",
            "default:agent",
            "--json",
        ]
    )
    envelope = json.loads(capsys.readouterr().err)

    assert result.code == "ASSUME_CONFIRMATION_REQUIRED"
    assert envelope["error"]["data"] == {"preview": preview}
    rendered = json.dumps(envelope)
    assert repr(prepared) not in rendered
    assert "AccessKeyId" not in rendered
    assert "SecretAccessKey" not in rendered
    assert "SessionToken" not in rendered


def test_assume_confirmation_executes_only_the_prepared_plan_and_surfaces_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    _seed_presets(tmp_path)
    prepared = object()
    prepares: list[object] = []
    preview = {
        "source": {"profile": "admin"},
        "destination": {"profile": "agent"},
        "role": "arn:aws:iam::123456789012:role/AgentSession",
        "durationSeconds": 2700,
    }

    def prepare(_context: _configs.Context) -> object:
        prepares.append(prepared)
        return prepared

    def confirm(_prompt: str) -> str:
        data = _state.load_config()
        data["boundaries"]["Read"]["role_arn"] = (
            "arn:aws:iam::123456789012:role/ChangedAfterPreview"
        )
        _state.save_config(data)
        return "yes"

    def execute(_context: _configs.Context, plan: object) -> _configs.Result:
        assert plan is prepared
        message = (
            "AssumeRole plan changed after preview; no local credential changes "
            "were made. Review a fresh preview and retry."
        )
        raise _cli._sessions.AssumePlanChanged(message)

    monkeypatch.setattr(_cli._sessions, "recover_journal", lambda: None)
    monkeypatch.setattr(_cli._sessions, "prepare_assume_role", prepare)
    monkeypatch.setattr(
        _cli._sessions,
        "assume_role_preview",
        lambda plan: preview if plan is prepared else pytest.fail("plan changed"),
    )
    monkeypatch.setattr(_cli._sessions, "assume_role", execute)
    monkeypatch.setattr(sys, "stdin", _Terminal())
    monkeypatch.setattr("builtins.input", confirm)

    result = _cli.console_main(["assume", "+Bounded"])

    assert result.code == "OPERATIONAL_ERROR"
    assert "Review a fresh preview" in result.message
    assert prepares == [prepared]
    assert "Duration (seconds): 2700" in _cli._assume_preview_text(preview)
    assert capsys.readouterr().err


def test_assume_engine_revalidation_rejects_config_mutation_after_preview(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    _state.save_config(_state.default_config())
    args = _direct_arguments()
    context = _configs.Context(args=args)
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    data: dict[str, Any] = {
        "source": source,
        "source_profile": "admin",
        "destination": destination,
        "destination_profile": "agent",
        "source_cache": ([], [], []),
        "destination_cache": ([], [], []),
        "cache_expected": {},
        "hacksaws_config_expected": _cli._sessions._file_fingerprint(
            _state.root() / "config.json"
        ),
        "policy_source_expected": None,
        "source_expected": {
            "credentials": _cli._sessions._section_state(
                source / "credentials", "admin"
            ),
            "config": _cli._sessions._section_state(source / "config", "profile admin"),
        },
        "destination_expected": {
            "credentials": _cli._sessions._section_state(
                destination / "credentials", "agent"
            ),
            "config": _cli._sessions._section_state(
                destination / "config", "profile agent"
            ),
        },
    }
    prepared = _cli._sessions.AssumeRolePlan(
        data, _cli._sessions._assume_arguments_fingerprint(args)
    )
    changed = _state.load_config()
    changed["accounts"]["Prod"] = {"id": "123456789012", "partition": "aws"}
    _state.save_config(changed)

    with pytest.raises(_cli._sessions.AssumePlanChanged, match="fresh preview"):
        _cli._sessions._revalidate_assume_plan(context, prepared)


def test_assume_rejects_general_force_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = _cli.console_main(
        [
            "assume",
            "admin",
            "--role",
            "AgentSession",
            "--self",
            "--force",
        ]
    )
    assert result.code == "ARGUMENT_ERROR"
    assert result.exit_code == _configs.EXIT_USAGE
    assert "unrecognized arguments: --force" in capsys.readouterr().err
