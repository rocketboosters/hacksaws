"""Regression coverage for stale and blank ambient AWS environment state."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from botocore import loaders

from hacksaws import _aws_env
from hacksaws import _cli
from hacksaws import _configs
from hacksaws import _history
from hacksaws import _regions
from hacksaws import _sessions
from hacksaws import _state


def _clear_region_caches() -> None:
    _regions._partition_data.cache_clear()
    _regions._endpoint_data.cache_clear()
    _regions._region_registry.cache_clear()
    _regions._service_endpoint_prefix.cache_clear()


def _logout_args(directory: Path, profile: str = "dev") -> argparse.Namespace:
    return argparse.Namespace(
        target=None,
        directory=str(directory),
        profile=profile,
        aws_account_name=None,
        to=None,
        to_directory=None,
        ecr=False,
        podman=False,
        keep_ecr=False,
        force=False,
        except_profiles=[],
    )


def _temporary_profile(state_home: Path, directory: Path, profile: str = "dev") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    credentials = directory / "credentials"
    config = directory / "config"
    credentials.write_text(
        f"[{profile}]\naws_access_key_id = temporary\n"
        "aws_secret_access_key = temporary\n",
        encoding="utf-8",
    )
    config.write_text(f"[profile {profile}]\nregion = us-east-1\n", encoding="utf-8")
    key = f"{directory.absolute()}::{profile}"
    _state.save_sessions(
        {
            key: {
                "destination": str(directory.absolute()),
                "profile": profile,
                "auth_method": "browser",
                "backup": [],
                "section_backup": {
                    "credentials": {
                        "path": str(credentials.absolute()),
                        "section": profile,
                        "original": {"exists": False, "values": {}},
                        "installed": _sessions._section_state(credentials, profile),
                    },
                    "config": {
                        "path": str(config.absolute()),
                        "section": f"profile {profile}",
                        "original": {"exists": False, "values": {}},
                        "installed": _sessions._section_state(
                            config, f"profile {profile}"
                        ),
                    },
                },
                "ecr": [],
            }
        }
    )
    assert _state.root() == state_home


def test_aws_value_and_mapping_normalization_is_pure_and_lossless() -> None:
    source = {
        "AWS_PROFILE": "  ",
        "AWS_DEFAULT_PROFILE": "null",
        "AWS_REGION": "none",
        "AWS_DATA_PATH": " custom path ",
        "NOT_AWS": "",
    }

    assert _aws_env.normalize_aws_value("AWS_PROFILE", None) is None
    assert _aws_env.normalize_aws_value("AWS_PROFILE", "") is None
    assert _aws_env.normalize_aws_value("AWS_PROFILE", " \t") is None
    assert _aws_env.normalize_aws_value("AWS_PROFILE", "null") == "null"
    assert _aws_env.normalize_aws_value("AWS_PROFILE", "none") == "none"
    assert _aws_env.normalize_aws_value("NOT_AWS", "") == ""
    assert _aws_env.normalized_aws_environment(source) == {
        "AWS_DEFAULT_PROFILE": "null",
        "AWS_REGION": "none",
        "AWS_DATA_PATH": " custom path ",
        "NOT_AWS": "",
    }
    assert source["AWS_PROFILE"] == "  "


def test_clean_and_scoped_aws_environments_normalize_blanks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("AWS_UNKNOWN_BLANK", "  ")
    monkeypatch.setenv("AWS_DATA_PATH", "custom-data")
    monkeypatch.setenv("AWS_PROFILE", "none")
    clean = _sessions._clean_env()
    assert "AWS_UNKNOWN_BLANK" not in clean
    assert clean["AWS_DATA_PATH"] == "custom-data"
    assert "AWS_PROFILE" not in clean

    before = dict(os.environ)
    with _sessions._aws_environment(
        tmp_path / "config", tmp_path / "credentials", tmp_path / "cache"
    ):
        assert "AWS_UNKNOWN_BLANK" not in os.environ
        assert os.environ["AWS_DATA_PATH"] == "custom-data"
    assert dict(os.environ) == before


def test_blank_login_cache_and_region_environment_follow_existing_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_LOGIN_CACHE_DIRECTORY", " \t")
    assert _sessions._native_login_cache() == Path.home() / ".aws" / "login" / "cache"
    monkeypatch.setenv("AWS_LOGIN_CACHE_DIRECTORY", " custom-cache ")
    assert _sessions._native_login_cache() == Path(" custom-cache ").absolute()

    monkeypatch.setenv("AWS_REGION", " ")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
    preference = _regions.resolve_region_preference(source="us-east-1")
    assert preference.canonical == "us-west-2"
    assert preference.source == "aws-default-region-env"


def test_nonblank_aws_data_path_and_custom_alias_work_with_dangling_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    data = copy.deepcopy(loaders.create_loader().load_data("partitions"))
    partition = next(item for item in data["partitions"] if item["id"] == "aws")
    partition["regions"]["us-test-1"] = {"description": "Test Region"}
    data_path = tmp_path / "data"
    data_path.mkdir()
    (data_path / "partitions.json").write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setenv("AWS_DATA_PATH", str(data_path))
    monkeypatch.setenv("AWS_PROFILE", "removed-profile")
    _clear_region_caches()

    resolution = _regions.resolve_region(
        "test-region", custom_aliases={"test-region": {"region": "us-test-1"}}
    )
    assert resolution.canonical == "us-test-1"
    assert resolution.source == "custom"
    assert (
        next(
            item for item in _regions.region_registry() if item.name == "us-test-1"
        ).description
        == "Test Region"
    )


@pytest.mark.parametrize("variable", ["AWS_PROFILE", "AWS_DEFAULT_PROFILE"])
def test_local_commands_ignore_a_dangling_ambient_profile(
    variable: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    config = tmp_path / "aws-config"
    config.write_text("[profile available]\nregion=us-east-1\n", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv(variable, "removed-profile")
    other = "AWS_DEFAULT_PROFILE" if variable == "AWS_PROFILE" else "AWS_PROFILE"
    monkeypatch.delenv(other, raising=False)

    for arguments in (
        ["status"],
        ["history", "status"],
        ["config", "options"],
        ["target", "list"],
        ["boundary", "list"],
    ):
        _clear_region_caches()
        result = _cli.console_main(arguments)
        assert result.exit_code == 0, arguments


@pytest.mark.parametrize(
    ("value", "expected"),
    [("", False), ("  ", False), ("other", False), ("dev", True)],
)
@pytest.mark.parametrize("variable", ["AWS_PROFILE", "AWS_DEFAULT_PROFILE"])
def test_logout_stale_profile_warning_positive_and_negative_cases(
    variable: str,
    value: str,
    expected: bool,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    directory = tmp_path / "aws"
    monkeypatch.setenv(variable, value)
    other = "AWS_DEFAULT_PROFILE" if variable == "AWS_PROFILE" else "AWS_PROFILE"
    monkeypatch.delenv(other, raising=False)
    _temporary_profile(_state.root(), directory)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(directory / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(directory / "credentials"))

    outcome = _sessions._logout_key(
        f"{directory.absolute()}::dev", _logout_args(directory)
    )
    assert bool(outcome.get("warnings")) is expected
    if expected:
        assert f"$env:{variable} = $null" in outcome["warnings"][0]


def test_logout_does_not_warn_when_selected_profile_is_restored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("AWS_PROFILE", "dev")
    directory = tmp_path / "aws"
    directory.mkdir()
    (directory / "credentials").write_text("[dev]\nkey=value\n", encoding="utf-8")
    assert _sessions.stale_profile_environment_warnings(directory, "dev") == ()


@pytest.mark.parametrize(
    ("default_profile", "profile", "warning_variable"),
    [
        ("other", "dev", None),
        ("dev", "other", "AWS_DEFAULT_PROFILE"),
        ("  ", "dev", "AWS_PROFILE"),
    ],
)
def test_stale_profile_warning_uses_effective_selector_precedence(
    default_profile: str,
    profile: str,
    warning_variable: str | None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = tmp_path / "aws"
    directory.mkdir()
    config = directory / "config"
    credentials = directory / "credentials"
    config.write_text("", encoding="utf-8")
    credentials.write_text("", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials))
    monkeypatch.setenv("AWS_DEFAULT_PROFILE", default_profile)
    monkeypatch.setenv("AWS_PROFILE", profile)

    warnings = _sessions.stale_profile_environment_warnings(directory, "dev")
    if warning_variable is None:
        assert warnings == ()
    else:
        assert len(warnings) == 1
        assert warnings[0].startswith(f"{warning_variable} still selects")


@pytest.mark.parametrize("warnings", [(), ("stale selector",)])
def test_single_logout_json_omits_empty_warnings_and_includes_present_warnings(
    warnings: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    with (
        patch("hacksaws._sessions.recover_journal"),
        patch("hacksaws._sessions.logout", return_value=True),
        patch("hacksaws._sessions.logout_environment_warnings", return_value=warnings),
    ):
        result = _cli.console_main(["logout", "dev", "--json"])

    assert isinstance(result.data, dict)
    envelope = json.loads(capsys.readouterr().out)
    if warnings:
        assert result.data["warnings"] == list(warnings)
        assert envelope["data"]["warnings"] == list(warnings)
    else:
        assert "warnings" not in result.data
        assert "warnings" not in envelope["data"]


def test_history_settings_begin_and_finish_failures_preserve_command_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    sentinel = _configs.Result("SENTINEL", "", 7)
    with (
        patch("hacksaws._history._settings", side_effect=RuntimeError("config")),
        patch("hacksaws._cli._console_main_invocation", return_value=sentinel),
    ):
        assert _cli.console_main(["status"]) is sentinel
    assert "continuing without recording" in capsys.readouterr().err

    handle = _history.HistoryHandle(id="id", started_monotonic=0.0, enabled=True)
    with (
        patch("hacksaws._history.begin", side_effect=RuntimeError("begin")),
        patch("hacksaws._cli._console_main_invocation", return_value=sentinel),
    ):
        assert _cli.console_main(["status"]) is sentinel
    assert "continuing without recording" in capsys.readouterr().err

    with (
        patch("hacksaws._history.begin", return_value=handle),
        patch("hacksaws._history.finish", side_effect=RuntimeError("finish")),
        patch(
            "hacksaws._history.warn_unavailable",
            side_effect=RuntimeError("warning-output"),
        ),
        patch("hacksaws._cli._console_main_invocation", return_value=sentinel),
    ):
        assert _cli.console_main(["status"]) is sentinel

    with (
        patch("hacksaws._history.begin", return_value=handle),
        patch("hacksaws._history.finish", side_effect=RuntimeError("finish")),
        patch("hacksaws._cli._console_main_invocation", return_value=sentinel),
    ):
        assert _cli.console_main(["status"]) is sentinel
    assert "continuing without recording" in capsys.readouterr().err


def test_history_enrich_and_note_failures_do_not_block_requested_handlers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    status_data: dict[str, object] = {
        "sessions": [],
        "counts": {},
        "warnings": [],
    }
    with (
        patch("hacksaws._history.enrich", side_effect=RuntimeError("enrich")),
        patch("hacksaws._sessions.status_report", return_value=status_data) as handler,
        patch("hacksaws._cli._status_text", return_value="status survived"),
    ):
        status = _cli.console_main(["status"])
    assert status.exit_code == 0
    assert status.message == "status survived"
    assert "status survived" in capsys.readouterr().out
    handler.assert_called_once()

    mfa_args = argparse.Namespace(
        action="login",
        profile="dev",
        target=None,
        mfa_code="123456",
        mfa_code_stdin=False,
        json=False,
    )
    expected = _configs.Result("MFA_SENTINEL", "mfa survived", 9)
    with (
        patch("hacksaws._history.note_mfa_code", side_effect=RuntimeError("note")),
        patch("hacksaws._sessions.mfa_login", return_value=expected) as mfa_handler,
    ):
        assert _cli._run_mfa(_configs.Context(mfa_args)) is expected
    mfa_handler.assert_called_once()


def test_history_parse_and_failure_notes_preserve_real_errors_and_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    with patch(
        "hacksaws._history.note_parse_failure", side_effect=RuntimeError("parse-note")
    ):
        result = _cli.console_main(["not-a-command"])
    assert result.exit_code == _configs.EXIT_USAGE
    assert "invalid choice" in capsys.readouterr().err

    with (
        patch("hacksaws._history.fail", side_effect=RuntimeError("history-fail")),
        patch(
            "hacksaws._cli._console_main_invocation",
            side_effect=RuntimeError("real-command-failure"),
        ),
        pytest.raises(RuntimeError, match="real-command-failure"),
    ):
        _cli.console_main(["status"])


def test_integrated_logout_stale_environment_then_status_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    directory = tmp_path / "aws"
    _temporary_profile(_state.root(), directory)
    monkeypatch.setenv("AWS_PROFILE", "dev")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(directory / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(directory / "credentials"))

    logout = _cli.console_main(["logout", "dev", "--directory", str(directory)])
    assert logout.exit_code == 0
    assert "AWS_PROFILE still selects removed profile" in logout.message
    assert os.environ["AWS_PROFILE"] == "dev"
    _clear_region_caches()
    status = _cli.console_main(["status"])
    assert status.exit_code == 0


def _legacy_logout_inventory(directory: Path) -> dict[str, object]:
    return {
        "profiles": [
            {
                "auth_method": "legacy-mfa",
                "location": None,
                "profile": "dev",
                "directory": str(directory),
            }
        ]
    }


@pytest.mark.parametrize(
    ("variable", "json_mode"),
    [("AWS_PROFILE", False), ("AWS_DEFAULT_PROFILE", True)],
)
def test_legacy_logout_all_attaches_stale_selector_warning(
    variable: str,
    json_mode: bool,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    directory = tmp_path / "aws"
    directory.mkdir()
    config = directory / "config"
    credentials = directory / "credentials"
    config.write_text("[profile dev]\nregion=us-east-1\n", encoding="utf-8")
    credentials.write_text("[dev]\nkey=value\n", encoding="utf-8")
    monkeypatch.setenv(variable, "dev")
    other = "AWS_DEFAULT_PROFILE" if variable == "AWS_PROFILE" else "AWS_PROFILE"
    monkeypatch.delenv(other, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials))

    def remove_profile(_context: _configs.Context) -> None:
        config.write_text("", encoding="utf-8")
        credentials.write_text("", encoding="utf-8")

    arguments = ["logout", "--all", *(["--json"] if json_mode else [])]
    with (
        patch(
            "hacksaws._sessions.logout_all",
            return_value={"outcomes": [], "errors": []},
        ),
        patch(
            "hacksaws._sessions.profile_inventory",
            return_value=_legacy_logout_inventory(directory),
        ),
        patch("hacksaws._aws.logout", side_effect=remove_profile),
    ):
        result = _cli.console_main(arguments)

    assert isinstance(result.data, dict)
    outcome = result.data["outcomes"][0]
    assert f"$env:{variable} = $null" in outcome["warnings"][0]
    assert f"Warning: {variable} still selects removed profile" in result.message
    captured = capsys.readouterr()
    if json_mode:
        envelope = json.loads(captured.out)
        assert envelope["data"]["outcomes"][0]["warnings"] == outcome["warnings"]


@pytest.mark.parametrize(
    ("selector", "remove_profile"),
    [("", True), ("  ", True), ("other", True), ("dev", False)],
)
def test_legacy_logout_all_omits_warning_for_nonstale_selector_or_restored_profile(
    selector: str,
    remove_profile: bool,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    directory = tmp_path / "aws"
    directory.mkdir()
    config = directory / "config"
    credentials = directory / "credentials"
    config.write_text("[profile dev]\nregion=us-east-1\n", encoding="utf-8")
    credentials.write_text("[dev]\nkey=value\n", encoding="utf-8")
    monkeypatch.setenv("AWS_PROFILE", selector)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials))

    def finish_logout(_context: _configs.Context) -> None:
        if remove_profile:
            config.write_text("", encoding="utf-8")
            credentials.write_text("", encoding="utf-8")

    with (
        patch(
            "hacksaws._sessions.logout_all",
            return_value={"outcomes": [], "errors": []},
        ),
        patch(
            "hacksaws._sessions.profile_inventory",
            return_value=_legacy_logout_inventory(directory),
        ),
        patch("hacksaws._aws.logout", side_effect=finish_logout),
    ):
        result = _cli.console_main(["logout", "--all"])

    assert isinstance(result.data, dict)
    assert "warnings" not in result.data["outcomes"][0]
    assert "Warning:" not in result.message
