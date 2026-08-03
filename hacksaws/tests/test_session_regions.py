"""Focused coverage for profile-region session lifecycle behavior."""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import patch

import pytest

from hacksaws import _cli
from hacksaws import _configs
from hacksaws import _sessions
from hacksaws import _state


def _configure_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "hacksaws-home"))
    _state.save_config(_state.default_config())


def _profile_args(
    aws: Path, action: str, region: str | None = None
) -> argparse.Namespace:
    arguments = ["profile", "region", action]
    if region is not None:
        arguments.append(region)
    arguments.extend(("--directory", str(aws), "--profile", "debug"))
    return _cli._create_parser().parse_args(arguments)


def _write_profile(aws: Path, region: str | None) -> None:
    parser = _sessions._read_ini(aws / "config")
    parser["profile debug"] = {"output": "json"}
    if region:
        parser["profile debug"]["region"] = region
    _sessions._write_ini(aws / "config", parser)


def _managed_session(
    aws: Path, *, auth_method: str = "assume-role"
) -> dict[str, object]:
    config = aws / "config"
    return {
        "destination": str(aws.absolute()),
        "profile": "debug",
        "auth_method": auth_method,
        "source_partition": "aws",
        "section_backup": {
            "config": {
                "path": str(config.absolute()),
                "section": "profile debug",
                "original": {
                    "exists": True,
                    "values": {"output": "json", "region": "us-east-1"},
                },
                "installed": _sessions._section_state(config, "profile debug"),
            }
        },
        "ecr": [],
    }


def test_profile_region_crud_and_same_region_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_home(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    _write_profile(aws, None)

    result = _cli._run_profile(_profile_args(aws, "set", "usw2"))
    assert result.code == "PROFILE_REGION_SET"
    assert isinstance(result.data, dict)
    assert result.data["region"] == "us-west-2"
    assert _sessions._profile_region(aws, "debug") == "us-west-2"

    with patch("hacksaws._sessions._begin") as begin:
        unchanged = _sessions.profile_region_change(
            _profile_args(aws, "set", "us-west-2")
        )
    assert unchanged["changed"] is False
    begin.assert_not_called()

    shown = _cli._run_profile(_profile_args(aws, "get"))
    assert isinstance(shown.data, dict)
    assert shown.data["region"] == "us-west-2"
    cleared = _cli._run_profile(_profile_args(aws, "clear"))
    assert cleared.code == "PROFILE_REGION_CLEAR"
    assert isinstance(cleared.data, dict)
    assert cleared.data["region"] is None
    cleared_again = _sessions.profile_region_change(
        _profile_args(aws, "clear"), clear=True
    )
    assert cleared_again["changed"] is False


def test_profile_region_rejects_cross_partition_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_home(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    _write_profile(aws, "us-gov-west-1")

    with pytest.raises(_configs.OperationalError, match="partition"):
        _sessions.profile_region_change(_profile_args(aws, "set", "us-east-1"))
    assert _sessions._profile_region(aws, "debug") == "us-gov-west-1"


def test_managed_profile_region_rebases_logout_restore_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_home(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    _write_profile(aws, "us-east-1")
    key = f"{aws.absolute()}::debug"
    _state.save_sessions({key: _managed_session(aws)})  # type: ignore[dict-item]

    changed = _sessions.profile_region_change(_profile_args(aws, "set", "us-west-2"))
    assert changed["changed"] is True
    saved = _state.load_sessions()[key]
    assert saved["region"] == "us-west-2"
    assert (
        saved["section_backup"]["config"]["original"]["values"]["region"] == "us-west-2"
    )

    cleared = _sessions.profile_region_change(_profile_args(aws, "clear"), clear=True)
    assert cleared["region"] is None
    cleared_session = _state.load_sessions()[key]
    assert "region" not in cleared_session
    assert (
        "region"
        not in cleared_session["section_backup"]["config"]["original"]["values"]
    )
    _sessions.profile_region_change(_profile_args(aws, "set", "us-west-2"))

    logout_args = argparse.Namespace(
        target=None,
        directory=str(aws),
        profile="debug",
        aws_account_name=None,
        to=None,
        to_directory=None,
        to_profile="default",
        force=False,
        keep_ecr=False,
        except_profiles=[],
    )
    assert _sessions.logout(_configs.Context(logout_args)) is True
    assert _sessions._profile_region(aws, "debug") == "us-west-2"
    assert key not in _state.load_sessions()


def test_profile_region_transaction_rolls_back_config_and_session_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_home(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    _write_profile(aws, "us-east-1")
    key = f"{aws.absolute()}::debug"
    _state.save_sessions({key: _managed_session(aws)})  # type: ignore[dict-item]
    original_config = (aws / "config").read_bytes()
    original_sessions = _state.sessions_path().read_bytes()

    with (
        patch("hacksaws._sessions._state.save_sessions", side_effect=OSError("write")),
        pytest.raises(OSError, match="write"),
    ):
        _sessions.profile_region_change(_profile_args(aws, "set", "us-west-2"))

    assert (aws / "config").read_bytes() == original_config
    assert _state.sessions_path().read_bytes() == original_sessions


def test_browser_native_region_clear_requires_logout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_home(tmp_path, monkeypatch)
    aws = tmp_path / "aws"
    _write_profile(aws, "us-east-1")
    key = f"{aws.absolute()}::debug"
    session = _managed_session(aws, auth_method="browser-native")
    _state.save_sessions({key: session})  # type: ignore[dict-item]

    with pytest.raises(_configs.OperationalError, match="log out before clearing"):
        _sessions.profile_region_change(_profile_args(aws, "clear"), clear=True)
    assert _sessions._profile_region(aws, "debug") == "us-east-1"
