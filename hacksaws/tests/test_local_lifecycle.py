"""Focused coverage for local profile, session, logout, and cache lifecycle UX."""

from __future__ import annotations

import argparse
import base64
import configparser
import json
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from hacksaws import _cli
from hacksaws import _configs
from hacksaws import _policies
from hacksaws import _sessions
from hacksaws import _state

DOCUMENT = {"Version": "2012-10-17", "Statement": []}


def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "user"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    _state.save_config(_state.default_config())
    return home


def _ini(path: Path, sections: dict[str, dict[str, str]]) -> None:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_dict(sections)
    _sessions._write_ini(path, parser)


def _logout_args(
    directory: Path, profile: str = "dev", **values: object
) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "target": None,
        "directory": str(directory),
        "profile": profile,
        "aws_account_name": None,
        "to": None,
        "to_directory": None,
        "to_profile": None,
        "except_profiles": [],
        "force": False,
        "keep_ecr": False,
        "ecr": False,
        "podman": False,
    }
    defaults.update(values)
    return argparse.Namespace(**defaults)


def _record_session(directory: Path, profile: str = "dev") -> None:
    journal = _sessions._begin(
        [directory / "credentials", directory / "config", _state.sessions_path()]
    )
    credentials = _sessions._read_ini(directory / "credentials")
    credentials[profile] = {
        "aws_access_key_id": "temporary",
        "aws_secret_access_key": "temporary-secret",
        "aws_session_token": "temporary-token",
    }
    _sessions._write_ini(directory / "credentials", credentials)
    config = _sessions._read_ini(directory / "config")
    config[_sessions._section(profile, config=True)] = {"region": "us-west-2"}
    _sessions._write_ini(directory / "config", config)
    _sessions._record(
        directory,
        profile,
        {"expires_at": (datetime.now(UTC) + timedelta(minutes=30)).isoformat()},
        journal,
        method="mfa",
    )
    _sessions._commit()


def test_profile_inventory_scans_locations_targets_and_reports_parse_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolated_home(tmp_path, monkeypatch)
    default = home / ".aws"
    horizon = home / ".aws-horizon"
    custom = tmp_path / "custom"
    _ini(default / "credentials", {"default": {}, "dev": {}})
    _ini(default / "config", {"profile prod": {"region": "us-east-1"}})
    _ini(horizon / "config", {"profile admin": {"region": "us-west-2"}})
    _ini(custom / "credentials", {"source": {}})
    broken = home / ".aws-broken" / "config"
    broken.parent.mkdir()
    broken.write_text("[", encoding="utf-8")
    data = _state.load_config()
    data["accounts"]["unused"] = {"id": "123456789012", "partition": "aws"}
    data["targets"]["custom"] = {
        "source_account": "unused",
        "source_profile": "source",
        "source_directory": str(custom),
    }
    _state.save_config(data)

    report = _sessions.profile_inventory()
    values = {
        (item["location"], item["profile"], item["directory"])
        for item in report["profiles"]
    }

    assert ("default", "default", str(default.absolute())) in values
    assert ("default", "dev", str(default.absolute())) in values
    assert ("horizon", "admin", str(horizon.absolute())) in values
    assert (None, "source", str(custom.absolute())) in values
    assert report["warnings"][0]["path"] == str(broken)
    assert "aws_secret_access_key" not in json.dumps(report)


def test_status_is_structured_neutral_and_network_free_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    directory = tmp_path / "aws"
    _ini(
        directory / "credentials",
        {"dev": {"aws_access_key_id": "original", "aws_secret_access_key": "secret"}},
    )
    _ini(directory / "config", {"profile dev": {"region": "us-east-1"}})
    _record_session(directory)

    with patch(
        "hacksaws._sessions.boto3.Session", side_effect=AssertionError("network")
    ):
        result = _cli.console_main(["status", "--json"])
    envelope = json.loads(capsys.readouterr().out)
    assert result.code == "STATUS"
    assert envelope["data"]["sessions"][0]["state"] == "active"
    assert "message" not in envelope["data"]
    assert "backup" not in json.dumps(envelope)

    result = _cli.console_main(["status", "--no-color"])
    human = capsys.readouterr().out
    assert result.kind == "info"
    assert "LOCATION" in human
    assert "PROFILE" in human
    assert "ACTIVE" in human.upper()
    assert not human.lstrip().startswith("{")


def test_status_verification_is_opt_in_and_per_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    directory = tmp_path / "aws"
    _ini(directory / "credentials", {"dev": {}})
    _ini(directory / "config", {"profile dev": {}})
    _record_session(directory)
    with patch(
        "hacksaws._sessions._verify_status",
        return_value={"status": "error", "message": "expired"},
    ) as verify:
        report = _sessions.status_report(verify=True)
    verify.assert_called_once()
    assert report["sessions"][0]["verification"] == {
        "status": "error",
        "message": "expired",
    }


def test_section_cas_logout_preserves_unrelated_edits_and_blocks_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    directory = tmp_path / "aws"
    _ini(
        directory / "credentials",
        {
            "dev": {"aws_access_key_id": "original", "aws_secret_access_key": "secret"},
            "other": {"aws_access_key_id": "other"},
        },
    )
    _ini(
        directory / "config",
        {"profile dev": {"region": "us-east-1"}, "profile other": {"region": "a"}},
    )
    _record_session(directory)
    credentials = _sessions._read_ini(directory / "credentials")
    credentials["other"]["aws_access_key_id"] = "edited-other"
    _sessions._write_ini(directory / "credentials", credentials)

    assert _sessions.logout(_configs.Context(_logout_args(directory)))
    restored = _sessions._read_ini(directory / "credentials")
    assert restored["dev"]["aws_access_key_id"] == "original"
    assert restored["other"]["aws_access_key_id"] == "edited-other"

    _record_session(directory)
    credentials = _sessions._read_ini(directory / "credentials")
    credentials["dev"]["aws_access_key_id"] = "external-change"
    _sessions._write_ini(directory / "credentials", credentials)
    with pytest.raises(_configs.OperationalError, match="changed after login"):
        _sessions.logout(_configs.Context(_logout_args(directory)))
    assert _sessions.logout(_configs.Context(_logout_args(directory, force=True)))
    assert (
        _sessions._read_ini(directory / "credentials")["dev"]["aws_access_key_id"]
        == "original"
    )


def test_bulk_logout_except_and_keep_ecr_are_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    one = tmp_path / "one"
    two = tmp_path / "two"
    for directory, profile in ((one, "one"), (two, "two")):
        _ini(directory / "credentials", {profile: {}})
        _ini(directory / "config", {f"profile {profile}": {}})
        _record_session(directory, profile)
    report = _sessions.logout_all(_logout_args(one, all=True, except_profiles=["two"]))
    assert {item["state"] for item in report["outcomes"]} == {"logged-out", "excluded"}
    assert len(_state.load_sessions()) == 1

    key = next(iter(_state.load_sessions()))
    sessions = _state.load_sessions()
    sessions[key]["ecr"] = ["registry.example"]
    sessions[key]["ecr_engine"] = "docker"
    _state.save_sessions(sessions)
    with patch("hacksaws._ecr._run_container_engine") as engine:
        outcome = _sessions._logout_key(
            key, _logout_args(two, profile="two", keep_ecr=True)
        )
    engine.assert_not_called()
    assert outcome["state"] == "ecr-only"
    assert _state.load_sessions()[key]["ecr"] == ["registry.example"]

    with patch("hacksaws._ecr._run_container_engine") as engine:
        _sessions._logout_key(key, _logout_args(two, profile="two"))
    engine.assert_called_once_with("docker", ["docker", "logout", "registry.example"])


def test_policy_cache_inventory_show_and_selective_clear(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    _policies.cache_write(
        "fresh", DOCUMENT, origin="local", resolver="file", source_identity="fresh.yaml"
    )
    _policies.cache_write(
        "stale", DOCUMENT, origin="stored", resolver="stored", source_identity="Stored"
    )
    stale = _policies.cache_root() / "stale.json"
    value = json.loads(stale.read_text(encoding="utf-8"))
    value["fetched_at"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    stale.write_text(json.dumps(value), encoding="utf-8")
    (_policies.cache_root() / "invalid.json").write_text("{", encoding="utf-8")
    native = tmp_path / "native-login-cache.json"
    native.write_text("credential-provider-state", encoding="utf-8")

    report = _policies.cache_inventory(max_age=3600)
    assert report["counts"] == {"fresh": 1, "stale": 1, "invalid": 1}
    assert "document" not in json.dumps(report)
    assert _policies.cache_show("fresh")["document"] == DOCUMENT
    removed = _policies.clear_cache_entries(stale_only=True)
    assert set(removed) == {"stale", "invalid"}
    assert native.read_text(encoding="utf-8") == "credential-provider-state"


def test_cache_cli_get_list_show_and_noninteractive_clear(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    _policies.cache_write(
        "fresh", DOCUMENT, origin="local", resolver="file", source_identity="fresh.yaml"
    )
    result = _cli.console_main(["cache", "get", "max-age", "--json"])
    assert json.loads(capsys.readouterr().out)["data"] == {
        "setting": "max-age",
        "value": 3600,
    }
    assert result.code == "CACHE_GET"
    result = _cli.console_main(["cache", "list", "--json"])
    listed = json.loads(capsys.readouterr().out)["data"]
    assert listed["entries"][0]["identity"] == "fresh"
    assert "document" not in json.dumps(listed)
    result = _cli.console_main(["cache", "show", "fresh", "--json"])
    assert json.loads(capsys.readouterr().out)["data"]["document"] == DOCUMENT
    assert result.code == "CACHE_SHOW"

    result = _cli.console_main(["cache", "clear", "--json"])
    capsys.readouterr()
    assert result.code == "CACHE_CLEAR_CANCELLED"
    assert (_policies.cache_root() / "fresh.json").exists()
    result = _cli.console_main(["cache", "clear", "--yes", "--json"])
    assert json.loads(capsys.readouterr().out)["data"]["removed"] == ["fresh"]
    assert result.code == "CACHE_CLEAR"


def test_status_classifies_conservative_local_states_and_filters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolated_home(tmp_path, monkeypatch)
    destination = home / ".aws-horizon"
    now = datetime.now(UTC)
    missing_path = destination / "credentials"
    stable = {
        "credentials": {
            "path": str(missing_path),
            "section": "dev",
            "installed": _sessions._section_state(missing_path, "dev"),
            "original": {"exists": False, "values": {}},
        }
    }
    sessions: dict[str, dict[str, Any]] = {
        "ecr": {
            "destination": str(destination),
            "profile": "ecr",
            "auth_method": "ecr-only",
            "ecr": ["example"],
        },
        "legacy": {"destination": str(destination), "profile": "legacy"},
        "missing": {
            "destination": str(destination),
            "profile": "missing",
            "section_backup": {
                "credentials": {
                    **stable["credentials"],
                    "installed": {"exists": True, "fingerprint": "gone"},
                }
            },
        },
        "drifted": {
            "destination": str(destination),
            "profile": "drifted",
            "section_backup": {"credentials": "invalid"},
        },
        "expired": {
            "destination": str(destination),
            "profile": "expired",
            "expires_at": (now - timedelta(seconds=1)).isoformat(),
            "section_backup": stable,
        },
        "expiring": {
            "destination": str(destination),
            "profile": "expiring",
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "section_backup": stable,
        },
        "invalid": {
            "destination": str(destination),
            "profile": "invalid",
            "expires_at": "not-a-date",
            "section_backup": stable,
        },
    }
    _state.save_sessions(sessions)
    states = {item["profile"]: item for item in _sessions.status()}
    assert {name: item["state"] for name, item in states.items()} == {
        "ecr": "ecr-only",
        "legacy": "legacy-unverified",
        "missing": "missing",
        "drifted": "drifted",
        "expired": "expired",
        "expiring": "expiring",
        "invalid": "invalid",
    }
    assert all(item["location"] == "horizon" for item in states.values())
    assert _sessions.status_report(profile="invalid")["counts"] == {"invalid": 1}
    assert _sessions.status_report(location="horizon")["sessions"]
    assert _sessions.status_report(directory=destination)["sessions"]


def test_status_verification_skips_unsafe_state_and_reports_success_or_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    destination = tmp_path / "aws"
    skipped = _sessions._verify_status(
        {"state": "drifted", "destination": str(destination), "profile": "dev"}
    )
    assert skipped == {"status": "skipped", "reason": "local state is drifted"}
    with (
        patch("hacksaws._sessions.boto3.Session"),
        patch(
            "hacksaws._sessions._identity",
            return_value=("123456789012", "aws", "arn:aws:iam::123456789012:user/me"),
        ),
    ):
        verified = _sessions._verify_status(
            {
                "state": "active",
                "destination": str(destination),
                "profile": "dev",
                "target_account": "123456789012",
                "target_partition": "aws",
            }
        )
    assert verified["status"] == "verified"
    with (
        patch("hacksaws._sessions.boto3.Session"),
        patch(
            "hacksaws._sessions._identity",
            side_effect=_configs.OperationalError("expired"),
        ),
    ):
        failed = _sessions._verify_status(
            {
                "state": "active",
                "destination": str(destination),
                "profile": "dev",
                "target_account": "123456789012",
                "target_partition": "aws",
            }
        )
    assert failed == {"status": "error", "message": "expired"}


def test_legacy_section_restore_requires_force_and_only_restores_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    destination = tmp_path / "aws"
    credentials = destination / "credentials"
    _ini(
        credentials,
        {
            "dev": {"aws_access_key_id": "original"},
            "other": {"aws_access_key_id": "other"},
        },
    )
    original = credentials.read_bytes()
    _ini(
        credentials,
        {
            "dev": {"aws_access_key_id": "temporary"},
            "other": {"aws_access_key_id": "edited"},
        },
    )
    session = {
        "backup": [
            {
                "path": str(credentials.absolute()),
                "exists": True,
                "data": base64.b64encode(original).decode(),
            }
        ]
    }
    with pytest.raises(_configs.OperationalError, match="legacy session"):
        _sessions._restore_profile_sections(
            session, destination.absolute(), "dev", force=False
        )
    _sessions._restore_profile_sections(
        session, destination.absolute(), "dev", force=True
    )
    parser = _sessions._read_ini(credentials)
    assert parser["dev"]["aws_access_key_id"] == "original"
    assert parser["other"]["aws_access_key_id"] == "edited"


@pytest.mark.parametrize(
    ("section_backup", "message"),
    [
        ({"credentials": "bad"}, "section state is invalid"),
        (
            {
                "credentials": {
                    "path": "wrong",
                    "section": "dev",
                    "original": {"exists": False, "values": {}},
                }
            },
            "does not match its destination",
        ),
        (
            {
                "credentials": {
                    "path": "DESTINATION",
                    "section": "dev",
                    "original": "bad",
                }
            },
            "original section is invalid",
        ),
        (
            {
                "credentials": {
                    "path": "DESTINATION",
                    "section": "dev",
                    "original": {"exists": True, "values": "bad"},
                }
            },
            "original section values are invalid",
        ),
    ],
)
def test_section_restore_rejects_corrupt_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    section_backup: dict[str, object],
    message: str,
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    destination = tmp_path / "aws"
    item = section_backup.get("credentials")
    if isinstance(item, dict) and item.get("path") == "DESTINATION":
        item["path"] = str((destination / "credentials").absolute())
    with pytest.raises(_configs.OperationalError, match=message):
        _sessions._restore_profile_sections(
            {"section_backup": section_backup},
            destination.absolute(),
            "dev",
            force=True,
        )


def test_browser_cache_cleanup_is_scoped_and_fingerprint_guarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    destination = tmp_path / "aws"
    root = destination / "login" / "cache"
    root.mkdir(parents=True)
    matched = root / "matched.json"
    changed = root / "changed.json"
    outside = tmp_path / "outside.json"
    for path in (matched, changed, outside):
        path.write_text(path.stem, encoding="utf-8")
    session = {
        "auth_method": "browser-native",
        "login_cache_directories": [str(root)],
        "login_cache_files": [str(matched), str(changed), str(outside)],
        "login_cache_fingerprints": {
            str(matched): _state.digest(matched.read_bytes()),
            str(changed): "different",
            str(outside): _state.digest(outside.read_bytes()),
        },
    }
    with pytest.raises(_configs.OperationalError, match="no logout changes"):
        _sessions._tracked_login_cache_plan(session, destination, force=False)
    roots, removals, residue, _ = _sessions._tracked_login_cache_plan(
        session, destination, force=True
    )
    assert roots == [root.absolute()]
    residue = _sessions._remove_tracked_login_cache(removals, residue, force=True)
    assert not matched.exists()
    assert changed.exists()
    assert outside.exists()
    assert {item["path"] for item in residue} == {
        str(changed.absolute()),
        str(outside.absolute()),
    }


def test_logout_not_managed_and_bulk_collects_independent_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    assert (
        _sessions._logout_key("missing", argparse.Namespace())["state"] == "not-managed"
    )
    _state.save_sessions({"a": {}, "b": {}})
    with patch(
        "hacksaws._sessions._logout_key",
        side_effect=[
            {"key": "a", "state": "logged-out", "changed": True},
            _configs.OperationalError("drift"),
        ],
    ):
        report = _sessions.logout_all(argparse.Namespace())
    assert report["outcomes"][0]["key"] == "a"
    assert report["errors"] == [{"key": "b", "message": "drift"}]


def test_cache_status_filters_clear_validation_and_profile_help(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    _policies.cache_write(
        "fresh", DOCUMENT, origin="local", resolver="file", source_identity="fresh.yaml"
    )
    assert _cli.console_main(["cache", "status", "--json"]).code == "CACHE_STATUS"
    status_data = json.loads(capsys.readouterr().out)["data"]
    assert "entries" not in status_data
    assert status_data["counts"]["fresh"] == 1
    assert (
        _cli.console_main(
            ["cache", "list", "--fresh", "--origin", "local", "--json"]
        ).code
        == "CACHE_LIST"
    )
    assert json.loads(capsys.readouterr().out)["data"]["count"] == 1
    result = _cli.console_main(
        ["cache", "clear", "fresh", "--stale", "--yes", "--json"]
    )
    assert result.code == "OPERATIONAL_ERROR"
    capsys.readouterr()
    assert _cli.console_main(["profile", "list", "--json"]).code == "PROFILE_LIST"
    assert "profiles" in json.loads(capsys.readouterr().out)["data"]
    assert (
        _cli._run_profile(argparse.Namespace(profile_action=None)).code
        == "PROFILE_HELP"
    )


def test_bulk_logout_cli_handles_legacy_exclusions_and_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    inventory = {
        "profiles": [
            {
                "auth_method": "legacy-mfa",
                "location": "horizon",
                "profile": "skip",
                "directory": str(tmp_path / "one"),
            },
            {
                "auth_method": "legacy-mfa",
                "location": None,
                "profile": "fail",
                "directory": str(tmp_path / "two"),
            },
            {"auth_method": None, "profile": "unmanaged", "directory": "ignored"},
        ]
    }
    with (
        patch(
            "hacksaws._sessions.logout_all",
            return_value={"outcomes": [], "errors": []},
        ),
        patch("hacksaws._sessions.profile_inventory", return_value=inventory),
        patch(
            "hacksaws._aws.logout",
            side_effect=_configs.OperationalError("legacy failure"),
        ),
    ):
        result = _cli.console_main(
            ["logout", "--all", "--except", "horizon:skip", "--json"]
        )
    assert result.code == "LOGOUT_ALL"
    assert result.exit_code == 1
    assert isinstance(result.data, dict)
    assert result.data["outcomes"][0]["state"] == "excluded"
    assert result.data["errors"][0]["message"] == "legacy failure"


def test_policy_cache_show_and_clear_reject_bad_or_missing_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    with pytest.raises(
        _configs.OperationalError, match="Invalid policy cache identity"
    ):
        _policies.cache_show("../escape")
    with pytest.raises(_configs.OperationalError, match="does not exist"):
        _policies.cache_show("missing")
    assert _policies.clear_cache_entries(["missing"]) == []


def test_policy_cache_reads_fail_closed_on_tampering_and_clear_supports_patterns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    _policies.cache_write(
        "aws-read-only", DOCUMENT, origin="aws", resolver="arn", source_identity="x"
    )
    _policies.cache_write(
        "local-debug", DOCUMENT, origin="local", resolver="file", source_identity="y"
    )
    path = _policies.cache_root() / "aws-read-only.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["digest"] = "tampered"
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="digest mismatch"):
        _policies.cache_read("aws-read-only", 60)
    with pytest.raises(_configs.OperationalError, match="digest mismatch"):
        _policies.cache_show("aws-read-only")
    assert _policies.clear_cache_entries(["LOCAL-*"]) == ["local-debug"]


def test_default_normalization_arbitrary_target_shorthand_and_logout_patterns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolated_home(tmp_path, monkeypatch)
    args = _logout_args(home / ".aws", profile=".", to=".:.")
    _source, source_profile, destination, destination_profile = _sessions._paths(args)
    assert (source_profile, destination, destination_profile) == (
        "default",
        home / ".aws",
        "default",
    )
    assert _sessions.matches_logout_exclusion(
        destination=str(home / ".aws-horizon"),
        profile="ProdAdmin",
        location="horizon",
        excluded={"HORIZON:prod*"},
    )


def test_logout_preflights_before_ecr_and_rolls_back_partial_profile_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    directory = tmp_path / "aws"
    _ini(directory / "credentials", {"dev": {"aws_access_key_id": "original"}})
    _ini(directory / "config", {"profile dev": {"region": "us-east-1"}})
    _record_session(directory)
    key = f"{directory.absolute()}::dev"
    sessions = _state.load_sessions()
    sessions[key]["ecr"] = ["registry.example"]
    sessions[key]["ecr_engine"] = "docker"
    _state.save_sessions(sessions)
    credentials = directory / "credentials"
    config = directory / "config"
    credentials_before = credentials.read_bytes()
    config_before = config.read_bytes()
    parser = _sessions._read_ini(credentials)
    parser["dev"]["aws_access_key_id"] = "drifted"
    _sessions._write_ini(credentials, parser)
    with (
        patch("hacksaws._ecr._run_container_engine") as engine,
        pytest.raises(_configs.OperationalError, match="changed after login"),
    ):
        _sessions._logout_key(key, _logout_args(directory))
    engine.assert_not_called()
    credentials.write_bytes(credentials_before)

    original_write = _sessions._write_ini
    calls = 0
    second_write_error = _configs.OperationalError("second write failed")

    def fail_second(path: Path, value: configparser.ConfigParser) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise second_write_error
        original_write(path, value)

    with (
        patch("hacksaws._sessions._write_ini", side_effect=fail_second),
        pytest.raises(_configs.OperationalError, match="second write failed"),
    ):
        _sessions._logout_key(key, _logout_args(directory, keep_ecr=True))
    assert credentials.read_bytes() == credentials_before
    assert config.read_bytes() == config_before
    assert key in _state.load_sessions()


def test_config_fix_walks_remote_boundary_and_account_issues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    data = _state.load_config()
    data["accounts"]["Prod"] = {"id": "111111111111", "partition": "aws"}
    data["boundaries"]["Guard"] = {
        "role_arn": "arn:aws:iam::111111111111:role/Old",
        "account": "Prod",
        "duration": 3600,
        "verified": False,
    }
    data["targets"]["Agent"] = {
        "source_account": "Prod",
        "source_profile": "default",
        "source_location": "default",
        "boundary": "Guard",
    }
    _state.save_config(data)
    args = argparse.Namespace(
        account="Prod",
        yes=False,
        remote=True,
        probe=False,
        profile="default",
        target=None,
        location="default",
        directory=None,
    )
    with (
        patch("hacksaws._sessions._check_config") as check,
        patch("hacksaws._sessions.sys.stdin.isatty", return_value=True),
        patch(
            "builtins.input",
            side_effect=["update", "arn:aws:iam::111111111111:role/New"],
        ),
    ):
        check.return_value = {
            "ok": False,
            "errors": ["Boundary Guard: missing (gone)."],
            "warnings": [],
        }
        assert _sessions.fix_config(args).code == "CONFIG_FIX"
    assert _state.load_config()["boundaries"]["Guard"]["role_arn"].endswith("/New")

    with (
        patch("hacksaws._sessions._check_config") as check,
        patch("hacksaws._sessions.sys.stdin.isatty", return_value=True),
        patch("builtins.input", side_effect=["update", "replacement.json"]),
    ):
        check.return_value = {
            "ok": False,
            "errors": ["Boundary Guard policy: remote policy is missing"],
            "warnings": [],
        }
        assert _sessions.fix_config(args).code == "CONFIG_FIX"
    assert _state.load_config()["boundaries"]["Guard"]["policy"] == "replacement.json"

    with (
        patch("hacksaws._sessions._check_config") as check,
        patch("hacksaws._sessions.sys.stdin.isatty", return_value=True),
        patch("builtins.input", return_value="update"),
    ):
        check.return_value = {
            "ok": False,
            "errors": [
                "Selected account does not match caller aws-us-gov:222222222222."
            ],
            "warnings": [],
        }
        assert _sessions.fix_config(args).code == "CONFIG_FIX"
    account = _state.load_config()["accounts"]["Prod"]
    assert (account["partition"], account["id"]) == (
        "aws-us-gov",
        "222222222222",
    )

    with (
        patch("hacksaws._sessions._check_config") as check,
        patch("hacksaws._sessions.sys.stdin.isatty", return_value=True),
        patch("builtins.input", return_value="remove"),
    ):
        check.return_value = {
            "ok": False,
            "errors": ["Boundary Guard: missing (gone)."],
            "warnings": [],
        }
        assert _sessions.fix_config(args).code == "CONFIG_FIX"
    fixed = _state.load_config()
    assert "Guard" not in fixed["boundaries"]
    assert "Agent" not in fixed["targets"]


def test_cache_record_is_bound_to_filename_and_source_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    _policies.cache_write(
        "original", DOCUMENT, origin="local", resolver="file", source_identity="a.json"
    )
    original = _policies.cache_root() / "original.json"
    copied = _policies.cache_root() / "copied.json"
    copied.write_bytes(original.read_bytes())
    with pytest.raises(_configs.OperationalError, match="identity does not match"):
        _policies.cache_read("copied", 60)
    record = json.loads(original.read_text(encoding="utf-8"))
    record["source_identity"] = "b.json"
    original.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="digest mismatch"):
        _policies.cache_show("original")


def test_browser_logout_cache_drift_fails_closed_and_force_tracks_residue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    directory = tmp_path / "aws"
    _ini(directory / "credentials", {"dev": {"aws_access_key_id": "original"}})
    _ini(directory / "config", {"profile dev": {"region": "us-east-1"}})
    _record_session(directory)
    root = directory / "login" / "cache"
    root.mkdir(parents=True)
    changed = root / "changed.json"
    outside = tmp_path / "outside.json"
    changed.write_text("new", encoding="utf-8")
    outside.write_text("outside", encoding="utf-8")
    key = f"{directory.absolute()}::dev"
    sessions = _state.load_sessions()
    sessions[key].update(
        auth_method="browser-native",
        login_cache_directories=[str(root)],
        login_cache_files=[str(changed), str(outside)],
        login_cache_fingerprints={
            str(changed.absolute()): _state.digest(b"old"),
            str(outside.absolute()): _state.digest(outside.read_bytes()),
        },
    )
    _state.save_sessions(sessions)
    before_credentials = (directory / "credentials").read_bytes()
    with pytest.raises(_configs.OperationalError, match="no logout changes"):
        _sessions._logout_key(key, _logout_args(directory))
    assert (directory / "credentials").read_bytes() == before_credentials
    assert key in _state.load_sessions()
    assert changed.exists()

    outcome = _sessions._logout_key(key, _logout_args(directory, force=True))
    assert outcome["state"] == "logout-residue"
    assert changed.exists()
    assert outside.exists()
    residue_session = _state.load_sessions()[key]
    assert residue_session["auth_method"] == "browser-cache-residue"
    assert {item["path"] for item in residue_session["login_cache_residue"]} == {
        str(changed.absolute()),
        str(outside.absolute()),
    }


def test_config_check_scopes_local_stored_policies_to_selected_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    data = _state.load_config()
    for name, account_id in (("One", "111111111111"), ("Two", "222222222222")):
        data["accounts"][name] = {"id": account_id, "partition": "aws"}
        data["policies"][name] = {"file": f"stored_session_policies/{name}.yaml"}
        data["boundaries"][name] = {
            "role_arn": f"arn:aws:iam::{account_id}:role/{name}",
            "account": name,
            "policy": name,
            "duration": 3600,
            "verified": False,
        }
    _state.save_config(data)

    errors = {
        "One": _configs.OperationalError("bad One"),
        "Two": _configs.OperationalError("bad Two"),
    }

    def parse(path: Path) -> tuple[dict[str, Any], bytes]:
        raise errors[path.stem]

    args = argparse.Namespace(account="One", remote=False, probe=False)
    with patch("hacksaws._policies.parse_policy", side_effect=parse):
        report = _sessions.check_config(args)
    assert report["errors"] == ["bad One"]


def test_remote_config_check_and_fix_infer_local_policy_scope_from_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    data = _state.load_config()
    for name, account_id in (("One", "111111111111"), ("Two", "222222222222")):
        data["accounts"][name] = {"id": account_id, "partition": "aws"}
        data["policies"][name] = {"file": f"stored_session_policies/{name}.yaml"}
        data["boundaries"][name] = {
            "role_arn": f"arn:aws:iam::{account_id}:role/{name}",
            "account": name,
            "policy": name,
            "duration": 3600,
            "verified": False,
        }
    _state.save_config(data)
    parsed: list[str] = []
    policy_errors = {
        "One": _configs.OperationalError("bad One"),
        "Two": _configs.OperationalError("bad Two"),
    }

    def parse(path: Path) -> tuple[dict[str, Any], bytes]:
        parsed.append(path.stem)
        raise policy_errors[path.stem]

    session = MagicMock()
    session.client.return_value.get_role.return_value = {}
    args = argparse.Namespace(
        account=None,
        remote=True,
        probe=False,
        profile="default",
        target=None,
        location="default",
        directory=None,
        yes=True,
    )
    with (
        patch("hacksaws._sessions.boto3.Session", return_value=session),
        patch(
            "hacksaws._sessions._identity",
            return_value=("111111111111", "aws", "arn"),
        ),
        patch("hacksaws._policies.parse_policy", side_effect=parse),
        patch("hacksaws._policies.resolve"),
    ):
        report = _sessions.check_config(args)
    assert parsed == ["One"]
    assert report["errors"] == ["bad One"]

    parsed.clear()
    with (
        patch("hacksaws._sessions.boto3.Session", return_value=session),
        patch(
            "hacksaws._sessions._identity",
            return_value=("111111111111", "aws", "arn"),
        ),
        patch("hacksaws._policies.parse_policy", side_effect=parse),
        patch(
            "hacksaws._sessions._check_config",
            return_value={"ok": True, "errors": [], "warnings": []},
        ),
    ):
        assert _sessions.fix_config(args).code == "CONFIG_FIX_UNRESOLVED"
    assert parsed == ["One"]


def test_cache_consumers_reject_self_consistent_wrong_resolver_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    account = "111111111111"
    aws_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    aws_identity = _policies._cache_identity(aws_arn, account=account, partition="aws")
    _policies.cache_write(
        aws_identity,
        DOCUMENT,
        origin="remote-customer",
        resolver="name",
        source_identity=f"arn:aws:iam::{account}:policy/ReadOnlyAccess",
    )
    with pytest.raises(_configs.OperationalError, match="metadata does not match"):
        _policies._fetch_aws_managed(
            aws_arn,
            account_id=account,
            partition="aws",
            profile="default",
            max_age=60,
        )

    name_identity = _policies._cache_identity(
        "name:Debug", account=account, partition="aws"
    )
    _policies.cache_write(
        name_identity,
        DOCUMENT,
        origin="remote-customer",
        resolver="name",
        source_identity=f"arn:aws:iam::{account}:policy/Other",
    )
    with pytest.raises(_configs.OperationalError, match="requested policy name"):
        _policies._resolve_remote_name("Debug", account, "aws", "default", 60)


def test_console_invocations_do_not_leak_json_output_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated_home(tmp_path, monkeypatch)
    assert _cli.console_main(["cache", "get", "--json"]).exit_code == 0
    capsys.readouterr()
    _configs.Result("PLAIN", "plain", stream="stderr").echo()
    assert capsys.readouterr().err == "plain\n"
