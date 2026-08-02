"""Transactional coverage for handoff from an already-authenticated profile."""

from __future__ import annotations

import argparse
import json
from contextlib import AbstractContextManager
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from hacksaws import _configs
from hacksaws import _sessions
from hacksaws import _state

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/AgentSession"


def _args(source: Path, **overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "profile": "admin",
        "directory": str(source),
        "aws_account_name": None,
        "target": None,
        "to": None,
        "to_directory": None,
        "to_profile": None,
        "self_destination": False,
        "role": ROLE,
        "boundary": None,
        "policy": None,
        "external_id": None,
        "account": None,
        "session_name": None,
        "region": None,
        "duration": None,
        "htl": None,
        "mtl": None,
        "stl": None,
        "keep_source": False,
        "keep_ecr": False,
        "replace": False,
        "force": False,
        "yes": True,
        "podman": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _ini(path: Path, sections: dict[str, dict[str, str]]) -> None:
    parser = _sessions._read_ini(path)
    parser.read_dict(sections)
    _sessions._write_ini(path, parser)


def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    _state.save_config(_state.default_config())
    return home


def _managed_source(directory: Path, profile: str = "admin") -> None:
    _ini(
        directory / "credentials",
        {
            profile: {
                "aws_access_key_id": "ORIGINAL",
                "aws_secret_access_key": "original-secret",
            }
        },
    )
    _ini(directory / "config", {f"profile {profile}": {"region": "us-west-2"}})
    journal = _sessions._begin(
        [directory / "credentials", directory / "config", _state.sessions_path()]
    )
    _sessions._save_credentials(
        directory / "credentials",
        profile,
        {
            "AccessKeyId": "AUTHENTICATED",
            "SecretAccessKey": "authenticated-secret",
            "SessionToken": "authenticated-token",
        },
    )
    _sessions._record(
        directory,
        profile,
        {
            "source_account": ACCOUNT,
            "target_account": ACCOUNT,
            "role": None,
            "boundary": None,
            "policy": None,
            "policy_provenance": None,
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
        journal,
        method="mfa",
    )
    _sessions._commit()


def _managed_browser_source_with_absent_originals(
    directory: Path, profile: str = "admin"
) -> Path:
    credentials = directory / "credentials"
    config = directory / "config"
    cache = directory / "login" / "cache" / "browser.json"
    journal = _sessions._begin([credentials, config, _state.sessions_path()])
    _ini(
        config,
        {
            f"profile {profile}": {
                "login_session": "browser-session",
                "region": "us-west-2",
            }
        },
    )
    cache.parent.mkdir(parents=True)
    cache.write_text("browser-auth-token", encoding="utf-8")
    _sessions._record(
        directory,
        profile,
        {
            "source_account": ACCOUNT,
            "target_account": ACCOUNT,
            "role": None,
            "boundary": None,
            "policy": None,
            "policy_provenance": "AWS-native login_session",
            "expires_at": None,
            "login_cache_files": [str(cache.absolute())],
            "login_cache_directories": [str(cache.parent.absolute())],
            "login_cache_fingerprints": {
                str(cache.absolute()): _state.digest(cache.read_bytes())
            },
        },
        journal,
        method="browser-native",
    )
    _sessions._commit()
    return cache


def _final() -> tuple[dict[str, object], dict[str, object]]:
    return (
        {
            "AccessKeyId": "BOUNDARY",
            "SecretAccessKey": "boundary-secret",
            "SessionToken": "boundary-token",
        },
        {
            "target_account": ACCOUNT,
            "role": ROLE,
            "boundary": None,
            "policy": None,
            "policy_provenance": None,
            "expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
        },
    )


def _identity_patches() -> tuple[
    AbstractContextManager[object], AbstractContextManager[object]
]:
    session = MagicMock(region_name="us-west-2")
    session.client.return_value.get_role.return_value = {
        "Role": {"MaxSessionDuration": 3600}
    }
    return (
        patch("hacksaws._sessions.boto3.Session", return_value=session),
        patch(
            "hacksaws._sessions._identity",
            return_value=(
                ACCOUNT,
                "aws",
                f"arn:aws:sts::{ACCOUNT}:assumed-role/Admin/live",
            ),
        ),
    )


def _preview(args: argparse.Namespace) -> dict[str, Any]:
    context = _configs.Context(args)
    return _sessions.assume_role_preview(_sessions.prepare_assume_role(context))


def _crash_journal(
    args: argparse.Namespace,
) -> tuple[_configs.Context, dict[str, Any]]:
    context = _configs.Context(args)
    session_patch, identity_patch = _identity_patches()
    with session_patch, identity_patch:
        prepared = _sessions.prepare_assume_role(context)
    credentials, metadata = _final()
    journal = _sessions._build_assume_journal(
        prepared._data, args, credentials, metadata
    )
    _sessions._write_assume_journal(journal)
    return context, journal


def _install_crash_destination(journal: dict[str, Any]) -> None:
    destination = journal["destination"]
    credentials, _metadata = _final()
    _sessions._save_credentials(
        Path(destination["directory"]) / "credentials",
        str(destination["profile"]),
        credentials,
    )
    _sessions._install_assume_destination(journal)
    journal["phase"] = "destination-installed"
    _sessions._write_assume_journal(journal)


def test_assume_moves_managed_source_to_distinct_destination_without_secret_retention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    args = _args(
        source,
        to_directory=str(destination),
        to_profile="debug",
    )
    session_patch, identity_patch = _identity_patches()
    with (
        session_patch,
        identity_patch,
        patch("hacksaws._sessions._assume", return_value=_final()),
    ):
        result = _sessions.assume_role(_configs.Context(args))

    assert result.code == "ASSUME_ROLE"
    source_credentials = _sessions._read_ini(source / "credentials")
    assert source_credentials["admin"]["aws_access_key_id"] == "ORIGINAL"
    destination_credentials = _sessions._read_ini(destination / "credentials")
    assert destination_credentials["debug"]["aws_access_key_id"] == "BOUNDARY"
    sessions = _state.load_sessions()
    assert set(sessions) == {f"{destination.absolute()}::debug"}
    assert sessions[f"{destination.absolute()}::debug"]["source_logged_out"] is True
    persisted = _state.sessions_path().read_text(encoding="utf-8")
    assert "authenticated-secret" not in persisted
    assert "authenticated-token" not in persisted
    assert not _sessions._journal_path().exists()


def test_unmanaged_source_requires_keep_source_and_destination_requires_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _ini(
        source / "credentials",
        {"admin": {"aws_access_key_id": "STATIC", "aws_secret_access_key": "secret"}},
    )
    _ini(destination / "config", {"profile debug": {"region": "us-east-1"}})
    args = _args(source, to_directory=str(destination), to_profile="debug")
    with pytest.raises(_configs.OperationalError, match="--keep-source"):
        _preview(args)

    args.keep_source = True
    session_patch, identity_patch = _identity_patches()
    with (
        session_patch,
        identity_patch,
        pytest.raises(_configs.OperationalError, match="--replace"),
    ):
        _preview(args)

    args.replace = True
    session_patch, identity_patch = _identity_patches()
    with (
        session_patch,
        identity_patch,
        patch("hacksaws._sessions._assume", return_value=_final()),
    ):
        _sessions.assume_role(_configs.Context(args))
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("STATIC")
    assert (
        _sessions._read_ini(destination / "credentials")["debug"]["aws_access_key_id"]
        == "BOUNDARY"
    )


def test_distinct_profile_in_same_aws_files_does_not_back_up_source_session_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    _managed_source(source)
    args = _args(source, to_profile="debug")
    session_patch, identity_patch = _identity_patches()
    with (
        session_patch,
        identity_patch,
        patch("hacksaws._sessions._assume", return_value=_final()),
    ):
        assert _sessions.assume_role(_configs.Context(args)).code == "ASSUME_ROLE"
    parser = _sessions._read_ini(source / "credentials")
    assert parser["admin"]["aws_access_key_id"] == "ORIGINAL"
    assert parser["debug"]["aws_access_key_id"] == "BOUNDARY"
    saved = _state.load_sessions()[f"{source.absolute()}::debug"]
    assert saved["backup"] == []
    persisted = _state.sessions_path().read_text(encoding="utf-8")
    assert "authenticated-secret" not in persisted
    assert "authenticated-token" not in persisted


def test_keep_source_upgrades_valid_legacy_browser_cache_lineage_after_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    login_session = f"arn:aws:iam::{ACCOUNT}:user/browser-user"
    cache_root = source / "login" / "cache"
    cache = cache_root / f"{_state.digest(login_session.encode())}.json"
    journal = _sessions._begin(
        [source / "credentials", source / "config", _state.sessions_path()]
    )
    _ini(
        source / "config",
        {
            "profile admin": {
                "login_session": login_session,
                "region": "us-west-2",
            }
        },
    )
    cache.parent.mkdir(parents=True)
    cache.write_text(
        json.dumps(
            {
                "accessToken": {
                    "accountId": ACCOUNT,
                    "accessKeyId": "access",
                    "secretAccessKey": "secret",
                    "sessionToken": "token",
                    "expiresAt": "2030-01-01T00:00:00Z",
                },
                "refreshToken": "refresh",
                "clientId": "client-generation",
                "dpopKey": "dpop-generation",
            }
        ),
        encoding="utf-8",
    )
    _sessions._record(
        source,
        "admin",
        {
            "source_account": ACCOUNT,
            "target_account": ACCOUNT,
            "role": None,
            "boundary": None,
            "policy": None,
            "policy_provenance": "legacy AWS-native login_session",
            "expires_at": None,
            "login_cache_files": [str(cache.absolute())],
            "login_cache_directories": [str(cache_root.absolute())],
            "login_cache_fingerprints": {
                str(cache.absolute()): _state.digest(cache.read_bytes())
            },
        },
        journal,
        method="browser-native",
    )
    _sessions._commit()

    args = _args(
        source,
        to_directory=str(destination),
        to_profile="debug",
        keep_source=True,
    )
    session_patch, identity_patch = _identity_patches()
    with (
        session_patch,
        identity_patch,
        patch("hacksaws._sessions._assume", return_value=_final()),
    ):
        result = _sessions.assume_role(_configs.Context(args))

    assert result.code == "ASSUME_ROLE"
    assert cache.exists()
    source_session = _state.load_sessions()[f"{source.absolute()}::admin"]
    assert source_session["login_cache_lineage"]["schema_version"] == 1
    assert source_session["login_cache_lineage"]["path"] == str(cache.absolute())
    for legacy_key in (
        "login_cache_files",
        "login_cache_directories",
        "login_cache_fingerprints",
    ):
        assert legacy_key not in source_session


def test_self_assume_preserves_original_chain_and_never_backs_up_authenticated_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    _managed_source(source)
    args = _args(source, self_destination=True)
    session_patch, identity_patch = _identity_patches()
    with (
        session_patch,
        identity_patch,
        patch("hacksaws._sessions._assume", return_value=_final()),
    ):
        _sessions.assume_role(_configs.Context(args))
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("BOUNDARY")
    persisted = _state.sessions_path().read_text(encoding="utf-8")
    assert "authenticated-secret" not in persisted
    assert "authenticated-token" not in persisted
    logout_args = argparse.Namespace(
        **{
            **vars(args),
            "target": None,
            "to": None,
            "self_destination": False,
            "except_profiles": [],
        }
    )
    assert _sessions.logout(_configs.Context(logout_args))
    restored = _sessions._read_ini(source / "credentials")
    assert restored["admin"]["aws_access_key_id"] == "ORIGINAL"


def test_legacy_mfa_self_assume_promotes_persistent_backup_into_managed_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    _ini(
        source / "credentials",
        {
            "admin": {
                "aws_access_key_id": "LEGACY-AUTH",
                "aws_secret_access_key": "legacy-auth-secret",
                "aws_session_token": "legacy-auth-token",
            }
        },
    )
    _ini(source / "config", {"profile admin": {"region": "us-east-2"}})
    _ini(
        source / "admin.store.credentials",
        {
            "admin": {
                "aws_access_key_id": "PERSISTENT",
                "aws_secret_access_key": "persistent-secret",
            }
        },
    )
    args = _args(source, self_destination=True)
    session_patch, identity_patch = _identity_patches()
    with (
        session_patch,
        identity_patch,
        patch("hacksaws._sessions._assume", return_value=_final()),
    ):
        assert _sessions.assume_role(_configs.Context(args)).code == "ASSUME_ROLE"
    assert not (source / "admin.store.credentials").exists()
    persisted = _state.sessions_path().read_text(encoding="utf-8")
    assert "legacy-auth-secret" not in persisted
    assert "legacy-auth-token" not in persisted
    logout_args = argparse.Namespace(
        **{
            **vars(args),
            "self_destination": False,
            "to": None,
            "except_profiles": [],
        }
    )
    assert _sessions.logout(_configs.Context(logout_args))
    restored = _sessions._read_ini(source / "credentials")
    assert restored["admin"]["aws_access_key_id"] == "PERSISTENT"


def test_assume_rolls_forward_after_destination_install_phase_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    args = _args(source, to_directory=str(destination), to_profile="debug")
    original_write_journal = _sessions._write_assume_journal
    writes = 0

    def fail_second_journal_write(journal: dict[str, Any]) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            message = "injected phase write failure"
            raise _configs.OperationalError(message)
        original_write_journal(journal)

    session_patch, identity_patch = _identity_patches()
    with (
        session_patch,
        identity_patch,
        patch("hacksaws._sessions._assume", return_value=_final()),
        patch(
            "hacksaws._sessions._write_assume_journal",
            side_effect=fail_second_journal_write,
        ),
        pytest.raises(_configs.OperationalError, match="injected phase write failure"),
    ):
        _sessions.assume_role(_configs.Context(args))
    source_credentials = _sessions._read_ini(source / "credentials")
    assert source_credentials["admin"]["aws_access_key_id"] == "ORIGINAL"
    destination_credentials = _sessions._read_ini(destination / "credentials")
    assert destination_credentials["debug"]["aws_access_key_id"] == "BOUNDARY"
    assert f"{destination.absolute()}::debug" in _state.load_sessions()
    assert not _sessions._journal_path().exists()


def test_source_drift_fails_closed_only_when_source_will_be_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    parser = _sessions._read_ini(source / "credentials")
    parser["admin"]["aws_access_key_id"] = "DRIFTED"
    _sessions._write_ini(source / "credentials", parser)
    args = _args(source, to_directory=str(destination), to_profile="debug")
    with pytest.raises(_configs.OperationalError, match="changed after login"):
        _preview(args)

    args.keep_source = True
    session_patch, identity_patch = _identity_patches()
    with (
        session_patch,
        identity_patch,
        patch("hacksaws._sessions._assume", return_value=_final()),
    ):
        assert _sessions.assume_role(_configs.Context(args)).code == "ASSUME_ROLE"
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("DRIFTED")


def test_ecr_failure_happens_after_commit_and_leaves_ecr_only_source_residue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    source_key = f"{source.absolute()}::admin"
    sessions = _state.load_sessions()
    sessions[source_key].update(ecr=["registry.example"], ecr_engine="docker")
    _state.save_sessions(sessions)
    args = _args(source, to_directory=str(destination), to_profile="debug")
    session_patch, identity_patch = _identity_patches()
    with (
        session_patch,
        identity_patch,
        patch("hacksaws._sessions._assume", return_value=_final()),
        patch(
            "hacksaws._ecr._run_container_engine",
            side_effect=_configs.OperationalError("docker unavailable"),
        ),
    ):
        result = _sessions.assume_role(_configs.Context(args))
    assert result.code == "ASSUME_ROLE_ECR_RESIDUE"
    assert result.exit_code == 1
    sessions = _state.load_sessions()
    assert sessions[source_key]["auth_method"] == "ecr-only"
    assert sessions[source_key]["ecr"] == ["registry.example"]
    assert f"{destination.absolute()}::debug" in sessions
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("ORIGINAL")
    assert not _sessions._journal_path().exists()


def test_preview_is_secret_free_and_does_not_call_assume_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    args = _args(source, to_directory=str(destination), to_profile="debug")
    before = _state.sessions_path().read_bytes()
    session_patch, identity_patch = _identity_patches()
    with session_patch, identity_patch, patch("hacksaws._sessions._assume") as assume:
        preview = _preview(args)
    assume.assert_not_called()
    encoded = json.dumps(preview)
    assert "authenticated-token" not in encoded
    assert "authenticated-secret" not in encoded
    assert _state.sessions_path().read_bytes() == before


def test_prepared_target_rejects_boundary_config_change_after_sts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    config = _state.load_config()
    config["accounts"]["Prod"] = {"id": ACCOUNT, "partition": "aws"}
    config["boundaries"]["Read"] = {
        "role_arn": ROLE,
        "account": "Prod",
        "verified": False,
    }
    config["targets"]["Agent"] = {
        "source_account": "Prod",
        "source_profile": "admin",
        "source_directory": str(source),
        "destination_profile": "debug",
        "destination_directory": str(destination),
        "boundary": "Read",
    }
    _state.save_config(config)
    args = _args(source, profile=None, target="+Agent", role=None)
    context = _configs.Context(args)
    session_patch, identity_patch = _identity_patches()
    with session_patch, identity_patch:
        prepared = _sessions.prepare_assume_role(context)

    def change_boundary(
        *_args: object, **_kwargs: object
    ) -> tuple[dict[str, object], dict[str, object]]:
        changed = _state.load_config()
        changed["boundaries"]["Read"]["role_arn"] = (
            f"arn:aws:iam::{ACCOUNT}:role/ChangedAfterPreview"
        )
        _state.save_config(changed)
        return _final()

    with (
        patch("hacksaws._sessions._assume", side_effect=change_boundary),
        pytest.raises(_sessions.AssumePlanChanged, match="fresh preview"),
    ):
        _sessions.assume_role(context, prepared)
    assert not (destination / "credentials").exists()
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("AUTHENTICATED")
    assert not _sessions._journal_path().exists()


def test_revalidation_refreshes_both_browser_cache_plans_without_stale_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source_record = {"auth_method": "browser-native", "profile": "admin"}
    destination_record = {"auth_method": "browser-native", "profile": "debug"}
    source_key = f"{source.absolute()}::admin"
    destination_key = f"{destination.absolute()}::debug"
    _state.save_sessions(
        {source_key: source_record, destination_key: destination_record}
    )
    args = _args(
        source,
        to_directory=str(destination),
        to_profile="debug",
        keep_source=True,
    )
    absent = {
        "exists": False,
        "fingerprint": _state.digest(b"hacksaws:absent-section"),
    }
    old_source = tmp_path / "old-source-cache.json"
    old_destination = tmp_path / "old-destination-cache.json"
    old_source.write_bytes(b"source-refreshed-after-preview")
    old_destination.write_bytes(b"destination-refreshed-after-preview")
    new_source = tmp_path / "new-source-cache.json"
    new_destination = tmp_path / "new-destination-cache.json"
    new_source.write_bytes(b"source-current")
    new_destination.write_bytes(b"destination-current")
    source_claim = {
        "path": str(new_source),
        "whole_digest": _state.digest(new_source.read_bytes()),
    }
    destination_claim = {
        "path": str(new_destination),
        "whole_digest": _state.digest(new_destination.read_bytes()),
    }
    data: dict[str, Any] = {
        "source": source,
        "destination": destination,
        "source_profile": "admin",
        "destination_profile": "debug",
        "source_expected": {"credentials": absent, "config": absent},
        "destination_expected": {"credentials": absent, "config": absent},
        "source_record": source_record,
        "destination_record": destination_record,
        "source_key": source_key,
        "destination_key": destination_key,
        "source_session_expected": _sessions._session_record_state(source_record),
        "destination_session_expected": _sessions._session_record_state(
            destination_record
        ),
        "source_cache": (
            [old_source.parent],
            [
                {
                    "path": str(old_source),
                    "whole_digest": "preview-source-digest",
                }
            ],
            [],
            None,
        ),
        "destination_cache": (
            [old_destination.parent],
            [
                {
                    "path": str(old_destination),
                    "whole_digest": "preview-destination-digest",
                }
            ],
            [],
            None,
        ),
        "cache_expected": {"preview": "stale"},
        "keep_source": True,
        "same_key": False,
        "hacksaws_config_expected": _sessions._file_fingerprint(
            _state.root() / "config.json"
        ),
        "policy_source_expected": None,
    }
    prepared = _sessions.AssumeRolePlan(
        data, _sessions._assume_arguments_fingerprint(args)
    )
    refreshed_source: tuple[
        list[Path], list[dict[str, Any]], list[dict[str, str]], dict[str, Any]
    ] = (
        [new_source.parent],
        [source_claim],
        [],
        {"schema_version": 1, **source_claim},
    )
    refreshed_destination: tuple[
        list[Path], list[dict[str, Any]], list[dict[str, str]], dict[str, Any]
    ] = (
        [new_destination.parent],
        [destination_claim],
        [],
        {"schema_version": 1, **destination_claim},
    )
    with (
        patch(
            "hacksaws._sessions._tracked_login_cache_plan",
            side_effect=[refreshed_source, refreshed_destination],
        ) as refresh,
        patch(
            "hacksaws._sessions._state.load_sessions",
            return_value={
                source_key: source_record,
                destination_key: destination_record,
            },
        ),
    ):
        _sessions._revalidate_assume_plan(_configs.Context(args), prepared)

    assert refresh.call_count == 2
    assert data["source_cache"][1] == []
    assert data["source_cache"][3] == refreshed_source[3]
    assert data["destination_cache"] == refreshed_destination
    assert data["cache_expected"] == {
        str(new_destination.resolve()): _state.digest(new_destination.read_bytes())
    }


def test_prepared_local_policy_rejects_file_change_after_sts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    policy = tmp_path / "agent-policy.json"
    policy.write_text(
        json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "logs:Get*", "Resource": "*"}
                ],
            }
        ),
        encoding="utf-8",
    )
    args = _args(
        source,
        policy=str(policy),
        to_directory=str(destination),
        to_profile="debug",
    )
    context = _configs.Context(args)
    session_patch, identity_patch = _identity_patches()
    with session_patch, identity_patch:
        prepared = _sessions.prepare_assume_role(context)

    def change_policy(
        *_args: object, **_kwargs: object
    ) -> tuple[dict[str, object], dict[str, object]]:
        policy.write_text(
            policy.read_text(encoding="utf-8").replace("logs:Get*", "logs:Delete*"),
            encoding="utf-8",
        )
        return _final()

    with (
        patch("hacksaws._sessions._assume", side_effect=change_policy),
        pytest.raises(_sessions.AssumePlanChanged, match="fresh preview"),
    ):
        _sessions.assume_role(context, prepared)
    assert not (destination / "credentials").exists()
    assert not _sessions._journal_path().exists()


@pytest.mark.parametrize("drift", ["source", "destination"])
def test_post_sts_profile_drift_fails_without_clobbering_concurrent_change(
    drift: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    args = _args(source, to_directory=str(destination), to_profile="debug")
    context = _configs.Context(args)
    session_patch, identity_patch = _identity_patches()
    with session_patch, identity_patch:
        prepared = _sessions.prepare_assume_role(context)

    changed_directory = source if drift == "source" else destination
    changed_profile = "admin" if drift == "source" else "debug"

    def concurrent_change(
        *_args: object, **_kwargs: object
    ) -> tuple[dict[str, object], dict[str, object]]:
        _ini(
            changed_directory / "credentials",
            {
                changed_profile: {
                    "aws_access_key_id": "CONCURRENT",
                    "aws_secret_access_key": "external-secret",
                }
            },
        )
        return _final()

    with (
        patch("hacksaws._sessions._assume", side_effect=concurrent_change),
        pytest.raises(_sessions.AssumePlanChanged, match="fresh preview"),
    ):
        _sessions.assume_role(context, prepared)
    assert _sessions._read_ini(changed_directory / "credentials")[changed_profile][
        "aws_access_key_id"
    ] == ("CONCURRENT")
    assert not _sessions._journal_path().exists()


@pytest.mark.parametrize("drift", ["source", "destination"])
def test_post_sts_session_metadata_drift_fails_before_journal_creation(
    drift: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    args = _args(source, to_directory=str(destination), to_profile="debug")
    context = _configs.Context(args)
    session_patch, identity_patch = _identity_patches()
    with session_patch, identity_patch:
        prepared = _sessions.prepare_assume_role(context)
    source_key = f"{source.absolute()}::admin"
    destination_key = f"{destination.absolute()}::debug"

    def concurrent_session_change(
        *_args: object, **_kwargs: object
    ) -> tuple[dict[str, object], dict[str, object]]:
        sessions = _state.load_sessions()
        if drift == "source":
            sessions[source_key]["ecr"] = ["changed-after-preview.example"]
        else:
            sessions[destination_key] = {
                "destination": str(destination),
                "profile": "debug",
                "auth_method": "external-test",
                "ecr": ["appeared-after-preview.example"],
            }
        _state.save_sessions(sessions)
        return _final()

    with (
        patch("hacksaws._sessions._assume", side_effect=concurrent_session_change),
        pytest.raises(_sessions.AssumePlanChanged, match="fresh preview"),
    ):
        _sessions.assume_role(context, prepared)
    sessions = _state.load_sessions()
    changed_key = source_key if drift == "source" else destination_key
    assert sessions[changed_key]["ecr"]
    assert not _sessions._journal_path().exists()


def test_prepared_recovery_rejects_destination_that_appears_after_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    _context, journal = _crash_journal(
        _args(source, to_directory=str(destination), to_profile="debug")
    )
    _ini(
        destination / "credentials",
        {
            "debug": {
                "aws_access_key_id": "EXTERNAL",
                "aws_secret_access_key": "external-secret",
            }
        },
    )

    with pytest.raises(_configs.OperationalError, match="manual review"):
        _sessions._recover_assume_journal(journal)
    assert _sessions._read_ini(destination / "credentials")["debug"][
        "aws_access_key_id"
    ] == ("EXTERNAL")
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("AUTHENTICATED")
    assert _sessions._journal_path().exists()


@pytest.mark.parametrize(
    "drift",
    ["credentials", "config", "destination-session", "source-session"],
)
def test_installed_recovery_rejects_post_crash_state_drift_before_source_logout(
    drift: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    _context, journal = _crash_journal(
        _args(source, to_directory=str(destination), to_profile="debug")
    )
    _install_crash_destination(journal)
    source_key = f"{source.absolute()}::admin"
    destination_key = f"{destination.absolute()}::debug"
    if drift == "credentials":
        _ini(
            destination / "credentials",
            {
                "debug": {
                    "aws_access_key_id": "DRIFTED",
                    "aws_secret_access_key": "drifted-secret",
                }
            },
        )
    elif drift == "config":
        _ini(destination / "config", {"profile debug": {"region": "eu-west-1"}})
    else:
        sessions = _state.load_sessions()
        key = destination_key if drift == "destination-session" else source_key
        sessions[key]["ecr"] = ["metadata-drift.example"]
        _state.save_sessions(sessions)

    with pytest.raises(_configs.OperationalError, match="manual review"):
        _sessions._recover_assume_journal(journal)
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("AUTHENTICATED")
    assert _sessions._journal_path().exists()
    if drift == "credentials":
        assert _sessions._read_ini(destination / "credentials")["debug"][
            "aws_access_key_id"
        ] == ("DRIFTED")
    elif drift == "config":
        assert _sessions._read_ini(destination / "config")["profile debug"][
            "region"
        ] == ("eu-west-1")
    else:
        key = destination_key if drift == "destination-session" else source_key
        assert _state.load_sessions()[key]["ecr"] == ["metadata-drift.example"]


def test_installed_recovery_rejects_browser_cache_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    cache = source / "login" / "cache" / "browser.json"
    cache.parent.mkdir(parents=True)
    cache.write_text("owned-browser-token", encoding="utf-8")
    source_key = f"{source.absolute()}::admin"
    sessions = _state.load_sessions()
    sessions[source_key].update(
        auth_method="browser-native",
        login_cache_directories=[str(cache.parent.absolute())],
        login_cache_files=[str(cache.absolute())],
        login_cache_fingerprints={
            str(cache.absolute()): _state.digest(cache.read_bytes())
        },
    )
    _state.save_sessions(sessions)
    _context, journal = _crash_journal(
        _args(source, to_directory=str(destination), to_profile="debug")
    )
    _install_crash_destination(journal)
    cache.write_text("externally-changed-token", encoding="utf-8")

    with pytest.raises(_configs.OperationalError, match="browser-cache-residue"):
        _sessions._recover_assume_journal(journal)
    assert cache.read_text(encoding="utf-8") == "externally-changed-token"
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("ORIGINAL")
    assert not _sessions._journal_path().exists()


def test_installed_recovery_retries_owned_cache_removal_without_restoring_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    cache = source / "login" / "cache" / "browser.json"
    cache.parent.mkdir(parents=True)
    cache.write_text("owned-browser-token", encoding="utf-8")
    source_key = f"{source.absolute()}::admin"
    sessions = _state.load_sessions()
    sessions[source_key].update(
        auth_method="browser-native",
        login_cache_directories=[str(cache.parent.absolute())],
        login_cache_files=[str(cache.absolute())],
        login_cache_fingerprints={
            str(cache.absolute()): _state.digest(cache.read_bytes())
        },
    )
    _state.save_sessions(sessions)
    _context, journal = _crash_journal(
        _args(source, to_directory=str(destination), to_profile="debug")
    )
    _install_crash_destination(journal)
    original_unlink = Path.unlink

    def fail_cache_unlink(path: Path, *args: object, **kwargs: object) -> None:
        if path == cache:
            message = "cache is locked"
            raise OSError(message)
        original_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    with (
        patch.object(Path, "unlink", fail_cache_unlink),
        pytest.raises(_configs.OperationalError, match="browser-cache-residue"),
    ):
        _sessions._recover_assume_journal(journal)
    assert cache.exists()
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("ORIGINAL")
    assert not _sessions._journal_path().exists()

    _sessions._logout_key(source_key, _args(source, force=True))
    assert not cache.exists()
    assert not _sessions._journal_path().exists()
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("ORIGINAL")


def test_source_removed_recovery_is_idempotent_but_rejects_later_session_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    args = _args(source, to_directory=str(destination), to_profile="debug")
    _context, journal = _crash_journal(args)
    _install_crash_destination(journal)
    _sessions._finish_assume_source(journal)
    journal["phase"] = "source-removed"
    _sessions._write_assume_journal(journal)
    destination_key = f"{destination.absolute()}::debug"
    sessions = _state.load_sessions()
    sessions[destination_key]["ecr"] = ["changed-after-source-logout.example"]
    _state.save_sessions(sessions)

    with pytest.raises(_configs.OperationalError, match="manual review"):
        _sessions._recover_assume_journal(journal)
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("ORIGINAL")
    assert _state.load_sessions()[destination_key]["ecr"] == [
        "changed-after-source-logout.example"
    ]
    assert _sessions._journal_path().exists()

    sessions = _state.load_sessions()
    sessions[destination_key] = journal["destination"]["session"]
    _state.save_sessions(sessions)
    _sessions._recover_assume_journal(journal)
    assert not _sessions._journal_path().exists()
    assert _sessions._read_ini(destination / "credentials")["debug"][
        "aws_access_key_id"
    ] == ("BOUNDARY")


def test_prepared_duration_is_reused_by_preview_execution_and_sts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    args = _args(
        source,
        duration="15m",
        to_directory=str(destination),
        to_profile="debug",
    )
    context = _configs.Context(args)
    session_patch, identity_patch = _identity_patches()
    with session_patch, identity_patch:
        prepared = _sessions.prepare_assume_role(context)
    assert _sessions.assume_role_preview(prepared)["durationSeconds"] == 900
    with patch("hacksaws._sessions._assume", return_value=_final()) as assume:
        result = _sessions.assume_role(context, prepared)
    assert assume.call_args.kwargs["effective_duration"] == 900
    assert isinstance(result.data, dict)
    assert result.data["durationSeconds"] == 900


def test_assume_journal_never_contains_authenticated_or_browser_cache_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    destination = home / ".aws-agent"
    _managed_source(source)
    cache = source / "login" / "cache" / "browser.json"
    cache.parent.mkdir(parents=True)
    cache.write_text("browser-login-token-bytes", encoding="utf-8")
    source_key = f"{source.absolute()}::admin"
    sessions = _state.load_sessions()
    sessions[source_key].update(
        auth_method="browser-native",
        login_cache_directories=[str(cache.parent.absolute())],
        login_cache_files=[str(cache.absolute())],
        login_cache_fingerprints={
            str(cache.absolute()): _state.digest(cache.read_bytes())
        },
    )
    _state.save_sessions(sessions)
    args = _args(source, to_directory=str(destination), to_profile="debug")
    context = _configs.Context(args)
    session_patch, identity_patch = _identity_patches()
    with session_patch, identity_patch:
        prepared = _sessions.prepare_assume_role(context)
    captured = ""

    def fail_destination_write(*_args: object, **_kwargs: object) -> None:
        nonlocal captured
        captured = _sessions._journal_path().read_text(encoding="utf-8")
        message = "simulated destination write failure"
        raise RuntimeError(message)

    with (
        patch("hacksaws._sessions._assume", return_value=_final()),
        patch("hacksaws._sessions._write_section_cas", fail_destination_write),
        pytest.raises(RuntimeError, match="simulated destination write failure"),
    ):
        _sessions.assume_role(context, prepared)
    for secret in (
        "AUTHENTICATED",
        "authenticated-secret",
        "authenticated-token",
        "browser-login-token-bytes",
    ):
        assert secret not in captured
    assert cache.exists()
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("AUTHENTICATED")
    assert not _sessions._journal_path().exists()


def test_self_crash_recovery_rolls_forward_without_resurrecting_broad_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    _managed_source(source)
    args = _args(source, self_destination=True)
    context = _configs.Context(args)
    session_patch, identity_patch = _identity_patches()
    with session_patch, identity_patch:
        prepared = _sessions.prepare_assume_role(context)
    original_write = _sessions._write_assume_journal
    writes = 0

    def crash_after_install(journal: dict[str, Any]) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            message = "simulated phase crash"
            raise RuntimeError(message)
        original_write(journal)

    with (
        patch("hacksaws._sessions._assume", return_value=_final()),
        patch(
            "hacksaws._sessions._write_assume_journal",
            side_effect=crash_after_install,
        ),
        patch(
            "hacksaws._sessions._recover_assume_journal",
            side_effect=RuntimeError("process stopped"),
        ),
        pytest.raises(RuntimeError, match="process stopped"),
    ):
        _sessions.assume_role(context, prepared)
    persisted = _sessions._journal_path().read_text(encoding="utf-8")
    assert "authenticated-secret" not in persisted
    assert "authenticated-token" not in persisted
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("BOUNDARY")

    _sessions.recover_journal()
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("BOUNDARY")
    assert not _sessions._journal_path().exists()

    logout_args = argparse.Namespace(
        **{
            **vars(args),
            "self_destination": False,
            "to": None,
            "except_profiles": [],
        }
    )
    assert _sessions.logout(_configs.Context(logout_args))
    assert _sessions._read_ini(source / "credentials")["admin"][
        "aws_access_key_id"
    ] == ("ORIGINAL")


def test_distinct_recovery_cleans_browser_source_with_absent_original_sections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-browser"
    destination = home / ".aws-agent"
    cache = _managed_browser_source_with_absent_originals(source)
    args = _args(source, to_directory=str(destination), to_profile="debug")
    _context, journal = _crash_journal(args)
    _install_crash_destination(journal)

    _sessions.recover_journal()

    assert not _sessions._section_state(source / "credentials", "admin")["exists"]
    assert not _sessions._section_state(source / "config", "profile admin")["exists"]
    assert not cache.exists()
    assert not _sessions._journal_path().exists()
    sessions = _state.load_sessions()
    assert f"{source.absolute()}::admin" not in sessions
    assert sessions[f"{destination.absolute()}::debug"]["auth_method"] == "assume-role"

    logout_args = _args(destination, profile="debug")
    logout_args.except_profiles = []
    assert _sessions.logout(_configs.Context(logout_args))
    assert not _sessions._section_state(destination / "credentials", "debug")["exists"]
    assert not _sessions._section_state(destination / "config", "profile debug")[
        "exists"
    ]


def test_self_recovery_replaces_browser_auth_then_logout_restores_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-browser"
    cache = _managed_browser_source_with_absent_originals(source)
    args = _args(source, self_destination=True)
    _context, journal = _crash_journal(args)
    _install_crash_destination(journal)

    _sessions.recover_journal()

    credentials = _sessions._read_ini(source / "credentials")
    assert credentials["admin"]["aws_access_key_id"] == "BOUNDARY"
    config = _sessions._read_ini(source / "config")
    assert "login_session" not in config["profile admin"]
    assert not cache.exists()
    assert not _sessions._journal_path().exists()
    session = _state.load_sessions()[f"{source.absolute()}::admin"]
    assert session["auth_method"] == "assume-role"
    assert "login_cache_files" not in session

    logout_args = argparse.Namespace(
        **{
            **vars(args),
            "self_destination": False,
            "to": None,
            "except_profiles": [],
        }
    )
    assert _sessions.logout(_configs.Context(logout_args))
    assert not _sessions._section_state(source / "credentials", "admin")["exists"]
    assert not _sessions._section_state(source / "config", "profile admin")["exists"]
    assert f"{source.absolute()}::admin" not in _state.load_sessions()


def test_prepared_plan_contract_rejects_wrong_reused_and_changed_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    _managed_source(source)
    args = _args(source, self_destination=True)
    context = _configs.Context(args)
    session_patch, identity_patch = _identity_patches()
    with session_patch, identity_patch:
        prepared = _sessions.prepare_assume_role(context)
    with pytest.raises(TypeError, match="prepare_assume_role output"):
        _sessions.assume_role_preview(object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="prepare_assume_role output"):
        _sessions.assume_role(context, object())  # type: ignore[arg-type]

    prepared._consumed = True
    with pytest.raises(_sessions.AssumePlanChanged, match="already been consumed"):
        _sessions.assume_role(context, prepared)
    prepared._consumed = False
    args.role = f"arn:aws:iam::{ACCOUNT}:role/ChangedAfterPreview"
    with pytest.raises(_sessions.AssumePlanChanged, match="fresh preview"):
        _sessions.assume_role(context, prepared)
    assert not _sessions._journal_path().exists()


def test_assume_recovery_rejects_invalid_records_and_reports_cache_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    with pytest.raises(_configs.OperationalError, match="Unsupported AssumeRole"):
        _sessions._recover_assume_journal({"schema_version": 1})
    with pytest.raises(_configs.OperationalError, match="section is invalid"):
        _sessions._write_section(
            tmp_path / "credentials",
            "admin",
            {"exists": True, "values": "not-a-section"},
        )
    with pytest.raises(_configs.OperationalError, match="no safe original"):
        _sessions._assume_original_section(
            {"source_record": {"section_backup": {}}, "destination_record": None},
            source=True,
            kind="credentials",
        )
    missing_cache = tmp_path / "missing-owned.cache"
    with pytest.raises(_configs.OperationalError, match="manual review"):
        _sessions._validate_assume_cache(
            {"cache": [{"path": str(missing_cache), "fingerprint": "expected"}]},
            allow_missing=False,
        )
    with pytest.raises(_configs.OperationalError, match="final session metadata"):
        _sessions._write_session_cas(
            "missing::profile",
            expected={"exists": False, "fingerprint": None},
            final={"exists": True, "fingerprint": "invalid-without-values"},
            label="test session metadata",
        )
    legacy = tmp_path / "admin.store.credentials"
    legacy_journal = {
        "source": {
            "legacy_backup": {
                "path": str(legacy),
                "fingerprint": _state.digest(b"original"),
            }
        }
    }
    _sessions._validate_assume_legacy(legacy_journal, allow_missing=True)
    with pytest.raises(_configs.OperationalError, match="manual review"):
        _sessions._validate_assume_legacy(legacy_journal, allow_missing=False)
    legacy.write_bytes(b"changed")
    with pytest.raises(_configs.OperationalError, match="manual review"):
        _sessions._validate_assume_legacy(legacy_journal, allow_missing=True)

    changed = tmp_path / "changed.cache"
    changed.write_bytes(b"changed")
    locked = tmp_path / "locked.cache"
    locked.write_bytes(b"owned")
    original_unlink = Path.unlink

    def fail_locked(path: Path, *args: object, **kwargs: object) -> None:
        if path == locked:
            message = "locked by another process"
            raise OSError(message)
        original_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "unlink", fail_locked)
    residue = _sessions._remove_assume_cache(
        {
            "cache": [
                {"path": str(changed), "fingerprint": _state.digest(b"original")},
                {"path": str(locked), "fingerprint": _state.digest(b"owned")},
                {"path": str(tmp_path / "missing.cache"), "fingerprint": None},
            ]
        }
    )
    assert {item["reason"] for item in residue} == {
        "legacy cache fingerprint changed",
        "remove failed: locked by another process",
    }
    assert changed.exists()
    assert locked.exists()


@pytest.mark.parametrize(
    "session",
    [
        {"auth_method": "ecr-only"},
        {"auth_method": "mfa", "expires_at": "not-a-time"},
        {
            "auth_method": "mfa",
            "expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        },
    ],
)
def test_assume_source_state_guards_reject_residue_invalid_and_expired_sessions(
    session: dict[str, object],
) -> None:
    with pytest.raises(_configs.OperationalError):
        _sessions._session_is_usable_source(session)


def test_raw_account_id_uses_caller_partition_and_asserts_direct_role_arn() -> None:
    args = _args(Path(), role="AgentSession", account=OTHER_ACCOUNT)
    role, *_ = _sessions._role_details(args, {}, ACCOUNT, "aws-cn")
    assert role == f"arn:aws-cn:iam::{OTHER_ACCOUNT}:role/AgentSession"

    args.role = f"arn:aws-cn:iam::{OTHER_ACCOUNT}:role/AgentSession"
    role, *_ = _sessions._role_details(args, {}, ACCOUNT, "aws-cn")
    assert role == args.role

    args.role = f"arn:aws-cn:iam::{ACCOUNT}:role/AgentSession"
    with pytest.raises(_configs.OperationalError, match="conflicts with --account"):
        _sessions._role_details(args, {}, ACCOUNT, "aws-cn")


def test_configured_account_name_keeps_its_configured_partition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    data = _state.default_config()
    data["accounts"]["China"] = {"id": OTHER_ACCOUNT, "partition": "aws-cn"}
    _state.save_config(data)
    args = _args(Path(), role="AgentSession", account="China")
    role, *_ = _sessions._role_details(args, {}, ACCOUNT, "aws")
    assert role == f"arn:aws-cn:iam::{OTHER_ACCOUNT}:role/AgentSession"


def test_legacy_backup_validation_errors_are_operational_errors(
    tmp_path: Path,
) -> None:
    _ini(tmp_path / "admin.store.credentials", {"other": {"value": "x"}})
    with pytest.raises(_configs.OperationalError, match="has no profile"):
        _sessions._legacy_source_backup(tmp_path, "admin")
    _ini(tmp_path / "admin.store.credentials", {"admin": {"aws_access_key_id": "x"}})
    with pytest.raises(_configs.OperationalError, match="incomplete"):
        _sessions._legacy_source_backup(tmp_path, "admin")


def test_region_helpers_cover_absent_config_and_explicit_override(
    tmp_path: Path,
) -> None:
    assert _sessions._region_values(tmp_path, "admin") == {}
    _sessions._apply_region_values(
        tmp_path, "debug", {"region": "us-east-1", "output": "json"}, "us-west-1"
    )
    config = _sessions._read_ini(tmp_path / "config")
    assert config["profile debug"]["region"] == "us-west-1"
    assert "output" not in config["profile debug"]


def test_verbose_self_preview_warns_and_requires_explicit_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path, monkeypatch)
    source = home / ".aws-source"
    _managed_source(source)
    implicit = _args(source)
    with pytest.raises(_configs.OperationalError, match="Use --self"):
        _preview(implicit)

    verbose = _args(source, to_profile="admin")
    session_patch, identity_patch = _identity_patches()
    with session_patch, identity_patch:
        preview = _preview(verbose)
    assert preview["warnings"]
    assert preview["lifecycle"]["destination"] == "replace-source-in-place"


def test_cleanup_assume_ecr_updates_active_and_residual_owners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(tmp_path, monkeypatch)
    _state.save_sessions(
        {
            "residual": {
                "auth_method": "ecr-only",
                "ecr": ["one.example"],
            },
            "active": {
                "auth_method": "assume-role",
                "ecr": ["one.example", "two.example"],
            },
        }
    )
    owners = {
        "residual": ("docker", ["one.example"]),
        "active": ("docker", ["one.example", "two.example"]),
        "missing": ("docker", ["one.example"]),
    }
    with patch("hacksaws._ecr._run_container_engine") as engine:
        assert _sessions._cleanup_assume_ecr(owners) == []
    assert engine.call_count == 2
    sessions = _state.load_sessions()
    assert "residual" not in sessions
    assert sessions["active"]["ecr"] == []
