"""Security coverage for browser cache lineage and secret-safe auth input."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from hacksaws import _cli
from hacksaws import _configs
from hacksaws import _history
from hacksaws import _sessions
from hacksaws import _state

ACCOUNT = "123456789012"
PRINCIPAL = f"arn:aws:iam::{ACCOUNT}:user/browser-user"


def _cache(
    directory: Path,
    profile: str = "dev",
    *,
    login_session: str = PRINCIPAL,
    client_id: str = "client-generation-one",
    dpop: str = (
        "-----BEGIN PRIVATE KEY-----\ndpop-generation-one\n-----END PRIVATE KEY-----"
    ),
    access_key: str = "ACCESS-SENTINEL",
    refresh: str = "REFRESH-SENTINEL",
) -> tuple[Path, dict[str, object]]:
    config = _sessions._read_ini(directory / "config")
    config[_sessions._section(profile, config=True)] = {
        "login_session": login_session,
        "region": "us-east-1",
    }
    _sessions._write_ini(directory / "config", config)
    root = directory / "login" / "cache"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{_state.digest(login_session.encode())}.json"
    token: dict[str, object] = {
        "accessToken": {
            "accessKeyId": access_key,
            "secretAccessKey": "SECRET-SENTINEL",
            "sessionToken": "SESSION-SENTINEL",
            "accountId": ACCOUNT,
            "expiresAt": "2030-01-01T00:00:00Z",
        },
        "refreshToken": refresh,
        "clientId": client_id,
        "dpopKey": dpop,
    }
    path.write_text(json.dumps(token), encoding="utf-8")
    return path, token


def _browser_session(directory: Path, lineage: dict[str, object]) -> dict[str, object]:
    return {
        "destination": str(directory.absolute()),
        "profile": "dev",
        "auth_method": "browser-native",
        "source_account": ACCOUNT,
        "source_partition": "aws",
        "login_cache_lineage": lineage,
        "backup": [],
        "section_backup": {},
        "ecr": [],
    }


def test_lineage_is_exact_and_contains_no_browser_secrets(tmp_path: Path) -> None:
    path, _ = _cache(tmp_path)
    lineage = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    encoded = json.dumps(lineage)
    assert lineage["path"] == str(path.resolve())
    assert lineage["cache_key"] == path.stem
    for sentinel in (
        "ACCESS-SENTINEL",
        "SECRET-SENTINEL",
        "SESSION-SENTINEL",
        "REFRESH-SENTINEL",
        "dpop-generation-one",
        "client-generation-one",
    ):
        assert sentinel not in encoded


def test_refresh_rotation_is_accepted_after_identity_verification(
    tmp_path: Path,
) -> None:
    path, token = _cache(tmp_path)
    lineage = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    token["refreshToken"] = "ROTATED-REFRESH-SENTINEL"
    token["accessToken"] = {
        **token["accessToken"],  # type: ignore[dict-item]
        "accessKeyId": "ROTATED-ACCESS-SENTINEL",
        "expiresAt": "2031-01-01T00:00:00Z",
    }
    path.write_text(json.dumps(token), encoding="utf-8")
    with (
        patch("hacksaws._sessions.boto3.Session", return_value=MagicMock()),
        patch("hacksaws._sessions._identity", return_value=(ACCOUNT, "aws", PRINCIPAL)),
    ):
        _roots, removals, residue, upgraded = _sessions._tracked_login_cache_plan(
            _browser_session(tmp_path, lineage), tmp_path, "dev", force=False
        )
    assert residue == []
    assert removals[0]["whole_digest"] == _state.digest(path.read_bytes())
    assert upgraded == removals[0]


def test_force_preserves_a_demonstrably_different_generation(tmp_path: Path) -> None:
    path, _ = _cache(tmp_path)
    lineage = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    _cache(tmp_path, dpop="different-DPoP-generation")
    _roots, removals, residue, _ = _sessions._tracked_login_cache_plan(
        _browser_session(tmp_path, lineage), tmp_path, "dev", force=True
    )
    assert removals == []
    assert "different login generation" in residue[0]["reason"]
    _sessions._remove_tracked_login_cache(removals, residue, force=True)
    assert path.exists()


def test_compare_and_delete_preserves_concurrent_refresh(tmp_path: Path) -> None:
    path, token = _cache(tmp_path)
    claim = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    claim.update(config=str((tmp_path / "config").resolve()), profile="dev")
    token["refreshToken"] = "CONCURRENT-ROTATION"
    path.write_text(json.dumps(token), encoding="utf-8")
    residue = _sessions._remove_tracked_login_cache([claim], [], force=True)
    assert residue[0]["reason"] == "browser cache changed during compare-and-delete"
    assert path.exists()


def test_exact_claim_removal_handles_missing_refresh_and_replacement(
    tmp_path: Path,
) -> None:
    path, token = _cache(tmp_path)
    claim = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    claim.update(config=str((tmp_path / "config").resolve()), profile="dev")

    path.unlink()
    assert _sessions._remove_browser_cache_claim(claim, strict=True) is None

    path.write_text(json.dumps(token), encoding="utf-8")
    token["refreshToken"] = "REFRESH-ROTATED-BEFORE-ROLLBACK"
    path.write_text(json.dumps(token), encoding="utf-8")
    assert _sessions._remove_browser_cache_claim(claim, strict=True) is None
    assert not path.exists()

    path, _ = _cache(tmp_path)
    replacement_claim = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    replacement_claim.update(config=str((tmp_path / "config").resolve()), profile="dev")
    _cache(tmp_path, dpop="replacement")
    with pytest.raises(_configs.OperationalError, match="different login generation"):
        _sessions._remove_browser_cache_claim(replacement_claim, strict=True)
    residue = _sessions._remove_browser_cache_claim(replacement_claim, strict=False)
    assert residue is not None
    assert residue["reason"] == "browser cache belongs to a different login generation"
    assert path.exists()


def test_exact_claim_removal_reports_missing_config_and_unlink_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _ = _cache(tmp_path)
    claim = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    claim.update(config=str((tmp_path / "config").resolve()), profile="dev")
    (tmp_path / "config").unlink()
    residue = _sessions._remove_browser_cache_claim(claim, strict=False)
    assert residue is not None
    assert "no login_session" in residue["reason"]
    with pytest.raises(_configs.OperationalError, match="no login_session"):
        _sessions._remove_browser_cache_claim(claim, strict=True)

    _cache(tmp_path)

    def locked(_path: Path) -> None:
        raise PermissionError("locked")

    monkeypatch.setattr(Path, "unlink", locked)
    residue = _sessions._remove_browser_cache_claim(claim, strict=False)
    assert residue is not None
    assert residue["reason"] == "remove failed: locked"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing-session", "no login_session"),
        ("invalid-json", "Unable to read"),
        ("non-object", "not a JSON object"),
        ("missing-fields", "missing stable lineage"),
        ("wrong-account", "does not match GetCallerIdentity"),
    ],
)
def test_lineage_rejects_incomplete_or_cross_account_cache(
    tmp_path: Path, mutation: str, message: str
) -> None:
    path, token = _cache(tmp_path)
    if mutation == "missing-session":
        config = _sessions._read_ini(tmp_path / "config")
        config["profile dev"].pop("login_session")
        _sessions._write_ini(tmp_path / "config", config)
    elif mutation == "invalid-json":
        path.write_text("{broken", encoding="utf-8")
    elif mutation == "non-object":
        path.write_text("[]", encoding="utf-8")
    elif mutation == "missing-fields":
        path.write_text(json.dumps({"accessToken": {}}), encoding="utf-8")
    else:
        token["accessToken"] = {
            **token["accessToken"],  # type: ignore[dict-item]
            "accountId": "210987654321",
        }
        path.write_text(json.dumps(token), encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match=message):
        _sessions._browser_cache_lineage(
            tmp_path / "config",
            "dev",
            path.parent,
            identity=(ACCOUNT, "aws", PRINCIPAL),
        )


def test_browser_rollback_claim_is_secret_free_and_exact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "hacksaws-home"))
    path, _ = _cache(tmp_path)
    original_config = (tmp_path / "config").read_bytes()
    journal = _sessions._begin([tmp_path / "config"])
    lineage = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    _sessions._record_browser_cache_claim(journal, lineage, tmp_path / "config", "dev")
    serialized = _sessions._journal_path().read_text(encoding="utf-8")
    assert "REFRESH-SENTINEL" not in serialized
    assert "SESSION-SENTINEL" not in serialized
    (tmp_path / "config").write_text("[profile dev]\nregion=x\n", encoding="utf-8")
    # Rollback evaluates the claim before restoring the config, so retain the
    # login_session until the exact owned file is removed.
    (tmp_path / "config").write_bytes(original_config)
    _sessions._rollback(journal)
    assert not path.exists()
    assert (tmp_path / "config").read_bytes() == original_config


def test_browser_rollback_preserves_a_replaced_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "hacksaws-home"))
    path, _ = _cache(tmp_path)
    journal = _sessions._begin([tmp_path / "config"])
    lineage = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    _sessions._record_browser_cache_claim(journal, lineage, tmp_path / "config", "dev")
    _cache(tmp_path, dpop="replacement-generation")
    with pytest.raises(_configs.OperationalError, match="different login generation"):
        _sessions._rollback(journal)
    assert path.exists()
    assert _sessions._journal_path().exists()


def test_unchanged_lineage_does_not_require_network_identity(tmp_path: Path) -> None:
    path, _ = _cache(tmp_path)
    lineage = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    with patch("hacksaws._sessions._identity") as identity:
        _roots, removals, residue, _ = _sessions._tracked_login_cache_plan(
            _browser_session(tmp_path, lineage), tmp_path, "dev", force=False
        )
    identity.assert_not_called()
    assert removals == [lineage]
    assert residue == []


def test_refresh_with_wrong_sts_identity_becomes_residue(tmp_path: Path) -> None:
    path, token = _cache(tmp_path)
    lineage = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    token["refreshToken"] = "rotated"
    path.write_text(json.dumps(token), encoding="utf-8")
    with (
        patch("hacksaws._sessions.boto3.Session", return_value=MagicMock()),
        patch(
            "hacksaws._sessions._identity",
            return_value=(ACCOUNT, "aws", f"arn:aws:iam::{ACCOUNT}:user/other"),
        ),
    ):
        _roots, removals, residue, _ = _sessions._tracked_login_cache_plan(
            _browser_session(tmp_path, lineage), tmp_path, "dev", force=True
        )
    assert removals == []
    assert "GetCallerIdentity" in residue[0]["reason"]
    assert path.exists()


def test_assume_cache_validation_accepts_refresh_but_rejects_generation_change(
    tmp_path: Path,
) -> None:
    path, token = _cache(tmp_path)
    claim = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    original_digest = claim["whole_digest"]
    token["refreshToken"] = "ROTATED-DURING-ASSUME"
    path.write_text(json.dumps(token), encoding="utf-8")
    journal = {"cache": [claim]}
    _sessions._validate_assume_cache(journal, allow_missing=True)
    assert claim["whole_digest"] != original_digest
    stale = {**claim, "whole_digest": str(original_digest)}
    with pytest.raises(_configs.OperationalError, match="manual review"):
        _sessions._validate_assume_cache({"cache": [stale]}, allow_missing=False)

    _cache(tmp_path, dpop="different-assume-generation")
    changed = {"cache": [claim]}
    _sessions._validate_assume_cache(changed, allow_missing=True)
    assert claim["residue_reason"] == "different browser login generation"
    with pytest.raises(_configs.OperationalError, match="manual review"):
        _sessions._validate_assume_cache(
            {"cache": [{**claim, "residue_reason": None}]}, allow_missing=False
        )


def test_assume_cache_removal_deletes_same_lineage_and_preserves_unknown(
    tmp_path: Path,
) -> None:
    path, token = _cache(tmp_path)
    claim = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    token["refreshToken"] = "ROTATED-BEFORE-FINAL-CLEANUP"
    path.write_text(json.dumps(token), encoding="utf-8")
    assert _sessions._remove_assume_cache({"cache": [claim]}) == []
    assert not path.exists()

    path, _ = _cache(tmp_path)
    different = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    _cache(tmp_path, dpop="different-final-generation")
    residue = _sessions._remove_assume_cache({"cache": [different]})
    assert residue == [
        {"path": str(path.absolute()), "reason": "different browser login generation"}
    ]
    assert path.exists()
    with pytest.raises(_configs.OperationalError, match="manual review"):
        _sessions._remove_assume_cache({"cache": [different]}, strict=True)

    already_residue = {**different, "residue_reason": "ownership uncertain"}
    assert _sessions._remove_assume_cache({"cache": [already_residue]}) == [
        {"path": str(path.absolute()), "reason": "ownership uncertain"}
    ]


def test_exact_claim_and_assume_cleanup_close_compare_delete_races(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, token = _cache(tmp_path)
    claim = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    claim.update(config=str((tmp_path / "config").resolve()), profile="dev")
    original_current_claim = _sessions._current_browser_cache_claim

    def rotate_after_claim_read(value: dict[str, object]) -> dict[str, object]:
        current = original_current_claim(value)
        token["refreshToken"] = "RACE-AFTER-CLAIM-READ"
        path.write_text(json.dumps(token), encoding="utf-8")
        return current

    monkeypatch.setattr(
        _sessions, "_current_browser_cache_claim", rotate_after_claim_read
    )
    with pytest.raises(_configs.OperationalError, match="compare-and-delete"):
        _sessions._remove_browser_cache_claim(claim, strict=True)
    assert path.exists()

    monkeypatch.setattr(
        _sessions, "_current_browser_cache_claim", original_current_claim
    )
    current_claim = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    original_content = _sessions._current_browser_cache_content
    rotation = 0

    def rotate_after_content_read(value: dict[str, object]) -> dict[str, object]:
        nonlocal rotation
        current = original_content(value)
        rotation += 1
        token["refreshToken"] = f"RACE-AFTER-CONTENT-READ-{rotation}"
        path.write_text(json.dumps(token), encoding="utf-8")
        return current

    monkeypatch.setattr(
        _sessions, "_current_browser_cache_content", rotate_after_content_read
    )
    residue = _sessions._remove_assume_cache({"cache": [current_claim]})
    assert residue[0]["reason"] == "cache changed during compare-and-delete"
    assert path.exists()
    with pytest.raises(_configs.OperationalError, match="manual review"):
        _sessions._remove_assume_cache({"cache": [current_claim]}, strict=True)


def test_strict_cache_removal_reports_unlink_and_content_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _ = _cache(tmp_path)
    claim = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    claim.update(config=str((tmp_path / "config").resolve()), profile="dev")

    def locked(_path: Path) -> None:
        raise PermissionError("locked")

    monkeypatch.setattr(Path, "unlink", locked)
    with pytest.raises(
        _configs.OperationalError, match="Unable to remove browser cache"
    ):
        _sessions._remove_browser_cache_claim(claim, strict=True)
    with pytest.raises(
        _configs.OperationalError, match="Unable to remove owned browser login cache"
    ):
        _sessions._remove_assume_cache({"cache": [claim]}, strict=True)

    monkeypatch.setattr(
        _sessions,
        "_current_browser_cache_content",
        lambda _claim: (_ for _ in ()).throw(
            _configs.OperationalError("content unreadable")
        ),
    )
    residue = _sessions._remove_assume_cache({"cache": [claim]})
    assert residue[0]["reason"] == "unreadable: content unreadable"
    with pytest.raises(_configs.OperationalError, match="manual review"):
        _sessions._remove_assume_cache({"cache": [claim]}, strict=True)


def test_legacy_lineage_plan_is_cas_only_even_with_force(tmp_path: Path) -> None:
    path = tmp_path / "legacy.json"
    root = path.parent
    session = {
        "auth_method": "browser-cache-residue",
        "login_cache_lineage": {
            "schema_version": 0,
            "legacy_cas_only": True,
            "root": str(root),
            "path": str(path),
            "whole_digest": _state.digest(b"owned"),
        },
    }
    roots, removals, residue, upgraded = _sessions._tracked_login_cache_plan(
        session, tmp_path, "dev", force=False
    )
    assert roots == [root.resolve()]
    assert removals == residue == []
    assert upgraded is None

    path.write_bytes(b"changed")
    with pytest.raises(_configs.OperationalError, match="changed after login"):
        _sessions._tracked_login_cache_plan(session, tmp_path, "dev", force=False)
    _roots, removals, residue, _ = _sessions._tracked_login_cache_plan(
        session, tmp_path, "dev", force=True
    )
    assert removals == []
    assert residue[0]["reason"] == "legacy cache fingerprint changed after login"

    path.write_bytes(b"owned")
    _roots, removals, residue, _ = _sessions._tracked_login_cache_plan(
        session, tmp_path, "dev", force=False
    )
    assert removals[0]["legacy_cas_only"] is True
    assert residue == []


def test_removed_profile_and_failed_or_racing_identity_preserve_cache(
    tmp_path: Path,
) -> None:
    path, token = _cache(tmp_path)
    lineage = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    session = _browser_session(tmp_path, lineage)
    (tmp_path / "config").unlink()
    token["refreshToken"] = "ROTATED-WITHOUT-PROFILE"
    path.write_text(json.dumps(token), encoding="utf-8")
    _roots, removals, residue, _ = _sessions._tracked_login_cache_plan(
        session, tmp_path, "dev", force=True
    )
    assert removals == []
    assert "ownership cannot be reverified" in residue[0]["reason"]

    path, token = _cache(tmp_path)
    lineage = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    session = _browser_session(tmp_path, lineage)
    token["refreshToken"] = "ROTATED-BEFORE-FAILED-IDENTITY"
    path.write_text(json.dumps(token), encoding="utf-8")
    with (
        patch("hacksaws._sessions.boto3.Session", return_value=MagicMock()),
        patch(
            "hacksaws._sessions._identity",
            side_effect=_configs.OperationalError("identity unavailable"),
        ),
    ):
        _roots, removals, residue, _ = _sessions._tracked_login_cache_plan(
            session, tmp_path, "dev", force=True
        )
    assert removals == []
    assert residue[0]["reason"] == "identity unavailable"

    def change_generation_during_identity(
        _session: object, *, label: str
    ) -> tuple[str, str, str]:
        assert label == "browser login cache ownership"
        _cache(tmp_path, dpop="GENERATION-CHANGED-DURING-IDENTITY")
        return ACCOUNT, "aws", PRINCIPAL

    path, token = _cache(tmp_path)
    lineage = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )
    token["refreshToken"] = "ROTATED-BEFORE-RACING-IDENTITY"
    path.write_text(json.dumps(token), encoding="utf-8")
    with (
        patch("hacksaws._sessions.boto3.Session", return_value=MagicMock()),
        patch(
            "hacksaws._sessions._identity",
            side_effect=change_generation_during_identity,
        ),
    ):
        _roots, removals, residue, _ = _sessions._tracked_login_cache_plan(
            _browser_session(tmp_path, lineage), tmp_path, "dev", force=True
        )
    assert removals == []
    assert (
        residue[0]["reason"] == "browser cache changed generation during verification"
    )


def test_final_tracked_cache_unlink_failure_is_residue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _ = _cache(tmp_path)
    claim = _sessions._browser_cache_lineage(
        tmp_path / "config",
        "dev",
        path.parent,
        identity=(ACCOUNT, "aws", PRINCIPAL),
    )

    def locked(_path: Path) -> None:
        raise PermissionError("locked")

    monkeypatch.setattr(Path, "unlink", locked)
    residue = _sessions._remove_tracked_login_cache([claim], [], force=True)
    assert residue == [{"path": str(path), "reason": "remove failed: locked"}]


def test_original_file_reconstructs_only_persistent_managed_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    aws = tmp_path / "aws"
    config = aws / "config"
    parser = _sessions._read_ini(config)
    parser["profile dev"] = {
        "region": "temporary-region",
        "login_session": "temporary-browser-session",
    }
    parser["profile untouched"] = {"region": "eu-west-1"}
    _sessions._write_ini(config, parser)
    key = f"{aws.absolute()}::dev"
    session = {
        "section_backup": {
            "config": {
                "original": {
                    "exists": True,
                    "values": {"region": "us-west-2"},
                }
            }
        },
        "backup": [],
    }
    _state.save_sessions({key: session})

    reconstructed = _sessions._original_file(config, "dev")
    assert reconstructed is not None
    assert b"temporary-browser-session" not in reconstructed
    assert b"region = us-west-2" in reconstructed
    assert b"profile untouched" in reconstructed

    session["section_backup"]["config"]["original"] = {  # type: ignore[index]
        "exists": False,
        "values": {},
    }
    _state.save_sessions({key: session})
    absent = _sessions._original_file(config, "dev")
    assert absent is not None
    assert b"profile dev" not in absent
    assert b"profile untouched" in absent

    session["section_backup"]["config"]["original"] = {  # type: ignore[index]
        "exists": True,
        "values": "invalid",
    }
    _state.save_sessions({key: session})
    with pytest.raises(_configs.OperationalError, match="original section values"):
        _sessions._original_file(config, "dev")


def test_logout_exclusions_resolve_saved_target_directory_and_location_forms(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    direct_destination = tmp_path / "direct-destination"
    same_destination = tmp_path / "same-destination"
    location_source = tmp_path / "location-source"
    location_destination = tmp_path / "location-destination"
    config = {
        "targets": {
            "Direct": {
                "source_directory": str(source),
                "destination_directory": str(direct_destination),
                "source_profile": "admin",
                "destination_profile": "agent",
            },
            "Located": {
                "source_location": "source-location",
                "destination_location": "destination-location",
                "source_profile": "admin",
                "destination_profile": "located-agent",
            },
            "Same": {
                "source_directory": str(same_destination),
                "source_profile": "same-agent",
            },
        }
    }

    def aws_directory(location: object) -> Path:
        return {
            "source-location": location_source,
            "destination-location": location_destination,
        }[str(location)]

    with (
        patch("hacksaws._sessions._state.load_config", return_value=config),
        patch("hacksaws._sessions._state.aws_directory", side_effect=aws_directory),
    ):
        assert _sessions.matches_logout_exclusion(
            destination=str(direct_destination),
            profile="agent",
            excluded={"+direct"},
        )
        assert _sessions.matches_logout_exclusion(
            destination=str(location_destination),
            profile="located-agent",
            excluded={"+LOCATED"},
        )
        assert _sessions.matches_logout_exclusion(
            destination=str(same_destination),
            profile="same-agent",
            excluded={"+Same"},
        )

    with patch(
        "hacksaws._sessions._state.load_config",
        side_effect=_configs.OperationalError("configuration unavailable"),
    ):
        assert _sessions.matches_logout_exclusion(
            destination=str(direct_destination),
            profile="agent",
            excluded={"agent"},
        )


def test_assume_second_positional_and_locked_conflicts() -> None:
    parser = _cli._create_parser()
    parsed = parser.parse_args(["assume", "admin", ".", "--role", "AgentSession"])
    _cli._validate_assume(parsed)
    assert parsed.to_profile == "default"
    for arguments in (
        ["assume", "admin", "agent", "--self", "--role", "AgentSession"],
        ["assume", "admin", "agent", "--to-profile", "other", "--role", "AgentSession"],
        ["assume", "admin", "agent", "--target", "Saved"],
    ):
        with pytest.raises(_configs.OperationalError, match="Positional DEST"):
            _cli._validate_assume(parser.parse_args(arguments))


def _mfa_args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "action": "in",
        "profile": "dev",
        "target": None,
        "mfa_code": None,
        "mfa_code_stdin": False,
        "json": False,
        "directory": "~/.aws",
        "aws_account_name": None,
        "to": None,
        "to_directory": None,
        "to_profile": None,
        "boundary": None,
        "role": None,
        "policy": None,
        "external_id": None,
        "account": None,
        "session_name": None,
        "region": None,
        "duration": None,
        "htl": None,
        "mtl": None,
        "stl": None,
        "ecr": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_mfa_prompt_and_stdin_sources_never_require_argv_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_sessions, "is_expanded_login", lambda _args: True)
    monkeypatch.setattr(
        _sessions,
        "mfa_login",
        lambda context: _configs.Result(
            "MFA_LOGIN", f"{context.args.mfa_code_source}:{context.args.mfa_code}"
        ),
    )
    terminal = MagicMock()
    terminal.isatty.return_value = True
    monkeypatch.setattr(_cli.sys, "stdin", terminal)
    monkeypatch.setattr(_cli.getpass, "getpass", lambda _prompt: "123456")
    prompted = _cli._run_mfa(_configs.Context(_mfa_args()))
    assert prompted.message == "prompt:123456"

    monkeypatch.setattr(_cli.sys, "stdin", io.StringIO("654321\n"))
    streamed = _cli._run_mfa(_configs.Context(_mfa_args(mfa_code_stdin=True)))
    assert streamed.message == "stdin:654321"


def test_mfa_argument_stdin_and_prompt_history_retains_only_safe_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "history-home"))
    _state.save_config(_state.default_config())
    monkeypatch.setattr(_sessions, "is_expanded_login", lambda _args: True)
    monkeypatch.setattr(
        _sessions,
        "mfa_login",
        lambda _context: _configs.Result("MFA_LOGIN", "authenticated"),
    )
    terminal = MagicMock()
    terminal.isatty.return_value = True
    canaries = {
        "argument": "111111-ARGUMENT-CANARY",
        "stdin": "222222-STDIN-CANARY",
        "prompt": "333333-PROMPT-CANARY",
    }

    for source, canary in canaries.items():
        args = _mfa_args(
            access_type="mfa",
            mfa_code=canary if source == "argument" else None,
            mfa_code_stdin=source == "stdin",
        )
        handle = _history.begin(json_mode=False, interactive=source == "prompt")
        _history.enrich(handle, args)
        if source == "stdin":
            monkeypatch.setattr(_cli.sys, "stdin", io.StringIO(f"{canary}\n"))
        else:
            monkeypatch.setattr(_cli.sys, "stdin", terminal)
        monkeypatch.setattr(
            _cli.getpass, "getpass", lambda _prompt, value=canary: value
        )
        result = _cli._run_mfa(_configs.Context(args))
        _history.finish(handle, result)

    records = _history.list_records(limit=10)
    safe_sources: set[str] = set()
    for record in records:
        safe = record["safe"]
        assert isinstance(safe, dict)
        safe_source_value = safe.get("mfaCodeSource")
        assert isinstance(safe_source_value, str)
        safe_sources.add(safe_source_value)
    assert safe_sources == {"argument", "stdin", "prompt"}
    raw_history = _history.database_path().read_bytes()
    for canary in canaries.values():
        assert canary.encode() not in raw_history


def test_mfa_rejects_conflicting_or_empty_protected_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(_configs.OperationalError, match="not both"):
        _cli._run_mfa(
            _configs.Context(_mfa_args(mfa_code="123456", mfa_code_stdin=True))
        )
    monkeypatch.setattr(_cli.sys, "stdin", io.StringIO("\n"))
    with pytest.raises(_configs.OperationalError, match="cannot be empty"):
        _cli._run_mfa(_configs.Context(_mfa_args(mfa_code_stdin=True)))
