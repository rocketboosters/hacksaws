"""Post-login reusable configuration save and recovery tests."""

from __future__ import annotations

import argparse
import dataclasses
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import Any
from typing import cast
from unittest.mock import patch

import pytest

from hacksaws import _account_discovery
from hacksaws import _configs
from hacksaws import _session_save
from hacksaws import _sessions
from hacksaws import _state

ACCOUNT = "123456789012"
ROLE_ACCOUNT = "210987654321"
ROLE = f"arn:aws:iam::{ROLE_ACCOUNT}:role/AgentSession"
POLICY = f"arn:aws:iam::{ROLE_ACCOUNT}:policy/hacksaws/ReadOnly"


def _args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "save": False,
        "save_name": "debug",
        "save_source_account": "source",
        "save_role_account": "role",
        "save_boundary": None,
        "save_external_id": False,
        "store_policy_as": None,
        "target": None,
        "boundary": None,
        "role": ROLE,
        "policy": POLICY,
        "external_id": "secret-external-id",
        "duration": "1h",
        "htl": None,
        "mtl": None,
        "stl": None,
        "json": False,
        "description": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _discovery(
    key: str, account_id: str, *, existing: bool = False
) -> _account_discovery.AccountDiscovery:
    identity = _account_discovery.AccountIdentity(
        partition="aws",
        account_id=account_id,
        arn=f"arn:aws:iam::{account_id}:root",
        verified=True,
    )
    record = (
        {
            "id": account_id,
            "partition": "aws",
            "display_name": key,
            "display_source": "user",
        }
        if existing
        else None
    )
    return _account_discovery.AccountDiscovery(
        identity=identity,
        source_identity=identity,
        key=key,
        key_source="existing" if existing else "user",
        display_name=key,
        display_source="user",
        existing=existing,
        _existing_record=record,
    )


def _plan(tmp_path: Path, **overrides: object) -> _session_save.SavePlan:
    source = tmp_path / ".aws-source"
    destination = tmp_path / ".aws-agent"
    return _session_save.prepare(
        _args(**overrides),
        source_directory=source,
        source_profile="admin",
        destination_directory=destination,
        destination_profile="debug",
        region="us-west-2",
    )


def _accounts() -> _session_save.SaveAccounts:
    return _session_save.SaveAccounts(
        source=_discovery("source", ACCOUNT),
        role=_discovery("role", ROLE_ACCOUNT),
    )


def _persist(
    plan: _session_save.SavePlan,
    accounts: _session_save.SaveAccounts,
    session: dict[str, Any],
) -> _session_save.SaveOutcome:
    return _session_save.persist(
        plan,
        accounts,
        session,
        begin=lambda paths: _sessions._begin(paths, kind="session-save"),
        commit=_sessions._commit,
        rollback=_sessions._rollback,
    )


def test_persist_builds_canonical_resources_and_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    plan = _plan(tmp_path)
    session = {
        "role": ROLE,
        "policy_origin": "remote-customer",
        "policy_arn": POLICY,
    }

    first = _persist(plan, _accounts(), session)
    second = _persist(plan, _accounts(), session)

    assert first.changed is True
    assert second.changed is False
    config = _state.load_config()
    assert config["boundaries"]["debug"] == {
        "role_arn": ROLE,
        "account": "role",
        "policy": POLICY,
        "duration": 3600,
        "verified": True,
    }
    assert config["targets"]["debug"] == {
        "source_account": "source",
        "source_profile": "admin",
        "source_directory": str((tmp_path / ".aws-source").absolute()),
        "destination_profile": "debug",
        "destination_directory": str((tmp_path / ".aws-agent").absolute()),
        "boundary": "debug",
        "region": "us-west-2",
    }


def test_external_id_requires_explicit_persistence_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    without = _plan(tmp_path)
    session = {"role": ROLE}
    _persist(without, _accounts(), session)
    assert "external_id" not in _state.load_config()["boundaries"]["debug"]

    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "consented-state"))
    with_consent = _plan(tmp_path, save_external_id=True)
    _persist(with_consent, _accounts(), session)
    assert (
        _state.load_config()["boundaries"]["debug"]["external_id"]
        == "secret-external-id"
    )


def test_local_policy_is_promoted_transactionally_and_preserves_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    policy = tmp_path / "debug.yaml"
    policy.write_text(
        "# keep this comment\nVersion: '2012-10-17'\nStatement: []\n",
        encoding="utf-8",
    )
    plan = _plan(tmp_path, policy=str(policy), store_policy_as="debug-policy")

    outcome = _persist(
        plan,
        _accounts(),
        {"role": ROLE, "policy_origin": "local"},
    )

    assert outcome.policy == "debug-policy"
    stored = tmp_path / "state" / "stored_session_policies" / "debug-policy.yaml"
    assert stored.read_text(encoding="utf-8").startswith("# keep this comment")
    config = _state.load_config()
    assert config["boundaries"]["debug"]["policy"] == "debug-policy"


def test_divergent_name_fails_without_replacing_existing_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    plan = _plan(tmp_path)
    _persist(plan, _accounts(), {"role": ROLE})
    before = (tmp_path / "state" / "config.json").read_bytes()
    divergent = dataclasses.replace(plan, source_profile="different")

    with pytest.raises(_configs.OperationalError, match="different settings"):
        _persist(divergent, _accounts(), {"role": ROLE})

    assert (tmp_path / "state" / "config.json").read_bytes() == before


def test_post_commit_save_failure_returns_partial_success_and_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    plan = _plan(tmp_path)
    destination = plan.destination_directory
    _state.save_sessions(
        {
            f"{destination}::debug": {
                "destination": str(destination),
                "profile": "debug",
                "auth_method": "mfa",
            }
        }
    )
    with patch(
        "hacksaws._sessions._session_save.persist",
        side_effect=_configs.OperationalError("config conflict"),
    ):
        result = _sessions._finish_session_save(
            _configs.Result("MFA_LOGIN", "Logged in."),
            plan=plan,
            accounts=_accounts(),
            discovery_error=None,
            destination=destination,
            profile="debug",
        )

    assert result.code == "PARTIAL_SUCCESS"
    assert result.exit_code == 1
    result_data = cast("dict[str, Any]", result.data)
    assert result_data["credentialsActive"] is True
    assert "--from-session debug" in result_data["save"]["retryCommand"]
    assert _state.load_sessions()[f"{destination}::debug"]["auth_method"] == "mfa"


def test_target_from_session_recovers_and_repeats_as_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    monkeypatch.setenv("HACKSAWS_HOME", str(state))
    destination = tmp_path / ".aws-agent"
    source = tmp_path / ".aws-source"
    expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    _state.save_sessions(
        {
            f"{destination.absolute()}::debug": {
                "destination": str(destination.absolute()),
                "profile": "debug",
                "source_destination": str(source.absolute()),
                "source_profile": "admin",
                "source_account": ACCOUNT,
                "source_partition": "aws",
                "target_account": ROLE_ACCOUNT,
                "target_partition": "aws",
                "role": ROLE,
                "policy_origin": "remote-customer",
                "policy_arn": POLICY,
                "region": "us-west-2",
                "expires_at": expires,
                "auth_method": "mfa",
            }
        }
    )
    args = _args(
        resource_name="debug",
        from_session="debug",
        directory=str(destination),
        location=None,
        save_name=None,
        save=True,
        save_source_account="source",
        save_role_account="role",
        role=None,
        policy=None,
        external_id=None,
        duration=None,
    )

    first = _sessions.save_target_from_session(args)
    second = _sessions.save_target_from_session(args)

    first_data = cast("dict[str, Any]", first.data)
    second_data = cast("dict[str, Any]", second.data)
    assert first_data["changed"] is True
    assert second_data["changed"] is False
    assert _state.load_config()["targets"]["debug"]["boundary"] == "debug"


def test_existing_account_without_region_is_reused_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    config = _state.default_config()
    config["accounts"]["legacy"] = {
        "id": ACCOUNT,
        "partition": "aws",
        "display_name": "legacy",
        "display_source": "user",
    }
    _state.save_config(config)
    plan = _plan(
        tmp_path,
        save_name=None,
        save=False,
        save_source_account=None,
        save_role_account=None,
        role=None,
        policy=None,
        duration=None,
    )
    accounts = _session_save.SaveAccounts(
        source=_discovery("legacy", ACCOUNT, existing=True),
        role=None,
    )

    result = _persist(plan, accounts, {"role": None})

    assert result.changed is False
    assert "region" not in _state.load_config()["accounts"]["legacy"]


def test_locations_are_saved_as_portable_location_endpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The normal and named AWS folders should not become machine-specific paths."""
    monkeypatch.setattr("hacksaws._session_save.Path.home", lambda: tmp_path)

    assert _session_save._logical_location(tmp_path / ".aws") == "default"
    assert _session_save._logical_location(tmp_path / ".aws-horizon") == "horizon"
    assert _session_save._endpoint(
        tmp_path / ".aws-horizon", "admin", prefix="source"
    ) == {"source_profile": "admin", "source_location": "horizon"}


def test_prepare_rejects_invalid_save_combinations_before_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))

    with pytest.raises(_configs.OperationalError, match="require --save"):
        _plan(tmp_path, save=False, save_name=None, save_source_account="source")
    with pytest.raises(_configs.OperationalError, match="requires a role"):
        _plan(tmp_path, role=None, save_boundary="debug")
    with pytest.raises(_configs.OperationalError, match="requires a role"):
        _plan(tmp_path, role=None, save_role_account="role")
    with pytest.raises(_configs.OperationalError, match="requires a role"):
        _plan(tmp_path, role=None, save_role_account=None, save_external_id=True)
    with pytest.raises(_configs.OperationalError, match="only valid"):
        _plan(tmp_path, store_policy_as="stored")
    with pytest.raises(_configs.OperationalError, match="requires a session policy"):
        _plan(tmp_path, policy=None, store_policy_as="stored")


def test_prepare_rejects_conflicting_target_before_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    config = _state.default_config()
    config["accounts"]["source"] = {
        "id": ACCOUNT,
        "partition": "aws",
        "display_name": "source",
        "display_source": "user",
    }
    config["targets"]["debug"] = {
        "source_account": "source",
        "source_profile": "different",
        "source_directory": str((tmp_path / ".aws-source").absolute()),
        "region": "us-west-2",
    }
    _state.save_config(config)

    with pytest.raises(_configs.OperationalError, match="login was not attempted"):
        _plan(tmp_path)


def test_discover_accounts_registers_source_before_resolving_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    source = _discovery("source", ACCOUNT)
    role = _discovery("role", ROLE_ACCOUNT)
    calls: list[tuple[dict[str, Any], str | None]] = []

    def discover(
        _session: object,
        config: dict[str, Any],
        *,
        explicit_name: str | None,
        role_arn: str | None = None,
    ) -> _account_discovery.AccountDiscovery:
        calls.append((config, role_arn))
        return role if role_arn else source

    with patch("hacksaws._session_save._account_discovery.discover_account", discover):
        found = _session_save.discover_accounts(
            _plan(tmp_path),
            cast("_account_discovery.IntermediateSession", object()),
            role_arn=ROLE,
        )

    assert found == _session_save.SaveAccounts(source=source, role=role)
    assert calls[1][0]["accounts"]["source"]["region"] == "us-west-2"
    assert calls[1][1] == ROLE


def test_recovery_account_discovery_validates_lineage_and_name_collisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    plan = _plan(tmp_path)

    with pytest.raises(_configs.OperationalError, match="valid source account"):
        _session_save.accounts_from_session(plan, {"source_account": "broken"})

    config = _state.default_config()
    config["accounts"]["source"] = {
        "id": ROLE_ACCOUNT,
        "partition": "aws",
        "display_name": "source",
        "display_source": "user",
    }
    _state.save_config(config)
    with pytest.raises(_configs.OperationalError, match="different AWS account"):
        _session_save.accounts_from_identity(
            plan,
            source_account=ACCOUNT,
            source_partition="aws",
            role_arn=None,
        )


def test_prepare_and_recovery_use_configured_resources_and_account_id_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    config = _state.default_config()
    config["accounts"]["role"] = {
        "id": ROLE_ACCOUNT,
        "partition": "aws",
        "display_name": "role",
        "display_source": "user",
    }
    config["boundaries"]["agent"] = {
        "role_arn": ROLE,
        "account": "role",
        "duration": 1800,
    }
    config["targets"]["saved"] = {
        "source_account": "role",
        "source_profile": "admin",
        "source_directory": str((tmp_path / ".aws-source").absolute()),
        "boundary": "agent",
        "region": "us-west-2",
    }
    _state.save_config(config)

    prepared = _plan(
        tmp_path,
        target="+saved",
        boundary=None,
        role=None,
        policy=None,
        external_id=None,
        duration=None,
        save_source_account=None,
        save_role_account=None,
    )
    assert prepared.role == ROLE
    assert prepared.duration == 1800
    assert prepared.boundary_name == "debug"

    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "fresh-state"))
    recovered = _session_save.accounts_from_identity(
        _plan(
            tmp_path,
            save_source_account=None,
            save_role_account=None,
        ),
        source_account=ACCOUNT,
        source_partition="aws",
        role_arn=ROLE,
    )
    assert recovered.source.key == f"account-{ACCOUNT}"
    assert recovered.role is not None
    assert recovered.role.key == f"account-{ROLE_ACCOUNT}"


def test_prompt_and_policy_canonicalization_handle_cancel_and_incomplete_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    with (
        patch("builtins.input", side_effect=EOFError),
        pytest.raises(_session_save.SaveCancelled),
    ):
        _session_save._prompt_name("Save", "debug")
    with (
        patch("builtins.input", return_value="q"),
        pytest.raises(_session_save.SaveCancelled),
    ):
        _session_save._prompt_name("Save", "debug")

    assert _session_save._policy_output(
        _plan(tmp_path, policy=None), target_name="debug"
    ) == (
        None,
        None,
        None,
    )
    assert _session_save._policy_output(_plan(tmp_path), target_name="debug") == (
        POLICY,
        None,
        None,
    )
    with pytest.raises(_configs.OperationalError, match="source path was not retained"):
        _session_save._canonical_policy(
            _plan(tmp_path, policy=None),
            {"policy_origin": "local"},
            target_name="debug",
        )
    with pytest.raises(_configs.OperationalError, match="canonical managed-policy ARN"):
        _session_save._canonical_policy(
            _plan(tmp_path), {"policy_origin": "aws-managed"}, target_name="debug"
        )
    assert _session_save._canonical_policy(
        _plan(tmp_path),
        {"policy_origin": "stored", "policy_reference": "saved"},
        target_name="debug",
    ) == ("saved", None, None)


def test_local_policy_prompt_and_noninteractive_safeguard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    policy = tmp_path / "read-only.json"
    policy.write_text('{"Version":"2012-10-17","Statement":[]}', encoding="utf-8")
    plan = _plan(tmp_path, policy=str(policy), store_policy_as=None)

    with pytest.raises(_configs.OperationalError, match="noninteractively"):
        _session_save._policy_output(plan, target_name="debug")
    interactive = dataclasses.replace(plan, interactive=True)
    with patch("builtins.input", return_value="prompted-policy"):
        name, path, encoded = _session_save._policy_output(
            interactive, target_name="debug"
        )

    assert name == "prompted-policy"
    assert path is not None
    assert path.name == "prompted-policy.yaml"
    assert encoded == b"Version: '2012-10-17'\nStatement: []\n"


def test_persist_handles_noninteractive_name_policy_conflict_and_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    bare = _plan(tmp_path, save=True, save_name=None)
    with pytest.raises(_configs.OperationalError, match="noninteractive save"):
        _persist(bare, _accounts(), {"role": ROLE})

    policy = tmp_path / "read.yaml"
    policy.write_text("Version: '2012-10-17'\nStatement: []\n", encoding="utf-8")
    local = _plan(tmp_path, policy=str(policy), store_policy_as="read")
    stored = _state.root() / "stored_session_policies" / "read.yaml"
    stored.parent.mkdir(parents=True, exist_ok=True)
    stored.write_text("Version: '2012-10-17'\nStatement: [{}]\n", encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="different content"):
        _persist(local, _accounts(), {"role": ROLE, "policy_origin": "local"})

    plan = _plan(tmp_path)
    commits: list[str] = []

    def conflict_begin(_paths: list[Path]) -> dict[str, Any]:
        config = _state.default_config()
        config["accounts"]["other"] = {
            "id": "999999999999",
            "partition": "aws",
            "display_name": "other",
            "display_source": "user",
        }
        _state.save_config(config)
        return {}

    with pytest.raises(_session_save.SavePlanChanged, match="changed while"):
        _session_save.persist(
            plan,
            _accounts(),
            {"role": ROLE},
            begin=conflict_begin,
            commit=lambda: commits.append("commit"),
            rollback=lambda _journal: pytest.fail("no write should be rolled back"),
        )
    assert commits == ["commit"]
    assert "other" in _state.load_config()["accounts"]


def test_persist_prompts_for_bare_interactive_save_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    plan = dataclasses.replace(
        _plan(tmp_path, save=True, save_name=None), interactive=True
    )
    with patch("builtins.input", return_value="prompted"):
        outcome = _persist(plan, _accounts(), {"role": ROLE})

    assert outcome.target == "prompted"
    assert "prompted" in _state.load_config()["targets"]


def test_persist_rolls_back_after_a_started_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    policy = tmp_path / "read.yaml"
    policy.write_text("Version: '2012-10-17'\nStatement: []\n", encoding="utf-8")
    plan = _plan(tmp_path, policy=str(policy), store_policy_as="read")
    rollback: list[dict[str, Any]] = []
    with (
        patch(
            "hacksaws._session_save._state.save_config",
            side_effect=OSError("disk full"),
        ),
        pytest.raises(OSError, match="disk full"),
    ):
        _session_save.persist(
            plan,
            _accounts(),
            {"role": ROLE, "policy_origin": "local"},
            begin=lambda _paths: {"journal": "test"},
            commit=lambda: pytest.fail("commit should not run"),
            rollback=rollback.append,
        )
    assert rollback == [{"journal": "test"}]


def test_recovery_plan_outcome_and_retry_command_are_credential_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    session = {
        "destination": str(tmp_path / ".aws-agent"),
        "source_destination": str(tmp_path / ".aws-source"),
        "source_profile": "admin",
        "profile": "debug",
        "role": ROLE,
        "policy_reference": "stored-policy",
        "region": "us-west-2",
    }
    plan = _session_save.recovery_plan(
        _args(policy=None, external_id="recovery-external-id"), session, name="saved"
    )
    assert plan.name == "saved"
    assert plan.policy == "stored-policy"
    assert plan.save_external_id is True
    assert "recovery-external-id" not in _session_save.retry_command(plan)
    assert _session_save.outcome_data(
        _session_save.SaveOutcome(
            target="saved",
            boundary="saved",
            source_account="source",
            role_account="role",
            changed=True,
            policy="stored-policy",
        )
    ) == {
        "accountRegistration": {"created": 0, "reused": 0, "refreshed": 0},
        "bundleRequested": True,
        "bundleSaved": True,
        "bundleChanged": True,
        "changed": True,
        "target": "saved",
        "boundary": "saved",
        "sourceAccount": "source",
        "roleAccount": "role",
        "policy": "stored-policy",
    }


def test_discovery_failure_reports_the_fallback_failure_without_credential_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    plan = _plan(tmp_path)
    discovery_failure = _configs.OperationalError("optional provider unavailable")
    fallback_failure = _configs.OperationalError("account name collision")
    with (
        patch(
            "hacksaws._sessions._session_save.discover_accounts",
            side_effect=discovery_failure,
        ),
        patch(
            "hacksaws._sessions._session_save.accounts_from_identity",
            side_effect=fallback_failure,
        ),
    ):
        accounts, error = _sessions._discover_save_accounts(
            plan,
            object(),
            role=ROLE,
            source_account=ACCOUNT,
            source_partition="aws",
        )

    assert accounts is None
    assert error is fallback_failure


def test_finish_session_save_preserves_active_credentials_on_cancel_or_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    plan = _plan(tmp_path)
    original = _configs.Result("WEB_LOGIN", "Logged in.", data={"source": "web"})
    destination = tmp_path / ".aws-agent"

    for error in (
        _session_save.SaveCancelled("Configuration save cancelled."),
        _configs.OperationalError("policy conflict"),
    ):
        with (
            patch(
                "hacksaws._sessions._persist_committed_session_save", side_effect=error
            ),
            patch("hacksaws._sessions._history.note_session_save") as history,
        ):
            result = _sessions._finish_session_save(
                original,
                plan=plan,
                accounts=_accounts(),
                discovery_error=None,
                destination=destination,
                profile="debug",
            )

        assert result.code == "PARTIAL_SUCCESS"
        assert isinstance(result.data, dict)
        assert result.data["credentialsActive"] is True
        assert "Credentials remain active" in result.message
        assert history.call_args.kwargs["status"] in {"cancelled", "failed"}


def test_finish_session_save_reports_saved_and_noop_suffixes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    plan = _plan(tmp_path)
    original = _configs.Result("MFA_LOGIN", "Logged in.", data={"tier": "mfa"})
    destination = tmp_path / ".aws-agent"

    for changed, expected in (
        (True, "Saved target 'debug'."),
        (False, "already current"),
    ):
        outcome = _session_save.SaveOutcome(
            target="debug",
            boundary="debug",
            source_account="source",
            role_account="role",
            changed=changed,
        )
        with (
            patch(
                "hacksaws._sessions._persist_committed_session_save",
                return_value=outcome,
            ),
            patch("hacksaws._sessions._history.note_session_save") as history,
        ):
            result = _sessions._finish_session_save(
                original,
                plan=plan,
                accounts=_accounts(),
                discovery_error=None,
                destination=destination,
                profile="debug",
            )

        assert expected in result.message
        assert isinstance(result.data, dict)
        saved = result.data["save"]
        assert isinstance(saved, dict)
        assert saved["changed"] is changed
        assert history.call_args.kwargs["status"] == ("saved" if changed else "noop")


def test_finish_without_save_reports_only_account_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    plan = _plan(
        tmp_path,
        save=False,
        save_name=None,
        save_source_account=None,
        save_role_account=None,
        role=None,
        policy=None,
        duration=None,
    )
    original = _configs.Result("WEB_LOGIN", "Logged in.")
    outcome = _session_save.SaveOutcome(
        target=None,
        boundary=None,
        source_account="source",
        role_account=None,
        changed=True,
        bundle_requested=False,
        bundle_changed=False,
        accounts_created=1,
    )
    with (
        patch(
            "hacksaws._sessions._persist_committed_session_save",
            return_value=outcome,
        ),
        patch("hacksaws._sessions._history.note_session_save") as save_history,
        patch(
            "hacksaws._sessions._history.note_account_registration"
        ) as registration_history,
    ):
        result = _sessions._finish_session_save(
            original,
            plan=plan,
            accounts=_accounts(),
            discovery_error=None,
            destination=tmp_path / ".aws-agent",
            profile="debug",
        )

    assert result.message == "Logged in."
    assert result.data == {
        "accountRegistration": {"created": 1, "reused": 0, "refreshed": 0},
        "bundleRequested": False,
        "bundleSaved": False,
    }
    save_history.assert_not_called()
    registration_history.assert_called_once_with(
        status="completed", created=1, reused=0, refreshed=0
    )


def test_committed_save_requires_discovery_accounts_and_live_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    plan = _plan(tmp_path)
    destination = tmp_path / ".aws-agent"
    with pytest.raises(_configs.OperationalError, match="provider failure"):
        _sessions._persist_committed_session_save(
            plan,
            _accounts(),
            _configs.OperationalError("provider failure"),
            destination,
            "debug",
        )
    with pytest.raises(_configs.OperationalError, match="did not produce"):
        _sessions._persist_committed_session_save(
            plan, None, None, destination, "debug"
        )
    with pytest.raises(_configs.OperationalError, match="could not be found"):
        _sessions._persist_committed_session_save(
            plan, _accounts(), None, destination, "debug"
        )


def test_recovery_selector_rejects_missing_ambiguous_and_unusable_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    args = _args(
        resource_name="saved", from_session="debug", directory=None, location=None
    )
    with pytest.raises(_configs.OperationalError, match="No Hacksaws-managed session"):
        _sessions.save_target_from_session(args)

    first = tmp_path / ".aws-first"
    second = tmp_path / ".aws-second"
    _state.save_sessions(
        {
            f"{first.absolute()}::debug": {
                "destination": str(first.absolute()),
                "profile": "debug",
            },
            f"{second.absolute()}::debug": {
                "destination": str(second.absolute()),
                "profile": "debug",
            },
        }
    )
    with pytest.raises(_configs.OperationalError, match="multiple AWS folders"):
        _sessions.save_target_from_session(args)

    selected = _args(
        resource_name="saved", from_session="debug", directory=str(first), location=None
    )
    _state.save_sessions(
        {
            f"{first.absolute()}::debug": {
                "destination": str(first.absolute()),
                "profile": "debug",
                "auth_method": "logout-residue",
            }
        }
    )
    with pytest.raises(
        _configs.OperationalError, match="Managed source session is logout-residue"
    ):
        _sessions.save_target_from_session(selected)


def test_recovery_requires_external_id_and_records_failure_saved_and_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    destination = tmp_path / ".aws-agent"
    session = {
        "destination": str(destination),
        "profile": "debug",
        "auth_method": "mfa",
    }
    _state.save_sessions({f"{destination.absolute()}::debug": session})
    external = _args(
        resource_name="saved",
        from_session="debug",
        directory=str(destination),
        location=None,
        save_external_id=True,
        external_id=None,
    )
    with pytest.raises(_configs.OperationalError, match="recovery-only"):
        _sessions.save_target_from_session(external)

    args = _args(
        resource_name="saved",
        from_session="debug",
        directory=str(destination),
        location=None,
    )
    plan = _plan(tmp_path)
    outcomes = [
        _session_save.SaveOutcome(
            target="saved",
            boundary="saved",
            source_account="source",
            role_account="role",
            changed=True,
        ),
        _session_save.SaveOutcome(
            target="saved",
            boundary="saved",
            source_account="source",
            role_account="role",
            changed=False,
        ),
    ]
    with (
        patch("hacksaws._sessions._session_save.recovery_plan", return_value=plan),
        patch(
            "hacksaws._sessions._session_save.accounts_from_session",
            return_value=_accounts(),
        ),
        patch("hacksaws._sessions._session_save.persist", side_effect=outcomes),
        patch("hacksaws._sessions._history.note_session_save") as history,
    ):
        saved = _sessions.save_target_from_session(args)
        noop = _sessions.save_target_from_session(args)

    assert saved.kind == "success"
    assert noop.kind == "info"
    assert "already matches" in noop.message
    assert [call.kwargs["status"] for call in history.call_args_list] == [
        "saved",
        "noop",
    ]

    with (
        patch("hacksaws._sessions._session_save.recovery_plan", return_value=plan),
        patch(
            "hacksaws._sessions._session_save.accounts_from_session",
            return_value=_accounts(),
        ),
        patch(
            "hacksaws._sessions._session_save.persist",
            side_effect=_configs.OperationalError("different settings"),
        ),
        patch("hacksaws._sessions._history.note_session_save") as history,
        pytest.raises(_configs.OperationalError, match="different settings"),
    ):
        _sessions.save_target_from_session(args)
    assert history.call_args.kwargs["status"] == "failed"
