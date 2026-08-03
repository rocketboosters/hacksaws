"""Plan and persist reusable configuration from successful credential sessions.

The authentication transaction deliberately does not include this module's writes.
Callers prepare before authentication, discover accounts with the intermediate
credentials, commit the credential transaction, and only then call :func:`persist`.
"""

# ruff: noqa: C901, N818, PLR0912, PLR0913, PLR0915, SLF001, TRY003, TRY301

from __future__ import annotations

import copy
import dataclasses
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any

import yaml

from hacksaws import _account_discovery
from hacksaws import _duration
from hacksaws import _policies
from hacksaws import _state
from hacksaws._configs import OperationalError

if TYPE_CHECKING:
    import argparse
    from collections.abc import Callable


class SaveCancelled(OperationalError):
    """Raised after login when an interactive save is declined."""


class SavePlanChanged(OperationalError):
    """Raised when configuration changes between save planning and persistence."""


@dataclasses.dataclass(frozen=True)
class SavePlan:
    """Secret-bearing, in-memory-only plan for an optional post-login save."""

    requested: bool
    name: str | None
    source_directory: Path
    source_profile: str
    destination_directory: Path
    destination_profile: str
    region: str
    source_account_name: str | None
    role_account_name: str | None
    boundary_name: str | None
    save_external_id: bool
    store_policy_as: str | None
    role: str | None
    policy: str | None
    external_id: str | None = dataclasses.field(default=None, repr=False)
    duration: int | None = None
    description: str | None = None
    interactive: bool = False
    config_fingerprint: str | None = dataclasses.field(default=None, repr=False)


@dataclasses.dataclass(frozen=True)
class SaveAccounts:
    """Account discoveries made with the pre-boundary credential tier."""

    source: _account_discovery.AccountDiscovery
    role: _account_discovery.AccountDiscovery | None


@dataclasses.dataclass(frozen=True)
class SaveOutcome:
    """Safe description of one completed configuration save."""

    target: str | None
    boundary: str | None
    source_account: str
    role_account: str | None
    changed: bool
    policy: str | None = None
    bundle_requested: bool = True
    bundle_changed: bool | None = None
    accounts_created: int = 0
    accounts_reused: int = 0
    accounts_refreshed: int = 0


def _fingerprint(path: Path) -> str | None:
    return _state.digest(path.read_bytes()) if path.exists() else None


def _logical_location(directory: Path) -> str | None:
    absolute = directory.expanduser().absolute()
    default = (Path.home() / ".aws").absolute()
    if absolute == default:
        return "default"
    if absolute.parent == Path.home().absolute() and absolute.name.startswith(".aws-"):
        return absolute.name[5:] or None
    return None


def _endpoint(directory: Path, profile: str, *, prefix: str) -> dict[str, str]:
    location = _logical_location(directory)
    result = {f"{prefix}_profile": profile}
    if location is None:
        result[f"{prefix}_directory"] = str(directory.expanduser().absolute())
    else:
        result[f"{prefix}_location"] = location
    return result


def _configured_boundary(
    args: argparse.Namespace, config: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    target: dict[str, Any] = {}
    if getattr(args, "target", None):
        _, configured = _state.get_resource(
            config, "target", str(args.target).lstrip("+")
        )
        target = dict(configured)
    boundary_name = getattr(args, "boundary", None) or target.get("boundary")
    boundary: dict[str, Any] = {}
    if boundary_name:
        _, configured = _state.get_resource(config, "boundary", str(boundary_name))
        boundary = dict(configured)
    return target, boundary


def _requested_duration(
    args: argparse.Namespace, boundary: dict[str, Any]
) -> int | None:
    supplied = any(
        getattr(args, key, None) is not None
        for key in ("duration", "htl", "mtl", "stl")
    )
    if supplied:
        return _duration.session_duration(
            duration=getattr(args, "duration", None),
            htl=getattr(args, "htl", None),
            mtl=getattr(args, "mtl", None),
            stl=getattr(args, "stl", None),
        )
    configured = boundary.get("duration")
    return configured if isinstance(configured, int) else None


def _known_target_conflict(
    config: dict[str, Any], name: str, expected: dict[str, str]
) -> None:
    key = _state._find_key(config["targets"], name)
    if key is None:
        return
    current = config["targets"][key]
    for field, value in expected.items():
        if field in current and current[field] != value:
            raise OperationalError(
                f"Target {key!r} already exists with a different "
                f"{field.replace('_', ' ')}. "
                "Choose another --save name; login was not attempted."
            )


def prepare(
    args: argparse.Namespace,
    *,
    source_directory: Path,
    source_profile: str,
    destination_directory: Path,
    destination_profile: str,
    region: str,
) -> SavePlan:
    """Freeze locally knowable save inputs and reject known conflicts pre-auth."""
    config = _state.load_config()
    requested = bool(getattr(args, "save", False) or getattr(args, "save_name", None))
    advanced = {
        "--save-source-account": getattr(args, "save_source_account", None),
        "--save-role-account": getattr(args, "save_role_account", None),
        "--save-boundary": getattr(args, "save_boundary", None),
        "--save-external-id": getattr(args, "save_external_id", False),
        "--store-policy-as": getattr(args, "store_policy_as", None),
    }
    if any(advanced.values()) and not requested:
        names = ", ".join(name for name, value in advanced.items() if value)
        raise OperationalError(f"{names} require --save or --save-name.")
    name = getattr(args, "save_name", None)
    for value, kind in (
        (name, "target"),
        (getattr(args, "save_source_account", None), "account"),
        (getattr(args, "save_role_account", None), "account"),
        (getattr(args, "save_boundary", None), "boundary"),
        (getattr(args, "store_policy_as", None), "policy"),
    ):
        if value is not None:
            _state.validate_name(str(value), kind=kind)
    _target, boundary = _configured_boundary(args, config)
    role = getattr(args, "role", None) or boundary.get("role_arn")
    policy = getattr(args, "policy", None) or boundary.get("policy")
    external_id = getattr(args, "external_id", None) or boundary.get("external_id")
    boundary_name = getattr(args, "save_boundary", None)
    if requested and role and not boundary_name and name:
        boundary_name = name
    if requested and not role and boundary_name:
        raise OperationalError("--save-boundary requires a role to save.")
    if requested and not role and getattr(args, "save_role_account", None):
        raise OperationalError("--save-role-account requires a role to save.")
    if requested and not role and bool(getattr(args, "save_external_id", False)):
        raise OperationalError("--save-external-id requires a role to save.")
    if requested and name:
        known_target = {
            **_endpoint(source_directory, source_profile, prefix="source"),
            **(
                _endpoint(
                    destination_directory,
                    destination_profile,
                    prefix="destination",
                )
                if (
                    source_directory.absolute() != destination_directory.absolute()
                    or source_profile != destination_profile
                )
                else {}
            ),
            "region": region,
        }
        if boundary_name:
            known_target["boundary"] = str(boundary_name)
        _known_target_conflict(config, str(name), known_target)
    store_policy_as = getattr(args, "store_policy_as", None)
    if store_policy_as and policy and not _looks_local_policy(str(policy)):
        raise OperationalError(
            "--store-policy-as is only valid when the session policy is a local file."
        )
    if store_policy_as and not policy:
        raise OperationalError("--store-policy-as requires a session policy.")
    return SavePlan(
        requested=requested,
        name=str(name) if name else None,
        source_directory=source_directory.expanduser().absolute(),
        source_profile=source_profile,
        destination_directory=destination_directory.expanduser().absolute(),
        destination_profile=destination_profile,
        region=region,
        source_account_name=(
            str(args.save_source_account)
            if getattr(args, "save_source_account", None)
            else None
        ),
        role_account_name=(
            str(args.save_role_account)
            if getattr(args, "save_role_account", None)
            else None
        ),
        boundary_name=str(boundary_name) if boundary_name else None,
        save_external_id=bool(getattr(args, "save_external_id", False)),
        store_policy_as=str(store_policy_as) if store_policy_as else None,
        role=str(role) if role else None,
        policy=str(policy) if policy else None,
        external_id=str(external_id) if external_id else None,
        duration=_requested_duration(args, boundary),
        description=(
            str(args.description) if getattr(args, "description", None) else None
        ),
        interactive=not bool(getattr(args, "json", False)) and sys.stdin.isatty(),
        config_fingerprint=_fingerprint(_state.root() / "config.json"),
    )


def _looks_local_policy(value: str) -> bool:
    if _policies.POLICY_ARN.fullmatch(value):
        return False
    candidate = Path(value).expanduser()
    return (
        value == "-"
        or value.startswith((".", "~", "/", "\\"))
        or "/" in value
        or "\\" in value
        or candidate.suffix.casefold() in _policies.PATH_SUFFIXES
    )


def discover_accounts(
    plan: SavePlan,
    session: _account_discovery.IntermediateSession,
    *,
    role_arn: str | None,
) -> SaveAccounts:
    """Discover source and optional role accounts with the intermediate session."""
    config = _state.load_config()
    source = _account_discovery.discover_account(
        session,
        config,
        explicit_name=plan.source_account_name,
    )
    role = None
    if role_arn:
        role_config = copy.deepcopy(config)
        source_record = source.account_record(verified=True)
        if not source.existing:
            source_record.setdefault("region", plan.region)
        role_config["accounts"].setdefault(source.key, source_record)
        role = _account_discovery.discover_account(
            session,
            role_config,
            explicit_name=plan.role_account_name,
            role_arn=role_arn,
        )
    return SaveAccounts(source=source, role=role)


def _session_discovery(
    config: dict[str, Any],
    *,
    account_id: str,
    partition: str,
    explicit_name: str | None,
) -> _account_discovery.AccountDiscovery:
    existing = next(
        (
            (name, value)
            for name, value in config["accounts"].items()
            if value.get("id") == account_id and value.get("partition") == partition
        ),
        None,
    )
    if existing:
        key = existing[0]
        source = "existing"
    elif explicit_name:
        collision = _state._find_key(config["accounts"], explicit_name)
        if collision is not None:
            value = config["accounts"][collision]
            if value.get("id") != account_id or value.get("partition") != partition:
                raise OperationalError(
                    f"Account {collision!r} already refers to a different AWS account."
                )
        key = collision or explicit_name
        source = "existing" if collision else "user"
    else:
        key = f"account-{account_id}"
        source = "account-id"
    record = config["accounts"].get(key, {})
    display = str(record.get("display_name") or key)
    display_source = str(record.get("display_source") or source)
    identity = _account_discovery.AccountIdentity(
        partition=partition,
        account_id=account_id,
        arn=f"arn:{partition}:iam::{account_id}:root",
        verified=True,
    )
    return _account_discovery.AccountDiscovery(
        identity=identity,
        source_identity=identity,
        key=key,
        key_source=source,  # type: ignore[arg-type]
        display_name=display,
        display_source=display_source,  # type: ignore[arg-type]
        existing=bool(record),
        _existing_record=record or None,
    )


def accounts_from_session(plan: SavePlan, session: dict[str, Any]) -> SaveAccounts:
    """Reconstruct account discoveries from verified managed-session lineage."""
    config = _state.load_config()
    source_id = str(session.get("source_account") or "")
    source_partition = str(session.get("source_partition") or "")
    if (
        not re.fullmatch(r"\d{12}", source_id)
        or source_partition not in _state.PARTITIONS
    ):
        raise OperationalError(
            "Managed session lacks a valid source account and partition."
        )
    source = _session_discovery(
        config,
        account_id=source_id,
        partition=source_partition,
        explicit_name=plan.source_account_name,
    )
    role = None
    role_arn = session.get("role")
    if isinstance(role_arn, str) and role_arn:
        role_partition, role_account, _resource = _state.parse_role_arn(role_arn)
        role_config = copy.deepcopy(config)
        source_record = source.account_record(verified=True)
        if not source.existing:
            source_record.setdefault("region", plan.region)
        role_config["accounts"].setdefault(source.key, source_record)
        role = _session_discovery(
            role_config,
            account_id=role_account,
            partition=role_partition,
            explicit_name=plan.role_account_name,
        )
    return SaveAccounts(source=source, role=role)


def accounts_from_identity(
    plan: SavePlan,
    *,
    source_account: str,
    source_partition: str,
    role_arn: str | None,
) -> SaveAccounts:
    """Build deterministic account records when optional discovery is unavailable."""
    config = _state.load_config()
    source = _session_discovery(
        config,
        account_id=source_account,
        partition=source_partition,
        explicit_name=plan.source_account_name,
    )
    role = None
    if role_arn:
        role_partition, role_account, _resource = _state.parse_role_arn(role_arn)
        role_config = copy.deepcopy(config)
        source_record = source.account_record(verified=True)
        if not source.existing:
            source_record.setdefault("region", plan.region)
        role_config["accounts"].setdefault(source.key, source_record)
        role = _session_discovery(
            role_config,
            account_id=role_account,
            partition=role_partition,
            explicit_name=plan.role_account_name,
        )
    return SaveAccounts(source=source, role=role)


def _prompt_name(prompt: str, default: str) -> str:
    try:
        value = input(f"{prompt} [{default}]: ").strip()
    except (EOFError, KeyboardInterrupt) as error:
        raise SaveCancelled("Configuration save cancelled.") from error
    if value.casefold() in {"cancel", "quit", "q"}:
        raise SaveCancelled("Configuration save cancelled.")
    return _state.validate_name(value or default)


def _policy_output(
    plan: SavePlan, *, target_name: str
) -> tuple[str | None, Path | None, bytes | None]:
    policy = plan.policy
    if not policy:
        return None, None, None
    if not _looks_local_policy(policy):
        return policy, None, None
    source = Path(policy).expanduser().absolute()
    document, raw = _policies.parse_policy(source)
    stored_name = plan.store_policy_as
    if stored_name is None:
        if not plan.interactive:
            raise OperationalError(
                "Saving a local session policy noninteractively requires "
                "--store-policy-as NAME."
            )
        stem = re.sub(r"[^A-Za-z0-9._-]+", "-", source.stem).strip("-._")
        default = (stem or f"{target_name}-policy")[:64]
        if not default[0].isalnum():
            default = f"policy-{default}"[:64]
        stored_name = _prompt_name("Stored policy name", default)
    _state.validate_name(stored_name, kind="policy")
    encoded = (
        raw
        if source.suffix.casefold() in {".yaml", ".yml"}
        else yaml.safe_dump(document, sort_keys=False).encode()
    )
    return stored_name, _policies.stored_directory() / f"{stored_name}.yaml", encoded


def _canonical_policy(
    plan: SavePlan,
    session: dict[str, Any],
    *,
    target_name: str,
) -> tuple[str | None, Path | None, bytes | None]:
    origin = session.get("policy_origin")
    if origin == "local" or (plan.policy and _looks_local_policy(plan.policy)):
        if not plan.policy:
            raise OperationalError(
                "The managed session used a local policy whose source path was not "
                "retained; supply --policy FILE and --store-policy-as NAME."
            )
        return _policy_output(plan, target_name=target_name)
    if origin in {"aws-managed", "remote-customer"}:
        arn = session.get("policy_arn")
        if not isinstance(arn, str) or not _policies.POLICY_ARN.fullmatch(arn):
            raise OperationalError(
                "The active session lacks a canonical managed-policy ARN; retry the "
                "save with `target add --from-session` after supplying the policy."
            )
        return arn, None, None
    if origin == "stored":
        reference = session.get("policy_reference") or session.get("policy")
        if isinstance(reference, str):
            return reference, None, None
    return None, None, None


def _add_exact(
    data: dict[str, Any], kind: str, name: str, value: dict[str, Any]
) -> bool:
    collection = data[_state.collection_name(kind)]
    existing = _state._find_key(collection, name)
    if existing is None:
        collection[name] = value
        return True
    if collection[existing] != value:
        raise OperationalError(
            f"{kind.title()} {existing!r} already exists with different settings; "
            "the active credentials were left unchanged."
        )
    return False


def _account_values(
    discovery: _account_discovery.AccountDiscovery, *, region: str, verified: bool
) -> tuple[str, dict[str, Any]]:
    record = copy.deepcopy(discovery.account_record(verified=verified))
    if not discovery.existing:
        record.setdefault("region", region)
    return discovery.key, record


def persist(
    plan: SavePlan,
    accounts: SaveAccounts,
    session: dict[str, Any],
    *,
    begin: Callable[[list[Path]], dict[str, Any]],
    commit: Callable[[], None],
    rollback: Callable[[dict[str, Any]], None],
) -> SaveOutcome:
    """Persist account plus optional boundary/target after credentials are active."""
    target_name = plan.name
    if plan.requested and target_name is None:
        if not plan.interactive:
            raise OperationalError("A noninteractive save requires --save=NAME.")
        target_name = _prompt_name("Saved target name", plan.destination_profile)
    source_name, source_record = _account_values(
        accounts.source, region=plan.region, verified=True
    )
    role_name: str | None = None
    role_record: dict[str, Any] | None = None
    if accounts.role is not None:
        role_name, role_record = _account_values(
            accounts.role, region=plan.region, verified=True
        )

    policy_reference: str | None = None
    policy_path: Path | None = None
    policy_bytes: bytes | None = None
    if plan.requested and target_name and session.get("role"):
        policy_reference, policy_path, policy_bytes = _canonical_policy(
            plan, session, target_name=target_name
        )
    config_path = _state.root() / "config.json"
    current_fingerprint = _fingerprint(config_path)
    data = _state.load_config()
    changed = False
    account_results: dict[str, bool] = {}
    account_results[source_name.casefold()] = _add_exact(
        data, "account", source_name, source_record
    )
    changed |= account_results[source_name.casefold()]
    if role_name and role_record:
        role_key = role_name.casefold()
        if role_key not in account_results:
            account_results[role_key] = _add_exact(
                data, "account", role_name, role_record
            )
            changed |= account_results[role_key]

    boundary_name = plan.boundary_name
    bundle_changed = False
    if plan.requested and target_name and session.get("role"):
        boundary_name = boundary_name or target_name
        boundary = {
            "role_arn": str(session["role"]),
            "account": role_name or source_name,
            **({"policy": policy_reference} if policy_reference else {}),
            **({"duration": plan.duration} if plan.duration is not None else {}),
            **(
                {"external_id": plan.external_id}
                if plan.save_external_id and plan.external_id
                else {}
            ),
            "verified": True,
        }
        boundary_changed = _add_exact(data, "boundary", boundary_name, boundary)
        bundle_changed |= boundary_changed
        changed |= boundary_changed
    if plan.requested and target_name:
        target = {
            "source_account": source_name,
            **_endpoint(plan.source_directory, plan.source_profile, prefix="source"),
            **(
                _endpoint(
                    plan.destination_directory,
                    plan.destination_profile,
                    prefix="destination",
                )
                if (
                    plan.source_directory != plan.destination_directory
                    or plan.source_profile != plan.destination_profile
                )
                else {}
            ),
            **({"boundary": boundary_name} if boundary_name else {}),
            **({"description": plan.description} if plan.description else {}),
            "region": plan.region,
        }
        target_changed = _add_exact(data, "target", target_name, target)
        bundle_changed |= target_changed
        changed |= target_changed
    if policy_path is not None and policy_bytes is not None and policy_reference:
        policy_value = {"file": f"stored_session_policies/{policy_reference}.yaml"}
        policy_changed = _add_exact(data, "policy", policy_reference, policy_value)
        bundle_changed |= policy_changed
        changed |= policy_changed
        if policy_path.exists() and policy_path.read_bytes() != policy_bytes:
            raise OperationalError(
                f"Stored policy {policy_reference!r} already exists with different "
                "content; the active credentials were left unchanged."
            )

    _state._validate_config(data)
    if not changed and (policy_path is None or policy_path.exists()):
        return SaveOutcome(
            target=target_name,
            boundary=boundary_name,
            source_account=source_name,
            role_account=role_name,
            policy=policy_reference,
            changed=False,
            bundle_requested=plan.requested,
            bundle_changed=False,
            accounts_created=sum(account_results.values()),
            accounts_reused=len(account_results) - sum(account_results.values()),
        )
    paths = [config_path, *([policy_path] if policy_path is not None else [])]
    journal = begin(paths)
    write_started = False
    try:
        if _fingerprint(config_path) != current_fingerprint:
            commit()
            raise SavePlanChanged(
                "Hacksaws configuration changed while the session save was being "
                "prepared; active credentials were left unchanged."
            )
        if policy_path is not None and policy_bytes is not None:
            write_started = True
            _state.atomic_write(policy_path, policy_bytes)
        write_started = True
        _state.save_config(data)
        commit()
    except Exception:
        if write_started:
            rollback(journal)
        raise
    return SaveOutcome(
        target=target_name,
        boundary=boundary_name,
        source_account=source_name,
        role_account=role_name,
        policy=policy_reference,
        changed=True,
        bundle_requested=plan.requested,
        bundle_changed=bundle_changed,
        accounts_created=sum(account_results.values()),
        accounts_reused=len(account_results) - sum(account_results.values()),
    )


def recovery_plan(
    args: argparse.Namespace, session: dict[str, Any], *, name: str
) -> SavePlan:
    """Build a post-login save plan from secret-free managed-session metadata."""
    destination = Path(str(session["destination"])).expanduser().absolute()
    source = Path(str(session.get("source_destination") or destination)).absolute()
    source_profile = str(
        session.get("source_profile") or session.get("profile") or "default"
    )
    destination_profile = str(session.get("profile") or "default")
    role = session.get("role")
    policy = getattr(args, "policy", None) or session.get("policy_reference")
    external_id = getattr(args, "external_id", None)
    namespace = copy.copy(args)
    namespace.save = True
    namespace.save_name = name
    namespace.role = role
    namespace.policy = policy
    namespace.external_id = external_id
    namespace.save_external_id = bool(external_id)
    namespace.profile = source_profile
    namespace.duration = getattr(args, "duration", None)
    namespace.htl = getattr(args, "htl", None)
    namespace.mtl = getattr(args, "mtl", None)
    namespace.stl = getattr(args, "stl", None)
    namespace.target = None
    namespace.boundary = None
    return prepare(
        namespace,
        source_directory=source,
        source_profile=source_profile,
        destination_directory=destination,
        destination_profile=destination_profile,
        region=str(session.get("region") or "us-east-1"),
    )


def outcome_data(outcome: SaveOutcome) -> dict[str, Any]:
    """Return the documented, credential-free save result payload."""
    bundle_changed = (
        outcome.changed if outcome.bundle_changed is None else outcome.bundle_changed
    )
    return {
        "accountRegistration": {
            "created": outcome.accounts_created,
            "reused": outcome.accounts_reused,
            "refreshed": outcome.accounts_refreshed,
        },
        "bundleRequested": outcome.bundle_requested,
        "bundleSaved": outcome.bundle_requested,
        "bundleChanged": bundle_changed if outcome.bundle_requested else False,
        "changed": outcome.changed,
        "target": outcome.target,
        "boundary": outcome.boundary,
        "sourceAccount": outcome.source_account,
        "roleAccount": outcome.role_account,
        "policy": outcome.policy,
    }


def retry_command(plan: SavePlan) -> str:
    """Return a credential-free recovery command for a partial save."""
    name = plan.name or "NAME"
    location = _logical_location(plan.destination_directory)
    selector = (
        f" --location {location}"
        if location is not None
        else f' --directory "{plan.destination_directory}"'
    )
    return (
        f"hacksaws target add {name} --from-session {plan.destination_profile}"
        f"{selector}"
    )
