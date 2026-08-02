"""Transactional MFA/browser login, boundary, logout, and portability workflows."""

from __future__ import annotations

import base64
import configparser
import copy
import dataclasses
import fnmatch
import getpass
import importlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import uuid
import zipfile
from contextlib import contextmanager
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any
from typing import NoReturn
from typing import cast

import boto3
import yaml
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from hacksaws import _configs
from hacksaws import _duration
from hacksaws import _ecr
from hacksaws import _policies
from hacksaws import _state

if TYPE_CHECKING:
    from collections.abc import Iterator

_AWS_VERSION = re.compile(r"aws-cli/(\d+)\.(\d+)\.(\d+)")
_CONFLICTING_ENV = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_LOGIN_CACHE_DIRECTORY",
}


class AssumePlanChanged(_configs.OperationalError):
    """Raised when local state no longer matches a confirmed AssumeRole preview."""


@dataclasses.dataclass
class AssumeRolePlan:
    """Opaque prepared AssumeRole operation; callers may expose only its preview."""

    _data: dict[str, Any] = dataclasses.field(repr=False)
    _arguments_fingerprint: str = dataclasses.field(repr=False)
    _consumed: bool = dataclasses.field(default=False, repr=False)


def is_expanded_login(args: Any) -> bool:
    """Return whether an invocation needs the v0.4 transaction path."""
    return any(
        getattr(args, name, None)
        for name in (
            "target",
            "to",
            "to_directory",
            "to_profile",
            "boundary",
            "role",
            "policy",
            "external_id",
            "account",
            "session_name",
            "region",
            "duration",
            "htl",
            "mtl",
            "stl",
        )
    )


def _journal_path() -> Path:
    return _state.root() / "transaction.json"


def _snapshot(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "exists": False}
    stat = path.stat()
    return {
        "path": str(path),
        "exists": True,
        "data": base64.b64encode(path.read_bytes()).decode(),
        "mode": stat.st_mode,
        "mtime_ns": stat.st_mtime_ns,
    }


def _restore(snapshot: dict[str, Any]) -> None:
    path = Path(snapshot["path"])
    if snapshot["exists"]:
        _state.atomic_write(path, base64.b64decode(snapshot["data"]))
        if "mode" in snapshot:
            path.chmod(snapshot["mode"])
        if "mtime_ns" in snapshot:
            os.utime(path, ns=(snapshot["mtime_ns"], snapshot["mtime_ns"]))
    else:
        path.unlink(missing_ok=True)


def _begin(paths: list[Path]) -> dict[str, Any]:
    journal = {
        "schema_version": 1,
        "started_at": _state.iso_now(),
        "files": [_snapshot(path) for path in paths],
        "safe_to_rollback": True,
        "ecr_created": [],
        "browser_cache_claims": [],
    }
    _state.atomic_write(
        _journal_path(), (json.dumps(journal, indent=2) + "\n").encode()
    )
    return journal


def _record_ecr_in_journal(journal: dict[str, Any], engine: str, registry: str) -> None:
    """Persist each ECR side effect immediately for crash recovery."""
    journal["ecr_engine"] = engine
    journal.setdefault("ecr_created", []).append(registry)
    _state.atomic_write(
        _journal_path(), (json.dumps(journal, indent=2) + "\n").encode()
    )


def _rollback(journal: dict[str, Any]) -> None:
    failures: list[str] = []
    engine = journal.get("ecr_engine")
    if engine:
        for registry in reversed(journal.get("ecr_created", [])):
            try:
                _ecr._run_container_engine(
                    engine, [engine, "logout", registry], check=False
                )
            except _configs.OperationalError as error:
                failures.append(f"ECR {registry}: {error}")
    for claim in journal.get("browser_cache_claims", []):
        try:
            _remove_browser_cache_claim(claim, strict=True)
        except _configs.OperationalError as error:
            failures.append(str(error))
    for snapshot in reversed(journal["files"]):
        try:
            _restore(snapshot)
        except OSError as error:
            failures.append(f"{snapshot['path']}: {error}")
    if failures:
        raise _configs.OperationalError(
            "Login failed and automatic recovery was incomplete. Restore these files "
            f"from {_journal_path()}: {'; '.join(failures)}"
        )
    _journal_path().unlink(missing_ok=True)


def recover_journal() -> None:
    """Roll back a safely recoverable interrupted transaction before every command."""
    path = _journal_path()
    if not path.exists():
        return
    try:
        journal = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise _configs.OperationalError(
            f"An unreadable transaction journal remains at {path}; preserve it and restore affected AWS files manually: {error}"
        ) from error
    if journal.get("kind") == "assume-role":
        _recover_assume_journal(journal)
        return
    if not journal.get("safe_to_rollback") or not isinstance(
        journal.get("files"), list
    ):
        raise _configs.OperationalError(
            f"Transaction recovery is unsafe; inspect {path} and restore AWS files manually."
        )
    _rollback(journal)


def _commit() -> None:
    _journal_path().unlink(missing_ok=True)


def _canonical_path(path: Path) -> Path:
    """Return one stable absolute path without requiring the target to exist."""
    return path.expanduser().resolve(strict=False)


def _lineage_hash(value: str) -> str:
    """Hash a normalized, high-entropy lineage component without retaining it."""
    return _state.digest(value.strip().encode("utf-8"))


def _dpop_generation_hash(value: str) -> str:
    """Hash the DER payload so PEM whitespace cannot create a false generation."""
    payload = "".join(
        line.strip()
        for line in value.splitlines()
        if not line.strip().startswith("-----BEGIN")
        and not line.strip().startswith("-----END")
    )
    return _lineage_hash(payload)


def _login_session_value(config: Path, profile: str) -> str:
    parser = _read_ini(config)
    section = _section(profile, config=True)
    value = parser.get(section, "login_session", fallback="").strip()
    if not value:
        raise _configs.OperationalError(
            f"Browser profile {profile!r} has no login_session after AWS login."
        )
    return value


def _browser_cache_lineage(
    config: Path,
    profile: str,
    root: Path,
    *,
    identity: tuple[str, str, str] | None = None,
) -> dict[str, Any]:
    """Describe one AWS login cache generation without retaining token material."""
    canonical_root = _canonical_path(root)
    login_session = _login_session_value(config, profile)
    cache_key = _state.digest(login_session.encode("utf-8"))
    path = _canonical_path(canonical_root / f"{cache_key}.json")
    if path.parent != canonical_root:
        raise _configs.OperationalError("Derived browser cache path escaped its root.")
    content = _browser_cache_content_lineage(path, identity=identity)
    return {
        "schema_version": 1,
        "root": str(canonical_root),
        "path": str(path),
        "cache_key": cache_key,
        "login_session_hash": _lineage_hash(login_session),
        **content,
    }


def _browser_cache_content_lineage(
    path: Path, *, identity: tuple[str, str, str] | None = None
) -> dict[str, Any]:
    """Read stable generation fields from one already-derived cache path."""
    try:
        raw = path.read_bytes()
        token = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise _configs.OperationalError(
            f"Unable to read the derived AWS browser login cache {path}: {error}"
        ) from error
    if not isinstance(token, dict):
        raise _configs.OperationalError("AWS browser login cache is not a JSON object.")
    client_id = token.get("clientId")
    dpop_key = token.get("dpopKey")
    access_token = token.get("accessToken")
    if (
        not isinstance(client_id, str)
        or not isinstance(dpop_key, str)
        or not isinstance(access_token, dict)
    ):
        raise _configs.OperationalError(
            "AWS browser login cache is missing stable lineage fields."
        )
    token_account = str(access_token.get("accountId", "")).strip()
    if identity is None:
        account = token_account
        partition = ""
        principal = ""
    else:
        account, partition, principal = identity
        if token_account and token_account != account:
            raise _configs.OperationalError(
                "AWS browser cache account does not match GetCallerIdentity."
            )
    return {
        "client_id_hash": _lineage_hash(client_id),
        "dpop_generation_hash": _dpop_generation_hash(dpop_key),
        "account": account,
        "partition": partition,
        "principal": principal,
        "whole_digest": _state.digest(raw),
    }


_BROWSER_STABLE_LINEAGE = (
    "root",
    "path",
    "cache_key",
    "login_session_hash",
    "client_id_hash",
    "dpop_generation_hash",
)


def _same_browser_lineage(expected: dict[str, Any], current: dict[str, Any]) -> bool:
    return all(expected.get(key) == current.get(key) for key in _BROWSER_STABLE_LINEAGE)


def _record_browser_cache_claim(
    journal: dict[str, Any], lineage: dict[str, Any], config: Path, profile: str
) -> None:
    claim = {
        **lineage,
        "config": str(_canonical_path(config)),
        "profile": profile,
    }
    journal.setdefault("browser_cache_claims", []).append(claim)
    _state.atomic_write(
        _journal_path(), (json.dumps(journal, indent=2) + "\n").encode()
    )


def _current_browser_cache_claim(claim: dict[str, Any]) -> dict[str, Any]:
    identity = None
    if all(claim.get(key) for key in ("account", "partition", "principal")):
        identity = (
            str(claim["account"]),
            str(claim["partition"]),
            str(claim["principal"]),
        )
    return _browser_cache_lineage(
        Path(str(claim["config"])),
        str(claim["profile"]),
        Path(str(claim["root"])),
        identity=identity,
    )


def _current_browser_cache_content(claim: dict[str, Any]) -> dict[str, Any]:
    """Re-read a claimed file after its profile config may have been removed."""
    path = _canonical_path(Path(str(claim["path"])))
    identity = None
    if all(claim.get(key) for key in ("account", "partition", "principal")):
        identity = (
            str(claim["account"]),
            str(claim["partition"]),
            str(claim["principal"]),
        )
    return {
        **{key: claim.get(key) for key in _BROWSER_STABLE_LINEAGE[:4]},
        **_browser_cache_content_lineage(path, identity=identity),
    }


def _remove_browser_cache_claim(
    claim: dict[str, Any], *, strict: bool
) -> dict[str, str] | None:
    path = _canonical_path(Path(str(claim["path"])))
    if not path.exists():
        return None
    try:
        current = _current_browser_cache_claim(claim)
    except _configs.OperationalError as error:
        if strict:
            raise
        return {"path": str(path), "reason": str(error)}
    if not _same_browser_lineage(claim, current):
        reason = "browser cache belongs to a different login generation"
        if strict:
            raise _configs.OperationalError(f"{reason}: {path}")
        return {"path": str(path), "reason": reason}
    expected_digest = current.get("whole_digest")
    try:
        if _state.digest(path.read_bytes()) != expected_digest:
            raise _configs.OperationalError(
                f"Browser cache changed during compare-and-delete: {path}"
            )
        path.unlink()
    except OSError as error:
        if strict:
            raise _configs.OperationalError(
                f"Unable to remove browser cache {path}: {error}"
            ) from error
        return {"path": str(path), "reason": f"remove failed: {error}"}
    return None


def _read_ini(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    if path.exists():
        try:
            parser.read(path, encoding="utf-8")
        except (OSError, configparser.Error) as error:
            raise _configs.OperationalError(
                f"Unable to parse AWS file {path}: {error}"
            ) from error
    return parser


def _write_ini(path: Path, parser: configparser.ConfigParser) -> None:
    import io

    stream = io.StringIO()
    parser.write(stream)
    _state.atomic_write(path, stream.getvalue().encode())


def _section(profile: str, *, config: bool) -> str:
    return profile if not config or profile == "default" else f"profile {profile}"


def _section_values(
    parser: configparser.ConfigParser, section: str
) -> dict[str, str] | None:
    if section not in parser:
        return None
    return dict(parser[section].items())


def _section_fingerprint(values: dict[str, str] | None) -> str:
    if values is None:
        return _state.digest(b"hacksaws:absent-section")
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    return _state.digest(encoded)


def _section_state(path: Path, section: str) -> dict[str, Any]:
    values = _section_values(_read_ini(path), section)
    return {
        "exists": values is not None,
        "fingerprint": _section_fingerprint(values),
    }


def _snapshot_bytes(journal: dict[str, Any], path: Path) -> bytes | None:
    absolute = path.absolute()
    for snapshot in journal.get("files", []):
        if Path(str(snapshot.get("path", ""))).absolute() != absolute:
            continue
        if not snapshot.get("exists"):
            return None
        return base64.b64decode(str(snapshot["data"]))
    return path.read_bytes() if path.exists() else None


def _section_backup(
    destination: Path,
    profile: str,
    journal: dict[str, Any],
    previous: dict[str, Any] | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    previous_sections = previous.get("section_backup", {}) if previous else {}
    for kind, filename, is_config in (
        ("credentials", "credentials", False),
        ("config", "config", True),
    ):
        path = destination / filename
        section = _section(profile, config=is_config)
        previous_item = previous_sections.get(kind)
        if isinstance(previous_item, dict) and isinstance(
            previous_item.get("original"), dict
        ):
            original = copy.deepcopy(previous_item["original"])
        else:
            original_parser = _parser_from_bytes(_snapshot_bytes(journal, path), path)
            original_values = _section_values(original_parser, section)
            original = {
                "exists": original_values is not None,
                "values": original_values or {},
            }
        result[kind] = {
            "path": str(path.absolute()),
            "section": section,
            "original": original,
            "installed": _section_state(path, section),
        }
    return result


def _partition(arn: str) -> str:
    parts = arn.split(":", 2)
    if len(parts) < 2 or parts[0] != "arn" or parts[1] not in _state.PARTITIONS:
        raise _configs.OperationalError(f"AWS returned an invalid ARN {arn!r}.")
    return parts[1]


def _identity(session: Any, *, label: str) -> tuple[str, str, str]:
    try:
        response = session.client("sts").get_caller_identity()
        account = str(response["Account"])
        arn = str(response["Arn"])
    except (BotoCoreError, ClientError, KeyError) as error:
        raise _configs.OperationalError(
            f"Unable to verify {label} with GetCallerIdentity: {error}"
        ) from error
    if not re.fullmatch(r"\d{12}", account):
        raise _configs.OperationalError(
            f"AWS returned invalid account {account!r} for {label}."
        )
    return account, _partition(arn), arn


def _paths(args: Any) -> tuple[Path, str, Path, str]:
    """Resolve secure preset or raw source/destination."""
    if getattr(args, "target", None):
        data = _state.load_config()
        target_name = args.target.lstrip("+")
        _, target = _state.get_resource(data, "target", target_name)
        source_dir = (
            Path(target["source_directory"])
            if target.get("source_directory")
            else _state.aws_directory(target.get("source_location"))
        )
        source_profile = _normalize_profile(target.get("source_profile"))
        if target.get("destination_directory"):
            destination_dir = Path(target["destination_directory"])
        elif target.get("destination_location"):
            destination_dir = _state.aws_directory(target["destination_location"])
        else:
            destination_dir = source_dir
        destination_profile = _normalize_profile(
            target.get("destination_profile", source_profile)
        )
        return source_dir, source_profile, destination_dir, destination_profile
    source = Path(args.directory).expanduser().absolute()
    profile = _normalize_profile(args.profile)
    if getattr(args, "aws_account_name", None):
        source = _state.aws_directory(args.aws_account_name)
    if getattr(args, "to", None):
        location, separator, destination_profile = args.to.partition(":")
        if not separator or not destination_profile:
            raise _configs.OperationalError("--to must be LOCATION:PROFILE.")
        return (
            source,
            profile,
            _state.aws_directory(location),
            _normalize_profile(destination_profile),
        )
    if getattr(args, "to_directory", None):
        return (
            source,
            profile,
            Path(args.to_directory).expanduser().absolute(),
            _normalize_profile(args.to_profile),
        )
    return source, profile, source, profile


def _normalize_profile(value: object) -> str:
    return "default" if value in {None, ".", "default"} else str(value)


def _target_details(args: Any, source_account: str, partition: str) -> dict[str, Any]:
    data = _state.load_config()
    target: dict[str, Any] = {}
    if args.target:
        target_name, target = _state.get_resource(
            data, "target", args.target.lstrip("+")
        )
        target = dict(target)
        target["target_name"] = target_name
        account_name, account = _state.get_resource(
            data, "account", str(target["source_account"])
        )
        if account["id"] != source_account or account["partition"] != partition:
            raise _configs.OperationalError(
                f"Source identity is {partition}:{source_account}, but target {target_name!r} requires {account['partition']}:{account['id']}."
            )
    boundary_name = args.boundary or target.get("boundary")
    if boundary_name:
        canonical, boundary = _state.get_resource(data, "boundary", boundary_name)
        target["boundary_name"] = canonical
        target["boundary_data"] = boundary
    return target


def _role_details(
    args: Any, target: dict[str, Any], source_account: str, partition: str
) -> tuple[str | None, str | None, str | None, str | None]:
    boundary = target.get("boundary_data", {})
    role = args.role or boundary.get("role_arn")
    policy = args.policy or boundary.get("policy")
    external_id = args.external_id or boundary.get("external_id")
    account_name = args.account
    if role and not str(role).startswith("arn:"):
        account_id = source_account
        role_partition = partition
        if account_name:
            account_id, role_partition = _role_account_assertion(
                str(account_name), partition
            )
        role = f"arn:{role_partition}:iam::{account_id}:role/{role}"
    if role:
        match = re.fullmatch(
            r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/(.+)", str(role)
        )
        if not match:
            raise _configs.OperationalError(f"Invalid role ARN {role!r}.")
        if account_name:
            asserted_account, asserted_partition = _role_account_assertion(
                str(account_name), partition
            )
            if (
                match.group(1) != asserted_partition
                or match.group(2) != asserted_account
            ):
                raise _configs.OperationalError(
                    "Explicit role ARN account/partition conflicts with --account."
                )
        if boundary:
            data = _state.load_config()
            _, configured = _state.get_resource(data, "account", boundary["account"])
            if (
                match.group(1) != configured["partition"]
                or match.group(2) != configured["id"]
            ):
                raise _configs.OperationalError(
                    "Boundary role account/partition conflicts with its configured account."
                )
    return role, policy, external_id, target.get("boundary_name")


def _role_account_assertion(value: str, caller_partition: str) -> tuple[str, str]:
    """Resolve a configured account name or a raw ID in the caller partition."""
    if re.fullmatch(r"\d{12}", value):
        return value, caller_partition
    data = _state.load_config()
    _, account = _state.get_resource(data, "account", value)
    return str(account["id"]), str(account["partition"])


def _require_concrete_role(args: Any, role: str | None) -> None:
    """Fail before authentication when role-only operands have no concrete role."""
    operands = {
        "--policy": getattr(args, "policy", None),
        "--duration/--ttl": getattr(args, "duration", None),
        "--htl": getattr(args, "htl", None),
        "--mtl": getattr(args, "mtl", None),
        "--stl": getattr(args, "stl", None),
        "--account": getattr(args, "account", None),
        "--external-id": getattr(args, "external_id", None),
        "--session-name": getattr(args, "session_name", None),
    }
    supplied = [name for name, value in operands.items() if value is not None]
    if supplied and role is None:
        raise _configs.OperationalError(
            f"{', '.join(supplied)} require a concrete role or boundary; the "
            "selected target is unbounded."
        )


def _require_bounded_browser_role(role: str | None) -> str:
    """Return a resolved browser boundary role or fail closed."""
    if not role:
        raise _configs.OperationalError("Bounded browser login requires a role.")
    return role


def _configured_role_before_auth(args: Any) -> str | None:
    """Resolve only local target/boundary role configuration before browser auth."""
    if getattr(args, "role", None):
        return str(args.role)
    data = _state.load_config()
    boundary_name = getattr(args, "boundary", None)
    if getattr(args, "target", None):
        _, target = _state.get_resource(data, "target", args.target.lstrip("+"))
        boundary_name = boundary_name or target.get("boundary")
    if not boundary_name:
        return None
    _, boundary = _state.get_resource(data, "boundary", boundary_name)
    return str(boundary["role_arn"])


def _session_name(role: str, boundary: str | None, override: str | None) -> str:
    raw = (
        override
        or f"hacksaws-{getpass.getuser()}-{boundary or role.rsplit('/', 1)[-1]}"
    )
    cleaned = re.sub(r"[^A-Za-z0-9+=,.@_-]", "-", raw).strip("-")[:64]
    if len(cleaned) < 2:
        cleaned = f"hacksaws-{cleaned or 'session'}"
    return cleaned[:64]


def _duration_for(args: Any, target: dict[str, Any], *, chained: bool) -> int:
    configured = target.get("boundary_data", {}).get("duration", 3600)
    duration = _duration.session_duration(
        duration=args.duration,
        htl=args.htl,
        mtl=args.mtl,
        stl=args.stl,
        default=int(configured),
    )
    if duration < 900:
        raise _configs.OperationalError(
            "AWS boundary sessions require at least 900 seconds."
        )
    if chained and duration > 3600:
        raise _configs.OperationalError(
            "AWS role chaining permits at most 3600 seconds."
        )
    return duration


def _policy_display_name(
    reference: str, origin: str, source_arn: str | None = None
) -> str:
    """Return a compact, non-secret policy label without embedding an ARN."""
    arn_match = _policies.POLICY_ARN.fullmatch(source_arn or reference)
    if arn_match:
        return arn_match.group(3)
    if origin == "local":
        return Path(reference).name or "session policy"
    value = reference.strip()
    if not value or value.casefold().startswith("arn:"):
        return "session policy"
    return value


def _assume(
    session: Any,
    role: str,
    *,
    policy: str | None,
    source_profile: str,
    args: Any,
    target: dict[str, Any],
    external_id: str | None,
    boundary_name: str | None,
    effective_duration: int | None = None,
    resolved_policy: _policies.ResolvedPolicy | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    match = re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/.+", role)
    if not match:
        raise _configs.OperationalError(f"Invalid role ARN {role!r}.")
    duration = effective_duration or _effective_assume_duration(
        session, role, args=args, target=target
    )
    request: dict[str, Any] = {
        "RoleArn": role,
        "RoleSessionName": _session_name(role, boundary_name, args.session_name),
        "DurationSeconds": duration,
    }
    resolved = resolved_policy
    if policy:
        if resolved is None:
            resolved = _policies.resolve(
                policy,
                account_id=match.group(2),
                partition=match.group(1),
                profile=source_profile,
                session=session,
            )
        if resolved.arn:
            request["PolicyArns"] = [{"arn": resolved.arn}]
        elif resolved.document:
            request["Policy"] = resolved.document
    if external_id:
        request["ExternalId"] = external_id
    try:
        response = session.client("sts").assume_role(**request)
    except (BotoCoreError, ClientError) as error:
        raise _configs.OperationalError(
            f"Unable to assume boundary role {role}: {error}"
        ) from error
    final_session = boto3.Session(
        aws_access_key_id=response["Credentials"]["AccessKeyId"],
        aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
        aws_session_token=response["Credentials"]["SessionToken"],
    )
    account, final_partition, _ = _identity(final_session, label="boundary credentials")
    if account != match.group(2) or final_partition != match.group(1):
        raise _configs.OperationalError(
            f"Boundary identity mismatch: expected {match.group(1)}:{match.group(2)}, got {final_partition}:{account}."
        )
    metadata = {
        "session_schema_version": 2,
        "target_account": account,
        "target_partition": final_partition,
        "role": role,
        "boundary": boundary_name,
        "policy": resolved.identity if resolved else None,
        "policy_provenance": resolved.provenance if resolved else None,
        "policy_reference": policy if resolved else None,
        "policy_origin": resolved.origin if resolved else None,
        "policy_arn": resolved.source_arn if resolved else None,
        "policy_cached": resolved.cached if resolved else False,
        "policy_display": (
            _policy_display_name(policy, resolved.origin, resolved.source_arn)
            if resolved and policy
            else None
        ),
        "expires_at": response["Credentials"]["Expiration"].astimezone(UTC).isoformat(),
    }
    return response["Credentials"], metadata


def _effective_assume_duration(
    session: Any, role: str, *, args: Any, target: dict[str, Any]
) -> int:
    """Resolve role-chaining and configured-role duration limits before preview."""
    credentials = session.get_credentials()
    chained = bool(credentials and credentials.token)
    duration = _duration_for(args, target, chained=chained)
    role_name = role.split("role/", 1)[-1]
    try:
        maximum = int(
            session.client("iam").get_role(RoleName=role_name)["Role"][
                "MaxSessionDuration"
            ]
        )
    except (BotoCoreError, ClientError, KeyError, TypeError, ValueError):
        maximum = None
    if maximum is not None and duration > maximum:
        raise _configs.OperationalError(
            f"Requested boundary duration {duration} seconds exceeds role "
            f"MaxSessionDuration {maximum} seconds."
        )
    return duration


def _save_credentials(path: Path, profile: str, credentials: dict[str, Any]) -> None:
    parser = _read_ini(path)
    parser[profile] = {
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
    }
    _write_ini(path, parser)


def _copy_region(
    source_config: Path,
    source_profile: str,
    destination_config: Path,
    destination_profile: str,
    explicit: str | None,
) -> None:
    source = _read_ini(source_config)
    destination = _read_ini(destination_config)
    source_section = _section(source_profile, config=True)
    destination_section = _section(destination_profile, config=True)
    if destination_section not in destination:
        destination.add_section(destination_section)
    if explicit:
        destination[destination_section]["region"] = explicit
    else:
        for key in ("region", "output"):
            if key not in destination[destination_section] and source.has_option(
                source_section, key
            ):
                destination[destination_section][key] = source[source_section][key]
    _write_ini(destination_config, destination)


def _record(
    destination: Path,
    profile: str,
    metadata: dict[str, Any],
    journal: dict[str, Any],
    *,
    method: str,
    ecr: list[str] | None = None,
    ecr_engine: str | None = None,
    previous_override: dict[str, Any] | None = None,
    inherit_runtime_state: bool = True,
    retain_file_backup: bool = True,
) -> None:
    sessions = _state.load_sessions()
    key = f"{destination.absolute()}::{profile}"
    previous = previous_override or sessions.get(key)
    destination_paths = {
        (destination / "credentials").absolute(),
        (destination / "config").absolute(),
    }
    destination_backup = [
        item
        for item in journal["files"]
        if Path(str(item.get("path", ""))).absolute() in destination_paths
    ]
    if previous:
        original_backup = previous.get("backup") or (
            destination_backup if retain_file_backup else []
        )
    else:
        original_backup = destination_backup if retain_file_backup else []
    previous_ecr = previous.get("ecr", []) if previous and inherit_runtime_state else []
    if "login_cache_lineage" not in metadata:
        previous_cache = (
            previous.get("login_cache_files", [])
            if previous and inherit_runtime_state
            else []
        )
        current_cache = metadata.get("login_cache_files", [])
        if previous_cache or current_cache:
            metadata["login_cache_files"] = list(
                dict.fromkeys([*previous_cache, *current_cache])
            )
        previous_cache_directories = (
            previous.get("login_cache_directories", [])
            if previous and inherit_runtime_state
            else []
        )
        current_cache_directories = metadata.get("login_cache_directories", [])
        if previous_cache_directories or current_cache_directories:
            metadata["login_cache_directories"] = list(
                dict.fromkeys([*previous_cache_directories, *current_cache_directories])
            )
        previous_fingerprints = (
            previous.get("login_cache_fingerprints", {})
            if previous and inherit_runtime_state
            else {}
        )
        current_fingerprints = metadata.get("login_cache_fingerprints", {})
        if previous_fingerprints or current_fingerprints:
            metadata["login_cache_fingerprints"] = {
                **previous_fingerprints,
                **current_fingerprints,
            }
    sessions[key] = {
        **metadata,
        "destination": str(destination.absolute()),
        "profile": profile,
        "auth_method": method,
        "started_at": _state.iso_now(),
        "backup": original_backup,
        "section_backup": _section_backup(destination, profile, journal, previous),
        "ecr": list(dict.fromkeys([*previous_ecr, *(ecr or [])])),
        "ecr_engine": (
            previous.get("ecr_engine") if previous and not ecr_engine else ecr_engine
        ),
    }
    _state.save_sessions(sessions)


def _original_file(path: Path, profile: str) -> bytes | None:
    """Read an active session's original file snapshot when this is its destination."""
    key = f"{path.parent.absolute()}::{profile}"
    session = _state.load_sessions().get(key)
    if session:
        kind = "config" if path.name == "config" else "credentials"
        section_item = session.get("section_backup", {}).get(kind)
        if isinstance(section_item, dict) and isinstance(
            section_item.get("original"), dict
        ):
            original = section_item["original"]
            parser = _read_ini(path)
            section = _section(profile, config=kind == "config")
            if original.get("exists"):
                values = original.get("values")
                if not isinstance(values, dict):
                    raise _configs.OperationalError(
                        "Managed session original section values are invalid."
                    )
                parser[section] = {
                    str(name): str(value) for name, value in values.items()
                }
            else:
                parser.remove_section(section)
            import io

            stream = io.StringIO()
            parser.write(stream)
            return stream.getvalue().encode()
        for snapshot in session.get("backup", []):
            if Path(snapshot["path"]).absolute() == path.absolute():
                return (
                    base64.b64decode(snapshot["data"])
                    if snapshot.get("exists")
                    else None
                )
    return path.read_bytes() if path.exists() else None


def _parser_from_bytes(value: bytes | None, path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    if value is not None:
        try:
            parser.read_string(value.decode("utf-8"), source=str(path))
        except (UnicodeError, configparser.Error) as error:
            raise _configs.OperationalError(
                f"Unable to parse original AWS file {path}: {error}"
            ) from error
    return parser


def _persistent_source(
    source_dir: Path, profile: str
) -> tuple[Any, configparser.ConfigParser]:
    """Build a session from original persistent credentials, never installed output."""
    credentials_path = source_dir / "credentials"
    config_path = source_dir / "config"
    credentials = _parser_from_bytes(
        _original_file(credentials_path, profile), credentials_path
    )
    config = _parser_from_bytes(_original_file(config_path, profile), config_path)
    if profile not in credentials:
        raise _configs.OperationalError(
            f"Persistent source profile {profile!r} is missing from {credentials_path}."
        )
    values = credentials[profile]
    if "aws_access_key_id" not in values or "aws_secret_access_key" not in values:
        raise _configs.OperationalError(
            f"Persistent source profile {profile!r} must contain readable access keys "
            "for transactional MFA re-login."
        )
    config_section = _section(profile, config=True)
    region = config.get(config_section, "region", fallback=None)
    source = boto3.Session(
        aws_access_key_id=values["aws_access_key_id"],
        aws_secret_access_key=values["aws_secret_access_key"],
        aws_session_token=values.get("aws_session_token"),
        region_name=region,
    )
    return source, config


def _mfa_session(
    source: Any,
    config: configparser.ConfigParser,
    profile: str,
    token: str,
    lifespan: int,
) -> Any:
    section = _section(profile, config=True)
    if not config.has_option(section, "mfa_serial"):
        raise _configs.OperationalError(
            f"Profile {profile!r} does not define mfa_serial."
        )
    try:
        response = source.client("sts").get_session_token(
            DurationSeconds=lifespan,
            SerialNumber=config[section]["mfa_serial"],
            TokenCode=token,
        )
    except (BotoCoreError, ClientError) as error:
        raise _configs.OperationalError(
            f"Unable to start MFA session for {profile!r}: {error}"
        ) from error
    values = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=values["AccessKeyId"],
        aws_secret_access_key=values["SecretAccessKey"],
        aws_session_token=values["SessionToken"],
        region_name=source.region_name,
    )


def mfa_login(context: _configs.Context) -> _configs.Result:
    """Authenticate with MFA and transactionally persist only the final tier."""
    args = context.args
    source_dir, source_profile, destination_dir, destination_profile = _paths(args)
    raw, source_config = _persistent_source(source_dir, source_profile)
    source_account, partition, _ = _identity(raw, label="MFA source credentials")
    target = _target_details(args, source_account, partition)
    role, policy, external_id, boundary_name = _role_details(
        args, target, source_account, partition
    )
    _require_concrete_role(args, role)
    intermediate = _mfa_session(
        raw, source_config, source_profile, args.mfa_code, args.lifespan
    )
    journal = _begin(
        [
            destination_dir / "credentials",
            destination_dir / "config",
            _state.sessions_path(),
        ]
    )
    ecr_registries = []
    try:
        if args.ecr:
            account = _configs.AwsAccount(
                identity_response={
                    "Account": source_account,
                    "Arn": f"arn:{partition}:iam::{source_account}:user/hacksaws",
                },
                region_name=intermediate.region_name or args.region or "us-east-1",
                ecr_additional_regions=tuple(args.ecr_region or ()),
            )
            ecr_registries = _ecr.login_with_session(
                context,
                account,
                intermediate,
                on_success=lambda registry: _record_ecr_in_journal(
                    journal, context.container_engine, registry
                ),
            )
        if role:
            credentials, metadata = _assume(
                intermediate,
                role,
                policy=policy,
                source_profile=source_profile,
                args=args,
                target=target,
                external_id=external_id,
                boundary_name=boundary_name,
            )
        else:
            frozen = intermediate.get_credentials().get_frozen_credentials()
            credentials = {
                "AccessKeyId": frozen.access_key,
                "SecretAccessKey": frozen.secret_key,
                "SessionToken": frozen.token,
            }
            metadata = {
                "target_account": source_account,
                "role": None,
                "boundary": None,
                "policy": None,
                "policy_provenance": None,
                "expires_at": None,
            }
        _save_credentials(
            destination_dir / "credentials", destination_profile, credentials
        )
        _copy_region(
            source_dir / "config",
            source_profile,
            destination_dir / "config",
            destination_profile,
            args.region,
        )
        metadata["source_account"] = source_account
        metadata["source_partition"] = partition
        metadata["target"] = target.get("target_name")
        _record(
            destination_dir,
            destination_profile,
            metadata,
            journal,
            method="mfa",
            ecr=ecr_registries,
            ecr_engine=context.container_engine if ecr_registries else None,
        )
        _commit()
    except Exception:
        _rollback(journal)
        raise
    return _configs.Result("MFA_LOGIN", f"Logged into profile {destination_profile}")


def _aws_cli_version() -> tuple[int, int, int]:
    try:
        result = subprocess.run(
            ["aws", "--version"],
            capture_output=True,
            text=True,
            check=True,
            env=_clean_env(),
        )
    except (FileNotFoundError, OSError, subprocess.CalledProcessError) as error:
        raise _configs.OperationalError(
            f"AWS CLI v2.32.0 or newer is required for browser login: {error}"
        ) from error
    match = _AWS_VERSION.search(result.stdout + result.stderr)
    if (
        not match
        or int(match.group(1)) != 2
        or tuple(map(int, match.groups())) < (2, 32, 0)
    ):
        found = match.group(0) if match else "unknown version"
        raise _configs.OperationalError(
            f"AWS CLI v2.32.0 or newer is required; found {found}."
        )
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _require_browser_runtime() -> None:
    """Fail before browser authentication when the Boto3 login provider is unusable."""
    try:
        importlib.import_module("awscrt.auth")
        importlib.import_module("awscrt.io")
    except (ImportError, OSError) as error:
        raise _configs.OperationalError(
            "Browser login requires AWS Common Runtime (CRT) support. Reinstall "
            "Hacksaws with its runtime dependencies (use `uv sync` in a source "
            "checkout, or refresh the `uvx hacksaws` installation) and retry."
        ) from error


def _native_login_cache() -> Path:
    """Resolve the cache directory external AWS tools will use after native login."""
    configured = os.environ.get("AWS_LOGIN_CACHE_DIRECTORY")
    if configured:
        return Path(configured).expanduser().absolute()
    return Path.home() / ".aws" / "login" / "cache"


def _clean_env(
    config: Path | None = None,
    credentials: Path | None = None,
    login_cache: Path | None = None,
) -> dict[str, str]:
    env = {
        key: value for key, value in os.environ.items() if key not in _CONFLICTING_ENV
    }
    if config:
        env["AWS_CONFIG_FILE"] = str(config)
    if credentials:
        env["AWS_SHARED_CREDENTIALS_FILE"] = str(credentials)
    if login_cache:
        env["AWS_LOGIN_CACHE_DIRECTORY"] = str(login_cache)
    return env


@contextmanager
def _aws_environment(
    config: Path, credentials: Path, login_cache: Path
) -> Iterator[None]:
    """Temporarily scrub inherited AWS identity/path variables for one staging area."""
    previous = {key: os.environ.get(key) for key in _CONFLICTING_ENV}
    for key in _CONFLICTING_ENV:
        os.environ.pop(key, None)
    os.environ["AWS_CONFIG_FILE"] = str(config)
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(credentials)
    os.environ["AWS_LOGIN_CACHE_DIRECTORY"] = str(login_cache)
    try:
        yield
    finally:
        for key in _CONFLICTING_ENV:
            value = previous[key]
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _aws_login(
    config: Path,
    credentials: Path,
    profile: str,
    *,
    remote: bool,
    login_cache: Path,
) -> None:
    _aws_cli_version()
    config.parent.mkdir(parents=True, exist_ok=True)
    command = ["aws", "login", "--profile", profile]
    if remote:
        command.append("--remote")
    try:
        subprocess.run(
            command,
            check=True,
            env=_clean_env(config, credentials, login_cache),
        )
    except (FileNotFoundError, OSError, subprocess.CalledProcessError) as error:
        raise _configs.OperationalError(f"AWS browser login failed: {error}") from error


def browser_login(context: _configs.Context) -> _configs.Result:
    """Run AWS-native browser login or isolate it before a role boundary."""
    _require_browser_runtime()
    args = context.args
    source_dir, source_profile, destination_dir, destination_profile = _paths(args)
    # Determine role from config without requiring caller identity first.
    configured_role = _configured_role_before_auth(args)
    _require_concrete_role(args, configured_role)
    has_boundary = configured_role is not None
    if not has_boundary:
        native_cache = _native_login_cache()
        journal = _begin(
            [
                destination_dir / "config",
                destination_dir / "credentials",
                _state.sessions_path(),
            ]
        )
        ecr_registries: list[str] = []
        login_completed = False
        try:
            _aws_login(
                destination_dir / "config",
                destination_dir / "credentials",
                destination_profile,
                remote=args.remote,
                login_cache=native_cache,
            )
            login_completed = True
            initial_lineage = _browser_cache_lineage(
                destination_dir / "config",
                destination_profile,
                native_cache,
            )
            _record_browser_cache_claim(
                journal,
                initial_lineage,
                destination_dir / "config",
                destination_profile,
            )
            with _aws_environment(
                destination_dir / "config",
                destination_dir / "credentials",
                native_cache,
            ):
                native = boto3.Session(profile_name=destination_profile)
                account, partition, principal = _identity(native, label="browser login")
            lineage = _browser_cache_lineage(
                destination_dir / "config",
                destination_profile,
                native_cache,
                identity=(account, partition, principal),
            )
            journal["browser_cache_claims"][-1].update(lineage)
            _state.atomic_write(
                _journal_path(), (json.dumps(journal, indent=2) + "\n").encode()
            )
            target = _target_details(args, account, partition)
            if args.ecr:
                aws_account = _configs.AwsAccount(
                    {
                        "Account": account,
                        "Arn": f"arn:{partition}:iam::{account}:user/hacksaws",
                    },
                    native.region_name or args.region or "us-east-1",
                    tuple(args.ecr_region or ()),
                )
                ecr_registries = _ecr.login_with_session(
                    context,
                    aws_account,
                    native,
                    on_success=lambda registry: _record_ecr_in_journal(
                        journal, context.container_engine, registry
                    ),
                )
            _record(
                destination_dir,
                destination_profile,
                {
                    "source_account": account,
                    "source_partition": partition,
                    "target_account": account,
                    "target_partition": partition,
                    "target": target.get("target_name"),
                    "role": None,
                    "boundary": None,
                    "policy": None,
                    "policy_provenance": "AWS-native login_session",
                    "expires_at": None,
                    "login_cache_lineage": lineage,
                },
                journal,
                method="browser-native",
                ecr=ecr_registries,
                ecr_engine=context.container_engine if ecr_registries else None,
            )
            _commit()
        except Exception as error:
            _rollback(journal)
            if login_completed and isinstance(error, _configs.OperationalError):
                raise _configs.OperationalError(
                    f"{error} Browser login changes for profile "
                    f"{destination_profile!r} were rolled back."
                ) from error
            raise
        return _configs.Result(
            "BROWSER_LOGIN",
            f"AWS-native browser login active for profile {destination_profile}.",
        )

    staging = _state.root() / "staging" / uuid.uuid4().hex
    staging_config = staging / "config"
    staging_credentials = staging / "credentials"
    staging_cache = staging / "login" / "cache"
    journal = _begin(
        [
            destination_dir / "config",
            destination_dir / "credentials",
            _state.sessions_path(),
        ]
    )
    ecr_registries = []
    login_completed = False
    try:
        _aws_login(
            staging_config,
            staging_credentials,
            source_profile,
            remote=args.remote,
            login_cache=staging_cache,
        )
        login_completed = True
        initial_lineage = _browser_cache_lineage(
            staging_config, source_profile, staging_cache
        )
        _record_browser_cache_claim(
            journal, initial_lineage, staging_config, source_profile
        )
        with _aws_environment(staging_config, staging_credentials, staging_cache):
            intermediate = boto3.Session(profile_name=source_profile)
            source_account, partition, source_principal = _identity(
                intermediate, label="browser staging login"
            )
            lineage = _browser_cache_lineage(
                staging_config,
                source_profile,
                staging_cache,
                identity=(source_account, partition, source_principal),
            )
            journal["browser_cache_claims"][-1].update(lineage)
            _state.atomic_write(
                _journal_path(), (json.dumps(journal, indent=2) + "\n").encode()
            )
            target = _target_details(args, source_account, partition)
            role, policy, external_id, boundary_name = _role_details(
                args, target, source_account, partition
            )
            role = _require_bounded_browser_role(role)
            if args.ecr:
                aws_account = _configs.AwsAccount(
                    {
                        "Account": source_account,
                        "Arn": (f"arn:{partition}:iam::{source_account}:user/hacksaws"),
                    },
                    intermediate.region_name or args.region or "us-east-1",
                    tuple(args.ecr_region or ()),
                )
                ecr_registries = _ecr.login_with_session(
                    context,
                    aws_account,
                    intermediate,
                    on_success=lambda registry: _record_ecr_in_journal(
                        journal, context.container_engine, registry
                    ),
                )
            credentials, metadata = _assume(
                intermediate,
                role,
                policy=policy,
                source_profile=source_profile,
                args=args,
                target=target,
                external_id=external_id,
                boundary_name=boundary_name,
            )
        _save_credentials(
            destination_dir / "credentials", destination_profile, credentials
        )
        _copy_region(
            staging_config,
            source_profile,
            destination_dir / "config",
            destination_profile,
            args.region,
        )
        config = _read_ini(destination_dir / "config")
        section = _section(destination_profile, config=True)
        if section in config:
            config[section].pop("login_session", None)
            _write_ini(destination_dir / "config", config)
        metadata.update(
            source_account=source_account,
            source_partition=partition,
            target=target.get("target_name"),
        )
        _record(
            destination_dir,
            destination_profile,
            metadata,
            journal,
            method="browser-boundary",
            ecr=ecr_registries,
            ecr_engine=context.container_engine if ecr_registries else None,
        )
        _remove_browser_cache_claim(journal["browser_cache_claims"][-1], strict=True)
        journal["browser_cache_claims"] = []
        _commit()
    except Exception as error:
        _rollback(journal)
        if login_completed and isinstance(error, _configs.OperationalError):
            raise _configs.OperationalError(
                f"{error} Browser login changes for profile "
                f"{destination_profile!r} were rolled back."
            ) from error
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return _configs.Result(
        "BROWSER_LOGIN",
        f"Bounded browser login active for profile {destination_profile}.",
    )


def _profile_exists(directory: Path, profile: str) -> bool:
    """Return whether either AWS file already contains a profile section."""
    credentials = _read_ini(directory / "credentials")
    config = _read_ini(directory / "config")
    return profile in credentials or _section(profile, config=True) in config


def _legacy_source_backup(
    directory: Path, profile: str
) -> tuple[Path, dict[str, str]] | None:
    """Read the persistent credential tier behind a legacy MFA login."""
    path = directory / f"{profile}.store.credentials"
    if not path.exists():
        return None
    parser = _read_ini(path)
    if profile not in parser:
        raise _configs.OperationalError(
            f"Legacy credential backup {path} has no profile {profile!r}."
        )
    values = dict(parser[profile].items())
    if not {"aws_access_key_id", "aws_secret_access_key"} <= values.keys():
        raise _configs.OperationalError(
            f"Legacy credential backup {path} has incomplete persistent credentials."
        )
    return path, values


def _region_values(directory: Path, profile: str) -> dict[str, str]:
    """Capture only non-secret regional settings from an authenticated source."""
    parser = _read_ini(directory / "config")
    section = _section(profile, config=True)
    if section not in parser:
        return {}
    return {
        key: parser[section][key]
        for key in ("region", "output")
        if key in parser[section]
    }


def _apply_region_values(
    destination: Path,
    profile: str,
    values: dict[str, str],
    explicit: str | None,
) -> None:
    """Apply login-compatible region/output inheritance to one profile section."""
    parser = _read_ini(destination / "config")
    section = _section(profile, config=True)
    if section not in parser:
        parser.add_section(section)
    if explicit:
        parser[section]["region"] = explicit
    else:
        for key, value in values.items():
            if key not in parser[section]:
                parser[section][key] = value
    parser[section].pop("login_session", None)
    _write_ini(destination / "config", parser)


def _session_is_usable_source(session: dict[str, Any]) -> None:
    """Reject managed records that no longer represent usable AWS credentials."""
    method = session.get("auth_method")
    if method in {"ecr-only", "browser-cache-residue", "logout-residue"}:
        raise _configs.OperationalError(
            f"Managed source session is {method}; log in again before assuming a role."
        )
    expires_at = session.get("expires_at")
    if expires_at:
        try:
            expired = datetime.fromisoformat(str(expires_at)) <= datetime.now(UTC)
        except (TypeError, ValueError) as error:
            raise _configs.OperationalError(
                "Managed source session has an invalid expiration timestamp."
            ) from error
        if expired:
            raise _configs.OperationalError(
                "Managed source session has expired; log in again before assuming a role."
            )


def _assume_preflight(context: _configs.Context) -> dict[str, Any]:
    """Resolve and validate an already-authenticated AssumeRole handoff."""
    args = context.args
    source, source_profile, destination, destination_profile = _paths(args)
    if (
        getattr(args, "to_profile", None)
        and not getattr(args, "to_directory", None)
        and not getattr(args, "to", None)
    ):
        destination = source
        destination_profile = _normalize_profile(args.to_profile)
    source = source.absolute()
    destination = destination.absolute()
    source_key = f"{source}::{source_profile}"
    destination_key = f"{destination}::{destination_profile}"
    same_key = source_key == destination_key
    explicit_self = bool(getattr(args, "self_destination", False))
    verbose_self = (
        bool(getattr(args, "to", None))
        or bool(getattr(args, "to_directory", None))
        or bool(getattr(args, "to_profile", None))
    )
    if same_key and not (explicit_self or verbose_self):
        raise _configs.OperationalError(
            "Source and destination are the same profile. Use --self or explicitly "
            "repeat the destination with --to LOCATION:PROFILE."
        )
    if explicit_self and not same_key:
        raise _configs.OperationalError("--self must resolve to the source profile.")
    if same_key and bool(getattr(args, "keep_source", False)):
        raise _configs.OperationalError("--keep-source cannot be combined with --self.")

    sessions = _state.load_sessions()
    source_record = sessions.get(source_key)
    legacy = None if source_record else _legacy_source_backup(source, source_profile)
    keep_source = bool(getattr(args, "keep_source", False))
    if source_record:
        _session_is_usable_source(source_record)
    elif legacy is None and not keep_source:
        raise _configs.OperationalError(
            "The source profile is not a Hacksaws-managed login. Retry with "
            "--keep-source to leave the source untouched."
        )
    force = bool(getattr(args, "force", False))
    source_plans: list[tuple[Path, str, dict[str, Any]]] = []
    source_cache: tuple[
        list[Path], list[dict[str, Any]], list[dict[str, str]], dict[str, Any] | None
    ] = ([], [], [], None)
    if source_record:
        if not keep_source:
            source_plans = _profile_section_plans(
                source_record, source, source_profile, force=force
            )
        source_cache = _tracked_login_cache_plan(
            source_record, source, source_profile, force=force
        )
        if keep_source:
            source_cache = (
                source_cache[0],
                [],
                source_cache[2],
                source_cache[3],
            )

    destination_record = sessions.get(destination_key)
    destination_cache: tuple[
        list[Path], list[dict[str, Any]], list[dict[str, str]], dict[str, Any] | None
    ] = (
        [],
        [],
        [],
        None,
    )
    if destination_record and not same_key:
        _profile_section_plans(
            destination_record, destination, destination_profile, force=False
        )
        destination_cache = _tracked_login_cache_plan(
            destination_record, destination, destination_profile, force=False
        )
    destination_exists = _profile_exists(destination, destination_profile)
    if (
        not same_key
        and destination_record is None
        and destination_exists
        and not bool(getattr(args, "replace", False))
    ):
        raise _configs.OperationalError(
            f"Destination profile {destination_profile!r} already exists outside "
            "Hacksaws management; retry with --replace after reviewing it."
        )

    if source_record:
        stored_lineage = source_record.get("login_cache_lineage")
        configured = (
            [stored_lineage["root"]]
            if isinstance(stored_lineage, dict) and stored_lineage.get("root")
            else source_record.get("login_cache_directories", [])
        )
        source_login_cache = (
            Path(str(configured[0])).absolute() if configured else _native_login_cache()
        )
    else:
        source_login_cache = _native_login_cache()
    with _aws_environment(
        source / "config", source / "credentials", source_login_cache
    ):
        authenticated = boto3.Session(profile_name=source_profile)
        source_account, partition, source_arn = _identity(
            authenticated, label="authenticated assume-role source"
        )
    target = _target_details(args, source_account, partition)
    role, policy, external_id, boundary_name = _role_details(
        args, target, source_account, partition
    )
    if role is None:
        raise _configs.OperationalError(
            "hacksaws assume requires a concrete --role, --boundary/--as, or bounded target."
        )
    return {
        "source": source,
        "source_profile": source_profile,
        "source_key": source_key,
        "source_record": source_record,
        "source_plans": source_plans,
        "source_cache": source_cache,
        "legacy": legacy,
        "destination": destination,
        "destination_profile": destination_profile,
        "destination_key": destination_key,
        "destination_record": destination_record,
        "destination_cache": destination_cache,
        "same_key": same_key,
        "explicit_self": explicit_self,
        "keep_source": keep_source,
        "keep_ecr": bool(getattr(args, "keep_ecr", False)),
        "replace": bool(getattr(args, "replace", False)),
        "destination_exists": destination_exists,
        "authenticated": authenticated,
        "source_account": source_account,
        "source_partition": partition,
        "source_arn": source_arn,
        "target": target,
        "role": role,
        "policy": policy,
        "external_id": external_id,
        "boundary_name": boundary_name,
        "region_values": _region_values(source, source_profile),
    }


def _assume_public_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Return a stable, secret-free preview of an AssumeRole handoff."""
    source_record = plan.get("source_record") or {}
    warnings = []
    if plan["same_key"] and not plan["explicit_self"]:
        warnings.append(
            "The explicit destination resolves to the source profile; the source "
            "credentials will be replaced in place."
        )
    if plan["same_key"]:
        destination_action = "replace-source-in-place"
    elif plan.get("destination_record") is not None:
        destination_action = "replace-managed"
    elif plan["destination_exists"]:
        destination_action = "replace-unmanaged"
    else:
        destination_action = "create"
    return {
        "source": {
            "directory": str(plan["source"]),
            "profile": plan["source_profile"],
            "account": plan["source_account"],
            "partition": plan["source_partition"],
            "principal": plan["source_arn"],
            "authMethod": source_record.get("auth_method", "unmanaged"),
            "willLogout": not plan["keep_source"],
        },
        "destination": {
            "directory": str(plan["destination"]),
            "profile": plan["destination_profile"],
            "sameAsSource": plan["same_key"],
            "replacesManaged": plan.get("destination_record") is not None,
        },
        "role": plan["role"],
        "policy": plan["policy"],
        "boundary": plan["boundary_name"],
        "target": plan["target"].get("target_name"),
        "durationSeconds": plan["effective_duration"],
        "keepSource": plan["keep_source"],
        "keepEcr": plan["keep_ecr"],
        "replace": plan["replace"],
        "lifecycle": {
            "source": "keep" if plan["keep_source"] else "logout",
            "destination": destination_action,
            "ecr": "keep" if plan["keep_ecr"] else "logout-after-commit",
            "replaceApproved": plan["replace"],
        },
        "warnings": warnings,
    }


def _assume_arguments_fingerprint(args: Any) -> str:
    """Bind execution to the security-relevant arguments used for its preview."""
    names = (
        "profile",
        "directory",
        "aws_account_name",
        "target",
        "to",
        "to_directory",
        "to_profile",
        "self_destination",
        "role",
        "boundary",
        "policy",
        "external_id",
        "account",
        "session_name",
        "region",
        "duration",
        "htl",
        "mtl",
        "stl",
        "keep_source",
        "keep_ecr",
        "replace",
        "force",
    )
    encoded = json.dumps(
        {name: getattr(args, name, None) for name in names},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    return _state.digest(encoded)


def _owned_cache_state(plan: dict[str, Any]) -> dict[str, str | None]:
    claims = [*plan["source_cache"][1], *plan["destination_cache"][1]]
    result: dict[str, str | None] = {}
    for claim in claims:
        path = _canonical_path(Path(str(claim["path"])))
        result[str(path)] = _state.digest(path.read_bytes()) if path.exists() else None
    return result


def _file_fingerprint(path: Path) -> str | None:
    return _state.digest(path.read_bytes()) if path.exists() else None


def _session_record_state(record: object) -> dict[str, Any]:
    """Fingerprint one sessions.json key without embedding its record in a journal."""
    if not isinstance(record, dict):
        return {"exists": False, "fingerprint": None}
    encoded = json.dumps(
        record, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return {"exists": True, "fingerprint": _state.digest(encoded)}


def _session_final_state(record: dict[str, Any] | None) -> dict[str, Any]:
    state = _session_record_state(record)
    if record is not None:
        state["values"] = copy.deepcopy(record)
    return state


def _current_session_state(key: str) -> dict[str, Any]:
    return _session_record_state(_state.load_sessions().get(key))


def prepare_assume_role(context: _configs.Context) -> AssumeRolePlan:
    """Freeze a secret-safe AssumeRole plan for preview and later execution."""
    data = _assume_preflight(context)
    role = str(data["role"])
    match = re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/.+", role)
    if match is None:
        raise _configs.OperationalError(f"Invalid role ARN {role!r}.")
    data["effective_duration"] = _effective_assume_duration(
        data["authenticated"], role, args=context.args, target=data["target"]
    )
    data["resolved_policy"] = (
        _policies.resolve(
            data["policy"],
            account_id=match.group(2),
            partition=match.group(1),
            profile=data["source_profile"],
            session=data["authenticated"],
        )
        if data["policy"]
        else None
    )
    data["hacksaws_config_expected"] = _file_fingerprint(_state.root() / "config.json")
    data["policy_source_expected"] = None
    resolved = data["resolved_policy"]
    if resolved and resolved.origin == "local":
        policy_path = Path(resolved.provenance).expanduser().absolute()
        data["policy_source_expected"] = {
            "path": str(policy_path),
            "fingerprint": _file_fingerprint(policy_path),
        }
    elif resolved and resolved.origin == "stored":
        policy_path = (
            _policies.stored_directory() / f"{resolved.identity}.yaml"
        ).absolute()
        data["policy_source_expected"] = {
            "path": str(policy_path),
            "fingerprint": _file_fingerprint(policy_path),
        }
    data["source_expected"] = {
        "credentials": _section_state(
            data["source"] / "credentials", data["source_profile"]
        ),
        "config": _section_state(
            data["source"] / "config",
            _section(data["source_profile"], config=True),
        ),
    }
    data["destination_expected"] = {
        "credentials": _section_state(
            data["destination"] / "credentials", data["destination_profile"]
        ),
        "config": _section_state(
            data["destination"] / "config",
            _section(data["destination_profile"], config=True),
        ),
    }
    sessions = _state.load_sessions()
    source_session = _session_record_state(sessions.get(data["source_key"]))
    destination_session = _session_record_state(sessions.get(data["destination_key"]))
    if source_session != _session_record_state(data["source_record"]) or (
        destination_session != _session_record_state(data["destination_record"])
    ):
        raise _configs.OperationalError(
            "Managed session metadata changed during AssumeRole preparation; retry."
        )
    data["source_session_expected"] = source_session
    data["destination_session_expected"] = destination_session
    data["cache_expected"] = _owned_cache_state(data)
    return AssumeRolePlan(data, _assume_arguments_fingerprint(context.args))


def assume_role_preview(plan: AssumeRolePlan) -> dict[str, Any]:
    """Return the public, secret-free view of one frozen AssumeRole plan."""
    if not isinstance(plan, AssumeRolePlan):
        raise TypeError("assume_role_preview requires prepare_assume_role output")
    return _assume_public_plan(plan._data)


def _cleanup_assume_ecr(
    owners: dict[str, tuple[str, list[str]]],
) -> list[dict[str, str]]:
    """Remove post-commit ECR state and retain precise local residue on failure."""
    failures: list[dict[str, str]] = []
    operations: dict[tuple[str, str], set[str]] = {}
    for key, (engine, registries) in owners.items():
        for registry in registries:
            operations.setdefault((engine, registry), set()).add(key)
    for (engine_name, registry), keys in operations.items():
        engine = cast("_configs.ContainerEngine", engine_name)
        try:
            _ecr._run_container_engine(engine, [engine, "logout", registry])
        except _configs.OperationalError as error:
            failures.append({"registry": registry, "message": str(error)})
            continue
        sessions = _state.load_sessions()
        for key in keys:
            session = sessions.get(key)
            if not session:
                continue
            remaining = [value for value in session.get("ecr", []) if value != registry]
            if remaining:
                session["ecr"] = remaining
            elif session.get("auth_method") == "ecr-only":
                sessions.pop(key, None)
            else:
                session["ecr"] = []
        _state.save_sessions(sessions)
    return failures


def _assume_original_section(
    data: dict[str, Any], *, source: bool, kind: str
) -> dict[str, Any]:
    """Return only the authorized persistent section used after logout."""
    record = data["source_record"] if source else data["destination_record"]
    if record:
        item = record.get("section_backup", {}).get(kind)
        if not isinstance(item, dict) or not isinstance(item.get("original"), dict):
            raise _configs.OperationalError(
                "Managed AssumeRole endpoint has no safe original section state."
            )
        return copy.deepcopy(item["original"])
    directory = cast("Path", data["source"] if source else data["destination"])
    profile = str(data["source_profile"] if source else data["destination_profile"])
    if source and data["legacy"] and kind == "credentials":
        return {"exists": True, "values": dict(data["legacy"][1])}
    parser = _read_ini(directory / kind)
    section = _section(profile, config=kind == "config")
    values = _section_values(parser, section)
    return {"exists": values is not None, "values": values or {}}


def _write_section(path: Path, section: str, state: dict[str, Any]) -> None:
    parser = _read_ini(path)
    if state.get("exists"):
        values = state.get("values")
        if not isinstance(values, dict):
            raise _configs.OperationalError("AssumeRole journal section is invalid.")
        parser[section] = {str(key): str(value) for key, value in values.items()}
    else:
        parser.remove_section(section)
    _write_ini(path, parser)


def _planned_destination_config(data: dict[str, Any], args: Any) -> dict[str, str]:
    destination = cast("Path", data["destination"])
    profile = str(data["destination_profile"])
    parser = _read_ini(destination / "config")
    section = _section(profile, config=True)
    values = dict(parser[section].items()) if section in parser else {}
    if getattr(args, "region", None):
        values["region"] = str(args.region)
    else:
        for key, value in data["region_values"].items():
            values.setdefault(key, value)
    values.pop("login_session", None)
    return values


def _revalidate_assume_plan(
    context: _configs.Context, prepared: AssumeRolePlan
) -> None:
    data = prepared._data
    changed = prepared._consumed or (
        prepared._arguments_fingerprint != _assume_arguments_fingerprint(context.args)
    )
    for prefix, directory_key, profile_key in (
        ("source", "source", "source_profile"),
        ("destination", "destination", "destination_profile"),
    ):
        directory = cast("Path", data[directory_key])
        profile = str(data[profile_key])
        current = {
            "credentials": _section_state(directory / "credentials", profile),
            "config": _section_state(
                directory / "config", _section(profile, config=True)
            ),
        }
        changed = changed or current != data[f"{prefix}_expected"]
    if _owned_cache_state(data) != data["cache_expected"]:
        source_record = data.get("source_record")
        if source_record:
            source_cache = _tracked_login_cache_plan(
                source_record,
                data["source"],
                data["source_profile"],
                force=False,
            )
            if data["keep_source"]:
                source_cache = (
                    source_cache[0],
                    [],
                    source_cache[2],
                    source_cache[3],
                )
            data["source_cache"] = source_cache
        destination_record = data.get("destination_record")
        if destination_record and not data["same_key"]:
            data["destination_cache"] = _tracked_login_cache_plan(
                destination_record,
                data["destination"],
                data["destination_profile"],
                force=False,
            )
        data["cache_expected"] = _owned_cache_state(data)
    changed = (
        changed
        or _file_fingerprint(_state.root() / "config.json")
        != data["hacksaws_config_expected"]
    )
    policy_source = data.get("policy_source_expected")
    if policy_source:
        changed = (
            changed
            or _file_fingerprint(Path(policy_source["path"]))
            != policy_source["fingerprint"]
        )
    sessions = _state.load_sessions()
    changed = (
        changed
        or _session_record_state(sessions.get(data["source_key"]))
        != data["source_session_expected"]
    )
    changed = (
        changed
        or _session_record_state(sessions.get(data["destination_key"]))
        != data["destination_session_expected"]
    )
    if changed:
        raise AssumePlanChanged(
            "AssumeRole plan changed after preview; no local credential changes were "
            "made. Review a fresh preview and retry."
        )


def _write_assume_journal(journal: dict[str, Any]) -> None:
    _state.atomic_write(
        _journal_path(), (json.dumps(journal, indent=2, default=str) + "\n").encode()
    )


def _build_assume_journal(
    data: dict[str, Any],
    args: Any,
    credentials: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    source = cast("Path", data["source"])
    destination = cast("Path", data["destination"])
    source_profile = str(data["source_profile"])
    destination_profile = str(data["destination_profile"])
    credential_values = {
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
    }
    config_values = _planned_destination_config(data, args)
    source_original = (
        {
            kind: _assume_original_section(data, source=True, kind=kind)
            for kind in ("credentials", "config")
        }
        if not data["keep_source"]
        else {}
    )
    destination_original = (
        copy.deepcopy(source_original)
        if data["same_key"]
        else {
            kind: _assume_original_section(data, source=False, kind=kind)
            for kind in ("credentials", "config")
        }
    )
    runtime_record = (
        data["source_record"] if data["same_key"] else data["destination_record"]
    ) or {}
    inherited_ecr = list(runtime_record.get("ecr", []))
    inherited_engine = str(runtime_record.get("ecr_engine") or "docker")
    metadata.update(
        source_account=data["source_account"],
        source_partition=data["source_partition"],
        source_profile=source_profile,
        source_destination=str(source),
        source_auth_method=(data["source_record"] or {}).get(
            "auth_method", "legacy-mfa" if data["legacy"] else "unmanaged"
        ),
        source_logged_out=not data["keep_source"],
        target=data["target"].get("target_name"),
    )
    section_backup = {
        "credentials": {
            "path": str((destination / "credentials").absolute()),
            "section": destination_profile,
            "original": destination_original["credentials"],
            "installed": {
                "exists": True,
                "fingerprint": _section_fingerprint(credential_values),
            },
        },
        "config": {
            "path": str((destination / "config").absolute()),
            "section": _section(destination_profile, config=True),
            "original": destination_original["config"],
            "installed": {
                "exists": True,
                "fingerprint": _section_fingerprint(config_values),
            },
        },
    }
    previous_backup = (
        data["destination_record"].get("backup", [])
        if data["destination_record"]
        else []
    )
    destination_session = {
        **metadata,
        "destination": str(destination),
        "profile": destination_profile,
        "auth_method": "assume-role",
        "started_at": _state.iso_now(),
        "backup": previous_backup,
        "section_backup": section_backup,
        "ecr": inherited_ecr,
        "ecr_engine": inherited_engine if inherited_ecr else None,
    }
    cache = [
        {**copy.deepcopy(claim), "owner": owner}
        for owner, claims in (
            ("source", data["source_cache"][1]),
            ("destination", data["destination_cache"][1]),
        )
        for claim in claims
    ]
    source_record = data["source_record"] or {}
    source_runtime = {
        "started_at": source_record.get("started_at"),
        "ecr": list(source_record.get("ecr", [])),
        "ecr_engine": source_record.get("ecr_engine"),
    }
    if data["same_key"]:
        source_session_final = _session_final_state(destination_session)
    elif data["keep_source"]:
        upgraded_source = copy.deepcopy(data["source_record"])
        upgraded_lineage = data["source_cache"][3]
        if upgraded_source and upgraded_lineage:
            upgraded_source["login_cache_lineage"] = copy.deepcopy(upgraded_lineage)
            for legacy_name in (
                "login_cache_files",
                "login_cache_directories",
                "login_cache_fingerprints",
            ):
                upgraded_source.pop(legacy_name, None)
            source_session_final = _session_final_state(upgraded_source)
        else:
            source_session_final = copy.deepcopy(data["source_session_expected"])
    elif source_runtime["ecr"]:
        source_session_final = _session_final_state(
            {
                "destination": str(source),
                "profile": source_profile,
                "auth_method": "ecr-only",
                "started_at": source_runtime["started_at"],
                "backup": [],
                "section_backup": {},
                "ecr": source_runtime["ecr"],
                "ecr_engine": source_runtime["ecr_engine"],
            }
        )
    else:
        source_session_final = _session_final_state(None)
    legacy_backup = None
    if data["legacy"]:
        legacy_path = Path(data["legacy"][0]).absolute()
        legacy_backup = {
            "path": str(legacy_path),
            "fingerprint": _file_fingerprint(legacy_path),
        }
    return {
        "schema_version": 2,
        "kind": "assume-role",
        "phase": "prepared",
        "source": {
            "directory": str(source),
            "profile": source_profile,
            "key": data["source_key"],
            "same_key": data["same_key"],
            "keep": data["keep_source"],
            "original": source_original,
            "expected": data["source_expected"],
            "session_expected": data["source_session_expected"],
            "session_final": source_session_final,
            "legacy_backup": legacy_backup,
            "runtime": source_runtime,
        },
        "destination": {
            "directory": str(destination),
            "profile": destination_profile,
            "key": data["destination_key"],
            "original": destination_original,
            "expected": data["destination_expected"],
            "session_expected": data["destination_session_expected"],
            "final": {
                "credentials": section_backup["credentials"]["installed"],
                "config": section_backup["config"]["installed"],
                "config_values": config_values,
            },
            "session": destination_session,
            "session_final": _session_final_state(destination_session),
        },
        "cache": cache,
        "ecr_owners": {},
    }


def _original_section_state(original: dict[str, Any]) -> dict[str, Any]:
    exists = bool(original.get("exists"))
    values = original.get("values", {})
    return {
        "exists": exists,
        "fingerprint": _section_fingerprint(values if exists else None),
    }


def _assume_recovery_error(label: str) -> NoReturn:
    raise _configs.OperationalError(
        f"AssumeRole recovery stopped because {label} changed outside the prepared "
        "transaction. The recovery journal was retained for manual review."
    )


def _require_assume_state(
    label: str, current: dict[str, Any], *allowed: dict[str, Any]
) -> None:
    identity = (current.get("exists"), current.get("fingerprint"))
    if not any(
        identity == (state.get("exists"), state.get("fingerprint")) for state in allowed
    ):
        _assume_recovery_error(label)


def _validate_assume_cache(journal: dict[str, Any], *, allow_missing: bool) -> None:
    for item in journal.get("cache", []):
        path = Path(str(item["path"])).absolute()
        if not path.exists():
            if allow_missing:
                continue
            _assume_recovery_error(f"browser login cache {path}")
        if item.get("legacy_cas_only") or (
            "fingerprint" in item and "schema_version" not in item
        ):
            expected_digest = item.get("whole_digest", item.get("fingerprint"))
            try:
                current_digest = _state.digest(path.read_bytes())
            except OSError:
                _assume_recovery_error(f"browser login cache {path}")
            if current_digest != expected_digest:
                if allow_missing:
                    item["residue_reason"] = "legacy cache fingerprint changed"
                    continue
                _assume_recovery_error(f"browser login cache {path}")
            continue
        try:
            current = _current_browser_cache_content(item)
        except _configs.OperationalError:
            _assume_recovery_error(f"browser login cache {path}")
        if not _same_browser_lineage(item, current):
            if allow_missing:
                item["residue_reason"] = "different browser login generation"
                continue
            _assume_recovery_error(f"browser login cache {path}")
        if allow_missing:
            item["whole_digest"] = current["whole_digest"]
        elif current["whole_digest"] != item.get("whole_digest"):
            _assume_recovery_error(f"browser login cache {path}")


def _validate_assume_legacy(journal: dict[str, Any], *, allow_missing: bool) -> None:
    item = journal["source"].get("legacy_backup")
    if not item:
        return
    path = Path(str(item["path"])).absolute()
    if not path.exists():
        if allow_missing:
            return
        _assume_recovery_error(f"legacy credential backup {path}")
    if _file_fingerprint(path) != item.get("fingerprint"):
        _assume_recovery_error(f"legacy credential backup {path}")


def _validate_assume_recovery(journal: dict[str, Any], *, roll_forward: bool) -> None:
    source = journal["source"]
    destination = journal["destination"]
    destination_directory = Path(destination["directory"])
    destination_profile = str(destination["profile"])
    destination_credentials = _section_state(
        destination_directory / "credentials", destination_profile
    )
    _require_assume_state(
        "destination credential section",
        destination_credentials,
        destination["final"]["credentials"]
        if roll_forward
        else destination["expected"]["credentials"],
    )
    destination_config = _section_state(
        destination_directory / "config",
        _section(destination_profile, config=True),
    )
    if roll_forward:
        _require_assume_state(
            "destination config section",
            destination_config,
            destination["expected"]["config"],
            destination["final"]["config"],
        )
    else:
        _require_assume_state(
            "destination config section",
            destination_config,
            destination["expected"]["config"],
        )

    sessions = _state.load_sessions()
    destination_session = _session_record_state(sessions.get(destination["key"]))
    source_session = _session_record_state(sessions.get(source["key"]))
    if roll_forward:
        _require_assume_state(
            "destination session metadata",
            destination_session,
            destination["session_expected"],
            destination["session_final"],
        )
        _require_assume_state(
            "source session metadata",
            source_session,
            source["session_expected"],
            source["session_final"],
        )
    else:
        _require_assume_state(
            "destination session metadata",
            destination_session,
            destination["session_expected"],
        )
        _require_assume_state(
            "source session metadata",
            source_session,
            source["session_expected"],
        )

    if not source["same_key"]:
        source_directory = Path(source["directory"])
        source_profile = str(source["profile"])
        for kind in ("credentials", "config"):
            current = _section_state(
                source_directory / kind,
                _section(source_profile, config=kind == "config"),
            )
            allowed = [source["expected"][kind]]
            if roll_forward and not source["keep"]:
                allowed.append(_original_section_state(source["original"][kind]))
            _require_assume_state(f"source {kind} section", current, *allowed)
    _validate_assume_cache(journal, allow_missing=roll_forward)
    _validate_assume_legacy(journal, allow_missing=roll_forward)


def _remove_assume_cache(
    journal: dict[str, Any], *, strict: bool = False
) -> list[dict[str, str]]:
    residue = []
    for item in journal.get("cache", []):
        path = Path(str(item["path"])).absolute()
        if not path.exists():
            continue
        if item.get("residue_reason"):
            residue.append({"path": str(path), "reason": str(item["residue_reason"])})
            continue
        if item.get("legacy_cas_only") or (
            "fingerprint" in item and "schema_version" not in item
        ):
            expected_digest = item.get("whole_digest", item.get("fingerprint"))
            try:
                current_digest = _state.digest(path.read_bytes())
            except OSError as error:
                if strict:
                    _assume_recovery_error(f"browser login cache {path}")
                residue.append({"path": str(path), "reason": f"unreadable: {error}"})
                continue
            if current_digest != expected_digest:
                if strict:
                    _assume_recovery_error(f"browser login cache {path}")
                residue.append(
                    {"path": str(path), "reason": "legacy cache fingerprint changed"}
                )
                continue
            try:
                path.unlink()
            except OSError as error:
                if strict:
                    raise _configs.OperationalError(
                        f"Unable to remove owned browser login cache {path}; the "
                        f"AssumeRole recovery journal was retained: {error}"
                    ) from error
                residue.append({"path": str(path), "reason": f"remove failed: {error}"})
            continue
        try:
            current = _current_browser_cache_content(item)
        except _configs.OperationalError as error:
            if strict:
                _assume_recovery_error(f"browser login cache {path}")
            residue.append({"path": str(path), "reason": f"unreadable: {error}"})
            continue
        if not _same_browser_lineage(item, current):
            if strict:
                _assume_recovery_error(f"browser login cache {path}")
            residue.append(
                {"path": str(path), "reason": "different browser login generation"}
            )
            continue
        try:
            unchanged = _state.digest(path.read_bytes()) == current["whole_digest"]
        except OSError as error:
            if strict:
                raise _configs.OperationalError(
                    f"Unable to read owned browser login cache {path}: {error}"
                ) from error
            residue.append({"path": str(path), "reason": f"unreadable: {error}"})
            continue
        if not unchanged:
            if strict:
                _assume_recovery_error(f"browser login cache {path}")
            residue.append(
                {
                    "path": str(path),
                    "reason": "cache changed during compare-and-delete",
                }
            )
            continue
        try:
            path.unlink()
        except OSError as error:
            if strict:
                raise _configs.OperationalError(
                    f"Unable to remove owned browser login cache {path}; the "
                    "AssumeRole recovery journal was retained: {error}"
                ) from error
            residue.append({"path": str(path), "reason": f"remove failed: {error}"})
    return residue


def _write_section_cas(
    path: Path,
    section: str,
    *,
    expected: dict[str, Any],
    final: dict[str, Any],
    values: dict[str, Any],
    label: str,
) -> None:
    current = _section_state(path, section)
    if current == final:
        return
    _require_assume_state(label, current, expected)
    _write_section(path, section, values)
    _require_assume_state(label, _section_state(path, section), final)


def _write_session_cas(
    key: str,
    *,
    expected: dict[str, Any],
    final: dict[str, Any],
    label: str,
) -> None:
    sessions = _state.load_sessions()
    current = _session_record_state(sessions.get(key))
    if (current.get("exists"), current.get("fingerprint")) == (
        final.get("exists"),
        final.get("fingerprint"),
    ):
        return
    _require_assume_state(label, current, expected)
    if final.get("exists"):
        values = final.get("values")
        if not isinstance(values, dict):
            raise _configs.OperationalError(
                "AssumeRole journal final session metadata is invalid."
            )
        sessions[key] = copy.deepcopy(values)
    else:
        sessions.pop(key, None)
    _state.save_sessions(sessions)
    _require_assume_state(label, _current_session_state(key), final)


def _install_assume_destination(journal: dict[str, Any]) -> None:
    _validate_assume_recovery(journal, roll_forward=True)
    destination = journal["destination"]
    directory = Path(destination["directory"])
    profile = str(destination["profile"])
    _write_section_cas(
        directory / "config",
        _section(profile, config=True),
        expected=destination["expected"]["config"],
        final=destination["final"]["config"],
        values={"exists": True, "values": destination["final"]["config_values"]},
        label="destination config section",
    )
    _require_assume_state(
        "destination credential section",
        _section_state(directory / "credentials", profile),
        destination["final"]["credentials"],
    )
    _write_session_cas(
        destination["key"],
        expected=destination["session_expected"],
        final=destination["session_final"],
        label="destination session metadata",
    )


def _finish_assume_source(journal: dict[str, Any]) -> list[dict[str, str]]:
    _validate_assume_recovery(journal, roll_forward=True)
    source = journal["source"]
    same_key = bool(source["same_key"])
    if not source["keep"] and not same_key:
        directory = Path(source["directory"])
        profile = str(source["profile"])
        for kind in ("credentials", "config"):
            final_values = source["original"][kind]
            _write_section_cas(
                directory / kind,
                _section(profile, config=kind == "config"),
                expected=source["expected"][kind],
                final=_original_section_state(final_values),
                values=final_values,
                label=f"source {kind} section",
            )
    legacy = source.get("legacy_backup")
    if legacy and not source["keep"]:
        path = Path(str(legacy["path"])).absolute()
        if path.exists():
            if _file_fingerprint(path) != legacy.get("fingerprint"):
                _assume_recovery_error(f"legacy credential backup {path}")
            path.unlink()
    cache_residue = _remove_assume_cache(journal, strict=False)
    residue_paths = {item["path"] for item in cache_residue}
    source_residue = [
        item
        for item in cache_residue
        if any(
            str(claim.get("path")) == item["path"] and claim.get("owner") == "source"
            for claim in journal.get("cache", [])
        )
    ]
    destination_residue = [
        item
        for item in cache_residue
        if item["path"] not in {value["path"] for value in source_residue}
    ]
    if source_residue and not same_key and not source["keep"]:
        runtime = source.get("runtime", {})
        source_claim = next(
            (
                claim
                for claim in journal.get("cache", [])
                if str(claim.get("path")) in residue_paths
                and claim.get("owner") == "source"
            ),
            None,
        )
        residual = {
            "destination": source["directory"],
            "profile": source["profile"],
            "auth_method": (
                "logout-residue" if runtime.get("ecr") else "browser-cache-residue"
            ),
            "started_at": runtime.get("started_at"),
            "backup": [],
            "section_backup": {},
            "ecr": list(runtime.get("ecr", [])),
            "ecr_engine": runtime.get("ecr_engine"),
            "login_cache_residue": source_residue,
        }
        if source_claim:
            residual["login_cache_lineage"] = {
                key: value
                for key, value in source_claim.items()
                if key not in {"owner", "residue_reason", "config", "profile"}
            }
        source["session_final"] = _session_final_state(residual)
        _write_assume_journal(journal)
    if not same_key:
        _write_session_cas(
            source["key"],
            expected=source["session_expected"],
            final=source["session_final"],
            label="source session metadata",
        )
    if destination_residue:
        destination = journal["destination"]
        current_final = copy.deepcopy(destination["session_final"])
        values = current_final.get("values")
        if isinstance(values, dict):
            values["login_cache_residue"] = destination_residue
            updated = _session_final_state(values)
            _write_session_cas(
                destination["key"],
                expected=destination["session_final"],
                final=updated,
                label="destination session metadata residue",
            )
            destination["session"] = values
            destination["session_final"] = updated
            _write_assume_journal(journal)
    return cache_residue


def _recover_assume_journal(journal: dict[str, Any]) -> None:
    """Recover by finishing restriction/logout, never restoring expanded source auth."""
    if journal.get("schema_version") != 2:
        raise _configs.OperationalError("Unsupported AssumeRole transaction journal.")
    destination = journal["destination"]
    directory = Path(destination["directory"])
    profile = str(destination["profile"])
    credentials = _section_state(directory / "credentials", profile)
    installed = credentials == destination["final"]["credentials"]
    prepared = journal.get("phase") == "prepared"
    if not installed and not (
        prepared and credentials == destination["expected"]["credentials"]
    ):
        _assume_recovery_error("destination credential section")
    _validate_assume_recovery(journal, roll_forward=installed)
    if installed:
        _install_assume_destination(journal)
        residue = _finish_assume_source(journal)
    else:
        residue = []
    _commit()
    if residue:
        raise _configs.OperationalError(
            "AssumeRole recovery installed the restricted destination and removed "
            "the broad source credentials, but preserved an unowned browser cache "
            "generation as browser-cache-residue."
        )


def assume_role(
    context: _configs.Context, prepared: AssumeRolePlan | None = None
) -> _configs.Result:
    """Execute one prepared AssumeRole plan with secret-free roll-forward recovery."""
    plan = prepared or prepare_assume_role(context)
    if not isinstance(plan, AssumeRolePlan):
        raise TypeError("assume_role requires prepare_assume_role output")
    data = plan._data
    if plan._consumed:
        raise AssumePlanChanged(
            "AssumeRole plan has already been consumed; prepare again."
        )
    if plan._arguments_fingerprint != _assume_arguments_fingerprint(context.args):
        raise AssumePlanChanged(
            "AssumeRole plan changed after preview; no local credential changes were "
            "made. Review a fresh preview and retry."
        )
    plan._consumed = True
    credentials, metadata = _assume(
        data["authenticated"],
        data["role"],
        policy=data["policy"],
        source_profile=data["source_profile"],
        args=context.args,
        target=data["target"],
        external_id=data["external_id"],
        boundary_name=data["boundary_name"],
        effective_duration=data["effective_duration"],
        resolved_policy=data["resolved_policy"],
    )
    plan._consumed = False
    _revalidate_assume_plan(context, plan)
    plan._consumed = True
    journal = _build_assume_journal(data, context.args, credentials, metadata)
    _write_assume_journal(journal)
    try:
        destination = cast("Path", data["destination"])
        _validate_assume_recovery(journal, roll_forward=False)
        credential_values = {
            "aws_access_key_id": credentials["AccessKeyId"],
            "aws_secret_access_key": credentials["SecretAccessKey"],
            "aws_session_token": credentials["SessionToken"],
        }
        _write_section_cas(
            destination / "credentials",
            str(data["destination_profile"]),
            expected=journal["destination"]["expected"]["credentials"],
            final=journal["destination"]["final"]["credentials"],
            values={"exists": True, "values": credential_values},
            label="destination credential section",
        )
        _install_assume_destination(journal)
        journal["phase"] = "destination-installed"
        _write_assume_journal(journal)
        cache_residue = _finish_assume_source(journal)
        journal["phase"] = "source-removed"
        _write_assume_journal(journal)
        _commit()
    except Exception:
        persisted = json.loads(_journal_path().read_text(encoding="utf-8"))
        _recover_assume_journal(persisted)
        raise

    ecr_owners: dict[str, tuple[str, list[str]]] = {}
    source_runtime = journal["source"]["runtime"]
    if source_runtime.get("ecr") and not data["same_key"]:
        ecr_owners[data["source_key"]] = (
            str(source_runtime.get("ecr_engine") or "docker"),
            list(source_runtime["ecr"]),
        )
    destination_session = journal["destination"]["session"]
    if destination_session.get("ecr"):
        ecr_owners[data["destination_key"]] = (
            str(destination_session.get("ecr_engine") or "docker"),
            list(destination_session["ecr"]),
        )
    failures = []
    if ecr_owners and not bool(getattr(context.args, "keep_ecr", False)):
        failures = _cleanup_assume_ecr(ecr_owners)
    public = _assume_public_plan(data)
    public.update(
        targetAccount=metadata["target_account"],
        expiresAt=metadata["expires_at"],
        policyProvenance=metadata.get("policy_provenance"),
        ecrResidue=failures,
    )
    if cache_residue:
        public["browserCacheResidue"] = cache_residue
        return _configs.Result(
            "ASSUME_ROLE_BROWSER_CACHE_RESIDUE",
            "Role credentials were installed and the broad source credentials were "
            "removed, but a browser cache with unknown ownership was preserved.",
            1,
            "stderr",
            public,
            kind="warning",
        )
    if failures:
        return _configs.Result(
            "ASSUME_ROLE_ECR_RESIDUE",
            "Role credentials were installed and the local credential handoff "
            "completed, but one or more ECR logouts failed; tracked residue remains.",
            1,
            "stderr",
            public,
            kind="warning",
        )
    return _configs.Result(
        "ASSUME_ROLE",
        f"Assumed {data['role']} into profile {data['destination_profile']}.",
        data=public,
    )


def _location_for_directory(directory: Path) -> str | None:
    absolute = directory.expanduser().absolute()
    default = (Path.home() / ".aws").absolute()
    if absolute == default:
        return "default"
    if absolute.parent == Path.home().absolute() and absolute.name.startswith(".aws-"):
        return absolute.name[5:] or None
    return None


def _managed_section_state(session: dict[str, Any]) -> str | None:
    sections = session.get("section_backup")
    if not isinstance(sections, dict) or not sections:
        return None
    missing = False
    for item in sections.values():
        if not isinstance(item, dict):
            return "drifted"
        path = Path(str(item.get("path", ""))).absolute()
        section = str(item.get("section", ""))
        installed = item.get("installed")
        if not section or not isinstance(installed, dict):
            return "drifted"
        current = _section_state(path, section)
        if current != installed:
            if installed.get("exists") and not current["exists"]:
                missing = True
            else:
                return "drifted"
    return "missing" if missing else None


def _role_display_name(value: object) -> str | None:
    """Shorten a role ARN while preserving its full IAM path."""
    if not isinstance(value, str) or not value.strip():
        return None
    role = value.strip()
    match = re.fullmatch(r"arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/(.+)", role)
    if match:
        return match.group(1)
    if role.casefold().startswith("arn:"):
        return None
    return role


def _cached_policy_source(  # noqa: PLR0911
    identity: str, *, target_account: object
) -> dict[str, Any] | None:
    """Recover display-only policy metadata from a validated local cache entry."""
    try:
        entry = _policies.cache_show(identity)
    except _configs.OperationalError:
        return None
    values = (
        entry.get("origin"),
        entry.get("resolver"),
        entry.get("source_identity"),
    )
    if not all(isinstance(value, str) and value for value in values):
        return None
    origin, resolver, source = (
        str(values[0]),
        str(values[1]),
        str(values[2]),
    )
    display: str | None = None
    arn: str | None = None
    if origin == "local" and resolver == "file":
        expected = "local-" + _state.digest(source.casefold().encode())[:24]
        if identity != expected:
            return None
        display = Path(source).name
    elif origin == "stored" and resolver == "stored":
        if identity != f"stored-{source.casefold()}":
            return None
        display = source
    elif origin in {"aws-managed", "remote-customer"}:
        match = _policies.POLICY_ARN.fullmatch(source)
        if not match:
            return None
        partition, account, resource = match.groups()
        target = str(target_account or "")
        if origin == "aws-managed":
            if resolver != "arn" or account != "aws" or not target:
                return None
            expected = _policies._cache_identity(
                source, account=target, partition=partition
            )
        else:
            if resolver != "name" or account == "aws" or account != target:
                return None
            expected = _policies._cache_identity(
                f"name:{resource.rsplit('/', 1)[-1]}",
                account=account,
                partition=partition,
            )
        if identity != expected:
            return None
        display = resource
        arn = source
    if not display:
        return None
    return {
        "origin": origin,
        "reference": source,
        "arn": arn,
        "cached": True,
        "display": display,
    }


def _policy_scope(session: dict[str, Any]) -> dict[str, Any]:
    """Project persisted policy metadata without resolving anything over the network."""
    policy = session.get("policy")
    if not isinstance(policy, str) or not policy:
        unknown_policy = bool(policy)
        return {
            "label": "session policy" if unknown_policy else None,
            "known": False if unknown_policy else "policy" in session,
            "source": None,
        }
    persisted_display = session.get("policy_display")
    origin = (
        session["policy_origin"]
        if isinstance(session.get("policy_origin"), str)
        else "unknown"
    )
    reference = (
        session["policy_reference"]
        if isinstance(session.get("policy_reference"), str)
        else None
    )
    source_arn = (
        session["policy_arn"] if isinstance(session.get("policy_arn"), str) else None
    )
    if isinstance(persisted_display, str) and persisted_display.strip():
        label = _policy_display_name(
            persisted_display,
            origin,
            source_arn,
        )
        return {
            "label": label,
            "known": label != "session policy",
            "source": {
                "origin": origin,
                "reference": reference,
                "arn": source_arn,
                "cached": bool(session.get("policy_cached", False)),
            },
        }
    policy_text = policy
    provenance = session.get("policy_provenance")
    match = _policies.POLICY_ARN.fullmatch(policy_text)
    if match:
        return {
            "label": match.group(3),
            "known": True,
            "source": {
                "origin": "aws-managed"
                if match.group(2) == "aws"
                else "remote-customer",
                "reference": policy_text,
                "arn": policy_text,
                "cached": False,
            },
        }
    if (
        isinstance(provenance, str)
        and provenance.startswith("stored policy ")
        and provenance.removeprefix("stored policy ") == policy_text
    ):
        return {
            "label": policy_text,
            "known": True,
            "source": {
                "origin": "stored",
                "reference": policy_text,
                "arn": None,
                "cached": False,
            },
        }
    cached = _cached_policy_source(
        policy_text, target_account=session.get("target_account")
    )
    if cached:
        return {
            "label": cached.pop("display"),
            "known": True,
            "source": cached,
        }
    return {
        "label": "session policy",
        "known": False,
        "source": None,
    }


def _effective_scope(session: dict[str, Any]) -> dict[str, Any]:
    """Describe the credential restriction inputs without claiming IAM evaluation."""
    method = session.get("auth_method")
    policy = _policy_scope(session)
    boundary = _role_display_name(session.get("boundary"))
    role = _role_display_name(session.get("role"))
    if method == "ecr-only":
        kind = "ecr-only"
    elif method in {"browser-cache-residue", "logout-residue"}:
        kind = "logout-residue"
    elif role or method in {"browser-boundary", "assume-role"}:
        kind = "role-session"
    elif method == "browser-native":
        kind = "account-login"
    elif method == "mfa":
        kind = "mfa-session"
    elif not session.get("section_backup"):
        kind = "legacy-unknown"
    else:
        kind = "unknown"
    return {
        "kind": kind,
        "role_label": role,
        "boundary_label": boundary,
        "policy_label": policy["label"],
        "policy_source": policy["source"],
        "policy_known": policy["known"],
    }


_PUBLIC_SESSION_STRING_FIELDS = {
    "source_account",
    "source_partition",
    "target_account",
    "target_partition",
    "role",
    "boundary",
    "policy",
    "policy_provenance",
    "policy_reference",
    "policy_origin",
    "policy_arn",
    "policy_display",
    "expires_at",
    "target",
    "profile",
    "auth_method",
    "started_at",
    "ecr_engine",
    "source_profile",
    "source_destination",
    "source_auth_method",
}
_PUBLIC_SESSION_BOOL_FIELDS = {
    "cache_cleanup_incomplete",
    "policy_cached",
    "source_logged_out",
}
_PUBLIC_SESSION_INT_FIELDS = {"session_schema_version"}


def _public_session_fields(session: dict[str, Any]) -> dict[str, Any]:
    """Copy only the documented scalar/list session status contract."""
    public: dict[str, Any] = {}
    for key in _PUBLIC_SESSION_STRING_FIELDS:
        if key in session and (session[key] is None or isinstance(session[key], str)):
            public[key] = session[key]
    for key in _PUBLIC_SESSION_BOOL_FIELDS:
        if key in session and isinstance(session[key], bool):
            public[key] = session[key]
    for key in _PUBLIC_SESSION_INT_FIELDS:
        value = session.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            public[key] = value
    ecr = session.get("ecr")
    if isinstance(ecr, list) and all(isinstance(item, str) for item in ecr):
        public["ecr"] = list(ecr)
    residue = session.get("login_cache_residue")
    if isinstance(residue, list):
        public["login_cache_residue"] = [
            {"path": item["path"], "reason": item["reason"]}
            for item in residue
            if isinstance(item, dict)
            and isinstance(item.get("path"), str)
            and isinstance(item.get("reason"), str)
        ]
    return public


def _public_session(session: dict[str, Any], *, now: datetime) -> dict[str, Any]:
    public = _public_session_fields(session)
    raw_destination = session.get("destination")
    destination = (
        Path(raw_destination).absolute()
        if isinstance(raw_destination, str)
        else (Path.home() / ".aws").absolute()
    )
    public["destination"] = str(destination)
    public["location"] = _location_for_directory(destination)
    public["managed"] = True
    effective_scope = _effective_scope(session)
    public["effective_scope"] = effective_scope
    drift = _managed_section_state(session)
    expiry = public.get("expires_at")
    remaining: int | None = None
    expiry_invalid = False
    if expiry:
        try:
            parsed_expiry = datetime.fromisoformat(str(expiry))
            if parsed_expiry.tzinfo is not None:
                remaining = max(0, math.ceil((parsed_expiry - now).total_seconds()))
            else:
                expiry_invalid = True
        except (TypeError, ValueError):
            remaining = None
            expiry_invalid = True
    public["remaining_seconds"] = remaining
    if expiry_invalid:
        public["warnings"] = [
            {
                "code": "INVALID_EXPIRY",
                "source": "expires_at",
                "message": "Session expiry metadata is invalid.",
            }
        ]
    if public.get("auth_method") in {"browser-cache-residue", "logout-residue"}:
        state = "logout-residue"
    elif public.get("auth_method") == "ecr-only":
        state = "ecr-only"
    elif drift:
        state = drift
    elif not session.get("section_backup"):
        state = "legacy-unverified"
    elif expiry_invalid:
        state = "invalid"
    elif remaining == 0 and expiry:
        state = "expired"
    elif remaining is not None and remaining <= 900:
        state = "expiring"
    else:
        state = "active"
    public["state"] = state
    return public


def status() -> list[dict[str, Any]]:
    """Return secret-free, local-only managed-session status."""
    now = datetime.now(UTC)
    return sorted(
        (_public_session(item, now=now) for item in _state.load_sessions().values()),
        key=lambda item: (str(item.get("destination")), str(item.get("profile"))),
    )


def _verification_expectations(
    item: dict[str, Any],
) -> tuple[str, str, str | None] | None:
    """Return internally consistent expected account, partition, and role name."""
    account = item.get("target_account") or item.get("source_account")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account):
        return None
    partition_value = item.get("target_partition") or item.get("source_partition")
    partition = (
        partition_value
        if isinstance(partition_value, str) and partition_value in _state.PARTITIONS
        else None
    )
    role_name: str | None = None
    role = item.get("role")
    if isinstance(role, str):
        match = re.fullmatch(
            r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/(.+)", role
        )
        if match:
            if match.group(2) != account or (
                partition is not None and match.group(1) != partition
            ):
                return None
            partition = match.group(1)
            role_name = match.group(3).rsplit("/", 1)[-1]
    if partition is None:
        return None
    return account, partition, role_name


def _safe_caller_arn(arn: str, *, account: str, partition: str) -> str | None:
    """Return an identity ARN only when it matches the verified account envelope."""
    if re.fullmatch(
        rf"arn:{re.escape(partition)}:(?:iam|sts)::"
        rf"{re.escape(account)}:[A-Za-z0-9+=,.@_:/-]+",
        arn,
    ):
        return arn
    return None


def _verify_status(item: dict[str, Any]) -> dict[str, Any]:
    if item.get("state") in {
        "ecr-only",
        "logout-residue",
        "missing",
        "drifted",
        "invalid",
    }:
        return {"status": "skipped", "reason": f"local state is {item['state']}"}
    expected = _verification_expectations(item)
    if expected is None:
        return {
            "status": "error",
            "message": (
                "Session metadata does not contain a consistent expected AWS account "
                "and partition."
            ),
        }
    expected_account, expected_partition, expected_role = expected
    directory = Path(str(item["destination"]))
    profile = str(item.get("profile", "default"))
    try:
        with _aws_environment(
            directory / "config", directory / "credentials", _native_login_cache()
        ):
            account, partition, arn = _identity(
                boto3.Session(profile_name=profile), label=f"profile {profile!r}"
            )
    except _configs.OperationalError as error:
        return {"status": "error", "message": str(error)}
    actual_arn = _safe_caller_arn(arn, account=account, partition=partition)
    if actual_arn is None:
        return {
            "status": "error",
            "message": "AWS returned an invalid caller ARN during status verification.",
            "actual_account": account,
            "actual_partition": partition,
        }
    mismatches = []
    if account != expected_account:
        mismatches.append("account")
    if partition != expected_partition:
        mismatches.append("partition")
    actual_role: str | None = None
    if expected_role is not None:
        assumed = re.fullmatch(
            rf"arn:{re.escape(partition)}:sts::{re.escape(account)}:"
            r"assumed-role/([^/]+)/[^/]+",
            actual_arn,
        )
        actual_role = assumed.group(1) if assumed else None
        if actual_role != expected_role:
            mismatches.append("role")
    if mismatches:
        mismatch: dict[str, Any] = {
            "status": "mismatch",
            "reason": f"{', '.join(mismatches)} mismatch",
            "expected_account": expected_account,
            "actual_account": account,
            "expected_partition": expected_partition,
            "actual_partition": partition,
            "actual_arn": actual_arn,
        }
        if expected_role is not None:
            mismatch["expected_role"] = expected_role
            mismatch["actual_role"] = actual_role
        return mismatch
    return {
        "status": "verified",
        "account": account,
        "partition": partition,
        "arn": arn,
    }


def status_report(
    *,
    profile: str | None = None,
    location: str | None = None,
    directory: Path | None = None,
    verify: bool = False,
) -> dict[str, Any]:
    """Return filtered local lifecycle state with optional explicit AWS verification."""
    sessions = status()
    if profile:
        sessions = [item for item in sessions if item.get("profile") == profile]
    if location:
        normalized = _state.normalize_location(location)
        sessions = [item for item in sessions if item.get("location") == normalized]
    if directory:
        wanted = str(directory.expanduser().absolute())
        sessions = [item for item in sessions if item.get("destination") == wanted]
    if verify:
        for item in sessions:
            item["verification"] = _verify_status(item)
    counts: dict[str, int] = {}
    for item in sessions:
        state = str(item["state"])
        counts[state] = counts.get(state, 0) + 1
    return {"sessions": sessions, "counts": counts, "warnings": []}


def _known_directories() -> dict[Path, str | None]:
    directories: dict[Path, str | None] = {(Path.home() / ".aws").absolute(): "default"}
    try:
        for path in Path.home().glob(".aws-*"):
            if path.is_dir():
                directories[path.absolute()] = path.name[5:] or None
    except OSError:
        pass
    data = _state.load_config()
    for target in data["targets"].values():
        for prefix in ("source", "destination"):
            raw_directory = target.get(f"{prefix}_directory")
            raw_location = target.get(f"{prefix}_location")
            if raw_directory:
                path = Path(str(raw_directory)).expanduser().absolute()
                directories.setdefault(path, None)
            elif raw_location:
                path = _state.aws_directory(str(raw_location)).absolute()
                directories.setdefault(
                    path, _state.normalize_location(str(raw_location))
                )
    for session in _state.load_sessions().values():
        if session.get("destination"):
            path = Path(str(session["destination"])).absolute()
            directories.setdefault(path, _location_for_directory(path))
    return directories


def profile_inventory(
    patterns: list[str] | None = None, *, verify: bool = False
) -> dict[str, Any]:
    """Enumerate local profile names without reading or returning credential values."""
    warnings: list[dict[str, str]] = []
    found: dict[tuple[str, str], dict[str, Any]] = {}
    managed = {
        (str(item["destination"]), str(item.get("profile", "default"))): item
        for item in status()
    }
    for directory, location in _known_directories().items():
        names: set[str] = set()
        for filename, is_config in (("credentials", False), ("config", True)):
            path = directory / filename
            try:
                parser = _read_ini(path)
            except _configs.OperationalError as error:
                warnings.append({"path": str(path), "message": str(error)})
                continue
            for section in parser.sections():
                if is_config:
                    if section == "default":
                        names.add("default")
                    elif section.startswith("profile ") and section[8:]:
                        names.add(section[8:])
                else:
                    names.add(section)
        if directory.exists():
            try:
                for path in directory.glob("*.store.credentials"):
                    names.add(path.name[: -len(".store.credentials")])
            except OSError as error:
                warnings.append({"path": str(directory), "message": str(error)})
        for destination, profile_name in managed:
            if destination == str(directory):
                names.add(profile_name)
        for profile_name in names:
            key = (str(directory), profile_name)
            lifecycle = managed.get(key)
            legacy = (directory / f"{profile_name}.store.credentials").is_file()
            found[key] = {
                "location": location,
                "directory": str(directory),
                "profile": profile_name,
                "managed": lifecycle is not None or legacy,
                "state": (
                    lifecycle["state"]
                    if lifecycle
                    else "legacy-unverified"
                    if legacy
                    else "unmanaged"
                ),
                "auth_method": (
                    lifecycle.get("auth_method")
                    if lifecycle
                    else "legacy-mfa"
                    if legacy
                    else None
                ),
            }
    profiles = sorted(
        found.values(),
        key=lambda item: (
            str(item.get("location") or "~"),
            str(item["directory"]),
            str(item["profile"]),
        ),
    )
    if patterns:
        profiles = [
            item
            for item in profiles
            if any(
                fnmatch.fnmatchcase(candidate.casefold(), pattern.casefold())
                for pattern in patterns
                for candidate in (
                    str(item["profile"]),
                    f"{item.get('location') or item['directory']}:{item['profile']}",
                )
            )
        ]
    if verify:
        for item in profiles:
            item["verification"] = _verify_status(
                {
                    **item,
                    "destination": item["directory"],
                }
            )
    return {"profiles": profiles, "count": len(profiles), "warnings": warnings}


def _restore_profile_sections(
    session: dict[str, Any], destination: Path, profile: str, *, force: bool
) -> None:
    plans = _profile_section_plans(session, destination, profile, force=force)
    _apply_profile_section_plans(plans)


def _profile_section_plans(
    session: dict[str, Any], destination: Path, profile: str, *, force: bool
) -> list[tuple[Path, str, dict[str, Any]]]:
    sections = session.get("section_backup")
    if not isinstance(sections, dict) or not sections:
        snapshots = {
            Path(str(item.get("path", ""))).absolute(): item
            for item in session.get("backup", [])
            if isinstance(item, dict)
        }
        relevant = any(
            (destination / filename).absolute() in snapshots
            for filename in ("credentials", "config")
        )
        if relevant and not force:
            raise _configs.OperationalError(
                "This legacy session has no installed-section fingerprint; retry "
                "with --force to restore only its recorded profile sections."
            )
        if not relevant:
            return []
        sections = {}
        for kind, filename, is_config in (
            ("credentials", "credentials", False),
            ("config", "config", True),
        ):
            path = (destination / filename).absolute()
            snapshot = snapshots.get(path)
            if snapshot is None:
                continue
            raw = base64.b64decode(snapshot["data"]) if snapshot.get("exists") else None
            parser = _parser_from_bytes(raw, path)
            section = _section(profile, config=is_config)
            values = _section_values(parser, section)
            sections[kind] = {
                "path": str(path),
                "section": section,
                "original": {"exists": values is not None, "values": values or {}},
            }
    plans: list[tuple[Path, str, dict[str, Any]]] = []
    for kind, item in sections.items():
        if not isinstance(item, dict):
            raise _configs.OperationalError("Managed session section state is invalid.")
        expected_path = (
            destination / ("config" if kind == "config" else "credentials")
        ).absolute()
        path = Path(str(item.get("path", ""))).absolute()
        expected_section = _section(profile, config=kind == "config")
        if path != expected_path or item.get("section") != expected_section:
            raise _configs.OperationalError(
                "Managed session section state does not match its destination."
            )
        installed = item.get("installed")
        if not force and (
            isinstance(installed, dict)
            and _section_state(path, expected_section) != installed
        ):
            raise _configs.OperationalError(
                f"Profile {profile!r} changed after login in {path}; retry with "
                "--force only after reviewing the local changes."
            )
        original = item.get("original")
        if not isinstance(original, dict):
            raise _configs.OperationalError(
                "Managed session original section is invalid."
            )
        plans.append((path, expected_section, original))
    return plans


def _apply_profile_section_plans(
    plans: list[tuple[Path, str, dict[str, Any]]],
) -> None:
    for path, section, original in plans:
        parser = _read_ini(path)
        if original.get("exists"):
            values = original.get("values")
            if not isinstance(values, dict):
                raise _configs.OperationalError(
                    "Managed session original section values are invalid."
                )
            parser[section] = {str(key): str(value) for key, value in values.items()}
        else:
            parser.remove_section(section)
        _write_ini(path, parser)


def _upgrade_legacy_browser_lineage(
    destination: Path,
    profile: str,
    root: Path,
    removals: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Bind an exact legacy cache claim to stable lineage when AWS can verify it."""
    config = destination / "config"
    try:
        candidate = _browser_cache_lineage(config, profile, root)
    except _configs.OperationalError:
        return None
    owned = next(
        (
            claim
            for claim in removals
            if _canonical_path(Path(str(claim.get("path", ""))))
            == _canonical_path(Path(str(candidate["path"])))
            and claim.get("whole_digest") == candidate.get("whole_digest")
        ),
        None,
    )
    if owned is None:
        return None
    try:
        with _aws_environment(
            destination / "config", destination / "credentials", root
        ):
            active = boto3.Session(profile_name=profile)
            identity = _identity(active, label="legacy browser login cache ownership")
        current = _browser_cache_lineage(config, profile, root, identity=identity)
    except _configs.OperationalError:
        return None
    if not _same_browser_lineage(candidate, current) or current.get(
        "whole_digest"
    ) != owned.get("whole_digest"):
        return None
    return current


def _tracked_login_cache_plan(  # noqa: PLR0911
    session: dict[str, Any],
    destination: Path,
    profile: str = "default",
    *,
    force: bool,
) -> tuple[
    list[Path], list[dict[str, Any]], list[dict[str, str]], dict[str, Any] | None
]:
    if session.get("auth_method") not in {
        "browser-native",
        "browser-cache-residue",
        "logout-residue",
    }:
        return [], [], [], None
    stored = session.get("login_cache_lineage")
    if isinstance(stored, dict) and stored.get("legacy_cas_only"):
        path = _canonical_path(Path(str(stored.get("path", ""))))
        roots = [_canonical_path(Path(str(stored.get("root", path.parent))))]
        if not path.exists():
            return roots, [], [], None
        try:
            current_digest = _state.digest(path.read_bytes())
        except OSError as error:
            legacy_residue = [{"path": str(path), "reason": f"unreadable: {error}"}]
        else:
            if current_digest == stored.get("whole_digest"):
                return roots, [copy.deepcopy(stored)], [], None
            legacy_residue = [
                {
                    "path": str(path),
                    "reason": "legacy cache fingerprint changed after login",
                }
            ]
        if not force:
            raise _configs.OperationalError(
                "Tracked browser login cache changed after login; no logout changes "
                "were made. Review the cache or retry with --force: "
                f"{legacy_residue[0]['reason']}"
            )
        return roots, [], legacy_residue, None
    if isinstance(stored, dict) and stored.get("schema_version") == 1:
        allowed_roots = [_canonical_path(Path(str(stored.get("root", ""))))]
    else:
        configured_roots = session.get("login_cache_directories") or [
            str((destination / "login" / "cache").absolute())
        ]
        allowed_roots = [
            _canonical_path(Path(str(value))) for value in configured_roots
        ]
    removals: list[dict[str, Any]] = []
    residue: list[dict[str, str]] = []
    legacy_files = session.get("login_cache_files", [])
    legacy_fingerprints = session.get("login_cache_fingerprints", {})
    if not isinstance(stored, dict) and isinstance(legacy_files, list):
        for value in legacy_files:
            path = _canonical_path(Path(str(value)))
            in_scope = any(
                root == path.parent or root in path.parents for root in allowed_roots
            )
            expected = (
                legacy_fingerprints.get(str(path))
                if isinstance(legacy_fingerprints, dict)
                else None
            )
            if not in_scope:
                residue.append(
                    {"path": str(path), "reason": "outside tracked cache roots"}
                )
                continue
            if not path.exists():
                continue
            try:
                current_digest = _state.digest(path.read_bytes())
            except OSError as error:
                residue.append({"path": str(path), "reason": f"unreadable: {error}"})
                continue
            if not isinstance(expected, str) or current_digest != expected:
                residue.append(
                    {
                        "path": str(path),
                        "reason": "legacy cache fingerprint changed after login",
                    }
                )
                continue
            removals.append(
                {
                    "schema_version": 0,
                    "legacy_cas_only": True,
                    "root": str(path.parent),
                    "path": str(path),
                    "whole_digest": current_digest,
                }
            )
        if residue and not force:
            details = "; ".join(f"{item['path']}: {item['reason']}" for item in residue)
            raise _configs.OperationalError(
                "Tracked browser login cache changed after login; no logout changes "
                f"were made. Review the cache or retry with --force: {details}"
            )
        if legacy_files:
            upgraded = _upgrade_legacy_browser_lineage(
                destination, profile, allowed_roots[0], removals
            )
            if upgraded is None:
                return allowed_roots, removals, residue, None
            upgraded_path = _canonical_path(Path(str(upgraded["path"])))
            removals = [
                claim
                for claim in removals
                if _canonical_path(Path(str(claim["path"]))) != upgraded_path
            ]
            removals.append(upgraded)
            return allowed_roots, removals, residue, upgraded
    config = destination / "config"
    try:
        root = allowed_roots[0]
        current = _browser_cache_lineage(config, profile, root)
    except _configs.OperationalError as error:
        if isinstance(stored, dict):
            try:
                current = _current_browser_cache_content(stored)
            except _configs.OperationalError:
                residue.append({"path": str(allowed_roots[0]), "reason": str(error)})
                current = None
            else:
                if current.get("whole_digest") != stored.get("whole_digest"):
                    residue.append(
                        {
                            "path": str(current["path"]),
                            "reason": (
                                "browser cache rotated after its profile was removed; "
                                "ownership cannot be reverified"
                            ),
                        }
                    )
                    current = None
        else:
            residue.append({"path": str(allowed_roots[0]), "reason": str(error)})
            current = None
    if current is not None:
        if isinstance(stored, dict) and not _same_browser_lineage(stored, current):
            residue.append(
                {
                    "path": str(current["path"]),
                    "reason": "browser cache belongs to a different login generation",
                }
            )
        else:
            # A whole-file digest change is expected during refresh. Establish the
            # current caller before accepting the rotated bytes as the same owner.
            needs_identity = not isinstance(stored, dict) or (
                current.get("whole_digest") != stored.get("whole_digest")
            )
            identity: tuple[str, str, str] | None = None
            if needs_identity:
                try:
                    with _aws_environment(
                        destination / "config",
                        destination / "credentials",
                        root,
                    ):
                        active = boto3.Session(profile_name=profile)
                        identity = _identity(
                            active, label="browser login cache ownership"
                        )
                    current = _browser_cache_lineage(
                        config, profile, root, identity=identity
                    )
                except _configs.OperationalError as error:
                    residue.append({"path": str(current["path"]), "reason": str(error)})
                    current = None
            if current is not None:
                account = str(
                    (stored or {}).get("account")
                    or session.get("source_account")
                    or session.get("target_account")
                    or ""
                )
                partition = str(
                    (stored or {}).get("partition")
                    or session.get("source_partition")
                    or session.get("target_partition")
                    or ""
                )
                principal = str((stored or {}).get("principal") or "")
                if identity is not None and (
                    (account and identity[0] != account)
                    or (partition and identity[1] != partition)
                    or (principal and identity[2] != principal)
                ):
                    residue.append(
                        {
                            "path": str(current["path"]),
                            "reason": "GetCallerIdentity does not match tracked browser lineage",
                        }
                    )
                    current = None
                elif isinstance(stored, dict) and not _same_browser_lineage(
                    stored, current
                ):
                    residue.append(
                        {
                            "path": str(current["path"]),
                            "reason": "browser cache changed generation during verification",
                        }
                    )
                    current = None
            if current is not None:
                if identity is not None:
                    current.update(
                        account=identity[0],
                        partition=identity[1],
                        principal=identity[2],
                    )
                elif isinstance(stored, dict):
                    current.update(
                        account=stored.get("account", ""),
                        partition=stored.get("partition", ""),
                        principal=stored.get("principal", ""),
                    )
                removals.append(current)
    if residue and not force:
        details = "; ".join(f"{item['path']}: {item['reason']}" for item in residue)
        raise _configs.OperationalError(
            "Tracked browser login cache changed after login; no logout changes were "
            f"made. Review the cache or retry with --force: {details}"
        )
    return allowed_roots, removals, residue, current


def _remove_tracked_login_cache(
    removals: list[dict[str, Any]], residue: list[dict[str, str]], *, force: bool
) -> list[dict[str, str]]:
    del force  # Force never authorizes deleting an unknown or different generation.
    for claim in removals:
        cache_file = Path(str(claim["path"]))
        try:
            if _state.digest(cache_file.read_bytes()) != claim.get("whole_digest"):
                residue.append(
                    {
                        "path": str(cache_file),
                        "reason": "browser cache changed during compare-and-delete",
                    }
                )
                continue
            cache_file.unlink()
        except OSError as error:
            residue.append(
                {"path": str(cache_file), "reason": f"remove failed: {error}"}
            )
    return residue


def _matches_except(session: dict[str, Any], excluded: set[str]) -> bool:
    if not excluded:
        return False
    profile = str(session.get("profile", "default"))
    destination = Path(str(session.get("destination", Path.home() / ".aws")))
    location = session.get("location") or _location_for_directory(destination)
    candidates = {profile, f"{location or destination}:{profile}"}
    target_name = session.get("target")
    if target_name:
        candidates.add(f"+{str(target_name).lstrip('+')}")
    try:
        for name, target in _state.load_config()["targets"].items():
            source = (
                Path(str(target["source_directory"])).expanduser().absolute()
                if target.get("source_directory")
                else _state.aws_directory(target.get("source_location"))
            )
            target_destination = (
                Path(str(target["destination_directory"])).expanduser().absolute()
                if target.get("destination_directory")
                else _state.aws_directory(target["destination_location"])
                if target.get("destination_location")
                else source
            )
            target_profile = _normalize_profile(
                target.get("destination_profile", target.get("source_profile"))
            )
            if (
                target_destination == destination.absolute()
                and target_profile == profile
            ):
                candidates.add(f"+{name}")
    except _configs.OperationalError:
        pass
    return any(
        fnmatch.fnmatchcase(candidate.casefold(), pattern.casefold())
        for candidate in candidates
        for pattern in excluded
    )


def matches_logout_exclusion(
    *, destination: str, profile: str, excluded: set[str], location: str | None = None
) -> bool:
    """Match bulk-logout selectors without exposing credential contents."""
    return _matches_except(
        {"destination": destination, "profile": profile, "location": location}, excluded
    )


def _logout_key(key: str, args: Any) -> dict[str, Any]:
    sessions = _state.load_sessions()
    session = sessions.get(key)
    if not session:
        return {"key": key, "state": "not-managed", "changed": False}
    destination = Path(str(session["destination"])).absolute()
    profile = str(session.get("profile", "default"))
    if _matches_except(session, set(getattr(args, "except_profiles", []) or [])):
        return {"key": key, "state": "excluded", "changed": False}
    keep_ecr = bool(getattr(args, "keep_ecr", False))
    force = bool(getattr(args, "force", False))
    registries = list(session.get("ecr", []))
    plans = _profile_section_plans(session, destination, profile, force=force)
    _cache_roots, cache_removals, cache_residue, _ = _tracked_login_cache_plan(
        session, destination, profile, force=force
    )
    journal = _begin(
        [destination / "credentials", destination / "config", _state.sessions_path()]
    )
    residual: dict[str, Any] = {
        "destination": str(destination),
        "profile": profile,
        "auth_method": "ecr-only",
        "started_at": session.get("started_at"),
        "backup": [],
        "section_backup": {},
        "ecr": registries,
        "ecr_engine": session.get("ecr_engine"),
    }
    lineage = session.get("login_cache_lineage")
    pending_cache = [
        *cache_residue,
        *(
            {
                "path": str(claim["path"]),
                "reason": "browser cache cleanup pending",
            }
            for claim in cache_removals
        ),
    ]
    if pending_cache:
        residual.update(
            auth_method="logout-residue" if registries else "browser-cache-residue",
            login_cache_residue=pending_cache,
        )
        if isinstance(lineage, dict):
            residual["login_cache_lineage"] = copy.deepcopy(lineage)
    try:
        _apply_profile_section_plans(plans)
        if registries or pending_cache:
            sessions[key] = residual
        else:
            del sessions[key]
        _state.save_sessions(sessions)
        _commit()
    except Exception:
        _rollback(journal)
        raise
    cache_residue = _remove_tracked_login_cache(
        cache_removals, cache_residue, force=force
    )
    sessions = _state.load_sessions()
    if cache_residue:
        residual.update(
            auth_method="logout-residue" if registries else "browser-cache-residue",
            login_cache_residue=cache_residue,
        )
        if isinstance(lineage, dict):
            residual["login_cache_lineage"] = copy.deepcopy(lineage)
        sessions[key] = residual
    elif registries:
        residual.pop("login_cache_residue", None)
        residual.pop("login_cache_lineage", None)
        residual["auth_method"] = "ecr-only"
        sessions[key] = residual
    else:
        sessions.pop(key, None)
    _state.save_sessions(sessions)
    if registries and not keep_ecr:
        engine = cast(
            "_configs.ContainerEngine",
            str(
                session.get("ecr_engine")
                or ("podman" if getattr(args, "podman", False) else "docker")
            ),
        )
        remaining = list(registries)
        for registry in registries:
            try:
                _ecr._run_container_engine(engine, [engine, "logout", registry])
            except _configs.OperationalError:
                sessions = _state.load_sessions()
                sessions[key] = {**residual, "ecr": remaining}
                _state.save_sessions(sessions)
                raise
            remaining.remove(registry)
            sessions = _state.load_sessions()
            if remaining:
                sessions[key] = {**residual, "ecr": remaining}
            elif cache_residue:
                sessions[key] = {**residual, "ecr": []}
            else:
                sessions.pop(key, None)
            _state.save_sessions(sessions)
    return {
        "key": key,
        "destination": str(destination),
        "profile": profile,
        "state": (
            "logout-residue"
            if cache_residue
            else "ecr-only"
            if registries and keep_ecr
            else "logged-out"
        ),
        "residue": cache_residue,
        "changed": True,
    }


def logout(context: _configs.Context) -> bool:
    """Restore one managed session locally using compare-and-swap sections."""
    _source, _source_profile, destination, profile = _paths(context.args)
    key = f"{destination.absolute()}::{profile}"
    return bool(_logout_key(key, context.args)["changed"])


def logout_all(args: Any) -> dict[str, Any]:
    """Log out every managed session except explicit profile selectors."""
    outcomes = []
    errors = []
    for key in sorted(_state.load_sessions()):
        try:
            outcomes.append(_logout_key(key, args))
        except _configs.OperationalError as error:
            errors.append({"key": key, "message": str(error)})
    return {"outcomes": outcomes, "errors": errors}


def explain_target(value: str) -> dict[str, Any]:
    """Resolve a target without authenticating."""
    data = _state.load_config()
    name, target = _state.get_resource(data, "target", value.lstrip("+"))
    account_name, account = _state.get_resource(
        data, "account", target["source_account"]
    )
    source_directory = target.get("source_directory") or str(
        _state.aws_directory(target.get("source_location"))
    )
    destination_directory = target.get("destination_directory")
    if not destination_directory:
        destination_directory = (
            str(_state.aws_directory(target["destination_location"]))
            if target.get("destination_location")
            else source_directory
        )
    result: dict[str, Any] = {
        "target": name,
        "source": {
            "account": account_name,
            "account_id": account["id"],
            "partition": account["partition"],
            "profile": target.get("source_profile", "default"),
            "directory": source_directory,
        },
        "destination": {
            "profile": target.get(
                "destination_profile", target.get("source_profile", "default")
            ),
            "directory": destination_directory,
        },
        "cache_max_age": data["cache"]["max_age"],
    }
    if target.get("boundary"):
        boundary_name, boundary = _state.get_resource(
            data, "boundary", target["boundary"]
        )
        result["boundary"] = {
            "name": boundary_name,
            **boundary,
            "duration": boundary.get("duration", 3600),
        }
    else:
        result["boundary"] = None
    return result


def check_config(args: Any) -> dict[str, Any]:
    """Run config checks without leaking credential environment mutations."""
    previous = {key: os.environ.get(key) for key in _CONFLICTING_ENV}
    try:
        return _check_config(args)
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _check_config(args: Any) -> dict[str, Any]:
    """Check local integrity and optionally verify account-scoped remote resources."""
    errors: list[str] = []
    warnings: list[str] = []
    try:
        data = _state.load_config()
    except _configs.OperationalError as error:
        return {"ok": False, "errors": [str(error)], "warnings": []}
    remote = bool(getattr(args, "remote", False) or getattr(args, "probe", False))
    scoped_accounts: set[str] = set()
    if getattr(args, "account", None):
        account_name, _ = _state.get_resource(data, "account", args.account)
        scoped_accounts.add(account_name.casefold())
    check_session: Any | None = None
    profile = "default"
    account: str | None = None
    partition: str | None = None
    if remote:
        try:
            selector = _configs.resolve_credential_selector(args)
            profile = selector.profile
            if selector.target:
                target_name, target = _state.get_resource(
                    data, "target", selector.target.lstrip("+")
                )
                profile = target.get("source_profile", "default")
                source_directory = (
                    Path(target["source_directory"])
                    if target.get("source_directory")
                    else _state.aws_directory(target.get("source_location"))
                )
                warnings.append(f"Using target {target_name} credential source.")
            else:
                source_directory = selector.directory or _state.aws_directory(
                    selector.location
                )
            os.environ["AWS_CONFIG_FILE"] = str(source_directory / "config")
            os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(
                source_directory / "credentials"
            )
            check_session = boto3.Session(profile_name=profile)
            account, partition, _ = _identity(check_session, label="config check")
            if not scoped_accounts:
                scoped_accounts = {
                    name.casefold()
                    for name, configured in data["accounts"].items()
                    if configured["id"] == account
                    and configured["partition"] == partition
                }
        except _configs.OperationalError as error:
            errors.append(f"Remote resources unverifiable: {error}")
    scoped_policies: set[str] | None = None
    if getattr(args, "account", None) or remote:
        scoped_policies = {
            str(boundary["policy"])
            for boundary in data["boundaries"].values()
            if str(boundary["account"]).casefold() in scoped_accounts
            and boundary.get("policy")
        }
    for name in data["policies"]:
        if scoped_policies is not None and not any(
            name.casefold() == policy.casefold() for policy in scoped_policies
        ):
            continue
        try:
            _policies.parse_policy(_policies.stored_directory() / f"{name}.yaml")
        except _configs.OperationalError as error:
            errors.append(str(error))
    if (
        remote
        and check_session is not None
        and account is not None
        and partition is not None
    ):
        try:
            if getattr(args, "account", None):
                _, configured = _state.get_resource(data, "account", args.account)
                if configured["id"] != account or configured["partition"] != partition:
                    errors.append(
                        f"Selected account does not match caller {partition}:{account}."
                    )
            iam = check_session.client("iam")
            scoped_boundaries: list[tuple[str, dict[str, Any]]] = []
            for name, boundary in data["boundaries"].items():
                _, configured = _state.get_resource(
                    data, "account", boundary["account"]
                )
                if configured["id"] != account or configured["partition"] != partition:
                    continue
                scoped_boundaries.append((name, boundary))
                role_name = boundary["role_arn"].split("role/", 1)[-1]
                try:
                    iam.get_role(RoleName=role_name)
                except ClientError as error:
                    code = error.response.get("Error", {}).get("Code")
                    label = "missing" if code == "NoSuchEntity" else "unverifiable"
                    errors.append(f"Boundary {name}: {label} ({error}).")
                except BotoCoreError as error:
                    errors.append(f"Boundary {name}: unverifiable ({error}).")
                if boundary.get("policy"):
                    try:
                        _policies.resolve(
                            str(boundary["policy"]),
                            account_id=account,
                            partition=partition,
                            profile=profile,
                            session=check_session,
                        )
                    except _configs.OperationalError as error:
                        errors.append(f"Boundary {name} policy: {error}")
            if getattr(args, "probe", False):
                deny_all = json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "*",
                                "Resource": "*",
                            }
                        ],
                    },
                    separators=(",", ":"),
                )
                sts = check_session.client("sts")
                for name, boundary in scoped_boundaries:
                    request: dict[str, Any] = {
                        "RoleArn": boundary["role_arn"],
                        "RoleSessionName": _session_name(
                            boundary["role_arn"], name, "hacksaws-config-probe"
                        ),
                        "DurationSeconds": 900,
                        "Policy": deny_all,
                    }
                    if boundary.get("external_id"):
                        request["ExternalId"] = boundary["external_id"]
                    try:
                        sts.assume_role(**request)
                    except (BotoCoreError, ClientError) as error:
                        errors.append(f"Boundary {name} probe failed: {error}")
                    else:
                        warnings.append(
                            f"Boundary {name} deny-all AssumeRole probe succeeded; "
                            "credentials were discarded."
                        )
        except _configs.OperationalError as error:
            errors.append(f"Remote resources unverifiable: {error}")
    return {"ok": not errors, "errors": errors, "warnings": warnings}


def fix_config(args: Any) -> _configs.Result:
    """Back up, then interactively repair/leave/remove local non-security issues."""
    data = _state.load_config()
    scope_message = ""
    if args.account:
        account_name, _ = _state.get_resource(data, "account", args.account)
        scope_message = f" for account {account_name}"
    path = _state.root() / "config.json"
    if path.exists():
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup = _state.root() / "backups" / f"config-{stamp}.json"
        _state.atomic_write(backup, path.read_bytes())
    issues: list[tuple[str, str, str]] = []
    scoped_policies: set[str] | None = None
    scoped_account_names: set[str] = set()
    if args.account:
        scoped_account_names.add(account_name.casefold())
    elif getattr(args, "remote", False) or getattr(args, "probe", False):
        try:
            selector = _configs.resolve_credential_selector(args)
            profile = selector.profile
            if selector.target:
                _, target = _state.get_resource(
                    data, "target", selector.target.lstrip("+")
                )
                profile = str(target.get("source_profile", "default"))
                source_directory = (
                    Path(str(target["source_directory"])).expanduser().absolute()
                    if target.get("source_directory")
                    else _state.aws_directory(target.get("source_location"))
                )
            else:
                source_directory = selector.directory or _state.aws_directory(
                    selector.location
                )
            with _aws_environment(
                source_directory / "config",
                source_directory / "credentials",
                _native_login_cache(),
            ):
                caller_account, caller_partition, _ = _identity(
                    boto3.Session(profile_name=profile), label="config fix"
                )
            scoped_account_names = {
                name.casefold()
                for name, configured in data["accounts"].items()
                if configured["id"] == caller_account
                and configured["partition"] == caller_partition
            }
        except _configs.OperationalError:
            scoped_account_names = set()
    if args.account or getattr(args, "remote", False) or getattr(args, "probe", False):
        scoped_policies = {
            str(boundary["policy"])
            for boundary in data["boundaries"].values()
            if str(boundary["account"]).casefold() in scoped_account_names
            and boundary.get("policy")
        }
    for name in data["policies"]:
        if scoped_policies is not None and not any(
            name.casefold() == policy.casefold() for policy in scoped_policies
        ):
            continue
        try:
            _policies.parse_policy(_policies.stored_directory() / f"{name}.yaml")
        except _configs.OperationalError as error:
            issues.append(("policy", name, str(error)))
    unresolved: list[str] = []
    for kind, name, message in issues:
        if args.yes or not sys.stdin.isatty():
            unresolved.append(message)
            continue
        dependents = _state.references(data, kind, name)
        answer = (
            input(
                f"Issue {kind}:{name}: {message}\nDependents: "
                f"{', '.join(dependents) or '(none)'}\n"
                "Choose repair, leave, or remove [r/l/x]: "
            )
            .strip()
            .casefold()
        )
        if answer in {"r", "repair"}:
            replacement = Path(
                input("Replacement policy file path: ").strip()
            ).expanduser()
            try:
                document, raw = _policies.parse_policy(replacement)
                content = (
                    raw
                    if replacement.suffix.lower() in {".yaml", ".yml"}
                    else yaml.safe_dump(document, sort_keys=False).encode()
                )
                _state.atomic_write(
                    _policies.stored_directory() / f"{name}.yaml", content
                )
            except _configs.OperationalError as error:
                unresolved.append(f"Repair for policy {name!r} failed: {error}")
        elif answer in {"x", "remove"} and not dependents:
            del data[_state.collection_name(kind)][name]
            (_policies.stored_directory() / f"{name}.yaml").unlink(missing_ok=True)
        else:
            unresolved.append(message)
    if getattr(args, "remote", False) or getattr(args, "probe", False):
        report = _check_config(args)
        local_messages = {message for _kind, _name, message in issues}
        for message in report["errors"]:
            if message in local_messages:
                continue
            boundary_match = re.match(r"Boundary ([^:]+):", message)
            boundary_policy_match = re.match(r"Boundary ([^:]+) policy:", message)
            kind = (
                "boundary-policy"
                if boundary_policy_match
                else "boundary"
                if boundary_match
                else "account"
                if message.startswith("Selected account does not match caller ")
                else "remote"
            )
            name = (
                boundary_policy_match.group(1)
                if boundary_policy_match
                else boundary_match.group(1)
                if boundary_match
                else str(getattr(args, "account", "verification"))
            )
            if args.yes or not sys.stdin.isatty():
                unresolved.append(message)
                continue
            answer = (
                input(
                    f"Issue {kind}:{name}: {message}\n"
                    "Choose update, leave, or remove [u/l/x]: "
                )
                .strip()
                .casefold()
            )
            if answer in {"u", "update", "r", "repair"} and kind == "boundary":
                role_arn = input("Replacement role ARN: ").strip()
                if not re.fullmatch(r"arn:[^:]+:iam::\d{12}:role/.+", role_arn):
                    unresolved.append(
                        f"Update for boundary {name!r} failed: replacement must be "
                        "a complete IAM role ARN."
                    )
                    continue
                canonical, boundary = _state.get_resource(data, "boundary", name)
                boundary["role_arn"] = role_arn
                data["boundaries"][canonical] = boundary
            elif answer in {"u", "update", "r", "repair"} and kind == "boundary-policy":
                policy = input("Replacement policy name, ARN, or file: ").strip()
                canonical, boundary = _state.get_resource(data, "boundary", name)
                if policy:
                    boundary["policy"] = policy
                else:
                    boundary.pop("policy", None)
                data["boundaries"][canonical] = boundary
            elif answer in {"u", "update", "r", "repair"} and kind == "account":
                caller = re.search(r"caller ([^:]+):(\d{12})", message)
                if not caller:
                    unresolved.append(message)
                    continue
                canonical, account = _state.get_resource(data, "account", name)
                account.update(partition=caller.group(1), id=caller.group(2))
                data["accounts"][canonical] = account
                for boundary in data["boundaries"].values():
                    if (
                        str(boundary.get("account", "")).casefold()
                        != canonical.casefold()
                    ):
                        continue
                    role_path = str(boundary["role_arn"]).split(":role/", 1)[-1]
                    boundary["role_arn"] = (
                        f"arn:{caller.group(1)}:iam::{caller.group(2)}:role/{role_path}"
                    )
            elif answer in {"x", "remove"} and kind in {
                "boundary",
                "boundary-policy",
                "account",
            }:
                resource_kind = "boundary" if kind == "boundary-policy" else kind
                canonical, _ = _state.get_resource(data, resource_kind, name)
                removed_boundaries: set[str] = set()
                if resource_kind == "boundary":
                    removed_boundaries.add(canonical.casefold())
                else:
                    removed_boundaries = {
                        key.casefold()
                        for key, value in data["boundaries"].items()
                        if str(value.get("account", "")).casefold()
                        == canonical.casefold()
                    }
                    data["boundaries"] = {
                        key: value
                        for key, value in data["boundaries"].items()
                        if key.casefold() not in removed_boundaries
                    }
                data["targets"] = {
                    key: value
                    for key, value in data["targets"].items()
                    if str(value.get("boundary", "")).casefold()
                    not in removed_boundaries
                    and not (
                        resource_kind == "account"
                        and str(value.get("source_account", "")).casefold()
                        == canonical.casefold()
                    )
                }
                del data[_state.collection_name(resource_kind)][canonical]
            else:
                unresolved.append(message)
    _state.save_config(data)
    if unresolved:
        return _configs.Result(
            "CONFIG_FIX_UNRESOLVED",
            f"Configuration normalized{scope_message}; {len(unresolved)} issue(s) "
            "remain unresolved and no security references were weakened.",
            exit_code=1,
            stream="stderr",
        )
    return _configs.Result(
        "CONFIG_FIX",
        f"Configuration normalized{scope_message}; all local issues are resolved.",
    )


def export_config(destination: str | None) -> Path:
    """Create a safe portable archive excluding credentials, sessions, and caches."""
    data = _state.load_config()
    portable = json.loads(json.dumps(data))
    output = (
        Path(destination).expanduser().absolute()
        if destination
        else Path.cwd() / "hacksaws-config.zip"
    )
    manifest: dict[str, Any] = {"schema_version": 1, "files": {}}
    files: dict[str, bytes] = {}
    for name in data["policies"]:
        path = _policies.stored_directory() / f"{name}.yaml"
        files[f"stored_session_policies/{name}.yaml"] = path.read_bytes()
    for boundary in portable["boundaries"].values():
        policy = boundary.get("policy")
        if not policy or any(
            name.casefold() == str(policy).casefold() for name in data["policies"]
        ):
            continue
        external = Path(policy).expanduser().absolute()
        if not external.is_file():
            raise _configs.OperationalError(
                f"Referenced external policy does not exist: {external}"
            )
        member = (
            f"external_policies/{_state.digest(str(external).casefold().encode())[:12]}"
            f"-{external.name}"
        )
        files[member] = external.read_bytes()
        boundary["policy"] = member
    files["config.json"] = (json.dumps(portable, indent=2) + "\n").encode()
    for name, content in files.items():
        manifest["files"][name] = _state.digest(content)
    files["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return output


def import_config(source: Path, *, replace: bool, yes: bool) -> str:
    """Validate entirely in memory, preview, then atomically merge an archive."""
    try:
        with zipfile.ZipFile(source) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise _configs.OperationalError("Archive contains duplicate members.")
            if any(
                Path(name).is_absolute() or ".." in Path(name).parts or "\\" in name
                for name in names
            ):
                raise _configs.OperationalError("Archive contains an unsafe path.")
            if "manifest.json" not in names or "config.json" not in names:
                raise _configs.OperationalError(
                    "Archive is missing manifest.json or config.json."
                )
            manifest = json.loads(archive.read("manifest.json"))
            if (
                type(manifest) is not dict
                or set(manifest) != {"schema_version", "files"}
                or type(manifest.get("schema_version")) is not int
                or manifest["schema_version"] != 1
                or type(manifest.get("files")) is not dict
            ):
                raise _configs.OperationalError("Archive manifest schema is invalid.")
            if any(
                type(name) is not str
                or type(digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                for name, digest in manifest["files"].items()
            ):
                raise _configs.OperationalError(
                    "Archive manifest file names and SHA-256 digests must be exact strings."
                )
            if "config.json" not in manifest["files"]:
                raise _configs.OperationalError(
                    "Archive manifest does not declare config.json."
                )
            config_bytes = archive.read("config.json")
            if _state.digest(config_bytes) != manifest["files"]["config.json"]:
                raise _configs.OperationalError(
                    "Archive checksum failed for config.json."
                )
            imported = _state._validate_config(json.loads(config_bytes))
            imported_policy_names = {
                name.casefold(): name for name in imported["policies"]
            }
            external_references: set[str] = set()
            for boundary_name, boundary in imported["boundaries"].items():
                policy = boundary.get("policy")
                if policy is None:
                    continue
                if policy.casefold() in imported_policy_names:
                    continue
                if (
                    policy.startswith("external_policies/")
                    and "\\" not in policy
                    and ".." not in Path(policy).parts
                    and Path(policy).suffix.lower()
                    in {".json", ".yaml", ".yml", ".toml"}
                ):
                    external_references.add(policy)
                    continue
                raise _configs.OperationalError(
                    f"Imported boundary {boundary_name!r} has non-portable policy "
                    f"reference {policy!r}; only imported stored names or bundled "
                    "external_policies payloads are allowed."
                )
            derived_payloads = {"config.json"}
            derived_payloads.update(
                f"stored_session_policies/{name}.yaml" for name in imported["policies"]
            )
            derived_payloads.update(external_references)
            manifest_payloads = set(manifest["files"])
            if manifest_payloads != derived_payloads:
                extras = sorted(manifest_payloads - derived_payloads)
                missing = sorted(derived_payloads - manifest_payloads)
                raise _configs.OperationalError(
                    "Archive manifest contains payloads not referenced by config or "
                    f"omits required payloads; extras={extras}, missing={missing}."
                )
            expected_names = {*derived_payloads, "manifest.json"}
            if set(names) != expected_names:
                extras = sorted(set(names) - expected_names)
                missing = sorted(expected_names - set(names))
                raise _configs.OperationalError(
                    f"Archive member set differs from config; extras={extras}, "
                    f"missing={missing}."
                )
            payloads = {name: archive.read(name) for name in derived_payloads}
            for name, expected in manifest["files"].items():
                if (
                    not isinstance(expected, str)
                    or _state.digest(payloads[name]) != expected
                ):
                    raise _configs.OperationalError(
                        f"Archive checksum failed for {name}."
                    )
            policy_outputs: dict[str, bytes] = {}
            for boundary in imported["boundaries"].values():
                policy = boundary.get("policy")
                if not isinstance(policy, str) or not policy.startswith(
                    "external_policies/"
                ):
                    continue
                if policy not in payloads:
                    raise _configs.OperationalError(
                        f"Archive is missing external policy {policy}."
                    )
                raw = payloads[policy]
                suffix = Path(policy).suffix.lower()
                base = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(policy).stem)
                promoted_name = f"imported-{base[:35]}-{_state.digest(raw)[:12]}"[:64]
                document = _policies.parse_policy_bytes(
                    raw, kind=suffix.lstrip("."), source=policy
                )
                if promoted_name.casefold() in imported_policy_names:
                    raise _configs.OperationalError(
                        f"External policy {policy!r} collides with imported stored "
                        f"policy {imported_policy_names[promoted_name.casefold()]!r}."
                    )
                policy_outputs[promoted_name] = yaml.safe_dump(
                    document, sort_keys=False
                ).encode()
                imported["policies"].setdefault(
                    promoted_name,
                    {
                        "file": f"stored_session_policies/{promoted_name}.yaml",
                        "description": f"Imported from {policy}",
                    },
                )
                boundary["policy"] = promoted_name
            for name in imported["policies"]:
                if name in policy_outputs:
                    continue
                member = f"stored_session_policies/{name}.yaml"
                if member not in payloads:
                    raise _configs.OperationalError(
                        f"Archive is missing stored policy {name}."
                    )
                policy_bytes = payloads[member]
                _policies.parse_policy_bytes(policy_bytes, kind="yaml", source=member)
                policy_outputs[name] = policy_bytes
            imported = _state._validate_config(imported)
            existing_config = _state.load_config()
            current = copy.deepcopy(existing_config)
            conflicts: list[str] = []
            for collection in ("accounts", "boundaries", "targets", "policies"):
                for name, value in imported[collection].items():
                    existing = next(
                        (
                            key
                            for key in current[collection]
                            if key.casefold() == name.casefold()
                        ),
                        None,
                    )
                    if existing and current[collection][existing] != value:
                        conflicts.append(f"{collection[:-1]}:{name}")
                        if not replace:
                            continue
                        del current[collection][existing]
                    current[collection][name] = value
            for imported_name, imported_content in policy_outputs.items():
                existing_name = next(
                    (
                        name
                        for name in existing_config["policies"]
                        if name.casefold() == imported_name.casefold()
                    ),
                    None,
                )
                destination_path = _policies.stored_directory() / (
                    f"{existing_name or imported_name}.yaml"
                )
                if destination_path.exists():
                    try:
                        existing_content = destination_path.read_bytes()
                    except OSError as error:
                        raise _configs.OperationalError(
                            f"Unable to inspect existing stored policy "
                            f"{existing_name or imported_name!r}: {error}"
                        ) from error
                    if _state.digest(existing_content) != _state.digest(
                        imported_content
                    ):
                        conflicts.append(f"policy-content:{imported_name}")
                elif existing_name is not None:
                    conflicts.append(f"policy-content:{imported_name}")
            conflicts = list(dict.fromkeys(conflicts))
            preview = (
                f"Import preview: {sum(len(imported[name]) for name in ('accounts', 'boundaries', 'targets', 'policies'))} "
                f"resources; conflicts: {', '.join(conflicts) or '(none)'}."
            )
            if conflicts and not replace:
                raise _configs.OperationalError(
                    f"{preview} Conflicts require --replace."
                )
            if conflicts and replace and not yes:
                if not sys.stdin.isatty():
                    raise _configs.OperationalError(
                        f"{preview} Noninteractive replacement requires --yes."
                    )
                answer = input(f"{preview} Replace these resources? [y/N] ").strip()
                if answer.casefold() not in {"y", "yes"}:
                    raise _configs.OperationalError(
                        "Import cancelled; no files changed."
                    )
            _state._validate_config(current)
    except (OSError, zipfile.BadZipFile, KeyError, json.JSONDecodeError) as error:
        raise _configs.OperationalError(
            f"Unable to import archive {source}: {error}"
        ) from error
    outputs = {
        _policies.stored_directory() / f"{name}.yaml": content
        for name, content in policy_outputs.items()
    }
    journal = _begin([_state.root() / "config.json", *outputs])
    try:
        for path, content in outputs.items():
            _state.atomic_write(path, content)
        _state.save_config(current)
        _commit()
    except Exception:
        _rollback(journal)
        raise
    return f"{preview} Imported portable configuration."
