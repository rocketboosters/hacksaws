"""Transactional MFA/browser login, boundary, logout, and portability workflows."""

from __future__ import annotations

import base64
import configparser
import copy
import fnmatch
import getpass
import importlib
import json
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


def _begin(
    paths: list[Path], *, cache_roots: list[Path] | None = None
) -> dict[str, Any]:
    cache_snapshots = []
    for cache_root in cache_roots or []:
        root_exists = cache_root.exists()
        existing = (
            [
                _snapshot(path.absolute())
                for path in cache_root.rglob("*")
                if path.is_file()
            ]
            if cache_root.exists()
            else []
        )
        directories = (
            [
                str(path.absolute())
                for path in [cache_root, *cache_root.rglob("*")]
                if path.is_dir()
            ]
            if root_exists
            else []
        )
        cache_snapshots.append(
            {
                "root": str(cache_root.absolute()),
                "root_exists": root_exists,
                "directories": directories,
                "files": existing,
            }
        )
    journal = {
        "schema_version": 1,
        "started_at": _state.iso_now(),
        "files": [_snapshot(path) for path in paths],
        "safe_to_rollback": True,
        "ecr_created": [],
        "cache_snapshots": cache_snapshots,
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
    for snapshot in journal.get("cache_snapshots", []):
        cache_root = Path(snapshot["root"]).absolute()
        before = {item["path"] for item in snapshot.get("files", [])}
        if cache_root.exists():
            for cache_file in cache_root.rglob("*"):
                if cache_file.is_file() and str(cache_file.absolute()) not in before:
                    try:
                        cache_file.unlink()
                    except OSError as error:
                        failures.append(f"cache {cache_file}: {error}")
        for cache_file_snapshot in snapshot.get("files", []):
            try:
                _restore(cache_file_snapshot)
            except OSError as error:
                failures.append(f"cache {cache_file_snapshot['path']}: {error}")
        before_directories = {
            str(Path(value).absolute()) for value in snapshot.get("directories", [])
        }
        if "directories" in snapshot and cache_root.exists():
            current_directories = sorted(
                (path for path in cache_root.rglob("*") if path.is_dir()),
                key=lambda path: len(path.parts),
                reverse=True,
            )
            if not snapshot.get("root_exists", True):
                current_directories.append(cache_root)
            for directory in current_directories:
                if str(directory.absolute()) in before_directories:
                    continue
                try:
                    directory.rmdir()
                except OSError as error:
                    failures.append(f"cache directory {directory}: {error}")
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
    if not journal.get("safe_to_rollback") or not isinstance(
        journal.get("files"), list
    ):
        raise _configs.OperationalError(
            f"Transaction recovery is unsafe; inspect {path} and restore AWS files manually."
        )
    _rollback(journal)


def _commit() -> None:
    _journal_path().unlink(missing_ok=True)


def _changed_cache_files(snapshot: dict[str, Any]) -> list[str]:
    """Return cache files created or changed by the current transaction."""
    cache_root = Path(snapshot["root"]).absolute()
    before = {
        item["path"]: base64.b64decode(item["data"])
        for item in snapshot.get("files", [])
    }
    if not cache_root.exists():
        return []
    changed = []
    for path in cache_root.rglob("*"):
        if not path.is_file():
            continue
        absolute = str(path.absolute())
        if absolute not in before or path.read_bytes() != before[absolute]:
            changed.append(absolute)
    return sorted(changed)


def _cache_fingerprints(paths: list[str]) -> dict[str, str]:
    """Fingerprint tracked cache content so logout cannot remove replacements."""
    return {
        str(Path(value).absolute()): _state.digest(Path(value).read_bytes())
        for value in paths
    }


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
            data = _state.load_config()
            _, account = _state.get_resource(data, "account", account_name)
            account_id, role_partition = account["id"], account["partition"]
        role = f"arn:{role_partition}:iam::{account_id}:role/{role}"
    if role:
        match = re.fullmatch(
            r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/(.+)", str(role)
        )
        if not match:
            raise _configs.OperationalError(f"Invalid role ARN {role!r}.")
        if account_name:
            data = _state.load_config()
            _, selected = _state.get_resource(data, "account", account_name)
            if (
                match.group(1) != selected["partition"]
                or match.group(2) != selected["id"]
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
) -> tuple[dict[str, Any], dict[str, Any]]:
    match = re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/.+", role)
    if not match:
        raise _configs.OperationalError(f"Invalid role ARN {role!r}.")
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
    request: dict[str, Any] = {
        "RoleArn": role,
        "RoleSessionName": _session_name(role, boundary_name, args.session_name),
        "DurationSeconds": duration,
    }
    resolved = None
    if policy:
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
        "target_account": account,
        "role": role,
        "boundary": boundary_name,
        "policy": resolved.identity if resolved else None,
        "policy_provenance": resolved.provenance if resolved else None,
        "expires_at": response["Credentials"]["Expiration"].astimezone(UTC).isoformat(),
    }
    return response["Credentials"], metadata


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
) -> None:
    sessions = _state.load_sessions()
    key = f"{destination.absolute()}::{profile}"
    previous = sessions.get(key)
    original_backup = (
        previous.get("backup") or journal["files"] if previous else journal["files"]
    )
    previous_ecr = previous.get("ecr", []) if previous else []
    previous_cache = previous.get("login_cache_files", []) if previous else []
    current_cache = metadata.get("login_cache_files", [])
    if previous_cache or current_cache:
        metadata["login_cache_files"] = list(
            dict.fromkeys([*previous_cache, *current_cache])
        )
    previous_cache_directories = (
        previous.get("login_cache_directories", []) if previous else []
    )
    current_cache_directories = metadata.get("login_cache_directories", [])
    if previous_cache_directories or current_cache_directories:
        metadata["login_cache_directories"] = list(
            dict.fromkeys([*previous_cache_directories, *current_cache_directories])
        )
    previous_fingerprints = (
        previous.get("login_cache_fingerprints", {}) if previous else {}
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
            ],
            cache_roots=[native_cache],
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
            with _aws_environment(
                destination_dir / "config",
                destination_dir / "credentials",
                native_cache,
            ):
                native = boto3.Session(profile_name=destination_profile)
                account, partition, _ = _identity(native, label="browser login")
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
            changed_cache = _changed_cache_files(journal["cache_snapshots"][0])
            _record(
                destination_dir,
                destination_profile,
                {
                    "source_account": account,
                    "target_account": account,
                    "target": target.get("target_name"),
                    "role": None,
                    "boundary": None,
                    "policy": None,
                    "policy_provenance": "AWS-native login_session",
                    "expires_at": None,
                    "login_cache_files": changed_cache,
                    "login_cache_directories": [str(native_cache.absolute())],
                    "login_cache_fingerprints": _cache_fingerprints(changed_cache),
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
        ],
        cache_roots=[staging],
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
        with _aws_environment(staging_config, staging_credentials, staging_cache):
            intermediate = boto3.Session(profile_name=source_profile)
            source_account, partition, _ = _identity(
                intermediate, label="browser staging login"
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
        metadata.update(source_account=source_account, target=target.get("target_name"))
        _record(
            destination_dir,
            destination_profile,
            metadata,
            journal,
            method="browser-boundary",
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
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return _configs.Result(
        "BROWSER_LOGIN",
        f"Bounded browser login active for profile {destination_profile}.",
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


def _public_session(session: dict[str, Any], *, now: datetime) -> dict[str, Any]:
    hidden = {
        "backup",
        "section_backup",
        "login_cache_files",
        "login_cache_directories",
        "login_cache_fingerprints",
    }
    public = {key: value for key, value in session.items() if key not in hidden}
    destination = Path(str(public.get("destination", Path.home() / ".aws"))).absolute()
    public["destination"] = str(destination)
    public["location"] = _location_for_directory(destination)
    public["managed"] = True
    drift = _managed_section_state(session)
    expiry = public.get("expires_at")
    remaining: int | None = None
    if expiry:
        try:
            remaining = max(
                0, int((datetime.fromisoformat(str(expiry)) - now).total_seconds())
            )
        except ValueError:
            remaining = None
    public["remaining_seconds"] = remaining
    if public.get("auth_method") in {"browser-cache-residue", "logout-residue"}:
        state = "logout-residue"
    elif public.get("auth_method") == "ecr-only":
        state = "ecr-only"
    elif drift:
        state = drift
    elif not session.get("section_backup"):
        state = "legacy-unverified"
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


def _verify_status(item: dict[str, Any]) -> dict[str, Any]:
    if item.get("state") in {"ecr-only", "missing", "drifted"}:
        return {"status": "skipped", "reason": f"local state is {item['state']}"}
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


def _tracked_login_cache_plan(
    session: dict[str, Any], destination: Path, *, force: bool
) -> tuple[list[Path], list[Path], list[dict[str, str]]]:
    if session.get("auth_method") not in {
        "browser-native",
        "browser-cache-residue",
        "logout-residue",
    }:
        return [], [], []
    configured_roots = session.get("login_cache_directories") or [
        str((destination / "login" / "cache").absolute())
    ]
    allowed_roots = [Path(str(value)).absolute() for value in configured_roots]
    fingerprints = session.get("login_cache_fingerprints", {})
    removals: list[Path] = []
    residue: list[dict[str, str]] = []
    for value in session.get("login_cache_files", []):
        cache_file = Path(str(value)).absolute()
        expected = fingerprints.get(str(cache_file))
        in_scope = any(
            root == cache_file.parent or root in cache_file.parents
            for root in allowed_roots
        )
        if not in_scope:
            residue.append(
                {"path": str(cache_file), "reason": "outside tracked cache roots"}
            )
            continue
        if not cache_file.exists():
            continue
        try:
            current = _state.digest(cache_file.read_bytes())
        except OSError as error:
            if force:
                removals.append(cache_file)
                continue
            residue.append({"path": str(cache_file), "reason": f"unreadable: {error}"})
            continue
        if not isinstance(expected, str) or current != expected:
            if force:
                removals.append(cache_file)
                continue
            residue.append(
                {"path": str(cache_file), "reason": "fingerprint changed after login"}
            )
            continue
        removals.append(cache_file)
    if residue and not force:
        details = "; ".join(f"{item['path']}: {item['reason']}" for item in residue)
        raise _configs.OperationalError(
            "Tracked browser login cache changed after login; no logout changes were "
            f"made. Review the cache or retry with --force: {details}"
        )
    return allowed_roots, removals, residue


def _remove_tracked_login_cache(
    removals: list[Path], residue: list[dict[str, str]], *, force: bool
) -> list[dict[str, str]]:
    for cache_file in removals:
        try:
            cache_file.unlink()
        except OSError as error:
            if not force:
                raise _configs.OperationalError(
                    f"Unable to remove tracked browser login cache {cache_file}: {error}"
                ) from error
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
    cache_roots, cache_removals, cache_residue = _tracked_login_cache_plan(
        session, destination, force=force
    )
    journal = _begin(
        [destination / "credentials", destination / "config", _state.sessions_path()],
        cache_roots=cache_roots,
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
    try:
        _apply_profile_section_plans(plans)
        cache_residue = _remove_tracked_login_cache(
            cache_removals, cache_residue, force=force
        )
        if cache_residue:
            residual.update(
                auth_method="logout-residue" if registries else "browser-cache-residue",
                login_cache_residue=cache_residue,
                login_cache_directories=[str(path) for path in cache_roots],
                login_cache_files=[item["path"] for item in cache_residue],
                login_cache_fingerprints={},
            )
        if registries or cache_residue:
            sessions[key] = residual
        else:
            del sessions[key]
        _state.save_sessions(sessions)
        _commit()
    except Exception:
        _rollback(journal)
        raise
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
