"""Transactional MFA/browser login, boundary, logout, and portability workflows."""

from __future__ import annotations

import base64
import configparser
import copy
import getpass
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
        existing = (
            [
                _snapshot(path.absolute())
                for path in cache_root.rglob("*")
                if path.is_file()
            ]
            if cache_root.exists()
            else []
        )
        cache_snapshots.append({"root": str(cache_root.absolute()), "files": existing})
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
        source_profile = str(target.get("source_profile", "default"))
        if target.get("destination_directory"):
            destination_dir = Path(target["destination_directory"])
        elif target.get("destination_location"):
            destination_dir = _state.aws_directory(target["destination_location"])
        else:
            destination_dir = source_dir
        destination_profile = str(target.get("destination_profile", source_profile))
        return source_dir, source_profile, destination_dir, destination_profile
    source = Path(args.directory).expanduser().absolute()
    profile = args.profile or "default"
    if getattr(args, "aws_account_name", None):
        source = _state.aws_directory(args.aws_account_name)
    if getattr(args, "to", None):
        location, separator, destination_profile = args.to.partition(":")
        if not separator or not destination_profile:
            raise _configs.OperationalError("--to must be LOCATION:PROFILE.")
        return source, profile, _state.aws_directory(location), destination_profile
    if getattr(args, "to_directory", None):
        return (
            source,
            profile,
            Path(args.to_directory).expanduser().absolute(),
            args.to_profile,
        )
    return source, profile, source, profile


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
    sessions[key] = {
        **metadata,
        "destination": str(destination.absolute()),
        "profile": profile,
        "auth_method": method,
        "started_at": _state.iso_now(),
        "backup": original_backup,
        "ecr": list(dict.fromkeys([*previous_ecr, *(ecr or [])])),
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


def _clean_env(
    config: Path | None = None, credentials: Path | None = None
) -> dict[str, str]:
    env = {
        key: value for key, value in os.environ.items() if key not in _CONFLICTING_ENV
    }
    if config:
        env["AWS_CONFIG_FILE"] = str(config)
    if credentials:
        env["AWS_SHARED_CREDENTIALS_FILE"] = str(credentials)
    return env


@contextmanager
def _aws_environment(config: Path, credentials: Path) -> Iterator[None]:
    """Temporarily scrub inherited AWS identity/path variables for one staging area."""
    previous = {key: os.environ.get(key) for key in _CONFLICTING_ENV}
    for key in _CONFLICTING_ENV:
        os.environ.pop(key, None)
    os.environ["AWS_CONFIG_FILE"] = str(config)
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(credentials)
    try:
        yield
    finally:
        for key in _CONFLICTING_ENV:
            value = previous[key]
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _aws_login(config: Path, credentials: Path, profile: str, *, remote: bool) -> None:
    _aws_cli_version()
    config.parent.mkdir(parents=True, exist_ok=True)
    command = ["aws", "login", "--profile", profile]
    if remote:
        command.append("--remote")
    try:
        subprocess.run(command, check=True, env=_clean_env(config, credentials))
    except (FileNotFoundError, OSError, subprocess.CalledProcessError) as error:
        raise _configs.OperationalError(f"AWS browser login failed: {error}") from error


def browser_login(context: _configs.Context) -> _configs.Result:
    """Run AWS-native browser login or isolate it before a role boundary."""
    args = context.args
    source_dir, source_profile, destination_dir, destination_profile = _paths(args)
    # Determine role from config without requiring caller identity first.
    configured_role = _configured_role_before_auth(args)
    _require_concrete_role(args, configured_role)
    has_boundary = configured_role is not None
    if not has_boundary:
        native_cache = destination_dir / "login" / "cache"
        journal = _begin(
            [
                destination_dir / "config",
                destination_dir / "credentials",
                _state.sessions_path(),
            ],
            cache_roots=[native_cache],
        )
        ecr_registries: list[str] = []
        try:
            _aws_login(
                destination_dir / "config",
                destination_dir / "credentials",
                destination_profile,
                remote=args.remote,
            )
            with _aws_environment(
                destination_dir / "config", destination_dir / "credentials"
            ):
                native = boto3.Session(profile_name=destination_profile)
                account, partition, _ = _identity(native, label="browser login")
            cache_before = {
                item["path"] for item in journal["cache_snapshots"][0]["files"]
            }
            cache_after = (
                {
                    str(path.absolute())
                    for path in native_cache.rglob("*")
                    if path.is_file()
                }
                if native_cache.exists()
                else set()
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
                    "target_account": account,
                    "target": target.get("target_name"),
                    "role": None,
                    "boundary": None,
                    "policy": None,
                    "policy_provenance": "AWS-native login_session",
                    "expires_at": None,
                    "login_cache_files": sorted(cache_after - cache_before),
                },
                journal,
                method="browser-native",
                ecr=ecr_registries,
            )
            _commit()
        except Exception:
            _rollback(journal)
            raise
        return _configs.Result(
            "BROWSER_LOGIN",
            f"AWS-native browser login active for profile {destination_profile}.",
        )

    staging = _state.root() / "staging" / uuid.uuid4().hex
    staging_config = staging / "config"
    staging_credentials = staging / "credentials"
    journal = _begin(
        [
            destination_dir / "config",
            destination_dir / "credentials",
            _state.sessions_path(),
        ],
        cache_roots=[staging],
    )
    ecr_registries = []
    try:
        _aws_login(
            staging_config, staging_credentials, source_profile, remote=args.remote
        )
        env = _clean_env(staging_config, staging_credentials)
        old = {
            key: os.environ.get(key)
            for key in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE")
        }
        os.environ.update(
            {
                key: env[key]
                for key in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE")
            }
        )
        try:
            intermediate = boto3.Session(profile_name=source_profile)
            source_account, partition, _ = _identity(
                intermediate, label="browser staging login"
            )
            target = _target_details(args, source_account, partition)
            role, policy, external_id, boundary_name = _role_details(
                args, target, source_account, partition
            )
            if not role:
                raise _configs.OperationalError(
                    "Bounded browser login requires a role."
                )
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
        finally:
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
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
        )
        _commit()
    except Exception:
        _rollback(journal)
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return _configs.Result(
        "BROWSER_LOGIN",
        f"Bounded browser login active for profile {destination_profile}.",
    )


def logout(context: _configs.Context) -> bool:
    """Restore an expanded session locally, making no AWS logout call."""
    _source, _source_profile, destination, profile = _paths(context.args)
    sessions = _state.load_sessions()
    key = f"{destination.absolute()}::{profile}"
    session = sessions.get(key)
    if not session:
        return False
    for snapshot in reversed(session.get("backup", [])):
        if Path(snapshot["path"]) == _state.sessions_path():
            continue
        _restore(snapshot)
    if session.get("auth_method") == "browser-native":
        allowed_root = (destination / "login" / "cache").absolute()
        for value in session.get("login_cache_files", []):
            cache_file = Path(value).absolute()
            if allowed_root in cache_file.parents:
                cache_file.unlink(missing_ok=True)
    if context.args.ecr:
        for registry in session.get("ecr", []):
            _ecr._run_container_engine(
                context.container_engine, [context.container_engine, "logout", registry]
            )
        del sessions[key]
    elif session.get("ecr"):
        sessions[key] = {
            "destination": str(destination.absolute()),
            "profile": profile,
            "auth_method": "ecr-only",
            "started_at": session.get("started_at"),
            "backup": [],
            "ecr": session["ecr"],
        }
    else:
        del sessions[key]
    _state.save_sessions(sessions)
    return True


def status() -> list[dict[str, Any]]:
    """Return secret-free active session status."""
    now = datetime.now(UTC)
    result = []
    for session in _state.load_sessions().values():
        public = {key: value for key, value in session.items() if key != "backup"}
        expiry = public.get("expires_at")
        if expiry:
            try:
                public["remaining_seconds"] = max(
                    0, int((datetime.fromisoformat(expiry) - now).total_seconds())
                )
            except ValueError:
                public["remaining_seconds"] = None
        result.append(public)
    return result


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
    for name in data["policies"]:
        try:
            _policies.parse_policy(_policies.stored_directory() / f"{name}.yaml")
        except _configs.OperationalError as error:
            errors.append(str(error))
    if args.remote or args.probe:
        profile = args.profile or "default"
        if args.target:
            target_name, target = _state.get_resource(
                data, "target", args.target.lstrip("+")
            )
            profile = target.get("source_profile", "default")
            source_directory = (
                Path(target["source_directory"])
                if target.get("source_directory")
                else _state.aws_directory(target.get("source_location"))
            )
            os.environ["AWS_CONFIG_FILE"] = str(source_directory / "config")
            os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(
                source_directory / "credentials"
            )
            warnings.append(f"Using target {target_name} credential source.")
        try:
            check_session = boto3.Session(profile_name=profile)
            account, partition, _ = _identity(check_session, label="config check")
            if args.account:
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
            if args.probe:
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
    if args.account:
        scoped_policies = {
            str(boundary["policy"])
            for boundary in data["boundaries"].values()
            if str(boundary["account"]).casefold() == account_name.casefold()
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
