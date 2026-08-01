"""Versioned Hacksaws configuration and local session state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from copy import deepcopy
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import Any

from hacksaws._configs import OperationalError

SCHEMA_VERSION = 1
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ROLE_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/"
    r"((?:[A-Za-z0-9_+=,.@-]+/)*[A-Za-z0-9_+=,.@-]{1,64})$"
)
PARTITIONS = {"aws", "aws-us-gov", "aws-cn"}
TOP_LEVEL = {"schema_version", "accounts", "boundaries", "targets", "policies", "cache"}


def collection_name(kind: str) -> str:
    """Return the schema collection name for a singular resource kind."""
    return {"boundary": "boundaries", "policy": "policies"}.get(kind, f"{kind}s")


def root() -> Path:
    """Return the one canonical Hacksaws state root."""
    override = os.environ.get("HACKSAWS_HOME")
    return (
        Path(override).expanduser().absolute()
        if override
        else Path.home() / ".hacksaws"
    )


def default_config() -> dict[str, Any]:
    """Return an empty schema-one configuration."""
    return {
        "schema_version": SCHEMA_VERSION,
        "accounts": {},
        "boundaries": {},
        "targets": {},
        "policies": {},
        "cache": {"max_age": 3600},
    }


def validate_name(value: str, *, kind: str = "resource") -> str:
    """Validate a portable, case-insensitively unique resource name."""
    if type(value) is not str or not NAME_RE.fullmatch(value):
        raise OperationalError(
            f"Invalid {kind} name {value!r}; use 1-64 letters, digits, '.', '_', or "
            "'-', beginning with a letter or digit."
        )
    return value


def normalize_location(value: str | None) -> str:
    """Normalize logical AWS locations."""
    if value is None or value in {".", "default"}:
        return "default"
    if type(value) is not str:
        raise OperationalError("AWS location must be text.")
    return validate_name(value, kind="AWS location")


def parse_role_arn(value: object) -> tuple[str, str, str]:
    """Validate a canonical IAM role ARN and return partition/account/resource."""
    if type(value) is not str:
        raise OperationalError("IAM role ARN must be text.")
    match = ROLE_ARN_RE.fullmatch(value)
    if match is None or len(match.group(3)) > 512:
        raise OperationalError(f"Invalid canonical IAM role ARN {value!r}.")
    return match.group(1), match.group(2), match.group(3)


def aws_directory(location: str | None) -> Path:
    """Resolve a logical AWS location to its standard directory."""
    normalized = normalize_location(location)
    return Path.home() / (".aws" if normalized == "default" else f".aws-{normalized}")


def _secure(path: Path) -> None:
    """Harden a local state path where the platform supports POSIX-style modes."""
    try:
        path.chmod(0o600 if path.is_file() else 0o700)
    except OSError:
        pass


def atomic_write(path: Path, data: bytes) -> None:
    """Atomically replace a user-only file in a user-only directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    _secure(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _secure(temporary_path)
        os.replace(temporary_path, path)
        _secure(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _validate_config(data: object) -> dict[str, Any]:
    if type(data) is not dict:
        raise OperationalError("Hacksaws config must be a JSON object.")
    unknown = set(data) - TOP_LEVEL
    if unknown:
        raise OperationalError(
            f"Unknown config field(s): {', '.join(sorted(unknown))}."
        )
    version = data.get("schema_version")
    if type(version) is not int or version != SCHEMA_VERSION:
        raise OperationalError(
            f"Unsupported Hacksaws config schema {version!r}; expected {SCHEMA_VERSION}."
        )
    for collection in ("accounts", "boundaries", "targets", "policies"):
        if type(data.get(collection)) is not dict:
            raise OperationalError(f"Config field {collection!r} must be an object.")
    cache = data.get("cache")
    if type(cache) is not dict or set(cache) != {"max_age"}:
        raise OperationalError("Config cache accepts only the max_age setting.")
    if type(cache.get("max_age")) is not int or cache["max_age"] < 0:
        raise OperationalError("Config cache.max_age must be non-negative seconds.")
    _validate_resources(data)
    return data


def _validate_resources(data: dict[str, Any]) -> None:
    for collection in ("accounts", "boundaries", "targets", "policies"):
        seen: set[str] = set()
        for name, value in data[collection].items():
            validate_name(name, kind=collection[:-1])
            folded = name.casefold()
            if folded in seen:
                raise OperationalError(
                    f"Duplicate case-insensitive {collection[:-1]} {name!r}."
                )
            seen.add(folded)
            if type(value) is not dict:
                raise OperationalError(
                    f"{collection[:-1].title()} {name!r} must be an object."
                )
    for name, account in data["accounts"].items():
        unknown = set(account) - {"id", "partition", "description", "unverified"}
        if unknown:
            raise OperationalError(
                f"Unknown account field(s) for {name}: {', '.join(unknown)}."
            )
        if type(account.get("id")) is not str or not re.fullmatch(
            r"\d{12}", account["id"]
        ):
            raise OperationalError(f"Account {name!r} must have a 12-digit id.")
        if (
            type(account.get("partition")) is not str
            or account["partition"] not in PARTITIONS
        ):
            raise OperationalError(f"Account {name!r} has an unsupported partition.")
        if "description" in account and type(account["description"]) is not str:
            raise OperationalError(f"Account {name!r} description must be text.")
        if "unverified" in account and (
            type(account["unverified"]) is not bool or account["unverified"] is not True
        ):
            raise OperationalError(
                f"Account {name!r} unverified must be true when set."
            )
    for name, policy in data["policies"].items():
        unknown = set(policy) - {"file", "description"}
        if unknown:
            raise OperationalError(
                f"Unknown policy field(s) for {name}: {', '.join(sorted(unknown))}."
            )
        if type(policy.get("file")) is not str or policy["file"] != (
            f"stored_session_policies/{name}.yaml"
        ):
            raise OperationalError(
                f"Policy {name!r} must use its canonical stored YAML path."
            )
        if "description" in policy and type(policy["description"]) is not str:
            raise OperationalError(f"Policy {name!r} description must be text.")
    for name, boundary in data["boundaries"].items():
        allowed = {
            "role_arn",
            "account",
            "policy",
            "duration",
            "external_id",
            "description",
            "verified",
        }
        if set(boundary) - allowed:
            raise OperationalError(f"Unknown boundary field(s) for {name}.")
        role_partition, role_account, _ = parse_role_arn(boundary.get("role_arn"))
        if type(boundary.get("account")) is not str:
            raise OperationalError(f"Boundary {name!r} account reference must be text.")
        account_key = _find_key(data["accounts"], boundary["account"])
        if account_key is None:
            raise OperationalError(f"Boundary {name!r} references a missing account.")
        referenced_account = data["accounts"][account_key]
        if (
            role_partition != referenced_account["partition"]
            or role_account != referenced_account["id"]
        ):
            raise OperationalError(
                f"Boundary {name!r} role ARN does not match referenced account "
                f"{account_key!r}."
            )
        policy = boundary.get("policy")
        if policy is not None and type(policy) is not str:
            raise OperationalError(f"Boundary {name!r} policy reference must be text.")
        policy_path = Path(policy).expanduser() if policy else None
        if (
            policy
            and _find_key(data["policies"], policy) is None
            and policy_path is not None
            and policy_path.suffix.lower() not in {".json", ".yaml", ".yml", ".toml"}
        ):
            raise OperationalError(
                f"Boundary {name!r} references neither a stored policy nor a policy file: {policy!r}."
            )
        if "duration" in boundary and (
            type(boundary["duration"]) is not int
            or not 900 <= boundary["duration"] <= 43200
        ):
            raise OperationalError(
                f"Boundary {name!r} duration must be integral seconds from 900 "
                "through 43200."
            )
        for field in ("external_id", "description"):
            if field in boundary and type(boundary[field]) is not str:
                raise OperationalError(f"Boundary {name!r} {field} must be text.")
        if "verified" in boundary and type(boundary["verified"]) is not bool:
            raise OperationalError(f"Boundary {name!r} verified must be boolean.")
    for name, target in data["targets"].items():
        allowed = {
            "source_account",
            "source_profile",
            "source_location",
            "source_directory",
            "destination_profile",
            "destination_location",
            "destination_directory",
            "boundary",
            "description",
        }
        if set(target) - allowed:
            raise OperationalError(f"Unknown target field(s) for {name}.")
        if type(target.get("source_account")) is not str:
            raise OperationalError(
                f"Target {name!r} source_account reference must be text."
            )
        if _find_key(data["accounts"], target["source_account"]) is None:
            raise OperationalError(
                f"Target {name!r} references a missing source account."
            )
        source_fields = [
            field
            for field in ("source_location", "source_directory")
            if field in target
        ]
        if len(source_fields) != 1:
            raise OperationalError(
                f"Target {name!r} requires exactly one source location or directory."
            )
        destination_fields = [
            field
            for field in ("destination_location", "destination_directory")
            if field in target
        ]
        if len(destination_fields) > 1:
            raise OperationalError(
                f"Target {name!r} destination location/directory are exclusive."
            )
        if "destination_profile" in target and not destination_fields:
            raise OperationalError(
                f"Target {name!r} destination_profile requires a destination."
            )
        for field in ("source_profile", "destination_profile", "description"):
            if field in target and (
                type(target[field]) is not str or not target[field]
            ):
                raise OperationalError(f"Target {name!r} {field} must be text.")
        for field in ("source_directory", "destination_directory"):
            if field in target and (
                type(target[field]) is not str or not Path(target[field]).is_absolute()
            ):
                raise OperationalError(
                    f"Target {name!r} {field} must be an absolute path."
                )
        for field in ("source_location", "destination_location"):
            if field in target:
                if type(target[field]) is not str:
                    raise OperationalError(f"Target {name!r} {field} must be text.")
                normalize_location(target[field])
        boundary = target.get("boundary")
        if boundary is not None and type(boundary) is not str:
            raise OperationalError(f"Target {name!r} boundary reference must be text.")
        if boundary and _find_key(data["boundaries"], boundary) is None:
            raise OperationalError(
                f"Target {name!r} references missing boundary {boundary!r}."
            )


def load_config(*, create: bool = False) -> dict[str, Any]:
    """Load and strictly validate config.json."""
    path = root() / "config.json"
    if not path.exists():
        data = default_config()
        if create:
            save_config(data)
        return data
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OperationalError(
            f"Unable to read Hacksaws config {path}: {error}"
        ) from error
    return _validate_config(data)


def save_config(data: dict[str, Any]) -> None:
    """Validate and atomically save config.json."""
    validated = _validate_config(deepcopy(data))
    encoded = (json.dumps(validated, indent=2, sort_keys=False) + "\n").encode()
    atomic_write(root() / "config.json", encoded)


def _find_key(collection: dict[str, Any], name: str) -> str | None:
    folded = name.casefold()
    return next((key for key in collection if key.casefold() == folded), None)


def get_resource(
    data: dict[str, Any], kind: str, name: str
) -> tuple[str, dict[str, Any]]:
    """Return a named resource with case-insensitive lookup."""
    collection = data[collection_name(kind)]
    key = _find_key(collection, name)
    if key is None:
        raise OperationalError(f"{kind.title()} {name!r} does not exist.")
    return key, collection[key]


def add_resource(
    data: dict[str, Any], kind: str, name: str, value: dict[str, Any]
) -> None:
    """Add a resource, failing on case-insensitive collision."""
    validate_name(name, kind=kind)
    collection = data[collection_name(kind)]
    if _find_key(collection, name) is not None:
        raise OperationalError(f"{kind.title()} {name!r} already exists.")
    collection[name] = value
    _validate_config(data)


def update_resource(
    data: dict[str, Any], kind: str, name: str, patch: dict[str, Any]
) -> None:
    """Patch an existing resource."""
    key, value = get_resource(data, kind, name)
    value.update(patch)
    data[collection_name(kind)][key] = value
    _validate_config(data)


def references(data: dict[str, Any], kind: str, name: str) -> list[str]:
    """List configuration and active-session references to a resource."""
    canonical, _ = get_resource(data, kind, name)
    found: list[str] = []
    if kind == "account":
        found.extend(
            f"boundary:{key}"
            for key, item in data["boundaries"].items()
            if str(item.get("account", "")).casefold() == canonical.casefold()
        )
        found.extend(
            f"target:{key}"
            for key, item in data["targets"].items()
            if str(item.get("source_account", "")).casefold() == canonical.casefold()
        )
    elif kind == "boundary":
        found.extend(
            f"target:{key}"
            for key, item in data["targets"].items()
            if str(item.get("boundary", "")).casefold() == canonical.casefold()
        )
    elif kind == "policy":
        found.extend(
            f"boundary:{key}"
            for key, item in data["boundaries"].items()
            if str(item.get("policy", "")).casefold() == canonical.casefold()
        )
    for destination, session in load_sessions().items():
        field = {
            "account": "target_account",
            "boundary": "boundary",
            "target": "target",
            "policy": "policy",
        }[kind]
        if str(session.get(field, "")).casefold() == canonical.casefold():
            found.append(f"session:{destination}")
    return found


def remove_resource(data: dict[str, Any], kind: str, name: str) -> None:
    """Remove an unreferenced resource."""
    key, _ = get_resource(data, kind, name)
    dependents = references(data, kind, name)
    if dependents:
        raise OperationalError(
            f"Cannot remove {kind} {key!r}; referenced by {', '.join(dependents)}."
        )
    del data[collection_name(kind)][key]


def rename_resource(data: dict[str, Any], kind: str, old: str, new: str) -> None:
    """Rename a resource and atomically rewrite all references."""
    validate_name(new, kind=kind)
    old_key, value = get_resource(data, kind, old)
    collision = _find_key(data[collection_name(kind)], new)
    if collision is not None and collision != old_key:
        raise OperationalError(f"{kind.title()} {new!r} already exists.")
    rebuilt: dict[str, Any] = {}
    for key, item in data[collection_name(kind)].items():
        rebuilt[new if key == old_key else key] = item
    data[collection_name(kind)] = rebuilt
    fields = {
        "account": (("boundaries", "account"), ("targets", "source_account")),
        "boundary": (("targets", "boundary"),),
        "policy": (("boundaries", "policy"),),
        "target": (),
    }
    for collection, field in fields[kind]:
        for item in data[collection].values():
            if str(item.get(field, "")).casefold() == old_key.casefold():
                item[field] = new
    sessions = load_sessions()
    field = {
        "account": "target_account",
        "boundary": "boundary",
        "target": "target",
        "policy": "policy",
    }[kind]
    changed = False
    for session in sessions.values():
        if str(session.get(field, "")).casefold() == old_key.casefold():
            session[field] = new
            changed = True
    if changed:
        save_sessions(sessions)
    _validate_config(data)


def sessions_path() -> Path:
    """Return active session metadata path."""
    return root() / "sessions.json"


def load_sessions() -> dict[str, dict[str, Any]]:
    """Load non-secret active session metadata."""
    path = sessions_path()
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OperationalError(
            f"Unable to read session state {path}: {error}"
        ) from error
    if not isinstance(value, dict) or any(
        not isinstance(item, dict) for item in value.values()
    ):
        raise OperationalError(f"Invalid session state in {path}.")
    return value


def save_sessions(value: dict[str, dict[str, Any]]) -> None:
    """Atomically save non-secret active session metadata."""
    atomic_write(sessions_path(), (json.dumps(value, indent=2) + "\n").encode())


def iso_now() -> str:
    """Return a stable UTC timestamp."""
    return datetime.now(UTC).isoformat()


def digest(data: bytes) -> str:
    """Return a SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()
