"""Versioned Hacksaws configuration and local session state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import unicodedata
from copy import deepcopy
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import Any

from hacksaws import _regions
from hacksaws._configs import OperationalError

SCHEMA_VERSION = 1
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ROLE_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/"
    r"((?:[A-Za-z0-9_+=,.@-]+/)*[A-Za-z0-9_+=,.@-]{1,64})$"
)
POLICY_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::(aws|\d{12}):policy/"
    r"[A-Za-z0-9_+=,.@/-]+$"
)
PARTITIONS = {"aws", "aws-us-gov", "aws-cn"}
TOP_LEVEL = {
    "schema_version",
    "accounts",
    "boundaries",
    "targets",
    "policies",
    "cache",
    "naming",
    "iam",
    "session",
    "output",
    "history",
    "aws",
}
NAMING_FIELDS = {"case", "prefix", "suffix", "enforcement"}
NAMING_CASES = {"Pascal", "camel", "snake", "kebab"}
ENFORCEMENT_LEVELS = {"off", "warn", "error"}
COLOR_MODES = {"auto", "always", "never"}
ACCOUNT_DISPLAY_SOURCES = {
    "user",
    "iam-alias",
    "account-name",
    "organizations",
    "account-id",
}


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
        "naming": {
            "global": {
                "case": "Pascal",
                "prefix": "",
                "suffix": "",
                "enforcement": "off",
            },
            "resources": {},
            "accounts": {},
            "account_resources": {},
        },
        "iam": {"path": "/hacksaws/"},
        "session": {"packed_policy_warning": 80, "packed_policy_enforcement": "off"},
        "output": {"color": "auto"},
        "history": {
            "enabled": True,
            "max_age": 90 * 24 * 60 * 60,
            "max_entries": 10_000,
            "max_bytes": 50 * 1024 * 1024,
        },
        "aws": {"region": None, "region_aliases": {}},
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
    defaults = default_config()
    for key in ("naming", "iam", "session", "output", "history", "aws"):
        data.setdefault(key, deepcopy(defaults[key]))
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
    _validate_foundation_settings(data)
    _validate_resources(data)
    return data


def _validate_naming_override(value: object, *, label: str, require_all: bool) -> None:
    """Validate one naming layer while allowing sparse resource overrides."""
    if type(value) is not dict or set(value) - NAMING_FIELDS:
        raise OperationalError(f"Config naming {label} contains unsupported settings.")
    if require_all and set(value) != NAMING_FIELDS:
        raise OperationalError(
            f"Config naming {label} must define every naming setting."
        )
    if "case" in value and value["case"] not in NAMING_CASES:
        raise OperationalError(f"Config naming {label}.case is unsupported.")
    if "enforcement" in value and value["enforcement"] not in ENFORCEMENT_LEVELS:
        raise OperationalError(f"Config naming {label}.enforcement is unsupported.")
    for field in ("prefix", "suffix"):
        if field in value and type(value[field]) is not str:
            raise OperationalError(f"Config naming {label}.{field} must be text.")


def _validate_foundation_settings(data: dict[str, Any]) -> None:
    """Validate schema-one UX and IAM defaults without changing schema version."""
    naming = data["naming"]
    if type(naming) is not dict or set(naming) != {
        "global",
        "resources",
        "accounts",
        "account_resources",
    }:
        raise OperationalError("Config naming has an unsupported shape.")
    _validate_naming_override(naming["global"], label="global", require_all=True)
    for layer in ("resources", "accounts"):
        if type(naming[layer]) is not dict:
            raise OperationalError(f"Config naming.{layer} must be an object.")
        for name, override in naming[layer].items():
            validate_name(name, kind=f"naming {layer[:-1]}")
            _validate_naming_override(
                override, label=f"{layer}.{name}", require_all=False
            )
    if type(naming["account_resources"]) is not dict:
        raise OperationalError("Config naming.account_resources must be an object.")
    for account, resources in naming["account_resources"].items():
        validate_name(account, kind="naming account")
        if type(resources) is not dict:
            raise OperationalError(
                "Config naming.account_resources entries must be objects."
            )
        for resource, override in resources.items():
            validate_name(resource, kind="naming resource")
            _validate_naming_override(
                override,
                label=f"account_resources.{account}.{resource}",
                require_all=False,
            )
    iam = data["iam"]
    if type(iam) is not dict or set(iam) != {"path"} or type(iam["path"]) is not str:
        raise OperationalError("Config iam accepts only a text path setting.")
    if not iam["path"].startswith("/") or not iam["path"].endswith("/"):
        raise OperationalError("Config iam.path must start and end with '/'.")
    session = data["session"]
    if type(session) is not dict or set(session) != {
        "packed_policy_warning",
        "packed_policy_enforcement",
    }:
        raise OperationalError("Config session has an unsupported shape.")
    if (
        type(session["packed_policy_warning"]) is not int
        or not 0 <= session["packed_policy_warning"] <= 100
    ):
        raise OperationalError(
            "Config session.packed_policy_warning must be 0 through 100."
        )
    if session["packed_policy_enforcement"] not in ENFORCEMENT_LEVELS:
        raise OperationalError(
            "Config session.packed_policy_enforcement is unsupported."
        )
    output = data["output"]
    if (
        type(output) is not dict
        or set(output) != {"color"}
        or output["color"] not in COLOR_MODES
    ):
        raise OperationalError("Config output.color must be auto, always, or never.")
    history = data["history"]
    if type(history) is not dict or set(history) != {
        "enabled",
        "max_age",
        "max_entries",
        "max_bytes",
    }:
        raise OperationalError("Config history has an unsupported shape.")
    if type(history["enabled"]) is not bool:
        raise OperationalError("Config history.enabled must be true or false.")
    for field in ("max_age", "max_entries", "max_bytes"):
        if type(history[field]) is not int or history[field] < 1:
            raise OperationalError(
                f"Config history.{field} must be a positive integer."
            )
    aws = data["aws"]
    if type(aws) is not dict or set(aws) != {"region", "region_aliases"}:
        raise OperationalError(
            "Config aws accepts only region and region_aliases settings."
        )
    if aws["region"] is not None:
        _validate_canonical_region(aws["region"], label="Config aws.region")
    if type(aws["region_aliases"]) is not dict:
        raise OperationalError("Config aws.region_aliases must be an object.")
    _regions.validate_custom_aliases(aws["region_aliases"])


def _validate_canonical_region(
    value: object, *, label: str, partition: str | None = None
) -> str:
    """Require a canonical known or explicitly forward-compatible region."""
    if type(value) is not str:
        raise OperationalError(f"{label} must be canonical region text.")
    resolution = _regions.resolve_region(value, partition=partition, allow_unknown=True)
    if resolution.canonical != value or resolution.source not in {
        "canonical",
        "unknown",
    }:
        raise OperationalError(
            f"{label} must store canonical region {resolution.canonical!r}, not an alias."
        )
    return resolution.canonical


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
    account_identities: dict[tuple[str, str], str] = {}
    for name, account in data["accounts"].items():
        unknown = set(account) - {
            "id",
            "partition",
            "description",
            "display_name",
            "display_source",
            "unverified",
            "credential_target",
            "region",
        }
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
        identity = (account["partition"], account["id"])
        previous = account_identities.get(identity)
        if previous is not None:
            raise OperationalError(
                f"Accounts {previous!r} and {name!r} have the same AWS identity."
            )
        account_identities[identity] = name
        if "description" in account and type(account["description"]) is not str:
            raise OperationalError(f"Account {name!r} description must be text.")
        display_name = account.get("display_name")
        display_source = account.get("display_source")
        if (display_name is None) != (display_source is None):
            raise OperationalError(
                f"Account {name!r} display_name and display_source must be set together."
            )
        if display_name is not None:
            if (
                type(display_name) is not str
                or not display_name
                or display_name != display_name.strip()
                or len(display_name) > 128
                or any(
                    unicodedata.category(character).startswith("C")
                    for character in display_name
                )
            ):
                raise OperationalError(
                    f"Account {name!r} display_name must be 1-128 safe text characters."
                )
            if display_source not in ACCOUNT_DISPLAY_SOURCES:
                raise OperationalError(
                    f"Account {name!r} has an unsupported display_source."
                )
        if "credential_target" in account and (
            type(account["credential_target"]) is not str
            or not account["credential_target"]
        ):
            raise OperationalError(f"Account {name!r} credential_target must be text.")
        if "unverified" in account and (
            type(account["unverified"]) is not bool or account["unverified"] is not True
        ):
            raise OperationalError(
                f"Account {name!r} unverified must be true when set."
            )
        if "region" in account:
            _validate_canonical_region(
                account["region"],
                label=f"Account {name!r} region",
                partition=account["partition"],
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
            and POLICY_ARN_RE.fullmatch(policy) is None
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
            "region",
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
        if "region" in target:
            account_key = _find_key(data["accounts"], target["source_account"])
            account = data["accounts"][account_key]
            _validate_canonical_region(
                target["region"],
                label=f"Target {name!r} region",
                partition=account["partition"],
            )


CONFIG_OPTION_PATTERNS: dict[str, dict[str, object]] = {
    "aws.region": {
        "description": "Global fallback AWS region; aliases resolve before storage.",
        "default": None,
    },
    "aws.region_aliases.<alias>.region": {
        "description": "Canonical region selected by one global custom alias.",
    },
    "aws.region_aliases.<alias>.description": {
        "description": "Optional human description for one custom region alias.",
    },
    "naming.global.{case|prefix|suffix|enforcement}": {
        "description": "Default naming policy; later layers override earlier layers.",
        "default": {"case": "Pascal", "prefix": "", "suffix": "", "enforcement": "off"},
    },
    "naming.resources.<resource>.{case|prefix|suffix|enforcement}": {
        "description": "Naming override for one resource kind.",
    },
    "naming.accounts.<account>.{case|prefix|suffix|enforcement}": {
        "description": "Naming override for one AWS account.",
    },
    "naming.account_resources.<account>.<resource>.{case|prefix|suffix|enforcement}": {
        "description": "Most-specific account and resource naming override.",
    },
    "iam.path": {
        "description": "IAM resource path for managed artifacts.",
        "default": "/hacksaws/",
    },
    "session.packed_policy_warning": {
        "description": "Packed-policy warning threshold, in percent.",
        "default": 80,
    },
    "session.packed_policy_enforcement": {
        "description": "Packed-policy action: off, warn, or error.",
        "default": "off",
    },
    "output.color": {
        "description": "Color mode: auto, always, or never.",
        "default": "auto",
    },
    "history.enabled": {
        "description": "Record redacted command outcomes in local history.",
        "default": True,
    },
    "history.max_age": {
        "description": "Maximum history age in seconds before routine pruning.",
        "default": 90 * 24 * 60 * 60,
    },
    "history.max_entries": {
        "description": "Maximum retained resolved command records.",
        "default": 10_000,
    },
    "history.max_bytes": {
        "description": "Maximum logical history size in bytes.",
        "default": 50 * 1024 * 1024,
    },
    "accounts.<account>.credential_target": {
        "description": "Per-account credential target used only when explicitly selected.",
    },
    "accounts.<account>.region": {
        "description": "Preferred fallback region for one configured AWS account.",
    },
    "targets.<target>.region": {
        "description": "Saved target region, overriding profile/account/global defaults.",
    },
}


def config_option_patterns() -> dict[str, dict[str, object]]:
    """Return self-documenting, stable configuration option descriptions."""
    return deepcopy(CONFIG_OPTION_PATTERNS)


def resolve_naming(
    data: dict[str, Any],
    *,
    resource: str,
    account: str | None = None,
    explicit: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve naming in built-in/global/resource/account/account-resource/explicit order."""
    naming = data["naming"]
    resolved = {"case": "Pascal", "prefix": "", "suffix": "", "enforcement": "off"}
    resolved.update(naming["global"])
    resolved.update(naming["resources"].get(resource, {}))
    if account:
        resolved.update(naming["accounts"].get(account, {}))
        resolved.update(naming["account_resources"].get(account, {}).get(resource, {}))
    if explicit:
        resolved.update(explicit)
    return resolved


def _option_parts(key: str) -> list[str]:
    if not key or any(not part for part in key.split(".")):
        raise OperationalError("Config option key must use dotted names.")
    return key.split(".")


def get_config_option(data: dict[str, Any], key: str) -> object:
    """Read a declared configuration option by its dotted path."""
    current: object = data
    for part in _option_parts(key):
        if type(current) is not dict or part not in current:
            raise OperationalError(
                f"Unknown config option {key!r}; run 'config options'."
            )
        current = current[part]
    return deepcopy(current)


def set_config_option(data: dict[str, Any], key: str, value: object) -> None:
    """Set a known leaf option and validate the complete schema-one document."""
    parts = _option_parts(key)
    if parts[:2] == ["aws", "region_aliases"] and len(parts) == 4:
        alias, field = parts[2:]
        if field not in {"region", "description"}:
            raise OperationalError(
                f"Unknown config option {key!r}; run 'config options'."
            )
        aliases = data["aws"]["region_aliases"]
        existing = aliases.get(alias)
        if field == "description" and type(existing) is not dict:
            raise OperationalError(
                f"Set aws.region_aliases.{alias}.region before its description."
            )
        aliases.setdefault(alias, {})[field] = value
        _validate_config(data)
        return
    if parts[:2] == ["naming", "resources"] and len(parts) == 4:
        resource, field = parts[2:]
        validate_name(resource, kind="naming resource")
        if field not in NAMING_FIELDS:
            raise OperationalError(
                f"Unknown config option {key!r}; run 'config options'."
            )
        data["naming"]["resources"].setdefault(resource, {})[field] = value
        _validate_config(data)
        return
    if parts[:2] == ["naming", "accounts"] and len(parts) == 4:
        account, field = parts[2:]
        validate_name(account, kind="naming account")
        if field not in NAMING_FIELDS:
            raise OperationalError(
                f"Unknown config option {key!r}; run 'config options'."
            )
        data["naming"]["accounts"].setdefault(account, {})[field] = value
        _validate_config(data)
        return
    if parts[:2] == ["naming", "account_resources"] and len(parts) == 5:
        account, resource, field = parts[2:]
        validate_name(account, kind="naming account")
        validate_name(resource, kind="naming resource")
        if field not in NAMING_FIELDS:
            raise OperationalError(
                f"Unknown config option {key!r}; run 'config options'."
            )
        data["naming"]["account_resources"].setdefault(account, {}).setdefault(
            resource, {}
        )[field] = value
        _validate_config(data)
        return
    if (
        parts[:1] == ["accounts"]
        and len(parts) == 3
        and parts[2] in {"credential_target", "region"}
    ):
        account, value_map = get_resource(data, "account", parts[1])
        data["accounts"][account] = {**value_map, parts[2]: value}
        _validate_config(data)
        return
    if parts[:1] == ["targets"] and len(parts) == 3 and parts[2] == "region":
        target, value_map = get_resource(data, "target", parts[1])
        data["targets"][target] = {**value_map, "region": value}
        _validate_config(data)
        return
    current: dict[str, Any] = data
    for part in parts[:-1]:
        child = current.get(part)
        if type(child) is not dict:
            raise OperationalError(
                f"Unknown config option {key!r}; run 'config options'."
            )
        current = child
    if parts[-1] not in current or type(current[parts[-1]]) is dict:
        raise OperationalError(f"Config option {key!r} is not a settable leaf.")
    current[parts[-1]] = value
    _validate_config(data)


def reset_config_option(data: dict[str, Any], key: str) -> None:
    """Reset a known option to its schema-one default where one exists."""
    defaults = default_config()
    parts = _option_parts(key)
    if parts[:2] == ["aws", "region_aliases"] and len(parts) == 4:
        alias, field = parts[2:]
        aliases = data["aws"]["region_aliases"]
        existing = aliases.get(alias)
        if type(existing) is not dict or field not in existing:
            raise OperationalError(f"Config option {key!r} has no reset default.")
        if field == "region":
            del aliases[alias]
        elif field == "description":
            del existing[field]
        else:
            raise OperationalError(f"Config option {key!r} has no reset default.")
        _validate_config(data)
        return
    if parts[:2] == ["naming", "resources"] and len(parts) == 4:
        resource, field = parts[2:]
        override = data["naming"]["resources"].get(resource)
        if (
            field not in NAMING_FIELDS
            or type(override) is not dict
            or field not in override
        ):
            raise OperationalError(f"Config option {key!r} has no reset default.")
        del override[field]
        if not override:
            del data["naming"]["resources"][resource]
        _validate_config(data)
        return
    if parts[:2] == ["naming", "accounts"] and len(parts) == 4:
        account, field = parts[2:]
        override = data["naming"]["accounts"].get(account)
        if (
            field not in NAMING_FIELDS
            or type(override) is not dict
            or field not in override
        ):
            raise OperationalError(f"Config option {key!r} has no reset default.")
        del override[field]
        if not override:
            del data["naming"]["accounts"][account]
        _validate_config(data)
        return
    if parts[:2] == ["naming", "account_resources"] and len(parts) == 5:
        account, resource, field = parts[2:]
        resources = data["naming"]["account_resources"].get(account)
        override = resources.get(resource) if type(resources) is dict else None
        if (
            field not in NAMING_FIELDS
            or type(override) is not dict
            or field not in override
        ):
            raise OperationalError(f"Config option {key!r} has no reset default.")
        del override[field]
        if not override:
            del resources[resource]
        if not resources:
            del data["naming"]["account_resources"][account]
        _validate_config(data)
        return
    if (
        len(parts) == 3
        and parts[0] in {"accounts", "targets"}
        and parts[2]
        in ({"credential_target", "region"} if parts[0] == "accounts" else {"region"})
    ):
        kind = "account" if parts[0] == "accounts" else "target"
        canonical, value = get_resource(data, kind, parts[1])
        if parts[2] not in value:
            raise OperationalError(f"Config option {key!r} has no reset default.")
        value.pop(parts[2])
        data[parts[0]][canonical] = value
        _validate_config(data)
        return
    current: dict[str, Any] = data
    default_current: dict[str, Any] = defaults
    for part in parts[:-1]:
        if (
            type(current.get(part)) is not dict
            or type(default_current.get(part)) is not dict
        ):
            raise OperationalError(f"Config option {key!r} has no reset default.")
        current = current[part]
        default_current = default_current[part]
    if parts[-1] not in default_current:
        raise OperationalError(f"Config option {key!r} has no reset default.")
    current[parts[-1]] = deepcopy(default_current[parts[-1]])
    _validate_config(data)


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
