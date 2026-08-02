"""Session-policy parsing, storage, resolution, and inspection cache."""

from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import boto3
import yaml
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from hacksaws import _state
from hacksaws._configs import OperationalError

POLICY_ARN = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::(aws|\d{12}):policy/(.+)$")
PATH_SUFFIXES = {".json", ".yaml", ".yml", ".toml"}


@dataclass(frozen=True)
class ResolvedPolicy:
    """Policy material ready for AssumeRole."""

    identity: str
    origin: str
    provenance: str
    arn: str | None = None
    document: str | None = None
    cached: bool = False
    source_arn: str | None = None


def _validate_document(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OperationalError("An IAM policy document must be an object.")
    if "Version" not in value or "Statement" not in value:
        raise OperationalError("An IAM policy requires Version and Statement fields.")
    if not isinstance(value["Statement"], (dict, list)):
        raise OperationalError("IAM policy Statement must be an object or list.")
    return value


def parse_policy(
    path: Path, *, format_name: str | None = None
) -> tuple[dict[str, Any], bytes]:
    """Parse and validate an IAM policy file, returning its original bytes."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise OperationalError(f"Unable to read policy file {path}: {error}") from error
    kind = (format_name or path.suffix.lstrip(".")).lower()
    return parse_policy_bytes(raw, kind=kind, source=str(path)), raw


def parse_policy_bytes(raw: bytes, *, kind: str, source: str) -> dict[str, Any]:
    """Parse policy bytes without touching live state."""
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise OperationalError(
            f"Policy {source} is not valid UTF-8: {error}"
        ) from error
    try:
        if kind == "json":
            value = json.loads(text)
        elif kind in {"yaml", "yml"}:
            value = yaml.safe_load(text)
        elif kind == "toml":
            value = tomllib.loads(text)
        else:
            raise OperationalError(f"Unsupported policy format {kind!r}.")
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, yaml.YAMLError) as error:
        raise OperationalError(
            f"Invalid {kind.upper()} policy {source}: {error}"
        ) from error
    return _validate_document(value)


def minify(value: object) -> str:
    """Return canonical compact JSON for an IAM document."""
    return json.dumps(_validate_document(value), separators=(",", ":"), sort_keys=True)


def enforce_inline_limit(document: str) -> None:
    """Enforce the STS inline session policy character limit."""
    size = len(document)
    if size > 2048:
        raise OperationalError(
            f"Inline session policy is {size} characters; AWS AssumeRole permits at most "
            "2048. Use a same-account customer-managed policy ARN instead."
        )


def stored_directory() -> Path:
    return _state.root() / "stored_session_policies"


def add_stored(name: str, source: Path, description: str | None = None) -> None:
    """Add a validated canonical stored policy."""
    config = _state.load_config()
    document, raw = parse_policy(source)
    suffix = source.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        encoded = raw
    else:
        encoded = yaml.safe_dump(document, sort_keys=False).encode()
    _state.add_resource(
        config,
        "policy",
        name,
        {
            "file": f"stored_session_policies/{name}.yaml",
            **({"description": description} if description else {}),
        },
    )
    _state.atomic_write(stored_directory() / f"{name}.yaml", encoded)
    try:
        _state.save_config(config)
    except Exception:
        (stored_directory() / f"{name}.yaml").unlink(missing_ok=True)
        raise


def update_stored(name: str, source: Path, description: str | None = None) -> None:
    """Replace stored policy content while retaining its identity."""
    config = _state.load_config()
    key, metadata = _state.get_resource(config, "policy", name)
    document, raw = parse_policy(source)
    encoded = (
        raw
        if source.suffix.lower() in {".yaml", ".yml"}
        else yaml.safe_dump(document, sort_keys=False).encode()
    )
    path = stored_directory() / f"{key}.yaml"
    _state.atomic_write(path, encoded)
    if description is not None:
        metadata["description"] = description
    _state.save_config(config)


def remove_stored(name: str) -> None:
    config = _state.load_config()
    key, _ = _state.get_resource(config, "policy", name)
    _state.remove_resource(config, "policy", name)
    _state.save_config(config)
    (stored_directory() / f"{key}.yaml").unlink(missing_ok=True)


def rename_stored(old: str, new: str) -> None:
    config = _state.load_config()
    key, metadata = _state.get_resource(config, "policy", old)
    old_path = stored_directory() / f"{key}.yaml"
    new_path = stored_directory() / f"{new}.yaml"
    config_path = _state.root() / "config.json"
    sessions_path = _state.sessions_path()
    snapshots = {
        path: path.read_bytes() if path.exists() else None
        for path in (config_path, sessions_path, old_path, new_path)
    }
    try:
        # The resource validator requires a policy's canonical path to match its
        # name. Update the shared metadata object before rename_resource performs
        # its final whole-config validation.
        metadata["file"] = f"stored_session_policies/{new}.yaml"
        _state.rename_resource(config, "policy", old, new)
        if old_path.exists():
            old_path.replace(new_path)
        _state.save_config(config)
    except Exception:
        for path, content in snapshots.items():
            if content is None:
                path.unlink(missing_ok=True)
            else:
                _state.atomic_write(path, content)
        raise


def cache_root() -> Path:
    return _state.root() / "policy-cache"


def _cache_identity(source: str, *, account: str, partition: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", source.casefold()).strip("-")[-80:] or "policy"
    return f"{partition}-{account}-{slug}-{_state.digest(source.encode())[:12]}"


def _cache_path(identity: str) -> Path:
    return cache_root() / f"{identity}.json"


def cache_write(
    identity: str,
    document: object,
    *,
    origin: str,
    resolver: str,
    source_identity: str,
) -> str:
    compact = minify(document)
    bound = {
        "identity": identity,
        "origin": origin,
        "resolver": resolver,
        "source_identity": source_identity,
        "document": json.loads(compact),
    }
    record = {
        "schema_version": 2,
        **bound,
        "fetched_at": datetime.now(UTC).isoformat(),
        "digest": _state.digest(
            json.dumps(bound, sort_keys=True, separators=(",", ":")).encode()
        ),
    }
    _state.atomic_write(
        _cache_path(identity), (json.dumps(record, indent=2) + "\n").encode()
    )
    return compact


def cache_read(identity: str, max_age: int) -> tuple[dict[str, Any], float] | None:
    if max_age == 0:
        return None
    path = _cache_path(identity)
    if not path.exists():
        return None
    try:
        value, fetched, _digest = _validated_cache_record(
            json.loads(path.read_text(encoding="utf-8")), identity=identity
        )
        age = (datetime.now(UTC) - fetched).total_seconds()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise OperationalError(f"Invalid policy cache entry {path}: {error}") from error
    if age > max_age:
        return None
    return value, age


def _validated_cache_record(
    value: object, *, identity: str
) -> tuple[dict[str, Any], datetime, str]:
    if not isinstance(value, dict):
        raise TypeError("entry is not an object")
    fetched = datetime.fromisoformat(str(value["fetched_at"]))
    document = json.loads(minify(value["document"]))
    if value.get("schema_version") != 2:
        raise ValueError("unsupported schema version")
    if value.get("identity") != identity:
        raise ValueError("entry identity does not match its cache key")
    bound = {
        "identity": identity,
        "origin": str(value["origin"]),
        "resolver": str(value["resolver"]),
        "source_identity": str(value["source_identity"]),
        "document": document,
    }
    digest = _state.digest(
        json.dumps(bound, sort_keys=True, separators=(",", ":")).encode()
    )
    if value.get("digest") != digest:
        raise ValueError("document digest mismatch")
    return value, fetched, digest


def _public_cache_entry(path: Path, max_age: int) -> dict[str, Any]:
    identity = path.stem
    base: dict[str, Any] = {
        "identity": identity,
        "path": str(path),
    }
    try:
        base["size"] = path.stat().st_size
        value, fetched, digest = _validated_cache_record(
            json.loads(path.read_text(encoding="utf-8")), identity=identity
        )
        age = max(0.0, (datetime.now(UTC) - fetched).total_seconds())
        base.update(
            {
                "state": "fresh" if max_age > 0 and age <= max_age else "stale",
                "origin": value.get("origin"),
                "resolver": value.get("resolver"),
                "source_identity": value.get("source_identity"),
                "fetched_at": value["fetched_at"],
                "age_seconds": int(age),
                "digest": digest,
            }
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        base.update(
            {"size": int(base.get("size", 0)), "state": "invalid", "error": str(error)}
        )
    return base


def cache_inventory(*, max_age: int | None = None) -> dict[str, Any]:
    """Return secret-free policy-cache metadata, including invalid entries."""
    configured_age = (
        _state.load_config()["cache"]["max_age"] if max_age is None else max_age
    )
    paths = sorted(cache_root().glob("*.json")) if cache_root().exists() else []
    entries = [_public_cache_entry(path, configured_age) for path in paths]
    counts = {"fresh": 0, "stale": 0, "invalid": 0}
    for entry in entries:
        counts[str(entry["state"])] += 1
    return {
        "root": str(cache_root()),
        "max_age": configured_age,
        "entries": entries,
        "counts": counts,
        "total_bytes": sum(int(item["size"]) for item in entries),
    }


def _validated_cache_path(identity: str) -> Path:
    normalized = identity.removesuffix(".json")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", normalized):
        raise OperationalError(f"Invalid policy cache identity {identity!r}.")
    return _cache_path(normalized)


def cache_show(identity: str) -> dict[str, Any]:
    """Read one explicitly requested policy-cache entry, including its document."""
    path = _validated_cache_path(identity)
    if not path.is_file():
        raise OperationalError(f"Policy cache entry does not exist: {identity}")
    try:
        value, _fetched, _digest = _validated_cache_record(
            json.loads(path.read_text(encoding="utf-8")), identity=path.stem
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise OperationalError(f"Invalid policy cache entry {path}: {error}") from error
    return {"identity": path.stem, "path": str(path), **value}


def clear_cache_entries(
    identities: list[str] | None = None, *, stale_only: bool = False
) -> list[str]:
    """Remove selected policy-cache records and return removed identities."""
    if identities:
        inventory = cache_inventory()
        paths = [
            Path(str(item["path"]))
            for item in inventory["entries"]
            if any(
                fnmatch.fnmatchcase(
                    str(item["identity"]).casefold(), selector.casefold()
                )
                for selector in identities
            )
        ]
    else:
        inventory = cache_inventory()
        allowed = {"stale", "invalid"} if stale_only else {"fresh", "stale", "invalid"}
        paths = [
            Path(str(item["path"]))
            for item in inventory["entries"]
            if item["state"] in allowed
        ]
    removed = []
    for path in paths:
        if path.is_file():
            path.unlink()
            removed.append(path.stem)
    if cache_root().exists():
        with suppress(OSError):
            cache_root().rmdir()
    return removed


def resolve(
    value: str,
    *,
    account_id: str,
    partition: str,
    profile: str = "default",
    max_age: int | None = None,
    session: Any | None = None,
) -> ResolvedPolicy:
    """Resolve ARN, file, stored, then remote policy name in strict order."""
    arn_match = POLICY_ARN.fullmatch(value)
    if arn_match:
        if arn_match.group(1) != partition:
            raise OperationalError(
                f"Policy ARN partition {arn_match.group(1)!r} does not match "
                f"target partition {partition!r}."
            )
        policy_account = arn_match.group(2)
        if policy_account != "aws" and policy_account != account_id:
            raise OperationalError(
                "A customer-managed session policy must belong to the target role account."
            )
        if policy_account != "aws":
            return ResolvedPolicy(
                value,
                "remote-customer",
                "explicit ARN",
                arn=value,
                source_arn=value,
            )
        return _fetch_aws_managed(
            value,
            account_id=account_id,
            partition=partition,
            profile=profile,
            max_age=max_age,
            session=session,
        )

    candidate = Path(value).expanduser()
    explicit_path = candidate.suffix.lower() in PATH_SUFFIXES or any(
        mark in value for mark in ("/", "\\")
    )
    if explicit_path:
        if not candidate.is_file():
            raise OperationalError(f"Policy path does not exist: {candidate}")
        document, _ = parse_policy(candidate)
        compact = minify(document)
        enforce_inline_limit(compact)
        identity = (
            "local-" + _state.digest(str(candidate.resolve()).casefold().encode())[:24]
        )
        cache_write(
            identity,
            document,
            origin="local",
            resolver="file",
            source_identity=str(candidate.resolve()),
        )
        return ResolvedPolicy(identity, "local", str(candidate), document=compact)

    config = _state.load_config()
    stored_key = next(
        (key for key in config["policies"] if key.casefold() == value.casefold()), None
    )
    if stored_key:
        path = stored_directory() / f"{stored_key}.yaml"
        document, _ = parse_policy(path)
        compact = minify(document)
        enforce_inline_limit(compact)
        cache_write(
            f"stored-{stored_key.casefold()}",
            document,
            origin="stored",
            resolver="stored",
            source_identity=stored_key,
        )
        return ResolvedPolicy(
            stored_key, "stored", f"stored policy {stored_key}", document=compact
        )
    return _resolve_remote_name(
        value, account_id, partition, profile, max_age, session=session
    )


def _get_document(client: Any, arn: str, version: str) -> object:
    response = client.get_policy_version(PolicyArn=arn, VersionId=version)
    document = response["PolicyVersion"]["Document"]
    if isinstance(document, str):
        document = json.loads(unquote(document))
    return document


def _require_cache_metadata(
    record: dict[str, Any],
    *,
    identity: str,
    origin: str,
    resolver: str,
    source_identity: str | None = None,
) -> None:
    expected = {"origin": origin, "resolver": resolver}
    mismatches = [key for key, value in expected.items() if record.get(key) != value]
    if source_identity is not None and record.get("source_identity") != source_identity:
        mismatches.append("source_identity")
    if mismatches:
        raise OperationalError(
            f"Policy cache entry {identity!r} metadata does not match the requested "
            f"policy ({', '.join(mismatches)}). Clear the entry and retry."
        )


def _fetch_aws_managed(
    arn: str,
    *,
    account_id: str,
    partition: str,
    profile: str,
    max_age: int | None,
    session: Any | None = None,
) -> ResolvedPolicy:
    identity = _cache_identity(arn, account=account_id, partition=partition)
    configured_age = (
        _state.load_config()["cache"]["max_age"] if max_age is None else max_age
    )
    cached = cache_read(identity, configured_age)
    if cached:
        _require_cache_metadata(
            cached[0],
            identity=identity,
            origin="aws-managed",
            resolver="arn",
            source_identity=arn,
        )
        compact = minify(cached[0]["document"])
        enforce_inline_limit(compact)
        return ResolvedPolicy(
            identity,
            "aws-managed",
            f"cached policy ({cached[1]:.0f}s old)",
            document=compact,
            cached=True,
            source_arn=arn,
        )
    try:
        client = (session or boto3.Session(profile_name=profile)).client("iam")
        metadata = client.get_policy(PolicyArn=arn)["Policy"]
        document = _get_document(client, arn, metadata["DefaultVersionId"])
    except (
        BotoCoreError,
        ClientError,
        KeyError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise OperationalError(
            f"Unable to fetch AWS-managed policy {arn}: {error}"
        ) from error
    compact = cache_write(
        identity, document, origin="aws-managed", resolver="arn", source_identity=arn
    )
    enforce_inline_limit(compact)
    return ResolvedPolicy(
        identity, "aws-managed", arn, document=compact, source_arn=arn
    )


def _resolve_remote_name(
    name: str,
    account_id: str,
    partition: str,
    profile: str,
    max_age: int | None,
    *,
    session: Any | None = None,
) -> ResolvedPolicy:
    source = f"name:{name}"
    identity = _cache_identity(source, account=account_id, partition=partition)
    configured_age = (
        _state.load_config()["cache"]["max_age"] if max_age is None else max_age
    )
    cached = cache_read(identity, configured_age)
    if cached:
        _require_cache_metadata(
            cached[0],
            identity=identity,
            origin="remote-customer",
            resolver="name",
        )
        origin = "remote-customer"
        cached_arn = str(cached[0]["source_identity"])
        cached_match = POLICY_ARN.fullmatch(cached_arn)
        if (
            cached_match is None
            or cached_match.group(1) != partition
            or cached_match.group(2) != account_id
            or cached_match.group(3).rsplit("/", 1)[-1] != name
        ):
            raise OperationalError(
                "Cached customer policy identity does not match the requested policy "
                "name and target account."
            )
        return ResolvedPolicy(
            identity,
            origin,
            f"cached policy ({cached[1]:.0f}s old)",
            arn=cached_arn,
            cached=True,
            source_arn=cached_arn,
        )
    resolution_session = session or boto3.Session(profile_name=profile)
    try:
        identity_response = resolution_session.client("sts").get_caller_identity()
        caller_account = str(identity_response["Account"])
        caller_arn = str(identity_response["Arn"])
        caller_partition = caller_arn.split(":", 2)[1]
    except (BotoCoreError, ClientError, KeyError, IndexError) as error:
        raise OperationalError(
            f"Unable to verify credentials for remote policy name {name!r}: {error}"
        ) from error
    if caller_account != account_id or caller_partition != partition:
        raise OperationalError(
            f"Bare policy name {name!r} targets {partition}:{account_id}, but the "
            f"authenticated resolver is {caller_partition}:{caller_account}. Use a "
            "full ARN or authenticate to the target account."
        )
    try:
        client = resolution_session.client("iam")
        local = [
            item
            for page in client.get_paginator("list_policies").paginate(Scope="Local")
            for item in page.get("Policies", [])
            if item.get("PolicyName") == name
        ]
        aws = [
            item
            for page in client.get_paginator("list_policies").paginate(Scope="AWS")
            for item in page.get("Policies", [])
            if item.get("PolicyName") == name
        ]
    except (BotoCoreError, ClientError) as error:
        arn = f"arn:{partition}:iam::{account_id}:policy/{name}"
        return ResolvedPolicy(
            identity,
            "remote-customer",
            f"unverified constructed ARN after list failure: {error}",
            arn=arn,
            source_arn=arn,
        )
    if local and aws:
        raise OperationalError(
            f"Policy name {name!r} is ambiguous between customer and AWS managed policies; use an ARN."
        )
    if not local and not aws:
        raise OperationalError(f"Remote IAM policy {name!r} does not exist.")
    item = (local or aws)[0]
    arn = str(item["Arn"])
    if local:
        try:
            document = _get_document(client, arn, str(item["DefaultVersionId"]))
            cache_write(
                identity,
                document,
                origin="remote-customer",
                resolver="name",
                source_identity=arn,
            )
        except (BotoCoreError, ClientError, KeyError) as error:
            raise OperationalError(
                f"Unable to inspect customer-managed policy {arn}: {error}"
            ) from error
        return ResolvedPolicy(
            identity,
            "remote-customer",
            "verified remote name",
            arn=arn,
            source_arn=arn,
        )
    return _fetch_aws_managed(
        arn,
        account_id=account_id,
        partition=partition,
        profile=profile,
        max_age=max_age,
        session=session,
    )
