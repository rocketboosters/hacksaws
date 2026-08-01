"""Strict IAM policy document loading, validation, and canonicalization."""

from __future__ import annotations

import hashlib
import json
import math
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING
from urllib.parse import unquote

import yaml

if TYPE_CHECKING:
    from pathlib import Path

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class PolicyInputError(ValueError):
    """Report a strict policy input parsing failure."""


class MetadataMode(StrEnum):
    """Select where policy import metadata is loaded from."""

    NESTED = "nested"
    SIDECAR = "sidecar"
    NONE = "none"


class PolicyFormat(StrEnum):
    """Supported human-authored policy input formats."""

    JSON = "json"
    YAML = "yaml"
    TOML = "toml"

    @classmethod
    def from_path(cls, path: Path) -> PolicyFormat:
        """Infer a supported policy format from a filename."""
        suffix = path.suffix.casefold()
        if suffix == ".json":
            return cls.JSON
        if suffix in {".yaml", ".yml"}:
            return cls.YAML
        if suffix == ".toml":
            return cls.TOML
        message = f"Unsupported policy file extension {path.suffix!r}."
        raise PolicyInputError(message)


@dataclass(frozen=True, slots=True)
class InputMetadata:
    """Simple metadata accompanying an imported policy document."""

    name: str | None = None
    description: str | None = None
    path: str | None = None
    tags: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class LoadedPolicyInput:
    """A strict JSON-compatible IAM policy plus optional metadata."""

    document: dict[str, JsonValue]
    metadata: InputMetadata
    source: Path
    source_format: PolicyFormat
    sidecar: Path | None = None

    @property
    def canonical_json(self) -> str:
        """Return deterministic JSON without changing policy semantics."""
        return canonical_policy_json(self.document)

    @property
    def digest(self) -> str:
        """Return a stable SHA-256 digest of the semantic document."""
        return policy_digest(self.document)


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    *,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as error:
            message = "YAML mapping keys must be scalar and hashable."
            raise PolicyInputError(message) from error
        if duplicate:
            message = f"Duplicate YAML mapping key {key!r}."
            raise PolicyInputError(message)
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _reject_duplicate_json(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            message = f"Duplicate JSON mapping key {key!r}."
            raise PolicyInputError(message)
        result[key] = value
    return result


def _json_value(value: object, *, location: str = "$") -> JsonValue:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            message = f"Non-finite number at {location} is not valid JSON."
            raise PolicyInputError(message)
        return value
    if isinstance(value, list):
        return [
            _json_value(item, location=f"{location}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                message = f"Object key at {location} must be a string, got {key!r}."
                raise PolicyInputError(message)
            result[key] = _json_value(item, location=f"{location}.{key}")
        return result
    message = f"Unsupported value at {location}: {type(value).__name__}."
    raise PolicyInputError(message)


def _object(value: object, *, label: str) -> dict[str, JsonValue]:
    converted = _json_value(value)
    if not isinstance(converted, dict):
        message = f"{label} must be an object."
        raise PolicyInputError(message)
    return converted


def _parse_text(text: str, policy_format: PolicyFormat) -> object:
    try:
        if policy_format is PolicyFormat.JSON:
            return json.loads(text, object_pairs_hook=_reject_duplicate_json)
        if policy_format is PolicyFormat.YAML:
            return yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506
        return tomllib.loads(text)
    except PolicyInputError:
        raise
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, yaml.YAMLError) as error:
        message = f"Invalid {policy_format.value.upper()} policy input: {error}"
        raise PolicyInputError(message) from error


def _metadata_tags(raw_tags: JsonValue) -> tuple[tuple[str, str], ...]:
    tags: list[tuple[str, str]] = []
    if isinstance(raw_tags, dict):
        for tag_key, tag_value in raw_tags.items():
            if not isinstance(tag_value, str):
                message = f"Policy metadata tag {tag_key!r} must have a string value."
                raise PolicyInputError(message)
            tags.append((tag_key, tag_value))
        return tuple(tags)
    if not isinstance(raw_tags, list):
        message = "Policy metadata tags must be an object or key/value object list."
        raise PolicyInputError(message)
    for index, item in enumerate(raw_tags):
        if not isinstance(item, dict):
            message = f"Policy metadata tags[{index}] must be an object."
            raise PolicyInputError(message)
        listed_key = item.get("key")
        tag_value = item.get("value", "")
        if not isinstance(listed_key, str) or not isinstance(tag_value, str):
            message = f"Policy metadata tags[{index}] requires string key/value."
            raise PolicyInputError(message)
        tags.append((listed_key, tag_value))
    return tuple(tags)


def _metadata(value: object) -> InputMetadata:
    if value is None:
        return InputMetadata()
    data = _object(value, label="Policy metadata")
    allowed = {"name", "description", "path", "tags"}
    unknown = sorted(set(data) - allowed)
    if unknown:
        message = f"Unknown policy metadata fields: {', '.join(unknown)}."
        raise PolicyInputError(message)

    def optional_string(key: str) -> str | None:
        item = data.get(key)
        if item is None:
            return None
        if not isinstance(item, str):
            message = f"Policy metadata {key!r} must be a string."
            raise PolicyInputError(message)
        return item

    raw_tags = data.get("tags", {})
    return InputMetadata(
        name=optional_string("name"),
        description=optional_string("description"),
        path=optional_string("path"),
        tags=_metadata_tags(raw_tags),
    )


def _default_sidecar(path: Path) -> Path:
    return path.with_name(f"{path.stem}.metadata{path.suffix}")


def load_policy_input(
    path: Path,
    *,
    metadata_mode: MetadataMode = MetadataMode.NONE,
    sidecar: Path | None = None,
) -> LoadedPolicyInput:
    """Load JSON, YAML, or TOML without lossy policy normalization."""
    policy_format = PolicyFormat.from_path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        message = f"Unable to read policy input {path}: {error}"
        raise PolicyInputError(message) from error
    parsed = _parse_text(text, policy_format)
    metadata = InputMetadata()
    document_source = parsed
    used_sidecar: Path | None = None

    if metadata_mode is MetadataMode.NESTED:
        wrapper = _object(parsed, label="Nested policy input")
        unknown = sorted(set(wrapper) - {"metadata", "policy"})
        if unknown:
            message = f"Unknown nested policy fields: {', '.join(unknown)}."
            raise PolicyInputError(message)
        if "policy" not in wrapper:
            message = "Nested policy input requires a 'policy' object."
            raise PolicyInputError(message)
        document_source = wrapper["policy"]
        metadata = _metadata(wrapper.get("metadata"))
    elif metadata_mode is MetadataMode.SIDECAR:
        used_sidecar = sidecar or _default_sidecar(path)
        sidecar_format = PolicyFormat.from_path(used_sidecar)
        try:
            sidecar_text = used_sidecar.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            message = f"Unable to read policy metadata sidecar {used_sidecar}: {error}"
            raise PolicyInputError(message) from error
        metadata = _metadata(_parse_text(sidecar_text, sidecar_format))

    document = _object(document_source, label="IAM policy document")
    return LoadedPolicyInput(
        document=document,
        metadata=metadata,
        source=path,
        source_format=policy_format,
        sidecar=used_sidecar,
    )


def canonical_policy_json(document: Mapping[str, JsonValue]) -> str:
    """Serialize deterministically while preserving arrays and scalar forms."""
    return json.dumps(
        dict(document),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def policy_digest(document: Mapping[str, JsonValue]) -> str:
    """Hash the canonical semantic representation of a policy document."""
    canonical = canonical_policy_json(document).encode()
    return hashlib.sha256(canonical).hexdigest()


def decode_iam_document(value: object) -> dict[str, JsonValue]:
    """Normalize boto3-decoded or raw RFC3986 IAM policy output."""
    if isinstance(value, str):
        try:
            value = json.loads(unquote(value), object_pairs_hook=_reject_duplicate_json)
        except json.JSONDecodeError as error:
            message = f"IAM returned an invalid policy document: {error}"
            raise PolicyInputError(message) from error
    return _object(value, label="IAM policy document")
