"""Canonical AWS region discovery, aliases, validation, and precedence."""

from __future__ import annotations

import difflib
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from typing import TYPE_CHECKING
from typing import Literal

import botocore.session
from botocore.exceptions import UnknownRegionError

from hacksaws._configs import OperationalError

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Iterable

OPERATIONAL_PARTITIONS = frozenset({"aws", "aws-cn", "aws-us-gov"})
REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-\d+$")
ALIAS_SEPARATOR_RE = re.compile(r"[\s._-]+")
MAX_PROMPT_ATTEMPTS = 5

ResolutionSource = Literal["canonical", "compact", "geography", "custom", "unknown"]
PreferenceSource = Literal[
    "explicit",
    "aws-region-env",
    "aws-default-region-env",
    "target",
    "destination-profile",
    "source-profile",
    "account",
    "global",
    "prompt",
]

# Friendly names are intentionally curated. Stored configuration always uses the
# canonical region, so additions here expand input vocabulary without migration.
CURATED_GEOGRAPHY_ALIASES: dict[str, tuple[str, ...]] = {
    "af-south-1": ("cape-town",),
    "ap-east-1": ("hong-kong",),
    "ap-east-2": ("taipei",),
    "ap-northeast-1": ("tokyo",),
    "ap-northeast-2": ("seoul",),
    "ap-northeast-3": ("osaka",),
    "ap-south-1": ("mumbai",),
    "ap-south-2": ("hyderabad",),
    "ap-southeast-1": ("singapore",),
    "ap-southeast-2": ("sydney",),
    "ap-southeast-3": ("jakarta",),
    "ap-southeast-4": ("melbourne",),
    "ap-southeast-5": ("malaysia",),
    "ap-southeast-6": ("new-zealand",),
    "ap-southeast-7": ("thailand",),
    "ca-central-1": ("canada-central",),
    "ca-west-1": ("calgary", "canada-west"),
    "cn-north-1": ("beijing",),
    "cn-northwest-1": ("ningxia",),
    "eu-central-1": ("frankfurt",),
    "eu-central-2": ("zurich",),
    "eu-north-1": ("stockholm",),
    "eu-south-1": ("milan",),
    "eu-south-2": ("spain",),
    "eu-west-1": ("ireland",),
    "eu-west-2": ("london",),
    "eu-west-3": ("paris",),
    "il-central-1": ("tel-aviv",),
    "me-central-1": ("uae",),
    "me-south-1": ("bahrain",),
    "mx-central-1": ("mexico-central",),
    "sa-east-1": ("sao-paulo",),
    "us-east-1": ("n-virginia", "north-virginia", "virginia"),
    "us-east-2": ("ohio",),
    "us-gov-east-1": ("govcloud-east",),
    "us-gov-west-1": ("govcloud-west",),
    "us-west-1": ("n-california", "north-california"),
    "us-west-2": ("oregon",),
}

_DIRECTION_ABBREVIATIONS = {
    "north": "n",
    "south": "s",
    "east": "e",
    "west": "w",
    "central": "c",
    "northeast": "ne",
    "northwest": "nw",
    "southeast": "se",
    "southwest": "sw",
}


class RegionError(OperationalError):
    """Structured region failure suitable for human and JSON repairs."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        candidates: Iterable[str] = (),
        repairs: Iterable[str] = (),
    ) -> None:
        self.code = code
        selected = tuple(candidates)
        super().__init__(
            message,
            data={"code": code, "candidates": list(selected)},
            details=list(selected),
            repairs=list(repairs),
        )


@dataclass(frozen=True)
class RegionInfo:
    """One canonical Botocore region and its stable input aliases."""

    name: str
    partition: str
    description: str
    compact_alias: str | None
    geography_aliases: tuple[str, ...]
    operational: bool


@dataclass(frozen=True)
class RegionResolution:
    """Canonical result of resolving one region-like input."""

    input: str
    canonical: str
    partition: str
    description: str
    source: ResolutionSource
    matched_alias: str | None = None
    known: bool = True
    operational: bool = True
    warning: str | None = None


@dataclass(frozen=True)
class RegionPreference:
    """Effective region plus the layer that selected and may persist it."""

    resolution: RegionResolution
    source: PreferenceSource
    persist_to_destination: bool

    @property
    def canonical(self) -> str:
        """Return the canonical effective region."""
        return self.resolution.canonical


def normalize_alias(value: str) -> str:
    """Normalize a human alias without treating it as a canonical region."""
    return ALIAS_SEPARATOR_RE.sub("-", value.strip().casefold()).strip("-")


def _compact_candidate(region: str) -> str:
    parts = region.split("-")
    ordinal = parts[-1]
    words = parts[:-1]
    if not ordinal.isdigit() or not words:
        return ""
    result = words[0]
    for word in words[1:]:
        result += _DIRECTION_ABBREVIATIONS.get(word, word[:1])
    return result + ordinal


@cache
def region_registry(*, all_partitions: bool = False) -> tuple[RegionInfo, ...]:
    """Return deterministic Botocore regions with collision-free compact aliases."""
    partitions = botocore.session.get_session().get_data("partitions")["partitions"]
    raw: list[tuple[str, str, str]] = []
    for partition in partitions:
        partition_name = str(partition["id"])
        if not all_partitions and partition_name not in OPERATIONAL_PARTITIONS:
            continue
        for region, metadata in partition.get("regions", {}).items():
            canonical = str(region).casefold()
            if not REGION_RE.fullmatch(canonical):
                continue
            raw.append(
                (
                    canonical,
                    partition_name,
                    str(metadata.get("description") or canonical),
                )
            )
    compact_owners: dict[str, set[str]] = {}
    for canonical, _, _ in raw:
        compact_owners.setdefault(_compact_candidate(canonical), set()).add(canonical)
    result = []
    for canonical, partition_name, description in sorted(raw):
        compact = _compact_candidate(canonical)
        result.append(
            RegionInfo(
                name=canonical,
                partition=partition_name,
                description=description,
                compact_alias=(
                    compact if compact and len(compact_owners[compact]) == 1 else None
                ),
                geography_aliases=tuple(
                    normalize_alias(value)
                    for value in CURATED_GEOGRAPHY_ALIASES.get(canonical, ())
                ),
                operational=partition_name in OPERATIONAL_PARTITIONS,
            )
        )
    return tuple(result)


def _registry_maps(
    *,
    all_partitions: bool,
) -> tuple[dict[str, RegionInfo], dict[str, list[tuple[RegionInfo, ResolutionSource]]]]:
    canonical: dict[str, RegionInfo] = {}
    aliases: dict[str, list[tuple[RegionInfo, ResolutionSource]]] = {}
    for info in region_registry(all_partitions=all_partitions):
        canonical[info.name] = info
        if info.compact_alias:
            aliases.setdefault(info.compact_alias, []).append((info, "compact"))
        for alias in info.geography_aliases:
            aliases.setdefault(alias, []).append((info, "geography"))
    return canonical, aliases


def custom_alias_map(
    aliases: Mapping[str, object] | None,
) -> dict[str, tuple[str, str | None]]:
    """Normalize schema aliases into alias -> canonical/description pairs."""
    result: dict[str, tuple[str, str | None]] = {}
    for name, raw in (aliases or {}).items():
        alias = normalize_alias(str(name))
        if isinstance(raw, str):
            result[alias] = (raw.casefold(), None)
            continue
        if isinstance(raw, Mapping) and isinstance(raw.get("region"), str):
            description = raw.get("description")
            result[alias] = (
                str(raw["region"]).casefold(),
                str(description) if isinstance(description, str) else None,
            )
    return result


def builtin_aliases(*, all_partitions: bool = True) -> dict[str, tuple[str, ...]]:
    """Return every normalized built-in alias and its canonical candidates."""
    _, aliases = _registry_maps(all_partitions=all_partitions)
    return {
        alias: tuple(sorted({item.name for item, _ in matches}))
        for alias, matches in aliases.items()
    }


def validate_custom_aliases(aliases: Mapping[str, object]) -> None:
    """Reject malformed, chained, duplicate, or built-in-shadowing aliases."""
    canonical, builtins = _registry_maps(all_partitions=True)
    seen: set[str] = set()
    normalized_names = [normalize_alias(str(name)) for name in aliases]
    if len(set(normalized_names)) != len(normalized_names):
        raise RegionError(
            "REGION_ALIAS_CONFLICT",
            "Region aliases must have unique normalized names.",
        )
    for original, raw in aliases.items():
        alias = normalize_alias(str(original))
        if not alias or alias != str(original):
            raise RegionError(
                "REGION_ALIAS_INVALID",
                f"Region alias {original!r} must use normalized lower kebab "
                f"case {alias!r}.",
            )
        if alias in seen or alias in canonical or alias in builtins:
            raise RegionError(
                "REGION_ALIAS_CONFLICT",
                f"Region alias {alias!r} conflicts with an existing canonical "
                "or built-in alias.",
                candidates=(alias,),
                repairs=("Choose a distinct alias name.",),
            )
        seen.add(alias)
        if not isinstance(raw, Mapping) or set(raw) - {"region", "description"}:
            raise RegionError(
                "REGION_ALIAS_INVALID",
                f"Region alias {alias!r} must contain region and optional description.",
            )
        target = raw.get("region")
        if (
            not isinstance(target, str)
            or target != target.casefold()
            or target not in canonical
        ):
            raise RegionError(
                "REGION_ALIAS_INVALID",
                f"Region alias {alias!r} must store a known canonical region, "
                "not another alias.",
            )
        if not canonical[target].operational:
            raise RegionError(
                "REGION_PARTITION_UNSUPPORTED",
                f"Region alias {alias!r} targets non-operational partition "
                f"{canonical[target].partition!r}.",
                repairs=(
                    "Choose a region in the aws, aws-cn, or aws-us-gov partition.",
                ),
            )
        if "description" in raw and not isinstance(raw["description"], str):
            raise RegionError(
                "REGION_ALIAS_INVALID",
                f"Region alias {alias!r} description must be text.",
            )


def _infer_partition(value: str) -> str:
    """Infer an unknown canonical region only through Botocore partition patterns."""
    try:
        return str(botocore.session.get_session().get_partition_for_region(value))
    except UnknownRegionError as error:
        raise RegionError(
            "REGION_PARTITION_UNKNOWN",
            f"Cannot infer an AWS partition for unknown region {value!r}.",
            repairs=(
                (
                    "Use a canonical region whose prefix belongs to an operational "
                    "AWS partition."
                ),
            ),
        ) from error


def _resolution(
    info: RegionInfo, value: str, source: ResolutionSource
) -> RegionResolution:
    return RegionResolution(
        input=value,
        canonical=info.name,
        partition=info.partition,
        description=info.description,
        source=source,
        matched_alias=None if source == "canonical" else normalize_alias(value),
        operational=info.operational,
    )


def resolve_region(  # noqa: C901
    value: str,
    *,
    custom_aliases: Mapping[str, object] | None = None,
    partition: str | None = None,
    allow_unknown: bool = False,
    allow_non_operational: bool = False,
) -> RegionResolution:
    """Resolve canonical, built-in, or custom input without prompting."""
    if not isinstance(value, str) or not value.strip():
        raise RegionError("REGION_INVALID", "AWS region cannot be blank.")
    raw = value.strip().casefold()
    alias = normalize_alias(value)
    canonical, builtins = _registry_maps(all_partitions=True)
    if raw in canonical:
        matches: list[tuple[RegionInfo, ResolutionSource]] = [
            (canonical[raw], "canonical")
        ]
    else:
        matches = list(builtins.get(alias, ()))
        custom = custom_alias_map(custom_aliases)
        if alias in custom:
            target, _ = custom[alias]
            info = canonical.get(target)
            if info is None:
                raise RegionError(
                    "REGION_ALIAS_INVALID",
                    f"Custom region alias {alias!r} references unavailable "
                    f"region {target!r}.",
                )
            matches.append((info, "custom"))
    if partition:
        matches = [match for match in matches if match[0].partition == partition]
    distinct = {match[0].name for match in matches}
    if len(distinct) > 1:
        candidates = sorted(distinct)
        raise RegionError(
            "REGION_AMBIGUOUS",
            f"Region alias {value!r} is ambiguous: {', '.join(candidates)}.",
            candidates=candidates,
            repairs=("Use a canonical region or collision-free compact alias.",),
        )
    if matches:
        info, source = matches[0]
        if not info.operational and not allow_non_operational:
            raise RegionError(
                "REGION_PARTITION_UNSUPPORTED",
                f"Region {info.name!r} belongs to unsupported operational "
                f"partition {info.partition!r}.",
                repairs=("Use --all-partitions only for discovery.",),
            )
        return _resolution(info, value, source)
    if allow_unknown and REGION_RE.fullmatch(raw):
        inferred_partition = _infer_partition(raw)
        if partition is not None and inferred_partition != partition:
            raise RegionError(
                "REGION_PARTITION_MISMATCH",
                f"Region {raw!r} belongs to {inferred_partition!r}, not {partition!r}.",
            )
        selected_partition = partition or inferred_partition
        if selected_partition not in OPERATIONAL_PARTITIONS:
            raise RegionError(
                "REGION_PARTITION_UNSUPPORTED",
                f"Unknown region {raw!r} is not in an operational Hacksaws partition.",
            )
        return RegionResolution(
            input=value,
            canonical=raw,
            partition=selected_partition,
            description="Unknown region accepted explicitly",
            source="unknown",
            known=False,
            warning=(
                f"Region {raw} is absent from bundled Botocore metadata; service "
                "support cannot be verified."
            ),
        )
    suggestions = suggest_regions(
        value, custom_aliases=custom_aliases, partition=partition
    )
    code = "REGION_UNKNOWN" if REGION_RE.fullmatch(raw) else "REGION_INVALID"
    raise RegionError(
        code,
        f"Unknown AWS region or alias {value!r}.",
        candidates=suggestions,
        repairs=(
            "Run 'hacksaws region list' to discover regions and aliases.",
            "Use --allow-unknown-region only for a new canonical AWS region.",
        ),
    )


def suggest_regions(
    value: str,
    *,
    custom_aliases: Mapping[str, object] | None = None,
    partition: str | None = None,
    limit: int = 5,
) -> tuple[str, ...]:
    """Return deterministic close canonical/alias suggestions."""
    canonical, builtins = _registry_maps(all_partitions=True)
    choices = {
        name
        for name, info in canonical.items()
        if (partition is None or info.partition == partition) and info.operational
    }
    choices.update(
        alias
        for alias, matches in builtins.items()
        if any(
            (partition is None or info.partition == partition) and info.operational
            for info, _ in matches
        )
    )
    choices.update(custom_alias_map(custom_aliases))
    return tuple(
        difflib.get_close_matches(
            normalize_alias(value), sorted(choices), n=limit, cutoff=0.35
        )
    )


def resolve_region_input(  # noqa: C901, PLR0913
    value: str | None,
    *,
    custom_aliases: Mapping[str, object] | None = None,
    partition: str | None = None,
    allow_unknown: bool = False,
    interactive: bool | None = None,
    default: str | None = None,
    prompt: str = "AWS Region",
    max_attempts: int = MAX_PROMPT_ATTEMPTS,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], object] = print,
) -> RegionResolution:
    """Resolve one input and strictly repair invalid interactive values."""
    can_prompt = sys.stdin.isatty() if interactive is None else interactive
    current = value
    attempts = 0
    while True:
        if current is None or not str(current).strip():
            if default:
                current = default
            elif not can_prompt:
                raise RegionError(
                    "REGION_REQUIRED",
                    "No AWS region could be resolved noninteractively.",
                    repairs=("Supply --region or configure an AWS/global region.",),
                )
        if current is not None and str(current).strip():
            try:
                return resolve_region(
                    str(current),
                    custom_aliases=custom_aliases,
                    partition=partition,
                    allow_unknown=allow_unknown,
                )
            except RegionError as error:
                if not can_prompt:
                    raise
                output_fn(str(error))
                details = (
                    error.details if isinstance(error.details, (list, tuple)) else ()
                )
                if details:
                    output_fn("Suggestions: " + ", ".join(map(str, details)))
        attempts += 1
        if attempts > max_attempts:
            raise RegionError(
                "REGION_ATTEMPTS_EXCEEDED",
                f"Unable to resolve an AWS region after {max_attempts} attempts.",
            )
        try:
            answer = input_fn(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
        except EOFError as error:
            raise RegionError(
                "REGION_CANCELLED", "AWS region selection cancelled."
            ) from error
        if answer.casefold() in {"q", "quit"}:
            raise RegionError("REGION_CANCELLED", "AWS region selection cancelled.")
        if answer == "?":
            values = [item.name for item in region_registry()]
            output_fn("Available regions: " + ", ".join(values))
            current = None
            continue
        current = answer or default


def resolve_region_preference(  # noqa: PLR0913
    *,
    explicit: str | None = None,
    env_region: str | None = None,
    env_default_region: str | None = None,
    target: str | None = None,
    destination: str | None = None,
    source: str | None = None,
    account: str | None = None,
    global_region: str | None = None,
    custom_aliases: Mapping[str, object] | None = None,
    partition: str | None = None,
    allow_unknown: bool = False,
    interactive: bool = False,
) -> RegionPreference:
    """Resolve the locked region precedence with destination persistence policy."""
    layers: tuple[tuple[PreferenceSource, str | None], ...] = (
        ("explicit", explicit),
        (
            "aws-region-env",
            env_region if env_region is not None else os.getenv("AWS_REGION"),
        ),
        (
            "aws-default-region-env",
            env_default_region
            if env_default_region is not None
            else os.getenv("AWS_DEFAULT_REGION"),
        ),
        ("target", target),
        ("destination-profile", destination),
        ("source-profile", source),
        ("account", account),
        ("global", global_region),
    )
    for layer, candidate in layers:
        if not candidate:
            continue
        resolution = resolve_region(
            candidate,
            custom_aliases=custom_aliases,
            partition=partition,
            allow_unknown=allow_unknown,
        )
        env_layer = layer in {"aws-region-env", "aws-default-region-env"}
        return RegionPreference(
            resolution=resolution,
            source=layer,
            persist_to_destination=not env_layer or not bool(destination),
        )
    resolution = resolve_region_input(
        None,
        custom_aliases=custom_aliases,
        partition=partition,
        allow_unknown=allow_unknown,
        interactive=interactive,
    )
    return RegionPreference(
        resolution=resolution, source="prompt", persist_to_destination=True
    )


def validate_service_region(
    resolution: RegionResolution,
    service: str,
    *,
    allow_unknown: bool = False,
) -> RegionResolution:
    """Require one region to support a Botocore service or regional sign-in."""
    if not resolution.known:
        if allow_unknown:
            return resolution
        raise RegionError(
            "REGION_UNKNOWN",
            f"Cannot verify {service} support for unknown region "
            f"{resolution.canonical!r}.",
        )
    if service == "signin":
        supported = resolution.partition in OPERATIONAL_PARTITIONS
    else:
        supported = (
            resolution.canonical
            in botocore.session.get_session().get_available_regions(
                service, partition_name=resolution.partition
            )
        )
    if not supported:
        raise RegionError(
            "REGION_SERVICE_UNAVAILABLE",
            f"AWS service {service!r} is unavailable in region "
            f"{resolution.canonical!r}.",
            repairs=("Choose a region listed for this service.",),
        )
    return resolution


def canonicalize_regions(
    values: Iterable[str],
    *,
    custom_aliases: Mapping[str, object] | None = None,
    partition: str | None = None,
    allow_unknown: bool = False,
    service: str | None = None,
) -> tuple[RegionResolution, ...]:
    """Resolve and canonical-deduplicate an ordered region sequence."""
    result: list[RegionResolution] = []
    seen: set[str] = set()
    for value in values:
        resolution = resolve_region(
            value,
            custom_aliases=custom_aliases,
            partition=partition,
            allow_unknown=allow_unknown,
        )
        if service:
            validate_service_region(resolution, service, allow_unknown=allow_unknown)
        if resolution.canonical in seen:
            continue
        seen.add(resolution.canonical)
        result.append(resolution)
    return tuple(result)
