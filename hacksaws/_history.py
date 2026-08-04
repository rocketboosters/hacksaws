"""Credential-free, best-effort command history for Hacksaws invocations."""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import json
import re
import sqlite3
import sys
import threading
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any
from typing import TypedDict

from hacksaws import _audit
from hacksaws import _state
from hacksaws._configs import OperationalError
from hacksaws._duration import parse_count
from hacksaws._duration import parse_duration

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Iterator

SCHEMA_VERSION = 2
REDACTION_VERSION = 2
EVENT_SCHEMA_VERSION = 1
DEFAULT_MAX_AGE = 90 * 24 * 60 * 60
DEFAULT_MAX_ENTRIES = 10_000
DEFAULT_MAX_BYTES = 50 * 1024 * 1024
_MAINTENANCE_INTERVAL = 24 * 60 * 60
_ABANDONED_AGE = 24 * 60 * 60
_INTERRUPTED_EXIT_CODE = 130
_IDENTIFIER = re.compile(r"^[\w+=,.@:/-]{1,1024}$", re.ASCII)
_COMMAND_SEGMENT = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_RESULT_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_LONG_AGO = re.compile(
    r"^((?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+))\s*"
    r"(d|day|days|w|week|weeks)$",
    re.IGNORECASE,
)
_current: ContextVar[str | None] = ContextVar("hacksaws_history_id", default=None)
_suspended: ContextVar[bool] = ContextVar("hacksaws_history_suspended", default=False)
_initialization_lock = threading.Lock()
_initialized_databases: set[Path] = set()

_SECRET_DESTS = {"external_id", "mfa_code"}
_PATH_DESTS = {
    "directory",
    "file",
    "metadata_file",
    "output",
    "source_directory",
    "to_directory",
    "trust_policy",
    "zip",
}
_IDENTIFIER_DESTS = {
    "account",
    "aws_account_name",
    "boundary",
    "destination",
    "location",
    "policy",
    "profile",
    "region",
    "resource_name",
    "role",
    "save_boundary",
    "save_name",
    "save_role_account",
    "save_source_account",
    "source_account",
    "source_profile",
    "store_policy_as",
    "target",
    "target_role",
    "to",
    "to_profile",
}
_DURATION_DESTS = {"duration", "htl", "lifespan", "mtl", "stl"}
_SAFE_FORMATS = {"json", "yaml", "yml", "toml", "zip"}
_MAX_OBSERVED_ITEMS = 64
_MAX_OPAQUE_COUNT = 255
_MAX_EVENT_BYTES = 4096
_MAX_REGISTERED_ACCOUNTS = 2
PARSE_FAILURE_KINDS = (
    "unknown-command",
    "unknown-subcommand",
    "unknown-option",
    "misplaced-option",
    "missing-command",
    "missing-subcommand",
    "missing-required-option",
    "missing-option-value",
    "invalid-choice",
    "invalid-value",
    "extra-positional",
    "mutually-exclusive",
    "duplicate-option",
    "conflicting-option",
    "invalid-combination",
    "invalid-syntax",
)
PARSE_PHASES = ("global", "selector", "argparse", "semantic")


class HistoryError(RuntimeError):
    """Raised internally when best-effort history cannot be recorded."""


class HistorySettings(TypedDict):
    """Validated history settings with built-in fallbacks."""

    enabled: bool
    max_age: int
    max_entries: int
    max_bytes: int


@dataclass(frozen=True, slots=True)
class HistoryHandle:
    """One optional invocation record active in the current process."""

    id: str | None
    started_monotonic: float
    enabled: bool


def root() -> Path:
    """Return the contained history directory."""
    return _state.root() / "history"


def database_path() -> Path:
    """Return the one SQLite history database path."""
    return root() / "history.db"


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _settings() -> HistorySettings:
    try:
        value = _state.load_config().get("history", {})
    except OperationalError:
        value = {}
    enabled = value.get("enabled", True)
    max_age = value.get("max_age", DEFAULT_MAX_AGE)
    max_entries = value.get("max_entries", DEFAULT_MAX_ENTRIES)
    max_bytes = value.get("max_bytes", DEFAULT_MAX_BYTES)
    return {
        "enabled": enabled if type(enabled) is bool else True,
        "max_age": max_age if type(max_age) is int else DEFAULT_MAX_AGE,
        "max_entries": (
            max_entries if type(max_entries) is int else DEFAULT_MAX_ENTRIES
        ),
        "max_bytes": max_bytes if type(max_bytes) is int else DEFAULT_MAX_BYTES,
    }


def _secure(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.chmod(0o600 if path.is_file() else 0o700)


def _connect() -> sqlite3.Connection:
    directory = root()
    directory.mkdir(parents=True, exist_ok=True)
    _secure(directory)
    path = database_path()
    connection = sqlite3.connect(path, timeout=5.0)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = NORMAL")
        with _initialization_lock:
            if path not in _initialized_databases:
                connection.execute("PRAGMA journal_mode = WAL")
                _migrate(connection)
                _initialized_databases.add(path)
    except BaseException:
        # sqlite3.connect() can succeed before a corrupt/locked database makes
        # an initialization PRAGMA fail. Close that partially initialized
        # handle immediately; Python 3.13+ warns when it is left to the GC.
        connection.close()
        raise
    else:
        _secure(path)
        return connection


@contextlib.contextmanager
def _database() -> Iterator[sqlite3.Connection]:
    """Commit or roll back one transaction and always close its connection."""
    connection = _connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _migrate(connection: sqlite3.Connection) -> None:
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version > SCHEMA_VERSION:
        raise HistoryError(_schema_too_new_message(version))
    if version == 0:
        with connection:
            connection.execute(
                """
                CREATE TABLE invocations (
                    id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    state TEXT NOT NULL,
                    command TEXT NOT NULL,
                    alias_used TEXT,
                    json_mode INTEGER NOT NULL,
                    interactive INTEGER NOT NULL,
                    dry_run INTEGER NOT NULL DEFAULT 0,
                    profile TEXT,
                    location TEXT,
                    target TEXT,
                    account_id TEXT,
                    partition_name TEXT,
                    resource_kind TEXT,
                    resource_name TEXT,
                    resource_arn TEXT,
                    confirmation TEXT NOT NULL DEFAULT 'not-requested',
                    outcome TEXT,
                    result_code TEXT,
                    exit_code INTEGER,
                    duration_ms INTEGER,
                    safe_json TEXT NOT NULL DEFAULT '{}',
                    recovery_unresolved INTEGER NOT NULL DEFAULT 0,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    invocation_id TEXT REFERENCES invocations(id) ON DELETE CASCADE,
                    occurred_at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    data_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            connection.execute(
                "CREATE INDEX invocation_started ON invocations(started_at DESC, id)"
            )
            connection.execute(
                "CREATE INDEX invocation_command "
                "ON invocations(command, started_at DESC)"
            )
            connection.execute(
                "CREATE INDEX invocation_outcome "
                "ON invocations(outcome, started_at DESC)"
            )
            connection.execute("PRAGMA user_version = 1")
        version = 1
    if version == 1:
        with connection:
            connection.execute(
                "CREATE INDEX IF NOT EXISTS event_invocation_kind "
                "ON events(invocation_id, kind, occurred_at, id)"
            )
            connection.execute("PRAGMA user_version = 2")


def _schema_too_new_message(version: int) -> str:
    return f"History schema {version} is newer than supported schema {SCHEMA_VERSION}."


def _canonical_command(args: argparse.Namespace) -> tuple[str, str | None]:
    access = str(getattr(args, "access_type", "unknown") or "unknown")
    alias = None
    if access == "remote":
        alias, access = access, "iam"
    elif access == "web":
        alias, access = access, "pk"
    parts = [access] if _COMMAND_SEGMENT.fullmatch(access) else ["unknown"]
    for field in (
        "action",
        "iam_action",
        "policy_action",
        "policy_tag_action",
        "role_command",
        "role_tag_action",
        "role_inline_action",
        "role_trust_action",
        "role_trust_kind",
        "resource_action",
        "cache_action",
        "config_action",
        "option_action",
        "profile_action",
        "profile_region_action",
        "history_action",
    ):
        value = getattr(args, field, None)
        segment = str(value) if value is not None else ""
        if _COMMAND_SEGMENT.fullmatch(segment) and segment not in parts:
            parts.append(segment)
    return ".".join(parts), alias


def _parser_children(
    parser: argparse.ArgumentParser,
) -> tuple[argparse._SubParsersAction[Any] | None, dict[str, argparse.ArgumentParser]]:
    for action in parser._actions:  # noqa: SLF001 - argparse exposes no public tree API
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            return action, dict(action.choices)
    return None, {}


def _option_catalog(
    parser: argparse.ArgumentParser,
) -> dict[str, tuple[argparse.Action, str]]:
    """Return every registered spelling with a stable canonical long name."""
    catalog: dict[str, tuple[argparse.Action, str]] = {}
    seen: set[int] = set()
    pending = [parser]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        for action in current._actions:  # noqa: SLF001
            if action.option_strings:
                canonical = next(
                    (
                        value
                        for value in action.option_strings
                        if value.startswith("--")
                    ),
                    action.option_strings[0],
                ).lstrip("-")
                for spelling in action.option_strings:
                    catalog.setdefault(spelling, (action, canonical))
            if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
                pending.extend(action.choices.values())
    return catalog


def _active_options(
    parsers: list[argparse.ArgumentParser],
) -> dict[str, tuple[argparse.Action, str]]:
    result: dict[str, tuple[argparse.Action, str]] = {}
    for parser in parsers:
        for action in parser._actions:  # noqa: SLF001
            if not action.option_strings:
                continue
            canonical = next(
                (value for value in action.option_strings if value.startswith("--")),
                action.option_strings[0],
            ).lstrip("-")
            for spelling in action.option_strings:
                result[spelling] = (action, canonical)
    return result


def _value_class(action: argparse.Action) -> str:
    if action.dest in _SECRET_DESTS:
        return "secret"
    if action.dest in _PATH_DESTS:
        return "path"
    if action.choices is not None:
        return "enum"
    if action.dest in _DURATION_DESTS:
        return "duration"
    if action.dest in _IDENTIFIER_DESTS:
        return "identifier"
    return "value"


def _takes_value(action: argparse.Action) -> bool:
    return action.nargs != 0


def _safe_format(value: str) -> str | None:
    suffix = Path(value).suffix.casefold().removeprefix(".")
    return suffix if suffix in _SAFE_FORMATS else ("other" if suffix else None)


def _canonical_choice(
    choices: dict[str, argparse.ArgumentParser], value: str
) -> tuple[str, argparse.ArgumentParser] | None:
    selected = choices.get(value)
    if selected is None:
        return None
    canonical = next(
        (name for name, parser in choices.items() if parser is selected), value
    )
    return canonical, selected


def observe_arguments(  # noqa: C901, PLR0912, PLR0915
    parser: argparse.ArgumentParser, arguments: list[str]
) -> dict[str, object]:
    """Build a bounded grammar-only observation without retaining raw values."""
    catalog = _option_catalog(parser)
    catalog.update(
        {
            "--json": (argparse.Action([], "json", nargs=0), "json"),
            "--no-color": (argparse.Action([], "color", nargs=0), "no-color"),
            "--color": (argparse.Action([], "color", nargs=None), "color"),
        }
    )
    parsers = [parser]
    current = parser
    command: list[str] = []
    aliases: list[str] = []
    options: dict[str, dict[str, object]] = {}
    positionals: list[dict[str, object]] = []
    positional_index = 0
    opaque_options = 0
    opaque_positionals = 0
    opaque_tail = 0
    misplaced: list[str] = []
    missing_values: list[str] = []
    truncated = False
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--":  # noqa: S105
            opaque_tail = min(len(arguments) - index - 1, _MAX_OPAQUE_COUNT)
            truncated = truncated or len(arguments) - index - 1 > _MAX_OPAQUE_COUNT
            break
        spelling, equals, attached = token.partition("=")
        if token.startswith("-"):
            active = _active_options(parsers)
            found = active.get(spelling)
            misplaced_option = False
            if found is None:
                found = catalog.get(spelling)
                misplaced_option = found is not None
            if found is None:
                opaque_options = min(opaque_options + 1, _MAX_OPAQUE_COUNT)
                truncated = truncated or opaque_options == _MAX_OPAQUE_COUNT
                index += 1
                continue
            action, canonical = found
            if misplaced_option and len(misplaced) < _MAX_OBSERVED_ITEMS:
                misplaced.append(canonical)
            item = options.setdefault(
                canonical,
                {
                    "name": canonical,
                    "count": 0,
                    "valueClass": _value_class(action),
                    "valueState": "none" if not _takes_value(action) else "missing",
                },
            )
            previous_count = item.get("count")
            count = previous_count if isinstance(previous_count, int) else 0
            item["count"] = min(count + 1, _MAX_OPAQUE_COUNT)
            if _takes_value(action):
                value: str | None = attached if equals else None
                if value is None and index + 1 < len(arguments):
                    candidate = arguments[index + 1]
                    if candidate != "--" and not candidate.startswith("-"):
                        value = candidate
                        index += 1
                if value is None or value == "":
                    if canonical not in missing_values:
                        missing_values.append(canonical)
                else:
                    item["valueState"] = "present"
                    if action.choices is not None:
                        item["valueState"] = (
                            "valid" if value in action.choices else "invalid"
                        )
                    if item["valueClass"] == "path":
                        format_name = _safe_format(value)
                        if format_name:
                            item["format"] = format_name
            index += 1
            continue
        subparsers, choices = _parser_children(current)
        if subparsers is not None:
            choice = _canonical_choice(choices, token)
            if choice is not None:
                canonical, selected = choice
                command.append(canonical)
                if canonical != token:
                    aliases.append(token)
                elif len(command) == 1 and token == "web":  # noqa: S105
                    command[-1] = "pk"
                    aliases.append("web")
                current = selected
                parsers.append(selected)
                positional_index = 0
                index += 1
                continue
            opaque_positionals = min(opaque_positionals + 1, _MAX_OPAQUE_COUNT)
            index += 1
            continue
        positional_actions = [
            action
            for action in current._actions  # noqa: SLF001
            if not action.option_strings
            and not isinstance(action, argparse._SubParsersAction)  # noqa: SLF001
            and action.dest != argparse.SUPPRESS
        ]
        if positional_index < len(positional_actions):
            action = positional_actions[positional_index]
            if len(positionals) < _MAX_OBSERVED_ITEMS:
                positionals.append(
                    {
                        "role": action.dest.replace("_", "-"),
                        "valueClass": _value_class(action),
                        "present": True,
                    }
                )
            if action.nargs not in {"*", "+"}:
                positional_index += 1
        else:
            opaque_positionals = min(opaque_positionals + 1, _MAX_OPAQUE_COUNT)
        index += 1
    if not command and opaque_positionals:
        inferred = "unknown-command"
    elif missing_values:
        inferred = "missing-option-value"
    elif misplaced:
        inferred = "misplaced-option"
    elif opaque_options:
        inferred = "unknown-option"
    elif opaque_positionals:
        inferred = "extra-positional"
    else:
        inferred = "invalid-syntax"
    canonical_command = ".".join(command) if command else "unknown"
    help_command = "hacksaws " + canonical_command.replace(".", " ")
    if canonical_command != "unknown":
        help_command += " --help"
    return {
        "command": canonical_command,
        "alias": ".".join(aliases) or None,
        "options": list(options.values())[:_MAX_OBSERVED_ITEMS],
        "positionals": positionals,
        "opaque": {
            "options": opaque_options,
            "positionals": opaque_positionals,
            "tail": opaque_tail,
            "truncated": truncated,
        },
        "misplacedOptions": sorted(set(misplaced)),
        "missingValues": missing_values[:_MAX_OBSERVED_ITEMS],
        "inferredKind": inferred,
        "helpCommand": help_command,
    }


def observe_arguments_safely(
    parser: argparse.ArgumentParser, arguments: list[str]
) -> dict[str, object]:
    """Isolate history observation failures from command execution."""
    try:
        return observe_arguments(parser, arguments)
    except Exception:  # noqa: BLE001 - telemetry must never change CLI behavior.
        return {
            "command": "unknown",
            "alias": None,
            "options": [],
            "positionals": [],
            "opaque": {
                "options": 0,
                "positionals": 0,
                "tail": 0,
                "truncated": True,
            },
            "misplacedOptions": [],
            "missingValues": [],
            "inferredKind": "invalid-syntax",
            "helpCommand": "hacksaws --help",
        }


def note_parse_failure(
    handle: HistoryHandle,
    observation: dict[str, object],
    *,
    phase: str,
    kind: str | None = None,
) -> None:
    """Persist one bounded parse event without raw argv or error text."""
    if not handle.enabled or handle.id is None:
        return
    selected_kind = kind or str(observation.get("inferredKind") or "invalid-syntax")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", selected_kind):
        selected_kind = "invalid-syntax"
    safe_phase = (
        phase if phase in {"global", "selector", "argparse", "semantic"} else "argparse"
    )
    payload = {
        "eventSchemaVersion": EVENT_SCHEMA_VERSION,
        "redactionVersion": REDACTION_VERSION,
        "phase": safe_phase,
        "command": observation.get("command", "unknown"),
        "alias": observation.get("alias"),
        "structure": {
            key: observation.get(key)
            for key in (
                "options",
                "positionals",
                "opaque",
                "misplacedOptions",
                "missingValues",
            )
        },
        "repair": {"helpCommand": observation.get("helpCommand", "hacksaws --help")},
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > _MAX_EVENT_BYTES:
        payload["structure"] = {
            "opaque": observation.get("opaque", {}),
            "truncated": True,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    try:
        with _database() as connection:
            connection.execute(
                "UPDATE invocations SET command = ?, "
                "alias_used = COALESCE(?, alias_used), updated_at = ? WHERE id = ?",
                (
                    observation.get("command", "unknown"),
                    observation.get("alias"),
                    _now(),
                    handle.id,
                ),
            )
            connection.execute(
                "INSERT INTO events (invocation_id, occurred_at, kind, data_json) "
                "VALUES (?, ?, ?, ?)",
                (handle.id, _now(), f"parse.{selected_kind}", encoded),
            )
    except (OSError, sqlite3.Error, HistoryError):
        return


def note_session_save(
    *,
    status: str,
    target: object = None,
    boundary: object = None,
    requested: bool,
    credentials_active: bool,
) -> None:
    """Record only the safe outcome of a post-credential configuration save."""
    if status not in {"saved", "noop", "failed", "cancelled"}:
        return
    identifier = _current.get()
    if identifier is None:
        return
    payload = {
        "eventSchemaVersion": EVENT_SCHEMA_VERSION,
        "redactionVersion": REDACTION_VERSION,
        "status": status,
        "target": _safe_identifier(target),
        "boundary": _safe_identifier(boundary),
        "requested": requested,
        "credentialsActive": credentials_active,
    }
    try:
        with _database() as connection:
            connection.execute(
                "INSERT INTO events (invocation_id, occurred_at, kind, data_json) "
                "VALUES (?, ?, ?, ?)",
                (
                    identifier,
                    _now(),
                    f"session-save.{status}",
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                ),
            )
    except (OSError, sqlite3.Error, HistoryError):
        return


def note_account_registration(
    *, status: str, created: int, reused: int, refreshed: int
) -> None:
    """Record safe account-registration counts separately from bundle saves."""
    if status not in {"completed", "failed"}:
        return
    counts = (created, reused, refreshed)
    if any(
        type(value) is not int or not 0 <= value <= _MAX_REGISTERED_ACCOUNTS
        for value in counts
    ):
        return
    identifier = _current.get()
    if identifier is None:
        return
    payload = {
        "eventSchemaVersion": EVENT_SCHEMA_VERSION,
        "redactionVersion": REDACTION_VERSION,
        "status": status,
        "created": created,
        "reused": reused,
        "refreshed": refreshed,
    }
    try:
        with _database() as connection:
            connection.execute(
                "INSERT INTO events (invocation_id, occurred_at, kind, data_json) "
                "VALUES (?, ?, ?, ?)",
                (
                    identifier,
                    _now(),
                    f"account-registration.{status}",
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                ),
            )
    except (OSError, sqlite3.Error, HistoryError):
        return


def _safe_identifier(value: object) -> str | None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        return None
    if not value.startswith("arn:") and _looks_like_file(value):
        return None
    return value


def _looks_like_file(value: str) -> bool:
    return (
        value == "-"
        or value.startswith((".", "~", "/", "\\"))
        or "/" in value
        or "\\" in value
        or Path(value).suffix.casefold() in {".json", ".yaml", ".yml", ".toml", ".zip"}
    )


def _safe_namespace(args: argparse.Namespace) -> dict[str, object]:
    values = vars(args)
    flags = sorted(
        key.replace("_", "-")
        for key in (
            "all",
            "all_account",
            "allow_unmanaged",
            "cascade",
            "created",
            "adopted",
            "legacy",
            "details",
            "dry_run",
            "inline",
            "probe",
            "remote",
            "replace",
            "smoke",
            "verify",
            "wide",
            "yes",
        )
        if values.get(key) is True
    )
    enums: dict[str, str] = {}
    for key in ("format", "metadata", "color"):
        value = values.get(key)
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", value):
            enums[key] = value
    input_kinds: list[dict[str, str]] = []
    for key in ("file", "trust_policy", "metadata_file", "zip", "output"):
        value = values.get(key)
        if value is None:
            continue
        input_kinds.append(
            {
                "role": key.replace("_", "-"),
                "format": _safe_format(str(value)) or "other",
            }
        )
    policy = values.get("policy")
    if isinstance(policy, str) and _looks_like_file(policy):
        input_kinds.append(
            {"role": "policy-file", "format": _safe_format(policy) or "other"}
        )
    identifiers: dict[str, str] = {}
    for key in (
        "profile",
        "aws_account_name",
        "location",
        "target",
        "account",
        "region",
        "resource_name",
        "role",
        "target_role",
        "policy",
    ):
        value = values.get(key)
        if key == "policy" and isinstance(value, str) and _looks_like_file(value):
            continue
        safe = _safe_identifier(value)
        if safe is not None:
            identifiers[key] = safe
    return {
        "flags": flags,
        "enums": enums,
        "identifiers": identifiers,
        "inputKinds": input_kinds,
        "secretPresence": {
            "mfaCode": bool(values.get("mfa_code")),
            "externalId": bool(values.get("external_id")),
        },
    }


def begin(*, json_mode: bool, interactive: bool) -> HistoryHandle:
    """Start one best-effort invocation without retaining argv."""
    started_monotonic = time.monotonic()
    try:
        _audit.reset_confirmation()
        settings = _settings()
        if settings["enabled"] is not True or _suspended.get():
            return HistoryHandle(
                id=None, started_monotonic=started_monotonic, enabled=False
            )
        identifier = uuid.uuid4().hex
        started = _now()
        with _database() as connection:
            connection.execute(
                """
                INSERT INTO invocations (
                    id, started_at, state, command, json_mode, interactive, updated_at
                ) VALUES (?, ?, 'running', 'unknown', ?, ?, ?)
                """,
                (identifier, started, int(json_mode), int(interactive), started),
            )
        _current.set(identifier)
        return HistoryHandle(
            id=identifier, started_monotonic=started_monotonic, enabled=True
        )
    except Exception:  # noqa: BLE001 - history must never prevent the command
        call_safely(warn_unavailable, json_mode=json_mode)
        _current.set(None)
        return HistoryHandle(
            id=None, started_monotonic=started_monotonic, enabled=False
        )


def warn_unavailable(*, json_mode: bool) -> None:
    """Warn when history is unavailable without corrupting JSON output."""
    if json_mode:
        return
    try:
        sys.stderr.write(
            "Warning: local command history is unavailable; continuing without "
            "recording.\n"
        )
    except Exception:  # noqa: BLE001 - even warning output is best-effort
        return


def call_safely(
    operation: Callable[..., object], /, *args: object, **kwargs: object
) -> bool:
    """Run one diagnostic history side effect without affecting its caller."""
    try:
        operation(*args, **kwargs)
    except Exception:  # noqa: BLE001 - history is optional telemetry
        return False
    return True


def enrich(handle: HistoryHandle, args: argparse.Namespace) -> None:
    """Attach only validated, allowlisted parser metadata."""
    if not handle.enabled or handle.id is None:
        return
    command, alias = _canonical_command(args)
    resource_kind = next(
        (
            kind
            for kind in ("policy", "role", "user", "group", "boundary", "target")
            if kind in command.split(".")
        ),
        None,
    )
    safe = _safe_namespace(args)
    identifiers = safe["identifiers"]
    if not isinstance(identifiers, dict):
        return
    try:
        with _database() as connection:
            connection.execute(
                """
                UPDATE invocations SET
                    command = ?, alias_used = ?, dry_run = ?, profile = ?,
                    location = ?, target = ?, account_id = ?, resource_kind = ?,
                    safe_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    command,
                    alias,
                    int(bool(getattr(args, "dry_run", False))),
                    identifiers.get("profile"),
                    identifiers.get("aws_account_name") or identifiers.get("location"),
                    identifiers.get("target"),
                    identifiers.get("account"),
                    resource_kind,
                    json.dumps(safe, sort_keys=True, separators=(",", ":")),
                    _now(),
                    handle.id,
                ),
            )
    except (OSError, sqlite3.Error, HistoryError):
        return


def note_confirmation(
    mechanism: _audit.ConfirmationMechanism,
    outcome: _audit.ConfirmationOutcome,
) -> None:
    """Record semantic confirmation state without prompt or entered text."""
    _audit.note_confirmation(mechanism, outcome)
    identifier = _current.get()
    if identifier is None:
        return
    value = f"{mechanism}:{outcome}"
    try:
        with _database() as connection:
            connection.execute(
                "UPDATE invocations SET confirmation = ?, updated_at = ? WHERE id = ?",
                (value, _now(), identifier),
            )
    except (OSError, sqlite3.Error, HistoryError):
        return


def note_mfa_code(*, source: str) -> None:
    """Record only MFA presence and its allowlisted delivery mechanism."""
    if source not in {"argument", "stdin", "prompt"}:
        return
    identifier = _current.get()
    if identifier is None:
        return
    try:
        with _database() as connection:
            row = connection.execute(
                "SELECT safe_json FROM invocations WHERE id = ?", (identifier,)
            ).fetchone()
            if row is None:
                return
            with contextlib.suppress(json.JSONDecodeError):
                safe = json.loads(row[0])
                if isinstance(safe, dict):
                    safe["mfaCodeProvided"] = True
                    safe["mfaCodeSource"] = source
                    connection.execute(
                        "UPDATE invocations SET safe_json = ?, updated_at = ? "
                        "WHERE id = ?",
                        (
                            json.dumps(safe, sort_keys=True, separators=(",", ":")),
                            _now(),
                            identifier,
                        ),
                    )
    except (OSError, sqlite3.Error, HistoryError):
        return


def note_region(*, region: str, partition: str, source: str) -> None:
    """Attach the resolved, secret-free region provenance to this invocation."""
    identifier = _current.get()
    if identifier is None:
        return
    try:
        with _database() as connection:
            row = connection.execute(
                "SELECT safe_json FROM invocations WHERE id = ?", (identifier,)
            ).fetchone()
            if row is None:
                return
            with contextlib.suppress(json.JSONDecodeError):
                safe = json.loads(row[0])
                if isinstance(safe, dict):
                    safe["resolvedRegion"] = region
                    safe["regionPartition"] = partition
                    safe["regionSource"] = source
                    connection.execute(
                        "UPDATE invocations SET safe_json = ?, updated_at = ? "
                        "WHERE id = ?",
                        (
                            json.dumps(safe, sort_keys=True, separators=(",", ":")),
                            _now(),
                            identifier,
                        ),
                    )
    except (OSError, sqlite3.Error, HistoryError):
        return


def _outcome(exit_code: int) -> str:
    return {
        0: "success",
        2: "usage-error",
        3: "policy-refusal",
        4: "cancelled",
        130: "interrupted",
    }.get(exit_code, "operational-error")


def _result_metadata(result: object) -> tuple[dict[str, object], dict[str, int]]:
    data = getattr(result, "data", None)
    raw_code = str(getattr(result, "code", "UNKNOWN"))
    code = raw_code if _RESULT_CODE.fullmatch(raw_code) else "UNKNOWN"
    selected: dict[str, object] = {}
    metrics: dict[str, int] = {}
    if isinstance(data, dict):
        for key in (
            "accountId",
            "partition",
            "arn",
            "name",
            "role",
            "policy",
            "action",
        ):
            value = data.get(key)
            safe_value = _safe_identifier(value)
            if safe_value is not None:
                selected[key] = safe_value
        for key in ("count", "matched", "changed", "failed"):
            value = data.get(key)
            if type(value) is int and value >= 0:
                metrics[key] = value
        journal = data.get("journalId")
        if isinstance(journal, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", journal):
            selected["journalId"] = journal
        classification = data.get("classification")
        if isinstance(classification, str) and re.fullmatch(
            r"[a-z-]{1,32}", classification
        ):
            selected["classification"] = classification
    selected["resultCode"] = code
    return selected, metrics


def finish(handle: HistoryHandle, result: object) -> None:
    """Atomically finalize one invocation using only positive-allowlist metadata."""
    if not handle.enabled or handle.id is None:
        return
    ended = _now()
    exit_code = int(getattr(result, "exit_code", 1))
    selected, metrics = _result_metadata(result)
    result_code = str(selected["resultCode"])
    safe: dict[str, object] = {"result": selected, "metrics": metrics}
    resource_arn = selected.get("arn") or selected.get("role")
    resource_name = selected.get("name") or selected.get("policy")
    unresolved = (
        selected.get("classification") == "recovery-required"
        or "RECOVERY_REQUIRED" in result_code
    )
    state = "interrupted" if exit_code == _INTERRUPTED_EXIT_CODE else "completed"
    try:
        with _database() as connection:
            row = connection.execute(
                "SELECT safe_json, confirmation FROM invocations WHERE id = ?",
                (handle.id,),
            ).fetchone()
            if row is not None:
                with contextlib.suppress(json.JSONDecodeError):
                    parsed = json.loads(row[0])
                    if isinstance(parsed, dict):
                        safe = {**parsed, **safe}
            encoded = json.dumps(safe, sort_keys=True, separators=(",", ":"))
            confirmation = row["confirmation"] if row is not None else "not-requested"
            if confirmation == "not-requested":
                confirmation = _audit.confirmation()
            flags = safe.get("flags")
            if (
                confirmation == "not-requested"
                and isinstance(flags, list)
                and "yes" in flags
            ):
                confirmation = "yes-flag:bypassed"
            event_bytes = int(
                connection.execute(
                    "SELECT COALESCE(SUM(LENGTH(data_json)), 0) FROM events "
                    "WHERE invocation_id = ?",
                    (handle.id,),
                ).fetchone()[0]
            )
            connection.execute(
                """
                UPDATE invocations SET
                    ended_at = ?, state = ?, outcome = ?, result_code = ?,
                    exit_code = ?, duration_ms = ?, resource_name = ?,
                    resource_arn = ?, safe_json = ?, recovery_unresolved = ?,
                    account_id = COALESCE(?, account_id),
                    partition_name = COALESCE(?, partition_name), confirmation = ?,
                    size_bytes = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    ended,
                    state,
                    _outcome(exit_code),
                    result_code,
                    exit_code,
                    max(0, round((time.monotonic() - handle.started_monotonic) * 1000)),
                    resource_name,
                    resource_arn,
                    encoded,
                    int(unresolved),
                    selected.get("accountId"),
                    selected.get("partition"),
                    confirmation,
                    len(encoded.encode("utf-8")) + event_bytes + 512,
                    ended,
                    handle.id,
                ),
            )
        _maintain()
    except (OSError, sqlite3.Error, HistoryError):
        return
    finally:
        _current.set(None)
        _audit.reset_confirmation()


def fail(handle: HistoryHandle, error: BaseException) -> None:
    """Finalize an interrupted or crashed invocation without exception text."""
    if not handle.enabled or handle.id is None:
        return
    interrupted = isinstance(error, KeyboardInterrupt)
    ended = _now()
    try:
        with _database() as connection:
            connection.execute(
                """
                UPDATE invocations SET ended_at = ?, state = ?, outcome = ?,
                    exit_code = ?, duration_ms = ?, safe_json = ?, size_bytes = ?,
                    confirmation = ?, updated_at = ? WHERE id = ?
                """,
                (
                    ended,
                    "interrupted" if interrupted else "crashed",
                    "interrupted" if interrupted else "crashed",
                    130 if interrupted else 1,
                    max(0, round((time.monotonic() - handle.started_monotonic) * 1000)),
                    "{}",
                    512,
                    _audit.confirmation(),
                    ended,
                    handle.id,
                ),
            )
    except (OSError, sqlite3.Error, HistoryError):
        return
    finally:
        _current.set(None)
        _audit.reset_confirmation()


def _maintain() -> None:
    settings = _settings()
    with _database() as connection:
        row = connection.execute(
            "SELECT occurred_at FROM events WHERE invocation_id IS NULL "
            "AND kind = 'retention' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        now = datetime.now(UTC)
        if row is not None:
            previous = datetime.fromisoformat(str(row[0]))
            if (now - previous).total_seconds() < _MAINTENANCE_INTERVAL:
                return
        abandoned_before = (
            (now - timedelta(seconds=_ABANDONED_AGE)).isoformat().replace("+00:00", "Z")
        )
        connection.execute(
            "UPDATE invocations SET state = 'abandoned', outcome = 'crashed', "
            "ended_at = updated_at WHERE state = 'running' AND started_at < ?",
            (abandoned_before,),
        )
        cutoff = (
            (now - timedelta(seconds=int(settings["max_age"])))
            .isoformat()
            .replace("+00:00", "Z")
        )
        connection.execute(
            "DELETE FROM invocations WHERE recovery_unresolved = 0 "
            "AND state != 'running' AND started_at < ?",
            (cutoff,),
        )
        while True:
            count, total = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM invocations "
                "WHERE state != 'running'"
            ).fetchone()
            if count <= int(settings["max_entries"]) and total <= int(
                settings["max_bytes"]
            ):
                break
            deleted = connection.execute(
                "DELETE FROM invocations WHERE id = (SELECT id FROM invocations "
                "WHERE recovery_unresolved = 0 AND state != 'running' "
                "ORDER BY started_at, id LIMIT 1)"
            ).rowcount
            if deleted == 0:
                break
        connection.execute(
            "INSERT INTO events (invocation_id, occurred_at, kind, data_json) "
            "VALUES (NULL, ?, 'retention', '{}')",
            (_now(),),
        )


def _event_data(row: sqlite3.Row) -> dict[str, object]:
    try:
        data = json.loads(row["data_json"])
    except json.JSONDecodeError:
        data = {"corrupt": True}
    return {
        "kind": row["kind"],
        "occurredAt": row["occurred_at"],
        "data": data,
    }


def _events_for(
    connection: sqlite3.Connection, identifiers: list[str]
) -> dict[str, list[dict[str, object]]]:
    if not identifiers:
        return {}
    placeholders = ",".join("?" for _identifier in identifiers)
    query = (
        "SELECT invocation_id, occurred_at, kind, data_json FROM events "  # noqa: S608
        f"WHERE invocation_id IN ({placeholders}) ORDER BY occurred_at, id"
    )
    rows = connection.execute(query, identifiers).fetchall()
    result: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        result.setdefault(str(row["invocation_id"]), []).append(_event_data(row))
    return result


def _row_data(
    row: sqlite3.Row, events: list[dict[str, object]] | None = None
) -> dict[str, object]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "redactionVersion": REDACTION_VERSION,
        "id": row["id"],
        "startedAt": row["started_at"],
        "endedAt": row["ended_at"],
        "state": row["state"],
        "command": row["command"],
        "aliasUsed": row["alias_used"],
        "json": bool(row["json_mode"]),
        "interactive": bool(row["interactive"]),
        "dryRun": bool(row["dry_run"]),
        "profile": row["profile"],
        "location": row["location"],
        "target": row["target"],
        "accountId": row["account_id"],
        "partition": row["partition_name"],
        "resourceKind": row["resource_kind"],
        "resourceName": row["resource_name"],
        "resourceArn": row["resource_arn"],
        "confirmation": row["confirmation"],
        "outcome": row["outcome"],
        "resultCode": row["result_code"],
        "exitCode": row["exit_code"],
        "durationMs": row["duration_ms"],
        "safe": json.loads(row["safe_json"]),
        "events": events or [],
        "recoveryUnresolved": bool(row["recovery_unresolved"]),
    }


def list_records(  # noqa: C901, PLR0913
    *,
    patterns: tuple[str, ...] = (),
    since: datetime | None = None,
    until: datetime | None = None,
    command: str | None = None,
    outcome: str | None = None,
    account: str | None = None,
    resource: str | None = None,
    failure: str | None = None,
    phase: str | None = None,
    limit: int = 50,
    include_running: bool = False,
) -> list[dict[str, object]]:
    """Return newest safe history records matching structured filters."""
    clauses = ["1 = 1"]
    params: list[object] = []
    if not include_running:
        clauses.append("state != 'running'")
    for clause, value in (
        (
            "started_at >= ?",
            since.isoformat().replace("+00:00", "Z") if since else None,
        ),
        (
            "started_at <= ?",
            until.isoformat().replace("+00:00", "Z") if until else None,
        ),
        ("command LIKE ?", f"{command}%" if command else None),
        ("outcome = ?", outcome),
        ("account_id = ?", account),
    ):
        if value is not None:
            clauses.append(clause)
            params.append(value)
    if resource:
        clauses.append("(resource_name LIKE ? OR resource_arn LIKE ?)")
        params.extend((f"%{resource}%", f"%{resource}%"))
    selected_limit = max(1, min(limit, 10_000))
    params.append(10_000 if failure or phase else selected_limit)
    try:
        with _database() as connection:
            rows = connection.execute(
                "SELECT * FROM invocations WHERE "  # noqa: S608
                + " AND ".join(clauses)
                + " ORDER BY started_at DESC, id DESC LIMIT ?",
                params,
            ).fetchall()
            events = _events_for(connection, [str(row["id"]) for row in rows])
    except (OSError, sqlite3.Error, HistoryError) as error:
        raise OperationalError(_read_error_message(error)) from error
    values = [_row_data(row, events.get(str(row["id"]), [])) for row in rows]
    if failure or phase:
        filtered: list[dict[str, object]] = []
        for item in values:
            item_events = item.get("events")
            if not isinstance(item_events, list):
                continue
            parse_events = [
                event
                for event in item_events
                if isinstance(event, dict)
                and str(event.get("kind", "")).startswith("parse.")
            ]
            if failure and not any(
                event.get("kind") == f"parse.{failure}" for event in parse_events
            ):
                continue
            if phase and not any(
                isinstance(event.get("data"), dict)
                and event["data"].get("phase") == phase
                for event in parse_events
            ):
                continue
            filtered.append(item)
        values = filtered[:selected_limit]
    if not patterns:
        return values
    folded = tuple(pattern.casefold() for pattern in patterns)
    return [
        item
        for item in values
        if any(
            fnmatch.fnmatchcase(
                " ".join(
                    str(item.get(key) or "")
                    for key in (
                        "command",
                        "resultCode",
                        "accountId",
                        "resourceName",
                        "resourceArn",
                        "profile",
                        "target",
                        "events",
                    )
                ).casefold(),
                pattern
                if any(character in pattern for character in "*?[")
                else f"*{pattern}*",
            )
            for pattern in folded
        )
    ]


def get_record(identifier: str) -> dict[str, object]:
    """Resolve one full or unique-prefix invocation identifier."""
    if not re.fullmatch(r"[a-f0-9]{4,32}", identifier):
        raise OperationalError(_invalid_id_message())
    with _database() as connection:
        rows = connection.execute(
            "SELECT * FROM invocations WHERE id LIKE ? ORDER BY id", (f"{identifier}%",)
        ).fetchall()
    if not rows:
        raise OperationalError(_missing_id_message(identifier))
    if len(rows) > 1:
        raise OperationalError(_ambiguous_id_message(identifier))
    with _database() as connection:
        events = _events_for(connection, [str(rows[0]["id"])])
    return _row_data(rows[0], events.get(str(rows[0]["id"]), []))


def command_template(record: dict[str, object]) -> str:
    """Reconstruct a safe teaching template without inventing stored values."""
    command = str(record.get("command") or "unknown").replace(".", " ")
    parts = ["hacksaws", command]
    safe = record.get("safe")
    safe_values = safe if isinstance(safe, dict) else {}
    identifiers = safe_values.get("identifiers")
    if isinstance(identifiers, dict):
        parts.extend(_template_identifiers(identifiers))
    input_kinds = safe_values.get("inputKinds")
    if isinstance(input_kinds, list):
        parts.extend(_template_inputs(input_kinds))
    secret_presence = safe_values.get("secretPresence")
    if isinstance(secret_presence, dict):
        if secret_presence.get("externalId") is True:
            parts.extend(("--external-id", "<redacted>"))
        if secret_presence.get("mfaCode") is True:
            parts.append("<mfa-code>")
    return " ".join(parts)


def parse_failure_event(record: dict[str, object]) -> dict[str, object] | None:
    """Return the first safe parse-failure event attached to one invocation."""
    events = record.get("events")
    if not isinstance(events, list):
        return None
    return next(
        (
            event
            for event in events
            if isinstance(event, dict)
            and str(event.get("kind", "")).startswith("parse.")
        ),
        None,
    )


def session_save_event(record: dict[str, object]) -> dict[str, object] | None:
    """Return the safe post-credential configuration-save event, when present."""
    events = record.get("events")
    if not isinstance(events, list):
        return None
    return next(
        (
            event
            for event in reversed(events)
            if isinstance(event, dict)
            and str(event.get("kind", "")).startswith("session-save.")
        ),
        None,
    )


def account_registration_event(
    record: dict[str, object],
) -> dict[str, object] | None:
    """Return the safe automatic account-registration outcome, when present."""
    events = record.get("events")
    if not isinstance(events, list):
        return None
    return next(
        (
            event
            for event in reversed(events)
            if isinstance(event, dict)
            and str(event.get("kind", "")).startswith("account-registration.")
        ),
        None,
    )


def parse_template(event: dict[str, object]) -> str:
    """Render only structural placeholders from one redacted parse event."""
    data = event.get("data")
    payload = data if isinstance(data, dict) else {}
    command = str(payload.get("command") or "unknown").replace(".", " ")
    parts = ["hacksaws", command]
    structure = payload.get("structure")
    safe_structure = structure if isinstance(structure, dict) else {}
    positionals = safe_structure.get("positionals")
    if isinstance(positionals, list):
        parts.extend(
            f"<{item['role']}>"
            for item in positionals
            if isinstance(item, dict) and isinstance(item.get("role"), str)
        )
    options = safe_structure.get("options")
    if isinstance(options, list):
        for item in options:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            parts.append(f"--{item['name']}")
            if (
                item.get("valueClass") != "value" or item.get("valueState") != "none"
            ) and item.get("valueState") != "none":
                parts.append(f"<{item.get('valueClass') or 'value'}>")
    return " ".join(parts)


def _template_identifiers(identifiers: dict[object, object]) -> list[str]:
    parts: list[str] = []
    for key in (
        "profile",
        "aws_account_name",
        "location",
        "target",
        "account",
        "region",
        "resource_name",
        "role",
        "target_role",
        "policy",
    ):
        value = identifiers.get(key)
        if isinstance(value, str):
            parts.extend((f"--{key.replace('_', '-')}", value))
    return parts


def _template_inputs(input_kinds: list[object]) -> list[str]:
    parts: list[str] = []
    for value in input_kinds:
        if not isinstance(value, dict):
            continue
        role = value.get("role")
        if isinstance(role, str) and _COMMAND_SEGMENT.fullmatch(role):
            parts.extend((f"--{role}", f"<{role}>"))
    return parts


def status() -> dict[str, object]:
    """Return database health and retention metadata."""
    settings = _settings()
    try:
        with _database() as connection:
            integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            current = _current.get()
            query = (
                "SELECT COUNT(*), MIN(started_at), MAX(started_at), "
                "SUM(state = 'running'), COALESCE(SUM(size_bytes), 0) "
                "FROM invocations"
            )
            parameters: tuple[str, ...] = ()
            if current is not None:
                query += " WHERE id != ?"
                parameters = (current,)
            row = connection.execute(query, parameters).fetchone()
            event_query = (
                "SELECT COUNT(*), SUM(kind LIKE 'parse.%'), "
                "SUM(kind LIKE 'session-save.%'), "
                "SUM(kind LIKE 'account-registration.%') FROM events "
                "WHERE invocation_id IS NOT NULL"
            )
            event_row = connection.execute(event_query).fetchone()
    except (OSError, sqlite3.Error, HistoryError) as error:
        raise OperationalError(_inspect_error_message(error)) from error
    return {
        "database": str(database_path()),
        "integrity": integrity,
        "count": int(row[0]),
        "oldest": row[1],
        "newest": row[2],
        "running": int(row[3] or 0),
        "logicalBytes": int(row[4]),
        "events": int(event_row[0] or 0),
        "parseFailures": int(event_row[1] or 0),
        "sessionSaves": int(event_row[2] or 0),
        "accountRegistrations": int(event_row[3] or 0),
        "retention": settings,
    }


def clear(
    *, before: datetime | None, all_records: bool, apply: bool
) -> dict[str, object]:
    """Plan or apply deletion of completed, resolved history records."""
    clauses = ["state != 'running'", "recovery_unresolved = 0"]
    params: list[object] = []
    if not all_records:
        if before is None:
            raise OperationalError(_clear_selector_message())
        clauses.append("started_at < ?")
        params.append(before.isoformat().replace("+00:00", "Z"))
    where = " AND ".join(clauses)
    with _database() as connection:
        count, size = connection.execute(
            f"SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) "  # noqa: S608
            f"FROM invocations WHERE {where}",
            params,
        ).fetchone()
        if apply:
            connection.execute(f"DELETE FROM invocations WHERE {where}", params)  # noqa: S608
    return {"count": int(count), "logicalBytes": int(size), "applied": apply}


def export_records(records: list[dict[str, object]], *, format_name: str) -> str:
    """Serialize safe records deterministically for agents."""
    ordered = sorted(
        records, key=lambda item: (str(item["startedAt"]), str(item["id"]))
    )
    if format_name == "json":
        return json.dumps(ordered, indent=2, sort_keys=True) + "\n"
    return "".join(json.dumps(item, sort_keys=True) + "\n" for item in ordered)


def check() -> dict[str, object]:
    """Validate schema and every stored record without exposing payloads."""
    report = status()
    with _database() as connection:
        corrupt = 0
        for row in connection.execute("SELECT safe_json FROM invocations"):
            try:
                value = json.loads(row[0])
                if not isinstance(value, dict):
                    corrupt += 1
            except json.JSONDecodeError:
                corrupt += 1
        corrupt_events = 0
        for row in connection.execute("SELECT kind, data_json FROM events"):
            if row["kind"] == "retention":
                continue
            try:
                value = json.loads(row["data_json"])
            except json.JSONDecodeError:
                corrupt_events += 1
                continue
            kind = str(row["kind"])
            versioned = (
                isinstance(value, dict)
                and value.get("eventSchemaVersion") == EVENT_SCHEMA_VERSION
                and value.get("redactionVersion") == REDACTION_VERSION
            )
            parse_valid = kind.startswith("parse.") and versioned
            save_status = kind.removeprefix("session-save.")
            save_valid = (
                kind.startswith("session-save.")
                and versioned
                and save_status in {"saved", "noop", "failed", "cancelled"}
                and value.get("status") == save_status
                and type(value.get("requested")) is bool
                and type(value.get("credentialsActive")) is bool
                and all(
                    item is None or _safe_identifier(item) == item
                    for item in (value.get("target"), value.get("boundary"))
                )
            )
            registration_status = kind.removeprefix("account-registration.")
            registration_valid = (
                kind.startswith("account-registration.")
                and versioned
                and registration_status in {"completed", "failed"}
                and value.get("status") == registration_status
                and all(
                    type(value.get(field)) is int
                    and 0 <= value[field] <= _MAX_REGISTERED_ACCOUNTS
                    for field in ("created", "reused", "refreshed")
                )
            )
            if not (parse_valid or save_valid or registration_valid):
                corrupt_events += 1
    return {
        **report,
        "corruptRecords": corrupt,
        "corruptEvents": corrupt_events,
        "ok": report["integrity"] == "ok" and corrupt == 0 and corrupt_events == 0,
    }


def parse_time(value: str, *, now: datetime | None = None) -> datetime:
    """Parse an ISO timestamp or a duration meaning that long ago."""
    selected_now = now or datetime.now(UTC)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        match = _LONG_AGO.fullmatch(value.strip())
        if match is not None:
            multiplier = (
                7 * 24 * 60 * 60
                if match.group(2).casefold().startswith("w")
                else 24 * 60 * 60
            )
            seconds = parse_count(match.group(1), multiplier)
        else:
            seconds = parse_duration(value)
        return selected_now - timedelta(seconds=seconds)
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def current_id() -> str | None:
    """Return the active invocation ID for semantic hooks."""
    return _current.get()


@contextlib.contextmanager
def disabled() -> Iterator[None]:
    """Temporarily suppress recursive recording in isolated internal operations."""
    current_token = _current.set(None)
    suspended_token = _suspended.set(True)
    try:
        yield
    finally:
        _suspended.reset(suspended_token)
        _current.reset(current_token)


def _read_error_message(error: BaseException) -> str:
    return f"Unable to read command history: {error}"


def _inspect_error_message(error: BaseException) -> str:
    return f"Unable to inspect command history: {error}"


def _invalid_id_message() -> str:
    return "History ID must be 4-32 lowercase hexadecimal characters."


def _missing_id_message(identifier: str) -> str:
    return f"History invocation {identifier!r} was not found."


def _ambiguous_id_message(identifier: str) -> str:
    return f"History ID prefix {identifier!r} is ambiguous."


def _clear_selector_message() -> str:
    return "History clear requires --before or --all."
