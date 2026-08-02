"""Credential-free, best-effort command history for Hacksaws invocations."""

from __future__ import annotations

import contextlib
import fnmatch
import json
import re
import sqlite3
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
from typing import TypedDict

from hacksaws import _audit
from hacksaws import _state
from hacksaws._configs import OperationalError
from hacksaws._duration import parse_count
from hacksaws._duration import parse_duration

if TYPE_CHECKING:
    import argparse
    from collections.abc import Iterator

SCHEMA_VERSION = 1
REDACTION_VERSION = 1
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
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = NORMAL")
    with _initialization_lock:
        if path not in _initialized_databases:
            try:
                connection.execute("PRAGMA journal_mode = WAL")
                _migrate(connection)
            except (OSError, sqlite3.Error, HistoryError):
                connection.close()
                raise
            _initialized_databases.add(path)
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
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


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
        "history_action",
    ):
        value = getattr(args, field, None)
        segment = str(value) if value is not None else ""
        if _COMMAND_SEGMENT.fullmatch(segment) and segment not in parts:
            parts.append(segment)
    return ".".join(parts), alias


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
        suffix = Path(str(value)).suffix.casefold().removeprefix(".") or "unknown"
        input_kinds.append({"role": key.replace("_", "-"), "format": suffix})
    policy = values.get("policy")
    if isinstance(policy, str) and _looks_like_file(policy):
        suffix = Path(policy).suffix.casefold().removeprefix(".") or "unknown"
        input_kinds.append({"role": "policy-file", "format": suffix})
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
    _audit.reset_confirmation()
    settings = _settings()
    if settings["enabled"] is not True or _suspended.get():
        return HistoryHandle(id=None, started_monotonic=time.monotonic(), enabled=False)
    identifier = uuid.uuid4().hex
    started = _now()
    try:
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
            id=identifier, started_monotonic=time.monotonic(), enabled=True
        )
    except (OSError, sqlite3.Error, HistoryError):
        return HistoryHandle(id=None, started_monotonic=time.monotonic(), enabled=False)


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
                    len(encoded.encode("utf-8")) + 512,
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


def _row_data(row: sqlite3.Row) -> dict[str, object]:
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
        "recoveryUnresolved": bool(row["recovery_unresolved"]),
    }


def list_records(  # noqa: PLR0913
    *,
    patterns: tuple[str, ...] = (),
    since: datetime | None = None,
    until: datetime | None = None,
    command: str | None = None,
    outcome: str | None = None,
    account: str | None = None,
    resource: str | None = None,
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
    params.append(max(1, min(limit, 10_000)))
    try:
        with _database() as connection:
            rows = connection.execute(
                "SELECT * FROM invocations WHERE "  # noqa: S608
                + " AND ".join(clauses)
                + " ORDER BY started_at DESC, id DESC LIMIT ?",
                params,
            ).fetchall()
    except (OSError, sqlite3.Error, HistoryError) as error:
        raise OperationalError(_read_error_message(error)) from error
    values = [_row_data(row) for row in rows]
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
    return _row_data(rows[0])


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
    return {
        **report,
        "corruptRecords": corrupt,
        "ok": report["integrity"] == "ok" and corrupt == 0,
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
