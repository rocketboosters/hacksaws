"""Durable, credential-free recovery journals for remote IAM mutations."""

# Recovery errors deliberately carry complete operator-facing diagnostics.
# ruff: noqa: E501, TRY003

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import re
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC
from datetime import datetime
from typing import TYPE_CHECKING
from typing import Any
from typing import cast

from hacksaws import _state
from hacksaws._configs import OperationalError

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Iterator
    from pathlib import Path

SCHEMA_VERSION = 1
_ID = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9])?$")
_FORBIDDEN_KEYS = (
    "accesskey",
    "secretkey",
    "sessiontoken",
    "securitytoken",
    "credential",
    "password",
)
_handlers: dict[tuple[str, str], RecoveryHandler] = {}


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def recovery_root() -> Path:
    """Return the IAM-only journal directory, separate from login transactions."""
    return _state.root() / "iam-recovery"


def _validated_id(journal_id: str) -> str:
    if not isinstance(journal_id, str) or not _ID.fullmatch(journal_id):
        raise OperationalError(f"Invalid IAM recovery journal ID {journal_id!r}.")
    return journal_id


def _contained_child(directory: Path, filename: str) -> Path:
    """Resolve a child path and prove it remains in the IAM recovery root."""
    boundary = recovery_root().resolve()
    resolved_directory = directory.resolve()
    if resolved_directory != boundary and not resolved_directory.is_relative_to(
        boundary
    ):
        raise OperationalError("IAM recovery storage resolves outside its state root.")
    candidate = (resolved_directory / filename).resolve()
    if candidate.parent != resolved_directory:
        raise OperationalError("IAM recovery path escapes its state directory.")
    return candidate


def _journal_path(journal_id: str) -> Path:
    identifier = _validated_id(journal_id)
    return _contained_child(recovery_root(), f"{identifier}.json")


def _lock_path(journal_id: str) -> Path:
    identifier = _validated_id(journal_id)
    return _contained_child(recovery_root() / ".locks", f"{identifier}.lock")


def _safe_payload(value: object, *, location: str = "payload") -> object:
    """Validate JSON payloads and reject fields that could contain credentials."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [
            _safe_payload(item, location=f"{location}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, tuple):
        return [
            _safe_payload(item, location=f"{location}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise OperationalError(f"{location} keys must be text.")
            normalized = re.sub(r"[^a-z]", "", key.casefold())
            if any(part in normalized for part in _FORBIDDEN_KEYS):
                raise OperationalError(
                    f"IAM recovery journals cannot store credential field {key!r}."
                )
            result[key] = _safe_payload(item, location=f"{location}.{key}")
        return result
    raise OperationalError(
        f"{location} must contain only JSON values, not {type(value).__name__}."
    )


def _write(journal: Mapping[str, object], *, journal_id: str) -> None:
    identifier = _validated_id(journal_id)
    if journal.get("id") != identifier:
        raise OperationalError(
            "IAM recovery journal identity does not match its locked filename.",
            details={"requestedId": identifier, "embeddedId": journal.get("id")},
        )
    path = _journal_path(identifier)
    _state.atomic_write(
        path,
        (json.dumps(journal, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def _lock_owner_alive(path: Path) -> bool:
    try:
        owner = int(path.read_text(encoding="ascii").splitlines()[0])
    except (OSError, ValueError, IndexError):
        return False
    if owner == os.getpid():
        return True
    if os.name == "nt":
        process = ctypes.windll.kernel32.OpenProcess(0x1000, 0, owner)  # type: ignore[attr-defined]
        if not process:
            return False
        ctypes.windll.kernel32.CloseHandle(process)  # type: ignore[attr-defined]
        return True
    try:
        os.kill(owner, 0)
    except OSError:
        return False
    return True


@contextlib.contextmanager
def _locked(journal_id: str, *, timeout: float = 2.0) -> Iterator[None]:
    """Serialize journal transitions with an atomic process lock file."""
    identifier = _validated_id(journal_id)
    path = _lock_path(identifier)
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    descriptor: int | None = None
    while descriptor is None:
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(descriptor, f"{os.getpid()}\n{_now()}\n".encode("ascii"))
            os.fsync(descriptor)
        except FileExistsError:
            if not _lock_owner_alive(path):
                with contextlib.suppress(OSError):
                    path.unlink()
                continue
            if time.monotonic() >= deadline:
                raise OperationalError(
                    f"IAM recovery journal {identifier!r} is busy in another process.",
                    details={"journalId": identifier, "lock": str(path)},
                ) from None
            time.sleep(0.02)
    try:
        yield
    finally:
        os.close(descriptor)
        with contextlib.suppress(OSError):
            path.unlink()


def _validate(journal: object, *, path: Path) -> dict[str, Any]:
    required = {
        "schemaVersion",
        "id",
        "serviceType",
        "accountId",
        "operation",
        "status",
        "createdAt",
        "updatedAt",
        "steps",
    }
    if not isinstance(journal, dict) or not required.issubset(journal):
        raise OperationalError(
            f"IAM recovery journal {path} has an invalid schema.",
            details={"path": str(path), "required": sorted(required)},
            repairs=["Preserve the file for inspection; do not retry the mutation."],
        )
    if journal["schemaVersion"] != SCHEMA_VERSION:
        raise OperationalError(
            f"IAM recovery journal {path} uses unsupported schema "
            f"{journal['schemaVersion']!r}.",
            details={"path": str(path), "supportedSchemaVersion": SCHEMA_VERSION},
        )
    partition = journal.get("partition")
    if partition is not None and (
        not isinstance(partition, str)
        or re.fullmatch(r"[a-z][a-z0-9-]{0,31}", partition) is None
    ):
        raise OperationalError(
            f"IAM recovery journal {path} contains an invalid AWS partition.",
            details={"path": str(path), "partition": partition},
        )
    if journal["status"] not in {
        "active",
        "failed",
        "completed",
        "rolling_back",
        "rolled_back",
    } or not isinstance(journal["steps"], list):
        raise OperationalError(
            f"IAM recovery journal {path} contains invalid status or steps.",
            details={"path": str(path)},
        )
    for step in journal["steps"]:
        if not isinstance(step, dict) or not {
            "id",
            "handler",
            "status",
            "forward",
            "compensation",
        }.issubset(step):
            raise OperationalError(
                f"IAM recovery journal {path} contains an invalid step.",
                details={"path": str(path)},
            )
        if step["status"] not in {"pending", "completed", "rolled_back"}:
            raise OperationalError(
                f"IAM recovery journal {path} contains an invalid step status.",
                details={"path": str(path), "stepId": step.get("id")},
            )
        _safe_payload(step["forward"], location="forward")
        _safe_payload(step["compensation"], location="compensation")
        if "effect" in step:
            _safe_payload(step["effect"], location="effect")
    return journal


def _read_unlocked(journal_id: str) -> dict[str, Any]:
    identifier = _validated_id(journal_id)
    path = _journal_path(identifier)
    if not path.exists():
        raise OperationalError(
            f"IAM recovery journal {identifier!r} was not found.",
            details={"journalId": identifier, "path": str(path)},
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OperationalError(
            f"Unable to read IAM recovery journal {path}: {error}",
            details={"journalId": identifier, "path": str(path)},
            repairs=["Preserve the corrupt file and inspect it before retrying."],
        ) from error
    journal = _validate(data, path=path)
    if journal["id"] != identifier:
        raise OperationalError(
            "IAM recovery journal identity does not match its filename.",
            details={
                "requestedId": identifier,
                "embeddedId": journal["id"],
                "path": str(path),
            },
            repairs=["Preserve the journal and inspect it before recovery."],
        )
    return journal


@dataclass(frozen=True)
class RecoveryHandler:
    """Whitelisted forward and compensation executors for one service step."""

    service_type: str
    name: str
    forward: Callable[[Mapping[str, object], object], Mapping[str, object] | None]
    compensate: Callable[[Mapping[str, object], object], Mapping[str, object] | None]


def register_handler(
    service_type: str,
    name: str,
    *,
    forward: Callable[[Mapping[str, object], object], Mapping[str, object] | None],
    compensate: Callable[[Mapping[str, object], object], Mapping[str, object] | None],
) -> None:
    """Whitelist one durable step handler; arbitrary journal code is never executed."""
    if not _ID.fullmatch(service_type) or not _ID.fullmatch(name):
        raise ValueError("Recovery service and handler names must be portable IDs.")
    key = (service_type, name)
    if key in _handlers:
        raise ValueError(
            f"Recovery handler {service_type}:{name} is already registered."
        )
    _handlers[key] = RecoveryHandler(service_type, name, forward, compensate)


def clear_handlers() -> None:
    """Clear registered executors for isolated tests."""
    _handlers.clear()


@dataclass(frozen=True)
class IamJournal:
    """Adapter-facing handle for recording an IAM mutation before it occurs."""

    id: str

    def record_before_mutation(
        self,
        handler: str,
        *,
        forward: Mapping[str, object],
        compensation: Mapping[str, object],
    ) -> str:
        return record_before_mutation(
            self.id, handler, forward=forward, compensation=compensation
        )

    def mark_completed(self, step_id: str) -> None:
        mark_step_completed(self.id, step_id)

    def mark_failure(self, error: BaseException, *, step_id: str | None = None) -> None:
        mark_failure(self.id, error, step_id=step_id)

    def finish(self, *, scrub_payloads: bool = False) -> None:
        finish_journal(self.id, scrub_payloads=scrub_payloads)


def begin_journal(
    service_type: str,
    account_id: str,
    operation: str,
    *,
    journal_id: str | None = None,
    partition: str = "aws",
) -> IamJournal:
    """Begin one durable IAM operation without storing any credential material."""
    if not _ID.fullmatch(service_type):
        raise OperationalError(f"Invalid IAM recovery service type {service_type!r}.")
    if not re.fullmatch(r"\d{12}", account_id):
        raise OperationalError(f"Invalid IAM recovery account ID {account_id!r}.")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", partition):
        raise OperationalError(f"Invalid IAM recovery partition {partition!r}.")
    identifier = journal_id or uuid.uuid4().hex
    path = _journal_path(identifier)
    with _locked(identifier):
        if path.exists():
            raise OperationalError(
                f"IAM recovery journal {identifier!r} already exists."
            )
        timestamp = _now()
        journal = {
            "schemaVersion": SCHEMA_VERSION,
            "id": identifier,
            "serviceType": service_type,
            "accountId": account_id,
            "partition": partition,
            "operation": operation,
            "status": "active",
            "createdAt": timestamp,
            "updatedAt": timestamp,
            "steps": [],
        }
        _write(journal, journal_id=identifier)
    return IamJournal(identifier)


def record_before_mutation(
    journal_id: str,
    handler: str,
    *,
    forward: Mapping[str, object],
    compensation: Mapping[str, object],
) -> str:
    """Persist a pending step before its corresponding AWS mutation is attempted."""
    with _locked(journal_id):
        journal = _read_unlocked(journal_id)
        if journal["status"] not in {"active", "failed"}:
            raise OperationalError(
                f"Cannot append to IAM recovery journal in {journal['status']} state."
            )
        if (str(journal["serviceType"]), handler) not in _handlers:
            raise OperationalError(
                f"Recovery handler {journal['serviceType']}:{handler} is not registered."
            )
        step_id = uuid.uuid4().hex
        timestamp = _now()
        journal["steps"].append(
            {
                "id": step_id,
                "handler": handler,
                "status": "pending",
                "forward": _safe_payload(forward, location="forward"),
                "compensation": _safe_payload(compensation, location="compensation"),
                "createdAt": timestamp,
                "updatedAt": timestamp,
            }
        )
        journal["status"] = "active"
        journal["updatedAt"] = timestamp
        journal.pop("failure", None)
        _write(journal, journal_id=journal_id)
    return step_id


def _find_step(journal: Mapping[str, Any], step_id: str) -> dict[str, Any]:
    for step in journal["steps"]:
        if step["id"] == step_id:
            return cast("dict[str, Any]", step)
    raise OperationalError(f"IAM recovery step {step_id!r} was not found.")


def mark_step_completed(
    journal_id: str,
    step_id: str,
    *,
    effect: Mapping[str, object] | None = None,
) -> None:
    """Mark a recorded mutation complete only after AWS reports success."""
    with _locked(journal_id):
        journal = _read_unlocked(journal_id)
        step = _find_step(journal, step_id)
        if step["status"] == "rolled_back":
            raise OperationalError(f"IAM recovery step {step_id!r} is rolled back.")
        timestamp = _now()
        step["status"] = "completed"
        if effect is not None:
            step["effect"] = _safe_payload(effect, location="effect")
        step["completedAt"] = timestamp
        step["updatedAt"] = timestamp
        step.pop("failure", None)
        journal["updatedAt"] = timestamp
        _write(journal, journal_id=journal_id)


def mark_failure(
    journal_id: str, error: BaseException, *, step_id: str | None = None
) -> None:
    """Persist failure metadata while leaving the failed mutation pending to resume."""
    with _locked(journal_id):
        journal = _read_unlocked(journal_id)
        timestamp = _now()
        failure = {"type": type(error).__name__, "message": str(error), "at": timestamp}
        journal["status"] = "failed"
        journal["failure"] = failure
        journal["updatedAt"] = timestamp
        if step_id is not None:
            step = _find_step(journal, step_id)
            step["failure"] = failure
            step["updatedAt"] = timestamp
        _write(journal, journal_id=journal_id)


def mark_queue_attempt(
    journal_id: str,
    step_id: str,
    *,
    attempts: int,
    error: BaseException,
) -> None:
    """Persist a retryable queue attempt without changing the pending step state."""
    with _locked(journal_id):
        journal = _read_unlocked(journal_id)
        step = _find_step(journal, step_id)
        if step["status"] != "pending":
            raise OperationalError(
                f"IAM recovery queue step {step_id!r} is not pending."
            )
        timestamp = _now()
        failure = {"type": type(error).__name__, "message": str(error), "at": timestamp}
        step["attempts"] = attempts
        step["lastFailure"] = failure
        step["updatedAt"] = timestamp
        # Persist the scheduler's "retry at the bottom" decision so a crash does
        # not silently restore the pre-failure execution order.
        journal["steps"].remove(step)
        journal["steps"].append(step)
        journal["updatedAt"] = timestamp
        _write(journal, journal_id=journal_id)


def finish_journal(journal_id: str, *, scrub_payloads: bool = False) -> None:
    """Mark an operation complete and optionally retain only diagnostic receipts."""
    with _locked(journal_id):
        journal = _read_unlocked(journal_id)
        pending = [
            step["id"] for step in journal["steps"] if step["status"] == "pending"
        ]
        if pending:
            raise OperationalError(
                "Cannot complete an IAM journal with pending steps.",
                details={"journalId": journal_id, "pendingStepIds": pending},
            )
        timestamp = _now()
        journal["status"] = "completed"
        journal["updatedAt"] = timestamp
        journal["completedAt"] = timestamp
        journal.pop("failure", None)
        if scrub_payloads:
            for step in journal["steps"]:
                forward = step["forward"]
                step["forward"] = {
                    key: forward[key]
                    for key in (
                        "planStepId",
                        "resourceKey",
                        "action",
                        "irreversible",
                    )
                    if key in forward
                }
                step["compensation"] = {}
                step.pop("effect", None)
                step.pop("failure", None)
                step.pop("lastFailure", None)
            journal["payloadsScrubbed"] = True
        _write(journal, journal_id=journal_id)


def get_journal(journal_id: str) -> dict[str, Any]:
    """Read and validate one journal under its process lock."""
    with _locked(journal_id):
        return _read_unlocked(journal_id)


def list_journals() -> list[dict[str, object]]:
    """List durable journals, retaining corrupt-file diagnostics for the operator."""
    directory = recovery_root()
    if not directory.exists():
        return []
    result: list[dict[str, object]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            journal = get_journal(path.stem)
            summary = {
                key: journal[key]
                for key in (
                    "id",
                    "serviceType",
                    "accountId",
                    "operation",
                    "status",
                    "createdAt",
                    "updatedAt",
                )
            }
            if "partition" in journal:
                summary["partition"] = journal["partition"]
            result.append(summary)
        except OperationalError as error:
            result.append({"id": path.stem, "status": "corrupt", "error": str(error)})
    return result


def _handler(
    journal: Mapping[str, object], step: Mapping[str, object]
) -> RecoveryHandler:
    key = (str(journal["serviceType"]), str(step["handler"]))
    handler = _handlers.get(key)
    if handler is None:
        raise OperationalError(
            f"No whitelisted recovery handler is registered for {key[0]}:{key[1]}.",
            details={"serviceType": key[0], "handler": key[1]},
            repairs=["Load the matching Hacksaws adapter and retry recovery."],
        )
    return handler


def _handler_payload(
    journal: Mapping[str, object],
    step: Mapping[str, object],
    direction: str,
) -> dict[str, object]:
    raw = step[direction]
    if not isinstance(raw, dict):
        raise OperationalError("IAM recovery step payload is invalid.")
    payload = dict(raw)
    source = payload.pop("effectSourceStep", None)
    if source is None:
        return payload
    source_step = step if source == "self" else _find_step(journal, str(source))
    effect = source_step.get("effect")
    if not isinstance(effect, dict):
        raise OperationalError(
            "IAM recovery cannot prove the AWS identity created by the journal; "
            "preserve the current resource and complete recovery manually.",
            details={"journalId": journal["id"], "effectSourceStep": source},
        )
    payload["effect"] = effect
    return payload


def _assert_recovery_scope(journal: Mapping[str, object], context: object) -> None:
    """Require exact account and partition proof before any recovery mutation."""
    account_id = getattr(context, "account_id", None)
    if account_id != journal["accountId"]:
        raise OperationalError(
            "Recovery credentials do not match the journal account.",
            details={
                "journalAccountId": journal["accountId"],
                "callerAccountId": account_id,
            },
        )
    recorded_partition = journal.get("partition")
    caller_partition = getattr(context, "partition", None)
    if recorded_partition is None:
        raise OperationalError(
            "IAM recovery journal has no recorded AWS partition and cannot be "
            "continued or rolled back safely.",
            details={"journalId": journal.get("id")},
            repairs=["Preserve the journal and complete recovery manually."],
        )
    if caller_partition != recorded_partition:
        raise OperationalError(
            "Recovery credentials do not match the journal partition.",
            details={
                "journalPartition": recorded_partition,
                "callerPartition": caller_partition,
            },
        )


def continue_journal(journal_id: str, context: object) -> dict[str, Any]:
    """Resume all pending forward steps in order, persisting after every success."""
    with _locked(journal_id):
        journal = _read_unlocked(journal_id)
        _assert_recovery_scope(journal, context)
        rolled_back_steps = [
            step["id"] for step in journal["steps"] if step["status"] == "rolled_back"
        ]
        if journal["status"] in {"rolling_back", "rolled_back"} or rolled_back_steps:
            raise OperationalError(
                "Cannot continue a journal that entered rollback.",
                details={
                    "journalId": journal_id,
                    "status": journal["status"],
                    "rolledBackStepIds": rolled_back_steps,
                },
                repairs=["Resume rollback instead of forward recovery."],
            )
        pending_steps = [
            step["id"] for step in journal["steps"] if step["status"] == "pending"
        ]
        if journal["status"] == "completed":
            if pending_steps:
                raise OperationalError(
                    "Completed IAM recovery journal contains pending steps.",
                    details={
                        "journalId": journal_id,
                        "pendingStepIds": pending_steps,
                    },
                )
            return journal
        for step in journal["steps"]:
            if step["status"] != "pending":
                continue
            handler = _handler(journal, step)
            try:
                effect = handler.forward(
                    _handler_payload(journal, step, "forward"), context
                )
            except Exception as error:
                timestamp = _now()
                failure = {
                    "type": type(error).__name__,
                    "message": str(error),
                    "at": timestamp,
                }
                journal["status"] = "failed"
                journal["failure"] = failure
                journal["updatedAt"] = timestamp
                step["failure"] = failure
                step["updatedAt"] = timestamp
                _write(journal, journal_id=journal_id)
                raise OperationalError(
                    f"IAM recovery forward step {step['id']} failed: {error}",
                    data={"journalId": journal_id, "stepId": step["id"]},
                ) from error
            timestamp = _now()
            if effect is not None:
                step["effect"] = _safe_payload(effect, location="effect")
            step["status"] = "completed"
            step["completedAt"] = timestamp
            step["updatedAt"] = timestamp
            step.pop("failure", None)
            journal["updatedAt"] = timestamp
            journal["status"] = "active"
            journal.pop("failure", None)
            _write(journal, journal_id=journal_id)
        timestamp = _now()
        journal["status"] = "completed"
        journal["completedAt"] = timestamp
        journal["updatedAt"] = timestamp
        _write(journal, journal_id=journal_id)
        return journal


def rollback_journal(journal_id: str, context: object) -> dict[str, Any]:
    """Compensate every potentially applied step in reverse and persist each success."""
    with _locked(journal_id):
        journal = _read_unlocked(journal_id)
        _assert_recovery_scope(journal, context)
        journal["status"] = "rolling_back"
        journal["updatedAt"] = _now()
        _write(journal, journal_id=journal_id)
        for step in reversed(journal["steps"]):
            if step["status"] not in {"pending", "completed"}:
                continue
            handler = _handler(journal, step)
            try:
                handler.compensate(
                    _handler_payload(journal, step, "compensation"), context
                )
            except Exception as error:
                timestamp = _now()
                failure = {
                    "type": type(error).__name__,
                    "message": str(error),
                    "at": timestamp,
                }
                journal["status"] = "failed"
                journal["failure"] = failure
                journal["updatedAt"] = timestamp
                step["failure"] = failure
                step["updatedAt"] = timestamp
                _write(journal, journal_id=journal_id)
                raise OperationalError(
                    f"IAM recovery compensation step {step['id']} failed: {error}",
                    data={"journalId": journal_id, "stepId": step["id"]},
                ) from error
            timestamp = _now()
            step["status"] = "rolled_back"
            step["rolledBackAt"] = timestamp
            step["updatedAt"] = timestamp
            step.pop("failure", None)
            journal["updatedAt"] = timestamp
            _write(journal, journal_id=journal_id)
        timestamp = _now()
        journal["status"] = "rolled_back"
        journal["rolledBackAt"] = timestamp
        journal["updatedAt"] = timestamp
        journal.pop("failure", None)
        _write(journal, journal_id=journal_id)
        return journal
