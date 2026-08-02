"""Shared credential-free mutation plans and results for human and JSON output."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from typing import Literal

from hacksaws import _output

Scalar = str | int | bool | None
Classification = Literal[
    "planned",
    "created",
    "updated",
    "deleted",
    "no-change",
    "conflict",
    "cancelled",
    "failed",
    "applied",
]


@dataclass(frozen=True, slots=True)
class FieldChange:
    """One exact scalar before-to-after resource field change."""

    field: str
    before: Scalar
    after: Scalar


@dataclass(frozen=True, slots=True)
class ActionView:
    """One ordered remote action without request parameters or documents."""

    service: str
    action: str
    summary: str
    destructive: bool = False


@dataclass(frozen=True, slots=True)
class DependencyView:
    """One relevant resource dependency and its planned treatment."""

    relation: str
    resource: str
    treatment: str


@dataclass(frozen=True, slots=True)
class ChangeView:
    """One deterministic review contract shared by every IAM mutation family."""

    operation: str
    resource_type: str
    name: str
    classification: Classification
    arn: str | None = None
    account_id: str | None = None
    partition: str | None = None
    path: str | None = None
    ownership: str | None = None
    origin: str | None = None
    before_exists: bool = False
    after_exists: bool = False
    changes: tuple[FieldChange, ...] = ()
    actions: tuple[ActionView, ...] = ()
    dependencies: tuple[DependencyView, ...] = ()
    warnings: tuple[str, ...] = ()
    confirmation: str = "not required"


@dataclass(frozen=True, slots=True)
class MutationResultView:
    """One explicit post-mutation outcome linked to its reviewed plan."""

    classification: Classification
    resource_type: str
    name: str
    arn: str | None = None
    resource_id: str | None = None
    console_url: str | None = None
    journal_id: str | None = None
    applied_actions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    plan: ChangeView | None = None
    details: dict[str, object] = field(default_factory=dict)


def change_data(view: ChangeView) -> dict[str, object]:
    """Return a stable JSON-ready mutation plan without raw AWS parameters."""
    return {
        "classification": view.classification,
        "operation": view.operation,
        "resource": {
            "type": view.resource_type,
            "name": view.name,
            "arn": view.arn,
            "accountId": view.account_id,
            "partition": view.partition,
            "path": view.path,
        },
        "ownership": {"status": view.ownership, "origin": view.origin},
        "before": {"exists": view.before_exists},
        "after": {"exists": view.after_exists},
        "changes": [
            {"field": item.field, "before": item.before, "after": item.after}
            for item in view.changes
        ],
        "actions": [
            {
                "service": item.service,
                "action": item.action,
                "summary": item.summary,
                "destructive": item.destructive,
            }
            for item in view.actions
        ],
        "dependencies": [
            {
                "relation": item.relation,
                "resource": item.resource,
                "treatment": item.treatment,
            }
            for item in view.dependencies
        ],
        "warnings": list(view.warnings),
        "confirmation": view.confirmation,
    }


def change_text(view: ChangeView) -> str:
    """Render the complete review contract as compact, self-educating text."""
    heading = f"{view.classification.upper()} — {view.operation} {view.resource_type}"
    lines = [heading, "", "Identity", f"  Name: {_safe(view.name)}"]
    for label, value in (
        ("ARN", view.arn),
        ("Account", view.account_id),
        ("Partition", view.partition),
        ("Path", view.path),
    ):
        if value is not None:
            lines.append(f"  {label}: {_safe(value)}")
    if view.ownership is not None or view.origin is not None:
        lines.extend(
            (
                "",
                "Ownership",
                f"  Status: {_safe(view.ownership or 'unknown')}",
                f"  Origin: {_safe(view.origin or 'unknown')}",
            )
        )
    lines.extend(("", "Before → After"))
    if view.changes:
        lines.extend(
            f"  {_safe(item.field)}: {_value(item.before)} → {_value(item.after)}"
            for item in view.changes
        )
    else:
        lines.append("  No field changes.")
    lines.extend(("", "AWS actions"))
    if view.actions:
        lines.extend(
            f"  {index}. {_safe(item.service)}:{_safe(item.action)} — "
            f"{_safe(item.summary)}"
            for index, item in enumerate(view.actions, start=1)
        )
    else:
        lines.append("  None.")
    if view.dependencies:
        lines.extend(("", "Dependencies"))
        lines.extend(
            f"  {_safe(item.relation)}: {_safe(item.resource)} — "
            f"{_safe(item.treatment)}"
            for item in view.dependencies
        )
    if view.warnings:
        lines.extend(("", "Warnings"))
        lines.extend(f"  ! {_safe(item)}" for item in view.warnings)
    lines.extend(("", f"Confirmation: {_safe(view.confirmation)}"))
    return "\n".join(lines)


def result_data(view: MutationResultView) -> dict[str, object]:
    """Return a stable JSON-ready mutation outcome and its reviewed plan."""
    return {
        "classification": view.classification,
        "resource": {
            "type": view.resource_type,
            "name": view.name,
            "arn": view.arn,
            "id": view.resource_id,
            "consoleUrl": view.console_url,
        },
        "journalId": view.journal_id,
        "appliedActions": list(view.applied_actions),
        "warnings": list(view.warnings),
        "plan": change_data(view.plan) if view.plan is not None else None,
        "details": view.details,
    }


def result_text(view: MutationResultView) -> str:
    """Render an outcome that makes success, no-change, and identity explicit."""
    heading = f"{view.classification.upper()} — {view.resource_type} {_safe(view.name)}"
    lines = [heading]
    for label, value in (
        ("ARN", view.arn),
        ("Resource ID", view.resource_id),
        ("Recovery journal", view.journal_id),
        ("AWS Console", view.console_url),
    ):
        if value is not None:
            lines.append(f"{label}: {_safe(value)}")
    if view.applied_actions:
        applied = ", ".join(_safe(item) for item in view.applied_actions)
        lines.append(f"Applied: {applied}")
    elif view.classification == "no-change":
        lines.append("Applied: none; remote state already matched the requested state.")
    if view.warnings:
        lines.extend(f"Warning: {_safe(item)}" for item in view.warnings)
    return "\n".join(lines)


def _safe(value: object) -> str:
    return _output.safe_terminal_text(value)


def _value(value: Scalar) -> str:
    if value is None:
        return "∅"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return _safe(value)
