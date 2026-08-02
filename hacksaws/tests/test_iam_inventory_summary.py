"""Cross-layer contracts for fast, non-destructive IAM inventory summaries."""

# Test doubles intentionally expose small boto-shaped dynamic interfaces.
# ruff: noqa: ANN401, D101, D102, D107

from __future__ import annotations

import argparse
import io
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING
from typing import Any

from botocore.exceptions import ClientError

from hacksaws import _cli
from hacksaws import _iam_cleanup as cleanup
from hacksaws import _iam_cli
from hacksaws import _iam_managed_policies as managed
from hacksaws import _iam_roles as roles
from hacksaws import _output

if TYPE_CHECKING:
    import pytest

ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/tester"
TRUST = {"Version": "2012-10-17", "Statement": []}


def role(
    name: str,
    *,
    account: str = ACCOUNT,
    partition: str = "aws",
    managed_by_hacksaws: bool = True,
    origin: str | None = "created",
    path: str = "/hacksaws/",
) -> roles.RoleSnapshot:
    tags: dict[str, str] = {}
    if managed_by_hacksaws:
        tags[roles.MANAGED_TAG] = "true"
        tags[roles.OWNER_TAG] = CALLER
    if origin is not None:
        tags[cleanup.ORIGIN_TAG] = origin
    return roles.RoleSnapshot(
        name,
        f"arn:{partition}:iam::{account}:role{path}{name}",
        path,
        TRUST,
        tags=tags,
        role_id=f"AROA{name}",
    )


def policy(
    name: str,
    *,
    resource_id: str,
    origin: str = "created",
    owned: bool = True,
) -> managed.ManagedPolicyRecord:
    tags: list[managed.Tag] = []
    if owned:
        tags.extend(
            (
                managed.Tag("hacksaws:managed-by", "hacksaws"),
                managed.Tag("hacksaws:resource-kind", "managed-policy"),
                managed.Tag("hacksaws:resource-id", resource_id),
                managed.Tag("hacksaws:created-by", CALLER),
                managed.Tag("hacksaws:created-at", "2026-08-01T00:00:00+00:00"),
            )
        )
    tags.append(managed.Tag(cleanup.ORIGIN_TAG, origin))
    return managed.ManagedPolicyRecord(
        managed.ManagedPolicyArn.parse(
            f"arn:aws:iam::{ACCOUNT}:policy/hacksaws/{name}"
        ),
        f"ANPA{name}",
        name,
        "/hacksaws/",
        "v1",
        0,
        0,
        tuple(tags),
    )


class RoleService:
    def __init__(
        self,
        summaries: tuple[roles.RoleSnapshot, ...] = (),
        hydrated: tuple[roles.RoleSnapshot, ...] = (),
        *,
        failure: BaseException | None = None,
    ) -> None:
        self.summaries = summaries
        self.hydrated = {item.name: item for item in hydrated}
        self.failure = failure
        self.paths: list[str] = []
        self.summary_calls: list[str] = []

    def list_roles(self, *, path_prefix: str) -> tuple[roles.RoleSnapshot, ...]:
        self.paths.append(path_prefix)
        return self.summaries

    def get_role_summary(self, name: str) -> roles.RoleSnapshot:
        self.summary_calls.append(name)
        if self.failure is not None:
            raise self.failure
        return self.hydrated[name]

    def get_role(self, name: str) -> roles.RoleSnapshot:
        return self.hydrated[name]


class PolicyService:
    def __init__(
        self,
        summaries: tuple[managed.ManagedPolicyRecord, ...] = (),
        hydrated: tuple[managed.ManagedPolicyRecord, ...] = (),
    ) -> None:
        self.summaries = summaries
        self.hydrated = {item.arn.value: item for item in hydrated}
        self.list_calls: list[dict[str, object]] = []
        self.summary_calls: list[str] = []

    def list_policies(
        self, **kwargs: object
    ) -> tuple[managed.ManagedPolicyRecord, ...]:
        self.list_calls.append(dict(kwargs))
        return self.summaries

    def get_policy_summary(
        self, item: managed.ManagedPolicyRecord
    ) -> managed.ManagedPolicyRecord:
        self.summary_calls.append(item.arn.value)
        return self.hydrated[item.arn.value]

    def get_policy(
        self, reference: str, **_kwargs: object
    ) -> managed.ManagedPolicyRecord:
        return self.hydrated[reference]

    def policy_dependencies_for_arn(
        self, _reference: str
    ) -> managed.PolicyDependencies:
        return managed.PolicyDependencies()

    def policy_dependencies(self, _reference: str) -> managed.PolicyDependencies:
        return managed.PolicyDependencies()


def service(
    role_service: RoleService | None = None,
    policy_service: PolicyService | None = None,
) -> cleanup.CleanupService:
    context = SimpleNamespace(
        account_id=ACCOUNT,
        partition="aws",
        arn=CALLER,
        iam=SimpleNamespace(),
        sts=SimpleNamespace(),
        access_analyzer=None,
    )
    return cleanup.CleanupService(
        context,
        role_service=role_service or RoleService(),  # type: ignore[arg-type]
        policy_service=policy_service or PolicyService(),  # type: ignore[arg-type]
        sleeper=lambda _delay: None,
        jitter=lambda _lower, upper: upper,
    )


def test_patterns_prefilter_summaries_but_never_establish_ownership() -> None:
    summaries = (
        role("OtherOwned"),
        role("MatchOwned"),
        role("MatchSpoof", managed_by_hacksaws=False),
    )
    roles_api = RoleService(summaries, summaries)
    policies_api = PolicyService()
    summary = service(roles_api, policies_api).inventory_summary(
        cleanup.InventoryQuery(
            patterns=("match*",),
            resource_types=frozenset({cleanup.ResourceType.ROLE}),
        )
    )

    assert roles_api.paths == [roles.DEFAULT_ROLE_PATH]
    assert set(roles_api.summary_calls) == {"MatchOwned", "MatchSpoof"}
    assert policies_api.list_calls == []
    assert [item.name for item in summary.items] == ["MatchOwned"]
    assert summary.items[0].owned is True
    assert summary.inventory_complete is True


def test_group_grants_require_live_policy_tag_classification() -> None:
    group = policy(
        "hacksaws-Agents-assume-roles",
        resource_id="group-Agents",
    )
    ordinary = policy("AgentRead", resource_id="policy-AgentRead")
    policies_api = PolicyService((ordinary, group), (ordinary, group))
    roles_api = RoleService()

    summary = service(roles_api, policies_api).inventory_summary(
        cleanup.InventoryQuery(
            resource_types=frozenset({cleanup.ResourceType.GROUP_GRANT})
        )
    )

    assert roles_api.paths == []
    assert set(policies_api.summary_calls) == {
        ordinary.arn.value,
        group.arn.value,
    }
    assert [(item.resource_type, item.name) for item in summary.items] == [
        (cleanup.ResourceType.GROUP_GRANT, group.name)
    ]


def test_all_account_origin_filters_are_honored_and_results_are_stable() -> None:
    created = role("ZuluCreated", origin="created", path="/")
    adopted = role("AlphaAdopted", origin="adopted", path="/")
    unowned = role("MiddleUnowned", managed_by_hacksaws=False, origin=None, path="/")
    roles_api = RoleService((created, unowned, adopted), (created, unowned, adopted))

    summary = service(roles_api).inventory_summary(
        cleanup.InventoryQuery(
            all_account=True,
            owned_only=False,
            origins=frozenset({cleanup.OwnershipOrigin.CREATED}),
        )
    )

    assert roles_api.paths == ["/"]
    assert [item.name for item in summary.items] == ["ZuluCreated"]

    every_origin = service(
        RoleService((created, unowned, adopted), (created, unowned, adopted))
    ).inventory_summary(
        cleanup.InventoryQuery(
            all_account=True,
            owned_only=False,
            origins=frozenset(),
        )
    )
    assert [item.name for item in every_origin.items] == [
        "AlphaAdopted",
        "MiddleUnowned",
        "ZuluCreated",
    ]


def test_role_identity_must_match_verified_account_and_partition() -> None:
    foreign = role(
        "Foreign",
        account="999999999999",
        partition="aws-us-gov",
        path="/",
    )
    summary = service(RoleService((foreign,), (foreign,))).inventory_summary(
        cleanup.InventoryQuery(all_account=True, owned_only=False, origins=frozenset())
    )

    assert summary.items == ()
    assert summary.inventory_complete is False
    assert any("account" in warning.casefold() for warning in summary.warnings)


def test_ownership_hydration_failure_is_partial_not_authoritative_empty() -> None:
    candidate = role("Denied")
    denied = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}},
        "GetRole",
    )
    summary = service(
        RoleService((candidate,), (candidate,), failure=denied)
    ).inventory_summary(cleanup.InventoryQuery())
    data = summary.as_dict()

    assert summary.items == ()
    assert summary.details_complete is False
    assert summary.inventory_complete is False
    assert data["inventoryComplete"] is False
    assert data["warnings"]


def test_cleanup_planning_never_uses_summary_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned = role("CleanupOwned")
    selected = service(RoleService((owned,), (owned,)))

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError

    monkeypatch.setattr(selected, "inventory_summary", forbidden)
    plan = selected.plan(
        cleanup.CleanupOptions(patterns=("CleanupOwned",), dry_run=True)
    )
    assert [item.name for item in plan.resources] == ["CleanupOwned"]


def test_json_inventory_is_one_quiet_envelope_even_with_forced_progress(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    context = SimpleNamespace()
    monkeypatch.setattr(_iam_cli.IamCommandContext, "create", lambda _args: context)

    class SummaryService:
        def __init__(self, actual: object) -> None:
            assert actual is context

        def inventory_summary(
            self,
            _query: cleanup.InventoryQuery,
            *,
            progress: Any = None,
        ) -> cleanup.InventorySummary:
            progress(
                cleanup.InventoryProgress(
                    cleanup.InventoryPhase.DISCOVERY,
                    "Discovery complete:",
                    candidates=1,
                )
            )
            return cleanup.InventorySummary(
                account_id=ACCOUNT,
                partition="aws",
                caller_arn=CALLER,
                items=(),
                warnings=(),
                details_complete=False,
                inventory_complete=True,
            )

    monkeypatch.setattr(_iam_cli._iam_cleanup, "CleanupService", SummaryService)
    result = _cli.console_main(["--json", "iam", "list", "--roles", "--progress"])
    captured = capsys.readouterr()
    envelope = json.loads(captured.out)

    assert result.code == "IAM_INVENTORY"
    assert captured.err == ""
    assert envelope["code"] == "IAM_INVENTORY"
    assert envelope["data"]["detailsComplete"] is False
    assert envelope["data"]["inventoryComplete"] is True


def test_rich_progress_lifecycle_is_bounded_and_deduplicates_plain_updates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Terminal(io.StringIO):
        def isatty(self) -> bool:
            return True

    class ScriptedEvent:
        def __init__(self) -> None:
            self.responses = iter((False, False, True))

        def wait(self, _timeout: float | None = None) -> bool:
            return next(self.responses, True)

        def set(self) -> None:
            events.append("event-set")

    class Status:
        def __init__(self, _message: object, **_kwargs: object) -> None:
            events.append("created")

        def start(self) -> None:
            events.append("started")

        def update(self, _message: object) -> None:
            events.append("updated")

        def stop(self) -> None:
            events.append("stopped")

    monkeypatch.setattr(_output, "Status", Status)
    reporter = _output.ProgressReporter(
        _output.OutputOptions(color="always"),
        mode="always",
        stream=Terminal(),
        delay=0,
    )
    assert reporter.enabled is True
    reporter.start("rich phase")
    reporter.close()
    worker = reporter._thread
    assert worker is not None
    assert not worker.is_alive()

    direct = _output.ProgressReporter(
        _output.OutputOptions(color="always"),
        mode="always",
        stream=Terminal(),
        delay=0,
    )
    monkeypatch.setattr(direct, "_stop", ScriptedEvent())
    direct._run()
    assert events[-4:] == ["created", "started", "updated", "stopped"]

    plain_stream = io.StringIO()
    plain = _output.ProgressReporter(
        _output.OutputOptions(color="never"),
        mode="always",
        stream=plain_stream,
    )
    plain._print_plain("one milestone")
    plain._print_plain("one milestone")
    assert plain_stream.getvalue().count("one milestone") == 1
    assert _output.confirm("ignored", assume_yes=True) is True


def test_cli_query_distinguishes_default_and_explicit_all_account_origins() -> None:
    defaults = {
        "patterns": [],
        "roles": False,
        "policies": False,
        "group_grants": False,
        "created": False,
        "adopted": False,
        "smoke": False,
        "smoke_run": None,
        "all_account": True,
        "details": False,
    }
    all_resources = _iam_cli._inventory_query(argparse.Namespace(**defaults))
    created_only = _iam_cli._inventory_query(
        argparse.Namespace(**{**defaults, "created": True})
    )

    assert all_resources.origins == frozenset()
    assert created_only.origins == frozenset({cleanup.OwnershipOrigin.CREATED})
