"""Focused contracts for account-scoped IAM inventory and cleanup."""

# Test doubles intentionally use dynamic boto-shaped interfaces and positional records.
# ruff: noqa: ANN401, D101, D102, D105, D107, FBT003, PT018

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from botocore.exceptions import ClientError

from hacksaws import _iam_cleanup as cleanup
from hacksaws import _iam_managed_policies as managed
from hacksaws import _iam_recovery as recovery
from hacksaws import _iam_roles as roles
from hacksaws._configs import OperationalError

ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/tester"
TRUST = {"Version": "2012-10-17", "Statement": []}


def policy(
    name: str = "AgentRead",
    *,
    resource_id: str = "policy-1",
    origin: str | None = "created",
    document: dict[str, Any] | None = None,
) -> managed.ManagedPolicyRecord:
    tags = [
        managed.Tag("hacksaws:managed-by", "hacksaws"),
        managed.Tag("hacksaws:resource-kind", "managed-policy"),
        managed.Tag("hacksaws:resource-id", resource_id),
    ]
    if origin is not None:
        tags.append(managed.Tag(cleanup.ORIGIN_TAG, origin))
    return managed.ManagedPolicyRecord(
        managed.ManagedPolicyArn.parse(
            f"arn:aws:iam::{ACCOUNT}:policy/hacksaws/{name}"
        ),
        f"ANPA{name}",
        name,
        "/hacksaws/",
        "v2",
        0,
        0,
        tuple(tags),
        document or {"Version": "2012-10-17", "Statement": []},
        (
            managed.PolicyVersionRecord("v1", False, None, {"Statement": []}),
            managed.PolicyVersionRecord("v2", True, None, {"Statement": []}),
        ),
    )


def role(
    name: str = "AgentRole",
    *,
    origin: str | None = "adopted",
    attached: tuple[str, ...] = (),
    boundary: str | None = None,
    profiles: tuple[str, ...] = (),
    trust: dict[str, Any] | None = None,
) -> roles.RoleSnapshot:
    tags = {roles.MANAGED_TAG: "true", roles.OWNER_TAG: CALLER}
    if origin is not None:
        tags[cleanup.ORIGIN_TAG] = origin
    return roles.RoleSnapshot(
        name,
        f"arn:aws:iam::{ACCOUNT}:role/hacksaws/{name}",
        "/hacksaws/",
        trust or TRUST,
        tags=tags,
        attached_policies=attached,
        permissions_boundary=boundary,
        instance_profiles=profiles,
        role_id=f"AROA{name}",
    )


class RoleService:
    def __init__(self, values: tuple[roles.RoleSnapshot, ...]) -> None:
        self.values = {item.name: item for item in values}

    def list_roles(self, *, path_prefix: str) -> tuple[roles.RoleSnapshot, ...]:
        assert path_prefix == "/"
        return tuple(self.values.values())

    def get_role(self, name: str) -> roles.RoleSnapshot:
        return self.values[name]


class PolicyService:
    def __init__(
        self,
        values: tuple[managed.ManagedPolicyRecord, ...],
        dependencies: managed.PolicyDependencies | None = None,
    ) -> None:
        self.values = {item.arn.value: item for item in values}
        self.dependencies = dependencies or managed.PolicyDependencies()

    def list_policies(
        self, *, scope: managed.PolicyScope, include_tags: bool
    ) -> tuple[managed.ManagedPolicyRecord, ...]:
        assert scope is managed.PolicyScope.LOCAL and include_tags
        return tuple(self.values.values())

    def get_policy(
        self, reference: str, **_kwargs: object
    ) -> managed.ManagedPolicyRecord:
        return self.values[reference]

    def policy_dependencies(self, _reference: str) -> managed.PolicyDependencies:
        return self.dependencies


class Iam:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.failures = 0
        self.role_exists = True
        self.policy_exists = True

    def get_role(self, **_kwargs: object) -> dict[str, object]:
        if not self.role_exists:
            raise ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "absent"}},
                "GetRole",
            )
        return {"Role": {"RoleId": "AROAAgentRole"}}

    def delete_role(self, **kwargs: object) -> None:
        self.calls.append(("delete_role", dict(kwargs)))
        if self.failures:
            self.failures -= 1
            raise ClientError(
                {"Error": {"Code": "ConcurrentModification", "Message": "retry"}},
                "DeleteRole",
            )
        self.role_exists = False

    def get_policy(self, **_kwargs: object) -> dict[str, object]:
        if not self.policy_exists:
            raise ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "absent"}},
                "GetPolicy",
            )
        return {"Policy": {"PolicyId": "ANPAAgentRead"}}

    def delete_policy(self, **kwargs: object) -> None:
        self.calls.append(("delete_policy", dict(kwargs)))
        self.policy_exists = False

    def __getattr__(self, action: str) -> Any:
        def call(**kwargs: object) -> None:
            self.calls.append((action, dict(kwargs)))

        return call


def context(iam: Iam | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        account_id=ACCOUNT,
        partition="aws",
        arn=CALLER,
        iam=iam or Iam(),
        sts=SimpleNamespace(),
        access_analyzer=None,
    )


@pytest.fixture(autouse=True)
def isolated_recovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    recovery.clear_handlers()
    cleanup.ensure_recovery_handler()


def service(
    role_values: tuple[roles.RoleSnapshot, ...] = (),
    policy_values: tuple[managed.ManagedPolicyRecord, ...] = (),
    *,
    dependencies: managed.PolicyDependencies | None = None,
    iam: Iam | None = None,
) -> cleanup.CleanupService:
    return cleanup.CleanupService(
        context(iam),
        role_service=RoleService(role_values),  # type: ignore[arg-type]
        policy_service=PolicyService(  # type: ignore[arg-type]
            policy_values, dependencies
        ),
        sleeper=lambda _delay: None,
        jitter=lambda _lower, upper: upper,
    )


def test_inventory_classifies_origins_groups_smoke_and_filters() -> None:
    created = policy()
    group = policy(
        "hacksaws-Agents-assume-roles",
        resource_id="group-Agents",
        origin=None,
    )
    adopted_role = role()
    adopted_role = replace(
        adopted_role,
        tags={
            **adopted_role.tags,
            cleanup.SMOKE_TAG: "true",
            cleanup.SMOKE_RUN_TAG: "run-1",
        },
    )
    inventory = service((adopted_role,), (created, group)).inventory()
    assert [item.resource_type for item in inventory.items] == [
        cleanup.ResourceType.GROUP_GRANT,
        cleanup.ResourceType.POLICY,
        cleanup.ResourceType.ROLE,
    ]
    assert inventory.items[0].origin is cleanup.OwnershipOrigin.LEGACY
    selected = inventory.filter(
        patterns=("agent*",),
        origins=(cleanup.OwnershipOrigin.ADOPTED,),
        owned_only=True,
        smoke_only=True,
        smoke_run_id="run-1",
    )
    assert selected == (inventory.items[2],)
    assert inventory.as_dict()["count"] == 3


def test_plan_requires_explicit_scope_and_reports_dependency_opt_ins() -> None:
    value = role(
        attached=("arn:aws:iam::aws:policy/ReadOnlyAccess",),
        boundary="arn:aws:iam::123456789012:policy/Boundary",
        profiles=("AgentProfile",),
    )
    selected = service((value,))
    with pytest.raises(OperationalError, match="PATTERN"):
        selected.plan(cleanup.CleanupOptions())
    plan = selected.plan(cleanup.CleanupOptions(patterns=("agent*",), dry_run=True))
    assert plan.classification is cleanup.PlanClassification.BLOCKED
    assert {item.code for item in plan.blockers} == {
        "CASCADE_REQUIRED",
        "BOUNDARY_OPT_IN_REQUIRED",
        "INSTANCE_PROFILE_OPT_IN_REQUIRED",
    }


def test_smoke_selectors_are_explicit_scope_and_dry_run_is_read_only() -> None:
    smoke_role = replace(
        role(),
        tags={
            **role().tags,
            cleanup.SMOKE_TAG: "true",
            cleanup.SMOKE_RUN_TAG: "run-1",
        },
    )
    selected = service((smoke_role,))

    smoke_plan = selected.plan(cleanup.CleanupOptions(smoke_only=True))
    run_plan = selected.plan(cleanup.CleanupOptions(smoke_run_id="run-1"))

    assert smoke_plan.resources == run_plan.resources
    assert [item.name for item in smoke_plan.resources] == ["AgentRole"]
    assert recovery.list_journals() == []
    assert selected.context.iam.calls == []


def test_plan_orders_roles_before_policies_and_marks_identity_commits() -> None:
    policy_value = policy()
    role_value = role(attached=(policy_value.arn.value,))
    plan = service((role_value,), (policy_value,)).plan(
        cleanup.CleanupOptions(
            all_resources=True,
            cascade=True,
            origins=frozenset(
                {cleanup.OwnershipOrigin.CREATED, cleanup.OwnershipOrigin.ADOPTED}
            ),
        )
    )
    assert plan.classification is cleanup.PlanClassification.PLANNED
    role_delete = next(step for step in plan.steps if step.action == "delete_role")
    policy_delete = next(step for step in plan.steps if step.action == "delete_policy")
    assert role_delete.irreversible and policy_delete.irreversible
    first_policy_step = next(
        step for step in plan.steps if step.resource_key.startswith("policy:")
    )
    assert role_delete.id in first_policy_step.prerequisites
    assert policy_delete.params["ExpectedPolicyId"] == policy_value.policy_id
    assert plan.as_dict()["leaveNoTrace"]["localRecoveryJournalRetained"] is True  # type: ignore[index]


def test_group_grant_cleanup_removes_owned_trust_before_aggregate_policy() -> None:
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/hacksaws/AgentRole"
    principal = roles.DurablePrincipal(
        "account", f"arn:aws:iam::{ACCOUNT}:root", ACCOUNT, "aws"
    )
    role_value = role(
        trust={
            "Version": "2012-10-17",
            "Statement": [roles.trust_statement(principal, "HacksawsGroupAccount")],
        }
    )
    group = policy(
        "hacksaws-Agents-assume-roles",
        resource_id="group-Agents",
        document={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "HacksawsGroupAssumeRoles",
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": [role_arn],
                }
            ],
        },
    )
    dependencies = managed.PolicyDependencies(
        permission_groups=(managed.EntityReference("group", "Agents", "AGPA1"),)
    )
    plan = service((role_value,), (group,), dependencies=dependencies).plan(
        cleanup.CleanupOptions(
            all_resources=True,
            resource_types=frozenset({cleanup.ResourceType.GROUP_GRANT}),
        )
    )
    actions = [step.action for step in plan.steps]
    assert actions[0] == "update_assume_role_policy"
    assert actions[-1] == "delete_policy"
    assert plan.steps[0].id in plan.steps[1].prerequisites


def test_execute_retries_transient_failure_and_finishes_lnt_journal() -> None:
    iam = Iam()
    iam.failures = 1
    selected = service(iam=iam)
    item = cleanup.InventoryItem(
        cleanup.ResourceType.ROLE,
        "AgentRole",
        f"arn:aws:iam::{ACCOUNT}:role/AgentRole",
        "AROAAgentRole",
        cleanup.OwnershipOrigin.CREATED,
        True,
        "/hacksaws/",
    )
    step = cleanup.CleanupStep(
        "delete-role",
        item.key,
        "delete_role",
        {"RoleName": "AgentRole", "ExpectedRoleId": "AROAAgentRole"},
        irreversible=True,
    )
    independent = cleanup.CleanupStep(
        "detach-group",
        item.key,
        "detach_group_policy",
        {"GroupName": "Agents", "PolicyArn": "arn:policy"},
    )
    plan = cleanup.CleanupPlan(
        ACCOUNT,
        "aws",
        CALLER,
        cleanup.CleanupOptions(all_resources=True, dry_run=False),
        (item,),
        (step, independent),
    )
    result = selected.execute(plan)
    assert result.classification is cleanup.ResultClassification.CLEANED
    assert result.lnt
    assert [action for action, _params in iam.calls] == [
        "delete_role",
        "detach_group_policy",
        "delete_role",
    ]
    journal = recovery.get_journal(str(result.journal_id))
    assert journal["status"] == "completed"
    assert journal["steps"][1]["attempts"] == 1
    assert journal["steps"][1]["forward"]["planStepId"] == "delete-role"
    assert journal["partition"] == "aws"
    assert journal["payloadsScrubbed"] is True
    assert all(step["compensation"] == {} for step in journal["steps"])
    assert "credential" not in str(journal).casefold()


def test_successful_cleanup_scrubs_policy_and_trust_recovery_material() -> None:
    iam = Iam()
    selected = service(iam=iam)
    item = cleanup.InventoryItem(
        cleanup.ResourceType.ROLE,
        "AgentRole",
        f"arn:aws:iam::{ACCOUNT}:role/AgentRole",
        "AROAAgentRole",
        cleanup.OwnershipOrigin.CREATED,
        True,
        "/hacksaws/",
    )
    secret_document = {
        "Version": "2012-10-17",
        "Statement": [{"Principal": {"AWS": CALLER}, "Action": "sts:AssumeRole"}],
    }
    plan = cleanup.CleanupPlan(
        ACCOUNT,
        "aws",
        CALLER,
        cleanup.CleanupOptions(all_resources=True, dry_run=False),
        (item,),
        (
            cleanup.CleanupStep(
                "trust",
                item.key,
                "update_assume_role_policy",
                {"RoleName": "AgentRole", "PolicyDocument": "{}"},
                "update_assume_role_policy",
                {"RoleName": "AgentRole", "PolicyDocument": secret_document},
            ),
            cleanup.CleanupStep(
                "delete-role",
                item.key,
                "delete_role",
                {"RoleName": "AgentRole", "ExpectedRoleId": "AROAAgentRole"},
                prerequisites=("trust",),
                irreversible=True,
            ),
        ),
    )

    result = selected.execute(plan)
    receipt = recovery.get_journal(str(result.journal_id))

    assert result.lnt
    assert receipt["payloadsScrubbed"] is True
    assert "PolicyDocument" not in str(receipt)
    assert CALLER not in str(receipt)
    assert selected.continue_journal(str(result.journal_id)).lnt
    with pytest.raises(OperationalError, match="cannot be rolled back"):
        selected.rollback_journal(str(result.journal_id))


def test_execute_preserves_nonretryable_failure_for_recovery() -> None:
    iam = Iam()

    def denied(**_kwargs: object) -> None:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "DeleteRole"
        )

    iam.delete_role = denied  # type: ignore[method-assign]
    selected = service(iam=iam)
    item = cleanup.InventoryItem(
        cleanup.ResourceType.ROLE,
        "AgentRole",
        f"arn:aws:iam::{ACCOUNT}:role/AgentRole",
        "AROAAgentRole",
        cleanup.OwnershipOrigin.CREATED,
        True,
        "/hacksaws/",
    )
    plan = cleanup.CleanupPlan(
        ACCOUNT,
        "aws",
        CALLER,
        cleanup.CleanupOptions(all_resources=True, dry_run=False),
        (item,),
        (
            cleanup.CleanupStep(
                "delete-role",
                item.key,
                "delete_role",
                {"RoleName": "AgentRole", "ExpectedRoleId": "AROAAgentRole"},
                irreversible=True,
            ),
        ),
    )
    result = selected.execute(plan)
    assert result.classification is cleanup.ResultClassification.RECOVERY_REQUIRED
    assert result.failed == (item.key,)
    assert result.remaining == (item.key,)
    assert recovery.get_journal(str(result.journal_id))["status"] == "failed"
    iam.delete_role = Iam.delete_role.__get__(iam, Iam)  # type: ignore[method-assign]
    resumed = selected.continue_journal(str(result.journal_id))
    assert resumed.classification is cleanup.ResultClassification.CLEANED
    assert resumed.lnt
    assert recovery.get_journal(str(result.journal_id))["status"] == "completed"


def test_origin_tags_are_emitted_for_create_and_adopt() -> None:
    spec = roles.RoleSpec("AgentRole", TRUST)
    assert roles.ownership_tags(spec)[roles.ORIGIN_TAG] == "created"
    adopted = roles.plan_adopt_role(role(origin=None), CALLER)
    tags = {
        item["Key"]: item["Value"]
        for operation in adopted.operations
        for item in operation.params["Tags"]
    }
    assert tags[roles.ORIGIN_TAG] == "adopted"


def test_policy_dependency_steps_cover_every_relationship_and_drift() -> None:
    value = policy()
    dependencies = managed.PolicyDependencies(
        permission_users=(managed.EntityReference("user", "Alice", "AIDA1"),),
        permission_groups=(managed.EntityReference("group", "Agents", "AGPA1"),),
        permission_roles=(managed.EntityReference("role", "Reader", "AROA1"),),
        boundary_users=(managed.EntityReference("user", "BoundaryUser", "AIDA2"),),
        boundary_roles=(managed.EntityReference("role", "BoundaryRole", "AROA2"),),
    )
    selected = service((role("Unselected"),), (value,), dependencies=dependencies)
    blocked = selected.plan(cleanup.CleanupOptions(all_resources=True))
    assert blocked.classification is cleanup.PlanClassification.BLOCKED
    assert {item.code for item in blocked.blockers} == {
        "CASCADE_REQUIRED",
        "BOUNDARY_OPT_IN_REQUIRED",
    }
    plan = selected.plan(
        cleanup.CleanupOptions(
            all_resources=True,
            resource_types=frozenset({cleanup.ResourceType.POLICY}),
            cascade=True,
            remove_boundaries=True,
        )
    )
    assert [step.action for step in plan.steps] == [
        "detach_user_policy",
        "detach_group_policy",
        "detach_role_policy",
        "delete_user_permissions_boundary",
        "delete_role_permissions_boundary",
        "delete_policy_version",
        "delete_policy",
    ]
    selected.policy_service.values[value.arn.value] = policy(origin="adopted")  # type: ignore[attr-defined]
    with pytest.raises(OperationalError, match="changed after cleanup planning"):
        selected.execute(plan)


def test_no_matches_blocked_and_account_mismatch_execution_results() -> None:
    selected = service((role(),))
    no_matches = selected.plan(cleanup.CleanupOptions(patterns=("missing*",)))
    assert no_matches.classification is cleanup.PlanClassification.NO_MATCHES
    assert selected.execute(no_matches).as_dict() == {
        "classification": "cleaned",
        "journalId": None,
        "completed": [],
        "failed": [],
        "remaining": [],
        "leaveNoTrace": True,
    }
    blocked = cleanup.CleanupPlan(
        ACCOUNT,
        "aws",
        CALLER,
        cleanup.CleanupOptions(all_resources=True),
        (),
        (),
        (cleanup.CleanupBlocker("role:x", "BLOCKED", "reason"),),
    )
    # A resource makes blocker classification take precedence over no-matches.
    blocked = cleanup.CleanupPlan(
        blocked.account_id,
        blocked.partition,
        blocked.caller_arn,
        blocked.options,
        (
            cleanup.InventoryItem(
                cleanup.ResourceType.ROLE,
                "x",
                "arn:x",
                "id",
                cleanup.OwnershipOrigin.CREATED,
                True,
                "/",
            ),
        ),
        (),
        blocked.blockers,
    )
    assert (
        selected.execute(blocked).classification is cleanup.ResultClassification.BLOCKED
    )
    wrong = cleanup.CleanupPlan(
        "999999999999",
        "aws",
        CALLER,
        cleanup.CleanupOptions(all_resources=True),
        blocked.resources,
        (),
    )
    with pytest.raises(OperationalError, match="does not match"):
        selected.execute(wrong)


def test_low_level_identity_and_recovery_payload_guards() -> None:
    iam = Iam()
    ctx = context(iam)
    assert cleanup.ownership_origin({cleanup.ORIGIN_TAG: "other"}) is (
        cleanup.OwnershipOrigin.UNKNOWN
    )
    assert cleanup._error_code(RuntimeError("x")) == "RuntimeError"
    with pytest.raises(OperationalError, match="not allowlisted"):
        cleanup._call(ctx, "delete_user", {})
    with pytest.raises(OperationalError, match="payload is invalid"):
        cleanup._forward({"action": 1}, ctx)
    with pytest.raises(OperationalError, match="payload is invalid"):
        cleanup._compensate({"action": 1, "params": {}}, ctx)
    cleanup._compensate({"action": None, "params": {}}, ctx)
    cleanup._compensate(
        {
            "irreversible": True,
            "forwardAction": "delete_role",
            "forwardParams": {
                "RoleName": "AgentRole",
                "ExpectedRoleId": "AROAAgentRole",
            },
        },
        ctx,
    )
    cleanup._compensate(
        {
            "irreversible": True,
            "forwardAction": "delete_policy",
            "forwardParams": {
                "PolicyArn": "arn:policy",
                "ExpectedPolicyId": "ANPAAgentRead",
            },
        },
        ctx,
    )
    iam.role_exists = False
    with pytest.raises(OperationalError, match="identity commit point"):
        cleanup._compensate(
            {
                "irreversible": True,
                "forwardAction": "delete_role",
                "forwardParams": {
                    "RoleName": "AgentRole",
                    "ExpectedRoleId": "AROAAgentRole",
                },
            },
            ctx,
        )


def test_cleanup_recovery_rejects_wrong_service_account_and_partition() -> None:
    selected = service()
    recovery.register_handler(
        "other",
        "noop",
        forward=lambda _payload, _context: None,
        compensate=lambda _payload, _context: None,
    )
    other = recovery.begin_journal("other", ACCOUNT, "test")
    with pytest.raises(OperationalError, match="not an IAM cleanup"):
        selected.continue_journal(other.id)
    handle = recovery.begin_journal("iam-cleanup", "999999999999", "cleanup")
    with pytest.raises(OperationalError, match="selected account"):
        selected.continue_journal(handle.id)
    legacy = recovery.begin_journal("iam-cleanup", ACCOUNT, "cleanup")
    legacy_path = recovery._journal_path(legacy.id)
    legacy_data = json.loads(legacy_path.read_text(encoding="utf-8"))
    legacy_data.pop("partition")
    legacy_path.write_text(json.dumps(legacy_data), encoding="utf-8")
    with pytest.raises(OperationalError, match="no recorded AWS partition"):
        selected.continue_journal(legacy.id)
    wrong_partition = recovery.begin_journal(
        "iam-cleanup", ACCOUNT, "cleanup", partition="aws-cn"
    )
    with pytest.raises(OperationalError, match="selected partition"):
        selected.continue_journal(wrong_partition.id)
    with pytest.raises(OperationalError, match="selected partition"):
        selected.rollback_journal(wrong_partition.id)


def test_invalid_snapshots_inventory_warning_and_role_drift() -> None:
    class FailingRoleService(RoleService):
        def get_role(self, name: str) -> roles.RoleSnapshot:
            raise ClientError(
                {"Error": {"Code": "ServiceFailure", "Message": name}}, "GetRole"
            )

    warned = cleanup.CleanupService(
        context(),
        role_service=FailingRoleService((role(),)),  # type: ignore[arg-type]
        policy_service=PolicyService(()),  # type: ignore[arg-type]
    ).inventory()
    assert warned.items == ()
    assert "Unable to hydrate role" in warned.warnings[0]

    selected = service((role(),))
    plan = selected.plan(cleanup.CleanupOptions(all_resources=True))
    selected.role_service.values["AgentRole"] = replace(  # type: ignore[attr-defined]
        role(), description="drift"
    )
    with pytest.raises(OperationalError, match="changed after cleanup planning"):
        selected.execute(plan)

    invalid = cleanup.InventoryItem(
        cleanup.ResourceType.ROLE,
        "invalid",
        "arn:invalid",
        "id",
        cleanup.OwnershipOrigin.CREATED,
        True,
        "/",
        snapshot=object(),
    )
    with pytest.raises(OperationalError, match="Role inventory snapshot"):
        selected._role_steps(invalid, cleanup.CleanupOptions(), ())
    invalid_policy = replace(invalid, resource_type=cleanup.ResourceType.POLICY)
    with pytest.raises(OperationalError, match="Policy inventory snapshot"):
        selected._policy_steps(invalid_policy, cleanup.CleanupOptions())


def test_group_grant_retention_parsing_and_ambiguous_trust_blocker() -> None:
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/hacksaws/AgentRole"
    selected_policy = policy(
        "hacksaws-Agents-assume-roles",
        resource_id="group-Agents",
        document={
            "Statement": {
                "Sid": "HacksawsGroupAssumeRoles",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": role_arn,
            }
        },
    )
    retained_policy = policy(
        "hacksaws-Other-assume-roles",
        resource_id="group-Other",
        document={
            "Statement": [
                {"Sid": "Unrelated"},
                {"Sid": "HacksawsGroupAssumeRoles", "Resource": [role_arn, 1]},
            ]
        },
    )
    dependencies = managed.PolicyDependencies(
        permission_groups=(managed.EntityReference("group", "Agents", "AGPA1"),)
    )
    selected = service(
        (role(),), (selected_policy, retained_policy), dependencies=dependencies
    )
    plan = selected.plan(
        cleanup.CleanupOptions(
            patterns=("*Agents*",),
            resource_types=frozenset({cleanup.ResourceType.GROUP_GRANT}),
        )
    )
    assert "update_assume_role_policy" not in [step.action for step in plan.steps]
    assert (
        cleanup.CleanupService._grant_role_arns(  # type: ignore[arg-type]
            replace(plan.resources[0], snapshot=object())
        )
        == ()
    )

    ambiguous = replace(
        role(),
        trust={
            "Statement": [
                {"Sid": "HacksawsGroupAccount"},
                {"Sid": "HacksawsGroupAccount"},
            ]
        },
    )
    only_selected = service((ambiguous,), (selected_policy,), dependencies=dependencies)
    blocked = only_selected.plan(
        cleanup.CleanupOptions(
            all_resources=True,
            resource_types=frozenset({cleanup.ResourceType.GROUP_GRANT}),
        )
    )
    assert blocked.blockers[0].code == "GROUP_TRUST_BLOCKED"


def test_lnt_residue_identity_mismatch_absence_and_stalled_queue() -> None:
    iam = Iam()

    def retained(**kwargs: object) -> None:
        iam.calls.append(("delete_role", dict(kwargs)))

    iam.delete_role = retained  # type: ignore[method-assign]
    selected = service(iam=iam)
    item = cleanup.InventoryItem(
        cleanup.ResourceType.ROLE,
        "AgentRole",
        f"arn:aws:iam::{ACCOUNT}:role/AgentRole",
        "AROAAgentRole",
        cleanup.OwnershipOrigin.CREATED,
        True,
        "/hacksaws/",
    )
    plan = cleanup.CleanupPlan(
        ACCOUNT,
        "aws",
        CALLER,
        cleanup.CleanupOptions(all_resources=True, dry_run=False),
        (item,),
        (
            cleanup.CleanupStep(
                "delete-role",
                item.key,
                "delete_role",
                {"RoleName": "AgentRole", "ExpectedRoleId": "AROAAgentRole"},
                irreversible=True,
            ),
        ),
    )
    result = selected.execute(plan)
    assert result.classification is cleanup.ResultClassification.PARTIAL
    assert result.remaining == (item.key,)

    with pytest.raises(OperationalError, match="Role identity changed"):
        cleanup._call(
            context(),
            "delete_role",
            {"RoleName": "AgentRole", "ExpectedRoleId": "different"},
        )
    with pytest.raises(OperationalError, match="Policy identity changed"):
        cleanup._call(
            context(),
            "delete_policy",
            {"PolicyArn": "arn:policy", "ExpectedPolicyId": "different"},
        )

    iam.role_exists = False
    assert cleanup._forward(
        {
            "action": "delete_role",
            "params": {"RoleName": "AgentRole", "ExpectedRoleId": "AROAAgentRole"},
        },
        context(iam),
    ) == {"absenceObserved": True}

    cleanup.ensure_recovery_handler()
    stalled = recovery.begin_journal("iam-cleanup", ACCOUNT, "cleanup", partition="aws")
    stalled.record_before_mutation(
        "aws-operation",
        forward={
            "planStepId": "blocked",
            "resourceKey": item.key,
            "prerequisites": ["missing"],
            "action": "delete_role",
            "params": {"RoleName": "AgentRole"},
            "irreversible": True,
        },
        compensation={"action": None, "params": {}, "irreversible": False},
    )
    state = cleanup._continue_queue(
        stalled.id,
        context(iam),
        sleeper=lambda _delay: None,
        jitter=lambda _lower, upper: upper,
    )
    assert state["remaining"] == [item.key]
