"""Account-scoped inventory and Leave No Trace cleanup planning for IAM."""

# Cleanup deliberately exposes complete operator-facing diagnostics.
# ruff: noqa: ANN401, BLE001, C901, PLR0913, TRY003

from __future__ import annotations

import fnmatch
import random
import time
from collections import deque
from collections.abc import Callable
from collections.abc import Iterable
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field
from enum import StrEnum
from typing import Any
from typing import cast

from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from hacksaws import _iam_managed_policies as policies
from hacksaws import _iam_recovery as recovery
from hacksaws import _iam_roles as roles
from hacksaws._configs import OperationalError

ORIGIN_TAG = "hacksaws:ownership-origin"
SMOKE_TAG = "hacksaws:smoke"
SMOKE_RUN_TAG = "hacksaws:run-id"
ROLE_KIND_TAG = "hacksaws:resource-kind"
ROLE_ID_TAG = "hacksaws:resource-id"
_RECOVERY_SERVICE = "iam-cleanup"
_HANDLER = "aws-operation"
_LNT_ATTEMPTS = 3
_TRANSIENT_CODES = frozenset(
    {
        "ConcurrentModification",
        "DeleteConflict",
        "LimitExceeded",
        "RequestLimitExceeded",
        "ServiceFailure",
        "ServiceUnavailable",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
    }
)


class ResourceType(StrEnum):
    """First-class remote resource types understood by cleanup."""

    ROLE = "role"
    POLICY = "policy"
    GROUP_GRANT = "group-grant"


class OwnershipOrigin(StrEnum):
    """How a managed resource entered Hacksaws ownership."""

    CREATED = "created"
    ADOPTED = "adopted"
    LEGACY = "legacy"
    UNKNOWN = "unknown"


class PlanClassification(StrEnum):
    """Stable cleanup planning outcomes used by CLI exit classification."""

    PLANNED = "planned"
    NO_MATCHES = "no-matches"
    BLOCKED = "blocked"


class ResultClassification(StrEnum):
    """Stable cleanup execution outcomes used by CLI exit classification."""

    CLEANED = "cleaned"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    RECOVERY_REQUIRED = "recovery-required"


@dataclass(frozen=True, slots=True)
class InventoryItem:
    """One normalized IAM inventory item with its deletion-relevant state."""

    resource_type: ResourceType
    name: str
    arn: str
    resource_id: str
    origin: OwnershipOrigin
    owned: bool
    path: str
    smoke: bool = False
    smoke_run_id: str | None = None
    dependencies: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    snapshot: object | None = field(default=None, repr=False, compare=False)

    @property
    def key(self) -> str:
        """Return a stable plan key for this account-local resource."""
        return f"{self.resource_type.value}:{self.arn}"

    def as_dict(self) -> dict[str, object]:
        """Return credential-free structured output for CLI renderers."""
        return {
            "type": self.resource_type.value,
            "name": self.name,
            "arn": self.arn,
            "resourceId": self.resource_id,
            "origin": self.origin.value,
            "owned": self.owned,
            "path": self.path,
            "smoke": self.smoke,
            "smokeRunId": self.smoke_run_id,
            "dependencies": {
                key: list(value) for key, value in self.dependencies.items()
            },
        }


@dataclass(frozen=True, slots=True)
class IamInventory:
    """Account-bound remote IAM inventory."""

    account_id: str
    partition: str
    caller_arn: str
    items: tuple[InventoryItem, ...]
    warnings: tuple[str, ...] = ()

    def filter(
        self,
        *,
        patterns: Iterable[str] = (),
        resource_types: Iterable[ResourceType] = (),
        origins: Iterable[OwnershipOrigin] = (),
        owned_only: bool = False,
        smoke_only: bool = False,
        smoke_run_id: str | None = None,
    ) -> tuple[InventoryItem, ...]:
        """Filter inventory with case-insensitive fnmatch name/ARN semantics."""
        selected_patterns = tuple(patterns)
        selected_types = frozenset(resource_types)
        selected_origins = frozenset(origins)
        return tuple(
            item
            for item in self.items
            if (not owned_only or item.owned)
            and (not selected_types or item.resource_type in selected_types)
            and (not selected_origins or item.origin in selected_origins)
            and (not smoke_only or item.smoke)
            and (smoke_run_id is None or item.smoke_run_id == smoke_run_id)
            and (
                not selected_patterns
                or any(
                    fnmatch.fnmatchcase(item.name.casefold(), pattern.casefold())
                    or fnmatch.fnmatchcase(item.arn.casefold(), pattern.casefold())
                    for pattern in selected_patterns
                )
            )
        )

    def as_dict(self) -> dict[str, object]:
        """Return structured inventory output."""
        return {
            "accountId": self.account_id,
            "partition": self.partition,
            "callerArn": self.caller_arn,
            "count": len(self.items),
            "items": [item.as_dict() for item in self.items],
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class CleanupOptions:
    """Selection and dependency safeguards for one cleanup plan."""

    patterns: tuple[str, ...] = ()
    all_resources: bool = False
    resource_types: frozenset[ResourceType] = frozenset()
    origins: frozenset[OwnershipOrigin] = frozenset()
    smoke_only: bool = False
    smoke_run_id: str | None = None
    cascade: bool = False
    remove_boundaries: bool = False
    remove_from_instance_profiles: bool = False
    dry_run: bool = True


@dataclass(frozen=True, slots=True)
class CleanupBlocker:
    """One explicit reason an otherwise-selected resource cannot be cleaned."""

    resource_key: str
    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        """Return structured blocker output."""
        return {
            "resource": self.resource_key,
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class CleanupStep:
    """One durable, dependency-ordered AWS mutation."""

    id: str
    resource_key: str
    action: str
    params: Mapping[str, object]
    compensate_action: str | None = None
    compensate_params: Mapping[str, object] = field(default_factory=dict)
    prerequisites: tuple[str, ...] = ()
    irreversible: bool = False

    def as_dict(self) -> dict[str, object]:
        """Return a credential-free exact preview."""
        return {
            "id": self.id,
            "resource": self.resource_key,
            "action": self.action,
            "params": dict(self.params),
            "compensateAction": self.compensate_action,
            "prerequisites": list(self.prerequisites),
            "irreversible": self.irreversible,
        }


@dataclass(frozen=True, slots=True)
class CleanupPlan:
    """Frozen account-scoped cleanup selection and dependency DAG."""

    account_id: str
    partition: str
    caller_arn: str
    options: CleanupOptions
    resources: tuple[InventoryItem, ...]
    steps: tuple[CleanupStep, ...]
    blockers: tuple[CleanupBlocker, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def classification(self) -> PlanClassification:
        """Classify this immutable plan."""
        if not self.resources:
            return PlanClassification.NO_MATCHES
        if self.blockers:
            return PlanClassification.BLOCKED
        return PlanClassification.PLANNED

    def as_dict(self) -> dict[str, object]:
        """Return an exact operator-facing preview."""
        return {
            "classification": self.classification.value,
            "accountId": self.account_id,
            "partition": self.partition,
            "callerArn": self.caller_arn,
            "resources": [item.as_dict() for item in self.resources],
            "steps": [step.as_dict() for step in self.steps],
            "blockers": [item.as_dict() for item in self.blockers],
            "warnings": list(self.warnings),
            "leaveNoTrace": {
                "awsResourcesExpectedAbsent": [item.key for item in self.resources],
                "localRecoveryJournalRetained": True,
            },
        }


@dataclass(frozen=True, slots=True)
class CleanupResult:
    """Durable cleanup execution result."""

    classification: ResultClassification
    journal_id: str | None
    completed: tuple[str, ...]
    failed: tuple[str, ...]
    remaining: tuple[str, ...]
    lnt: bool

    def as_dict(self) -> dict[str, object]:
        """Return structured execution output."""
        return {
            "classification": self.classification.value,
            "journalId": self.journal_id,
            "completed": list(self.completed),
            "failed": list(self.failed),
            "remaining": list(self.remaining),
            "leaveNoTrace": self.lnt,
        }


def _tag_values(value: Mapping[str, str] | Iterable[policies.Tag]) -> dict[str, str]:
    if isinstance(value, Mapping):
        return {str(key).casefold(): str(item) for key, item in value.items()}
    return {tag.key.casefold(): tag.value for tag in value}


def ownership_origin(
    tags: Mapping[str, str] | Iterable[policies.Tag],
) -> OwnershipOrigin:
    """Classify explicit origin tags while preserving legacy managed resources."""
    value = _tag_values(tags).get(ORIGIN_TAG)
    if value == OwnershipOrigin.CREATED.value:
        return OwnershipOrigin.CREATED
    if value == OwnershipOrigin.ADOPTED.value:
        return OwnershipOrigin.ADOPTED
    if value is None:
        return OwnershipOrigin.LEGACY
    return OwnershipOrigin.UNKNOWN


def _error_code(error: BaseException) -> str:
    if isinstance(error, ClientError):
        return str(error.response.get("Error", {}).get("Code", type(error).__name__))
    return type(error).__name__


def _step_id(prefix: str, index: int) -> str:
    return f"{prefix}-{index:04d}"


class CleanupService:
    """Inventory, plan, and durably execute remote IAM cleanup."""

    def __init__(
        self,
        context: Any,
        *,
        role_service: roles.IamRoleService | None = None,
        policy_service: policies.IamManagedPolicyService | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        jitter: Callable[[float, float], float] = random.uniform,
    ) -> None:
        self.context = context
        self.role_service = role_service or roles.IamRoleService(context.iam)
        self.policy_service = policy_service or policies.IamManagedPolicyService(
            context.iam,
            context.sts,
            getattr(context, "access_analyzer", None),
            policies.PolicyServiceOptions(
                account_id=context.account_id,
                partition=context.partition,
            ),
        )
        self._sleep = sleeper
        self._jitter = jitter

    def inventory(self) -> IamInventory:
        """Hydrate all roles and local policies into one account inventory."""
        items: list[InventoryItem] = []
        warnings: list[str] = []
        for summary in self.role_service.list_roles(path_prefix="/"):
            try:
                role = self.role_service.get_role(summary.name)
            except (BotoCoreError, ClientError) as error:
                warnings.append(f"Unable to hydrate role {summary.name}: {error}")
                continue
            tags = _tag_values(role.tags)
            owned = tags.get(roles.MANAGED_TAG) == "true"
            items.append(
                InventoryItem(
                    ResourceType.ROLE,
                    role.name,
                    role.arn,
                    role.role_id,
                    ownership_origin(role.tags) if owned else OwnershipOrigin.UNKNOWN,
                    owned,
                    role.path,
                    tags.get(SMOKE_TAG) == "true",
                    tags.get(SMOKE_RUN_TAG),
                    {
                        "attachedPolicies": tuple(role.attached_policies),
                        "inlinePolicies": tuple(role.inline_policies),
                        "instanceProfiles": tuple(role.instance_profiles),
                        "permissionsBoundary": (
                            (role.permissions_boundary,)
                            if role.permissions_boundary
                            else ()
                        ),
                    },
                    role,
                )
            )
        for policy_summary in self.policy_service.list_policies(
            scope=policies.PolicyScope.LOCAL, include_tags=True
        ):
            policy_record = self.policy_service.get_policy(
                policy_summary.arn.value,
                include_document=True,
                include_versions=True,
                include_tags=True,
            )
            tags = _tag_values(policy_record.tags)
            resource_id = tags.get("hacksaws:resource-id", "")
            group_name = resource_id.removeprefix("group-")
            resource_type = (
                ResourceType.GROUP_GRANT
                if policy_record.owned
                and resource_id.startswith("group-")
                and group_name
                and policy_record.name == f"hacksaws-{group_name}-assume-roles"
                else ResourceType.POLICY
            )
            dependencies = self.policy_service.policy_dependencies(
                policy_record.arn.value
            )
            items.append(
                InventoryItem(
                    resource_type,
                    policy_record.name,
                    policy_record.arn.value,
                    policy_record.policy_id,
                    (
                        ownership_origin(policy_record.tags)
                        if policy_record.owned
                        else OwnershipOrigin.UNKNOWN
                    ),
                    policy_record.owned,
                    policy_record.path,
                    tags.get(SMOKE_TAG) == "true",
                    tags.get(SMOKE_RUN_TAG),
                    {
                        "permissionUsers": tuple(
                            item.name for item in dependencies.permission_users
                        ),
                        "permissionGroups": tuple(
                            item.name for item in dependencies.permission_groups
                        ),
                        "permissionRoles": tuple(
                            item.name for item in dependencies.permission_roles
                        ),
                        "boundaryUsers": tuple(
                            item.name for item in dependencies.boundary_users
                        ),
                        "boundaryRoles": tuple(
                            item.name for item in dependencies.boundary_roles
                        ),
                    },
                    (policy_record, dependencies),
                )
            )
        return IamInventory(
            self.context.account_id,
            self.context.partition,
            self.context.arn,
            tuple(
                sorted(
                    items,
                    key=lambda item: (item.resource_type, item.name.casefold()),
                )
            ),
            tuple(warnings),
        )

    def plan(self, options: CleanupOptions) -> CleanupPlan:
        """Build an exact dependency-ordered deletion plan without mutating AWS."""
        if not (
            options.all_resources
            or options.patterns
            or options.smoke_only
            or options.smoke_run_id
        ):
            raise OperationalError(
                "Cleanup requires PATTERN arguments, --all, --smoke, or --smoke-run."
            )
        inventory = self.inventory()
        selected = inventory.filter(
            patterns=() if options.all_resources else options.patterns,
            resource_types=options.resource_types,
            origins=options.origins,
            owned_only=True,
            smoke_only=options.smoke_only,
            smoke_run_id=options.smoke_run_id,
        )
        blockers: list[CleanupBlocker] = []
        warnings = list(inventory.warnings)
        steps: list[CleanupStep] = []
        selected_roles = [
            item for item in selected if item.resource_type is ResourceType.ROLE
        ]
        selected_grants = [
            item for item in selected if item.resource_type is ResourceType.GROUP_GRANT
        ]
        selected_policies = [
            item for item in selected if item.resource_type is ResourceType.POLICY
        ]
        trust_steps, trust_blockers = self._group_trust_steps(
            selected_grants, inventory, selected_roles
        )
        steps.extend(trust_steps)
        blockers.extend(trust_blockers)
        trust_tail = (trust_steps[-1].id,) if trust_steps else ()
        grant_tail: list[str] = []
        for item in selected_grants:
            grant_steps, grant_blockers = self._policy_steps(item, options, trust_tail)
            steps.extend(grant_steps)
            blockers.extend(grant_blockers)
            if grant_steps:
                grant_tail.append(grant_steps[-1].id)
        role_tail: list[str] = []
        for item in selected_roles:
            role_steps, role_blockers = self._role_steps(
                item, options, tuple(grant_tail)
            )
            steps.extend(role_steps)
            blockers.extend(role_blockers)
            if role_steps:
                role_tail.append(role_steps[-1].id)
        policy_prerequisites = (*grant_tail, *role_tail)
        for item in selected_policies:
            policy_steps, policy_blockers = self._policy_steps(
                item, options, policy_prerequisites
            )
            steps.extend(policy_steps)
            blockers.extend(policy_blockers)
        return CleanupPlan(
            inventory.account_id,
            inventory.partition,
            inventory.caller_arn,
            options,
            selected,
            tuple(steps),
            tuple(blockers),
            tuple(warnings),
        )

    @staticmethod
    def _grant_role_arns(item: InventoryItem) -> tuple[str, ...]:
        snapshot = item.snapshot
        if not isinstance(snapshot, tuple) or not isinstance(
            snapshot[0], policies.ManagedPolicyRecord
        ):
            return ()
        document = snapshot[0].document or {}
        statements = document.get("Statement", [])
        if isinstance(statements, Mapping):
            statements = [statements]
        result: list[str] = []
        for statement in statements if isinstance(statements, list) else []:
            if not isinstance(statement, Mapping) or statement.get("Sid") != (
                "HacksawsGroupAssumeRoles"
            ):
                continue
            resources = statement.get("Resource", [])
            values = resources if isinstance(resources, list) else [resources]
            result.extend(str(value) for value in values if isinstance(value, str))
        return tuple(sorted(set(result)))

    def _group_trust_steps(
        self,
        selected_grants: Iterable[InventoryItem],
        inventory: IamInventory,
        selected_roles: Iterable[InventoryItem],
    ) -> tuple[list[CleanupStep], list[CleanupBlocker]]:
        grants = tuple(selected_grants)
        selected_grant_arns = {item.arn for item in grants}
        selected_role_arns = {item.arn for item in selected_roles}
        all_grants = tuple(
            item
            for item in inventory.items
            if item.resource_type is ResourceType.GROUP_GRANT and item.owned
        )
        candidates = {
            arn
            for item in grants
            for arn in self._grant_role_arns(item)
            if arn not in selected_role_arns
        }
        result: list[CleanupStep] = []
        blockers: list[CleanupBlocker] = []
        previous: tuple[str, ...] = ()
        principal = roles.DurablePrincipal(
            "account",
            f"arn:{self.context.partition}:iam::{self.context.account_id}:root",
            self.context.account_id,
            self.context.partition,
        )
        for role_arn in sorted(candidates):
            retained = any(
                grant.arn not in selected_grant_arns
                and role_arn in self._grant_role_arns(grant)
                for grant in all_grants
            )
            if retained:
                continue
            role_name = role_arn.rsplit("/", maxsplit=1)[-1]
            try:
                role = self.role_service.get_role(role_name)
                mutation = roles.plan_remove_owned_group_trust(
                    role.name, role.trust, principal
                )
            except (BotoCoreError, ClientError, roles.IamRoleError) as error:
                blockers.append(
                    CleanupBlocker(
                        f"role:{role_arn}",
                        "GROUP_TRUST_BLOCKED",
                        str(error),
                    )
                )
                continue
            for operation in mutation.operations:
                identifier = _step_id(
                    f"group-trust-{role.role_id or role.name}", len(result)
                )
                result.append(
                    CleanupStep(
                        identifier,
                        f"role:{role_arn}",
                        operation.action,
                        dict(operation.params),
                        operation.compensate_action,
                        dict(operation.compensate_params or {}),
                        previous,
                    )
                )
                previous = (identifier,)
        return result, blockers

    def _role_steps(
        self,
        item: InventoryItem,
        options: CleanupOptions,
        prerequisites: tuple[str, ...],
    ) -> tuple[list[CleanupStep], list[CleanupBlocker]]:
        role = item.snapshot
        if not isinstance(role, roles.RoleSnapshot):
            raise OperationalError(
                f"Role inventory snapshot is invalid for {item.arn}."
            )
        blockers: list[CleanupBlocker] = []
        has_dependencies = bool(
            role.attached_policies
            or role.inline_policies
            or role.permissions_boundary
            or role.instance_profiles
        )
        if has_dependencies and not options.cascade:
            blockers.append(
                CleanupBlocker(item.key, "CASCADE_REQUIRED", "Role has dependencies.")
            )
        if role.permissions_boundary and not options.remove_boundaries:
            blockers.append(
                CleanupBlocker(
                    item.key,
                    "BOUNDARY_OPT_IN_REQUIRED",
                    "Role permissions-boundary removal requires explicit opt-in.",
                )
            )
        if role.instance_profiles and not options.remove_from_instance_profiles:
            blockers.append(
                CleanupBlocker(
                    item.key,
                    "INSTANCE_PROFILE_OPT_IN_REQUIRED",
                    "Instance-profile membership removal requires explicit opt-in.",
                )
            )
        if blockers:
            return [], blockers
        plan = roles.plan_delete_role(
            role,
            cascade=True,
            remove_from_instance_profiles=options.remove_from_instance_profiles,
        )
        result: list[CleanupStep] = []
        previous = prerequisites
        for index, operation in enumerate(plan.operations):
            identifier = _step_id(f"role-{role.role_id or role.name}", index)
            params = dict(operation.params)
            if operation.action == "delete_role":
                params["ExpectedRoleId"] = role.role_id
            result.append(
                CleanupStep(
                    identifier,
                    item.key,
                    operation.action,
                    params,
                    operation.compensate_action,
                    dict(operation.compensate_params or {}),
                    previous,
                    operation.action == "delete_role",
                )
            )
            previous = (identifier,)
        return result, []

    def _policy_steps(
        self,
        item: InventoryItem,
        options: CleanupOptions,
        prerequisites: tuple[str, ...] = (),
    ) -> tuple[list[CleanupStep], list[CleanupBlocker]]:
        snapshot = item.snapshot
        if (
            not isinstance(snapshot, tuple)
            or len(snapshot) != len(("policy", "dependencies"))
            or not isinstance(snapshot[0], policies.ManagedPolicyRecord)
            or not isinstance(snapshot[1], policies.PolicyDependencies)
        ):
            raise OperationalError(
                f"Policy inventory snapshot is invalid for {item.arn}."
            )
        policy, dependencies = snapshot
        blockers: list[CleanupBlocker] = []
        own_group = (
            item.resource_type is ResourceType.GROUP_GRANT
            and len(dependencies.permission_groups) == 1
            and dependencies.permission_groups[0].name
            == _tag_values(policy.tags)
            .get("hacksaws:resource-id", "")
            .removeprefix("group-")
            and not dependencies.permission_users
            and not dependencies.permission_roles
        )
        permission_dependencies = bool(
            dependencies.permission_users
            or dependencies.permission_groups
            or dependencies.permission_roles
        )
        boundary_dependencies = bool(
            dependencies.boundary_users or dependencies.boundary_roles
        )
        if permission_dependencies and not options.cascade and not own_group:
            blockers.append(
                CleanupBlocker(item.key, "CASCADE_REQUIRED", "Policy has attachments.")
            )
        if boundary_dependencies and not (
            options.cascade and options.remove_boundaries
        ):
            blockers.append(
                CleanupBlocker(
                    item.key,
                    "BOUNDARY_OPT_IN_REQUIRED",
                    "Policy is assigned as a permissions boundary.",
                )
            )
        if blockers:
            return [], blockers
        result: list[CleanupStep] = []
        previous = prerequisites

        def append(
            action: str,
            params: Mapping[str, object],
            compensation: str | None = None,
            compensation_params: Mapping[str, object] | None = None,
            *,
            irreversible: bool = False,
        ) -> None:
            nonlocal previous
            identifier = _step_id(
                f"policy-{policy.policy_id or policy.name}", len(result)
            )
            result.append(
                CleanupStep(
                    identifier,
                    item.key,
                    action,
                    dict(params),
                    compensation,
                    dict(compensation_params or {}),
                    previous,
                    irreversible,
                )
            )
            previous = (identifier,)

        arn = policy.arn.value
        for entity in dependencies.permission_users:
            append(
                "detach_user_policy",
                {"UserName": entity.name, "PolicyArn": arn},
                "attach_user_policy",
                {"UserName": entity.name, "PolicyArn": arn},
            )
        for entity in dependencies.permission_groups:
            append(
                "detach_group_policy",
                {"GroupName": entity.name, "PolicyArn": arn},
                "attach_group_policy",
                {"GroupName": entity.name, "PolicyArn": arn},
            )
        for entity in dependencies.permission_roles:
            append(
                "detach_role_policy",
                {"RoleName": entity.name, "PolicyArn": arn},
                "attach_role_policy",
                {"RoleName": entity.name, "PolicyArn": arn},
            )
        for entity in dependencies.boundary_users:
            append(
                "delete_user_permissions_boundary",
                {"UserName": entity.name},
                "put_user_permissions_boundary",
                {"UserName": entity.name, "PermissionsBoundary": arn},
            )
        for entity in dependencies.boundary_roles:
            append(
                "delete_role_permissions_boundary",
                {"RoleName": entity.name},
                "put_role_permissions_boundary",
                {"RoleName": entity.name, "PermissionsBoundary": arn},
            )
        for version in policy.versions:
            if version.version_id == policy.default_version_id:
                continue
            compensation_params: dict[str, object] = {}
            if version.document is not None:
                compensation_params = {
                    "PolicyArn": arn,
                    "PolicyDocument": policies.canonical_policy_json(version.document),
                    "SetAsDefault": False,
                }
            append(
                "delete_policy_version",
                {"PolicyArn": arn, "VersionId": version.version_id},
                "create_policy_version" if compensation_params else None,
                compensation_params,
            )
        append(
            "delete_policy",
            {"PolicyArn": arn, "ExpectedPolicyId": policy.policy_id},
            irreversible=True,
        )
        return result, []

    def execute(self, plan: CleanupPlan) -> CleanupResult:
        """Execute a confirmed plan through an account-bound durable retry queue."""
        if (
            plan.account_id != self.context.account_id
            or plan.partition != self.context.partition
        ):
            raise OperationalError(
                "Cleanup plan does not match selected AWS credentials."
            )
        if plan.classification is PlanClassification.NO_MATCHES:
            return CleanupResult(
                ResultClassification.CLEANED, None, (), (), (), lnt=True
            )
        if plan.blockers:
            return CleanupResult(
                ResultClassification.BLOCKED,
                None,
                (),
                tuple(item.resource_key for item in plan.blockers),
                tuple(item.key for item in plan.resources),
                lnt=False,
            )
        self._assert_plan_current(plan)
        ensure_recovery_handler()
        journal = recovery.begin_journal(
            _RECOVERY_SERVICE,
            plan.account_id,
            "cleanup",
            partition=plan.partition,
        )
        for step in plan.steps:
            journal.record_before_mutation(
                _HANDLER,
                forward={
                    "planStepId": step.id,
                    "resourceKey": step.resource_key,
                    "prerequisites": list(step.prerequisites),
                    "action": step.action,
                    "params": dict(step.params),
                    "irreversible": step.irreversible,
                },
                compensation={
                    "action": step.compensate_action,
                    "params": dict(step.compensate_params),
                    "irreversible": step.irreversible,
                    "forwardAction": step.action,
                    "forwardParams": dict(step.params),
                },
            )
        state = _continue_queue(
            journal.id,
            self.context,
            sleeper=self._sleep,
            jitter=self._jitter,
        )
        completed = tuple(cast("list[str]", state["completed"]))
        failed = tuple(cast("list[str]", state["failed"]))
        remaining = tuple(cast("list[str]", state["remaining"]))
        residue = (
            self._verify_lnt(plan.resources) if not failed and not remaining else ()
        )
        if residue:
            recovery.mark_failure(
                journal.id,
                OperationalError(
                    "AWS cleanup completed but Leave No Trace absence could not "
                    "be proven."
                ),
            )
            remaining = residue
        elif not failed and not remaining:
            recovery.finish_journal(journal.id, scrub_payloads=True)
        lnt = not failed and not remaining
        classification = (
            ResultClassification.CLEANED
            if lnt
            else ResultClassification.RECOVERY_REQUIRED
            if state["irreversibleFailure"]
            else ResultClassification.PARTIAL
        )
        return CleanupResult(
            classification, journal.id, completed, failed, remaining, lnt
        )

    def _assert_plan_current(self, plan: CleanupPlan) -> None:
        for item in plan.resources:
            if isinstance(item.snapshot, roles.RoleSnapshot):
                current = self.role_service.get_role(item.name)
                if roles.role_snapshot_hash(current) != roles.role_snapshot_hash(
                    item.snapshot
                ):
                    raise OperationalError(
                        f"Role {item.name!r} changed after cleanup planning."
                    )
                continue
            snapshot = item.snapshot
            if not isinstance(snapshot, tuple) or not isinstance(
                snapshot[0], policies.ManagedPolicyRecord
            ):
                continue
            expected_policy, expected_dependencies = snapshot
            current_policy = self.policy_service.get_policy(
                item.arn,
                include_document=True,
                include_versions=True,
                include_tags=True,
            )
            current_dependencies = self.policy_service.policy_dependencies(item.arn)
            if (
                current_policy != expected_policy
                or current_dependencies != expected_dependencies
            ):
                raise OperationalError(
                    f"Policy {item.name!r} changed after cleanup planning."
                )

    def continue_journal(self, journal_id: str) -> CleanupResult:
        """Resume a cleanup journal with its dependency-aware retry scheduler."""
        ensure_recovery_handler()
        journal = recovery.get_journal(journal_id)
        if journal.get("serviceType") != _RECOVERY_SERVICE:
            raise OperationalError(f"Journal {journal_id!r} is not an IAM cleanup.")
        self._assert_journal_scope(journal)
        if journal.get("status") == "completed" and journal.get("payloadsScrubbed"):
            return CleanupResult(
                ResultClassification.CLEANED,
                journal_id,
                tuple(
                    str(step["forward"].get("resourceKey", ""))
                    for step in journal["steps"]
                ),
                (),
                (),
                lnt=True,
            )
        state = _continue_queue(
            journal_id,
            self.context,
            sleeper=self._sleep,
            jitter=self._jitter,
        )
        completed = tuple(cast("list[str]", state["completed"]))
        failed = tuple(cast("list[str]", state["failed"]))
        remaining = tuple(cast("list[str]", state["remaining"]))
        if not failed and not remaining:
            remaining = self._verify_journal_lnt(journal_id)
        if not failed and not remaining:
            recovery.finish_journal(journal_id, scrub_payloads=True)
        elif remaining:
            recovery.mark_failure(
                journal_id,
                OperationalError("Cleanup recovery could not prove AWS absence."),
            )
        classification = (
            ResultClassification.CLEANED
            if not failed and not remaining
            else ResultClassification.RECOVERY_REQUIRED
            if state["irreversibleFailure"]
            else ResultClassification.PARTIAL
        )
        return CleanupResult(
            classification,
            journal_id,
            completed,
            failed,
            remaining,
            lnt=classification is ResultClassification.CLEANED,
        )

    def rollback_journal(self, journal_id: str) -> dict[str, Any]:
        """Rollback a cleanup journal only within its recorded AWS scope."""
        ensure_recovery_handler()
        journal = recovery.get_journal(journal_id)
        if journal.get("serviceType") != _RECOVERY_SERVICE:
            raise OperationalError(f"Journal {journal_id!r} is not an IAM cleanup.")
        self._assert_journal_scope(journal)
        if journal.get("payloadsScrubbed"):
            raise OperationalError(
                "Completed cleanup receipts cannot be rolled back after recovery "
                "payloads have been scrubbed."
            )
        return recovery.rollback_journal(journal_id, self.context)

    def _assert_journal_scope(self, journal: Mapping[str, object]) -> None:
        if journal.get("accountId") != self.context.account_id:
            raise OperationalError("Cleanup journal does not match selected account.")
        recorded_partition = journal.get("partition")
        if recorded_partition is None:
            raise OperationalError(
                "Cleanup journal has no recorded AWS partition and cannot be "
                "recovered safely; preserve it for manual inspection."
            )
        if recorded_partition != self.context.partition:
            raise OperationalError("Cleanup journal does not match selected partition.")

    def _verify_journal_lnt(self, journal_id: str) -> tuple[str, ...]:
        journal = recovery.get_journal(journal_id)
        residue: list[str] = []
        for step in journal["steps"]:
            forward = step["forward"]
            if forward.get("irreversible") is not True:
                continue
            action = forward.get("action")
            params = forward.get("params", {})
            if not isinstance(params, Mapping):
                raise OperationalError("Cleanup journal identity payload is invalid.")
            try:
                if action == "delete_role":
                    self.context.iam.get_role(RoleName=params.get("RoleName"))
                elif action == "delete_policy":
                    self.context.iam.get_policy(PolicyArn=params.get("PolicyArn"))
                else:
                    continue
            except ClientError as error:
                if _error_code(error) == "NoSuchEntity":
                    continue
                raise
            resource = str(forward.get("resourceKey", "unknown"))
            if resource not in residue:
                residue.append(resource)
        return tuple(residue)

    def _verify_lnt(self, resources: Iterable[InventoryItem]) -> tuple[str, ...]:
        residue: list[str] = []
        for item in resources:
            absent = False
            for attempt in range(_LNT_ATTEMPTS):
                try:
                    if item.resource_type is ResourceType.ROLE:
                        self.context.iam.get_role(RoleName=item.name)
                    else:
                        self.context.iam.get_policy(PolicyArn=item.arn)
                except ClientError as error:
                    if _error_code(error) == "NoSuchEntity":
                        absent = True
                        break
                    raise
                if attempt + 1 < _LNT_ATTEMPTS:
                    self._sleep(self._jitter(0.0, 0.1 * (2**attempt)))
            if not absent:
                residue.append(item.key)
        return tuple(residue)


def _call(context: Any, action: str, params: Mapping[str, object]) -> None:
    allowed = {
        "add_role_to_instance_profile",
        "attach_group_policy",
        "attach_role_policy",
        "attach_user_policy",
        "create_policy_version",
        "delete_policy",
        "delete_policy_version",
        "delete_role",
        "delete_role_permissions_boundary",
        "delete_role_policy",
        "delete_user_permissions_boundary",
        "detach_group_policy",
        "detach_role_policy",
        "detach_user_policy",
        "put_role_permissions_boundary",
        "put_role_policy",
        "put_user_permissions_boundary",
        "remove_role_from_instance_profile",
        "update_assume_role_policy",
    }
    if action not in allowed:
        raise OperationalError(f"Cleanup action {action!r} is not allowlisted.")
    request = dict(params)
    expected_role_id = request.pop("ExpectedRoleId", None)
    expected_policy_id = request.pop("ExpectedPolicyId", None)
    if expected_role_id is not None:
        current = context.iam.get_role(RoleName=request["RoleName"])["Role"]
        if current.get("RoleId") != expected_role_id:
            raise OperationalError("Role identity changed after cleanup planning.")
    if expected_policy_id is not None:
        current = context.iam.get_policy(PolicyArn=request["PolicyArn"])["Policy"]
        if current.get("PolicyId") != expected_policy_id:
            raise OperationalError("Policy identity changed after cleanup planning.")
    getattr(context.iam, action)(**request)


def _forward(
    payload: Mapping[str, object], context: object
) -> Mapping[str, object] | None:
    action = payload.get("action")
    params = payload.get("params")
    if not isinstance(action, str) or not isinstance(params, Mapping):
        raise OperationalError("Cleanup recovery forward payload is invalid.")
    try:
        _call(context, action, params)
    except ClientError as error:
        if str(error.response.get("Error", {}).get("Code")) == "NoSuchEntity":
            return {"absenceObserved": True}
        raise
    if action in {"delete_policy", "delete_role"}:
        identity = params.get("ExpectedPolicyId") or params.get("ExpectedRoleId")
        return {
            "deletionAccepted": True,
            "expectedResourceId": str(identity or ""),
        }
    return None


def _compensate(payload: Mapping[str, object], raw_context: object) -> None:
    context = cast("Any", raw_context)
    if payload.get("irreversible") is True:
        action = payload.get("forwardAction")
        params = payload.get("forwardParams")
        if not isinstance(action, str) or not isinstance(params, Mapping):
            raise OperationalError("Cleanup commit-point receipt is invalid.")
        try:
            if action == "delete_role":
                current = context.iam.get_role(RoleName=params.get("RoleName"))["Role"]
                if current.get("RoleId") == params.get("ExpectedRoleId"):
                    return
            elif action == "delete_policy":
                current = context.iam.get_policy(PolicyArn=params.get("PolicyArn"))[
                    "Policy"
                ]
                if current.get("PolicyId") == params.get("ExpectedPolicyId"):
                    return
        except ClientError as error:
            if _error_code(error) != "NoSuchEntity":
                raise
        raise OperationalError(
            "Cleanup crossed an irreversible IAM identity commit point; "
            "Hacksaws will not recreate the deleted resource."
        )
    action = payload.get("action")
    params = payload.get("params")
    if action is None:
        return
    if not isinstance(action, str) or not isinstance(params, Mapping):
        raise OperationalError("Cleanup recovery compensation payload is invalid.")
    _call(context, action, params)


def ensure_recovery_handler() -> None:
    """Register the fixed allowlisted cleanup recovery handler once."""
    try:
        recovery.register_handler(
            _RECOVERY_SERVICE,
            _HANDLER,
            forward=_forward,
            compensate=_compensate,
        )
    except ValueError as error:
        if "already registered" not in str(error):
            raise


def _continue_queue(
    journal_id: str,
    context: object,
    *,
    sleeper: Callable[[float], None],
    jitter: Callable[[float, float], float],
    max_attempts: int = 3,
) -> dict[str, object]:
    """Run pending journal steps as a dependency-ready, durable retry queue."""
    initial = recovery.get_journal(journal_id)
    completed_steps = [
        step for step in initial["steps"] if step["status"] == "completed"
    ]
    completed_plan_ids: set[str] = {
        str(step["forward"].get("planStepId")) for step in completed_steps
    }
    completed_resources: list[str] = list(
        dict.fromkeys(
            str(step["forward"].get("resourceKey", "unknown"))
            for step in completed_steps
        )
    )
    failed_resources: list[str] = []
    irreversible_failure = False
    pending = deque(step for step in initial["steps"] if step["status"] == "pending")
    stalled = 0
    while pending:
        step = pending.popleft()
        forward = step["forward"]
        prerequisites = set(forward.get("prerequisites", []))
        if not prerequisites.issubset(completed_plan_ids):
            pending.append(step)
            stalled += 1
            if stalled >= len(pending):
                break
            continue
        stalled = 0
        attempts = int(step.get("attempts", 0)) + 1
        try:
            effect = _forward(forward, context)
        except Exception as error:
            code = _error_code(error)
            recovery.mark_queue_attempt(
                journal_id,
                str(step["id"]),
                attempts=attempts,
                error=error,
            )
            resource = str(forward.get("resourceKey", "unknown"))
            if code in _TRANSIENT_CODES and attempts < max_attempts:
                sleeper(jitter(0.0, 0.1 * (2 ** (attempts - 1))))
                step["attempts"] = attempts
                pending.append(step)
                continue
            if resource not in failed_resources:
                failed_resources.append(resource)
            if forward.get("irreversible") is True:
                irreversible_failure = True
            continue
        recovery.mark_step_completed(journal_id, str(step["id"]), effect=effect)
        plan_id = str(forward["planStepId"])
        completed_plan_ids.add(plan_id)
        resource = str(forward["resourceKey"])
        if resource not in completed_resources:
            completed_resources.append(resource)
    current = recovery.get_journal(journal_id)
    remaining = [
        str(step["forward"].get("resourceKey", "unknown"))
        for step in current["steps"]
        if step["status"] == "pending"
    ]
    remaining = list(dict.fromkeys(remaining))
    if remaining:
        recovery.mark_failure(
            journal_id,
            OperationalError("Cleanup queue retained pending or failed resources."),
        )
    return {
        "completed": completed_resources,
        "failed": failed_resources,
        "remaining": remaining,
        "irreversibleFailure": irreversible_failure,
    }


ensure_recovery_handler()
