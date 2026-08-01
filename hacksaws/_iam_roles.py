"""IAM role, trust, attachment, inline-policy, and group-grant primitives.

This module deliberately contains no CLI, prompts, configuration persistence, or
format rendering.  It exposes immutable snapshots and mutation plans so callers
can preview, journal, execute, or compensate multi-account changes explicitly.
"""

# ruff: noqa: ANN401, TRY003

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field
from typing import TYPE_CHECKING
from typing import Any
from typing import Literal
from typing import Protocol
from urllib.parse import unquote

from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Iterable

DEFAULT_ROLE_PATH = "/hacksaws/"
MANAGED_TAG = "hacksaws:managed"
OWNER_TAG = "hacksaws:owner"
AUDIT_TAG = "hacksaws:audit-id"
ORIGIN_TAG = "hacksaws:ownership-origin"
ROLE_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/([\w+=,.@/-]+)$"
)
IAM_PRINCIPAL_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):(user|role)/([\w+=,.@/-]+)$"
)
ACCOUNT_PRINCIPAL_ARN = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):root$")
ASSUMED_ROLE_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):sts::(\d{12}):"
    r"assumed-role/([\w+=,.@/-]+)/[\w+=,.@-]+$"
)
ACCOUNT_ID = re.compile(r"^\d{12}$")


class IamRoleError(RuntimeError):
    """Base error for IAM role service operations."""


class ConflictError(IamRoleError):
    """Raised when optimistic state or ownership no longer matches."""


class DependencyError(IamRoleError):
    """Raised when deletion would cross an unapproved dependency boundary."""


class AmbiguousTrustError(IamRoleError):
    """Raised when a logical trust mutation cannot preserve a complex statement."""


def canonical_json(value: object) -> str:
    """Return deterministic compact JSON."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def document_hash(value: object) -> str:
    """Return the optimistic-concurrency digest for a policy document."""
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def validate_trust_document(document: Mapping[str, Any]) -> None:
    """Reject trust-policy principal forms that cannot be bounded safely."""
    statements = _trust_statements(document)
    for index, statement in enumerate(statements):
        if "NotPrincipal" in statement:
            raise IamRoleError(
                f"Trust statement {index} uses NotPrincipal, which is not supported."
            )
        principal = statement.get("Principal")
        if principal is None:
            continue
        values: list[object] = []
        if isinstance(principal, Mapping):
            for value in principal.values():
                values.extend(value if isinstance(value, list) else [value])
        else:
            values.append(principal)
        for value in values:
            if not isinstance(value, str):
                raise IamRoleError(
                    f"Trust statement {index} contains an invalid Principal value."
                )
            if "*" in value:
                raise IamRoleError("Wildcard trust principals are not supported.")


def decode_document(value: object) -> dict[str, Any]:
    """Normalize an IAM API policy document into a mapping."""
    if isinstance(value, str):
        value = json.loads(unquote(value))
    if not isinstance(value, dict):
        raise IamRoleError("IAM policy document must be an object.")
    return value


def normalize_path(value: str) -> str:
    """Validate and normalize an IAM role path."""
    if not value.startswith("/") or not value.endswith("/") or "//" in value:
        raise IamRoleError("IAM role path must begin and end with one '/'.")
    return value


def normalize_caller_principal(arn: str) -> str:
    """Convert a caller ARN to an exact durable IAM user, role, or account ARN."""
    if "*" in arn:
        raise IamRoleError("Wildcard principals are not supported.")
    if IAM_PRINCIPAL_ARN.fullmatch(arn) or ACCOUNT_PRINCIPAL_ARN.fullmatch(arn):
        return arn
    assumed_role = ASSUMED_ROLE_ARN.fullmatch(arn)
    if assumed_role:
        return (
            f"arn:{assumed_role.group(1)}:iam::{assumed_role.group(2)}:"
            f"role/{assumed_role.group(3)}"
        )
    raise IamRoleError(f"Caller ARN {arn!r} is not a durable IAM user or role.")


@dataclass(frozen=True)
class AccountRef:
    """Account identity used for deterministic ARN resolution."""

    name: str
    account_id: str
    partition: str = "aws"

    def __post_init__(self) -> None:
        if not ACCOUNT_ID.fullmatch(self.account_id):
            raise IamRoleError("AWS account IDs must contain 12 digits.")
        if self.partition not in {"aws", "aws-us-gov", "aws-cn"}:
            raise IamRoleError("Unsupported AWS partition.")


@dataclass(frozen=True)
class PrincipalRef:
    """Unresolved exact trust principal supplied by a caller."""

    kind: Literal["caller", "principal", "user", "role", "account"]
    value: str
    account: str | None = None


@dataclass(frozen=True)
class DurablePrincipal:
    """Exact durable principal suitable for a trust policy."""

    kind: Literal["user", "role", "account"]
    arn: str
    account_id: str
    partition: str


def resolve_principal(
    reference: PrincipalRef,
    accounts: Mapping[str, AccountRef],
    *,
    caller_arn: str | None = None,
) -> DurablePrincipal:
    """Resolve name, ARN, account-qualified, or caller principal data."""
    value = reference.value
    if reference.kind == "caller":
        value = normalize_caller_principal(caller_arn or value)
    if reference.kind == "principal" or value.startswith("arn:"):
        durable = normalize_caller_principal(value)
        account_match = ACCOUNT_PRINCIPAL_ARN.fullmatch(durable)
        if account_match:
            return DurablePrincipal(
                "account",
                durable,
                account_match.group(2),
                account_match.group(1),
            )
        match = IAM_PRINCIPAL_ARN.fullmatch(durable)
        if match is None:  # pragma: no cover - guaranteed by normalization
            raise IamRoleError("Normalized principal was not an IAM principal.")
        kind: Literal["user", "role"] = "user" if match.group(3) == "user" else "role"
        return DurablePrincipal(kind, durable, match.group(2), match.group(1))
    account = accounts.get(reference.account or "")
    if account is None:
        raise IamRoleError("A configured account is required for named principals.")
    if reference.kind == "account":
        account_id = value if ACCOUNT_ID.fullmatch(value) else account.account_id
        return DurablePrincipal(
            "account",
            f"arn:{account.partition}:iam::{account_id}:root",
            account_id,
            account.partition,
        )
    if reference.kind not in {"user", "role"}:
        raise IamRoleError(f"Unsupported principal kind {reference.kind!r}.")
    arn = f"arn:{account.partition}:iam::{account.account_id}:{reference.kind}/{value}"
    return DurablePrincipal(reference.kind, arn, account.account_id, account.partition)


@dataclass(frozen=True)
class Operation:
    """One journalable AWS mutation and its optional compensation."""

    client: str
    action: str
    params: Mapping[str, Any]
    compensate_action: str | None = None
    compensate_params: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class MutationPlan:
    """Immutable, previewable multi-resource mutation plan."""

    kind: str
    resources: tuple[str, ...]
    operations: tuple[Operation, ...]
    expected: Mapping[str, str] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()


@dataclass
class ExecutionJournal:
    """In-memory journal usable by a durable integration adapter."""

    completed: list[Operation] = field(default_factory=list)
    compensated: list[Operation] = field(default_factory=list)


class ClientResolver(Protocol):
    """Resolve a named account/service client for plan execution."""

    def __call__(self, name: str) -> Any: ...


def execute_plan(
    plan: MutationPlan, resolve_client: ClientResolver
) -> ExecutionJournal:
    """Execute a plan and compensate completed operations in reverse on failure."""
    journal = ExecutionJournal()
    try:
        for operation in plan.operations:
            getattr(resolve_client(operation.client), operation.action)(
                **operation.params
            )
            journal.completed.append(operation)
    except Exception:
        for operation in reversed(journal.completed):
            if operation.compensate_action and operation.compensate_params is not None:
                getattr(resolve_client(operation.client), operation.compensate_action)(
                    **operation.compensate_params
                )
                journal.compensated.append(operation)
        raise
    return journal


@dataclass(frozen=True)
class RoleSpec:
    """Desired IAM role fields independent of CLI naming choices."""

    name: str
    trust: Mapping[str, Any]
    path: str = DEFAULT_ROLE_PATH
    description: str | None = None
    max_session_duration: int = 3600
    permissions_boundary: str | None = None
    tags: Mapping[str, str] = field(default_factory=dict)
    owner: str = "hacksaws"
    audit_id: str | None = None
    ownership_origin: str = "created"


@dataclass(frozen=True)
class RoleSnapshot:
    """Remote role state used for updates and dependency-safe deletion."""

    name: str
    arn: str
    path: str
    trust: Mapping[str, Any]
    description: str | None = None
    max_session_duration: int = 3600
    permissions_boundary: str | None = None
    tags: Mapping[str, str] = field(default_factory=dict)
    attached_policies: tuple[str, ...] = ()
    inline_policies: tuple[str, ...] = ()
    instance_profiles: tuple[str, ...] = ()
    inline_policy_documents: Mapping[str, Mapping[str, Any]] = field(
        default_factory=dict
    )
    role_id: str = ""


def ownership_tags(spec: RoleSpec) -> dict[str, str]:
    """Merge explicit naming/audit tags with required ownership markers."""
    result = {
        **spec.tags,
        MANAGED_TAG: "true",
        OWNER_TAG: spec.owner,
        ORIGIN_TAG: spec.ownership_origin,
    }
    if spec.audit_id:
        result[AUDIT_TAG] = spec.audit_id
    return result


def plan_create_role(spec: RoleSpec, *, client: str = "iam") -> MutationPlan:
    """Plan role creation under the safe Hacksaws path by default."""
    normalize_path(spec.path)
    validate_trust_document(spec.trust)
    params: dict[str, Any] = {
        "RoleName": spec.name,
        "Path": spec.path,
        "AssumeRolePolicyDocument": canonical_json(spec.trust),
        "MaxSessionDuration": spec.max_session_duration,
        "Tags": [
            {"Key": key, "Value": value} for key, value in ownership_tags(spec).items()
        ],
    }
    if spec.description is not None:
        params["Description"] = spec.description
    if spec.permissions_boundary:
        params["PermissionsBoundary"] = spec.permissions_boundary
    operation = Operation(
        client,
        "create_role",
        params,
        "delete_role",
        {"RoleName": spec.name},
    )
    return MutationPlan("role-create", (spec.name,), (operation,))


def plan_update_role(current: RoleSnapshot, desired: RoleSpec) -> MutationPlan:
    """Plan mutable role fields with an optimistic trust precondition."""
    if current.name != desired.name or current.path != desired.path:
        raise ConflictError("IAM role name and path require replacement, not update.")
    validate_trust_document(desired.trust)
    operations: list[Operation] = []
    if (
        current.description != desired.description
        or current.max_session_duration != desired.max_session_duration
    ):
        operations.append(
            Operation(
                "iam",
                "update_role",
                {
                    "RoleName": current.name,
                    "Description": desired.description or "",
                    "MaxSessionDuration": desired.max_session_duration,
                },
                "update_role",
                {
                    "RoleName": current.name,
                    "Description": current.description or "",
                    "MaxSessionDuration": current.max_session_duration,
                },
            )
        )
    if document_hash(current.trust) != document_hash(desired.trust):
        operations.append(
            Operation(
                "iam",
                "update_assume_role_policy",
                {
                    "RoleName": current.name,
                    "PolicyDocument": canonical_json(desired.trust),
                },
                "update_assume_role_policy",
                {
                    "RoleName": current.name,
                    "PolicyDocument": canonical_json(current.trust),
                },
            )
        )
    if current.permissions_boundary != desired.permissions_boundary:
        if desired.permissions_boundary:
            operations.append(
                Operation(
                    "iam",
                    "put_role_permissions_boundary",
                    {
                        "RoleName": current.name,
                        "PermissionsBoundary": desired.permissions_boundary,
                    },
                    (
                        "put_role_permissions_boundary"
                        if current.permissions_boundary
                        else "delete_role_permissions_boundary"
                    ),
                    (
                        {
                            "RoleName": current.name,
                            "PermissionsBoundary": current.permissions_boundary,
                        }
                        if current.permissions_boundary
                        else {"RoleName": current.name}
                    ),
                )
            )
        else:
            operations.append(
                Operation(
                    "iam",
                    "delete_role_permissions_boundary",
                    {"RoleName": current.name},
                    "put_role_permissions_boundary",
                    {
                        "RoleName": current.name,
                        "PermissionsBoundary": current.permissions_boundary,
                    },
                )
            )
    operations.extend(
        plan_sync_tags(current.name, current.tags, ownership_tags(desired)).operations
    )
    return MutationPlan(
        "role-update",
        (current.arn,),
        tuple(operations),
        expected={"role": role_snapshot_hash(current)},
    )


def role_snapshot_hash(role: RoleSnapshot) -> str:
    """Hash every mutable role field used by a mutation plan."""
    return document_hash(
        {
            "arn": role.arn,
            "roleId": role.role_id,
            "path": role.path,
            "trust": role.trust,
            "description": role.description,
            "maxSessionDuration": role.max_session_duration,
            "permissionsBoundary": role.permissions_boundary,
            "tags": dict(role.tags),
            "attachedPolicies": sorted(role.attached_policies),
            "inlinePolicies": dict(role.inline_policy_documents),
            "instanceProfiles": sorted(role.instance_profiles),
        }
    )


def plan_adopt_role(
    role: RoleSnapshot, owner: str, audit_id: str | None = None
) -> MutationPlan:
    """Plan explicit adoption without changing role permissions or trust."""
    current_owner = role.tags.get(OWNER_TAG)
    if role.tags.get(MANAGED_TAG) == "true" and current_owner not in {None, owner}:
        raise ConflictError(
            f"Role is already managed by {current_owner!r}; release it before adoption."
        )
    tags = {MANAGED_TAG: "true", OWNER_TAG: owner, ORIGIN_TAG: "adopted"}
    if audit_id:
        tags[AUDIT_TAG] = audit_id
    return plan_put_tags(
        role.name, tags, current=role.tags, kind="role-adopt", expected_role=role
    )


def plan_release_role(role: RoleSnapshot) -> MutationPlan:
    """Plan removal of Hacksaws ownership tags without deleting the role."""
    keys = tuple(
        key
        for key in (MANAGED_TAG, OWNER_TAG, AUDIT_TAG, ORIGIN_TAG)
        if key in role.tags
    )
    return plan_remove_tags(
        role.name, keys, current=role.tags, kind="role-release", expected_role=role
    )


def plan_put_tags(
    role_name: str,
    tags: Mapping[str, str],
    *,
    current: Mapping[str, str] | None = None,
    kind: str = "role-tag",
    expected_role: RoleSnapshot | None = None,
) -> MutationPlan:
    """Plan additive/update role tags."""
    operations = tuple(
        Operation(
            "iam",
            "tag_role",
            {
                "RoleName": role_name,
                "Tags": [{"Key": key, "Value": value}],
            },
            ("tag_role" if current is not None and key in current else "untag_role"),
            (
                {
                    "RoleName": role_name,
                    "Tags": [{"Key": key, "Value": current[key]}],
                }
                if current is not None and key in current
                else {"RoleName": role_name, "TagKeys": [key]}
            ),
        )
        for key, value in tags.items()
    )
    expected = (
        {"role": role_snapshot_hash(expected_role)} if expected_role is not None else {}
    )
    return MutationPlan(kind, (role_name,), operations, expected)


def plan_remove_tags(
    role_name: str,
    keys: Iterable[str],
    *,
    current: Mapping[str, str] | None = None,
    kind: str = "role-untag",
    expected_role: RoleSnapshot | None = None,
) -> MutationPlan:
    """Plan role tag removal."""
    values = tuple(keys)
    operations = tuple(
        Operation(
            "iam",
            "untag_role",
            {"RoleName": role_name, "TagKeys": [key]},
            "tag_role" if current is not None and key in current else None,
            (
                {
                    "RoleName": role_name,
                    "Tags": [{"Key": key, "Value": current[key]}],
                }
                if current is not None and key in current
                else None
            ),
        )
        for key in values
    )
    expected = (
        {"role": role_snapshot_hash(expected_role)} if expected_role is not None else {}
    )
    return MutationPlan(kind, (role_name,), operations, expected)


def plan_sync_tags(
    role_name: str, current: Mapping[str, str], desired: Mapping[str, str]
) -> MutationPlan:
    """Plan exact tag synchronization."""
    put = {key: value for key, value in desired.items() if current.get(key) != value}
    remove = [key for key in current if key not in desired]
    operations = (
        *plan_put_tags(role_name, put, current=current).operations,
        *plan_remove_tags(role_name, remove, current=current).operations,
    )
    return MutationPlan("role-tags-sync", (role_name,), operations)


def _trust_statements(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not all(
        isinstance(item, dict) for item in statements
    ):
        raise IamRoleError("Trust policy Statement must be an object or list.")
    return [dict(item) for item in statements]


def trust_statement(
    principal: DurablePrincipal, sid: str | None = None
) -> dict[str, Any]:
    """Create one distinct exact-principal trust statement."""
    statement: dict[str, Any] = {
        "Effect": "Allow",
        "Principal": {"AWS": principal.arn},
        "Action": "sts:AssumeRole",
    }
    if sid:
        statement["Sid"] = sid
    return statement


def _is_simple_exact_trust(item: Mapping[str, Any], principal_arn: str) -> bool:
    principal = item.get("Principal")
    if not isinstance(principal, dict) or set(principal) != {"AWS"}:
        return False
    aws = principal["AWS"]
    values = aws if isinstance(aws, list) else [aws]
    return (
        values == [principal_arn]
        and item.get("Effect") == "Allow"
        and item.get("Action") == "sts:AssumeRole"
        and not item.get("Condition")
        and set(item) <= {"Sid", "Effect", "Principal", "Action"}
    )


def plan_set_trust(
    role_name: str,
    current: Mapping[str, Any],
    desired: Mapping[str, Any],
    *,
    expected_hash: str | None = None,
) -> MutationPlan:
    """Plan exact trust replacement with optimistic concurrency."""
    validate_trust_document(desired)
    current_hash = document_hash(current)
    if expected_hash and expected_hash != current_hash:
        raise ConflictError("Trust policy changed since it was read.")
    operation = Operation(
        "iam",
        "update_assume_role_policy",
        {"RoleName": role_name, "PolicyDocument": canonical_json(desired)},
        "update_assume_role_policy",
        {"RoleName": role_name, "PolicyDocument": canonical_json(current)},
    )
    return MutationPlan(
        "trust-set", (role_name,), (operation,), {"trust": current_hash}
    )


def plan_add_trust(
    role_name: str,
    current: Mapping[str, Any],
    principal: DurablePrincipal,
    *,
    sid: str | None = None,
) -> MutationPlan:
    """Plan an idempotent distinct-statement trust grant."""
    statements = _trust_statements(current)
    addition = trust_statement(principal, sid)
    if any(_is_simple_exact_trust(item, principal.arn) for item in statements):
        return MutationPlan(
            "trust-add",
            (role_name, principal.arn),
            (),
            {"trust": document_hash(current)},
        )
    desired = {**current, "Statement": [*statements, addition]}
    return plan_set_trust(role_name, current, desired)


def plan_add_owned_group_trust(
    role_name: str,
    current: Mapping[str, Any],
    principal: DurablePrincipal,
) -> MutationPlan:
    """Add the distinct Hacksaws-owned account statement used by group grants."""
    statements = _trust_statements(current)
    owned = [item for item in statements if item.get("Sid") == "HacksawsGroupAccount"]
    if len(owned) > 1 or (
        owned and not _is_simple_exact_trust(owned[0], principal.arn)
    ):
        raise AmbiguousTrustError(
            "HacksawsGroupAccount exists with unexpected semantics; edit it explicitly."
        )
    if owned:
        return MutationPlan(
            "trust-add-owned-group",
            (role_name, principal.arn),
            (),
            {"trust": document_hash(current)},
        )
    desired = {
        **current,
        "Statement": [*statements, trust_statement(principal, "HacksawsGroupAccount")],
    }
    return plan_set_trust(role_name, current, desired)


def plan_remove_owned_group_trust(
    role_name: str,
    current: Mapping[str, Any],
    principal: DurablePrincipal,
) -> MutationPlan:
    """Remove only Hacksaws' distinct group-account statement."""
    statements = _trust_statements(current)
    owned_indexes = [
        index
        for index, item in enumerate(statements)
        if item.get("Sid") == "HacksawsGroupAccount"
    ]
    if len(owned_indexes) > 1:
        raise AmbiguousTrustError(
            "Multiple HacksawsGroupAccount statements exist; edit trust explicitly."
        )
    if not owned_indexes:
        return MutationPlan(
            "trust-remove-owned-group",
            (role_name, principal.arn),
            (),
            {"trust": document_hash(current)},
        )
    selected = statements[owned_indexes[0]]
    if not _is_simple_exact_trust(selected, principal.arn):
        raise AmbiguousTrustError(
            "HacksawsGroupAccount has unexpected semantics; edit trust explicitly."
        )
    desired = {
        **current,
        "Statement": [
            item for index, item in enumerate(statements) if index != owned_indexes[0]
        ],
    }
    return plan_set_trust(role_name, current, desired)


def plan_remove_trust(
    role_name: str,
    current: Mapping[str, Any],
    principal: DurablePrincipal,
) -> MutationPlan:
    """Remove only an exact standalone statement, rejecting complex ambiguity."""
    statements = _trust_statements(current)
    matches: list[int] = []
    for index, item in enumerate(statements):
        aws = (
            item.get("Principal", {}).get("AWS")
            if isinstance(item.get("Principal"), dict)
            else None
        )
        values = aws if isinstance(aws, list) else [aws]
        if principal.arn not in values:
            continue
        if not _is_simple_exact_trust(item, principal.arn):
            raise AmbiguousTrustError(
                "Principal occurs in a complex trust statement; edit explicitly."
            )
        matches.append(index)
    if not matches:
        return MutationPlan(
            "trust-remove",
            (role_name, principal.arn),
            (),
            {"trust": document_hash(current)},
        )
    desired = {
        **current,
        "Statement": [
            item for index, item in enumerate(statements) if index not in matches
        ],
    }
    return plan_set_trust(role_name, current, desired)


def plan_attach_policy(
    role_name: str, policy_arn: str, *, current: RoleSnapshot | None = None
) -> MutationPlan:
    """Plan attachment of an existing managed policy reference."""
    if current is not None and policy_arn in current.attached_policies:
        return MutationPlan(
            "role-policy-attach",
            (role_name, policy_arn),
            (),
            {"role": role_snapshot_hash(current)},
        )
    return MutationPlan(
        "role-policy-attach",
        (role_name, policy_arn),
        (
            Operation(
                "iam",
                "attach_role_policy",
                {"RoleName": role_name, "PolicyArn": policy_arn},
                "detach_role_policy",
                {"RoleName": role_name, "PolicyArn": policy_arn},
            ),
        ),
        ({"role": role_snapshot_hash(current)} if current is not None else {}),
    )


def plan_detach_policy(
    role_name: str, policy_arn: str, *, current: RoleSnapshot | None = None
) -> MutationPlan:
    """Plan detachment of an existing managed policy reference."""
    if current is not None and policy_arn not in current.attached_policies:
        return MutationPlan(
            "role-policy-detach",
            (role_name, policy_arn),
            (),
            {"role": role_snapshot_hash(current)},
        )
    return MutationPlan(
        "role-policy-detach",
        (role_name, policy_arn),
        (
            Operation(
                "iam",
                "detach_role_policy",
                {"RoleName": role_name, "PolicyArn": policy_arn},
                "attach_role_policy",
                {"RoleName": role_name, "PolicyArn": policy_arn},
            ),
        ),
        ({"role": role_snapshot_hash(current)} if current is not None else {}),
    )


def plan_publish_and_attach(
    role_name: str,
    policy_name: str,
    document: Mapping[str, Any],
    account: AccountRef,
    *,
    path: str = DEFAULT_ROLE_PATH,
) -> MutationPlan:
    """Plan publishing a local document and attaching its deterministic ARN."""
    normalize_path(path)
    arn = f"arn:{account.partition}:iam::{account.account_id}:policy{path}{policy_name}"
    create = Operation(
        "iam",
        "create_policy",
        {
            "PolicyName": policy_name,
            "Path": path,
            "PolicyDocument": canonical_json(document),
        },
        "delete_policy",
        {"PolicyArn": arn},
    )
    attach = plan_attach_policy(role_name, arn).operations[0]
    return MutationPlan(
        "policy-publish-attach",
        (role_name, arn),
        (create, attach),
        expected={"document": document_hash(document)},
    )


def plan_put_inline_policy(
    role_name: str,
    policy_name: str,
    document: Mapping[str, Any],
    *,
    current: Mapping[str, Any] | None = None,
    expected_hash: str | None = None,
) -> MutationPlan:
    """Plan no-history PutRolePolicy with optional optimistic concurrency."""
    if expected_hash and (current is None or document_hash(current) != expected_hash):
        raise ConflictError("Inline policy changed since it was read.")
    compensation = (
        (
            "put_role_policy",
            {
                "RoleName": role_name,
                "PolicyName": policy_name,
                "PolicyDocument": canonical_json(current),
            },
        )
        if current is not None
        else ("delete_role_policy", {"RoleName": role_name, "PolicyName": policy_name})
    )
    operation = Operation(
        "iam",
        "put_role_policy",
        {
            "RoleName": role_name,
            "PolicyName": policy_name,
            "PolicyDocument": canonical_json(document),
        },
        compensation[0],
        compensation[1],
    )
    expected = {"inline": document_hash(current) if current is not None else "absent"}
    return MutationPlan(
        "inline-policy-put", (role_name, policy_name), (operation,), expected
    )


def plan_delete_inline_policy(
    role_name: str,
    policy_name: str,
    *,
    current: Mapping[str, Any] | None = None,
    expected_hash: str | None = None,
) -> MutationPlan:
    """Plan deletion of one inline policy with optional safe compensation."""
    if expected_hash and (current is None or document_hash(current) != expected_hash):
        raise ConflictError("Inline policy changed since it was read.")
    compensate_action = "put_role_policy" if current is not None else None
    compensate_params = (
        {
            "RoleName": role_name,
            "PolicyName": policy_name,
            "PolicyDocument": canonical_json(current),
        }
        if current is not None
        else None
    )
    return MutationPlan(
        "inline-policy-delete",
        (role_name, policy_name),
        (
            Operation(
                "iam",
                "delete_role_policy",
                {"RoleName": role_name, "PolicyName": policy_name},
                compensate_action,
                compensate_params,
            ),
        ),
        expected={
            "inline": document_hash(current) if current is not None else "absent"
        },
    )


def export_inline_policy(document: Mapping[str, Any]) -> dict[str, Any]:
    """Return a detached JSON-compatible inline-policy snapshot for serializers."""
    return decode_document(canonical_json(document))


def plan_delete_role(
    role: RoleSnapshot,
    *,
    cascade: bool = False,
    remove_from_instance_profiles: bool = False,
    allow_unmanaged: bool = False,
) -> MutationPlan:
    """Plan dependency-complete deletion without deleting shared dependencies."""
    if role.tags.get(MANAGED_TAG) != "true" and not allow_unmanaged:
        raise DependencyError(
            "Role is not adopted by Hacksaws; adopt or explicitly override."
        )
    dependencies = bool(
        role.attached_policies
        or role.inline_policies
        or role.permissions_boundary
        or role.instance_profiles
    )
    if dependencies and not cascade:
        raise DependencyError("Role has dependencies; explicit cascade is required.")
    if role.instance_profiles and not remove_from_instance_profiles:
        raise DependencyError(
            "Instance-profile membership requires an explicit safeguard override."
        )
    operations: list[Operation] = []
    for arn in role.attached_policies:
        operations.extend(plan_detach_policy(role.name, arn).operations)
    for name in role.inline_policies:
        operations.extend(
            plan_delete_inline_policy(
                role.name,
                name,
                current=role.inline_policy_documents.get(name),
            ).operations
        )
    if role.permissions_boundary:
        operations.append(
            Operation(
                "iam",
                "delete_role_permissions_boundary",
                {"RoleName": role.name},
                "put_role_permissions_boundary",
                {
                    "RoleName": role.name,
                    "PermissionsBoundary": role.permissions_boundary,
                },
            )
        )
    operations.extend(
        (
            Operation(
                "iam",
                "remove_role_from_instance_profile",
                {"InstanceProfileName": profile, "RoleName": role.name},
                "add_role_to_instance_profile",
                {"InstanceProfileName": profile, "RoleName": role.name},
            )
        )
        for profile in role.instance_profiles
    )
    operations.append(
        Operation(
            "iam",
            "delete_role",
            {"RoleName": role.name},
            None,
            {"RoleName": role.name, "ExpectedRoleId": role.role_id},
        )
    )
    warnings_list = [
        (
            "Role deletion is irreversible: AWS assigns a new principal identity if "
            "the role is recreated, so rollback stops at the delete commit point."
        )
    ]
    if role.instance_profiles:
        warnings_list.append(
            "Instance profiles are preserved; only role membership is removed."
        )
    warnings = tuple(warnings_list)
    return MutationPlan(
        "role-delete",
        (role.arn,),
        tuple(operations),
        expected={"role": role_snapshot_hash(role)},
        warnings=warnings,
    )


@dataclass(frozen=True)
class GroupGrantSnapshot:
    """One group aggregate-policy snapshot for durable AssumeRole grants."""

    group_name: str
    account: AccountRef
    policy_name: str
    policy_arn: str
    role_arns: tuple[str, ...] = ()
    exists: bool = True
    attached: bool = True
    document: Mapping[str, Any] = field(
        default_factory=lambda: {"Version": "2012-10-17", "Statement": []}
    )
    default_version_id: str | None = None
    version_ids: tuple[str, ...] = ()
    tags: Mapping[str, str] = field(default_factory=dict)
    owned: bool = False
    path: str = DEFAULT_ROLE_PATH


def _group_document(
    role_arns: Iterable[str], current: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Replace only Hacksaws' aggregate statement and preserve all other semantics."""
    base = decode_document(canonical_json(current or {"Version": "2012-10-17"}))
    statements = _trust_statements(base)
    unrelated: list[dict[str, Any]] = []
    for statement in statements:
        if statement.get("Sid") != "HacksawsGroupAssumeRoles":
            unrelated.append(statement)
            continue
        if (
            statement.get("Effect") != "Allow"
            or statement.get("Action") != "sts:AssumeRole"
            or set(statement) - {"Sid", "Effect", "Action", "Resource"}
        ):
            raise ConflictError(
                "The aggregate group statement has unexpected semantics; refusing "
                "to replace it."
            )
    selected = sorted(set(role_arns))
    if selected:
        unrelated.append(
            {
                "Sid": "HacksawsGroupAssumeRoles",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": selected,
            }
        )
    return {**base, "Statement": unrelated}


def plan_group_grant(
    role: RoleSnapshot,
    trust: Mapping[str, Any],
    group: GroupGrantSnapshot,
) -> MutationPlan:
    """Plan account trust plus one aggregate managed group policy."""
    match = ROLE_ARN.fullmatch(role.arn)
    if match is None or match.group(2) != group.account.account_id:
        raise IamRoleError(
            "Group aggregate grants require same-account role membership."
        )
    account_principal = DurablePrincipal(
        "account",
        f"arn:{group.account.partition}:iam::{group.account.account_id}:root",
        group.account.account_id,
        group.account.partition,
    )
    trust_plan = plan_add_owned_group_trust(role.name, trust, account_principal)
    roles = tuple(sorted({*group.role_arns, role.arn}))
    policy_plan = plan_put_group_snapshot(group, roles)
    return MutationPlan(
        "group-grant",
        (role.arn, group.group_name, group.policy_arn),
        (*trust_plan.operations, *policy_plan.operations),
        expected={**trust_plan.expected, **policy_plan.expected},
    )


def plan_put_group_snapshot(
    group: GroupGrantSnapshot, role_arns: Iterable[str]
) -> MutationPlan:
    """Plan replacement of the one aggregate managed group policy document."""
    roles = tuple(sorted(set(role_arns)))
    for arn in roles:
        match = ROLE_ARN.fullmatch(arn)
        if match is None or match.group(2) != group.account.account_id:
            raise IamRoleError("Every group grant role must be in the group's account.")
    if group.exists and not group.owned:
        raise ConflictError(
            "Aggregate group policy exists but is not verified as Hacksaws-owned."
        )
    document = _group_document(roles, group.document)
    operations: list[Operation] = []
    operations.append(
        Operation(
            "managed_policy",
            "publish_owned_policy",
            {
                "PolicyArn": group.policy_arn,
                "PolicyName": group.policy_name,
                "Path": group.path,
                "PolicyDocument": document,
                "ExpectedDocumentHash": (
                    document_hash(group.document) if group.exists else "absent"
                ),
                **(
                    {
                        "ExpectedDefaultVersionId": group.default_version_id,
                        "ExpectedTagHash": document_hash(dict(group.tags)),
                    }
                    if group.exists
                    else {}
                ),
                "ResourceId": f"group-{group.group_name}",
            },
            "restore_owned_policy",
            {
                "PolicyArn": group.policy_arn,
                "PolicyName": group.policy_name,
                "Path": group.path,
                "PolicyDocument": dict(group.document),
                "ExpectedDocumentHash": document_hash(document),
                **(
                    {"ExpectedTagHash": document_hash(dict(group.tags))}
                    if group.exists
                    else {}
                ),
                "DeleteIfCreated": not group.exists,
                "ResourceId": f"group-{group.group_name}",
            },
        )
    )
    if not group.attached:
        operations.append(
            Operation(
                "iam",
                "attach_group_policy",
                {"GroupName": group.group_name, "PolicyArn": group.policy_arn},
                "detach_group_policy",
                {"GroupName": group.group_name, "PolicyArn": group.policy_arn},
            )
        )
    return MutationPlan(
        "group-snapshot",
        (group.group_name, *roles),
        tuple(operations),
        expected={
            "group": document_hash(group.document) if group.exists else "absent",
            "groupPolicyArn": group.policy_arn,
            "groupName": group.group_name,
            "groupAttached": str(group.attached).lower(),
        },
    )


def plan_add_group_member(group: GroupGrantSnapshot, role_arn: str) -> MutationPlan:
    """Add one role to a same-account group aggregate snapshot."""
    return plan_put_group_snapshot(group, (*group.role_arns, role_arn))


def plan_sync_group_members(
    group: GroupGrantSnapshot, role_arns: Iterable[str]
) -> MutationPlan:
    """Synchronize all same-account role grants in one aggregate snapshot."""
    return plan_put_group_snapshot(group, role_arns)


def plan_remove_group_member(group: GroupGrantSnapshot, role_arn: str) -> MutationPlan:
    """Remove one role from a same-account group aggregate snapshot."""
    return plan_put_group_snapshot(
        group, (arn for arn in group.role_arns if arn != role_arn)
    )


@dataclass(frozen=True)
class Assumability:
    """Static potential-assumability classification."""

    classification: Literal["potentially-allowed", "denied", "indeterminate"]
    reasons: tuple[str, ...]


def classify_assumability(
    *,
    trust_allows: bool | None,
    identity_allows: bool | None,
    explicit_deny: bool = False,
) -> Assumability:
    """Classify static evidence without claiming a live authorization result."""
    if explicit_deny or trust_allows is False or identity_allows is False:
        return Assumability(
            "denied",
            ("Static policy evidence contains a denial or missing required allow.",),
        )
    if trust_allows is True and identity_allows is True:
        return Assumability(
            "potentially-allowed",
            ("Trust and identity policies contain required allows.",),
        )
    policy_qualifiers = "Conditions, boundaries, SCPs, or unavailable policy data"
    return Assumability(
        "indeterminate",
        (f"{policy_qualifiers} may decide access.",),
    )


DENY_ALL = canonical_json(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }
)


class StsProbe(Protocol):
    """Explicit live AssumeRole probe interface."""

    def probe(
        self, role_arn: str, session_name: str, external_id: str | None = None
    ) -> Mapping[str, Any]: ...


@dataclass
class BotoStsProbe:
    """STS probe that returns metadata and never persists returned credentials."""

    client: Any

    def probe(
        self, role_arn: str, session_name: str, external_id: str | None = None
    ) -> Mapping[str, Any]:
        request: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": 900,
            "Policy": DENY_ALL,
        }
        if external_id:
            request["ExternalId"] = external_id
        response = self.client.assume_role(**request)
        return {"ok": True, "packed_policy_size": response.get("PackedPolicySize")}


@dataclass
class IamRoleService:
    """Read-side IAM role service with pagination and injected consistency retry."""

    client: Any
    attempts: int = 4
    delay: float = 0.1
    sleep: Callable[[float], None] = time.sleep

    def _retry(self, operation: Callable[[], Any]) -> Any:
        last: Exception | None = None
        for attempt in range(self.attempts):
            try:
                return operation()
            except (BotoCoreError, ClientError) as error:
                last = error
                if attempt + 1 < self.attempts:
                    self.sleep(self.delay * (attempt + 1))
        if last is None:  # pragma: no cover - attempts is validated by construction
            raise IamRoleError("Retry loop did not execute.")
        raise last

    def get_role(self, name: str) -> RoleSnapshot:
        """Read a role and all deletion-relevant dependencies."""
        response = self._retry(lambda: self.client.get_role(RoleName=name))["Role"]
        trust = decode_document(response["AssumeRolePolicyDocument"])
        attached = tuple(
            item["PolicyArn"]
            for item in self._pages(
                "list_attached_role_policies", "AttachedPolicies", RoleName=name
            )
        )
        inline = tuple(self._pages("list_role_policies", "PolicyNames", RoleName=name))
        inline_documents = {
            policy_name: self.get_inline_policy(name, policy_name)
            for policy_name in inline
        }
        profiles = tuple(
            item["InstanceProfileName"]
            for item in self._pages(
                "list_instance_profiles_for_role", "InstanceProfiles", RoleName=name
            )
        )
        tags = {item["Key"]: item["Value"] for item in response.get("Tags", [])}
        boundary = response.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
        return RoleSnapshot(
            name,
            response["Arn"],
            response.get("Path", "/"),
            trust,
            response.get("Description"),
            response.get("MaxSessionDuration", 3600),
            boundary,
            tags,
            attached,
            inline,
            profiles,
            inline_documents,
            str(response.get("RoleId", "")),
        )

    def list_roles(
        self, *, path_prefix: str = DEFAULT_ROLE_PATH
    ) -> tuple[RoleSnapshot, ...]:
        """List role summaries across all IAM pages."""
        return tuple(
            RoleSnapshot(
                item["RoleName"],
                item["Arn"],
                item.get("Path", "/"),
                decode_document(item["AssumeRolePolicyDocument"]),
                item.get("Description"),
                item.get("MaxSessionDuration", 3600),
                role_id=str(item.get("RoleId", "")),
            )
            for item in self._pages("list_roles", "Roles", PathPrefix=path_prefix)
        )

    def list_inline_policies(self, role_name: str) -> tuple[str, ...]:
        """List every named inline policy for a role."""
        return tuple(
            self._pages("list_role_policies", "PolicyNames", RoleName=role_name)
        )

    def get_inline_policy(self, role_name: str, policy_name: str) -> dict[str, Any]:
        """Read one named inline policy document with consistency retry."""
        response = self._retry(
            lambda: self.client.get_role_policy(
                RoleName=role_name, PolicyName=policy_name
            )
        )
        return decode_document(response["PolicyDocument"])

    def get_trust(self, role_name: str) -> dict[str, Any]:
        """Read one role trust policy."""
        response = self._retry(lambda: self.client.get_role(RoleName=role_name))
        return decode_document(response["Role"]["AssumeRolePolicyDocument"])

    def _pages(self, operation: str, key: str, **params: Any) -> Iterable[Any]:
        paginator = self.client.get_paginator(operation)
        for page in paginator.paginate(**params):
            yield from page.get(key, [])
