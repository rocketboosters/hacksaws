"""Pure, dependency-injected AWS IAM managed-policy workflows."""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from collections.abc import Callable
from collections.abc import Iterable
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import replace
from datetime import UTC
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from botocore.exceptions import ClientError

from hacksaws._iam_policy_documents import JsonValue
from hacksaws._iam_policy_documents import canonical_policy_json
from hacksaws._iam_policy_documents import decode_iam_document
from hacksaws._iam_policy_documents import policy_digest

DEFAULT_PATH = "/hacksaws/"
AWS_ACCOUNT = "aws"
MAX_TAGS = 50
MAX_TAG_KEY = 128
MAX_TAG_VALUE = 256
MAX_POLICY_NAME = 128
MAX_MANAGED_POLICY_SIZE = 6_144
MAX_POLICY_VERSIONS = 5
PACKED_WARNING_PERCENT = 80
MIN_SESSION_DURATION = 900
ARN_PART_COUNT = 6
ACCOUNT_PATTERN = re.compile(r"^\d{12}$")
NAME_PATTERN = re.compile(r"^[\w+=,.@-]{1,128}$", re.ASCII)
ARN_PATTERN = re.compile(
    r"^arn:(?P<partition>aws(?:-us-gov|-cn)?):iam::"
    r"(?P<account>aws|\d{12}):policy/(?P<resource>[^\s]+)$"
)
ROLE_ARN_PATTERN = re.compile(
    r"^arn:(?P<partition>aws(?:-us-gov|-cn)?):iam::"
    r"(?P<account>\d{12}):role/(?P<resource>[^\s]+)$"
)
RESERVED_TAGS = frozenset(
    {
        "hacksaws:managed-by",
        "hacksaws:resource-id",
        "hacksaws:resource-kind",
        "hacksaws:created-by",
        "hacksaws:created-at",
        "hacksaws:ownership-origin",
    }
)
OWNERSHIP_TAGS = frozenset(
    {
        "hacksaws:managed-by",
        "hacksaws:resource-id",
        "hacksaws:resource-kind",
    }
)
DENY_ALL_SESSION_POLICY: dict[str, JsonValue] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "HacksawsAssumabilityProbe",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        }
    ],
}


class IamClient(Protocol):
    """Minimal IAM client surface required by the policy service."""

    def list_policies(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_policy(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_policy_version(self, **kwargs: object) -> Mapping[str, object]: ...

    def list_policy_versions(self, **kwargs: object) -> Mapping[str, object]: ...

    def create_policy(self, **kwargs: object) -> Mapping[str, object]: ...

    def create_policy_version(self, **kwargs: object) -> Mapping[str, object]: ...

    def set_default_policy_version(self, **kwargs: object) -> object: ...

    def delete_policy_version(self, **kwargs: object) -> object: ...

    def list_policy_tags(self, **kwargs: object) -> Mapping[str, object]: ...

    def tag_policy(self, **kwargs: object) -> object: ...

    def untag_policy(self, **kwargs: object) -> object: ...

    def list_entities_for_policy(self, **kwargs: object) -> Mapping[str, object]: ...

    def detach_user_policy(self, **kwargs: object) -> object: ...

    def detach_group_policy(self, **kwargs: object) -> object: ...

    def detach_role_policy(self, **kwargs: object) -> object: ...

    def delete_user_permissions_boundary(self, **kwargs: object) -> object: ...

    def delete_role_permissions_boundary(self, **kwargs: object) -> object: ...

    def delete_policy(self, **kwargs: object) -> object: ...


class StsClient(Protocol):
    """Minimal STS client surface required by the policy service."""

    def get_caller_identity(self, **kwargs: object) -> Mapping[str, object]: ...

    def assume_role(self, **kwargs: object) -> Mapping[str, object]: ...


class AccessAnalyzerClient(Protocol):
    """Minimal IAM Access Analyzer client surface used for validation."""

    def validate_policy(self, **kwargs: object) -> Mapping[str, object]: ...


class PolicyServiceError(RuntimeError):
    """Base class for managed-policy service failures."""


class ImmutablePolicyError(PolicyServiceError):
    """Reject a mutation targeting an AWS-managed policy."""


class PolicyDriftError(PolicyServiceError):
    """Report optimistic-concurrency drift before a mutation."""


class PolicyValidationError(PolicyServiceError):
    """Report a plan that cannot be safely executed."""

    def __init__(self, report: ValidationReport) -> None:
        self.report = report
        super().__init__("Policy validation failed.")


class PackedPolicyProbeError(PolicyServiceError):
    """Expose structured STS packed-policy failure information."""

    def __init__(self, diagnostic: PackedPolicyDiagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.message)


class PolicyScope(StrEnum):
    """AWS list-policies scope values."""

    ALL = "All"
    AWS = "AWS"
    LOCAL = "Local"


class PolicyKind(StrEnum):
    """Managed policy ownership kinds."""

    AWS_MANAGED = "aws-managed"
    CUSTOMER_MANAGED = "customer-managed"


class DiagnosticSeverity(StrEnum):
    """Severity of a local or AWS policy validation diagnostic."""

    ERROR = "error"
    WARNING = "warning"
    SUGGESTION = "suggestion"


class ChangeAction(StrEnum):
    """High-level managed-policy publication actions."""

    CREATE = "create"
    NOOP = "noop"
    UPDATE = "update"
    ROLLBACK = "rollback"
    ADOPT = "adopt"
    RELEASE = "release"
    DELETE = "delete"


class StepState(StrEnum):
    """Execution state for an operation journal step."""

    PLANNED = "planned"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    COMPENSATED = "compensated"


@dataclass(frozen=True, slots=True)
class ManagedPolicyArn:
    """Parsed IAM managed-policy ARN with exact account semantics."""

    value: str
    partition: str
    account_id: str
    resource: str

    @property
    def kind(self) -> PolicyKind:
        """Classify AWS-owned and customer-owned managed policies."""
        if self.account_id == AWS_ACCOUNT:
            return PolicyKind.AWS_MANAGED
        return PolicyKind.CUSTOMER_MANAGED

    @property
    def name(self) -> str:
        """Return the final path segment of the policy ARN."""
        return self.resource.rsplit("/", maxsplit=1)[-1]

    @property
    def path(self) -> str:
        """Return the IAM policy path including leading and trailing slashes."""
        if "/" not in self.resource:
            return "/"
        prefix = self.resource.rsplit("/", maxsplit=1)[0]
        return f"/{prefix}/"

    @classmethod
    def parse(cls, value: str) -> ManagedPolicyArn:
        """Parse a full managed-policy ARN without accepting partial forms."""
        match = ARN_PATTERN.fullmatch(value)
        if match is None:
            message = f"Invalid IAM managed-policy ARN: {value!r}."
            raise PolicyServiceError(message)
        return cls(
            value=value,
            partition=match.group("partition"),
            account_id=match.group("account"),
            resource=match.group("resource"),
        )


@dataclass(frozen=True, slots=True)
class CallerIdentity:
    """Verified caller attribution used by policy audit tags."""

    account_id: str
    partition: str
    arn: str
    principal_id: str


@dataclass(frozen=True, slots=True)
class Tag:
    """IAM tag key and value."""

    key: str
    value: str

    def as_request(self) -> dict[str, str]:
        """Convert to boto3 request shape."""
        return {"Key": self.key, "Value": self.value}


@dataclass(frozen=True, slots=True)
class RepairAction:
    """Machine-readable proposed correction for a diagnostic."""

    code: str
    field: str
    message: str
    suggested_value: str | None = None


@dataclass(frozen=True, slots=True)
class ValidationDiagnostic:
    """Aggregated validation result suitable for later CLI rendering."""

    severity: DiagnosticSeverity
    code: str
    message: str
    field: str | None = None
    repair: RepairAction | None = None


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """Complete local and optional AWS validation results."""

    diagnostics: tuple[ValidationDiagnostic, ...] = ()

    @property
    def valid(self) -> bool:
        """Return whether the report contains no blocking errors."""
        return not any(
            item.severity is DiagnosticSeverity.ERROR for item in self.diagnostics
        )

    @property
    def repairs(self) -> tuple[RepairAction, ...]:
        """Return every actionable repair in diagnostic order."""
        return tuple(
            item.repair for item in self.diagnostics if item.repair is not None
        )

    def merge(self, other: ValidationReport) -> ValidationReport:
        """Combine reports without discarding either source."""
        return ValidationReport(self.diagnostics + other.diagnostics)


@dataclass(frozen=True, slots=True)
class PolicyVersionRecord:
    """IAM managed-policy version metadata and optional document."""

    version_id: str
    is_default: bool
    created_at: datetime | None
    document: dict[str, JsonValue] | None = None


@dataclass(frozen=True, slots=True)
class ManagedPolicyRecord:
    """Complete managed-policy metadata used by service workflows."""

    arn: ManagedPolicyArn
    policy_id: str
    name: str
    path: str
    default_version_id: str
    attachment_count: int
    permissions_boundary_usage_count: int
    tags: tuple[Tag, ...] = ()
    document: dict[str, JsonValue] | None = None
    versions: tuple[PolicyVersionRecord, ...] = ()
    description: str | None = None

    @property
    def owned(self) -> bool:
        """Return whether standard Hacksaws ownership tags are present."""
        values = {tag.key.casefold(): tag.value for tag in self.tags}
        return (
            values.get("hacksaws:managed-by") == "hacksaws"
            and values.get("hacksaws:resource-kind") == "managed-policy"
            and bool(values.get("hacksaws:resource-id"))
        )


@dataclass(frozen=True, slots=True)
class ResolutionResult:
    """Policy reference resolution that preserves all ambiguous candidates."""

    reference: str
    candidates: tuple[ManagedPolicyRecord, ...]

    @property
    def ambiguous(self) -> bool:
        """Return whether more than one candidate matched."""
        return len(self.candidates) > 1

    @property
    def selected(self) -> ManagedPolicyRecord | None:
        """Return the single candidate, otherwise no implicit selection."""
        if len(self.candidates) == 1:
            return self.candidates[0]
        return None


@dataclass(frozen=True, slots=True)
class Compensation:
    """Best-effort inverse operation available after a successful step."""

    operation: str
    parameters: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class OperationStep:
    """One inspectable mutation step with optional compensation metadata."""

    step_id: str
    operation: str
    parameters: Mapping[str, object]
    destructive: bool = False
    compensation: Compensation | None = None


@dataclass(frozen=True, slots=True)
class OperationPlan:
    """Pure operation plan produced before any AWS mutation occurs."""

    plan_id: str
    action: ChangeAction
    summary: str
    steps: tuple[OperationStep, ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """One immutable operation execution journal entry."""

    step_id: str
    state: StepState
    occurred_at: datetime
    detail: str | None = None


@dataclass(slots=True)
class OperationJournal:
    """Append-only in-memory journal returned to later persistence layers."""

    plan_id: str
    entries: list[JournalEntry]

    def record(
        self,
        step_id: str,
        state: StepState,
        detail: str | None = None,
    ) -> None:
        """Append an execution event without performing persistence."""
        self.entries.append(JournalEntry(step_id, state, datetime.now(UTC), detail))


@dataclass(frozen=True, slots=True)
class PolicyChangePlan:
    """Managed-policy publication plan with concurrency preconditions."""

    operation: OperationPlan
    policy_arn: ManagedPolicyArn | None
    name: str
    path: str
    document: dict[str, JsonValue]
    description: str | None
    tags: tuple[Tag, ...]
    expected_default_version_id: str | None = None
    expected_digest: str | None = None
    prune_version_id: str | None = None
    rollback_version_id: str | None = None
    validation: ValidationReport = ValidationReport()


@dataclass(frozen=True, slots=True)
class PublishResult:
    """Result of executing a create, no-op, update, or rollback plan."""

    action: ChangeAction
    policy: ManagedPolicyRecord
    journal: OperationJournal


@dataclass(frozen=True, slots=True)
class PolicyExport:
    """Lossless service-level export data for external serialization."""

    policy: ManagedPolicyRecord
    exported_at: datetime
    active_document: dict[str, JsonValue]
    versions: tuple[PolicyVersionRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class EntityReference:
    """IAM identity depending on a managed policy."""

    kind: str
    name: str
    entity_id: str


@dataclass(frozen=True, slots=True)
class PolicyDependencies:
    """All permission-policy and permissions-boundary dependencies."""

    permission_users: tuple[EntityReference, ...] = ()
    permission_groups: tuple[EntityReference, ...] = ()
    permission_roles: tuple[EntityReference, ...] = ()
    boundary_users: tuple[EntityReference, ...] = ()
    boundary_roles: tuple[EntityReference, ...] = ()

    @property
    def empty(self) -> bool:
        """Return whether the policy has no live entity dependencies."""
        return not any(
            (
                self.permission_users,
                self.permission_groups,
                self.permission_roles,
                self.boundary_users,
                self.boundary_roles,
            )
        )


@dataclass(frozen=True, slots=True)
class PolicyDeletionPlan:
    """Dependency-complete policy deletion plan."""

    policy: ManagedPolicyRecord
    dependencies: PolicyDependencies
    operation: OperationPlan
    cascade: bool

    @property
    def executable(self) -> bool:
        """Return whether dependencies permit the selected deletion mode."""
        return self.cascade or self.dependencies.empty


@dataclass(frozen=True, slots=True)
class TagChangePlan:
    """Optimistically guarded ownership or tag mutation plan."""

    policy: ManagedPolicyRecord
    operation: OperationPlan
    add: tuple[Tag, ...]
    remove: tuple[str, ...]
    expected_digest: str


@dataclass(frozen=True, slots=True)
class MutationResult:
    """Policy mutation result containing an auditable journal."""

    policy: ManagedPolicyRecord | None
    journal: OperationJournal


@dataclass(frozen=True, slots=True)
class PackedPolicyDiagnostic:
    """Structured STS PackedPolicyTooLarge error information."""

    code: str
    message: str
    packed_policy_size: int | None
    repairs: tuple[RepairAction, ...]


@dataclass(frozen=True, slots=True)
class PackedPolicyWarning:
    """Non-fatal warning returned for a successful near-limit STS request."""

    packed_policy_size: int
    threshold: int
    message: str


@dataclass(frozen=True, slots=True)
class AssumeRoleProbeResult:
    """Credential-free result of an explicit AssumeRole policy probe."""

    role_arn: str
    assumed_role_arn: str
    expires_at: datetime | None
    packed_policy_size: int | None
    warning: PackedPolicyWarning | None


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded delays for eventual-consistency verification."""

    delays: tuple[float, ...] = (0.0, 0.25, 0.5, 1.0, 2.0, 4.0)


@dataclass(frozen=True, slots=True)
class PolicyServiceOptions:
    """Account and retry configuration for the managed-policy service."""

    account_id: str
    partition: str
    owned_path: str = DEFAULT_PATH
    retry: RetryPolicy = RetryPolicy()


@dataclass(frozen=True, slots=True)
class CreatePolicyOptions:
    """Optional metadata and validation settings for policy creation."""

    description: str | None = None
    path: str | None = None
    resource_id: str | None = None
    user_tags: tuple[Tag, ...] = ()
    caller: CallerIdentity | None = None
    include_aws_validation: bool = True


@dataclass(frozen=True, slots=True)
class AssumeRoleProbeOptions:
    """Context parameters for an explicit deny-all AssumeRole probe."""

    session_name: str = "hacksaws-policy-probe"
    duration_seconds: int = MIN_SESSION_DURATION
    external_id: str | None = None
    source_identity: str | None = None
    session_tags: tuple[Tag, ...] = ()
    packed_warning_threshold: int = PACKED_WARNING_PERCENT


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        message = f"AWS response field {label!r} is not an object."
        raise PolicyServiceError(message)
    for key in value:
        if not isinstance(key, str):
            message = f"AWS response field {label!r} has a non-string key."
            raise PolicyServiceError(message)
    return value


def _items(value: object, *, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        message = f"AWS response field {label!r} is not a list."
        raise PolicyServiceError(message)
    return value


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        message = f"AWS response field {label!r} is not a string."
        raise PolicyServiceError(message)
    return value


def _integer(value: object, *, default: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value


def _datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    return None


def _normalize_path(path: str) -> str:
    if not path.startswith("/") or not path.endswith("/"):
        message = "IAM policy path must begin and end with '/'."
        raise PolicyServiceError(message)
    return path


def _new_step(
    operation: str,
    parameters: Mapping[str, object],
    *,
    destructive: bool = False,
    compensation: Compensation | None = None,
) -> OperationStep:
    return OperationStep(
        step_id=uuid.uuid4().hex,
        operation=operation,
        parameters=parameters,
        destructive=destructive,
        compensation=compensation,
    )


def _operation_plan(
    action: ChangeAction,
    summary: str,
    steps: Iterable[OperationStep],
    *,
    warnings: Iterable[str] = (),
) -> OperationPlan:
    return OperationPlan(
        plan_id=uuid.uuid4().hex,
        action=action,
        summary=summary,
        steps=tuple(steps),
        warnings=tuple(warnings),
    )


def _tags_from_response(value: object) -> tuple[Tag, ...]:
    result: list[Tag] = []
    for item in _items(value, label="Tags"):
        tag = _mapping(item, label="Tag")
        result.append(
            Tag(_string(tag.get("Key"), label="Tag.Key"), str(tag.get("Value", "")))
        )
    return tuple(result)


def _metadata_record(value: object) -> ManagedPolicyRecord:
    policy = _mapping(value, label="Policy")
    arn = ManagedPolicyArn.parse(_string(policy.get("Arn"), label="Policy.Arn"))
    return ManagedPolicyRecord(
        arn=arn,
        policy_id=_string(policy.get("PolicyId"), label="Policy.PolicyId"),
        name=_string(policy.get("PolicyName"), label="Policy.PolicyName"),
        path=str(policy.get("Path", arn.path)),
        default_version_id=_string(
            policy.get("DefaultVersionId"), label="Policy.DefaultVersionId"
        ),
        attachment_count=_integer(policy.get("AttachmentCount")),
        permissions_boundary_usage_count=_integer(
            policy.get("PermissionsBoundaryUsageCount")
        ),
        description=(
            str(policy["Description"])
            if policy.get("Description") is not None
            else None
        ),
    )


def _client_error_details(error: ClientError) -> tuple[str, str]:
    detail = error.response.get("Error", {})
    if not isinstance(detail, Mapping):
        return "Unknown", str(error)
    return str(detail.get("Code", "Unknown")), str(detail.get("Message", error))


def parse_packed_policy_diagnostic(
    error: ClientError,
) -> PackedPolicyDiagnostic | None:
    """Parse STS PackedPolicyTooLarge into actionable structured data."""
    code, message = _client_error_details(error)
    if code != "PackedPolicyTooLarge":
        return None
    match = re.search(r"(?P<size>\d{1,3})\s*%", message)
    packed_size = int(match.group("size")) if match else None
    repairs = (
        RepairAction(
            "reduce-session-policy",
            "Policy",
            "Remove redundant session statements or split the workflow.",
        ),
        RepairAction(
            "reduce-session-tags",
            "Tags",
            "Pass fewer or shorter session tags.",
        ),
        RepairAction(
            "use-role-permissions",
            "PolicyArns",
            "Move stable permissions into the role and keep the session "
            "boundary small.",
        ),
    )
    return PackedPolicyDiagnostic(code, message, packed_size, repairs)


def packed_policy_warning(
    packed_policy_size: int | None,
    *,
    threshold: int = PACKED_WARNING_PERCENT,
) -> PackedPolicyWarning | None:
    """Return warning data for successful STS calls near the packed limit."""
    if packed_policy_size is None or packed_policy_size < threshold:
        return None
    message = (
        f"STS packed policy size is {packed_policy_size}% of the service limit; "
        "future policy or tag growth may fail."
    )
    return PackedPolicyWarning(packed_policy_size, threshold, message)


class AccessAnalyzerPolicyValidator:
    """Translate paginated IAM Access Analyzer findings into diagnostics."""

    def __init__(self, client: AccessAnalyzerClient) -> None:
        self._client = client

    def validate(
        self,
        document: Mapping[str, JsonValue],
        *,
        policy_type: str = "IDENTITY_POLICY",
        resource_type: str | None = None,
    ) -> ValidationReport:
        """Validate a document and aggregate every result page."""
        diagnostics: list[ValidationDiagnostic] = []
        token: str | None = None
        while True:
            request: dict[str, object] = {
                "policyDocument": canonical_policy_json(document),
                "policyType": policy_type,
            }
            if resource_type is not None:
                request["validatePolicyResourceType"] = resource_type
            if token is not None:
                request["nextToken"] = token
            response = self._client.validate_policy(**request)
            for raw in _items(response.get("findings", []), label="findings"):
                finding = _mapping(raw, label="finding")
                finding_type = str(finding.get("findingType", "WARNING")).casefold()
                severity = {
                    "error": DiagnosticSeverity.ERROR,
                    "security_warning": DiagnosticSeverity.WARNING,
                    "warning": DiagnosticSeverity.WARNING,
                    "suggestion": DiagnosticSeverity.SUGGESTION,
                }.get(finding_type, DiagnosticSeverity.WARNING)
                diagnostics.append(
                    ValidationDiagnostic(
                        severity=severity,
                        code=str(finding.get("issueCode", "AWS_VALIDATION")),
                        message=str(
                            finding.get("findingDetails", "AWS policy finding")
                        ),
                    )
                )
            next_token = response.get("nextToken")
            if not isinstance(next_token, str) or not next_token:
                break
            token = next_token
        return ValidationReport(tuple(diagnostics))


class IamManagedPolicyService:
    """Plan and execute IAM managed-policy operations without UI side effects."""

    def __init__(
        self,
        iam: IamClient,
        sts: StsClient,
        access_analyzer: AccessAnalyzerClient | None,
        options: PolicyServiceOptions,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        account_id = options.account_id
        partition = options.partition
        if ACCOUNT_PATTERN.fullmatch(account_id) is None:
            message = f"Invalid target AWS account ID {account_id!r}."
            raise PolicyServiceError(message)
        if partition not in {"aws", "aws-us-gov", "aws-cn"}:
            message = f"Unsupported AWS partition {partition!r}."
            raise PolicyServiceError(message)
        self._iam = iam
        self._sts = sts
        self._validator = (
            AccessAnalyzerPolicyValidator(access_analyzer)
            if access_analyzer is not None
            else None
        )
        self.account_id = account_id
        self.partition = partition
        self.owned_path = _normalize_path(options.owned_path)
        self.retry = options.retry
        self._sleep = sleeper

    def caller_identity(self) -> CallerIdentity:
        """Get and exactly verify STS caller identity for this service target."""
        response = self._sts.get_caller_identity()
        account = _string(response.get("Account"), label="Account")
        arn = _string(response.get("Arn"), label="Arn")
        principal_id = _string(response.get("UserId"), label="UserId")
        arn_parts = arn.split(":", maxsplit=5)
        if len(arn_parts) != ARN_PART_COUNT:
            message = f"STS returned malformed caller ARN {arn!r}."
            raise PolicyServiceError(message)
        partition = arn_parts[1]
        if account != self.account_id or partition != self.partition:
            message = (
                f"Authenticated caller targets {partition}:{account}, expected "
                f"{self.partition}:{self.account_id}."
            )
            raise PolicyServiceError(message)
        return CallerIdentity(account, partition, arn, principal_id)

    def validate_policy(
        self,
        document: Mapping[str, JsonValue],
        *,
        name: str | None = None,
        path: str | None = None,
        tags: Sequence[Tag] = (),
        include_aws: bool = True,
    ) -> ValidationReport:
        """Aggregate local shape, quota, naming, tag, and AWS findings."""
        diagnostics: list[ValidationDiagnostic] = []
        if name is not None and (
            len(name) > MAX_POLICY_NAME or NAME_PATTERN.fullmatch(name) is None
        ):
            diagnostics.append(
                ValidationDiagnostic(
                    DiagnosticSeverity.ERROR,
                    "INVALID_POLICY_NAME",
                    "Policy name must be 1-128 IAM name characters.",
                    "name",
                    RepairAction(
                        "replace-name",
                        "name",
                        "Use letters, numbers, or _+=,.@-.",
                    ),
                )
            )
        checked_path = path or self.owned_path
        if (
            not checked_path.startswith("/")
            or not checked_path.endswith("/")
            or "*" in checked_path
        ):
            diagnostics.append(
                ValidationDiagnostic(
                    DiagnosticSeverity.ERROR,
                    "INVALID_POLICY_PATH",
                    "Policy path must begin/end with '/' and cannot contain '*'.",
                    "path",
                    RepairAction(
                        "replace-path",
                        "path",
                        "Use a valid IAM path.",
                        self.owned_path,
                    ),
                )
            )
        if document.get("Version") != "2012-10-17":
            diagnostics.append(
                ValidationDiagnostic(
                    DiagnosticSeverity.WARNING,
                    "POLICY_LANGUAGE_VERSION",
                    "Use IAM policy language version 2012-10-17.",
                    "Version",
                    RepairAction(
                        "set-policy-language-version",
                        "Version",
                        "Set the current IAM policy language version.",
                        "2012-10-17",
                    ),
                )
            )
        statements = document.get("Statement")
        if not isinstance(statements, (dict, list)):
            diagnostics.append(
                ValidationDiagnostic(
                    DiagnosticSeverity.ERROR,
                    "INVALID_STATEMENT",
                    "Policy Statement must be an object or list.",
                    "Statement",
                )
            )
        elif isinstance(statements, list) and not statements:
            diagnostics.append(
                ValidationDiagnostic(
                    DiagnosticSeverity.WARNING,
                    "EMPTY_STATEMENT",
                    "Policy contains no permission statements.",
                    "Statement",
                )
            )
        size = len(canonical_policy_json(document))
        if size > MAX_MANAGED_POLICY_SIZE:
            diagnostics.append(
                ValidationDiagnostic(
                    DiagnosticSeverity.ERROR,
                    "POLICY_SIZE_EXCEEDED",
                    f"Minified policy is {size} characters; maximum is 6144.",
                    "policy",
                    RepairAction(
                        "split-policy",
                        "policy",
                        "Split permissions into multiple managed policies.",
                    ),
                )
            )
        diagnostics.extend(self._validate_tags(tags))
        report = ValidationReport(tuple(diagnostics))
        if include_aws and self._validator is not None:
            report = report.merge(self._validator.validate(document))
        return report

    def _validate_tags(self, tags: Sequence[Tag]) -> list[ValidationDiagnostic]:
        diagnostics: list[ValidationDiagnostic] = []
        if len(tags) > MAX_TAGS:
            diagnostics.append(
                ValidationDiagnostic(
                    DiagnosticSeverity.ERROR,
                    "TAG_LIMIT_EXCEEDED",
                    f"IAM permits at most {MAX_TAGS} tags.",
                    "tags",
                )
            )
        seen: set[str] = set()
        for tag in tags:
            folded = tag.key.casefold()
            if not tag.key or len(tag.key) > MAX_TAG_KEY:
                diagnostics.append(
                    ValidationDiagnostic(
                        DiagnosticSeverity.ERROR,
                        "INVALID_TAG_KEY",
                        f"Invalid tag key {tag.key!r}.",
                        "tags",
                    )
                )
            if len(tag.value) > MAX_TAG_VALUE:
                diagnostics.append(
                    ValidationDiagnostic(
                        DiagnosticSeverity.ERROR,
                        "INVALID_TAG_VALUE",
                        f"Tag {tag.key!r} value exceeds {MAX_TAG_VALUE} characters.",
                        "tags",
                    )
                )
            if folded.startswith("aws:") or tag.value.casefold().startswith("aws:"):
                diagnostics.append(
                    ValidationDiagnostic(
                        DiagnosticSeverity.ERROR,
                        "RESERVED_AWS_TAG_PREFIX",
                        f"Tag {tag.key!r} uses the reserved aws: prefix.",
                        "tags",
                    )
                )
            if tag.key in seen:
                diagnostics.append(
                    ValidationDiagnostic(
                        DiagnosticSeverity.ERROR,
                        "DUPLICATE_TAG_KEY",
                        f"Tag key {tag.key!r} was supplied more than once.",
                        "tags",
                    )
                )
            seen.add(tag.key)
        return diagnostics

    def ownership_tags(
        self,
        resource_id: str,
        user_tags: Sequence[Tag] = (),
        *,
        caller: CallerIdentity | None = None,
        created_at: datetime | None = None,
        ownership_origin: str = "created",
    ) -> tuple[Tag, ...]:
        """Merge repeatable user tags with protected ownership/audit tags."""
        collisions = [
            tag.key for tag in user_tags if tag.key.casefold() in RESERVED_TAGS
        ]
        if collisions:
            message = (
                f"User tags cannot override reserved tags: {', '.join(collisions)}."
            )
            raise PolicyServiceError(message)
        identity = caller or self.caller_identity()
        timestamp = created_at or datetime.now(UTC)
        creator = identity.arn
        if len(creator) > MAX_TAG_VALUE:
            digest = hashlib.sha256(creator.encode()).hexdigest()
            creator = f"sha256:{digest}"
        result = [*user_tags]
        result.extend(
            (
                Tag("hacksaws:managed-by", "hacksaws"),
                Tag("hacksaws:resource-id", resource_id),
                Tag("hacksaws:resource-kind", "managed-policy"),
                Tag("hacksaws:created-by", creator),
                Tag("hacksaws:created-at", timestamp.isoformat()),
                Tag("hacksaws:ownership-origin", ownership_origin),
            )
        )
        report = ValidationReport(tuple(self._validate_tags(result)))
        if not report.valid:
            raise PolicyValidationError(report)
        return tuple(result)

    def list_policies(
        self,
        *,
        scope: PolicyScope = PolicyScope.ALL,
        path_prefix: str | None = None,
        include_tags: bool = False,
    ) -> tuple[ManagedPolicyRecord, ...]:
        """List every matching policy, following all IAM Marker pages."""
        marker: str | None = None
        records: list[ManagedPolicyRecord] = []
        while True:
            request: dict[str, object] = {"Scope": scope.value}
            if path_prefix is not None:
                request["PathPrefix"] = path_prefix
            if marker is not None:
                request["Marker"] = marker
            response = self._iam.list_policies(**request)
            for item in _items(response.get("Policies", []), label="Policies"):
                record = _metadata_record(item)
                self._assert_arn_target(record.arn)
                if include_tags and record.arn.kind is PolicyKind.CUSTOMER_MANAGED:
                    record = self._with_tags(record)
                records.append(record)
            if response.get("IsTruncated") is not True:
                break
            marker = _string(response.get("Marker"), label="Marker")
        return tuple(records)

    def _resolve_arn(self, reference: str) -> ResolutionResult:
        arn = ManagedPolicyArn.parse(reference)
        self._assert_arn_target(arn)
        try:
            return ResolutionResult(reference, (self._read_policy(arn),))
        except ClientError as error:
            code, _ = _client_error_details(error)
            if code == "NoSuchEntity":
                return ResolutionResult(reference, ())
            raise

    @staticmethod
    def _split_reference(reference: str) -> tuple[str | None, str]:
        if ":" not in reference:
            return None, reference
        namespace, name = reference.split(":", maxsplit=1)
        if namespace not in {"owned", "custom", "aws"}:
            return None, reference
        return namespace, name

    def resolve(self, reference: str) -> ResolutionResult:
        """Resolve ARN/name and explicit owned:/custom:/aws: namespaces."""
        if reference.startswith("arn:"):
            return self._resolve_arn(reference)

        namespace, name = self._split_reference(reference)
        if not name:
            message = "Policy reference name cannot be empty."
            raise PolicyServiceError(message)
        scopes = {
            "owned": (PolicyScope.LOCAL,),
            "custom": (PolicyScope.LOCAL,),
            "aws": (PolicyScope.AWS,),
            None: (PolicyScope.LOCAL, PolicyScope.AWS),
        }[namespace]
        matches: list[ManagedPolicyRecord] = []
        for scope in scopes:
            for record in self.list_policies(
                scope=scope,
                path_prefix=self.owned_path if namespace == "owned" else None,
                include_tags=namespace == "owned",
            ):
                if record.name.casefold() != name.casefold():
                    continue
                if namespace == "owned" and not record.owned:
                    continue
                matches.append(record)
        return ResolutionResult(reference, tuple(matches))

    def get_policy(
        self,
        reference: str,
        *,
        include_document: bool = True,
        include_versions: bool = False,
        include_tags: bool = True,
    ) -> ManagedPolicyRecord:
        """Get one unambiguous policy by ARN or supported name reference."""
        resolution = self.resolve(reference)
        selected = resolution.selected
        if selected is None:
            if resolution.ambiguous:
                arns = ", ".join(item.arn.value for item in resolution.candidates)
                message = f"Policy reference {reference!r} is ambiguous: {arns}."
            else:
                message = f"Policy reference {reference!r} was not found."
            raise PolicyServiceError(message)
        return self._hydrate_policy(
            selected,
            include_document=include_document,
            include_versions=include_versions,
            include_tags=include_tags,
        )

    def _assert_arn_target(self, arn: ManagedPolicyArn) -> None:
        if arn.partition != self.partition:
            message = (
                f"Policy partition {arn.partition!r} does not match {self.partition!r}."
            )
            raise PolicyServiceError(message)
        if (
            arn.kind is PolicyKind.CUSTOMER_MANAGED
            and arn.account_id != self.account_id
        ):
            message = (
                f"Customer policy account {arn.account_id} does not match "
                f"{self.account_id}."
            )
            raise PolicyServiceError(message)

    def _read_policy(self, arn: ManagedPolicyArn) -> ManagedPolicyRecord:
        response = self._iam.get_policy(PolicyArn=arn.value)
        record = _metadata_record(response.get("Policy"))
        self._assert_arn_target(record.arn)
        if record.arn.value != arn.value:
            message = "IAM returned a different policy ARN than requested."
            raise PolicyServiceError(message)
        return record

    def _with_tags(self, record: ManagedPolicyRecord) -> ManagedPolicyRecord:
        marker: str | None = None
        tags: list[Tag] = []
        while True:
            request: dict[str, object] = {"PolicyArn": record.arn.value}
            if marker is not None:
                request["Marker"] = marker
            response = self._iam.list_policy_tags(**request)
            tags.extend(_tags_from_response(response.get("Tags", [])))
            if response.get("IsTruncated") is not True:
                break
            marker = _string(response.get("Marker"), label="Marker")
        return replace(record, tags=tuple(tags))

    def _list_versions(
        self,
        arn: ManagedPolicyArn,
        *,
        include_documents: bool = False,
    ) -> tuple[PolicyVersionRecord, ...]:
        marker: str | None = None
        versions: list[PolicyVersionRecord] = []
        while True:
            request: dict[str, object] = {"PolicyArn": arn.value}
            if marker is not None:
                request["Marker"] = marker
            response = self._iam.list_policy_versions(**request)
            for raw in _items(response.get("Versions", []), label="Versions"):
                item = _mapping(raw, label="PolicyVersion")
                version_id = _string(item.get("VersionId"), label="VersionId")
                document = (
                    self._get_version_document(arn, version_id)
                    if include_documents
                    else None
                )
                versions.append(
                    PolicyVersionRecord(
                        version_id=version_id,
                        is_default=item.get("IsDefaultVersion") is True,
                        created_at=_datetime(item.get("CreateDate")),
                        document=document,
                    )
                )
            if response.get("IsTruncated") is not True:
                break
            marker = _string(response.get("Marker"), label="Marker")
        return tuple(versions)

    def _get_version_document(
        self, arn: ManagedPolicyArn, version_id: str
    ) -> dict[str, JsonValue]:
        response = self._iam.get_policy_version(
            PolicyArn=arn.value,
            VersionId=version_id,
        )
        version = _mapping(response.get("PolicyVersion"), label="PolicyVersion")
        return decode_iam_document(version.get("Document"))

    def _hydrate_policy(
        self,
        record: ManagedPolicyRecord,
        *,
        include_document: bool,
        include_versions: bool,
        include_tags: bool,
    ) -> ManagedPolicyRecord:
        current = self._read_policy(record.arn)
        tags = (
            self._with_tags(current).tags
            if include_tags and current.arn.kind is PolicyKind.CUSTOMER_MANAGED
            else ()
        )
        document = (
            self._get_version_document(current.arn, current.default_version_id)
            if include_document
            else None
        )
        versions = (
            self._list_versions(current.arn, include_documents=include_versions)
            if include_versions
            else ()
        )
        return replace(current, tags=tags, document=document, versions=versions)

    def plan_create(
        self,
        name: str,
        document: dict[str, JsonValue],
        *,
        options: CreatePolicyOptions | None = None,
    ) -> PolicyChangePlan:
        """Plan a tagged customer-managed policy creation."""
        selected_options = options or CreatePolicyOptions()
        selected_path = selected_options.path or self.owned_path
        tags = self.ownership_tags(
            selected_options.resource_id or uuid.uuid4().hex,
            selected_options.user_tags,
            caller=selected_options.caller,
        )
        report = self.validate_policy(
            document,
            name=name,
            path=selected_path,
            tags=tags,
            include_aws=selected_options.include_aws_validation,
        )
        request: dict[str, object] = {
            "PolicyName": name,
            "Path": selected_path,
            "PolicyDocument": canonical_policy_json(document),
            "Tags": [tag.as_request() for tag in tags],
        }
        if selected_options.description is not None:
            request["Description"] = selected_options.description
        step = _new_step(
            "CreatePolicy",
            request,
            compensation=Compensation(
                "DeletePolicy",
                {
                    "PolicyArn": (
                        f"arn:{self.partition}:iam::{self.account_id}:policy"
                        f"{selected_path}{name}"
                    )
                },
            ),
        )
        operation = _operation_plan(
            ChangeAction.CREATE,
            f"Create customer-managed policy {selected_path}{name}.",
            (step,),
        )
        return PolicyChangePlan(
            operation=operation,
            policy_arn=None,
            name=name,
            path=selected_path,
            document=document,
            description=selected_options.description,
            tags=tags,
            validation=report,
        )

    def plan_publish(
        self,
        reference: str,
        document: dict[str, JsonValue],
        *,
        include_aws_validation: bool = True,
    ) -> PolicyChangePlan:
        """Plan a no-op or safely versioned customer-policy update."""
        current = self.get_policy(
            reference,
            include_document=True,
            include_versions=True,
            include_tags=True,
        )
        self._require_mutable(current)
        report = self.validate_policy(
            document,
            name=current.name,
            path=current.path,
            tags=current.tags,
            include_aws=include_aws_validation,
        )
        if current.document is None:
            message = "Current managed policy document was not loaded."
            raise PolicyServiceError(message)
        current_digest = policy_digest(current.document)
        if current_digest == policy_digest(document):
            operation = _operation_plan(
                ChangeAction.NOOP,
                f"Policy {current.arn.value} is semantically unchanged.",
                (),
            )
            return PolicyChangePlan(
                operation=operation,
                policy_arn=current.arn,
                name=current.name,
                path=current.path,
                document=document,
                description=None,
                tags=current.tags,
                expected_default_version_id=current.default_version_id,
                expected_digest=current_digest,
                validation=report,
            )

        prune_id: str | None = None
        warnings: list[str] = []
        steps: list[OperationStep] = []
        if len(current.versions) >= MAX_POLICY_VERSIONS:
            nondefault = [item for item in current.versions if not item.is_default]
            if not current.owned:
                repair = RepairAction(
                    "select-version-to-prune",
                    "versions",
                    "Select and explicitly delete a nondefault version before "
                    "publishing.",
                )
                report = report.merge(
                    ValidationReport(
                        (
                            ValidationDiagnostic(
                                DiagnosticSeverity.ERROR,
                                "POLICY_VERSION_LIMIT",
                                "Unowned policy has five versions; automatic pruning "
                                "is refused.",
                                "versions",
                                repair,
                            ),
                        )
                    )
                )
            elif nondefault:
                prune = min(
                    nondefault,
                    key=lambda item: (
                        item.created_at or datetime.min.replace(tzinfo=UTC)
                    ),
                )
                prune_id = prune.version_id
                steps.append(
                    _new_step(
                        "DeletePolicyVersion",
                        {
                            "PolicyArn": current.arn.value,
                            "VersionId": prune_id,
                        },
                        destructive=True,
                    )
                )
                warnings.append(
                    f"Oldest nondefault version {prune_id} will be pruned at the "
                    "five-version limit."
                )
            else:
                report = report.merge(
                    ValidationReport(
                        (
                            ValidationDiagnostic(
                                DiagnosticSeverity.ERROR,
                                "NO_PRUNABLE_VERSION",
                                "Policy version limit reached with no nondefault "
                                "version.",
                                "versions",
                            ),
                        )
                    )
                )
        steps.append(
            _new_step(
                "CreatePolicyVersion",
                {
                    "PolicyArn": current.arn.value,
                    "PolicyDocument": canonical_policy_json(document),
                    "SetAsDefault": True,
                },
                compensation=Compensation(
                    "SetDefaultPolicyVersion",
                    {
                        "PolicyArn": current.arn.value,
                        "VersionId": current.default_version_id,
                    },
                ),
            )
        )
        operation = _operation_plan(
            ChangeAction.UPDATE,
            f"Publish a new default version for {current.arn.value}.",
            steps,
            warnings=warnings,
        )
        return PolicyChangePlan(
            operation=operation,
            policy_arn=current.arn,
            name=current.name,
            path=current.path,
            document=document,
            description=None,
            tags=current.tags,
            expected_default_version_id=current.default_version_id,
            expected_digest=current_digest,
            prune_version_id=prune_id,
            validation=report,
        )

    def plan_rollback(
        self,
        reference: str,
        version_id: str,
    ) -> PolicyChangePlan:
        """Plan switching a customer-managed policy to a retained version."""
        current = self.get_policy(
            reference,
            include_document=True,
            include_versions=True,
            include_tags=True,
        )
        self._require_mutable(current)
        target = next(
            (item for item in current.versions if item.version_id == version_id),
            None,
        )
        if target is None:
            message = f"Policy version {version_id!r} does not exist."
            raise PolicyServiceError(message)
        if current.document is None:
            message = "Current managed policy document was not loaded."
            raise PolicyServiceError(message)
        target_document = self._get_version_document(current.arn, version_id)
        action = (
            ChangeAction.NOOP
            if version_id == current.default_version_id
            else ChangeAction.ROLLBACK
        )
        steps: tuple[OperationStep, ...] = ()
        if action is ChangeAction.ROLLBACK:
            steps = (
                _new_step(
                    "SetDefaultPolicyVersion",
                    {"PolicyArn": current.arn.value, "VersionId": version_id},
                    compensation=Compensation(
                        "SetDefaultPolicyVersion",
                        {
                            "PolicyArn": current.arn.value,
                            "VersionId": current.default_version_id,
                        },
                    ),
                ),
            )
        operation = _operation_plan(
            action,
            f"Set {version_id} as default for {current.arn.value}.",
            steps,
        )
        return PolicyChangePlan(
            operation=operation,
            policy_arn=current.arn,
            name=current.name,
            path=current.path,
            document=target_document,
            description=None,
            tags=current.tags,
            expected_default_version_id=current.default_version_id,
            expected_digest=policy_digest(current.document),
            rollback_version_id=version_id,
        )

    def execute_change(self, plan: PolicyChangePlan) -> PublishResult:
        """Execute a validated policy change with drift and journal safeguards."""
        if not plan.validation.valid:
            raise PolicyValidationError(plan.validation)
        journal = OperationJournal(plan.operation.plan_id, [])
        if plan.operation.action is ChangeAction.CREATE:
            return self._execute_create(plan, journal)
        if plan.policy_arn is None:
            message = "Non-create policy plan requires an ARN."
            raise PolicyServiceError(message)
        current = self._assert_change_precondition(plan)
        if plan.operation.action is ChangeAction.NOOP:
            return PublishResult(ChangeAction.NOOP, current, journal)
        if plan.operation.action is ChangeAction.ROLLBACK:
            return self._execute_rollback(plan, current, journal)
        return self._execute_update(plan, current, journal)

    def _execute_create(
        self,
        plan: PolicyChangePlan,
        journal: OperationJournal,
    ) -> PublishResult:
        step = plan.operation.steps[0]
        request: dict[str, object] = {
            "PolicyName": plan.name,
            "Path": plan.path,
            "PolicyDocument": canonical_policy_json(plan.document),
            "Tags": [tag.as_request() for tag in plan.tags],
        }
        if plan.description is not None:
            request["Description"] = plan.description
        try:
            response = self._iam.create_policy(**request)
        except ClientError as error:
            journal.record(step.step_id, StepState.FAILED, str(error))
            raise
        journal.record(step.step_id, StepState.SUCCEEDED)
        created = _metadata_record(response.get("Policy"))
        self._assert_arn_target(created.arn)
        verified = self._verify_policy(
            created.arn,
            expected_version=created.default_version_id,
            expected_digest=policy_digest(plan.document),
        )
        return PublishResult(ChangeAction.CREATE, verified, journal)

    def _assert_change_precondition(
        self,
        plan: PolicyChangePlan,
    ) -> ManagedPolicyRecord:
        if plan.policy_arn is None:
            message = "Policy change precondition requires an ARN."
            raise PolicyServiceError(message)
        current = self._hydrate_policy(
            self._read_policy(plan.policy_arn),
            include_document=True,
            include_versions=True,
            include_tags=True,
        )
        if current.document is None:
            message = "Current managed policy document was not loaded."
            raise PolicyServiceError(message)
        if (
            current.default_version_id != plan.expected_default_version_id
            or policy_digest(current.document) != plan.expected_digest
        ):
            message = (
                f"Policy {current.arn.value} changed after planning; rebuild and "
                "review "
                "the operation plan."
            )
            raise PolicyDriftError(message)
        return current

    def _execute_update(
        self,
        plan: PolicyChangePlan,
        current: ManagedPolicyRecord,
        journal: OperationJournal,
    ) -> PublishResult:
        step_index = 0
        if plan.prune_version_id is not None:
            prune_step = plan.operation.steps[step_index]
            try:
                self._iam.delete_policy_version(
                    PolicyArn=current.arn.value,
                    VersionId=plan.prune_version_id,
                )
            except ClientError as error:
                journal.record(prune_step.step_id, StepState.FAILED, str(error))
                raise
            journal.record(prune_step.step_id, StepState.SUCCEEDED)
            step_index += 1
        publish_step = plan.operation.steps[step_index]
        try:
            response = self._iam.create_policy_version(
                PolicyArn=current.arn.value,
                PolicyDocument=canonical_policy_json(plan.document),
                SetAsDefault=True,
            )
        except ClientError as error:
            journal.record(publish_step.step_id, StepState.FAILED, str(error))
            raise
        version = _mapping(response.get("PolicyVersion"), label="PolicyVersion")
        version_id = _string(version.get("VersionId"), label="VersionId")
        journal.record(publish_step.step_id, StepState.SUCCEEDED, version_id)
        verified = self._verify_policy(
            current.arn,
            expected_version=version_id,
            expected_digest=policy_digest(plan.document),
        )
        return PublishResult(ChangeAction.UPDATE, verified, journal)

    def _execute_rollback(
        self,
        plan: PolicyChangePlan,
        current: ManagedPolicyRecord,
        journal: OperationJournal,
    ) -> PublishResult:
        version_id = plan.rollback_version_id
        if version_id is None:
            message = "Rollback plan does not specify a target version."
            raise PolicyServiceError(message)
        step = plan.operation.steps[0]
        try:
            self._iam.set_default_policy_version(
                PolicyArn=current.arn.value,
                VersionId=version_id,
            )
        except ClientError as error:
            journal.record(step.step_id, StepState.FAILED, str(error))
            raise
        journal.record(step.step_id, StepState.SUCCEEDED)
        verified = self._verify_policy(
            current.arn,
            expected_version=version_id,
            expected_digest=policy_digest(plan.document),
        )
        return PublishResult(ChangeAction.ROLLBACK, verified, journal)

    def _verify_policy(
        self,
        arn: ManagedPolicyArn,
        *,
        expected_version: str,
        expected_digest: str,
    ) -> ManagedPolicyRecord:
        last_detail = "policy was not visible"
        for delay in self.retry.delays:
            if delay:
                self._sleep(delay)
            try:
                current = self._hydrate_policy(
                    self._read_policy(arn),
                    include_document=True,
                    include_versions=False,
                    include_tags=True,
                )
            except ClientError as error:
                code, detail = _client_error_details(error)
                if code != "NoSuchEntity":
                    raise
                last_detail = detail
                continue
            if current.document is None:
                last_detail = "policy document was absent"
                continue
            if (
                current.default_version_id == expected_version
                and policy_digest(current.document) == expected_digest
            ):
                return current
            last_detail = (
                f"observed default {current.default_version_id} with digest "
                f"{policy_digest(current.document)}"
            )
        message = (
            f"IAM accepted the mutation for {arn.value}, but bounded propagation "
            f"verification failed: {last_detail}."
        )
        raise PolicyServiceError(message)

    def export_policy(
        self,
        reference: str,
        *,
        include_all_versions: bool = False,
    ) -> PolicyExport:
        """Return active policy data and optionally every retained version."""
        policy = self.get_policy(
            reference,
            include_document=True,
            include_versions=include_all_versions,
            include_tags=True,
        )
        if policy.document is None:
            message = "Managed policy export has no active document."
            raise PolicyServiceError(message)
        return PolicyExport(
            policy=policy,
            exported_at=datetime.now(UTC),
            active_document=policy.document,
            versions=policy.versions if include_all_versions else (),
        )

    @staticmethod
    def _require_mutable(policy: ManagedPolicyRecord) -> None:
        if policy.arn.kind is PolicyKind.AWS_MANAGED:
            message = f"AWS-managed policy {policy.arn.value} is immutable."
            raise ImmutablePolicyError(message)

    @staticmethod
    def _tag_digest(tags: Sequence[Tag]) -> str:
        value = json.dumps(
            sorted((tag.key, tag.value) for tag in tags),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(value.encode()).hexdigest()

    def plan_adopt(
        self,
        reference: str,
        resource_id: str,
        *,
        user_tags: Sequence[Tag] = (),
        caller: CallerIdentity | None = None,
    ) -> TagChangePlan:
        """Plan adopting an existing customer policy into Hacksaws ownership."""
        policy = self.get_policy(
            reference,
            include_document=False,
            include_versions=False,
            include_tags=True,
        )
        self._require_mutable(policy)
        values = {tag.key.casefold(): tag.value for tag in policy.tags}
        manager = values.get("hacksaws:managed-by")
        if manager is not None and manager != "hacksaws":
            message = f"Policy is already managed by {manager!r}."
            raise PolicyServiceError(message)
        add = self.ownership_tags(
            resource_id,
            user_tags,
            caller=caller,
            ownership_origin="adopted",
        )
        report = ValidationReport(tuple(self._validate_tags(add)))
        if not report.valid:
            raise PolicyValidationError(report)
        step = _new_step(
            "TagPolicy",
            {
                "PolicyArn": policy.arn.value,
                "Tags": [tag.as_request() for tag in add],
            },
            compensation=Compensation(
                "RestorePolicyTags",
                {"Tags": [tag.as_request() for tag in policy.tags]},
            ),
        )
        operation = _operation_plan(
            ChangeAction.ADOPT,
            f"Adopt {policy.arn.value} into Hacksaws ownership.",
            (step,),
        )
        return TagChangePlan(
            policy,
            operation,
            add,
            (),
            self._tag_digest(policy.tags),
        )

    def plan_release(self, reference: str) -> TagChangePlan:
        """Plan removing Hacksaws ownership/audit tags without deleting policy."""
        policy = self.get_policy(
            reference,
            include_document=False,
            include_versions=False,
            include_tags=True,
        )
        self._require_mutable(policy)
        remove = tuple(
            tag.key for tag in policy.tags if tag.key.casefold() in RESERVED_TAGS
        )
        steps: tuple[OperationStep, ...] = ()
        if remove:
            previous = [
                tag.as_request() for tag in policy.tags if tag.key in set(remove)
            ]
            steps = (
                _new_step(
                    "UntagPolicy",
                    {"PolicyArn": policy.arn.value, "TagKeys": list(remove)},
                    compensation=Compensation(
                        "TagPolicy",
                        {"PolicyArn": policy.arn.value, "Tags": previous},
                    ),
                ),
            )
        operation = _operation_plan(
            ChangeAction.RELEASE,
            f"Release {policy.arn.value} from Hacksaws ownership.",
            steps,
        )
        return TagChangePlan(
            policy,
            operation,
            (),
            remove,
            self._tag_digest(policy.tags),
        )

    def execute_tag_change(self, plan: TagChangePlan) -> MutationResult:
        """Execute an adopt/release tag plan after checking tag drift."""
        self._require_mutable(plan.policy)
        current = self.get_policy(
            plan.policy.arn.value,
            include_document=False,
            include_versions=False,
            include_tags=True,
        )
        if self._tag_digest(current.tags) != plan.expected_digest:
            message = (
                f"Policy tags for {current.arn.value} changed after planning; "
                "rebuild the tag plan."
            )
            raise PolicyDriftError(message)
        journal = OperationJournal(plan.operation.plan_id, [])
        if not plan.operation.steps:
            return MutationResult(current, journal)
        step = plan.operation.steps[0]
        try:
            if plan.add:
                self._iam.tag_policy(
                    PolicyArn=current.arn.value,
                    Tags=[tag.as_request() for tag in plan.add],
                )
            if plan.remove:
                self._iam.untag_policy(
                    PolicyArn=current.arn.value,
                    TagKeys=list(plan.remove),
                )
        except ClientError as error:
            journal.record(step.step_id, StepState.FAILED, str(error))
            raise
        journal.record(step.step_id, StepState.SUCCEEDED)
        updated = self.get_policy(
            current.arn.value,
            include_document=False,
            include_versions=False,
            include_tags=True,
        )
        return MutationResult(updated, journal)

    def _list_entities(
        self,
        arn: ManagedPolicyArn,
        usage: str,
    ) -> tuple[
        tuple[EntityReference, ...],
        tuple[EntityReference, ...],
        tuple[EntityReference, ...],
    ]:
        users: dict[str, EntityReference] = {}
        groups: dict[str, EntityReference] = {}
        roles: dict[str, EntityReference] = {}
        marker: str | None = None
        while True:
            request: dict[str, object] = {
                "PolicyArn": arn.value,
                "PolicyUsageFilter": usage,
            }
            if marker is not None:
                request["Marker"] = marker
            response = self._iam.list_entities_for_policy(**request)
            self._collect_entities(
                response.get("PolicyUsers", []),
                "User",
                "UserName",
                "UserId",
                users,
            )
            self._collect_entities(
                response.get("PolicyGroups", []),
                "Group",
                "GroupName",
                "GroupId",
                groups,
            )
            self._collect_entities(
                response.get("PolicyRoles", []),
                "Role",
                "RoleName",
                "RoleId",
                roles,
            )
            if response.get("IsTruncated") is not True:
                break
            marker = _string(response.get("Marker"), label="Marker")
        return tuple(users.values()), tuple(groups.values()), tuple(roles.values())

    @staticmethod
    def _collect_entities(
        raw_items: object,
        kind: str,
        name_key: str,
        id_key: str,
        destination: dict[str, EntityReference],
    ) -> None:
        for raw in _items(raw_items, label=f"Policy{kind}s"):
            item = _mapping(raw, label=kind)
            name = _string(item.get(name_key), label=name_key)
            entity_id = _string(item.get(id_key), label=id_key)
            destination[entity_id] = EntityReference(kind, name, entity_id)

    def policy_dependencies(self, reference: str) -> PolicyDependencies:
        """List every attachment and permissions-boundary dependency."""
        policy = self.get_policy(
            reference,
            include_document=False,
            include_versions=False,
            include_tags=False,
        )
        permission_users, permission_groups, permission_roles = self._list_entities(
            policy.arn,
            "PermissionsPolicy",
        )
        boundary_users, _, boundary_roles = self._list_entities(
            policy.arn,
            "PermissionsBoundary",
        )
        return PolicyDependencies(
            permission_users,
            permission_groups,
            permission_roles,
            boundary_users,
            boundary_roles,
        )

    @staticmethod
    def _cascade_delete_steps(
        arn: str,
        dependencies: PolicyDependencies,
    ) -> list[OperationStep]:
        steps = [
            _new_step(
                "DetachUserPolicy",
                {"UserName": entity.name, "PolicyArn": arn},
                destructive=True,
            )
            for entity in dependencies.permission_users
        ]
        steps.extend(
            _new_step(
                "DetachGroupPolicy",
                {"GroupName": entity.name, "PolicyArn": arn},
                destructive=True,
            )
            for entity in dependencies.permission_groups
        )
        steps.extend(
            _new_step(
                "DetachRolePolicy",
                {"RoleName": entity.name, "PolicyArn": arn},
                destructive=True,
            )
            for entity in dependencies.permission_roles
        )
        steps.extend(
            _new_step(
                "DeleteUserPermissionsBoundary",
                {"UserName": entity.name},
                destructive=True,
            )
            for entity in dependencies.boundary_users
        )
        steps.extend(
            _new_step(
                "DeleteRolePermissionsBoundary",
                {"RoleName": entity.name},
                destructive=True,
            )
            for entity in dependencies.boundary_roles
        )
        return steps

    @staticmethod
    def _version_delete_steps(policy: ManagedPolicyRecord) -> list[OperationStep]:
        return [
            _new_step(
                "DeletePolicyVersion",
                {
                    "PolicyArn": policy.arn.value,
                    "VersionId": version.version_id,
                },
                destructive=True,
            )
            for version in policy.versions
            if version.version_id != policy.default_version_id
        ]

    def plan_delete(
        self,
        reference: str,
        *,
        cascade: bool = False,
    ) -> PolicyDeletionPlan:
        """Plan dependency-complete deletion without performing confirmation."""
        policy = self.get_policy(
            reference,
            include_document=False,
            include_versions=True,
            include_tags=True,
        )
        self._require_mutable(policy)
        dependencies = self.policy_dependencies(policy.arn.value)
        steps: list[OperationStep] = []
        warnings: list[str] = []
        if not policy.owned:
            warnings.append("Policy does not carry complete Hacksaws ownership tags.")
        if cascade:
            steps.extend(self._cascade_delete_steps(policy.arn.value, dependencies))
        elif not dependencies.empty:
            warnings.append("Deletion is blocked until all dependencies are removed.")
        steps.extend(self._version_delete_steps(policy))
        steps.append(
            _new_step(
                "DeletePolicy",
                {"PolicyArn": policy.arn.value},
                destructive=True,
            )
        )
        operation = _operation_plan(
            ChangeAction.DELETE,
            f"Delete customer-managed policy {policy.arn.value}.",
            steps,
            warnings=warnings,
        )
        return PolicyDeletionPlan(policy, dependencies, operation, cascade)

    def execute_delete(self, plan: PolicyDeletionPlan) -> MutationResult:
        """Execute an already-confirmed dependency-complete deletion plan."""
        if not plan.executable:
            message = "Deletion plan has dependencies but cascade was not authorized."
            raise PolicyValidationError(
                ValidationReport(
                    (
                        ValidationDiagnostic(
                            DiagnosticSeverity.ERROR,
                            "POLICY_HAS_DEPENDENCIES",
                            message,
                            "dependencies",
                        ),
                    )
                )
            )
        current = self.get_policy(
            plan.policy.arn.value,
            include_document=False,
            include_versions=True,
            include_tags=True,
        )
        current_dependencies = self.policy_dependencies(current.arn.value)
        if (
            current.policy_id != plan.policy.policy_id
            or current.default_version_id != plan.policy.default_version_id
            or current.versions != plan.policy.versions
            or current_dependencies != plan.dependencies
        ):
            message = "Policy or its dependencies changed after deletion planning."
            raise PolicyDriftError(message)
        journal = OperationJournal(plan.operation.plan_id, [])
        for step in plan.operation.steps:
            try:
                self._execute_delete_step(step)
            except ClientError as error:
                journal.record(step.step_id, StepState.FAILED, str(error))
                raise
            journal.record(step.step_id, StepState.SUCCEEDED)
        return MutationResult(None, journal)

    def _execute_delete_step(self, step: OperationStep) -> None:
        parameters = dict(step.parameters)
        operations: dict[str, Callable[..., object]] = {
            "DetachUserPolicy": self._iam.detach_user_policy,
            "DetachGroupPolicy": self._iam.detach_group_policy,
            "DetachRolePolicy": self._iam.detach_role_policy,
            "DeleteUserPermissionsBoundary": (
                self._iam.delete_user_permissions_boundary
            ),
            "DeleteRolePermissionsBoundary": (
                self._iam.delete_role_permissions_boundary
            ),
            "DeletePolicyVersion": self._iam.delete_policy_version,
            "DeletePolicy": self._iam.delete_policy,
        }
        operation = operations.get(step.operation)
        if operation is None:
            message = f"Unsupported deletion step {step.operation!r}."
            raise PolicyServiceError(message)
        operation(**parameters)

    def probe_assume_role(
        self,
        role_arn: str,
        document: Mapping[str, JsonValue],
        *,
        options: AssumeRoleProbeOptions | None = None,
    ) -> AssumeRoleProbeResult:
        """Probe the selected policy exactly and discard returned credentials."""
        selected_options = options or AssumeRoleProbeOptions()
        role_match = ROLE_ARN_PATTERN.fullmatch(role_arn)
        if role_match is None:
            message = f"Invalid IAM role ARN {role_arn!r}."
            raise PolicyServiceError(message)
        if (
            role_match.group("partition") != self.partition
            or role_match.group("account") != self.account_id
        ):
            message = (
                "AssumeRole probe ARN does not match the target account/partition."
            )
            raise PolicyServiceError(message)
        request: dict[str, object] = {
            "RoleArn": role_arn,
            "RoleSessionName": selected_options.session_name,
            "DurationSeconds": selected_options.duration_seconds,
            "Policy": canonical_policy_json(document),
        }
        if selected_options.external_id is not None:
            request["ExternalId"] = selected_options.external_id
        if selected_options.source_identity is not None:
            request["SourceIdentity"] = selected_options.source_identity
        if selected_options.session_tags:
            request["Tags"] = [
                tag.as_request() for tag in selected_options.session_tags
            ]
        try:
            response = self._sts.assume_role(**request)
        except ClientError as error:
            diagnostic = parse_packed_policy_diagnostic(error)
            if diagnostic is not None:
                raise PackedPolicyProbeError(diagnostic) from error
            raise
        assumed = _mapping(response.get("AssumedRoleUser"), label="AssumedRoleUser")
        credentials = _mapping(response.get("Credentials"), label="Credentials")
        packed_size = (
            _integer(response.get("PackedPolicySize"), default=-1)
            if "PackedPolicySize" in response
            else None
        )
        if packed_size == -1:
            packed_size = None
        return AssumeRoleProbeResult(
            role_arn=role_arn,
            assumed_role_arn=_string(assumed.get("Arn"), label="AssumedRoleUser.Arn"),
            expires_at=_datetime(credentials.get("Expiration")),
            packed_policy_size=packed_size,
            warning=packed_policy_warning(
                packed_size,
                threshold=selected_options.packed_warning_threshold,
            ),
        )
