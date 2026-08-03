"""CLI adapter for safe AWS IAM managed-policy workflows."""

# The parser and dispatch functions intentionally enumerate a broad command grammar.
# ruff: noqa: C901, PLR0911, PLR0912, PLR0915, TRY003

from __future__ import annotations

import argparse
import contextlib
import difflib
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import asdict
from dataclasses import replace
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING
from typing import cast
from urllib.parse import quote

import yaml
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError
from rich.console import Console

from hacksaws import _configs
from hacksaws import _iam_recovery
from hacksaws import _output
from hacksaws import _policies
from hacksaws import _resource_input
from hacksaws import _state
from hacksaws._configs import OperationalError
from hacksaws._iam_managed_policies import RESERVED_TAGS
from hacksaws._iam_managed_policies import AssumeRoleProbeOptions
from hacksaws._iam_managed_policies import ChangeAction
from hacksaws._iam_managed_policies import CreatePolicyOptions
from hacksaws._iam_managed_policies import DiagnosticSeverity
from hacksaws._iam_managed_policies import EntityReference
from hacksaws._iam_managed_policies import IamManagedPolicyService
from hacksaws._iam_managed_policies import ImmutablePolicyError
from hacksaws._iam_managed_policies import ManagedPolicyArn
from hacksaws._iam_managed_policies import ManagedPolicyRecord
from hacksaws._iam_managed_policies import OperationStep
from hacksaws._iam_managed_policies import OwnershipStatus
from hacksaws._iam_managed_policies import PackedPolicyProbeError
from hacksaws._iam_managed_policies import PolicyChangePlan
from hacksaws._iam_managed_policies import PolicyDeletionPlan
from hacksaws._iam_managed_policies import PolicyDependencies
from hacksaws._iam_managed_policies import PolicyDriftError
from hacksaws._iam_managed_policies import PolicyKind
from hacksaws._iam_managed_policies import PolicyScope
from hacksaws._iam_managed_policies import PolicyServiceError
from hacksaws._iam_managed_policies import PolicyServiceOptions
from hacksaws._iam_managed_policies import PolicyValidationError
from hacksaws._iam_managed_policies import PolicyVersionRecord
from hacksaws._iam_managed_policies import Tag
from hacksaws._iam_managed_policies import TagChangePlan
from hacksaws._iam_managed_policies import ValidationReport
from hacksaws._iam_managed_policies import classify_ownership
from hacksaws._iam_managed_policies import ownership_origin
from hacksaws._iam_managed_policies import reconcile_owned_tags
from hacksaws._iam_policy_documents import InputMetadata
from hacksaws._iam_policy_documents import JsonValue
from hacksaws._iam_policy_documents import LoadedPolicyInput
from hacksaws._iam_policy_documents import MetadataMode
from hacksaws._iam_policy_documents import PolicyFormat
from hacksaws._iam_policy_documents import PolicyInputError
from hacksaws._iam_policy_documents import canonical_policy_json
from hacksaws._iam_policy_documents import load_policy_input
from hacksaws._iam_policy_documents import policy_digest

if TYPE_CHECKING:
    from collections.abc import Iterable

    from hacksaws._iam_cli import IamCommandContext

name = "policy"
_FORMAT_CHOICES = tuple(item.value for item in PolicyFormat)
_METADATA_CHOICES = tuple(item.value for item in MetadataMode)
_RESERVED_PREFIX = "hacksaws:"
_MAX_POLICY_VERSIONS = 5


def _console_url(context: IamCommandContext, arn: str) -> str:
    region = getattr(context, "region_name", None) or getattr(
        getattr(context, "session", None), "region_name", None
    )
    region = region or "us-east-1"
    domain = {
        "aws": "console.aws.amazon.com",
        "aws-cn": "console.amazonaws.cn",
        "aws-us-gov": "console.amazonaws-us-gov.com",
    }.get(context.partition)
    if domain is None:
        raise OperationalError(
            f"AWS Console links are not supported for partition {context.partition!r}."
        )
    return (
        f"https://{region}.{domain}/iam/home?region={region}"
        f"#/policies/details/{quote(arn, safe='')}?section=permissions"
    )


def _selectors(parser: argparse.ArgumentParser, *, mutation: bool = False) -> None:
    """Expose credential selectors on the terminal command where users need them."""
    group = parser.add_argument_group("credential selection")
    group.add_argument(
        "--profile",
        default=argparse.SUPPRESS,
        metavar="PROFILE",
        help="AWS profile to use.",
    )
    group.add_argument(
        "--location",
        default=argparse.SUPPRESS,
        metavar="NAME",
        help="Named AWS config directory to use.",
    )
    group.add_argument(
        "-d",
        "--directory",
        default=argparse.SUPPRESS,
        metavar="PATH",
        help="Explicit AWS config directory; conflicts with --location.",
    )
    group.add_argument(
        "--target",
        default=argparse.SUPPRESS,
        metavar="NAME",
        help="Saved target supplying the credential source.",
    )
    group.add_argument(
        "--account",
        default=argparse.SUPPRESS,
        metavar="NAME_OR_ID",
        help="Assert the selected AWS account.",
    )
    group.add_argument(
        "--region",
        default=argparse.SUPPRESS,
        metavar="REGION",
        help="Region used for AWS clients and console links.",
    )
    group.add_argument(
        "--allow-unknown-region",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Allow only an exact unknown canonical region; aliases stay strict.",
    )
    if mutation:
        safety = parser.add_argument_group("safety")
        safety.add_argument(
            "--dry-run",
            action="store_true",
            default=argparse.SUPPRESS,
            help=(
                "Show credential-free identity, before/after, actions, dependencies, "
                "warnings, and confirmation without changing AWS or local state."
            ),
        )
        safety.add_argument(
            "--yes",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Approve the exact displayed plan without prompting.",
        )


def _input_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=_FORMAT_CHOICES,
        help="Explicit input document format when it cannot be inferred.",
    )
    parser.add_argument(
        "--metadata",
        choices=_METADATA_CHOICES,
        help="Input metadata layout: embedded, separate sidecar, or omitted.",
    )
    parser.add_argument(
        "--metadata-file", type=Path, help="Metadata sidecar file for the policy input."
    )
    parser.add_argument(
        "--local-validation-only",
        action="store_true",
        help="Skip IAM Access Analyzer validation.",
    )


def _tag_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--tag",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Add an IAM tag; repeat for multiple tags.",
    )


def register(parser: argparse.ArgumentParser) -> None:
    """Register the complete managed-policy command grammar."""
    actions = parser.add_subparsers(dest="policy_action")

    create = actions.add_parser(
        "create",
        aliases=["publish"],
        help="Create a customer-managed policy without silently overwriting one.",
        description=(
            "Validate and publish a local policy document. If NAME is omitted, a "
            "name is derived from the filename and naming configuration."
        ),
        epilog=(
            "Examples:\n"
            "  hacksaws iam policy create agent-read.yaml --profile admin\n"
            "  hacksaws iam policy create agent-read.yaml AgentRead "
            "--tag project=api --dry-run\n"
            "  hacksaws iam policy create agent-read.yaml AgentRead --replace --yes"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    create.set_defaults(policy_action="create")
    create.add_argument(
        "policy_inputs",
        nargs="*",
        metavar="NAME_OR_FILE",
        help="Policy NAME and FILE in either order; NAME may be omitted.",
    )
    create.add_argument(
        "--name",
        dest="explicit_name",
        help="Explicit IAM policy name; otherwise derive it from FILE.",
    )
    create.add_argument(
        "--file",
        dest="explicit_file",
        help="Explicit JSON, YAML, or TOML policy document, or '-' for stdin.",
    )
    create.add_argument("--description", help="Human-readable IAM policy description.")
    create.add_argument(
        "--path",
        dest="iam_path",
        help="IAM path prefix (default from Hacksaws configuration).",
    )
    create.add_argument(
        "--replace",
        action="store_true",
        help="Deliberately update an existing differing policy after preview.",
    )
    _input_options(create)
    _tag_options(create)
    _selectors(create, mutation=True)

    listing = actions.add_parser("list", help="List managed policies.")
    listing.add_argument("patterns", nargs="*")
    scope = listing.add_mutually_exclusive_group()
    scope.add_argument("--custom", action="store_true")
    scope.add_argument("--aws", action="store_true")
    scope.add_argument("--all", action="store_true")
    width = listing.add_mutually_exclusive_group()
    width.add_argument("--compact", action="store_true")
    width.add_argument("--wide", action="store_true")
    _selectors(listing)

    get = actions.add_parser("get", help="Show a managed policy.")
    get.add_argument("policy")
    _selectors(get)

    export = actions.add_parser("export", help="Export a policy document.")
    export.add_argument("policy")
    export.add_argument("output", nargs="?")
    export.add_argument("--format", choices=_FORMAT_CHOICES)
    export.add_argument("--metadata", choices=_METADATA_CHOICES, default="none")
    export.add_argument("--metadata-file", type=Path)
    export.add_argument("--all-versions", action="store_true")
    _selectors(export)

    update = actions.add_parser("update", help="Publish a new policy version.")
    update.add_argument(
        "policy_inputs",
        nargs="*",
        metavar="POLICY_OR_FILE",
        help="Policy reference and FILE in either order, or metadata-bearing FILE.",
    )
    update.add_argument(
        "--policy",
        dest="explicit_policy",
        help="Explicit policy name or ARN; use with --file to resolve ambiguity.",
    )
    update.add_argument(
        "--file",
        dest="explicit_file",
        help="Explicit JSON/YAML/TOML policy document, or '-' for stdin.",
    )
    update.add_argument(
        "--from-stored",
        metavar="NAME",
        help="Publish the named policy from Hacksaws' local policy store.",
    )
    _input_options(update)
    _selectors(update, mutation=True)

    edit = actions.add_parser("edit", help="Edit and publish a policy.")
    edit.add_argument("policy")
    edit.add_argument("--format", choices=_FORMAT_CHOICES, default="yaml")
    edit.add_argument("--local-validation-only", action="store_true")
    _selectors(edit, mutation=True)

    versions = actions.add_parser("versions", help="List retained versions.")
    versions.add_argument("policy")
    _selectors(versions)

    rollback = actions.add_parser("rollback", help="Select a retained version.")
    rollback.add_argument("policy")
    rollback.add_argument("version")
    _selectors(rollback, mutation=True)

    delete = actions.add_parser(
        "delete", aliases=["remove"], help="Delete a customer-managed policy."
    )
    delete.set_defaults(policy_action="delete")
    delete.add_argument("policy")
    delete.add_argument("--cascade", action="store_true")
    delete.add_argument(
        "--remove-boundaries",
        action="store_true",
        help="Explicitly remove user/role permissions-boundary assignments.",
    )
    delete.add_argument("--allow-unmanaged", action="store_true")
    _selectors(delete, mutation=True)

    check = actions.add_parser("check", help="Validate a policy and optional role.")
    check.add_argument("policy")
    check.add_argument("--role")
    check.add_argument("--local-validation-only", action="store_true")
    _selectors(check)

    tag = actions.add_parser("tag", help="Manage customer-policy tags.")
    tag_actions = tag.add_subparsers(dest="policy_tag_action")
    tag_list = tag_actions.add_parser("list")
    tag_list.add_argument("policy")
    _selectors(tag_list)
    tag_set = tag_actions.add_parser("set")
    tag_set.add_argument("policy")
    _tag_options(tag_set)
    _selectors(tag_set, mutation=True)
    tag_remove = tag_actions.add_parser("remove")
    tag_remove.add_argument("policy")
    tag_remove.add_argument("keys", nargs="+")
    _selectors(tag_remove, mutation=True)

    adopt = actions.add_parser("adopt", help="Adopt a customer-managed policy.")
    adopt.add_argument("policy", help="Existing customer-managed policy name or ARN.")
    _tag_options(adopt)
    _selectors(adopt, mutation=True)
    release = actions.add_parser("release", help="Release Hacksaws ownership tags.")
    release.add_argument("policy", help="Managed policy name or ARN to release.")
    _selectors(release, mutation=True)


def normalize_arguments(args: argparse.Namespace) -> None:
    """Resolve policy mutation inputs before creating any AWS client."""
    action = getattr(args, "policy_action", None)
    if action == "create" and hasattr(args, "policy_inputs"):
        resolved = _resource_input.resolve_name_file(
            args.policy_inputs,
            explicit_name=getattr(args, "explicit_name", None),
            explicit_file=getattr(args, "explicit_file", None),
            require_name=False,
        )
        args.name = resolved.name
        args.file = str(resolved.file) if resolved.file is not None else None
        return
    if action != "update" or not hasattr(args, "policy_inputs"):
        return
    values = list(args.policy_inputs)
    explicit_policy = getattr(args, "explicit_policy", None)
    explicit_file = getattr(args, "explicit_file", None)
    if getattr(args, "from_stored", None):
        if explicit_file is not None:
            raise OperationalError("--from-stored cannot be combined with --file.")
        if len(values) + int(explicit_policy is not None) > 1:
            raise OperationalError(
                "--from-stored accepts at most one policy reference; use --policy "
                "to make it explicit."
            )
        args.policy_or_file = explicit_policy or (values[0] if values else None)
        args.file = None
        return
    resolved = _resource_input.resolve_name_file(
        values,
        explicit_name=explicit_policy,
        explicit_file=explicit_file,
        require_name=False,
        name_label="POLICY",
        name_option="--policy",
    )
    args.policy_or_file = resolved.name
    args.file = str(resolved.file) if resolved.file is not None else None


def _service(context: IamCommandContext) -> IamManagedPolicyService:
    config = _state.load_config()
    owned_path = str(config.get("iam", {}).get("path", "/hacksaws/"))
    return IamManagedPolicyService(
        context.iam,
        context.sts,
        context.access_analyzer,
        PolicyServiceOptions(
            account_id=context.account_id,
            partition=context.partition,
            owned_path=owned_path,
        ),
    )


def _aws_error_code(error: ClientError) -> str:
    detail = error.response.get("Error", {})
    return str(detail.get("Code", "")) if isinstance(detail, dict) else ""


def _policy_exists(context: IamCommandContext, arn: str) -> bool:
    try:
        context.iam.get_policy(PolicyArn=arn)
    except ClientError as error:
        if _aws_error_code(error) == "NoSuchEntity":
            return False
        raise
    return True


def _version_payload(item: PolicyVersionRecord) -> dict[str, object]:
    document = item.document
    if document is None:
        raise PolicyServiceError(
            "A durable policy snapshot requires every version document."
        )
    return {
        "id": item.version_id,
        "default": item.is_default,
        "document": document,
    }


def _entity_payload(item: object) -> dict[str, str]:
    entity = cast("EntityReference", item)
    return {"type": entity.kind, "name": entity.name, "id": entity.entity_id}


def _dependency_payload(
    dependencies: PolicyDependencies,
) -> dict[str, list[dict[str, str]]]:
    return {
        "permissionUsers": [
            _entity_payload(item) for item in dependencies.permission_users
        ],
        "permissionGroups": [
            _entity_payload(item) for item in dependencies.permission_groups
        ],
        "permissionRoles": [
            _entity_payload(item) for item in dependencies.permission_roles
        ],
        "boundaryUsers": [
            _entity_payload(item) for item in dependencies.boundary_users
        ],
        "boundaryRoles": [
            _entity_payload(item) for item in dependencies.boundary_roles
        ],
    }


def _policy_state(
    item: ManagedPolicyRecord,
    *,
    dependencies: PolicyDependencies | None = None,
    create_only: bool = False,
) -> dict[str, object]:
    versions = [_version_payload(version) for version in item.versions]
    if not versions and item.document is not None:
        versions = [
            {
                "id": item.default_version_id,
                "default": True,
                "document": item.document,
            }
        ]
    state: dict[str, object] = {
        "exists": True,
        "arn": item.arn.value,
        "policyId": item.policy_id,
        "name": item.name,
        "path": item.path,
        "description": item.description,
        "defaultVersionId": item.default_version_id,
        "tags": [tag.as_request() for tag in item.tags],
        "versions": versions,
        "createOnly": create_only,
    }
    if dependencies is not None:
        state["dependencies"] = _dependency_payload(dependencies)
    return state


def _absent_state(arn: str, name_value: str, path: str) -> dict[str, object]:
    return {"exists": False, "arn": arn, "name": name_value, "path": path}


def _state_versions(state: Mapping[str, object]) -> list[dict[str, object]]:
    value = state.get("versions", [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise OperationalError("IAM recovery policy versions are invalid.")
    return cast("list[dict[str, object]]", value)


def _state_tags(state: Mapping[str, object]) -> list[dict[str, str]]:
    value = state.get("tags", [])
    if not isinstance(value, list):
        raise OperationalError("IAM recovery policy tags are invalid.")
    result: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("Key"), str):
            raise OperationalError("IAM recovery policy tags are invalid.")
        result.append({"Key": item["Key"], "Value": str(item.get("Value", ""))})
    return result


_DEPENDENCY_TYPES = {
    "permissionUsers": "User",
    "permissionGroups": "Group",
    "permissionRoles": "Role",
    "boundaryUsers": "User",
    "boundaryRoles": "Role",
}


def _state_dependencies(
    state: Mapping[str, object],
) -> dict[str, list[dict[str, str]]]:
    raw = state.get("dependencies", {})
    if not isinstance(raw, dict):
        raise OperationalError("IAM recovery policy dependencies are invalid.")
    result: dict[str, list[dict[str, str]]] = {}
    for key, expected_type in _DEPENDENCY_TYPES.items():
        values = raw.get(key, [])
        if not isinstance(values, list):
            raise OperationalError("IAM recovery policy dependencies are invalid.")
        parsed: list[dict[str, str]] = []
        for value in values:
            if not isinstance(value, dict):
                raise OperationalError(
                    "IAM recovery dependencies must retain principal identity IDs."
                )
            kind = value.get("type")
            name_value = value.get("name")
            entity_id = value.get("id")
            if (
                kind != expected_type
                or not isinstance(name_value, str)
                or not name_value
                or not isinstance(entity_id, str)
                or not entity_id
            ):
                raise OperationalError("IAM recovery policy dependencies are invalid.")
            parsed.append({"type": kind, "name": name_value, "id": entity_id})
        result[key] = parsed
    return result


def _normalized_dependencies(
    state: Mapping[str, object],
) -> dict[str, list[tuple[str, str, str]]]:
    return {
        key: sorted((item["type"], item["name"], item["id"]) for item in values)
        for key, values in _state_dependencies(state).items()
    }


def _versions_match(live: Mapping[str, object], expected: Mapping[str, object]) -> bool:
    observed = _state_versions(live)
    wanted = _state_versions(expected)
    if len(observed) != len(wanted):
        return False
    unused = list(observed)
    for item in wanted:
        identifier = item.get("id")
        document = item.get("document")
        default = item.get("default") is True
        if not isinstance(identifier, str) or not isinstance(document, dict):
            raise OperationalError("IAM recovery policy versions are invalid.")
        match = next(
            (
                candidate
                for candidate in unused
                if isinstance(candidate.get("document"), dict)
                and candidate.get("default") is default
                and policy_digest(
                    cast("Mapping[str, JsonValue]", candidate["document"])
                )
                == policy_digest(cast("Mapping[str, JsonValue]", document))
                and (
                    identifier.startswith("pending")
                    or candidate.get("id") == identifier
                )
            ),
            None,
        )
        if match is None:
            return False
        unused.remove(match)
    return True


def _version_matches(
    observed: Mapping[str, object], expected: Mapping[str, object]
) -> bool:
    observed_document = observed.get("document")
    expected_document = expected.get("document")
    identifier = expected.get("id")
    return (
        isinstance(observed_document, dict)
        and isinstance(expected_document, dict)
        and isinstance(identifier, str)
        and observed.get("default") is expected.get("default")
        and policy_digest(cast("Mapping[str, JsonValue]", observed_document))
        == policy_digest(cast("Mapping[str, JsonValue]", expected_document))
        and (identifier.startswith("pending") or observed.get("id") == identifier)
    )


def _versions_subset(live: Mapping[str, object], allowed: Mapping[str, object]) -> bool:
    remaining = list(_state_versions(allowed))
    for observed in _state_versions(live):
        match = next(
            (item for item in remaining if _version_matches(observed, item)), None
        )
        if match is None:
            return False
        remaining.remove(match)
    return True


def _dependency_sets(
    state: Mapping[str, object],
) -> dict[str, set[tuple[str, str, str]]]:
    return {key: set(values) for key, values in _normalized_dependencies(state).items()}


def _dependencies_subset(
    live: Mapping[str, object], allowed: Mapping[str, object]
) -> bool:
    observed = _dependency_sets(live)
    wanted = _dependency_sets(allowed)
    return all(observed[key] <= wanted[key] for key in _DEPENDENCY_TYPES)


def _identity_matches(
    live: Mapping[str, object], expected: Mapping[str, object]
) -> bool:
    if live.get("exists") is not True or expected.get("exists") is not True:
        return False
    for key in ("arn", "name", "path", "description"):
        if live.get(key) != expected.get(key):
            return False
    policy_id = expected.get("policyId")
    return not (
        isinstance(policy_id, str)
        and not policy_id.startswith("pending")
        and live.get("policyId") != policy_id
    )


def _tags_match(live: Mapping[str, object], expected: Mapping[str, object]) -> bool:
    return sorted((item["Key"], item["Value"]) for item in _state_tags(live)) == sorted(
        (item["Key"], item["Value"]) for item in _state_tags(expected)
    )


def _valid_delete_checkpoint(
    live: Mapping[str, object], expected: Mapping[str, object]
) -> bool:
    return any(_states_match(live, state) for state in _delete_stages(expected))


def _valid_restore_checkpoint(
    live: Mapping[str, object], target: Mapping[str, object]
) -> bool:
    return any(_states_match(live, state) for state in _restore_stages(target))


def _valid_existing_checkpoint(
    live: Mapping[str, object],
    expected: Mapping[str, object],
    target: Mapping[str, object],
) -> bool:
    return any(
        _states_match(live, state) for state in _existing_stages(expected, target)
    )


def _valid_transition_checkpoint(
    live: Mapping[str, object],
    expected: Mapping[str, object],
    target: Mapping[str, object],
) -> bool:
    expected_exists = expected.get("exists") is True
    target_exists = target.get("exists") is True
    if expected_exists and not target_exists:
        return _valid_delete_checkpoint(live, expected)
    if not expected_exists and target_exists:
        return _valid_restore_checkpoint(live, target)
    if expected_exists and target_exists:
        return _valid_existing_checkpoint(live, expected, target)
    return False


def _states_match(live: Mapping[str, object], expected: Mapping[str, object]) -> bool:
    if live.get("arn") != expected.get("arn"):
        return False
    live_exists = live.get("exists") is True
    expected_exists = expected.get("exists") is True
    if live_exists != expected_exists:
        return False
    if not expected_exists:
        return True
    if not _identity_matches(live, expected) or not _tags_match(live, expected):
        return False
    return _versions_match(live, expected) and _normalized_dependencies(
        live
    ) == _normalized_dependencies(expected)


def _clone_state(state: Mapping[str, object]) -> dict[str, object]:
    return cast("dict[str, object]", json.loads(json.dumps(state)))


def _document_digest(version: Mapping[str, object]) -> str:
    document = version.get("document")
    if not isinstance(document, dict):
        raise OperationalError("IAM recovery policy versions are invalid.")
    return policy_digest(cast("Mapping[str, JsonValue]", document))


def _delete_stages(expected: Mapping[str, object]) -> list[dict[str, object]]:
    current = _clone_state(expected)
    stages: list[dict[str, object]] = []
    dependencies = _state_dependencies(current)
    for kind in _DEPENDENCY_TYPES:
        while dependencies[kind]:
            dependencies[kind].pop(0)
            current["dependencies"] = {
                key: [dict(item) for item in values]
                for key, values in dependencies.items()
            }
            stages.append(_clone_state(current))
    for version in list(_state_versions(current)):
        if version.get("default") is True:
            continue
        current["versions"] = [
            item
            for item in _state_versions(current)
            if item.get("id") != version.get("id")
        ]
        stages.append(_clone_state(current))
    return stages


def _restore_stages(target: Mapping[str, object]) -> list[dict[str, object]]:
    desired_versions = _state_versions(target)
    default = next(
        (item for item in desired_versions if item.get("default") is True), None
    )
    if default is None:
        return []
    current = _clone_state(target)
    current["versions"] = [dict(default)]
    current["dependencies"] = _dependency_payload(PolicyDependencies())
    stages = [_clone_state(current)]
    for version in desired_versions:
        if version.get("default") is True:
            continue
        current["versions"] = [*_state_versions(current), dict(version)]
        stages.append(_clone_state(current))
    desired_dependencies = _state_dependencies(target)
    current_dependencies = _state_dependencies(current)
    for kind in _DEPENDENCY_TYPES:
        for item in desired_dependencies[kind]:
            current_dependencies[kind].append(dict(item))
            current["dependencies"] = {
                key: [dict(value) for value in values]
                for key, values in current_dependencies.items()
            }
            stages.append(_clone_state(current))
    return stages


def _prune_stage_version(
    versions: list[dict[str, object]], desired_digests: set[str]
) -> dict[str, object] | None:
    candidate = next(
        (
            version
            for version in versions
            if version.get("default") is not True
            and _document_digest(version) not in desired_digests
        ),
        None,
    )
    return candidate or next(
        (version for version in versions if version.get("default") is not True), None
    )


def _existing_stages(
    expected: Mapping[str, object], target: Mapping[str, object]
) -> list[dict[str, object]]:
    current = _clone_state(expected)
    stages: list[dict[str, object]] = []
    desired_versions = _state_versions(target)
    desired_digests = {_document_digest(item) for item in desired_versions}
    default = next(
        (item for item in desired_versions if item.get("default") is True), None
    )
    if default is None:
        return stages
    default_digest = _document_digest(default)
    versions = _state_versions(current)
    selected = next(
        (item for item in versions if _document_digest(item) == default_digest), None
    )
    if selected is None:
        if len(versions) >= _MAX_POLICY_VERSIONS:
            candidate = _prune_stage_version(versions, desired_digests)
            if candidate is None:
                return stages
            versions = [item for item in versions if item is not candidate]
            current["versions"] = versions
            stages.append(_clone_state(current))
        for item in versions:
            item["default"] = False
        selected = dict(default)
        selected["id"] = str(default.get("id", "pending:default"))
        selected["default"] = True
        versions.append(selected)
        current["versions"] = versions
        stages.append(_clone_state(current))
    elif selected.get("default") is not True:
        for item in versions:
            item["default"] = item is selected
        stages.append(_clone_state(current))
    existing_digests = {_document_digest(item) for item in versions}
    for desired in desired_versions:
        digest = _document_digest(desired)
        if digest in existing_digests:
            continue
        if len(versions) >= _MAX_POLICY_VERSIONS:
            candidate = _prune_stage_version(versions, desired_digests)
            if candidate is None:
                return stages
            versions = [item for item in versions if item is not candidate]
            current["versions"] = versions
            stages.append(_clone_state(current))
        addition = dict(desired)
        addition["default"] = False
        versions.append(addition)
        current["versions"] = versions
        existing_digests.add(digest)
        stages.append(_clone_state(current))
    for version in list(versions):
        if version.get("default") is True:
            continue
        if _document_digest(version) not in desired_digests:
            versions = [item for item in versions if item is not version]
            current["versions"] = versions
            stages.append(_clone_state(current))
    observed_tags = {item["Key"]: item["Value"] for item in _state_tags(current)}
    wanted_tags = {item["Key"]: item["Value"] for item in _state_tags(target)}
    additions = {
        key: value
        for key, value in wanted_tags.items()
        if observed_tags.get(key) != value
    }
    if additions:
        observed_tags.update(additions)
        current["tags"] = [
            {"Key": key, "Value": value} for key, value in sorted(observed_tags.items())
        ]
        stages.append(_clone_state(current))
    removals = [key for key in observed_tags if key not in wanted_tags]
    if removals:
        for key in removals:
            observed_tags.pop(key)
        current["tags"] = [
            {"Key": key, "Value": value} for key, value in sorted(observed_tags.items())
        ]
        stages.append(_clone_state(current))
    return stages


def _transition_stages(
    expected: Mapping[str, object], target: Mapping[str, object]
) -> list[dict[str, object]]:
    expected_exists = expected.get("exists") is True
    target_exists = target.get("exists") is True
    if expected_exists and not target_exists:
        return _delete_stages(expected)
    if not expected_exists and target_exists:
        return _restore_stages(target)
    if expected_exists and target_exists:
        return _existing_stages(expected, target)
    return []


def _live_policy_state(
    context: IamCommandContext, service: IamManagedPolicyService, arn: str
) -> dict[str, object]:
    if not _policy_exists(context, arn):
        parsed = ManagedPolicyArn.parse(arn)
        return _absent_state(arn, parsed.name, parsed.path)
    item = service.get_policy(
        arn, include_document=True, include_versions=True, include_tags=True
    )
    return _policy_state(item, dependencies=service.policy_dependencies(arn))


def _delete_live_policy(
    context: IamCommandContext,
    service: IamManagedPolicyService,
    arn: str,
    expected: Mapping[str, object],
    checkpoints: Sequence[Mapping[str, object]] = (),
) -> None:
    if not _policy_exists(context, arn):
        return
    live = _live_policy_state(context, service, arn)
    if not _states_match(live, expected) and not any(
        _states_match(live, checkpoint) for checkpoint in checkpoints
    ):
        raise PolicyDriftError(
            "Managed policy identity, versions, tags, or dependencies changed "
            "before deletion; no destructive recovery action was taken."
        )
    dependencies = _state_dependencies(expected)
    present = _dependency_sets(live)
    calls = {
        "permissionUsers": lambda item: context.iam.detach_user_policy(
            UserName=item["name"], PolicyArn=arn
        ),
        "permissionGroups": lambda item: context.iam.detach_group_policy(
            GroupName=item["name"], PolicyArn=arn
        ),
        "permissionRoles": lambda item: context.iam.detach_role_policy(
            RoleName=item["name"], PolicyArn=arn
        ),
        "boundaryUsers": lambda item: context.iam.delete_user_permissions_boundary(
            UserName=item["name"]
        ),
        "boundaryRoles": lambda item: context.iam.delete_role_permissions_boundary(
            RoleName=item["name"]
        ),
    }
    for kind, callback in calls.items():
        for item in dependencies[kind]:
            identity = (item["type"], item["name"], item["id"])
            if identity in present[kind]:
                callback(item)
    present_versions = {item.get("id") for item in _state_versions(live)}
    for version in _state_versions(expected):
        if version.get("default") is not True and version.get("id") in present_versions:
            context.iam.delete_policy_version(
                PolicyArn=arn, VersionId=str(version["id"])
            )
    context.iam.delete_policy(PolicyArn=arn)


def _ensure_version_capacity(
    context: IamCommandContext,
    current: ManagedPolicyRecord,
    desired_digests: set[str],
) -> None:
    if len(current.versions) < _MAX_POLICY_VERSIONS:
        return
    candidate = next(
        (
            version
            for version in current.versions
            if not version.is_default
            and version.document is not None
            and policy_digest(version.document) not in desired_digests
        ),
        None,
    )
    if candidate is None:
        candidate = next(
            (version for version in current.versions if not version.is_default), None
        )
    if candidate is None:
        raise OperationalError("No nondefault managed-policy version can be pruned.")
    context.iam.delete_policy_version(
        PolicyArn=current.arn.value, VersionId=candidate.version_id
    )


def _restore_dependencies(
    context: IamCommandContext,
    service: IamManagedPolicyService,
    arn: str,
    raw: object,
) -> None:
    if not isinstance(raw, dict):
        return
    desired = _state_dependencies({"dependencies": raw})
    current = service.policy_dependencies(arn)
    present = {
        "permissionUsers": {
            (item.name, item.entity_id) for item in current.permission_users
        },
        "permissionGroups": {
            (item.name, item.entity_id) for item in current.permission_groups
        },
        "permissionRoles": {
            (item.name, item.entity_id) for item in current.permission_roles
        },
        "boundaryUsers": {
            (item.name, item.entity_id) for item in current.boundary_users
        },
        "boundaryRoles": {
            (item.name, item.entity_id) for item in current.boundary_roles
        },
    }
    calls = {
        "permissionUsers": lambda value: context.iam.attach_user_policy(
            UserName=value, PolicyArn=arn
        ),
        "permissionGroups": lambda value: context.iam.attach_group_policy(
            GroupName=value, PolicyArn=arn
        ),
        "permissionRoles": lambda value: context.iam.attach_role_policy(
            RoleName=value, PolicyArn=arn
        ),
        "boundaryUsers": lambda value: context.iam.put_user_permissions_boundary(
            UserName=value, PermissionsBoundary=arn
        ),
        "boundaryRoles": lambda value: context.iam.put_role_permissions_boundary(
            RoleName=value, PermissionsBoundary=arn
        ),
    }
    for kind, callback in calls.items():
        for value in desired[kind]:
            identity = (value["name"], value["id"])
            if identity in present[kind]:
                continue
            _verify_principal_identity(
                context, value["type"], value["name"], value["id"]
            )
            callback(value["name"])


def _verify_principal_identity(
    context: IamCommandContext,
    kind: str,
    name_value: str,
    expected_id: str,
) -> None:
    requests = {
        "User": (context.iam.get_user, "UserName", "User", "UserId"),
        "Group": (context.iam.get_group, "GroupName", "Group", "GroupId"),
        "Role": (context.iam.get_role, "RoleName", "Role", "RoleId"),
    }
    request, name_key, response_key, id_key = requests[kind]
    try:
        response = request(**{name_key: name_value})
    except ClientError as error:
        if _aws_error_code(error) == "NoSuchEntity":
            raise PolicyDriftError(
                f"Cannot restore dependency for missing {kind.lower()} "
                f"{name_value!r}; manual recovery is required."
            ) from error
        raise
    entity = response.get(response_key, {})
    observed_id = entity.get(id_key) if isinstance(entity, dict) else None
    if observed_id != expected_id:
        raise PolicyDriftError(
            f"Cannot restore dependency for {kind.lower()} {name_value!r}: "
            "the same name now identifies a different IAM principal; manual "
            "recovery is required."
        )


def _effect_policy_id(payload: Mapping[str, object]) -> str | None:
    effect = payload.get("effect")
    if effect is None:
        return None
    if not isinstance(effect, dict) or not isinstance(effect.get("policyId"), str):
        raise OperationalError("IAM recovery policy identity receipt is invalid.")
    return cast("str", effect["policyId"])


def _payload_checkpoints(
    payload: Mapping[str, object], policy_id: str | None
) -> list[dict[str, object]]:
    raw = payload.get("checkpoints", [])
    if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
        raise OperationalError("IAM recovery policy checkpoints are invalid.")
    return [_bind_policy_id(cast("dict[str, object]", item), policy_id) for item in raw]


def _bind_policy_id(
    state: Mapping[str, object], policy_id: str | None
) -> dict[str, object]:
    result = dict(state)
    if (
        policy_id is not None
        and result.get("exists") is True
        and isinstance(result.get("policyId"), str)
        and str(result["policyId"]).startswith("pending")
    ):
        result["policyId"] = policy_id
    return result


def _created_base_state(target: Mapping[str, object]) -> dict[str, object]:
    versions = _state_versions(target)
    default = next((item for item in versions if item.get("default") is True), None)
    if default is None:
        raise OperationalError("IAM recovery create state has no default document.")
    base = dict(target)
    base["policyId"] = "pending:create-receipt"
    base["defaultVersionId"] = "pending:create-default"
    base["versions"] = [{**default, "id": "pending:create-default", "default": True}]
    base["dependencies"] = _dependency_payload(PolicyDependencies())
    return base


def _create_policy_with_receipt(
    payload: Mapping[str, object], raw_context: object
) -> Mapping[str, object] | None:
    context = cast("IamCommandContext", raw_context)
    target = payload.get("target")
    if not isinstance(target, dict):
        raise OperationalError("IAM recovery create payload is invalid.")
    arn = str(target.get("arn", ""))
    parsed = ManagedPolicyArn.parse(arn)
    if parsed.partition != context.partition or parsed.account_id != context.account_id:
        raise OperationalError(
            "Recovery policy ARN does not match selected credentials."
        )
    if _policy_exists(context, arn):
        raise PolicyDriftError(
            "A policy exists at the create target but this journal has no durable "
            "AWS PolicyId receipt proving it created that policy; preserve it and "
            "recover manually."
        )
    versions = _state_versions(target)
    default = next((item for item in versions if item.get("default") is True), None)
    if default is None or not isinstance(default.get("document"), dict):
        raise OperationalError("IAM recovery create state has no default document.")
    request: dict[str, object] = {
        "PolicyName": str(target["name"]),
        "Path": str(target["path"]),
        "PolicyDocument": canonical_policy_json(
            cast("Mapping[str, JsonValue]", default["document"])
        ),
        "Tags": _state_tags(target),
    }
    if target.get("description") is not None:
        request["Description"] = str(target["description"])
    response = context.iam.create_policy(**request)
    policy = response.get("Policy", {})
    policy_id = policy.get("PolicyId") if isinstance(policy, dict) else None
    if not isinstance(policy_id, str) or not policy_id:
        raise OperationalError(
            "AWS created the policy without returning a PolicyId; the journal "
            "cannot bind destructive compensation and requires manual recovery."
        )
    return {"policyId": policy_id}


def _delete_created_policy_with_receipt(
    payload: Mapping[str, object], raw_context: object
) -> None:
    context = cast("IamCommandContext", raw_context)
    expected = payload.get("expected")
    target = payload.get("target")
    policy_id = _effect_policy_id(payload)
    if (
        not isinstance(expected, dict)
        or not isinstance(target, dict)
        or policy_id is None
    ):
        raise OperationalError(
            "Create rollback has no durable AWS PolicyId receipt; preserve any "
            "policy at the target ARN and recover manually."
        )
    expected = _bind_policy_id(expected, policy_id)
    arn = str(expected.get("arn", ""))
    service = _service(context)
    if not _policy_exists(context, arn):
        return
    _delete_live_policy(context, service, arn, expected)


def _reconcile_policy(payload: Mapping[str, object], raw_context: object) -> None:
    context = cast("IamCommandContext", raw_context)
    raw_expected = payload.get("expected")
    raw_target = payload.get("target")
    if not isinstance(raw_expected, dict) or not isinstance(raw_target, dict):
        raise OperationalError(
            "IAM recovery reconciliation requires exact expected and target states."
        )
    policy_id = _effect_policy_id(payload)
    expected = _bind_policy_id(raw_expected, policy_id)
    target = _bind_policy_id(raw_target, policy_id)
    checkpoints = _payload_checkpoints(payload, policy_id)
    arn = str(target.get("arn", ""))
    if expected.get("arn") != arn:
        raise OperationalError("IAM recovery state ARNs do not match.")
    parsed = ManagedPolicyArn.parse(arn)
    if parsed.partition != context.partition or parsed.account_id != context.account_id:
        raise OperationalError(
            "Recovery policy ARN does not match selected credentials."
        )
    service = _service(context)
    live = _live_policy_state(context, service, arn)
    if _states_match(live, target):
        return
    if not _states_match(live, expected) and not any(
        _states_match(live, checkpoint) for checkpoint in checkpoints
    ):
        raise PolicyDriftError(
            "Managed policy recovery found state that is neither the exact "
            "expected predecessor, an exact recovery checkpoint, nor the exact "
            "intended result; no mutation was attempted."
        )
    if (
        expected.get("exists") is not True
        and target.get("exists") is True
        and live.get("exists") is not True
    ):
        raise PolicyDriftError(
            "Managed policy deletion already crossed the irreversible AWS PolicyId "
            "commit point. Hacksaws will not recreate a same-named policy or restore "
            "dependencies to a different identity; rebuild it manually if required."
        )
    if target.get("exists") is not True:
        _delete_live_policy(context, service, arn, expected, checkpoints)
        return
    versions = _state_versions(target)
    default = next((item for item in versions if item.get("default") is True), None)
    if default is None or not isinstance(default.get("document"), dict):
        raise OperationalError("IAM recovery policy state has no default document.")
    desired_tags = _state_tags(target)
    exists = _policy_exists(context, arn)
    if exists and target.get("createOnly") is True:
        current = service.get_policy(
            arn, include_document=False, include_versions=False, include_tags=True
        )
        wanted = {item["Key"]: item["Value"] for item in desired_tags}
        observed = {tag.key: tag.value for tag in current.tags}
        resource_id = wanted.get("hacksaws:resource-id")
        if not resource_id or observed.get("hacksaws:resource-id") != resource_id:
            raise OperationalError(
                "Create recovery found a different policy at the target ARN."
            )
    if not exists:
        raise PolicyDriftError(
            "Managed policy recovery cannot recreate a deleted IAM policy identity; "
            "manual recovery is required."
        )
    current = service.get_policy(
        arn, include_document=True, include_versions=True, include_tags=True
    )
    desired_documents = [
        cast("dict[str, JsonValue]", item["document"])
        for item in versions
        if isinstance(item.get("document"), dict)
    ]
    desired_digests = {policy_digest(item) for item in desired_documents}
    default_document = cast("dict[str, JsonValue]", default["document"])
    default_digest = policy_digest(default_document)
    matches = {
        policy_digest(version.document): version
        for version in current.versions
        if version.document is not None
    }
    selected = matches.get(default_digest)
    if selected is None:
        _ensure_version_capacity(context, current, desired_digests)
        response = context.iam.create_policy_version(
            PolicyArn=arn,
            PolicyDocument=canonical_policy_json(default_document),
            SetAsDefault=True,
        )
        selected_id = str(response["PolicyVersion"]["VersionId"])
    else:
        selected_id = selected.version_id
        if not selected.is_default:
            context.iam.set_default_policy_version(
                PolicyArn=arn, VersionId=selected.version_id
            )
    current = service.get_policy(
        arn, include_document=True, include_versions=True, include_tags=True
    )
    existing_digests = {
        policy_digest(version.document)
        for version in current.versions
        if version.document is not None
    }
    for document in desired_documents:
        digest = policy_digest(document)
        if digest in existing_digests:
            continue
        _ensure_version_capacity(context, current, desired_digests)
        context.iam.create_policy_version(
            PolicyArn=arn,
            PolicyDocument=canonical_policy_json(document),
            SetAsDefault=False,
        )
        existing_digests.add(digest)
        current = service.get_policy(
            arn, include_document=True, include_versions=True, include_tags=True
        )
    for version in current.versions:
        if (
            version.version_id == selected_id
            or version.is_default
            or version.document is None
        ):
            continue
        if policy_digest(version.document) not in desired_digests:
            context.iam.delete_policy_version(
                PolicyArn=arn, VersionId=version.version_id
            )
    observed_tags = {tag.key: tag.value for tag in current.tags}
    wanted_tags = {item["Key"]: item["Value"] for item in desired_tags}
    additions = [
        {"Key": key, "Value": value}
        for key, value in wanted_tags.items()
        if observed_tags.get(key) != value
    ]
    removals = [key for key in observed_tags if key not in wanted_tags]
    if additions:
        context.iam.tag_policy(PolicyArn=arn, Tags=additions)
    if removals:
        context.iam.untag_policy(PolicyArn=arn, TagKeys=removals)
    _restore_dependencies(context, service, arn, target.get("dependencies"))
    final = _live_policy_state(context, service, arn)
    if not _states_match(final, target):
        raise PolicyDriftError(
            "Managed policy recovery did not reach its exact intended state; "
            "manual recovery is required."
        )


def ensure_recovery_handlers() -> None:
    """Register the policy adapter's idempotent durable state reconciler."""
    with contextlib.suppress(ValueError):
        _iam_recovery.register_handler(
            "policy",
            "reconcile",
            forward=_reconcile_policy,
            compensate=_reconcile_policy,
        )
    with contextlib.suppress(ValueError):
        _iam_recovery.register_handler(
            "policy",
            "create-policy",
            forward=_create_policy_with_receipt,
            compensate=_delete_created_policy_with_receipt,
        )


def _replacement_target(state: Mapping[str, object]) -> dict[str, object]:
    result = dict(state)
    if result.get("exists") is not True:
        return result
    result["policyId"] = "pending:replacement"
    versions: list[dict[str, object]] = []
    for index, version in enumerate(_state_versions(result)):
        replacement = dict(version)
        replacement["id"] = f"pending:replacement:{index}"
        versions.append(replacement)
    result["versions"] = versions
    result["defaultVersionId"] = "pending:replacement"
    return result


def _partial_delete_restore_target(
    state: Mapping[str, object],
) -> dict[str, object]:
    result = dict(state)
    versions: list[dict[str, object]] = []
    for index, version in enumerate(_state_versions(result)):
        replacement = dict(version)
        if replacement.get("default") is not True:
            replacement["id"] = f"pending:restore:{index}"
        versions.append(replacement)
    result["versions"] = versions
    return result


def _recovery_payload(
    expected: Mapping[str, object],
    target: Mapping[str, object],
    *,
    include_reverse_checkpoints: bool = False,
) -> dict[str, object]:
    intended = dict(target)
    if expected.get("exists") is not True and target.get("exists") is True:
        intended = _partial_delete_restore_target(target)
    elif expected.get("exists") is True and target.get("exists") is True:
        expected_ids = {
            item.get("id")
            for item in _state_versions(expected)
            if isinstance(item.get("id"), str)
            and not str(item.get("id")).startswith("pending")
        }
        versions: list[dict[str, object]] = []
        for index, version in enumerate(_state_versions(intended)):
            replacement = dict(version)
            identifier = replacement.get("id")
            if (
                isinstance(identifier, str)
                and not identifier.startswith("pending")
                and identifier not in expected_ids
            ):
                replacement["id"] = f"pending:restore:{index}"
            versions.append(replacement)
        intended["versions"] = versions
    predecessor = dict(expected)
    checkpoints = _transition_stages(predecessor, intended)
    if include_reverse_checkpoints:
        checkpoints.extend(_transition_stages(intended, predecessor))
    return {
        "expected": predecessor,
        "target": intended,
        "checkpoints": checkpoints,
    }


def _durable_reconcile(
    context: IamCommandContext,
    operation: str,
    forward: Mapping[str, object],
    compensation: Mapping[str, object],
) -> str:
    ensure_recovery_handlers()
    journal = _iam_recovery.begin_journal(
        "policy", context.account_id, operation, partition=context.partition
    )
    if compensation.get("exists") is not True and forward.get("exists") is True:
        created = _created_base_state(forward)
        create_step = journal.record_before_mutation(
            "create-policy",
            forward={"target": created},
            compensation={
                "expected": created,
                "target": compensation,
                "effectSourceStep": "self",
            },
        )
        journal.record_before_mutation(
            "reconcile",
            forward={
                **_recovery_payload(created, forward),
                "effectSourceStep": create_step,
            },
            compensation={
                **_recovery_payload(forward, created, include_reverse_checkpoints=True),
                "effectSourceStep": create_step,
            },
        )
        _iam_recovery.continue_journal(journal.id, context)
        return journal.id
    journal.record_before_mutation(
        "reconcile",
        forward=_recovery_payload(compensation, forward),
        compensation=_recovery_payload(
            forward, compensation, include_reverse_checkpoints=True
        ),
    )
    _iam_recovery.continue_journal(journal.id, context)
    return journal.id


def _error(
    code: str, message: str, exit_code: int = _configs.EXIT_ERROR
) -> _configs.Result:
    return _configs.Result(code, message, exit_code, "stderr")


def _table(
    columns: Sequence[str],
    rows: Iterable[Sequence[object]],
    *,
    legend: Sequence[tuple[str, str]] = (),
) -> str:
    target = StringIO()
    console = Console(file=target, color_system=None, force_terminal=False, width=160)
    console.print(_output.compact_table(columns, rows))
    if legend:
        console.print(_output.legend(legend))
    return target.getvalue().rstrip()


def _tags(values: Sequence[str]) -> tuple[Tag, ...]:
    result: list[Tag] = []
    seen: set[str] = set()
    for value in values:
        key, separator, item = value.partition("=")
        if not separator or not key:
            raise PolicyInputError(f"Tag {value!r} must use KEY=VALUE syntax.")
        folded = key.casefold()
        if folded in seen:
            raise PolicyInputError(f"Tag key {key!r} was supplied more than once.")
        seen.add(folded)
        result.append(Tag(key, item))
    return tuple(result)


def _metadata_mode(args: argparse.Namespace) -> MetadataMode:
    raw = getattr(args, "metadata", None)
    if raw is not None:
        return MetadataMode(raw)
    if getattr(args, "metadata_file", None) is not None:
        return MetadataMode.SIDECAR
    return MetadataMode.NONE


def _load_from_file(args: argparse.Namespace, source: str) -> LoadedPolicyInput:
    selected_format = getattr(args, "format", None)
    mode = _metadata_mode(args)
    if source != "-":
        path = Path(source).expanduser()
        if selected_format and path.suffix.casefold() not in {
            f".{selected_format}",
            ".yml" if selected_format == "yaml" else "",
        }:
            with tempfile.TemporaryDirectory(prefix="hacksaws-policy-") as directory:
                staged = Path(directory) / f"input.{selected_format}"
                staged.write_bytes(path.read_bytes())
                return load_policy_input(
                    staged,
                    metadata_mode=mode,
                    sidecar=getattr(args, "metadata_file", None),
                )
        return load_policy_input(
            path,
            metadata_mode=mode,
            sidecar=getattr(args, "metadata_file", None),
        )
    if selected_format is None:
        raise PolicyInputError("Policy input from stdin requires --format.")
    if mode is MetadataMode.SIDECAR and getattr(args, "metadata_file", None) is None:
        raise PolicyInputError(
            "Policy input from stdin with sidecar metadata requires --metadata-file."
        )
    source_stream = sys.stdin
    payload = source_stream.read()
    if not isinstance(payload, str):
        payload = payload.decode("utf-8")
    with tempfile.TemporaryDirectory(prefix="hacksaws-policy-") as directory:
        staged = Path(directory) / f"stdin.{selected_format}"
        staged.write_text(payload, encoding="utf-8")
        return load_policy_input(
            staged,
            metadata_mode=mode,
            sidecar=getattr(args, "metadata_file", None),
        )


def _stored_policy(stored_name: str) -> LoadedPolicyInput:
    data = _state.load_config()
    _, metadata = _state.get_resource(data, "policy", stored_name)
    path = _state.root() / str(metadata["file"])
    document, _ = _policies.parse_policy(path)
    return LoadedPolicyInput(
        document=document,
        metadata=InputMetadata(
            name=stored_name, description=metadata.get("description")
        ),
        source=path,
        source_format=PolicyFormat.YAML,
    )


def _loaded_update(args: argparse.Namespace) -> tuple[str, LoadedPolicyInput]:
    if hasattr(args, "policy_inputs") and not hasattr(args, "policy_or_file"):
        normalize_arguments(args)
    if args.from_stored:
        loaded = _stored_policy(args.from_stored)
        reference = args.policy_or_file or loaded.metadata.name
        if args.file is not None:
            raise PolicyInputError(
                "--from-stored cannot be combined with a policy file."
            )
    elif args.file is not None:
        loaded = _load_from_file(args, args.file)
        reference = args.policy_or_file or loaded.metadata.name
    elif args.policy_or_file is not None:
        loaded = _load_from_file(args, args.policy_or_file)
        reference = loaded.metadata.name
    else:
        raise PolicyInputError(
            "Update requires POLICY FILE, metadata-bearing FILE, or --from-stored NAME."
        )
    if not reference:
        raise PolicyInputError(
            "Policy reference is missing; supply POLICY or metadata.name."
        )
    return reference, loaded


def _words(value: str) -> list[str]:
    return [
        part
        for part in re.split(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])", value)
        if part
    ]


def _named(value: str, settings: Mapping[str, object]) -> str:
    words = _words(value)
    kind = str(settings.get("case", "Pascal")).casefold()
    if kind == "camel":
        core = (
            (words[0].lower() + "".join(word.capitalize() for word in words[1:]))
            if words
            else ""
        )
    elif kind == "snake":
        core = "_".join(word.lower() for word in words)
    elif kind == "kebab":
        core = "-".join(word.lower() for word in words)
    else:
        core = "".join(word.capitalize() for word in words)
    return f"{settings.get('prefix', '')}{core}{settings.get('suffix', '')}"


def _create_name(
    args: argparse.Namespace, loaded: LoadedPolicyInput
) -> tuple[str, list[str]]:
    base = args.name or loaded.metadata.name
    if base is None:
        if args.file == "-":
            raise PolicyInputError(
                "Policy input from stdin requires NAME or metadata.name."
            )
        base = Path(args.file).stem
    config = _state.load_config()
    settings = _state.resolve_naming(
        config, resource="policy", account=getattr(args, "account", None)
    )
    generated = _named(base, settings)
    warnings: list[str] = []
    if args.name and generated != args.name:
        enforcement = str(settings.get("enforcement", "off"))
        message = (
            f"Explicit policy name {args.name!r} does not match configured "
            f"name {generated!r}."
        )
        if enforcement == "error":
            raise PolicyInputError(message)
        if enforcement == "warn":
            warnings.append(message)
        return args.name, warnings
    if (
        args.name is None
        and loaded.metadata.name is None
        and not _configs.json_output_enabled()
        and bool(getattr(sys.stdin, "isatty", lambda: False)())
    ):
        choice = (
            input(
                f"Suggested IAM policy name: {generated}\n"
                "[A]ccept, [E]dit, or [C]ancel\n> "
            )
            .strip()
            .casefold()
        )
        if choice in {"c", "cancel"}:
            raise PolicyInputError(
                "Policy creation cancelled; no AWS changes were made."
            )
        if choice in {"e", "edit"}:
            edited = input("IAM policy name\n> ").strip()
            if not edited:
                raise PolicyInputError("Policy name cannot be empty.")
            return edited, warnings
        if choice not in {"", "a", "accept"}:
            raise PolicyInputError(
                "Choose Accept, Edit, or Cancel; no AWS changes were made."
            )
    return generated, warnings


def _select(service: IamManagedPolicyService, reference: str) -> ManagedPolicyRecord:
    result = service.resolve(reference)
    if not result.candidates:
        raise PolicyServiceError(f"Policy reference {reference!r} was not found.")
    if len(result.candidates) == 1:
        return result.candidates[0]
    if _configs.json_output_enabled() or not bool(
        getattr(sys.stdin, "isatty", lambda: False)()
    ):
        choices = ", ".join(item.arn.value for item in result.candidates)
        raise PolicyServiceError(
            f"Policy reference {reference!r} is ambiguous: {choices}."
        )
    rendered = "\n".join(
        f"  {index}. {item.arn.value}"
        for index, item in enumerate(result.candidates, 1)
    )
    answer = input(
        f"Policy reference {reference!r} is ambiguous:\n{rendered}\nSelect number: "
    ).strip()
    if not answer.isdecimal() or not 1 <= int(answer) <= len(result.candidates):
        raise PolicyServiceError("No valid policy selection was made.")
    return result.candidates[int(answer) - 1]


def _reference(service: IamManagedPolicyService, value: str) -> str:
    return _select(service, value).arn.value


def _confirm(args: argparse.Namespace, prompt: str) -> bool:
    if bool(getattr(args, "yes", False)):
        return True
    if _configs.json_output_enabled() or not bool(
        getattr(sys.stdin, "isatty", lambda: False)()
    ):
        return False
    return (
        input(f"{prompt}\n\nType exactly 'yes' to continue:\n> ").strip().casefold()
        == "yes"
    )


def _confirm_exact(args: argparse.Namespace, prompt: str, expected: str) -> bool:
    if bool(getattr(args, "yes", False)):
        return True
    if _configs.json_output_enabled() or not bool(
        getattr(sys.stdin, "isatty", lambda: False)()
    ):
        return False
    return (
        input(f"{prompt}\n\nType exactly {expected!r} to continue:\n> ").strip()
        == expected
    )


def _diagnostic_data(report: ValidationReport) -> list[dict[str, object]]:
    return [
        {
            "severity": item.severity.value,
            "code": item.code,
            "message": item.message,
            "field": item.field,
            "repair": asdict(item.repair) if item.repair else None,
        }
        for item in report.diagnostics
    ]


def _diagnostic_text(report: ValidationReport) -> str:
    return "\n".join(
        f"{item.severity.value.upper()} {item.code}: {item.message}"
        + (f" Repair: {item.repair.message}" if item.repair else "")
        for item in report.diagnostics
    )


def _tag_map(tags: Sequence[Tag]) -> dict[str, str]:
    """Return deterministic tag keys with non-reversible value references."""
    return dict(
        sorted(
            (tag.key, f"sha256:{_state.digest(tag.value.encode('utf-8'))[:12]}")
            for tag in tags
        )
    )


def _tag_delta(before: Sequence[Tag], after: Sequence[Tag]) -> dict[str, object]:
    """Return exact changed keys without exposing potentially sensitive values."""
    old = _tag_map(before)
    new = _tag_map(after)
    return {
        "before": old,
        "after": new,
        "added": {key: new[key] for key in new.keys() - old.keys()},
        "removed": {key: old[key] for key in old.keys() - new.keys()},
        "changed": {
            key: {"before": old[key], "after": new[key]}
            for key in old.keys() & new.keys()
            if old[key] != new[key]
        },
    }


def _document_summary(document: Mapping[str, JsonValue] | None) -> dict[str, object]:
    """Summarize policy semantics without exposing the policy document."""
    if document is None:
        return {
            "exists": False,
            "sha256": None,
            "minifiedBytes": 0,
            "statements": 0,
            "allowStatements": 0,
            "denyStatements": 0,
            "actions": 0,
            "resources": 0,
        }
    raw_statements = document.get("Statement", [])
    statements = (
        [raw_statements]
        if isinstance(raw_statements, Mapping)
        else raw_statements
        if isinstance(raw_statements, list)
        else []
    )
    valid = [item for item in statements if isinstance(item, Mapping)]

    def values(item: Mapping[str, object], key: str) -> int:
        value = item.get(key)
        if isinstance(value, list):
            return len(value)
        return int(value is not None)

    minified = canonical_policy_json(cast("dict[str, JsonValue]", document))
    return {
        "exists": True,
        "sha256": policy_digest(cast("dict[str, JsonValue]", document)),
        "minifiedBytes": len(minified.encode("utf-8")),
        "statements": len(valid),
        "allowStatements": sum(item.get("Effect") == "Allow" for item in valid),
        "denyStatements": sum(item.get("Effect") == "Deny" for item in valid),
        "actions": sum(values(item, "Action") for item in valid),
        "resources": sum(values(item, "Resource") for item in valid),
    }


def _policy_step_data(step: OperationStep) -> dict[str, object]:
    """Return one bounded operation row without policy documents or raw params."""
    operation = step
    params = step.parameters
    detail: dict[str, object] = {}
    if isinstance(params, Mapping):
        if isinstance(params.get("VersionId"), str):
            detail["versionId"] = params["VersionId"]
        raw_tags = params.get("Tags")
        if isinstance(raw_tags, list):
            detail["tagKeys"] = sorted(
                str(item.get("Key"))
                for item in raw_tags
                if isinstance(item, Mapping) and item.get("Key") is not None
            )
        raw_keys = params.get("TagKeys")
        if isinstance(raw_keys, list):
            detail["tagKeys"] = sorted(str(item) for item in raw_keys)
    return {
        "id": operation.step_id,
        "action": operation.operation,
        "destructive": bool(operation.destructive),
        "reversible": operation.compensation is not None,
        "detail": detail,
    }


def _policy_plan_data(
    plan: PolicyChangePlan,
    context: IamCommandContext,
    diagnostics: list[dict[str, object]],
    warnings: list[str],
) -> dict[str, object]:
    """Build the stable, document-free policy mutation review model."""
    before = plan.before
    after = plan.after
    arn = (
        after.arn
        if after is not None
        else before.arn
        if before is not None
        else plan.policy_arn.value
        if plan.policy_arn is not None
        else (
            f"arn:{context.partition}:iam::{context.account_id}:policy"
            f"{plan.path}{plan.name}"
        )
    )
    before_tags = before.tags if before is not None else ()
    after_tags = after.tags if after is not None else plan.tags
    before_origin = ownership_origin(before_tags)
    after_origin = ownership_origin(after_tags)
    before_document = before.document if before is not None else None
    after_document = after.document if after is not None else plan.document
    document_before = _document_summary(before_document)
    document_after = _document_summary(after_document)
    document_delta = {
        "before": document_before,
        "after": document_after,
        "changed": document_before["sha256"] != document_after["sha256"],
    }
    action = plan.operation.action.value
    risk = (
        "none"
        if plan.operation.action is ChangeAction.NOOP
        else "high"
        if any(step.destructive for step in plan.operation.steps)
        else "moderate"
        if plan.operation.action in {ChangeAction.UPDATE, ChangeAction.ROLLBACK}
        else "low"
    )
    return {
        "classification": (
            "no-change"
            if plan.operation.action is ChangeAction.NOOP
            else "blocked"
            if not plan.validation.valid
            else "planned"
        ),
        "action": action,
        "risk": risk,
        "verifiedIdentity": {
            "accountId": context.account_id,
            "partition": context.partition,
            "callerArn": getattr(context, "arn", None),
        },
        "resource": {
            "type": "managed-policy",
            "name": plan.name,
            "arn": arn,
            "policyId": (
                before.policy_id
                if before is not None
                else after.policy_id
                if after is not None
                else None
            ),
            "path": plan.path,
            "ownershipBefore": classify_ownership(before_tags).value,
            "ownershipAfter": classify_ownership(after_tags).value,
            "originBefore": before_origin.value if before_origin else None,
            "originAfter": after_origin.value if after_origin else None,
        },
        "changes": {
            "tags": _tag_delta(before_tags, after_tags),
            "document": document_delta,
            "prunedVersion": plan.prune_version_id,
        },
        "operations": [_policy_step_data(step) for step in plan.operation.steps],
        "dependencies": {},
        "blockers": [item for item in diagnostics if item.get("severity") == "error"],
        "warnings": warnings,
        "journalExpected": plan.operation.action is not ChangeAction.NOOP,
        "recovery": (
            "A credential-free journal will be written before the first AWS mutation."
            if plan.operation.action is not ChangeAction.NOOP
            else "No journal is needed because no mutation is planned."
        ),
    }


def _ownership_plan_data(
    plan: TagChangePlan,
    context: IamCommandContext,
    action: str,
) -> dict[str, object]:
    """Adapt an ownership-only plan to the stable policy review model."""
    before_tags = plan.before_tags or plan.policy.tags
    if plan.after_tags:
        after_tags = plan.after_tags
    else:
        values = {tag.key: tag.value for tag in before_tags}
        values.update({tag.key: tag.value for tag in plan.add})
        for key in plan.remove:
            values.pop(key, None)
        after_tags = tuple(Tag(key, value) for key, value in sorted(values.items()))
    before_origin = ownership_origin(before_tags)
    after_origin = ownership_origin(after_tags)
    return {
        "classification": "planned" if plan.operation.steps else "no-change",
        "action": action,
        "risk": "low" if plan.operation.steps else "none",
        "verifiedIdentity": {
            "accountId": context.account_id,
            "partition": context.partition,
            "callerArn": getattr(context, "arn", None),
        },
        "resource": {
            "type": "managed-policy",
            "name": plan.policy.name,
            "arn": plan.policy.arn.value,
            "policyId": plan.policy.policy_id,
            "path": plan.policy.path,
            "ownershipBefore": classify_ownership(before_tags).value,
            "ownershipAfter": classify_ownership(after_tags).value,
            "originBefore": before_origin.value if before_origin else None,
            "originAfter": after_origin.value if after_origin else None,
        },
        "changes": {
            "tags": _tag_delta(before_tags, after_tags),
            "document": {
                "before": _document_summary(None),
                "after": _document_summary(None),
                "changed": False,
            },
            "prunedVersion": None,
        },
        "operations": [_policy_step_data(step) for step in plan.operation.steps],
        "dependencies": {},
        "blockers": [],
        "warnings": list(plan.operation.warnings),
        "journalExpected": bool(plan.operation.steps),
        "recovery": (
            "A credential-free journal will be written before the first AWS mutation."
            if plan.operation.steps
            else "No journal is needed because ownership already matches."
        ),
    }


def _policy_delete_plan_data(
    plan: PolicyDeletionPlan,
    context: IamCommandContext,
    *,
    allow_unmanaged: bool,
    remove_boundaries: bool,
) -> dict[str, object]:
    """Build a bounded deletion review including dependency blockers."""
    policy = plan.policy
    dependencies = _dependency_data(plan)
    blockers: list[dict[str, str]] = []
    if not policy.owned and not allow_unmanaged:
        blockers.append(
            {
                "code": "UNMANAGED_POLICY",
                "message": (
                    "Policy is not Hacksaws-owned; --allow-unmanaged is required."
                ),
            }
        )
    if (
        plan.dependencies.boundary_users or plan.dependencies.boundary_roles
    ) and not remove_boundaries:
        blockers.append(
            {
                "code": "BOUNDARY_OPT_IN_REQUIRED",
                "message": "Permissions-boundary removal requires --remove-boundaries.",
            }
        )
    if not plan.executable:
        blockers.append(
            {
                "code": "CASCADE_REQUIRED",
                "message": "Policy dependencies require --cascade before deletion.",
            }
        )
    origin = policy.ownership_origin
    return {
        "classification": "blocked" if blockers else "planned",
        "action": "delete",
        "risk": "critical",
        "verifiedIdentity": {
            "accountId": context.account_id,
            "partition": context.partition,
            "callerArn": getattr(context, "arn", None),
        },
        "resource": {
            "type": "managed-policy",
            "name": policy.name,
            "arn": policy.arn.value,
            "policyId": policy.policy_id,
            "path": policy.path,
            "ownershipBefore": policy.ownership_status.value,
            "ownershipAfter": "absent",
            "originBefore": origin.value if origin else None,
            "originAfter": None,
        },
        "changes": {
            "tags": _tag_delta(policy.tags, ()),
            "document": {
                "before": _document_summary(policy.document),
                "after": _document_summary(None),
                "changed": policy.document is not None,
            },
            "prunedVersion": None,
        },
        "operations": [_policy_step_data(step) for step in plan.operation.steps],
        "dependencies": dependencies,
        "blockers": blockers,
        "warnings": list(plan.operation.warnings),
        "journalExpected": not blockers,
        "recovery": (
            "Deletion is irreversible after AWS accepts DeletePolicy; the journal "
            "retains a commit-point receipt but will not recreate the identity."
        ),
    }


def _short_hash(value: object) -> str:
    """Render a compact hash while preserving absent-state clarity."""
    return str(value)[:12] if value else "absent"


def _policy_plan_text(data: Mapping[str, object]) -> str:
    """Render a compact policy mutation review without raw JSON or documents."""
    identity = cast("Mapping[str, object]", data["verifiedIdentity"])
    resource = cast("Mapping[str, object]", data["resource"])
    changes = cast("Mapping[str, object]", data["changes"])
    tags = cast("Mapping[str, object]", changes["tags"])
    document = cast("Mapping[str, object]", changes["document"])
    before_doc = cast("Mapping[str, object]", document["before"])
    after_doc = cast("Mapping[str, object]", document["after"])
    lines = [
        f"PLAN — {str(data['action']).upper()} ({data['risk']} risk)",
        f"Account: {identity['accountId']} ({identity['partition']})",
        f"Caller: {identity.get('callerArn') or 'unknown'}",
        f"Policy: {resource['name']}",
        f"ARN: {resource['arn']}",
        f"Policy ID: {resource.get('policyId') or 'assigned by AWS on create'}",
        (
            "Ownership: "
            f"{resource['ownershipBefore']}/{resource.get('originBefore') or '-'}"
            " → "
            f"{resource['ownershipAfter']}/{resource.get('originAfter') or '-'}"
        ),
        (
            "Document: "
            f"{_short_hash(before_doc.get('sha256'))} → "
            f"{_short_hash(after_doc.get('sha256'))} "
            f"({after_doc.get('minifiedBytes', 0)} bytes; "
            f"{after_doc.get('statements', 0)} statements, "
            f"{after_doc.get('allowStatements', 0)} allow, "
            f"{after_doc.get('denyStatements', 0)} deny)"
        ),
    ]
    added = cast("Mapping[str, object]", tags["added"])
    removed = cast("Mapping[str, object]", tags["removed"])
    changed = cast("Mapping[str, Mapping[str, object]]", tags["changed"])
    if added or removed or changed:
        lines.append("Tag changes:")
        lines.extend(f"  + {key}={value}" for key, value in sorted(added.items()))
        lines.extend(f"  - {key}={value}" for key, value in sorted(removed.items()))
        lines.extend(
            f"  ~ {key}: {value['before']} → {value['after']}"
            for key, value in sorted(changed.items())
        )
    else:
        lines.append("Tag changes: none")
    operations = cast("list[Mapping[str, object]]", data["operations"])
    if operations:
        lines.append("Ordered AWS operations:")
        lines.extend(
            f"  {index}. {item['action']} "
            f"[{'reversible' if item['reversible'] else 'irreversible'}]"
            for index, item in enumerate(operations, 1)
        )
    blockers = cast("list[Mapping[str, object]]", data["blockers"])
    if blockers:
        lines.append("Blockers:")
        lines.extend(f"  - {item.get('message', item)}" for item in blockers)
    dependencies = cast("Mapping[str, object]", data["dependencies"])
    populated = {
        key: value
        for key, value in dependencies.items()
        if isinstance(value, list) and value
    }
    if populated:
        lines.append("Dependencies:")
        lines.extend(
            f"  - {key}: {', '.join(str(item) for item in value)}"
            for key, value in sorted(populated.items())
        )
    warnings = cast("list[str]", data["warnings"])
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"  - {item}" for item in warnings)
    lines.append(str(data["recovery"]))
    lines.append("No changes have been made.")
    return "\n".join(_output.safe_terminal_text(line) for line in lines)


def _confirmation_unavailable() -> bool:
    """Return whether a mutation needs explicit ``--yes`` in this process."""
    return _configs.json_output_enabled() or not bool(
        getattr(sys.stdin, "isatty", lambda: False)()
    )


def _policy_success_text(
    plan_data: Mapping[str, object],
    policy: ManagedPolicyRecord,
    *,
    journal_id: str | None,
    console_url: str,
) -> str:
    """Render a definitive verified policy result with only applied deltas."""
    action = str(plan_data["action"])
    verb = {
        "create": "Created",
        "update": "Updated",
        "rollback": "Rolled back",
        "noop": "No change —",
    }.get(action, action.replace("-", " ").title() + "d")
    changes = cast("Mapping[str, object]", plan_data["changes"])
    tags = cast("Mapping[str, object]", changes["tags"])
    document = cast("Mapping[str, object]", changes["document"])
    lines = [f"{verb} managed policy {policy.name}."]
    applied: list[str] = []
    if document.get("changed"):
        before = cast("Mapping[str, object]", document["before"])
        after = cast("Mapping[str, object]", document["after"])
        applied.append(
            f"document {_short_hash(before.get('sha256'))} → "
            f"{_short_hash(after.get('sha256'))}"
        )
    tag_count = sum(
        len(cast("Mapping[str, object]", tags[key]))
        for key in ("added", "removed", "changed")
    )
    if tag_count:
        applied.append(f"{tag_count} tag delta(s)")
    lines.append("Applied: " + (", ".join(applied) if applied else "none"))
    lines.extend(
        (
            f"ARN: {policy.arn.value}",
            f"Policy ID: {policy.policy_id}",
            f"Verified: IAM read-back matched version {policy.default_version_id}.",
            (
                f"Journal: {journal_id} (completed; use 'hacksaws iam recovery get "
                f"{journal_id}' for the recovery receipt)."
                if journal_id
                else "Journal: none (no mutation was required)."
            ),
            f"AWS Console: {console_url}",
        )
    )
    return "\n".join(_output.safe_terminal_text(line) for line in lines)


def _semantic_diff(
    service: IamManagedPolicyService, plan: PolicyChangePlan
) -> list[str]:
    if plan.policy_arn is None or plan.operation.action not in {
        ChangeAction.UPDATE,
        ChangeAction.ROLLBACK,
    }:
        return []
    current = service.get_policy(
        plan.policy_arn.value,
        include_document=True,
        include_versions=False,
        include_tags=False,
    )
    if current.document is None:
        return []
    before = json.dumps(current.document, indent=2, sort_keys=True).splitlines()
    after = json.dumps(plan.document, indent=2, sort_keys=True).splitlines()
    return list(
        difflib.unified_diff(
            before,
            after,
            fromfile=f"{current.default_version_id} (current)",
            tofile="proposed",
            lineterm="",
        )
    )


def _change_preview(
    plan: PolicyChangePlan,
    context: IamCommandContext,
    diagnostics: list[dict[str, object]],
    warnings: list[str],
    diff: list[str],
) -> dict[str, object]:
    arn = (
        plan.policy_arn.value
        if plan.policy_arn is not None
        else (
            f"arn:{context.partition}:iam::{context.account_id}:policy"
            f"{plan.path}{plan.name}"
        )
    )
    minified = canonical_policy_json(plan.document)
    return {
        "classification": (
            "no-change" if plan.operation.action is ChangeAction.NOOP else "planned"
        ),
        "action": plan.operation.action.value,
        "accountId": context.account_id,
        "callerArn": getattr(context, "arn", None),
        "name": plan.name,
        "path": plan.path,
        "arn": arn,
        "documentSha256": policy_digest(plan.document),
        "minifiedBytes": len(minified.encode("utf-8")),
        "tags": {tag.key: tag.value for tag in plan.tags},
        "validation": diagnostics,
        "warnings": warnings,
        "diff": diff,
        "prunedVersion": plan.prune_version_id,
    }


def _change_states(
    service: IamManagedPolicyService, plan: PolicyChangePlan
) -> tuple[dict[str, object], dict[str, object]]:
    if plan.policy_arn is None:
        arn = (
            f"arn:{service.partition}:iam::{service.account_id}:policy"
            f"{plan.path}{plan.name}"
        )
        created = ManagedPolicyRecord(
            arn=ManagedPolicyArn.parse(arn),
            policy_id="pending",
            name=plan.name,
            path=plan.path,
            default_version_id="pending",
            attachment_count=0,
            permissions_boundary_usage_count=0,
            tags=plan.tags,
            document=plan.document,
            description=plan.description,
        )
        return _policy_state(
            created, dependencies=PolicyDependencies(), create_only=True
        ), _absent_state(arn, plan.name, plan.path)
    before = service.get_policy(
        plan.policy_arn.value,
        include_document=True,
        include_versions=True,
        include_tags=True,
    )
    if before.document is None:
        raise PolicyServiceError("Current policy document is unavailable.")
    if (
        before.default_version_id != plan.expected_default_version_id
        or policy_digest(before.document) != plan.expected_digest
        or (
            plan.expected_tag_digest is not None
            and service._tag_digest(before.tags)  # noqa: SLF001
            != plan.expected_tag_digest
        )
    ):
        raise PolicyDriftError(
            "Policy changed after planning; review the operation again."
        )
    after_versions = [
        _version_payload(version)
        for version in before.versions
        if version.version_id != plan.prune_version_id
    ]
    publishes_version = any(
        step.operation == "CreatePolicyVersion" for step in plan.operation.steps
    ) or (
        plan.operation.action is ChangeAction.UPDATE
        and plan.before is None
        and plan.after is None
    )
    if plan.operation.action is ChangeAction.UPDATE and publishes_version:
        for version in after_versions:
            version["default"] = False
        after_versions.append(
            {"id": "pending", "default": True, "document": plan.document}
        )
    elif plan.operation.action is ChangeAction.ROLLBACK:
        for version in after_versions:
            version["default"] = version["id"] == plan.rollback_version_id
    dependencies = service.policy_dependencies(plan.policy_arn.value)
    after = _policy_state(before, dependencies=dependencies)
    after["versions"] = after_versions
    after["tags"] = [tag.as_request() for tag in plan.tags]
    return after, _policy_state(before, dependencies=dependencies)


def _repair(
    plan: PolicyChangePlan, args: argparse.Namespace, service: IamManagedPolicyService
) -> PolicyChangePlan:
    document = dict(plan.document)
    changed = False
    for repair in plan.validation.repairs:
        if repair.field != "Version" or repair.suggested_value is None:
            continue
        if bool(getattr(args, "yes", False)):
            continue
        if _configs.json_output_enabled() or not bool(
            getattr(sys.stdin, "isatty", lambda: False)()
        ):
            continue
        if (
            input(f"{repair.message} Apply {repair.suggested_value!r}? Type 'yes': ")
            .strip()
            .casefold()
            == "yes"
        ):
            document["Version"] = repair.suggested_value
            changed = True
    if not changed:
        return plan
    if plan.operation.action is ChangeAction.CREATE:
        return service.plan_create(
            plan.name,
            document,
            options=CreatePolicyOptions(
                description=plan.description,
                path=plan.path,
                user_tags=tuple(
                    tag
                    for tag in plan.tags
                    if not tag.key.casefold().startswith(_RESERVED_PREFIX)
                ),
                include_aws_validation=not bool(
                    getattr(args, "local_validation_only", False)
                ),
            ),
        )
    if plan.policy_arn is None:
        return plan
    return service.plan_publish(
        plan.policy_arn.value,
        document,
        include_aws_validation=not bool(getattr(args, "local_validation_only", False)),
        planned_tags=plan.tags,
    )


def _execute_plan(
    service: IamManagedPolicyService,
    plan: PolicyChangePlan,
    args: argparse.Namespace,
    context: IamCommandContext,
) -> _configs.Result:
    plan = _repair(plan, args, service)
    diagnostics = _diagnostic_data(plan.validation)
    warnings = [
        item.message
        for item in plan.validation.diagnostics
        if item.severity is not DiagnosticSeverity.ERROR
    ]
    warnings.extend(plan.operation.warnings)
    preview = _policy_plan_data(plan, context, diagnostics, warnings)
    review = _policy_plan_text(preview)
    if not plan.validation.valid:
        return _configs.Result(
            "IAM_POLICY_VALIDATION_FAILED",
            review,
            _configs.EXIT_POLICY,
            "stderr",
            {"plan": preview, "result": {"classification": "blocked"}},
        )
    if bool(getattr(args, "dry_run", False)):
        return _configs.Result(
            "IAM_POLICY_DRY_RUN",
            "DRY RUN\n" + review,
            data={
                "plan": preview,
                "result": {
                    "classification": "dry-run",
                    "journalId": None,
                    "changed": False,
                },
            },
        )
    if plan.operation.action is not ChangeAction.NOOP and not bool(
        getattr(args, "yes", False)
    ):
        if _confirmation_unavailable():
            return _configs.Result(
                "IAM_POLICY_CONFIRMATION_REQUIRED",
                review + "\nConfirmation required: rerun with --yes.",
                _configs.EXIT_CANCELLED,
                "stderr",
                {
                    "plan": preview,
                    "result": {"classification": "confirmation-required"},
                },
            )
        answer = input(
            review + "\n\nType exactly 'yes' to apply this plan:\n> "
        ).strip()
        if answer.casefold() != "yes":
            return _configs.Result(
                "IAM_POLICY_CANCELLED",
                "CANCELLED — Policy change declined. No changes have been made.",
                _configs.EXIT_CANCELLED,
                "stderr",
                {
                    "plan": preview,
                    "result": {"classification": "cancelled"},
                },
            )
    if plan.operation.action is ChangeAction.NOOP:
        policy = service.get_policy(
            cast("ManagedPolicyArn", plan.policy_arn).value,
            include_document=True,
            include_versions=True,
            include_tags=True,
        )
        journal_id = None
    else:
        forward, compensation = _change_states(service, plan)
        journal_id = _durable_reconcile(
            context, plan.operation.action.value, forward, compensation
        )
        reference = str(forward["arn"])
        policy = service.get_policy(
            reference,
            include_document=True,
            include_versions=True,
            include_tags=True,
        )
    console_url = _console_url(context, policy.arn.value)
    applied = cast("Mapping[str, object]", preview["changes"])
    result_data = {
        "classification": (
            "no-change" if plan.operation.action is ChangeAction.NOOP else "applied"
        ),
        "action": plan.operation.action.value,
        "arn": policy.arn.value,
        "name": policy.name,
        "policyId": policy.policy_id,
        "version": policy.default_version_id,
        "journalId": journal_id,
        "verified": True,
        "recoveryAvailable": journal_id is not None,
        "consoleUrl": console_url,
    }
    return _configs.Result(
        "IAM_POLICY_NO_CHANGE"
        if plan.operation.action is ChangeAction.NOOP
        else "IAM_POLICY_CHANGED",
        _policy_success_text(
            preview,
            policy,
            journal_id=journal_id,
            console_url=console_url,
        ),
        data={"plan": preview, "applied": applied, "result": result_data},
    )


def _create(
    args: argparse.Namespace,
    service: IamManagedPolicyService,
    context: IamCommandContext,
) -> _configs.Result:
    loaded = _load_from_file(args, args.file)
    policy_name, naming_warnings = _create_name(args, loaded)
    explicit_tags = _tags(args.tag)
    tags = (*[Tag(key, value) for key, value in loaded.metadata.tags], *explicit_tags)
    selected_path = args.iam_path or loaded.metadata.path
    existing = service.resolve(f"custom:{policy_name}")
    if existing.candidates:
        if len(existing.candidates) > 1:
            target = _select(service, f"custom:{policy_name}")
        else:
            target = existing.candidates[0]
        target = service.get_policy(
            target.arn.value,
            include_document=True,
            include_versions=True,
            include_tags=True,
        )
        if target.ownership_status is OwnershipStatus.UNOWNED:
            return _error(
                "IAM_POLICY_COLLISION",
                f"Policy {policy_name!r} already exists at {target.arn.value} but "
                "is not Hacksaws-owned. Review it and run 'iam policy adopt' "
                "before creating or updating it by name; --replace never adopts or "
                "rewrites ownership identity.",
                _configs.EXIT_POLICY,
            )
        if target.ownership_status is OwnershipStatus.UNSAFE:
            return _error(
                "IAM_POLICY_OWNERSHIP_UNSAFE",
                f"Policy {policy_name!r} has conflicting or partial Hacksaws "
                "ownership tags. Repair or release those tags explicitly; no "
                "document or identity changes were planned.",
                _configs.EXIT_POLICY,
            )
        desired_tags = reconcile_owned_tags(target, tags)
        same_document = target.document is not None and policy_digest(
            target.document
        ) == policy_digest(loaded.document)
        same_tags = tuple(sorted((tag.key, tag.value) for tag in target.tags)) == tuple(
            sorted((tag.key, tag.value) for tag in desired_tags)
        )
        same_attributes = (selected_path is None or selected_path == target.path) and (
            (args.description is None and loaded.metadata.description is None)
            or (args.description or loaded.metadata.description) == target.description
        )
        if same_document and same_tags and same_attributes:
            return _configs.Result(
                "IAM_POLICY_NO_CHANGE",
                f"NO CHANGE — Policy {policy_name!r} already matches "
                f"{target.arn.value}.",
                data={
                    "classification": "no-change",
                    "action": "no-op",
                    "arn": target.arn.value,
                    "name": target.name,
                    "version": target.default_version_id,
                },
            )
        if not args.replace and not (same_document and same_attributes):
            return _error(
                "IAM_POLICY_COLLISION",
                f"Policy {policy_name!r} already exists at {target.arn.value}; "
                "its document, tags, path, or description differs. Use 'iam policy "
                "update' for routine changes, or repeat create with --replace after "
                "reviewing the preview.",
                _configs.EXIT_POLICY,
            )
        plan = service.plan_publish(
            target.arn.value,
            loaded.document,
            include_aws_validation=not args.local_validation_only,
            planned_tags=desired_tags,
        )
    else:
        plan = service.plan_create(
            policy_name,
            loaded.document,
            options=CreatePolicyOptions(
                description=args.description or loaded.metadata.description,
                path=selected_path,
                user_tags=tags,
                resource_id=uuid.uuid4().hex,
                include_aws_validation=not args.local_validation_only,
            ),
        )
    result = _execute_plan(service, plan, args, context)
    if naming_warnings and result.exit_code == _configs.EXIT_OK:
        return _configs.Result(
            result.code,
            result.message
            + "\n"
            + "\n".join(f"Warning: {item}" for item in naming_warnings),
            data=result.data,
        )
    return result


def _list(
    args: argparse.Namespace, service: IamManagedPolicyService
) -> _configs.Result:
    scope = (
        PolicyScope.LOCAL
        if args.custom
        else PolicyScope.AWS
        if args.aws
        else PolicyScope.ALL
    )
    policies = service.list_policies(scope=scope, include_tags=True)
    patterns = args.patterns or ["*"]
    policies = tuple(
        item
        for item in policies
        if any(
            fnmatch.fnmatchcase(item.name.casefold(), pattern.casefold())
            or fnmatch.fnmatchcase(item.arn.value.casefold(), pattern.casefold())
            for pattern in patterns
        )
    )
    wide = bool(args.wide)
    columns = ["Name", "Kind", "Owner", "Attached"]
    if wide:
        columns += ["Path", "Default", "Boundaries", "ARN"]
    rows: list[list[object]] = []
    kinds: set[str] = set()
    owners = False
    for item in policies:
        kind = "A" if item.arn.kind is PolicyKind.AWS_MANAGED else "C"
        kinds.add(kind)
        owner = "H" if item.owned else "-"
        owners |= item.owned
        row: list[object] = [item.name, kind, owner, item.attachment_count]
        if wide:
            row += [
                item.path,
                item.default_version_id,
                item.permissions_boundary_usage_count,
                item.arn.value,
            ]
        rows.append(row)
    legend: list[tuple[str, str]] = []
    if "A" in kinds:
        legend.append(("A", "AWS-managed"))
    if "C" in kinds:
        legend.append(("C", "customer-managed"))
    if owners:
        legend.append(("H", "Hacksaws-owned"))
    data = {
        "scope": scope.value,
        "patterns": patterns,
        "policies": [_record_data(item) for item in policies],
        "view": "wide" if wide else "compact",
        "legend": dict(legend),
    }
    return _configs.Result(
        "IAM_POLICY_LIST", _table(columns, rows, legend=legend), data=data
    )


def _record_data(item: ManagedPolicyRecord) -> dict[str, object]:
    return {
        "arn": item.arn.value,
        "name": item.name,
        "kind": item.arn.kind.value,
        "path": item.path,
        "defaultVersion": item.default_version_id,
        "attachments": item.attachment_count,
        "permissionsBoundaryUsage": item.permissions_boundary_usage_count,
        "owned": item.owned,
        "tags": {tag.key: tag.value for tag in item.tags},
    }


def _get(args: argparse.Namespace, service: IamManagedPolicyService) -> _configs.Result:
    reference = _reference(service, args.policy)
    item = service.get_policy(
        reference, include_document=True, include_versions=True, include_tags=True
    )
    data = _record_data(item)
    data["versions"] = [version.version_id for version in item.versions]
    data["document"] = item.document
    rows = [
        ("ARN", item.arn.value),
        ("Kind", item.arn.kind.value),
        ("Path", item.path),
        ("Default version", item.default_version_id),
        ("Attachments", item.attachment_count),
        ("Boundary uses", item.permissions_boundary_usage_count),
        ("Owned", "yes" if item.owned else "no"),
    ]
    return _configs.Result(
        "IAM_POLICY_GET", _table(("Field", "Value"), rows), data=data
    )


def _output_format(args: argparse.Namespace) -> PolicyFormat:
    if args.format:
        return PolicyFormat(args.format)
    if args.output and args.output != "-":
        try:
            return PolicyFormat.from_path(Path(args.output))
        except PolicyInputError:
            pass
    return PolicyFormat.YAML


def _toml_scalar(value: JsonValue) -> str:
    if value is None:
        raise PolicyInputError(
            "TOML has no null value and cannot represent this policy losslessly; "
            "use YAML or JSON."
        )
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list) and all(not isinstance(item, dict) for item in value):
        return "[" + ", ".join(_toml_scalar(item) for item in value) + "]"
    raise PolicyInputError(
        "This policy shape cannot be represented losslessly as TOML; use YAML or JSON."
    )


def _toml_document(value: Mapping[str, JsonValue]) -> str:
    lines: list[str] = []

    def key(value: str) -> str:
        return value if re.fullmatch(r"[A-Za-z0-9_-]+", value) else json.dumps(value)

    def table(mapping: Mapping[str, JsonValue], prefix: tuple[str, ...]) -> None:
        deferred: list[tuple[str, JsonValue]] = []
        for item_key, item in mapping.items():
            if isinstance(item, dict) or (
                isinstance(item, list)
                and any(isinstance(child, dict) for child in item)
            ):
                deferred.append((item_key, item))
            else:
                lines.append(f"{key(item_key)} = {_toml_scalar(item)}")
        for item_key, item in deferred:
            path = ".".join(key(part) for part in (*prefix, item_key))
            if isinstance(item, dict):
                lines.extend(("", f"[{path}]"))
                table(item, (*prefix, item_key))
            else:
                children = cast("list[JsonValue]", item)
                for child in children:
                    if not isinstance(child, dict):
                        raise PolicyInputError(
                            "Mixed object/scalar TOML arrays are not supported."
                        )
                    lines.extend(("", f"[[{path}]]"))
                    table(child, (*prefix, item_key))

    table(value, ())
    return "\n".join(lines).lstrip() + "\n"


def _serialize(value: Mapping[str, JsonValue], selected: PolicyFormat) -> str:
    if selected is PolicyFormat.JSON:
        return json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if selected is PolicyFormat.YAML:
        return cast("str", yaml.safe_dump(dict(value), sort_keys=False))
    return _toml_document(value)


def _export_metadata(item: ManagedPolicyRecord) -> dict[str, JsonValue]:
    return {
        "name": item.name,
        "path": item.path,
        "description": item.description,
        "tags": {
            tag.key: tag.value
            for tag in item.tags
            if not tag.key.casefold().startswith(_RESERVED_PREFIX)
        },
    }


def _export(
    args: argparse.Namespace, service: IamManagedPolicyService
) -> _configs.Result:
    if args.policy.startswith("stored:"):
        stored = _stored_policy(args.policy.split(":", maxsplit=1)[1])
        selected = _output_format(args)
        mode = MetadataMode(args.metadata)
        metadata: dict[str, JsonValue] = {
            "name": stored.metadata.name,
            **(
                {"description": stored.metadata.description}
                if stored.metadata.description
                else {}
            ),
        }
        content_value: Mapping[str, JsonValue] = (
            {"metadata": metadata, "policy": stored.document}
            if mode is MetadataMode.NESTED
            else stored.document
        )
        if mode is MetadataMode.SIDECAR:
            raise PolicyInputError(
                "Stored-policy sidecar export is not supported; use nested metadata."
            )
        content = _serialize(content_value, selected)
        if args.output and args.output != "-":
            output_path = Path(args.output).expanduser()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding="utf-8")
            message = f"Exported stored policy {stored.metadata.name} to {output_path}."
        else:
            message = content.rstrip()
        return _configs.Result(
            "IAM_POLICY_EXPORT",
            message,
            data={
                "name": stored.metadata.name,
                "provenance": "stored",
                "source": str(stored.source),
                "format": selected.value,
                "metadata": mode.value,
                "output": args.output,
                "document": stored.document,
            },
        )
    reference = _reference(service, args.policy)
    exported = service.export_policy(reference, include_all_versions=args.all_versions)
    selected = _output_format(args)
    metadata = _export_metadata(exported.policy)
    mode = MetadataMode(args.metadata)
    version_data: list[dict[str, JsonValue]] = [
        {
            "id": version.version_id,
            "default": version.is_default,
            "createdAt": (
                version.created_at.isoformat() if version.created_at else None
            ),
            "policy": version.document,
        }
        for version in exported.versions
    ]
    remote_content: Mapping[str, JsonValue]
    if args.all_versions:
        remote_content = {
            **({"metadata": metadata} if mode is MetadataMode.NESTED else {}),
            "policy": exported.active_document,
            "versions": cast("JsonValue", version_data),
        }
    elif mode is MetadataMode.NESTED:
        remote_content = {"metadata": metadata, "policy": exported.active_document}
    else:
        remote_content = exported.active_document
    content = _serialize(remote_content, selected)
    output = args.output
    sidecar_path: Path | None = None
    if mode is MetadataMode.SIDECAR:
        if not output or output == "-":
            raise PolicyInputError("Sidecar metadata export requires an output file.")
        sidecar_path = args.metadata_file or Path(output).with_name(
            f"{Path(output).stem}.metadata{Path(output).suffix}"
        )
    if output and output != "-":
        output_path = Path(output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        if sidecar_path:
            sidecar_path.parent.mkdir(parents=True, exist_ok=True)
            sidecar_path.write_text(
                _serialize(metadata, PolicyFormat.from_path(sidecar_path)),
                encoding="utf-8",
            )
        message = f"Exported {exported.policy.arn.value} to {output_path}."
    else:
        message = content.rstrip()
    data = {
        "arn": exported.policy.arn.value,
        "provenance": "aws-managed"
        if exported.policy.arn.kind is PolicyKind.AWS_MANAGED
        else "customer-managed",
        "format": selected.value,
        "metadata": mode.value,
        "output": str(output) if output else None,
        "sidecar": str(sidecar_path) if sidecar_path else None,
        "versions": version_data,
        "document": exported.active_document,
    }
    return _configs.Result("IAM_POLICY_EXPORT", message, data=data)


def _update(
    args: argparse.Namespace,
    service: IamManagedPolicyService,
    context: IamCommandContext,
) -> _configs.Result:
    reference, loaded = _loaded_update(args)
    arn = _reference(service, reference)
    current = service.get_policy(
        arn, include_document=False, include_versions=False, include_tags=True
    )
    planned_tags: tuple[Tag, ...] | None = None
    if current.arn.kind is PolicyKind.CUSTOMER_MANAGED:
        if current.ownership_status is OwnershipStatus.UNOWNED:
            return _error(
                "IAM_POLICY_UNMANAGED",
                "Policy is not Hacksaws-owned; review and adopt it before update.",
                _configs.EXIT_POLICY,
            )
        if current.ownership_status is OwnershipStatus.UNSAFE:
            return _error(
                "IAM_POLICY_OWNERSHIP_UNSAFE",
                "Policy has conflicting or partial Hacksaws ownership tags; repair "
                "or release them before update.",
                _configs.EXIT_POLICY,
            )
        user_tags = tuple(
            tag for tag in current.tags if tag.key.casefold() not in RESERVED_TAGS
        )
        planned_tags = reconcile_owned_tags(current, user_tags)
    plan = service.plan_publish(
        arn,
        loaded.document,
        include_aws_validation=not args.local_validation_only,
        planned_tags=planned_tags,
    )
    return _execute_plan(service, plan, args, context)


def _edit(
    args: argparse.Namespace,
    service: IamManagedPolicyService,
    context: IamCommandContext,
) -> _configs.Result:
    arn = _reference(service, args.policy)
    exported = service.export_policy(arn)
    if exported.policy.arn.kind is PolicyKind.CUSTOMER_MANAGED:
        if exported.policy.ownership_status is OwnershipStatus.UNOWNED:
            return _error(
                "IAM_POLICY_UNMANAGED",
                "Policy is not Hacksaws-owned; review and adopt it before editing.",
                _configs.EXIT_POLICY,
            )
        if exported.policy.ownership_status is OwnershipStatus.UNSAFE:
            return _error(
                "IAM_POLICY_OWNERSHIP_UNSAFE",
                "Policy has conflicting or partial Hacksaws ownership tags; repair "
                "or release them before editing.",
                _configs.EXIT_POLICY,
            )
    selected = PolicyFormat(args.format)
    suffix = ".yaml" if selected is PolicyFormat.YAML else f".{selected.value}"
    with tempfile.TemporaryDirectory(prefix="hacksaws-edit-") as directory:
        path = Path(directory) / f"policy{suffix}"
        path.write_text(
            _serialize(exported.active_document, selected), encoding="utf-8"
        )
        editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "notepad.exe"
        command = [*shlex.split(editor, posix=os.name != "nt"), str(path)]
        completed = subprocess.run(command, check=False)  # noqa: S603
        if completed.returncode != 0:
            return _error(
                "IAM_POLICY_EDITOR_FAILED",
                f"Editor exited with status {completed.returncode}.",
            )
        loaded = load_policy_input(path)
    latest = service.get_policy(
        arn, include_document=True, include_versions=False, include_tags=False
    )
    if (
        latest.document is None
        or latest.default_version_id != exported.policy.default_version_id
        or policy_digest(latest.document) != policy_digest(exported.active_document)
    ):
        raise PolicyDriftError(
            "Policy changed while the editor was open; no update was made."
        )
    plan = service.plan_publish(
        arn,
        loaded.document,
        include_aws_validation=not args.local_validation_only,
        planned_tags=(
            reconcile_owned_tags(
                exported.policy,
                tuple(
                    tag
                    for tag in exported.policy.tags
                    if tag.key.casefold() not in RESERVED_TAGS
                ),
            )
            if exported.policy.arn.kind is PolicyKind.CUSTOMER_MANAGED
            and exported.policy.owned
            else None
        ),
    )
    return _execute_plan(service, plan, args, context)


def _versions(
    args: argparse.Namespace, service: IamManagedPolicyService
) -> _configs.Result:
    arn = _reference(service, args.policy)
    item = service.get_policy(
        arn, include_document=False, include_versions=True, include_tags=False
    )
    rows = [
        (
            version.version_id,
            "yes" if version.is_default else "no",
            version.created_at.isoformat() if version.created_at else "",
        )
        for version in item.versions
    ]
    data = {
        "arn": arn,
        "versions": [
            {
                "id": version.version_id,
                "default": version.is_default,
                "createdAt": version.created_at,
            }
            for version in item.versions
        ],
    }
    return _configs.Result(
        "IAM_POLICY_VERSIONS",
        _table(("Version", "Default", "Created"), rows),
        data=data,
    )


def _rollback(
    args: argparse.Namespace,
    service: IamManagedPolicyService,
    context: IamCommandContext,
) -> _configs.Result:
    arn = _reference(service, args.policy)
    return _execute_plan(
        service, service.plan_rollback(arn, args.version), args, context
    )


def _dependency_data(plan: PolicyDeletionPlan) -> dict[str, object]:
    dependencies = plan.dependencies
    return {
        "permissionUsers": [item.name for item in dependencies.permission_users],
        "permissionGroups": [item.name for item in dependencies.permission_groups],
        "permissionRoles": [item.name for item in dependencies.permission_roles],
        "boundaryUsers": [item.name for item in dependencies.boundary_users],
        "boundaryRoles": [item.name for item in dependencies.boundary_roles],
    }


def _delete(
    args: argparse.Namespace,
    service: IamManagedPolicyService,
    context: IamCommandContext,
) -> _configs.Result:
    arn = _reference(service, args.policy)
    plan = service.plan_delete(arn, cascade=args.cascade)
    preview = _policy_delete_plan_data(
        plan,
        context,
        allow_unmanaged=bool(args.allow_unmanaged),
        remove_boundaries=bool(args.remove_boundaries),
    )
    review = _policy_plan_text(preview)
    if preview["classification"] == "blocked":
        first_blocker = cast("list[Mapping[str, object]]", preview["blockers"])[0]
        blocked_code = {
            "UNMANAGED_POLICY": "IAM_POLICY_UNMANAGED",
            "BOUNDARY_OPT_IN_REQUIRED": "IAM_POLICY_BOUNDARIES",
            "CASCADE_REQUIRED": "IAM_POLICY_DEPENDENCIES",
        }.get(str(first_blocker.get("code")), "IAM_POLICY_DELETE_BLOCKED")
        return _configs.Result(
            blocked_code,
            review,
            _configs.EXIT_POLICY,
            "stderr",
            {"plan": preview, "result": {"classification": "blocked"}},
        )
    policy = service.get_policy(
        arn, include_document=True, include_versions=True, include_tags=True
    )
    dependencies = service.policy_dependencies(arn)
    if not policy.owned and not args.allow_unmanaged:
        return _error(
            "IAM_POLICY_UNMANAGED",
            "Policy ownership changed after deletion planning; refusing deletion "
            "without --allow-unmanaged after a fresh review.",
            _configs.EXIT_POLICY,
        )
    if (
        policy.policy_id != plan.policy.policy_id
        or policy.default_version_id != plan.policy.default_version_id
        or sorted((tag.key, tag.value) for tag in policy.tags)
        != sorted((tag.key, tag.value) for tag in plan.policy.tags)
        or tuple(version.version_id for version in policy.versions)
        != tuple(version.version_id for version in plan.policy.versions)
        or dependencies != plan.dependencies
    ):
        raise PolicyDriftError(
            "Policy or dependencies changed after deletion planning; review again."
        )
    if bool(getattr(args, "dry_run", False)):
        return _configs.Result(
            "IAM_POLICY_DELETE_DRY_RUN",
            "DRY RUN\n" + review,
            data={
                "plan": preview,
                "result": {
                    "classification": "dry-run",
                    "journalId": None,
                    "changed": False,
                },
            },
        )
    if not bool(getattr(args, "yes", False)):
        if _confirmation_unavailable():
            return _configs.Result(
                "IAM_POLICY_CONFIRMATION_REQUIRED",
                review + "\nConfirmation required: rerun with --yes.",
                _configs.EXIT_CANCELLED,
                "stderr",
                {
                    "plan": preview,
                    "result": {"classification": "confirmation-required"},
                },
            )
        if (
            input(review + f"\n\nType exactly {policy.name!r} to delete:\n> ").strip()
            != policy.name
        ):
            return _configs.Result(
                "IAM_POLICY_CANCELLED",
                "CANCELLED — Policy deletion declined. No changes have been made.",
                _configs.EXIT_CANCELLED,
                "stderr",
                {
                    "plan": preview,
                    "result": {"classification": "cancelled"},
                },
            )
    journal_id = _durable_reconcile(
        context,
        "delete",
        _absent_state(arn, policy.name, policy.path),
        _policy_state(policy, dependencies=dependencies),
    )
    operation_count = len(plan.operation.steps)
    console_url = _console_url(context, arn)
    message = (
        f"Deleted managed policy {policy.name}."
        f"\nApplied: {operation_count} ordered AWS operation(s); resource is absent."
        f"\nARN: {arn}\nPolicy ID: {policy.policy_id}"
        "\nVerified: IAM reported the policy absent."
        f"\nJournal: {journal_id} (completed; irreversible deletion receipt retained)."
        f"\nAWS Console: {console_url}"
    )
    result_data = {
        "classification": "deleted",
        "action": "delete",
        "arn": arn,
        "name": policy.name,
        "policyId": policy.policy_id,
        "operationsCompleted": operation_count,
        "journalId": journal_id,
        "verifiedAbsent": True,
        "recoveryAvailable": True,
        "consoleUrl": console_url,
    }
    return _configs.Result(
        "IAM_POLICY_DELETED",
        _output.safe_terminal_text(message),
        data={
            "plan": preview,
            "applied": preview["changes"],
            "result": result_data,
        },
    )


def _check(
    args: argparse.Namespace, service: IamManagedPolicyService
) -> _configs.Result:
    arn = _reference(service, args.policy)
    item = service.get_policy(
        arn, include_document=True, include_versions=False, include_tags=True
    )
    if item.document is None:
        raise PolicyServiceError("Managed policy has no active document.")
    report = service.validate_policy(
        item.document,
        name=item.name,
        path=item.path,
        tags=item.tags,
        include_aws=not args.local_validation_only,
    )
    probe_data: dict[str, object] | None = None
    messages = (
        [_diagnostic_text(report)]
        if report.diagnostics
        else ["Policy validation passed."]
    )
    if args.role:
        role_arn = (
            args.role
            if args.role.startswith("arn:")
            else f"arn:{service.partition}:iam::{service.account_id}:role/{args.role}"
        )
        config = _state.load_config()
        threshold = int(config.get("session", {}).get("packed_policy_warning", 80))
        probe = service.probe_assume_role(
            role_arn,
            item.document,
            options=AssumeRoleProbeOptions(packed_warning_threshold=threshold),
        )
        probe_data = {
            "roleArn": probe.role_arn,
            "assumedRoleArn": probe.assumed_role_arn,
            "expiresAt": probe.expires_at,
            "packedPolicySize": probe.packed_policy_size,
            "warning": probe.warning.message if probe.warning else None,
        }
        messages.append(f"Role assumability probe passed for {role_arn}.")
        if probe.warning:
            messages.append(f"Warning: {probe.warning.message}")
    data = {
        "arn": arn,
        "valid": report.valid,
        "diagnostics": _diagnostic_data(report),
        "probe": probe_data,
    }
    if not report.valid:
        return _configs.Result(
            "IAM_POLICY_CHECK_FAILED",
            "\n".join(filter(None, messages)),
            _configs.EXIT_POLICY,
            "stderr",
            data,
        )
    return _configs.Result(
        "IAM_POLICY_CHECK", "\n".join(filter(None, messages)), data=data
    )


def _tag(
    args: argparse.Namespace,
    service: IamManagedPolicyService,
    context: IamCommandContext,
) -> _configs.Result:
    if args.policy_tag_action not in {"list", "set", "remove"}:
        return _error(
            "IAM_POLICY_TAG_HELP",
            "Choose tag list, set, or remove.",
            _configs.EXIT_USAGE,
        )
    arn = _reference(service, args.policy)
    item = service.get_policy(
        arn,
        include_document=args.policy_tag_action != "list",
        include_versions=args.policy_tag_action != "list",
        include_tags=True,
    )
    if args.policy_tag_action == "list":
        rows = [(tag.key, tag.value) for tag in item.tags]
        return _configs.Result(
            "IAM_POLICY_TAG_LIST",
            _table(("Key", "Value"), rows),
            data={"arn": arn, "tags": {tag.key: tag.value for tag in item.tags}},
        )
    if item.arn.kind is PolicyKind.AWS_MANAGED:
        raise ImmutablePolicyError(f"AWS-managed policy {arn} is immutable.")
    if args.policy_tag_action == "set":
        tags = _tags(args.tag)
        if not tags:
            raise PolicyInputError("Tag set requires at least one --tag KEY=VALUE.")
        if any(tag.key.casefold().startswith(_RESERVED_PREFIX) for tag in tags):
            raise PolicyInputError(
                "Use adopt/release to change reserved Hacksaws ownership tags."
            )
        if bool(getattr(args, "dry_run", False)):
            return _configs.Result(
                "IAM_POLICY_TAG_DRY_RUN",
                f"DRY RUN — Set {len(tags)} tag(s) on {arn}.\n"
                "No AWS or local state was changed.",
                data={
                    "dryRun": True,
                    "action": "set",
                    "arn": arn,
                    "tags": {tag.key: tag.value for tag in tags},
                },
            )
        if not _confirm(args, f"Set {len(tags)} tag(s) on {arn}?"):
            return _error(
                "IAM_POLICY_CANCELLED", "Tag change cancelled.", _configs.EXIT_CANCELLED
            )
        values = {tag.key: tag.value for tag in item.tags}
        values.update({tag.key: tag.value for tag in tags})
        changed: object = {tag.key: tag.value for tag in tags}
    else:
        keys = args.keys
        if any(key.casefold().startswith(_RESERVED_PREFIX) for key in keys):
            raise PolicyInputError(
                "Use release to remove reserved Hacksaws ownership tags."
            )
        if bool(getattr(args, "dry_run", False)):
            return _configs.Result(
                "IAM_POLICY_TAG_DRY_RUN",
                f"DRY RUN — Remove {len(keys)} tag(s) from {arn}.\n"
                "No AWS or local state was changed.",
                data={
                    "dryRun": True,
                    "action": "remove",
                    "arn": arn,
                    "keys": list(keys),
                },
            )
        if not _confirm(args, f"Remove {len(keys)} tag(s) from {arn}?"):
            return _error(
                "IAM_POLICY_CANCELLED", "Tag change cancelled.", _configs.EXIT_CANCELLED
            )
        values = {tag.key: tag.value for tag in item.tags if tag.key not in set(keys)}
        changed = keys
    latest = service.get_policy(
        arn, include_document=True, include_versions=True, include_tags=True
    )
    if sorted((tag.key, tag.value) for tag in latest.tags) != sorted(
        (tag.key, tag.value) for tag in item.tags
    ):
        raise PolicyDriftError(
            f"Policy tags for {arn} changed after planning; review the change again."
        )
    desired = replace(
        latest,
        tags=tuple(Tag(key, value) for key, value in sorted(values.items())),
    )
    dependencies = service.policy_dependencies(arn)
    journal_id = _durable_reconcile(
        context,
        f"tag-{args.policy_tag_action}",
        _policy_state(desired, dependencies=dependencies),
        _policy_state(latest, dependencies=dependencies),
    )
    return _configs.Result(
        "IAM_POLICY_TAG_CHANGED",
        f"Updated tags on {arn}.",
        data={
            "arn": arn,
            "action": args.policy_tag_action,
            "changed": changed,
            "journalId": journal_id,
        },
    )


def _ownership(
    args: argparse.Namespace,
    service: IamManagedPolicyService,
    context: IamCommandContext,
) -> _configs.Result:
    arn = _reference(service, args.policy)
    if args.policy_action == "adopt":
        plan = service.plan_adopt(arn, uuid.uuid4().hex, user_tags=_tags(args.tag))
    else:
        plan = service.plan_release(arn)
    preview = _ownership_plan_data(plan, context, args.policy_action)
    review = _policy_plan_text(preview)
    if bool(getattr(args, "dry_run", False)):
        return _configs.Result(
            "IAM_POLICY_OWNERSHIP_DRY_RUN",
            "DRY RUN\n" + review,
            data={
                "plan": preview,
                "result": {
                    "classification": "dry-run",
                    "journalId": None,
                    "changed": False,
                },
            },
        )
    if plan.operation.steps and not bool(getattr(args, "yes", False)):
        if _confirmation_unavailable():
            return _configs.Result(
                "IAM_POLICY_CONFIRMATION_REQUIRED",
                review + "\nConfirmation required: rerun with --yes.",
                _configs.EXIT_CANCELLED,
                "stderr",
                {
                    "plan": preview,
                    "result": {"classification": "confirmation-required"},
                },
            )
        if (
            input(review + "\n\nType exactly 'yes' to apply this plan:\n> ")
            .strip()
            .casefold()
            != "yes"
        ):
            return _configs.Result(
                "IAM_POLICY_CANCELLED",
                "CANCELLED — Ownership change declined. No changes have been made.",
                _configs.EXIT_CANCELLED,
                "stderr",
                {
                    "plan": preview,
                    "result": {"classification": "cancelled"},
                },
            )
    current = service.get_policy(
        arn, include_document=True, include_versions=True, include_tags=True
    )
    if sorted((tag.key, tag.value) for tag in current.tags) != sorted(
        (tag.key, tag.value) for tag in plan.policy.tags
    ):
        raise PolicyDriftError(
            f"Policy tags for {arn} changed after planning; review the change again."
        )
    values = {tag.key: tag.value for tag in current.tags}
    values.update({tag.key: tag.value for tag in plan.add})
    for key in plan.remove:
        values.pop(key, None)
    desired = replace(
        current,
        tags=tuple(Tag(key, value) for key, value in sorted(values.items())),
    )
    journal_id = None
    if plan.operation.steps:
        dependencies = service.policy_dependencies(arn)
        journal_id = _durable_reconcile(
            context,
            args.policy_action,
            _policy_state(desired, dependencies=dependencies),
            _policy_state(current, dependencies=dependencies),
        )
    result_data = {
        "classification": "applied" if journal_id else "no-change",
        "action": args.policy_action,
        "arn": arn,
        "policyId": desired.policy_id,
        "owned": desired.owned,
        "journalId": journal_id,
        "verified": True,
        "recoveryAvailable": journal_id is not None,
    }
    ownership_verb = {"adopt": "Adopted", "release": "Released"}[args.policy_action]
    message = (
        f"{ownership_verb} ownership for managed policy {desired.name}."
        if journal_id
        else f"No change — managed policy {desired.name} ownership already matches."
    )
    message += (
        f"\nARN: {arn}\nPolicy ID: {desired.policy_id}"
        f"\nVerified: IAM read-back matched the planned tags."
        + (
            f"\nJournal: {journal_id} (completed; recovery receipt available)."
            if journal_id
            else "\nJournal: none (no mutation was required)."
        )
    )
    return _configs.Result(
        "IAM_POLICY_OWNERSHIP_CHANGED" if journal_id else "IAM_POLICY_NO_CHANGE",
        _output.safe_terminal_text(message),
        data={
            "plan": preview,
            "applied": preview["changes"],
            "result": result_data,
        },
    )


def dispatch(
    args: argparse.Namespace, context: IamCommandContext
) -> _configs.Result | None:
    """Dispatch one managed-policy leaf and normalize failures for JSON envelopes."""
    normalize_arguments(args)
    action = getattr(args, "policy_action", None)
    if action is None:
        return None
    handlers = {
        "list": _list,
        "get": _get,
        "export": _export,
        "versions": _versions,
        "check": _check,
    }
    try:
        service = _service(context)
        if action == "tag":
            return _tag(args, service, context)
        if action == "create":
            return _create(args, service, context)
        if action == "update":
            return _update(args, service, context)
        if action == "edit":
            return _edit(args, service, context)
        if action == "rollback":
            return _rollback(args, service, context)
        if action == "delete":
            return _delete(args, service, context)
        if action in {"adopt", "release"}:
            return _ownership(args, service, context)
        handler = handlers.get(action)
        if handler is None:
            return _error(
                "IAM_POLICY_HELP",
                "Choose a managed-policy command.",
                _configs.EXIT_USAGE,
            )
        return handler(args, service)
    except PolicyValidationError as error:
        return _configs.Result(
            "IAM_POLICY_VALIDATION_FAILED",
            _diagnostic_text(error.report),
            _configs.EXIT_POLICY,
            "stderr",
            {"diagnostics": _diagnostic_data(error.report)},
        )
    except PolicyDriftError as error:
        return _error("IAM_POLICY_DRIFT", str(error), _configs.EXIT_POLICY)
    except PackedPolicyProbeError as error:
        diagnostic = error.diagnostic
        return _configs.Result(
            "IAM_POLICY_PACKED_TOO_LARGE",
            diagnostic.message,
            _configs.EXIT_POLICY,
            "stderr",
            {
                "packedPolicySize": diagnostic.packed_policy_size,
                "repairs": [asdict(item) for item in diagnostic.repairs],
            },
        )
    except ImmutablePolicyError as error:
        return _error("IAM_POLICY_IMMUTABLE", str(error), _configs.EXIT_POLICY)
    except (PolicyInputError, PolicyServiceError, _configs.OperationalError) as error:
        return _error("IAM_POLICY_ERROR", str(error), _configs.EXIT_POLICY)
    except (
        BotoCoreError,
        ClientError,
        OSError,
        UnicodeError,
        subprocess.SubprocessError,
    ) as error:
        return _error("IAM_POLICY_AWS_ERROR", str(error))
