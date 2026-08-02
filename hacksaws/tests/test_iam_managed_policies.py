"""Focused offline tests for the pure IAM managed-policy service layer."""

# ruff: noqa: D102, D107

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from typing import cast
from unittest.mock import patch
from urllib.parse import quote

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from hacksaws import _configs
from hacksaws import _iam_managed_policies as managed
from hacksaws import _iam_policy_cli as policy_cli
from hacksaws import _iam_policy_documents as documents
from hacksaws import _iam_recovery

ACCOUNT = "123456789012"
PARTITION = "aws"
ARN = f"arn:{PARTITION}:iam::{ACCOUNT}:policy/hacksaws/AgentRead"
ROLE_ARN = f"arn:{PARTITION}:iam::{ACCOUNT}:role/AgentSession"
NOW = datetime(2026, 8, 1, tzinfo=UTC)
POLICY: dict[str, documents.JsonValue] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:GetLogEvents",
            "Resource": "*",
        }
    ],
}
CHANGED: dict[str, documents.JsonValue] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["logs:GetLogEvents", "logs:FilterLogEvents"],
            "Resource": "*",
        }
    ],
}


class StatefulIam:
    """Small stateful IAM fake exercising service concurrency semantics."""

    def __init__(self, *, existing: bool = True) -> None:
        self.exists = existing
        self.default = "v1"
        self.versions: dict[str, tuple[dict[str, documents.JsonValue], datetime]] = {
            "v1": (POLICY, NOW)
        }
        self.tags: dict[str, str] = {
            "hacksaws:managed-by": "hacksaws",
            "hacksaws:resource-id": "resource-1",
            "hacksaws:resource-kind": "managed-policy",
        }
        self.permission_users: dict[str, str] = {}
        self.permission_groups: dict[str, str] = {}
        self.permission_roles: dict[str, str] = {}
        self.boundary_users: dict[str, str] = {}
        self.boundary_roles: dict[str, str] = {}
        self.user_identities: dict[str, str] = {}
        self.group_identities: dict[str, str] = {}
        self.role_identities: dict[str, str] = {}
        self.calls: list[str] = []

    def _metadata(self) -> dict[str, object]:
        if not self.exists:
            raise self._not_found()
        return {
            "Arn": ARN,
            "PolicyId": "ANPA12345678901234567",
            "PolicyName": "AgentRead",
            "Path": "/hacksaws/",
            "DefaultVersionId": self.default,
            "AttachmentCount": len(self.permission_users)
            + len(self.permission_groups)
            + len(self.permission_roles),
            "PermissionsBoundaryUsageCount": len(self.boundary_users)
            + len(self.boundary_roles),
        }

    @staticmethod
    def _not_found() -> ClientError:
        return ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "not found"}},
            "GetPolicy",
        )

    def list_policies(self, **kwargs: object) -> dict[str, object]:
        scope = kwargs.get("Scope")
        policies = [self._metadata()] if self.exists and scope != "AWS" else []
        return {"Policies": policies, "IsTruncated": False}

    def get_policy(self, **kwargs: object) -> dict[str, object]:
        return {"Policy": self._metadata()}

    def get_policy_version(self, **kwargs: object) -> dict[str, object]:
        version_id = cast("str", kwargs["VersionId"])
        document, created = self.versions[version_id]
        return {
            "PolicyVersion": {
                "Document": document,
                "VersionId": version_id,
                "IsDefaultVersion": version_id == self.default,
                "CreateDate": created,
            }
        }

    def list_policy_versions(self, **kwargs: object) -> dict[str, object]:
        return {
            "Versions": [
                {
                    "VersionId": version_id,
                    "IsDefaultVersion": version_id == self.default,
                    "CreateDate": created,
                }
                for version_id, (_, created) in self.versions.items()
            ],
            "IsTruncated": False,
        }

    def create_policy(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("CreatePolicy")
        self.exists = True
        self.default = "v1"
        self.versions = {
            "v1": (
                json.loads(cast("str", kwargs["PolicyDocument"])),
                NOW,
            )
        }
        self.tags = {
            cast("str", item["Key"]): cast("str", item["Value"])
            for item in cast("list[dict[str, object]]", kwargs["Tags"])
        }
        return {"Policy": self._metadata()}

    def create_policy_version(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("CreatePolicyVersion")
        next_number = max(int(key[1:]) for key in self.versions) + 1
        version_id = f"v{next_number}"
        self.versions[version_id] = (
            json.loads(cast("str", kwargs["PolicyDocument"])),
            NOW,
        )
        if kwargs.get("SetAsDefault") is True:
            self.default = version_id
        return {
            "PolicyVersion": {
                "VersionId": version_id,
                "IsDefaultVersion": True,
                "CreateDate": NOW,
            }
        }

    def set_default_policy_version(self, **kwargs: object) -> None:
        self.calls.append("SetDefaultPolicyVersion")
        self.default = cast("str", kwargs["VersionId"])

    def delete_policy_version(self, **kwargs: object) -> None:
        self.calls.append("DeletePolicyVersion")
        del self.versions[cast("str", kwargs["VersionId"])]

    def list_policy_tags(self, **kwargs: object) -> dict[str, object]:
        return {
            "Tags": [{"Key": key, "Value": value} for key, value in self.tags.items()],
            "IsTruncated": False,
        }

    def tag_policy(self, **kwargs: object) -> None:
        self.calls.append("TagPolicy")
        for item in cast("list[dict[str, object]]", kwargs["Tags"]):
            self.tags[cast("str", item["Key"])] = cast("str", item["Value"])

    def untag_policy(self, **kwargs: object) -> None:
        self.calls.append("UntagPolicy")
        for key in cast("list[str]", kwargs["TagKeys"]):
            self.tags.pop(key, None)

    def list_entities_for_policy(self, **kwargs: object) -> dict[str, object]:
        boundary = kwargs.get("PolicyUsageFilter") == "PermissionsBoundary"
        users = self.boundary_users if boundary else self.permission_users
        roles = self.boundary_roles if boundary else self.permission_roles
        groups = {} if boundary else self.permission_groups
        return {
            "PolicyUsers": [
                {"UserName": name, "UserId": entity_id}
                for entity_id, name in users.items()
            ],
            "PolicyGroups": [
                {"GroupName": name, "GroupId": entity_id}
                for entity_id, name in groups.items()
            ],
            "PolicyRoles": [
                {"RoleName": name, "RoleId": entity_id}
                for entity_id, name in roles.items()
            ],
            "IsTruncated": False,
        }

    def detach_user_policy(self, **kwargs: object) -> None:
        self.calls.append("DetachUserPolicy")
        name = cast("str", kwargs["UserName"])
        self.user_identities.update(
            {value: key for key, value in self.permission_users.items()}
        )
        self.permission_users = {
            key: value for key, value in self.permission_users.items() if value != name
        }

    def attach_user_policy(self, **kwargs: object) -> None:
        self.calls.append("AttachUserPolicy")
        name = cast("str", kwargs["UserName"])
        self.permission_users[self.user_identities[name]] = name

    def detach_group_policy(self, **kwargs: object) -> None:
        self.calls.append("DetachGroupPolicy")
        name = cast("str", kwargs["GroupName"])
        self.group_identities.update(
            {value: key for key, value in self.permission_groups.items()}
        )
        self.permission_groups = {
            key: value for key, value in self.permission_groups.items() if value != name
        }

    def attach_group_policy(self, **kwargs: object) -> None:
        self.calls.append("AttachGroupPolicy")
        name = cast("str", kwargs["GroupName"])
        self.permission_groups[self.group_identities[name]] = name

    def detach_role_policy(self, **kwargs: object) -> None:
        self.calls.append("DetachRolePolicy")
        name = cast("str", kwargs["RoleName"])
        self.role_identities.update(
            {value: key for key, value in self.permission_roles.items()}
        )
        self.permission_roles = {
            key: value for key, value in self.permission_roles.items() if value != name
        }

    def attach_role_policy(self, **kwargs: object) -> None:
        self.calls.append("AttachRolePolicy")
        name = cast("str", kwargs["RoleName"])
        self.permission_roles[self.role_identities[name]] = name

    def delete_user_permissions_boundary(self, **kwargs: object) -> None:
        self.calls.append("DeleteUserPermissionsBoundary")
        name = cast("str", kwargs["UserName"])
        self.user_identities.update(
            {value: key for key, value in self.boundary_users.items()}
        )
        self.boundary_users = {
            key: value for key, value in self.boundary_users.items() if value != name
        }

    def put_user_permissions_boundary(self, **kwargs: object) -> None:
        self.calls.append("PutUserPermissionsBoundary")
        name = cast("str", kwargs["UserName"])
        self.boundary_users[self.user_identities[name]] = name

    def delete_role_permissions_boundary(self, **kwargs: object) -> None:
        self.calls.append("DeleteRolePermissionsBoundary")
        name = cast("str", kwargs["RoleName"])
        self.role_identities.update(
            {value: key for key, value in self.boundary_roles.items()}
        )
        self.boundary_roles = {
            key: value for key, value in self.boundary_roles.items() if value != name
        }

    def put_role_permissions_boundary(self, **kwargs: object) -> None:
        self.calls.append("PutRolePermissionsBoundary")
        name = cast("str", kwargs["RoleName"])
        self.boundary_roles[self.role_identities[name]] = name

    def get_user(self, **kwargs: object) -> dict[str, object]:
        name = cast("str", kwargs["UserName"])
        return {"User": {"UserName": name, "UserId": self.user_identities[name]}}

    def get_group(self, **kwargs: object) -> dict[str, object]:
        name = cast("str", kwargs["GroupName"])
        return {
            "Group": {"GroupName": name, "GroupId": self.group_identities[name]},
            "Users": [],
            "IsTruncated": False,
        }

    def get_role(self, **kwargs: object) -> dict[str, object]:
        name = cast("str", kwargs["RoleName"])
        return {"Role": {"RoleName": name, "RoleId": self.role_identities[name]}}

    def delete_policy(self, **kwargs: object) -> None:
        self.calls.append("DeletePolicy")
        self.exists = False


class FakeSts:
    """STS fake that records probes but never retains credentials."""

    def __init__(self) -> None:
        self.assume_request: dict[str, object] | None = None
        self.assume_error: ClientError | None = None

    def get_caller_identity(self, **kwargs: object) -> dict[str, object]:
        return {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/tester",
            "UserId": "AIDA12345678901234567",
        }

    def assume_role(self, **kwargs: object) -> dict[str, object]:
        self.assume_request = dict(kwargs)
        if self.assume_error is not None:
            raise self.assume_error
        return {
            "AssumedRoleUser": {
                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/AgentSession/probe",
                "AssumedRoleId": "AROA12345678901234567:probe",
            },
            "Credentials": {
                "AccessKeyId": "ASIAEXAMPLE",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": NOW,
            },
            "PackedPolicySize": 85,
        }


def make_service(
    iam: StatefulIam,
    sts: FakeSts | None = None,
    *,
    retry: managed.RetryPolicy | None = None,
) -> managed.IamManagedPolicyService:
    return managed.IamManagedPolicyService(
        iam,
        sts or FakeSts(),
        None,
        managed.PolicyServiceOptions(
            ACCOUNT,
            PARTITION,
            retry=retry or managed.RetryPolicy((0.0,)),
        ),
        sleeper=lambda _delay: None,
    )


def test_summary_tags_use_one_metadata_read_without_documents_or_versions() -> None:
    iam = StatefulIam()
    service = make_service(iam)
    summary = service.list_policies(
        scope=managed.PolicyScope.LOCAL,
        path_prefix=managed.DEFAULT_PATH,
        include_tags=False,
    )[0]

    metadata_reads = 0
    read_order: list[str] = []
    original_get = iam.get_policy
    original_tags = iam.list_policy_tags

    def tracked_get(**kwargs: object) -> dict[str, object]:
        nonlocal metadata_reads
        metadata_reads += 1
        read_order.append("metadata")
        return original_get(**kwargs)

    def tracked_tags(**kwargs: object) -> dict[str, object]:
        read_order.append("tags")
        return original_tags(**kwargs)

    def unexpected_read(**_kwargs: object) -> dict[str, object]:
        pytest.fail("summary reads must not hydrate policy details")

    iam.get_policy = tracked_get  # type: ignore[method-assign]
    iam.list_policy_tags = tracked_tags  # type: ignore[method-assign]
    iam.get_policy_version = unexpected_read  # type: ignore[method-assign]
    iam.list_policy_versions = unexpected_read  # type: ignore[method-assign]
    hydrated = service.get_policy_summary(summary)

    assert metadata_reads == 1
    assert read_order == ["tags", "metadata"]
    assert hydrated.owned
    assert hydrated.document is None
    assert hydrated.versions == ()


def test_known_arn_dependencies_skip_policy_metadata_and_document_reads() -> None:
    iam = StatefulIam()
    service = make_service(iam)

    def unexpected_read(**_kwargs: object) -> dict[str, object]:
        pytest.fail("known-ARN dependency reads must not hydrate policy metadata")

    iam.get_policy = unexpected_read  # type: ignore[method-assign]
    iam.get_policy_version = unexpected_read  # type: ignore[method-assign]
    iam.list_policy_versions = unexpected_read  # type: ignore[method-assign]

    assert service.policy_dependencies_for_arn(ARN).empty


def test_policy_summary_metadata_fence_detects_replacement_during_tag_read() -> None:
    class ReplacedDuringTags(StatefulIam):
        def __init__(self) -> None:
            super().__init__()
            self.policy_id = "ANPA-before-tag-read"

        def _metadata(self) -> dict[str, object]:
            metadata = super()._metadata()
            metadata["PolicyId"] = self.policy_id
            return metadata

        def list_policy_tags(self, **kwargs: object) -> dict[str, object]:
            response = super().list_policy_tags(**kwargs)
            self.policy_id = "ANPA-after-tag-read"
            return response

    iam = ReplacedDuringTags()
    service = make_service(iam)
    listed = service.list_policies(
        scope=managed.PolicyScope.LOCAL,
        path_prefix=managed.DEFAULT_PATH,
        include_tags=False,
    )[0]

    current = service.get_policy_summary(listed)

    assert listed.policy_id == "ANPA-before-tag-read"
    assert current.policy_id == "ANPA-after-tag-read"
    assert current.owned


def test_strict_policy_input_formats_metadata_and_canonicalization(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "policy.yaml"
    nested.write_text(
        "metadata:\n  name: Read\n  tags:\n    Team: Agents\n"
        "policy:\n  Version: '2012-10-17'\n  Statement: []\n",
        encoding="utf-8",
    )
    loaded = documents.load_policy_input(
        nested,
        metadata_mode=documents.MetadataMode.NESTED,
    )
    assert loaded.metadata.name == "Read"
    assert loaded.metadata.tags == (("Team", "Agents"),)
    assert loaded.canonical_json == '{"Statement":[],"Version":"2012-10-17"}'

    policy = tmp_path / "plain.toml"
    policy.write_text('Version="2012-10-17"\nStatement=[]\n', encoding="utf-8")
    sidecar = tmp_path / "meta.json"
    sidecar.write_text('{"description":"read only"}', encoding="utf-8")
    loaded = documents.load_policy_input(
        policy,
        metadata_mode=documents.MetadataMode.SIDECAR,
        sidecar=sidecar,
    )
    assert loaded.metadata.description == "read only"
    assert loaded.sidecar == sidecar


@pytest.mark.parametrize(
    ("suffix", "contents", "match"),
    [
        (".json", '{"Version":"x","Version":"y"}', "Duplicate JSON"),
        (".yaml", "Version: x\nVersion: y\n", "Duplicate YAML"),
        (".toml", "Version=nan\nStatement=[]\n", "Non-finite"),
    ],
)
def test_strict_policy_loader_rejects_lossy_inputs(
    tmp_path: Path,
    suffix: str,
    contents: str,
    match: str,
) -> None:
    path = tmp_path / f"bad{suffix}"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(documents.PolicyInputError, match=match):
        documents.load_policy_input(path)


def test_iam_document_decode_and_semantic_compare() -> None:
    encoded = quote(json.dumps(POLICY))
    assert documents.decode_iam_document(encoded) == POLICY
    reordered = {"Statement": POLICY["Statement"], "Version": "2012-10-17"}
    assert documents.policy_digest(reordered) == documents.policy_digest(POLICY)


def test_resolution_namespaces_ambiguity_and_exact_account_checks() -> None:
    iam = StatefulIam()
    service = make_service(iam)
    assert service.resolve("custom:AgentRead").selected is not None
    assert service.resolve("owned:AgentRead").selected is not None

    original_list = iam.list_policies

    def list_with_aws(**kwargs: object) -> dict[str, object]:
        result = original_list(**kwargs)
        if kwargs.get("Scope") == "AWS":
            policy = dict(iam._metadata())
            policy["Arn"] = "arn:aws:iam::aws:policy/AgentRead"
            policy["Path"] = "/"
            result["Policies"] = [policy]
        return result

    iam.list_policies = list_with_aws  # type: ignore[method-assign]
    ambiguous = service.resolve("AgentRead")
    assert ambiguous.ambiguous
    assert ambiguous.selected is None
    with pytest.raises(managed.PolicyServiceError, match="account"):
        service.resolve("arn:aws:iam::999999999999:policy/AgentRead")


def test_list_policies_uses_marker_pagination_with_stubber() -> None:
    client = boto3.client(
        "iam",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",  # noqa: S106
    )
    first = {
        "Policies": [],
        "IsTruncated": True,
        "Marker": "next",
    }
    second = {
        "Policies": [
            {
                "PolicyName": "AgentRead",
                "PolicyId": "ANPA12345678901234567",
                "Arn": ARN,
                "Path": "/hacksaws/",
                "DefaultVersionId": "v1",
                "AttachmentCount": 0,
                "PermissionsBoundaryUsageCount": 0,
                "IsAttachable": True,
                "CreateDate": NOW,
                "UpdateDate": NOW,
            }
        ],
        "IsTruncated": False,
    }
    with Stubber(client) as stubber:
        stubber.add_response("list_policies", first, {"Scope": "Local"})
        stubber.add_response(
            "list_policies",
            second,
            {"Scope": "Local", "Marker": "next"},
        )
        service = managed.IamManagedPolicyService(
            client,
            FakeSts(),
            None,
            managed.PolicyServiceOptions(ACCOUNT, PARTITION),
        )
        records = service.list_policies(scope=managed.PolicyScope.LOCAL)
    assert [item.arn.value for item in records] == [ARN]


def test_validation_aggregates_local_and_paginated_aws_findings() -> None:
    class Analyzer:
        def validate_policy(self, **kwargs: object) -> dict[str, object]:
            if "nextToken" not in kwargs:
                return {
                    "findings": [
                        {
                            "findingType": "ERROR",
                            "issueCode": "AWS_ERROR",
                            "findingDetails": "bad action",
                        }
                    ],
                    "nextToken": "next",
                }
            return {
                "findings": [
                    {
                        "findingType": "SUGGESTION",
                        "issueCode": "AWS_HINT",
                        "findingDetails": "consider scope",
                    }
                ]
            }

    iam = StatefulIam()
    service = managed.IamManagedPolicyService(
        iam,
        FakeSts(),
        Analyzer(),
        managed.PolicyServiceOptions(ACCOUNT, PARTITION),
    )
    bad: dict[str, documents.JsonValue] = {"Statement": "bad"}
    report = service.validate_policy(
        bad,
        name="not valid!",
        path="bad",
        tags=(managed.Tag("aws:bad", "x"),),
    )
    codes = {item.code for item in report.diagnostics}
    assert {
        "INVALID_POLICY_NAME",
        "INVALID_POLICY_PATH",
        "INVALID_STATEMENT",
        "RESERVED_AWS_TAG_PREFIX",
        "AWS_ERROR",
        "AWS_HINT",
    } <= codes
    assert not report.valid
    assert report.repairs


def test_caller_attribution_and_repeat_user_tags() -> None:
    iam = StatefulIam()
    service = make_service(iam)
    tags = service.ownership_tags(
        "abc",
        (managed.Tag("Team", "Agents"), managed.Tag("Purpose", "Debug")),
        created_at=NOW,
    )
    values = {tag.key: tag.value for tag in tags}
    assert values["Team"] == "Agents"
    assert values["hacksaws:created-by"].endswith(":user/tester")
    assert values["hacksaws:ownership-origin"] == "created"
    with pytest.raises(managed.PolicyServiceError, match="reserved"):
        service.ownership_tags(
            "abc",
            (managed.Tag("HACKSAWS:MANAGED-BY", "other"),),
        )


def test_create_and_noop_publish() -> None:
    iam = StatefulIam(existing=False)
    service = make_service(iam)
    plan = service.plan_create(
        "AgentRead",
        POLICY,
        options=managed.CreatePolicyOptions(
            resource_id="fixed",
            include_aws_validation=False,
        ),
    )
    result = service.execute_change(plan)
    assert result.action is managed.ChangeAction.CREATE
    assert result.policy.document == POLICY
    assert "CreatePolicy" in iam.calls

    noop = service.plan_publish(ARN, POLICY, include_aws_validation=False)
    assert noop.operation.action is managed.ChangeAction.NOOP
    assert service.execute_change(noop).action is managed.ChangeAction.NOOP


def test_five_version_update_prunes_oldest_nondefault_and_retains_rollback() -> None:
    iam = StatefulIam()
    iam.versions = {
        f"v{number}": (POLICY, NOW.replace(day=number)) for number in range(1, 6)
    }
    iam.default = "v5"
    service = make_service(iam)
    plan = service.plan_publish(ARN, CHANGED, include_aws_validation=False)
    assert plan.prune_version_id == "v1"
    assert plan.expected_default_version_id == "v5"
    result = service.execute_change(plan)
    assert result.action is managed.ChangeAction.UPDATE
    assert iam.default == "v6"
    assert "v1" not in iam.versions
    assert "v5" in iam.versions
    assert iam.calls[:2] == ["DeletePolicyVersion", "CreatePolicyVersion"]


def test_unowned_five_version_policy_refuses_automatic_pruning() -> None:
    iam = StatefulIam()
    iam.tags = {}
    iam.versions = {
        f"v{number}": (POLICY, NOW.replace(day=number)) for number in range(1, 6)
    }
    iam.default = "v5"
    service = make_service(iam)
    plan = service.plan_publish(ARN, CHANGED, include_aws_validation=False)
    assert not plan.validation.valid
    with pytest.raises(managed.PolicyValidationError):
        service.execute_change(plan)


def test_publish_detects_default_document_drift() -> None:
    iam = StatefulIam()
    service = make_service(iam)
    plan = service.plan_publish(ARN, CHANGED, include_aws_validation=False)
    iam.versions["v1"] = (CHANGED, NOW)
    with pytest.raises(managed.PolicyDriftError):
        service.execute_change(plan)
    assert "CreatePolicyVersion" not in iam.calls


def test_rollback_switches_default_and_keeps_versions() -> None:
    iam = StatefulIam()
    iam.versions["v2"] = (CHANGED, NOW.replace(day=2))
    iam.default = "v2"
    service = make_service(iam)
    plan = service.plan_rollback(ARN, "v1")
    result = service.execute_change(plan)
    assert result.action is managed.ChangeAction.ROLLBACK
    assert iam.default == "v1"
    assert set(iam.versions) == {"v1", "v2"}


def test_adopt_release_and_tag_drift() -> None:
    iam = StatefulIam()
    iam.tags = {"Existing": "yes"}
    service = make_service(iam)
    adopt = service.plan_adopt(
        ARN,
        "adopted",
        user_tags=(managed.Tag("Team", "Agents"),),
    )
    result = service.execute_tag_change(adopt)
    assert result.policy is not None
    assert result.policy.owned
    release = service.plan_release(ARN)
    iam.tags["drift"] = "true"
    with pytest.raises(managed.PolicyDriftError):
        service.execute_tag_change(release)
    del iam.tags["drift"]
    released = service.execute_tag_change(release)
    assert released.policy is not None
    assert not released.policy.owned
    assert iam.tags["Existing"] == "yes"


def test_dependency_complete_delete_requires_cascade_then_executes() -> None:
    iam = StatefulIam()
    iam.permission_users = {"U1": "alice"}
    iam.permission_groups = {"G1": "agents"}
    iam.permission_roles = {"R1": "reader"}
    iam.boundary_users = {"U2": "bob"}
    iam.boundary_roles = {"R2": "bounded"}
    iam.versions["v2"] = (CHANGED, NOW.replace(day=2))
    service = make_service(iam)
    blocked = service.plan_delete(ARN)
    assert not blocked.executable
    with pytest.raises(managed.PolicyValidationError):
        service.execute_delete(blocked)

    plan = service.plan_delete(ARN, cascade=True)
    assert plan.executable
    assert {
        "DetachUserPolicy",
        "DetachGroupPolicy",
        "DetachRolePolicy",
        "DeleteUserPermissionsBoundary",
        "DeleteRolePermissionsBoundary",
        "DeletePolicyVersion",
        "DeletePolicy",
    } <= {step.operation for step in plan.operation.steps}
    result = service.execute_delete(plan)
    assert result.policy is None
    assert not iam.exists


def test_aws_managed_policy_is_immutable() -> None:
    iam = StatefulIam()
    service = make_service(iam)
    customer = service.get_policy(ARN)
    aws_policy = managed.ManagedPolicyRecord(
        arn=managed.ManagedPolicyArn.parse("arn:aws:iam::aws:policy/ReadOnlyAccess"),
        policy_id=customer.policy_id,
        name="ReadOnlyAccess",
        path="/",
        default_version_id="v1",
        attachment_count=0,
        permissions_boundary_usage_count=0,
    )
    with pytest.raises(managed.ImmutablePolicyError):
        service._require_mutable(aws_policy)


def test_assume_role_probe_returns_no_credentials_and_warns() -> None:
    iam = StatefulIam()
    sts = FakeSts()
    service = make_service(iam, sts)
    result = service.probe_assume_role(ROLE_ARN, POLICY)
    assert result.packed_policy_size == 85
    assert result.warning is not None
    assert not hasattr(result, "credentials")
    assert sts.assume_request is not None
    assert json.loads(cast("str", sts.assume_request["Policy"])) == POLICY


def test_packed_policy_failure_is_actionable() -> None:
    iam = StatefulIam()
    sts = FakeSts()
    sts.assume_error = ClientError(
        {
            "Error": {
                "Code": "PackedPolicyTooLarge",
                "Message": "PackedPolicySize exceeded 104% of the allowed space",
            }
        },
        "AssumeRole",
    )
    service = make_service(iam, sts)
    with pytest.raises(managed.PackedPolicyProbeError) as captured:
        service.probe_assume_role(ROLE_ARN, POLICY)
    assert captured.value.diagnostic.packed_policy_size == 104
    assert len(captured.value.diagnostic.repairs) == 3


def test_bounded_eventual_consistency_retries_no_such_entity() -> None:
    class EventuallyVisibleIam(StatefulIam):
        def __init__(self) -> None:
            super().__init__(existing=False)
            self.remaining_failures = 0

        def create_policy(self, **kwargs: object) -> dict[str, object]:
            response = super().create_policy(**kwargs)
            self.remaining_failures = 1
            return response

        def get_policy(self, **kwargs: object) -> dict[str, object]:
            if self.remaining_failures:
                self.remaining_failures -= 1
                raise self._not_found()
            return super().get_policy(**kwargs)

    iam = EventuallyVisibleIam()
    delays: list[float] = []
    service = managed.IamManagedPolicyService(
        iam,
        FakeSts(),
        None,
        managed.PolicyServiceOptions(
            ACCOUNT,
            PARTITION,
            retry=managed.RetryPolicy((0.0, 0.5)),
        ),
        sleeper=delays.append,
    )
    plan = service.plan_create(
        "AgentRead",
        POLICY,
        options=managed.CreatePolicyOptions(include_aws_validation=False),
    )
    assert service.execute_change(plan).policy.document == POLICY
    assert delays == [0.5]


def test_policy_document_validation_edge_cases(tmp_path: Path) -> None:
    with pytest.raises(documents.PolicyInputError, match="Unsupported"):
        documents.PolicyFormat.from_path(tmp_path / "policy.txt")
    with pytest.raises(documents.PolicyInputError, match="must be an object"):
        documents.decode_iam_document("[]")
    with pytest.raises(documents.PolicyInputError, match="invalid policy"):
        documents.decode_iam_document("%7Bbad")
    assert documents.decode_iam_document({"Version": "x"}) == {"Version": "x"}

    source = tmp_path / "source.json"
    source.write_text(json.dumps(POLICY), encoding="utf-8")
    assert documents.load_policy_input(source).digest == documents.policy_digest(POLICY)
    with pytest.raises(documents.PolicyInputError, match="Unable to read"):
        documents.load_policy_input(tmp_path / "missing.json")


@pytest.mark.parametrize(
    ("metadata", "match"),
    [
        ({"unknown": "x"}, "Unknown policy metadata"),
        ({"name": 1}, "must be a string"),
        ({"tags": {"Team": 1}}, "string value"),
        ({"tags": "bad"}, "key/value object list"),
        ({"tags": ["bad"]}, "must be an object"),
        ({"tags": [{"key": 1}]}, "requires string"),
    ],
)
def test_nested_metadata_validation_failures(
    tmp_path: Path,
    metadata: object,
    match: str,
) -> None:
    path = tmp_path / "nested.json"
    path.write_text(
        json.dumps({"metadata": metadata, "policy": POLICY}),
        encoding="utf-8",
    )
    with pytest.raises(documents.PolicyInputError, match=match):
        documents.load_policy_input(path, metadata_mode=documents.MetadataMode.NESTED)


def test_nested_and_sidecar_structural_failures(tmp_path: Path) -> None:
    nested = tmp_path / "nested.json"
    nested.write_text('{"extra":true,"policy":{}}', encoding="utf-8")
    with pytest.raises(documents.PolicyInputError, match="Unknown nested"):
        documents.load_policy_input(nested, metadata_mode=documents.MetadataMode.NESTED)
    nested.write_text('{"metadata":{}}', encoding="utf-8")
    with pytest.raises(documents.PolicyInputError, match="requires a 'policy'"):
        documents.load_policy_input(nested, metadata_mode=documents.MetadataMode.NESTED)

    plain = tmp_path / "plain.yaml"
    plain.write_text("Version: x\nStatement: []\n", encoding="utf-8")
    with pytest.raises(documents.PolicyInputError, match="metadata sidecar"):
        documents.load_policy_input(
            plain,
            metadata_mode=documents.MetadataMode.SIDECAR,
        )


def test_yaml_and_json_value_strict_failures(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(documents.PolicyInputError, match="Invalid JSON"):
        documents.load_policy_input(malformed)

    non_string_key = tmp_path / "key.yaml"
    non_string_key.write_text("1: value\n", encoding="utf-8")
    with pytest.raises(documents.PolicyInputError, match="must be a string"):
        documents.load_policy_input(non_string_key)

    unhashable_key = tmp_path / "unhashable.yaml"
    unhashable_key.write_text("? [one, two]\n: value\n", encoding="utf-8")
    with pytest.raises(documents.PolicyInputError, match="hashable"):
        documents.load_policy_input(unhashable_key)

    with pytest.raises(documents.PolicyInputError, match="Unsupported value"):
        documents._json_value(object())


def aws_error(code: str = "AccessDenied", operation: str = "Operation") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": f"{code} message"}},
        operation,
    )


def test_models_helpers_and_packed_policy_non_errors() -> None:
    root = managed.ManagedPolicyArn.parse(f"arn:aws:iam::{ACCOUNT}:policy/RootPolicy")
    assert root.name == "RootPolicy"
    assert root.path == "/"
    assert root.kind is managed.PolicyKind.CUSTOMER_MANAGED
    aws = managed.ManagedPolicyArn.parse("arn:aws:iam::aws:policy/ReadOnlyAccess")
    assert aws.kind is managed.PolicyKind.AWS_MANAGED
    with pytest.raises(managed.PolicyServiceError, match="Invalid IAM"):
        managed.ManagedPolicyArn.parse("bad")

    tag = managed.Tag("Team", "Agents")
    assert tag.as_request() == {"Key": "Team", "Value": "Agents"}
    empty = managed.ResolutionResult("missing", ())
    assert not empty.ambiguous
    assert empty.selected is None
    dependencies = managed.PolicyDependencies()
    assert dependencies.empty
    assert managed.packed_policy_warning(None) is None
    assert managed.packed_policy_warning(10) is None
    assert managed.parse_packed_policy_diagnostic(aws_error()) is None

    report = managed.ValidationReport(
        (
            managed.ValidationDiagnostic(
                managed.DiagnosticSeverity.WARNING,
                "WARN",
                "warning",
            ),
        )
    )
    assert report.valid
    assert not report.repairs
    assert len(report.merge(report).diagnostics) == 2
    journal = managed.OperationJournal("plan", [])
    journal.record("step", managed.StepState.COMPENSATED, "done")
    assert journal.entries[0].detail == "done"


@pytest.mark.parametrize(
    ("value", "helper", "match"),
    [
        ([], managed._mapping, "not an object"),
        ("bad", managed._items, "not a list"),
        (1, managed._string, "not a string"),
    ],
)
def test_response_shape_helpers_reject_invalid_fields(
    value: object,
    helper: object,
    match: str,
) -> None:
    callable_helper = cast("object", helper)
    with pytest.raises(managed.PolicyServiceError, match=match):
        callable_helper(value, label="field")  # type: ignore[operator]


def test_service_options_and_caller_identity_validation() -> None:
    iam = StatefulIam()
    with pytest.raises(managed.PolicyServiceError, match="account ID"):
        managed.IamManagedPolicyService(
            iam,
            FakeSts(),
            None,
            managed.PolicyServiceOptions("bad", PARTITION),
        )
    with pytest.raises(managed.PolicyServiceError, match="partition"):
        managed.IamManagedPolicyService(
            iam,
            FakeSts(),
            None,
            managed.PolicyServiceOptions(ACCOUNT, "bad"),
        )
    with pytest.raises(managed.PolicyServiceError, match="begin and end"):
        managed.IamManagedPolicyService(
            iam,
            FakeSts(),
            None,
            managed.PolicyServiceOptions(ACCOUNT, PARTITION, "bad"),
        )

    sts = FakeSts()
    service = make_service(iam, sts)
    sts.get_caller_identity = lambda **_kwargs: {  # type: ignore[method-assign]
        "Account": ACCOUNT,
        "Arn": "malformed",
        "UserId": "id",
    }
    with pytest.raises(managed.PolicyServiceError, match="malformed"):
        service.caller_identity()
    sts.get_caller_identity = lambda **_kwargs: {  # type: ignore[method-assign]
        "Account": "999999999999",
        "Arn": "arn:aws:iam::999999999999:user/test",
        "UserId": "id",
    }
    with pytest.raises(managed.PolicyServiceError, match="expected"):
        service.caller_identity()


def test_validation_all_tag_and_size_diagnostics() -> None:
    service = make_service(StatefulIam())
    oversized: dict[str, documents.JsonValue] = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "x" * 6_200}],
    }
    tags = [managed.Tag(f"k{index}", "v") for index in range(51)]
    tags.extend(
        (
            managed.Tag("", "v"),
            managed.Tag("long", "v" * 257),
            managed.Tag("duplicate", "one"),
            managed.Tag("duplicate", "two"),
        )
    )
    report = service.validate_policy(
        oversized,
        tags=tags,
        include_aws=False,
    )
    codes = {item.code for item in report.diagnostics}
    assert {
        "POLICY_SIZE_EXCEEDED",
        "TAG_LIMIT_EXCEEDED",
        "INVALID_TAG_KEY",
        "INVALID_TAG_VALUE",
        "DUPLICATE_TAG_KEY",
    } <= codes
    empty_report = service.validate_policy(
        {"Version": "2012-10-17", "Statement": []},
        include_aws=False,
    )
    assert "EMPTY_STATEMENT" in {item.code for item in empty_report.diagnostics}


def test_long_caller_attribution_hash_and_tag_validation_failure() -> None:
    service = make_service(StatefulIam())
    caller = managed.CallerIdentity(
        ACCOUNT,
        PARTITION,
        "arn:aws:iam::" + "x" * 300,
        "principal",
    )
    tags = service.ownership_tags("id", caller=caller, created_at=NOW)
    assert {tag.key: tag.value for tag in tags}["hacksaws:created-by"].startswith(
        "sha256:"
    )
    with pytest.raises(managed.PolicyValidationError):
        service.ownership_tags("x" * 300, caller=caller)


def test_access_analyzer_resource_type_and_missing_finding_fields() -> None:
    class Analyzer:
        def __init__(self) -> None:
            self.request: dict[str, object] = {}

        def validate_policy(self, **kwargs: object) -> dict[str, object]:
            self.request = dict(kwargs)
            return {"findings": [{}]}

    analyzer = Analyzer()
    validator = managed.AccessAnalyzerPolicyValidator(analyzer)
    report = validator.validate(
        POLICY,
        policy_type="RESOURCE_POLICY",
        resource_type="AWS::IAM::AssumeRolePolicyDocument",
    )
    assert analyzer.request["validatePolicyResourceType"] == (
        "AWS::IAM::AssumeRolePolicyDocument"
    )
    assert report.diagnostics[0].severity is managed.DiagnosticSeverity.WARNING


def test_resolution_not_found_invalid_namespace_and_partition() -> None:
    iam = StatefulIam(existing=False)
    service = make_service(iam)
    assert service.resolve("custom:missing").candidates == ()
    assert service.resolve("weird:name").candidates == ()
    with pytest.raises(managed.PolicyServiceError, match="cannot be empty"):
        service.resolve("owned:")
    with pytest.raises(managed.PolicyServiceError, match="partition"):
        service.resolve(f"arn:aws-cn:iam::{ACCOUNT}:policy/Test")
    with pytest.raises(managed.PolicyServiceError, match="not found"):
        service.get_policy("missing")


def test_get_policy_reports_ambiguity() -> None:
    iam = StatefulIam()
    service = make_service(iam)
    original = iam.list_policies

    def list_both(**kwargs: object) -> dict[str, object]:
        result = original(**kwargs)
        if kwargs.get("Scope") == "AWS":
            item = dict(iam._metadata())
            item["Arn"] = "arn:aws:iam::aws:policy/AgentRead"
            item["Path"] = "/"
            result["Policies"] = [item]
        return result

    iam.list_policies = list_both  # type: ignore[method-assign]
    with pytest.raises(managed.PolicyServiceError, match="ambiguous"):
        service.get_policy("AgentRead")


def test_tag_version_and_entity_marker_pagination() -> None:
    iam = StatefulIam()
    service = make_service(iam)
    tag_calls = 0
    original_tags = iam.list_policy_tags

    def paged_tags(**kwargs: object) -> dict[str, object]:
        nonlocal tag_calls
        tag_calls += 1
        if tag_calls == 1:
            return {
                "Tags": [{"Key": "first", "Value": "1"}],
                "IsTruncated": True,
                "Marker": "next",
            }
        return original_tags(**kwargs)

    iam.list_policy_tags = paged_tags  # type: ignore[method-assign]
    record = service.get_policy(ARN, include_document=False)
    assert any(tag.key == "first" for tag in record.tags)

    version_calls = 0
    original_versions = iam.list_policy_versions

    def paged_versions(**kwargs: object) -> dict[str, object]:
        nonlocal version_calls
        version_calls += 1
        if version_calls == 1:
            return {"Versions": [], "IsTruncated": True, "Marker": "next"}
        return original_versions(**kwargs)

    iam.list_policy_versions = paged_versions  # type: ignore[method-assign]
    assert service.export_policy(ARN, include_all_versions=True).versions

    entity_calls = 0
    original_entities = iam.list_entities_for_policy

    def paged_entities(**kwargs: object) -> dict[str, object]:
        nonlocal entity_calls
        entity_calls += 1
        if entity_calls == 1:
            return {
                "PolicyUsers": [],
                "PolicyGroups": [],
                "PolicyRoles": [],
                "IsTruncated": True,
                "Marker": "next",
            }
        return original_entities(**kwargs)

    iam.list_entities_for_policy = paged_entities  # type: ignore[method-assign]
    assert service.policy_dependencies(ARN).empty


def test_arn_resolution_not_found_error_and_owned_filter() -> None:
    missing = make_service(StatefulIam(existing=False))
    assert missing.resolve(ARN).candidates == ()

    iam = StatefulIam()
    service = make_service(iam)
    iam.tags = {}
    assert service.resolve("owned:AgentRead").candidates == ()
    iam.get_policy = lambda **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        aws_error()
    )
    with pytest.raises(ClientError):
        service.resolve(ARN)


def test_read_policy_rejects_mismatched_returned_arn() -> None:
    iam = StatefulIam()
    service = make_service(iam)
    original = iam.get_policy

    def mismatched(**kwargs: object) -> dict[str, object]:
        response = original(**kwargs)
        policy = cast("dict[str, object]", response["Policy"])
        policy["Arn"] = f"arn:aws:iam::{ACCOUNT}:policy/hacksaws/Other"
        return response

    iam.get_policy = mismatched  # type: ignore[method-assign]
    with pytest.raises(managed.PolicyServiceError, match="different policy ARN"):
        service.resolve(ARN)


def test_create_description_and_create_failure() -> None:
    iam = StatefulIam(existing=False)
    service = make_service(iam)
    plan = service.plan_create(
        "AgentRead",
        POLICY,
        options=managed.CreatePolicyOptions(
            description="read logs",
            include_aws_validation=False,
        ),
    )
    assert plan.description == "read logs"
    compensation = plan.operation.steps[0].compensation
    assert compensation is not None
    assert compensation.parameters["PolicyArn"] == ARN
    iam.create_policy = lambda **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        aws_error(operation="CreatePolicy")
    )
    with pytest.raises(ClientError):
        service.execute_change(plan)


def test_aws_managed_get_skips_tags_and_publish_is_immutable() -> None:
    class AwsManagedIam(StatefulIam):
        def _metadata(self) -> dict[str, object]:
            metadata = super()._metadata()
            metadata["Arn"] = "arn:aws:iam::aws:policy/ReadOnlyAccess"
            metadata["PolicyName"] = "ReadOnlyAccess"
            metadata["Path"] = "/"
            return metadata

        def list_policy_tags(self, **kwargs: object) -> dict[str, object]:
            pytest.fail("AWS-managed policy tags must not be requested")

    iam = AwsManagedIam()
    service = make_service(iam)
    arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    policy = service.get_policy(arn)
    assert policy.tags == ()
    with pytest.raises(managed.ImmutablePolicyError):
        service.plan_publish(arn, CHANGED, include_aws_validation=False)


def test_plan_guards_missing_documents_versions_and_arns() -> None:
    iam = StatefulIam()
    service = make_service(iam)
    record = service.get_policy(ARN)
    missing_document = replace(record, document=None)
    with (
        patch.object(service, "get_policy", return_value=missing_document),
        pytest.raises(managed.PolicyServiceError, match="document was not loaded"),
    ):
        service.plan_publish(ARN, CHANGED, include_aws_validation=False)
    with pytest.raises(managed.PolicyServiceError, match="does not exist"):
        service.plan_rollback(ARN, "v99")

    create = service.plan_create(
        "Other",
        POLICY,
        options=managed.CreatePolicyOptions(include_aws_validation=False),
    )
    invalid = replace(
        create,
        operation=replace(create.operation, action=managed.ChangeAction.UPDATE),
    )
    with pytest.raises(managed.PolicyServiceError, match="requires an ARN"):
        service.execute_change(invalid)


def test_update_and_rollback_client_failures() -> None:
    iam = StatefulIam()
    service = make_service(iam)
    update = service.plan_publish(ARN, CHANGED, include_aws_validation=False)
    iam.create_policy_version = lambda **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        aws_error(operation="CreatePolicyVersion")
    )
    with pytest.raises(ClientError):
        service.execute_change(update)

    iam = StatefulIam()
    iam.versions["v2"] = (CHANGED, NOW)
    iam.default = "v2"
    service = make_service(iam)
    rollback = service.plan_rollback(ARN, "v1")
    iam.set_default_policy_version = lambda **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        aws_error(operation="SetDefaultPolicyVersion")
    )
    with pytest.raises(ClientError):
        service.execute_change(rollback)


def test_prune_client_failure_prevents_publish() -> None:
    iam = StatefulIam()
    iam.versions = {
        f"v{number}": (POLICY, NOW.replace(day=number)) for number in range(1, 6)
    }
    iam.default = "v5"
    service = make_service(iam)
    plan = service.plan_publish(ARN, CHANGED, include_aws_validation=False)
    iam.delete_policy_version = lambda **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        aws_error(operation="DeletePolicyVersion")
    )
    with pytest.raises(ClientError):
        service.execute_change(plan)
    assert "CreatePolicyVersion" not in iam.calls


def test_bounded_verification_reports_stale_and_non_retryable_errors() -> None:
    iam = StatefulIam()
    service = make_service(iam)
    with pytest.raises(managed.PolicyServiceError, match="bounded propagation"):
        service._verify_policy(
            managed.ManagedPolicyArn.parse(ARN),
            expected_version="v99",
            expected_digest="bad",
        )
    iam.get_policy = lambda **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        aws_error()
    )
    with pytest.raises(ClientError):
        service._verify_policy(
            managed.ManagedPolicyArn.parse(ARN),
            expected_version="v1",
            expected_digest=documents.policy_digest(POLICY),
        )


def test_export_missing_document_and_adoption_conflict() -> None:
    iam = StatefulIam()
    service = make_service(iam)
    record = service.get_policy(ARN)
    with (
        patch.object(
            service,
            "get_policy",
            return_value=replace(record, document=None),
        ),
        pytest.raises(managed.PolicyServiceError, match="no active document"),
    ):
        service.export_policy(ARN)
    iam.tags["hacksaws:managed-by"] = "another-tool"
    with pytest.raises(managed.PolicyServiceError, match="already managed"):
        service.plan_adopt(ARN, "id")


def test_release_noop_and_tag_client_failure() -> None:
    iam = StatefulIam()
    iam.tags = {"Existing": "yes"}
    service = make_service(iam)
    release = service.plan_release(ARN)
    assert service.execute_tag_change(release).journal.entries == []

    adopt = service.plan_adopt(ARN, "id")
    assert {tag.key: tag.value for tag in adopt.add}[
        "hacksaws:ownership-origin"
    ] == "adopted"
    iam.tag_policy = lambda **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        aws_error(operation="TagPolicy")
    )
    with pytest.raises(ClientError):
        service.execute_tag_change(adopt)


def test_delete_warns_for_unowned_detects_drift_and_client_failure() -> None:
    iam = StatefulIam()
    iam.tags = {}
    service = make_service(iam)
    plan = service.plan_delete(ARN, cascade=True)
    assert any("ownership" in warning for warning in plan.operation.warnings)
    iam.versions["v2"] = (CHANGED, NOW)
    with pytest.raises(managed.PolicyDriftError):
        service.execute_delete(plan)

    iam = StatefulIam()
    service = make_service(iam)
    plan = service.plan_delete(ARN, cascade=True)
    iam.delete_policy = lambda **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        aws_error(operation="DeletePolicy")
    )
    with pytest.raises(ClientError):
        service.execute_delete(plan)
    unknown = managed.OperationStep("x", "Unknown", {})
    with pytest.raises(managed.PolicyServiceError, match="Unsupported deletion"):
        service._execute_delete_step(unknown)


def test_probe_options_validation_and_nonpacked_failure() -> None:
    iam = StatefulIam()
    sts = FakeSts()
    service = make_service(iam, sts)
    with pytest.raises(managed.PolicyServiceError, match="Invalid IAM role"):
        service.probe_assume_role("bad", POLICY)
    with pytest.raises(managed.PolicyServiceError, match="does not match"):
        service.probe_assume_role("arn:aws:iam::999999999999:role/AgentSession", POLICY)

    result = service.probe_assume_role(
        ROLE_ARN,
        POLICY,
        options=managed.AssumeRoleProbeOptions(
            external_id="external",
            source_identity="tester",
            session_tags=(managed.Tag("Team", "Agents"),),
        ),
    )
    assert result.warning is not None
    assert sts.assume_request is not None
    assert sts.assume_request["ExternalId"] == "external"
    assert sts.assume_request["SourceIdentity"] == "tester"
    assert sts.assume_request["Tags"] == [{"Key": "Team", "Value": "Agents"}]

    sts.assume_error = aws_error(operation="AssumeRole")
    with pytest.raises(ClientError):
        service.probe_assume_role(ROLE_ARN, POLICY)


def test_probe_without_packed_size_or_expiration() -> None:
    class MinimalSts(FakeSts):
        def assume_role(self, **kwargs: object) -> dict[str, object]:
            return {
                "AssumedRoleUser": {"Arn": "arn:aws:sts::x:assumed-role/x/y"},
                "Credentials": {},
            }

    service = make_service(StatefulIam(), MinimalSts())
    result = service.probe_assume_role(ROLE_ARN, POLICY)
    assert result.packed_policy_size is None
    assert result.expires_at is None
    assert result.warning is None


def test_policy_recovery_delete_commit_point_is_irreversible_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    iam = StatefulIam()
    iam.versions["v2"] = (CHANGED, NOW)
    iam.default = "v2"
    iam.tags["environment"] = "test"
    iam.permission_users["U1"] = "Human"
    iam.permission_groups["G1"] = "Operators"
    iam.permission_roles["R1"] = "Reader"
    iam.boundary_users["BU1"] = "RestrictedUser"
    iam.boundary_roles["BR1"] = "RestrictedRole"
    sts = FakeSts()
    service = make_service(iam, sts)
    context = SimpleNamespace(
        iam=iam,
        sts=sts,
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    policy = service.get_policy(
        ARN, include_document=True, include_versions=True, include_tags=True
    )
    dependencies = service.policy_dependencies(ARN)
    compensation = policy_cli._policy_state(policy, dependencies=dependencies)
    forward = policy_cli._absent_state(ARN, policy.name, policy.path)

    _iam_recovery.clear_handlers()
    journal_id = policy_cli._durable_reconcile(
        cast("Any", context), "delete", forward, compensation
    )
    assert not iam.exists
    assert not iam.permission_users
    assert not iam.permission_groups
    assert not iam.permission_roles
    assert not iam.boundary_users
    assert not iam.boundary_roles

    mutation_calls = len(iam.calls)
    for _attempt in range(2):
        with pytest.raises(
            _configs.OperationalError, match="irreversible AWS PolicyId"
        ):
            _iam_recovery.rollback_journal(journal_id, context)
        assert not iam.exists
        assert len(iam.calls) == mutation_calls
    policy_cli._reconcile_policy(
        policy_cli._recovery_payload(compensation, forward), context
    )
    assert len(iam.calls) == mutation_calls
    assert "CreatePolicy" not in iam.calls
    assert "AttachUserPolicy" not in iam.calls
    assert "AttachGroupPolicy" not in iam.calls
    assert "AttachRolePolicy" not in iam.calls
    assert "PutUserPermissionsBoundary" not in iam.calls
    assert "PutRolePermissionsBoundary" not in iam.calls


def test_policy_recovery_rejects_wrong_account_and_create_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    iam = StatefulIam()
    sts = FakeSts()
    context = SimpleNamespace(
        iam=iam,
        sts=sts,
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    with pytest.raises(_configs.OperationalError, match="selected credentials"):
        policy_cli._reconcile_policy(
            policy_cli._recovery_payload(
                policy_cli._absent_state(
                    "arn:aws:iam::999999999999:policy/Test", "Test", "/"
                ),
                policy_cli._absent_state(
                    "arn:aws:iam::999999999999:policy/Test", "Test", "/"
                ),
            ),
            context,
        )
    collision = policy_cli._policy_state(
        make_service(iam, sts).get_policy(
            ARN, include_document=True, include_versions=True, include_tags=True
        ),
        create_only=True,
    )
    collision["tags"] = [{"Key": "hacksaws:resource-id", "Value": "different"}]
    with pytest.raises(managed.PolicyDriftError, match="exact expected predecessor"):
        policy_cli._reconcile_policy(
            policy_cli._recovery_payload(
                policy_cli._absent_state(ARN, "AgentRead", "/hacksaws/"),
                collision,
            ),
            context,
        )


def test_policy_recovery_selects_retained_default_and_reconciles_tags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    iam = StatefulIam()
    iam.versions["v2"] = (CHANGED, NOW)
    sts = FakeSts()
    context = SimpleNamespace(
        iam=iam,
        sts=sts,
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    service = make_service(iam, sts)
    original = policy_cli._policy_state(
        service.get_policy(
            ARN, include_document=True, include_versions=True, include_tags=True
        ),
        dependencies=service.policy_dependencies(ARN),
    )
    desired = dict(original)
    desired["versions"] = [{"id": "v2", "default": True, "document": CHANGED}]
    desired["tags"] = [{"Key": "environment", "Value": "production"}]

    policy_cli._reconcile_policy(
        policy_cli._recovery_payload(original, desired), context
    )

    assert iam.default == "v2"
    assert list(iam.versions) == ["v2"]
    assert iam.tags == {"environment": "production"}
    assert "SetDefaultPolicyVersion" in iam.calls
    assert "DeletePolicyVersion" in iam.calls
    assert "TagPolicy" in iam.calls
    assert "UntagPolicy" in iam.calls


def test_policy_recovery_rejects_concurrent_document_and_tag_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    iam = StatefulIam()
    service = make_service(iam)
    context = SimpleNamespace(
        iam=iam,
        sts=FakeSts(),
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    original = policy_cli._policy_state(
        service.get_policy(
            ARN, include_document=True, include_versions=True, include_tags=True
        ),
        dependencies=service.policy_dependencies(ARN),
    )
    desired = dict(original)
    desired["versions"] = [
        {"id": "v1", "default": False, "document": POLICY},
        {"id": "pending", "default": True, "document": CHANGED},
    ]

    deny_all: dict[str, documents.JsonValue] = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }
    iam.versions["v2"] = (deny_all, NOW)
    iam.default = "v2"
    iam.tags["concurrent"] = "preserve-me"
    before_calls = list(iam.calls)

    with pytest.raises(managed.PolicyDriftError, match="exact expected predecessor"):
        policy_cli._reconcile_policy(
            policy_cli._recovery_payload(original, desired), context
        )

    assert iam.calls == before_calls
    assert iam.default == "v2"
    assert iam.tags["concurrent"] == "preserve-me"


def test_policy_delete_recovery_rejects_new_attachment_and_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    iam = StatefulIam()
    service = make_service(iam)
    context = SimpleNamespace(
        iam=iam,
        sts=FakeSts(),
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    expected = policy_cli._policy_state(
        service.get_policy(
            ARN, include_document=True, include_versions=True, include_tags=True
        ),
        dependencies=service.policy_dependencies(ARN),
    )
    iam.permission_roles["R2"] = "NewAttachment"
    iam.boundary_roles["BR2"] = "NewBoundary"

    with pytest.raises(managed.PolicyDriftError, match="exact expected predecessor"):
        policy_cli._reconcile_policy(
            policy_cli._recovery_payload(
                expected,
                policy_cli._absent_state(ARN, "AgentRead", "/hacksaws/"),
            ),
            context,
        )

    assert "DetachRolePolicy" not in iam.calls
    assert "DeleteRolePermissionsBoundary" not in iam.calls
    assert "DeletePolicy" not in iam.calls
    assert iam.permission_roles == {"R2": "NewAttachment"}
    assert iam.boundary_roles == {"BR2": "NewBoundary"}


def test_create_rollback_preserves_unrelated_policy_at_same_arn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    iam = StatefulIam()
    service = make_service(iam)
    context = SimpleNamespace(
        iam=iam,
        sts=FakeSts(),
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    intended = policy_cli._policy_state(
        service.get_policy(
            ARN, include_document=True, include_versions=True, include_tags=True
        ),
        dependencies=managed.PolicyDependencies(),
        create_only=True,
    )
    intended["policyId"] = "pending"
    intended["defaultVersionId"] = "pending"
    intended["versions"] = [{"id": "pending", "default": True, "document": POLICY}]
    intended["tags"] = [
        {"Key": "hacksaws:managed-by", "Value": "hacksaws"},
        {"Key": "hacksaws:resource-id", "Value": "this-journal-only"},
        {"Key": "hacksaws:resource-kind", "Value": "managed-policy"},
    ]

    with pytest.raises(managed.PolicyDriftError, match="exact expected predecessor"):
        policy_cli._reconcile_policy(
            policy_cli._recovery_payload(
                intended,
                policy_cli._absent_state(ARN, "AgentRead", "/hacksaws/"),
            ),
            context,
        )

    assert iam.exists
    assert "DeletePolicy" not in iam.calls
    assert iam.tags["hacksaws:resource-id"] == "resource-1"


def test_create_rollback_requires_exact_durable_policy_id_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    iam = StatefulIam()
    service = make_service(iam)
    context = SimpleNamespace(
        iam=iam,
        sts=FakeSts(),
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    created = policy_cli._created_base_state(
        policy_cli._policy_state(
            service.get_policy(
                ARN, include_document=True, include_versions=True, include_tags=True
            ),
            dependencies=managed.PolicyDependencies(),
            create_only=True,
        )
    )
    payload = {
        "expected": created,
        "target": policy_cli._absent_state(ARN, "AgentRead", "/hacksaws/"),
        "effect": {"policyId": "ANPA-DIFFERENT-POLICY"},
    }

    with pytest.raises(managed.PolicyDriftError, match="before deletion"):
        policy_cli._delete_created_policy_with_receipt(payload, context)

    assert iam.exists
    assert "DeletePolicy" not in iam.calls


def test_unreceipted_create_crash_preserves_present_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    template_iam = StatefulIam()
    template_service = make_service(template_iam)
    target = policy_cli._created_base_state(
        policy_cli._policy_state(
            template_service.get_policy(
                ARN, include_document=True, include_versions=True, include_tags=True
            ),
            dependencies=managed.PolicyDependencies(),
            create_only=True,
        )
    )
    iam = StatefulIam(existing=False)
    context = SimpleNamespace(
        iam=iam,
        sts=FakeSts(),
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    _iam_recovery.clear_handlers()
    policy_cli.ensure_recovery_handlers()
    journal = _iam_recovery.begin_journal("policy", ACCOUNT, "create-crash")
    journal.record_before_mutation(
        "create-policy",
        forward={"target": target},
        compensation={
            "expected": target,
            "target": policy_cli._absent_state(ARN, "AgentRead", "/hacksaws/"),
            "effectSourceStep": "self",
        },
    )

    receipt = policy_cli._create_policy_with_receipt({"target": target}, context)
    assert receipt == {"policyId": "ANPA12345678901234567"}
    with pytest.raises(_configs.OperationalError, match="cannot prove"):
        _iam_recovery.rollback_journal(journal.id, context)

    assert iam.exists
    assert "DeletePolicy" not in iam.calls


def test_receipted_create_rollback_deletes_only_bound_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    template_iam = StatefulIam()
    template_service = make_service(template_iam)
    target = policy_cli._replacement_target(
        policy_cli._policy_state(
            template_service.get_policy(
                ARN, include_document=True, include_versions=True, include_tags=True
            ),
            dependencies=managed.PolicyDependencies(),
            create_only=True,
        )
    )
    iam = StatefulIam(existing=False)
    context = SimpleNamespace(
        iam=iam,
        sts=FakeSts(),
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    _iam_recovery.clear_handlers()

    journal_id = policy_cli._durable_reconcile(
        cast("Any", context),
        "create",
        target,
        policy_cli._absent_state(ARN, "AgentRead", "/hacksaws/"),
    )

    journal = _iam_recovery.get_journal(journal_id)
    assert journal["steps"][0]["effect"] == {"policyId": "ANPA12345678901234567"}
    assert iam.exists
    _iam_recovery.rollback_journal(journal_id, context)
    assert not iam.exists
    assert "DeletePolicy" in iam.calls


def test_existing_policy_checkpoint_rejects_partial_atomic_tag_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    iam = StatefulIam()
    iam.tags.update({"first": "old", "second": "old"})
    service = make_service(iam)
    context = SimpleNamespace(
        iam=iam,
        sts=FakeSts(),
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    expected = policy_cli._policy_state(
        service.get_policy(
            ARN, include_document=True, include_versions=True, include_tags=True
        ),
        dependencies=service.policy_dependencies(ARN),
    )
    target = policy_cli._clone_state(expected)
    target_tags = {
        item["Key"]: item["Value"] for item in policy_cli._state_tags(target)
    }
    target_tags.update({"first": "new", "second": "new"})
    target["tags"] = [
        {"Key": key, "Value": value} for key, value in sorted(target_tags.items())
    ]
    iam.tags["first"] = "new"
    before_calls = list(iam.calls)

    with pytest.raises(managed.PolicyDriftError, match="exact recovery checkpoint"):
        policy_cli._reconcile_policy(
            policy_cli._recovery_payload(expected, target), context
        )

    assert iam.calls == before_calls
    assert iam.tags["first"] == "new"
    assert iam.tags["second"] == "old"


def test_delete_checkpoint_rejects_out_of_order_missing_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    iam = StatefulIam()
    iam.permission_roles["R1"] = "Reader"
    iam.boundary_roles["BR1"] = "Restricted"
    service = make_service(iam)
    context = SimpleNamespace(
        iam=iam,
        sts=FakeSts(),
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    expected = policy_cli._policy_state(
        service.get_policy(
            ARN, include_document=True, include_versions=True, include_tags=True
        ),
        dependencies=service.policy_dependencies(ARN),
    )
    iam.boundary_roles.clear()
    payload = policy_cli._recovery_payload(
        expected, policy_cli._absent_state(ARN, "AgentRead", "/hacksaws/")
    )

    with pytest.raises(managed.PolicyDriftError, match="exact recovery checkpoint"):
        policy_cli._reconcile_policy(payload, context)

    assert iam.permission_roles == {"R1": "Reader"}
    assert "DetachRolePolicy" not in iam.calls
    assert "DeletePolicy" not in iam.calls


def test_dependency_restore_rejects_same_name_recreated_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    iam = StatefulIam()
    service = make_service(iam)
    context = SimpleNamespace(
        iam=iam,
        sts=FakeSts(),
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    target = policy_cli._policy_state(
        service.get_policy(
            ARN, include_document=True, include_versions=True, include_tags=True
        ),
        dependencies=managed.PolicyDependencies(
            permission_users=(managed.EntityReference("User", "Human", "U1"),)
        ),
    )
    iam.user_identities["Human"] = "U2"

    with pytest.raises(managed.PolicyDriftError, match="different IAM principal"):
        policy_cli._reconcile_policy(
            policy_cli._recovery_payload(
                policy_cli._absent_state(ARN, "AgentRead", "/hacksaws/"),
                target,
                include_reverse_checkpoints=True,
            ),
            context,
        )

    assert "AttachUserPolicy" not in iam.calls
    assert not iam.permission_users


@pytest.mark.parametrize("recover", ["continue", "rollback"])
def test_delete_recovery_resumes_exact_partial_checkpoint(
    monkeypatch: pytest.MonkeyPatch, recover: str
) -> None:
    iam = StatefulIam()
    iam.permission_roles["R1"] = "Reader"
    service = make_service(iam)
    context = SimpleNamespace(
        iam=iam,
        sts=FakeSts(),
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    original = policy_cli._policy_state(
        service.get_policy(
            ARN, include_document=True, include_versions=True, include_tags=True
        ),
        dependencies=service.policy_dependencies(ARN),
    )
    absent = policy_cli._absent_state(ARN, "AgentRead", "/hacksaws/")
    forward = policy_cli._recovery_payload(original, absent)
    compensation = policy_cli._recovery_payload(
        absent, original, include_reverse_checkpoints=True
    )
    detach = iam.detach_role_policy

    def detach_then_crash(**kwargs: object) -> None:
        detach(**kwargs)
        raise RuntimeError("crash after DetachRolePolicy")  # noqa: TRY003

    monkeypatch.setattr(iam, "detach_role_policy", detach_then_crash)
    with pytest.raises(RuntimeError, match="crash after DetachRolePolicy"):
        policy_cli._reconcile_policy(forward, context)
    monkeypatch.setattr(iam, "detach_role_policy", detach)

    policy_cli._reconcile_policy(
        forward if recover == "continue" else compensation, context
    )

    if recover == "continue":
        assert not iam.exists
    else:
        assert iam.exists
        assert service.policy_dependencies(ARN).permission_roles == (
            managed.EntityReference("Role", "Reader", "R1"),
        )


@pytest.mark.parametrize("recover", ["continue", "rollback"])
def test_update_recovery_resumes_after_prune_checkpoint(
    monkeypatch: pytest.MonkeyPatch, recover: str
) -> None:
    iam = StatefulIam()
    extra_documents: dict[str, dict[str, documents.JsonValue]] = {}
    for number in range(2, 6):
        document: dict[str, documents.JsonValue] = {
            "Version": "2012-10-17",
            "Statement": [{"Sid": f"Original{number}"}],
        }
        extra_documents[f"v{number}"] = document
        iam.versions[f"v{number}"] = (document, NOW)
    service = make_service(iam)
    context = SimpleNamespace(
        iam=iam,
        sts=FakeSts(),
        access_analyzer=None,
        account_id=ACCOUNT,
        partition=PARTITION,
    )
    monkeypatch.setattr(
        policy_cli._state, "load_config", policy_cli._state.default_config
    )
    original = policy_cli._policy_state(
        service.get_policy(
            ARN, include_document=True, include_versions=True, include_tags=True
        ),
        dependencies=service.policy_dependencies(ARN),
    )
    target = dict(original)
    target["versions"] = [
        {"id": "v1", "default": False, "document": POLICY},
        *[
            {
                "id": version_id,
                "default": False,
                "document": document,
            }
            for version_id, document in extra_documents.items()
            if version_id != "v2"
        ],
        {"id": "pending", "default": True, "document": CHANGED},
    ]
    forward = policy_cli._recovery_payload(original, target)
    compensation = policy_cli._recovery_payload(
        target, original, include_reverse_checkpoints=True
    )
    prune = iam.delete_policy_version

    def prune_then_crash(**kwargs: object) -> None:
        prune(**kwargs)
        raise RuntimeError("crash after DeletePolicyVersion")  # noqa: TRY003

    monkeypatch.setattr(iam, "delete_policy_version", prune_then_crash)
    with pytest.raises(RuntimeError, match="crash after DeletePolicyVersion"):
        policy_cli._reconcile_policy(forward, context)
    assert "v2" not in iam.versions
    monkeypatch.setattr(iam, "delete_policy_version", prune)

    policy_cli._reconcile_policy(
        forward if recover == "continue" else compensation, context
    )

    documents_after = {
        managed.policy_digest(document) for document, _created in iam.versions.values()
    }
    if recover == "continue":
        assert iam.default != "v1"
        assert managed.policy_digest(CHANGED) in documents_after
        assert managed.policy_digest(extra_documents["v2"]) not in documents_after
    else:
        assert iam.default == "v1"
        assert managed.policy_digest(extra_documents["v2"]) in documents_after
        assert managed.policy_digest(CHANGED) not in documents_after


def test_policy_recovery_prunes_capacity_and_validates_snapshot_shapes() -> None:
    iam = StatefulIam()
    for number in range(2, 6):
        iam.versions[f"v{number}"] = (
            {"Version": "2012-10-17", "Statement": [{"Sid": str(number)}]},
            NOW,
        )
    current = make_service(iam).get_policy(
        ARN, include_document=True, include_versions=True, include_tags=True
    )
    policy_cli._ensure_version_capacity(
        cast("Any", SimpleNamespace(iam=iam)),
        current,
        {managed.policy_digest(POLICY)},
    )
    assert len(iam.versions) == 4
    assert "v2" not in iam.versions

    with pytest.raises(managed.PolicyServiceError, match="every version document"):
        policy_cli._version_payload(
            managed.PolicyVersionRecord(
                version_id="v1",
                is_default=True,
                created_at=NOW,
                document=None,
            )
        )
    with pytest.raises(_configs.OperationalError, match="versions are invalid"):
        policy_cli._state_versions({"versions": "not-a-list"})
    with pytest.raises(_configs.OperationalError, match="tags are invalid"):
        policy_cli._state_tags({"tags": [{"Value": "missing-key"}]})
