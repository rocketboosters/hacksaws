"""Focused tests for pure IAM role and trust service contracts."""

# ruff: noqa: ANN401, D101, D102, D105, D107

from __future__ import annotations

import json
from typing import Any

import pytest
from botocore.exceptions import ClientError

from hacksaws import _iam_roles as roles

ACCOUNT = roles.AccountRef("prod", "123456789012")
ROLE_ARN = "arn:aws:iam::123456789012:role/hacksaws/Agent"
USER_ARN = "arn:aws:iam::123456789012:user/scott"
TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": USER_ARN},
            "Action": "sts:AssumeRole",
        }
    ],
}


def snapshot(**overrides: Any) -> roles.RoleSnapshot:
    values: dict[str, Any] = {
        "name": "Agent",
        "arn": ROLE_ARN,
        "path": "/hacksaws/",
        "trust": TRUST,
        "tags": {roles.MANAGED_TAG: "true", "old": "x"},
    }
    values.update(overrides)
    return roles.RoleSnapshot(**values)


class Recorder:
    def __init__(self, fail: str | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail = fail

    def __getattr__(self, name: str) -> Any:
        def call(**params: Any) -> dict[str, Any]:
            self.calls.append((name, params))
            if name == self.fail:
                raise RuntimeError(name)
            return {}

        return call


class Paginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.params: dict[str, Any] | None = None

    def paginate(self, **params: Any) -> list[dict[str, Any]]:
        self.params = params
        return self.pages


class ReadClient:
    def __init__(self) -> None:
        self.fail_once = False
        self.calls = 0
        self.paginators = {
            "list_attached_role_policies": Paginator(
                [
                    {"AttachedPolicies": [{"PolicyArn": "arn:policy/one"}]},
                    {"AttachedPolicies": [{"PolicyArn": "arn:policy/two"}]},
                ]
            ),
            "list_role_policies": Paginator(
                [{"PolicyNames": ["InlineOne"]}, {"PolicyNames": ["InlineTwo"]}]
            ),
            "list_instance_profiles_for_role": Paginator(
                [{"InstanceProfiles": [{"InstanceProfileName": "profile"}]}]
            ),
            "list_roles": Paginator(
                [
                    {
                        "Roles": [
                            {
                                "RoleName": "Agent",
                                "Arn": ROLE_ARN,
                                "Path": "/hacksaws/",
                                "AssumeRolePolicyDocument": TRUST,
                            }
                        ]
                    }
                ]
            ),
        }

    def get_paginator(self, name: str) -> Paginator:
        return self.paginators[name]

    def get_role(self, **params: Any) -> dict[str, Any]:
        self.calls += 1
        if self.fail_once and self.calls == 1:
            raise ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "wait"}}, "GetRole"
            )
        return {
            "Role": {
                "RoleName": params["RoleName"],
                "Arn": ROLE_ARN,
                "Path": "/hacksaws/",
                "AssumeRolePolicyDocument": TRUST,
                "Description": "agent",
                "MaxSessionDuration": 7200,
                "PermissionsBoundary": {"PermissionsBoundaryArn": "arn:boundary"},
                "Tags": [{"Key": roles.MANAGED_TAG, "Value": "true"}],
            }
        }

    def get_role_policy(self, **params: Any) -> dict[str, Any]:
        del params
        return {
            "PolicyDocument": (
                "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%5D%7D"
            )
        }


def test_document_path_account_and_principal_normalization() -> None:
    assert roles.decode_document(json.dumps(TRUST)) == TRUST
    assert roles.decode_document("%7B%22Version%22%3A%222012-10-17%22%7D") == {
        "Version": "2012-10-17"
    }
    with pytest.raises(roles.IamRoleError, match="object"):
        roles.decode_document([])
    assert roles.normalize_path("/hacksaws/") == "/hacksaws/"
    with pytest.raises(roles.IamRoleError, match="begin and end"):
        roles.normalize_path("hacksaws")
    with pytest.raises(roles.IamRoleError, match="12 digits"):
        roles.AccountRef("bad", "1")
    with pytest.raises(roles.IamRoleError, match="partition"):
        roles.AccountRef("bad", "123456789012", "mars")
    assert roles.normalize_caller_principal(USER_ARN) == USER_ARN
    root = "arn:aws:iam::123456789012:root"
    assert roles.normalize_caller_principal(root) == root
    assumed = "arn:aws:sts::123456789012:assumed-role/path/Agent/session"
    assert roles.normalize_caller_principal(assumed) == (
        "arn:aws:iam::123456789012:role/path/Agent"
    )
    with pytest.raises(roles.IamRoleError, match="Wildcard"):
        roles.normalize_caller_principal("arn:aws:iam::123456789012:role/*")
    with pytest.raises(roles.IamRoleError, match="durable"):
        roles.normalize_caller_principal("arn:aws:sts::123456789012:federated-user/x")


def test_resolve_all_principal_forms() -> None:
    accounts = {"prod": ACCOUNT}
    assert (
        roles.resolve_principal(
            roles.PrincipalRef("user", "scott", "prod"), accounts
        ).arn
        == USER_ARN
    )
    assert roles.resolve_principal(
        roles.PrincipalRef("role", "path/Agent", "prod"), accounts
    ).arn.endswith("role/path/Agent")
    assert roles.resolve_principal(
        roles.PrincipalRef("account", "prod", "prod"), accounts
    ).arn.endswith(":root")
    assert (
        roles.resolve_principal(
            roles.PrincipalRef("principal", USER_ARN), accounts
        ).kind
        == "user"
    )
    root = "arn:aws:iam::123456789012:root"
    assert (
        roles.resolve_principal(roles.PrincipalRef("principal", root), accounts).kind
        == "account"
    )
    assert (
        roles.resolve_principal(
            roles.PrincipalRef("caller", "", None), accounts, caller_arn=USER_ARN
        ).arn
        == USER_ARN
    )
    with pytest.raises(roles.IamRoleError, match="configured account"):
        roles.resolve_principal(roles.PrincipalRef("user", "x"), accounts)
    with pytest.raises(roles.IamRoleError, match="durable IAM user or role"):
        roles.resolve_principal(roles.PrincipalRef("caller", "bad"), accounts)
    with pytest.raises(roles.IamRoleError, match="Unsupported principal"):
        roles.resolve_principal(
            roles.PrincipalRef("service", "lambda", "prod"),  # type: ignore[arg-type]
            accounts,
        )


def test_execute_plan_success_and_reverse_compensation() -> None:
    client = Recorder()
    plan = roles.MutationPlan(
        "multi",
        ("x",),
        (
            roles.Operation("iam", "one", {"x": 1}, "undo_one", {"x": 1}),
            roles.Operation("iam", "two", {"x": 2}, "undo_two", {"x": 2}),
        ),
    )
    journal = roles.execute_plan(plan, lambda _name: client)
    assert [name for name, _ in client.calls] == ["one", "two"]
    assert len(journal.completed) == 2
    failing = Recorder(fail="two")
    with pytest.raises(RuntimeError, match="two"):
        roles.execute_plan(plan, lambda _name: failing)
    assert [name for name, _ in failing.calls] == ["one", "two", "undo_one"]


def test_role_create_update_ownership_and_tag_plans() -> None:
    spec = roles.RoleSpec(
        "Agent",
        TRUST,
        description="agent",
        max_session_duration=7200,
        permissions_boundary="arn:boundary",
        tags={"team": "platform"},
        owner="scott",
        audit_id="change-1",
    )
    create = roles.plan_create_role(spec)
    params = create.operations[0].params
    assert params["Path"] == "/hacksaws/"
    assert {item["Key"] for item in params["Tags"]} >= {
        roles.MANAGED_TAG,
        roles.OWNER_TAG,
        roles.AUDIT_TAG,
    }
    assert create.operations[0].compensate_action == "delete_role"
    with pytest.raises(roles.IamRoleError, match="Wildcard"):
        roles.plan_create_role(
            roles.RoleSpec("Bad", {"Statement": [{"Principal": "*"}]})
        )

    current = snapshot(description="old", permissions_boundary=None)
    update = roles.plan_update_role(current, spec)
    actions = [item.action for item in update.operations]
    assert actions[:3] == [
        "update_role",
        "put_role_permissions_boundary",
        "tag_role",
    ]
    assert "untag_role" in actions
    with pytest.raises(roles.ConflictError, match="replacement"):
        roles.plan_update_role(current, roles.RoleSpec("Other", TRUST))
    remove_boundary = roles.plan_update_role(
        snapshot(permissions_boundary="arn:boundary"), roles.RoleSpec("Agent", TRUST)
    )
    assert "delete_role_permissions_boundary" in [
        op.action for op in remove_boundary.operations
    ]
    changed_trust = {"Version": "2012-10-17", "Statement": []}
    trust_update = roles.plan_update_role(
        current, roles.RoleSpec("Agent", changed_trust)
    )
    assert "update_assume_role_policy" in [op.action for op in trust_update.operations]

    adopted = roles.plan_adopt_role(current, "scott", "audit")
    assert adopted.kind == "role-adopt"
    with pytest.raises(roles.ConflictError, match="already managed"):
        roles.plan_adopt_role(
            snapshot(tags={roles.MANAGED_TAG: "true", roles.OWNER_TAG: "other"}),
            "scott",
        )
    released = roles.plan_release_role(
        snapshot(tags={roles.MANAGED_TAG: "true", roles.OWNER_TAG: "x"})
    )
    assert released.operations[0].action == "untag_role"
    assert not roles.plan_put_tags("Agent", {}).operations
    assert not roles.plan_remove_tags("Agent", []).operations


def test_trust_set_add_remove_and_complex_ambiguity() -> None:
    principal = roles.DurablePrincipal(
        "role", "arn:aws:iam::123456789012:role/Caller", ACCOUNT.account_id, "aws"
    )
    added = roles.plan_add_trust("Agent", TRUST, principal, sid="Caller")
    desired = json.loads(added.operations[0].params["PolicyDocument"])
    assert desired["Statement"][-1]["Principal"]["AWS"] == principal.arn
    assert not roles.plan_add_trust("Agent", desired, principal).operations
    removed = roles.plan_remove_trust("Agent", desired, principal)
    assert (
        json.loads(removed.operations[0].params["PolicyDocument"])["Statement"]
        == TRUST["Statement"]
    )
    assert not roles.plan_remove_trust("Agent", TRUST, principal).operations
    with pytest.raises(roles.ConflictError, match="changed"):
        roles.plan_set_trust("Agent", TRUST, desired, expected_hash="stale")
    with pytest.raises(roles.IamRoleError, match="Wildcard"):
        roles.plan_set_trust("Agent", TRUST, {"Statement": [{"Principal": "*"}]})
    with pytest.raises(roles.IamRoleError, match="NotPrincipal"):
        roles.plan_set_trust(
            "Agent",
            TRUST,
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "NotPrincipal": {"AWS": USER_ARN},
                        "Action": "sts:AssumeRole",
                    }
                ]
            },
        )
    with pytest.raises(roles.IamRoleError, match="Wildcard"):
        roles.plan_update_role(
            snapshot(),
            roles.RoleSpec(
                "Agent",
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": f"{USER_ARN}*"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            ),
        )
    complex_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": [principal.arn, USER_ARN]},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    with pytest.raises(roles.AmbiguousTrustError, match="complex"):
        roles.plan_remove_trust("Agent", complex_doc, principal)
    with pytest.raises(roles.IamRoleError, match="Statement"):
        roles.plan_add_trust("Agent", {"Statement": "bad"}, principal)
    single_statement = {"Version": "2012-10-17", "Statement": TRUST["Statement"][0]}
    assert roles.plan_add_trust("Agent", single_statement, principal).operations
    denied = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {"AWS": principal.arn},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    assert roles.plan_add_trust("Agent", denied, principal).operations


def test_managed_attachment_publish_and_inline_policy_plans() -> None:
    attach = roles.plan_attach_policy("Agent", "arn:policy")
    assert attach.operations[0].compensate_action == "detach_role_policy"
    assert roles.plan_detach_policy("Agent", "arn:policy").operations[0].action == (
        "detach_role_policy"
    )
    document = {"Version": "2012-10-17", "Statement": []}
    publish = roles.plan_publish_and_attach("Agent", "Read", document, ACCOUNT)
    assert [op.action for op in publish.operations] == [
        "create_policy",
        "attach_role_policy",
    ]
    assert publish.resources[1].endswith("policy/hacksaws/Read")
    put = roles.plan_put_inline_policy("Agent", "Read", document)
    assert put.operations[0].compensate_action == "delete_role_policy"
    current = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny"}]}
    replace = roles.plan_put_inline_policy(
        "Agent",
        "Read",
        document,
        current=current,
        expected_hash=roles.document_hash(current),
    )
    assert replace.operations[0].compensate_action == "put_role_policy"
    with pytest.raises(roles.ConflictError, match="changed"):
        roles.plan_put_inline_policy(
            "Agent", "Read", document, current=current, expected_hash="bad"
        )
    assert roles.plan_delete_inline_policy("Agent", "Read").operations[0].action == (
        "delete_role_policy"
    )
    delete = roles.plan_delete_inline_policy("Agent", "Read", current=document)
    assert delete.operations[0].compensate_action == "put_role_policy"
    exported = roles.export_inline_policy(document)
    exported["Statement"].append("changed")
    assert document["Statement"] == []


def test_dependency_complete_role_delete_boundaries() -> None:
    unmanaged = snapshot(tags={})
    with pytest.raises(roles.DependencyError, match="not adopted"):
        roles.plan_delete_role(unmanaged)
    dependent = snapshot(
        attached_policies=("arn:one",),
        inline_policies=("Inline",),
        permissions_boundary="arn:boundary",
        instance_profiles=("Profile",),
        inline_policy_documents={"Inline": TRUST},
    )
    with pytest.raises(roles.DependencyError, match="cascade"):
        roles.plan_delete_role(dependent)
    with pytest.raises(roles.DependencyError, match="Instance-profile"):
        roles.plan_delete_role(dependent, cascade=True)
    plan = roles.plan_delete_role(
        dependent, cascade=True, remove_from_instance_profiles=True
    )
    assert [op.action for op in plan.operations] == [
        "detach_role_policy",
        "delete_role_policy",
        "delete_role_permissions_boundary",
        "remove_role_from_instance_profile",
        "delete_role",
    ]
    assert any("preserved" in warning for warning in plan.warnings)
    assert any("irreversible" in warning for warning in plan.warnings)
    assert plan.operations[1].compensate_action == "put_role_policy"
    assert plan.operations[-1].compensate_action is None
    assert roles.plan_delete_role(snapshot()).operations[-1].action == "delete_role"
    assert roles.plan_delete_role(unmanaged, allow_unmanaged=True).operations


def test_group_aggregate_grant_and_member_snapshot_plans() -> None:
    group = roles.GroupGrantSnapshot(
        "Agents",
        ACCOUNT,
        "hacksaws-Agents",
        "arn:aws:iam::123456789012:policy/hacksaws/hacksaws-Agents",
        (),
        exists=False,
        attached=False,
    )
    grant = roles.plan_group_grant(
        snapshot(), {"Version": "2012-10-17", "Statement": []}, group
    )
    assert [op.action for op in grant.operations] == [
        "update_assume_role_policy",
        "publish_owned_policy",
        "attach_group_policy",
    ]
    existing = roles.GroupGrantSnapshot(
        group.group_name,
        group.account,
        group.policy_name,
        group.policy_arn,
        (ROLE_ARN,),
    )
    existing = roles.GroupGrantSnapshot(
        existing.group_name,
        existing.account,
        existing.policy_name,
        existing.policy_arn,
        existing.role_arns,
        document=roles._group_document(existing.role_arns),
        owned=True,
    )
    assert roles.plan_add_group_member(existing, ROLE_ARN).operations[0].action == (
        "publish_owned_policy"
    )
    second = "arn:aws:iam::123456789012:role/hacksaws/Other"
    sync = roles.plan_sync_group_members(existing, [second])
    assert second in sync.resources
    remove = roles.plan_remove_group_member(existing, ROLE_ARN)
    document = remove.operations[0].params["PolicyDocument"]
    assert isinstance(document, dict)
    assert document["Statement"] == []
    other_account = "arn:aws:iam::210987654321:role/hacksaws/Other"
    with pytest.raises(roles.IamRoleError, match="group's account"):
        roles.plan_add_group_member(existing, other_account)
    with pytest.raises(roles.IamRoleError, match="same-account"):
        roles.plan_group_grant(snapshot(arn=other_account), TRUST, existing)
    unrelated = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Unrelated",
                "Effect": "Deny",
                "Action": "iam:*",
                "Resource": "*",
            },
            {
                "Sid": "HacksawsGroupAssumeRoles",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": ROLE_ARN,
            },
        ],
    }
    preserved = roles._group_document([second], unrelated)
    assert preserved["Statement"][0] == unrelated["Statement"][0]
    assert preserved["Statement"][1]["Resource"] == [second]


def test_group_trust_uses_owned_statement_and_preserves_preexisting_root() -> None:
    account_root = f"arn:aws:iam::{ACCOUNT.account_id}:root"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Preexisting",
                "Effect": "Allow",
                "Principal": {"AWS": account_root},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    principal = roles.DurablePrincipal(
        "account", account_root, ACCOUNT.account_id, "aws"
    )
    added = roles.plan_add_owned_group_trust("Agent", trust, principal)
    desired = roles.decode_document(added.operations[0].params["PolicyDocument"])
    assert [item["Sid"] for item in desired["Statement"]] == [
        "Preexisting",
        "HacksawsGroupAccount",
    ]
    removed = roles.plan_remove_owned_group_trust("Agent", desired, principal)
    restored = roles.decode_document(removed.operations[0].params["PolicyDocument"])
    assert restored == trust


def test_static_assumability_and_explicit_probe() -> None:
    assert (
        roles.classify_assumability(
            trust_allows=True, identity_allows=True
        ).classification
        == "potentially-allowed"
    )
    assert (
        roles.classify_assumability(
            trust_allows=True, identity_allows=True, explicit_deny=True
        ).classification
        == "denied"
    )
    assert (
        roles.classify_assumability(
            trust_allows=None, identity_allows=True
        ).classification
        == "indeterminate"
    )
    client = Recorder()
    client.assume_role = lambda **params: (
        client.calls.append(("assume_role", params))
        or {
            "Credentials": {"AccessKeyId": "never exposed"},
            "PackedPolicySize": 4,
        }
    )
    result = roles.BotoStsProbe(client).probe(ROLE_ARN, "probe", "external")
    assert result == {"ok": True, "packed_policy_size": 4}
    request = client.calls[0][1]
    assert request["Policy"] == roles.DENY_ALL
    assert request["DurationSeconds"] == 900
    assert request["ExternalId"] == "external"
    roles.BotoStsProbe(client).probe(ROLE_ARN, "probe")
    assert "ExternalId" not in client.calls[-1][1]


def test_role_service_paginates_reads_and_retries_eventual_consistency() -> None:
    client = ReadClient()
    client.fail_once = True
    sleeps: list[float] = []
    service = roles.IamRoleService(client, attempts=2, delay=0.01, sleep=sleeps.append)
    role = service.get_role("Agent")
    assert role.attached_policies == ("arn:policy/one", "arn:policy/two")
    assert role.inline_policies == ("InlineOne", "InlineTwo")
    assert role.instance_profiles == ("profile",)
    assert role.inline_policy_documents["InlineOne"]["Version"] == "2012-10-17"
    assert role.permissions_boundary == "arn:boundary"
    assert sleeps == [0.01]
    listed = service.list_roles()
    assert listed[0].name == "Agent"
    assert client.paginators["list_roles"].params == {"PathPrefix": "/hacksaws/"}
    assert service.list_inline_policies("Agent") == ("InlineOne", "InlineTwo")
    assert service.get_inline_policy("Agent", "Read")["Version"] == "2012-10-17"
    assert service.get_trust("Agent") == TRUST


def test_role_service_retry_exhaustion_propagates_client_error() -> None:
    client = ReadClient()

    def always_fail(**params: Any) -> dict[str, Any]:
        del params
        raise ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "wait"}}, "GetRole"
        )

    client.get_role = always_fail  # type: ignore[method-assign]
    service = roles.IamRoleService(
        client, attempts=2, delay=0, sleep=lambda _value: None
    )
    with pytest.raises(ClientError):
        service.get_trust("Agent")
