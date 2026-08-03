"""Focused command-adapter tests for IAM role workflows."""

# ruff: noqa: ANN401, ARG005, D101, D102, D107, FBT002, FBT003, PT018

from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from botocore.exceptions import ClientError
from botocore.exceptions import EndpointConnectionError

from hacksaws import _configs
from hacksaws import _iam_managed_policies as managed
from hacksaws import _iam_recovery as recovery
from hacksaws import _iam_role_cli as cli
from hacksaws import _iam_roles as roles
from hacksaws._configs import OperationalError

ACCOUNT_ID = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT_ID}:user/scott"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/hacksaws/Agent"
TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": CALLER},
            "Action": "sts:AssumeRole",
        }
    ],
}
POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "logs:Get*", "Resource": "x"}],
}


def role_snapshot(**overrides: Any) -> roles.RoleSnapshot:
    values: dict[str, Any] = {
        "name": "Agent",
        "arn": ROLE_ARN,
        "path": "/hacksaws/",
        "trust": TRUST,
        "description": "agent",
        "tags": {roles.MANAGED_TAG: "true", roles.OWNER_TAG: CALLER},
        "attached_policies": ("arn:aws:iam::aws:policy/ReadOnlyAccess",),
        "inline_policies": ("Read",),
        "inline_policy_documents": {"Read": POLICY},
        "role_id": "AIDAEXAMPLE",
    }
    values.update(overrides)
    return roles.RoleSnapshot(**values)


class FakeService:
    def __init__(self, role: roles.RoleSnapshot | None = None) -> None:
        self.role = role or role_snapshot()
        self.inline = dict(self.role.inline_policy_documents)

    def get_role(self, name: str) -> roles.RoleSnapshot:
        if name != self.role.name:
            raise client_error("NoSuchEntity")
        return self.role

    def list_roles(
        self, *, path_prefix: str = "/hacksaws/"
    ) -> tuple[roles.RoleSnapshot, ...]:
        assert path_prefix == "/"
        return (self.role,)

    def get_trust(self, name: str) -> dict[str, Any]:
        assert name == self.role.name
        return dict(self.role.trust)

    def list_inline_policies(self, name: str) -> tuple[str, ...]:
        assert name == self.role.name
        return tuple(self.inline)

    def get_inline_policy(self, name: str, policy: str) -> dict[str, Any]:
        assert name == self.role.name
        if policy not in self.inline:
            raise client_error("NoSuchEntity")
        return dict(self.inline[policy])


class Paginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.calls: list[dict[str, Any]] = []

    def paginate(self, **params: Any) -> list[dict[str, Any]]:
        self.calls.append(params)
        return self.pages


class FakeIam:
    def __init__(self) -> None:
        self.policy_pages = Paginator(
            [
                {
                    "Policies": [
                        {
                            "PolicyName": "ReadOnlyAccess",
                            "Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                        }
                    ]
                }
            ]
        )
        self.group_pages = Paginator([{"AttachedPolicies": []}])
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.group_policy_exists = False

    def get_paginator(self, name: str) -> Paginator:
        return self.policy_pages if name == "list_policies" else self.group_pages

    def get_user(self, **params: Any) -> dict[str, Any]:
        self.calls.append(("get_user", params))
        return {"User": {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{params['UserName']}"}}

    def get_role(self, **params: Any) -> dict[str, Any]:
        self.calls.append(("get_role", params))
        return {
            "Role": {
                "RoleName": params["RoleName"],
                "Arn": f"arn:aws:iam::{ACCOUNT_ID}:role/team/{params['RoleName']}",
            }
        }

    def get_group(self, **params: Any) -> dict[str, Any]:
        self.calls.append(("get_group", params))
        return {"Users": []}

    def get_policy(self, **params: Any) -> dict[str, Any]:
        if not self.group_policy_exists:
            raise client_error("NoSuchEntity")
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, **params: Any) -> dict[str, Any]:
        del params
        return {
            "PolicyVersion": {
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "HacksawsGroupAssumeRoles",
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": ROLE_ARN,
                        }
                    ],
                }
            }
        }

    def list_policy_tags(self, **params: Any) -> dict[str, Any]:
        del params
        return {
            "Tags": (
                [
                    {"Key": "hacksaws:managed-by", "Value": "hacksaws"},
                    {"Key": "hacksaws:resource-kind", "Value": "managed-policy"},
                    {"Key": "hacksaws:resource-id", "Value": "group-Agents"},
                ]
                if self.group_policy_exists
                else []
            )
        }


class FakeSts:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[dict[str, Any]] = []

    def assume_role(self, **params: Any) -> dict[str, Any]:
        self.calls.append(params)
        if self.fail:
            raise client_error("AccessDenied")
        return {"PackedPolicySize": 1, "Credentials": {"SecretAccessKey": "hidden"}}


class Tty:
    def __init__(self, tty: bool) -> None:
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


def client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "operation")


def context(*, iam: Any | None = None, sts: Any | None = None) -> Any:
    return SimpleNamespace(
        iam=iam or FakeIam(),
        sts=sts or FakeSts(),
        account_id=ACCOUNT_ID,
        partition="aws",
        arn=CALLER,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    cli.register(result)
    return result


def parse(arguments: list[str]) -> argparse.Namespace:
    return parser().parse_args(arguments)


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    data = {
        "accounts": {"prod": {"id": ACCOUNT_ID, "partition": "aws"}},
        "iam": {"path": "/hacksaws/"},
        "naming": {
            "global": {
                "case": "Pascal",
                "prefix": "",
                "suffix": "",
                "enforcement": "off",
            },
            "resources": {},
            "accounts": {},
            "account_resources": {},
        },
    }
    monkeypatch.setattr(cli._state, "load_config", lambda: data)
    return data


@pytest.fixture
def harness(
    monkeypatch: pytest.MonkeyPatch, configured: dict[str, Any]
) -> tuple[FakeService, list[roles.MutationPlan]]:
    del configured
    service = FakeService()
    plans: list[roles.MutationPlan] = []
    monkeypatch.setattr(cli, "_service", lambda _context: service)
    monkeypatch.setattr(
        cli,
        "_execute",
        lambda plan, _context, _args: plans.append(plan) or roles.ExecutionJournal(),
    )
    monkeypatch.setattr(
        cli,
        "_owned_publish_attach_plan",
        lambda role, policy_name, document, path, _context: roles.MutationPlan(
            "policy-publish-attach",
            (role.arn, f"arn:aws:iam::{ACCOUNT_ID}:policy{path}{policy_name}"),
            (
                roles.Operation(
                    "managed_policy",
                    "publish_owned_policy",
                    {"PolicyDocument": dict(document)},
                ),
                *roles.plan_attach_policy(
                    role.name,
                    f"arn:aws:iam::{ACCOUNT_ID}:policy{path}{policy_name}",
                    current=role,
                ).operations,
            ),
        ),
    )
    return service, plans


@pytest.mark.parametrize(
    ("arguments", "command", "nested"),
    [
        (["create", "Agent", "--trust-caller"], "create", None),
        (["get", "Agent"], "get", None),
        (["list", "Agent*", "--wide"], "list", None),
        (["update", "Agent", "--ttl", "2h"], "update", None),
        (["delete", "Agent", "--cascade"], "delete", None),
        (["attach", "Agent", "ReadOnlyAccess"], "attach", None),
        (["detach", "Agent", "ReadOnlyAccess"], "detach", None),
        (["tag", "set", "Agent", "team=platform"], "tag", "set"),
        (["inline-policy", "get", "Agent", "Read"], "inline-policy", "get"),
        (["trust", "add", "user", "Agent", "scott"], "trust", "add"),
        (["trust", "grant", "group", "Agent", "Agents"], "trust", "grant"),
        (["trust", "sync", "group-members", "Agents", "Agent"], "trust", "sync"),
    ],
)
def test_register_exposes_locked_grammar(
    arguments: list[str], command: str, nested: str | None
) -> None:
    args = parse(arguments)
    assert args.role_command == command
    if nested and command == "tag":
        assert args.role_tag_action == nested
    if nested and command == "inline-policy":
        assert args.role_inline_action == nested


def test_create_uses_naming_duration_tags_and_exact_caller(
    harness: Any, configured: dict[str, Any]
) -> None:
    _, plans = harness
    configured["naming"]["resources"]["role"] = {
        "prefix": "RB-",
        "enforcement": "warn",
    }
    result = cli.dispatch(
        parse(
            [
                "create",
                "agent",
                "--trust-caller",
                "--ttl",
                "2h",
                "--tag",
                "team=platform",
            ]
        ),
        context(),
    )
    assert result is not None and result.code == "IAM_ROLE_CREATED"
    assert "Warning" in result.message
    operation = plans[0].operations[0]
    assert operation.params["RoleName"] == "RB-Agent"
    assert operation.params["MaxSessionDuration"] == 7200
    trust = json.loads(operation.params["AssumeRolePolicyDocument"])
    assert trust["Statement"][0]["Principal"]["AWS"] == CALLER


def test_role_dry_run_returns_materialized_plan_without_journal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = FakeService()
    monkeypatch.setattr(cli, "_service", lambda _context: service)
    result = cli.dispatch(
        parse(["update", "Agent", "--description", "changed", "--dry-run"]),
        context(),
    )
    assert result is not None
    assert result.code == "IAM_ROLE_DRY_RUN"
    assert result.data["dryRun"] is True
    assert result.data["operations"][0]["action"] == "update_role"


def test_create_noninteractive_requires_explicit_trust(
    monkeypatch: pytest.MonkeyPatch, harness: Any
) -> None:
    del harness
    monkeypatch.setattr(cli.sys, "stdin", Tty(False))
    with pytest.raises(OperationalError, match="Noninteractive"):
        cli.dispatch(parse(["create", "Agent"]), context())


def test_get_and_list_default_scope_with_probe(harness: Any) -> None:
    service, _ = harness
    result = cli.dispatch(parse(["get", ROLE_ARN]), context())
    assert result is not None and result.data["inlinePolicies"]["Read"] == POLICY
    sts = FakeSts()
    listed = cli.dispatch(parse(["list", "A*", "--wide", "--probe"]), context(sts=sts))
    assert listed is not None and "Legend:" in listed.message
    assert listed.data["roles"][0]["probe"] == "ok"
    assert "CloudTrail" in listed.message
    service.role = role_snapshot(path="/aws-service-role/example/", tags={})
    service.inline = dict(service.role.inline_policy_documents)
    service_result = cli.dispatch(parse(["list", "--service"]), context())
    assert service_result is not None and service_result.data["roles"]


def test_list_custom_all_pattern_and_failed_probe(harness: Any) -> None:
    service, _ = harness
    service.role = role_snapshot(tags={})
    custom = cli.dispatch(parse(["list", "--custom"]), context())
    assert custom is not None and custom.data["roles"]
    missing = cli.dispatch(parse(["list", "Nope*"]), context())
    assert missing is not None and not missing.data["roles"]
    failed = cli.dispatch(
        parse(["list", "--all", "--probe"]), context(sts=FakeSts(True))
    )
    assert failed is not None and failed.data["roles"][0]["probe"] == "denied"

    class BrokenSts:
        def assume_role(self, **_params: Any) -> object:
            raise EndpointConnectionError(endpoint_url="https://sts.invalid")

    indeterminate = cli.dispatch(
        parse(["list", "--all", "--probe"]), context(sts=BrokenSts())
    )
    assert indeterminate is not None
    assert indeterminate.data["roles"][0]["probe"] == "indeterminate"


def test_update_and_delete_layered_safeguards(harness: Any) -> None:
    service, plans = harness
    updated = cli.dispatch(
        parse(
            [
                "update",
                "Agent",
                "--clear-description",
                "--clear-permissions-boundary",
                "--stl",
                "3600",
            ]
        ),
        context(),
    )
    assert updated is not None and updated.code == "IAM_ROLE_UPDATED"
    service.role = role_snapshot(
        path="/aws-service-role/test/", inline_policies=(), inline_policy_documents={}
    )
    with pytest.raises(OperationalError, match="Service-linked"):
        cli.dispatch(parse(["delete", "Agent", "--yes"]), context())
    service.role = role_snapshot(
        attached_policies=(), inline_policies=(), inline_policy_documents={}
    )
    captured = cli.dispatch(parse(["delete", "Agent"]), context())
    assert captured is not None and captured.code == "IAM_ROLE_DELETED"
    deleted = cli.dispatch(parse(["delete", "Agent", "--yes"]), context())
    assert deleted is not None and deleted.code == "IAM_ROLE_DELETED"
    assert plans[-1].operations[-1].action == "delete_role"


def test_remote_and_local_attach_and_detach(tmp_path: Path, harness: Any) -> None:
    service, plans = harness
    service.role = role_snapshot(attached_policies=())
    remote = cli.dispatch(parse(["attach", "Agent", "ReadOnlyAccess"]), context())
    assert remote is not None and plans[-1].operations[0].action == "attach_role_policy"
    service.role = role_snapshot()
    detached = cli.dispatch(parse(["detach", "Agent", "ReadOnlyAccess"]), context())
    assert (
        detached is not None and plans[-1].operations[0].action == "detach_role_policy"
    )
    path = tmp_path / "local.yaml"
    path.write_text(yaml.safe_dump(POLICY), encoding="utf-8")
    published = cli.dispatch(parse(["attach", "Agent", str(path)]), context())
    assert published is not None and [op.action for op in plans[-1].operations] == [
        "publish_owned_policy",
        "attach_role_policy",
    ]
    inline = cli.dispatch(
        parse(["attach", "Agent", str(path), "--inline", "--policy-name", "Local"]),
        context(),
    )
    assert inline is not None and plans[-1].kind == "inline-policy-put"


def test_tags_adopt_release_and_confirmations(harness: Any) -> None:
    service, plans = harness
    listed = cli.dispatch(parse(["tag", "list", "Agent"]), context())
    assert listed is not None and listed.data["tags"][roles.MANAGED_TAG] == "true"
    cli.dispatch(parse(["tag", "set", "Agent", "team=platform"]), context())
    assert plans[-1].operations[0].action == "tag_role"
    cli.dispatch(parse(["tag", "remove", "Agent", "team"]), context())
    assert plans[-1].operations[0].action == "untag_role"
    service.role = role_snapshot(tags={"team": "platform"})
    adopted = cli.dispatch(
        parse(["adopt", "Agent", "--yes", "--owner", "scott"]), context()
    )
    assert adopted is not None and plans[-1].kind == "role-adopt"
    released = cli.dispatch(parse(["release", "Agent", "--yes"]), context())
    assert released is not None and plans[-1].kind == "role-release"


def test_inline_policy_crud_export_and_new_put(tmp_path: Path, harness: Any) -> None:
    service, plans = harness
    listed = cli.dispatch(parse(["inline-policy", "list", "Agent"]), context())
    assert listed is not None and listed.data["policies"] == ["Read"]
    got = cli.dispatch(parse(["inline-policy", "get", "Agent", "Read"]), context())
    assert got is not None and got.data == POLICY
    output = tmp_path / "read.yaml"
    exported = cli.dispatch(
        parse(["inline-policy", "export", "Agent", "Read", "--output", str(output)]),
        context(),
    )
    assert exported is not None and output.exists()
    new_file = tmp_path / "new.json"
    new_file.write_text(json.dumps(POLICY), encoding="utf-8")
    put = cli.dispatch(
        parse(["inline-policy", "put", "Agent", "New", str(new_file)]), context()
    )
    assert (
        put is not None
        and plans[-1].operations[0].compensate_action == "delete_role_policy"
    )
    deleted = cli.dispatch(
        parse(["inline-policy", "delete", "Agent", "Read", "--yes"]), context()
    )
    assert (
        deleted is not None and plans[-1].operations[0].action == "delete_role_policy"
    )
    service.inline["Read"] = POLICY


def test_inline_edit_backup_and_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: Any
) -> None:
    service, plans = harness
    monkeypatch.setenv("EDITOR", "fake --wait")
    monkeypatch.setattr(cli._state, "root", lambda: tmp_path)

    def editor(command: list[str], **kwargs: Any) -> Any:
        del kwargs
        path = Path(command[-1])
        changed = {**POLICY, "Statement": []}
        path.write_text(yaml.safe_dump(changed), encoding="utf-8")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli, "_editor_runner", editor)
    result = cli.dispatch(parse(["inline-policy", "edit", "Agent", "Read"]), context())
    assert result is not None and plans[-1].kind == "inline-policy-put"
    assert list((tmp_path / "backups").glob("*.yaml"))
    calls = 0
    original = service.get_inline_policy

    def drift(name: str, policy: str) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return (
            {"Version": "changed", "Statement": []}
            if calls > 1
            else original(name, policy)
        )

    service.get_inline_policy = drift  # type: ignore[method-assign]
    with pytest.raises(OperationalError, match="changed while"):
        cli.dispatch(parse(["inline-policy", "edit", "Agent", "Read"]), context())


def test_trust_get_export_set_edit_and_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: Any
) -> None:
    _, plans = harness
    got = cli.dispatch(parse(["trust", "get", "Agent"]), context())
    assert got is not None and got.data == TRUST
    output = tmp_path / "trust.json"
    cli.dispatch(
        parse(
            [
                "trust",
                "export",
                "Agent",
                "--format",
                "json",
                "-o",
                str(output),
                "--metadata",
                "nested",
            ]
        ),
        context(),
    )
    assert json.loads(output.read_text())["metadata"]["name"] == "Agent-trust"
    source = tmp_path / "trust.yaml"
    source.write_text(yaml.safe_dump(TRUST), encoding="utf-8")
    cli.dispatch(parse(["trust", "set", "Agent", str(source)]), context())
    assert plans[-1].kind == "trust-set"
    checked = cli.dispatch(parse(["trust", "check", "Agent", "--probe"]), context())
    assert checked is not None and checked.data["probe"]["ok"] is True
    monkeypatch.setenv("EDITOR", "fake")
    monkeypatch.setattr(cli._state, "root", lambda: tmp_path)
    monkeypatch.setattr(
        cli, "_editor_runner", lambda command, **kwargs: SimpleNamespace(returncode=0)
    )
    edited = cli.dispatch(parse(["trust", "edit", "Agent"]), context())
    assert edited is not None and plans[-1].kind == "trust-set"


def test_trust_principals_conditions_remove_and_errors(harness: Any) -> None:
    _, plans = harness
    added = cli.dispatch(
        parse(
            [
                "trust",
                "add",
                "user",
                "Agent",
                "alice",
                "--sid",
                "Alice",
                "--condition",
                "StringEquals:aws:PrincipalTag/team=platform",
            ]
        ),
        context(),
    )
    assert added is not None and plans[-1].kind == "trust-set"
    document = json.loads(plans[-1].operations[0].params["PolicyDocument"])
    assert document["Statement"][-1]["Condition"]["StringEquals"]
    removed = cli.dispatch(
        parse(["trust", "remove", "user", "Agent", "scott"]), context()
    )
    assert removed is not None
    with pytest.raises(OperationalError, match="without wildcards"):
        cli.dispatch(
            parse(
                [
                    "trust",
                    "add",
                    "role",
                    "Agent",
                    "Other",
                    "--condition",
                    "StringLike:key=*",
                ]
            ),
            context(),
        )
    with pytest.raises(OperationalError, match="Configured account"):
        cli.dispatch(parse(["trust", "add", "account", "Agent", "missing"]), context())


def test_group_grant_revoke_and_member_snapshots(harness: Any) -> None:
    _, plans = harness
    granted = cli.dispatch(
        parse(["trust", "grant", "group", "Agent", "Agents"]), context()
    )
    assert granted is not None and plans[-1].kind == "group-grant"
    revoked = cli.dispatch(
        parse(["trust", "revoke", "group", "Agent", "Agents"]), context()
    )
    assert revoked is not None and plans[-1].kind == "group-revoke"
    for action in ("add", "sync", "remove"):
        result = cli.dispatch(
            parse(["trust", action, "group-members", "Agents", "Agent"]), context()
        )
        assert result is not None and plans[-1].kind == "group-snapshot"


def test_remaining_group_grants_requires_a_live_attached_exact_aggregate() -> None:
    iam = FakeIam()
    iam.group_policy_exists = True
    arn = f"arn:aws:iam::{ACCOUNT_ID}:policy/hacksaws/hacksaws-Agents-assume-roles"
    iam.policy_pages.pages = [
        {"Policies": [{"PolicyName": "hacksaws-Agents-assume-roles", "Arn": arn}]}
    ]
    assert cli._remaining_group_grants(ROLE_ARN, "excluded", context(iam=iam)) == ()
    iam.group_pages.pages = [{"AttachedPolicies": [{"PolicyArn": arn}]}]
    assert cli._remaining_group_grants(ROLE_ARN, "excluded", context(iam=iam)) == (arn,)


def test_group_attachment_drift_fails_before_journaling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli._state, "root", lambda: tmp_path)
    iam = FakeIam()
    group = cli._group_snapshot("Agents", context(iam=iam))
    plan = roles.plan_sync_group_members(group, [ROLE_ARN])
    iam.group_pages.pages = [{"AttachedPolicies": [{"PolicyArn": group.policy_arn}]}]
    with pytest.raises(OperationalError, match="attachment changed"):
        cli._assert_preconditions(plan, context(iam=iam))
    assert recovery.list_journals() == []


def test_helpers_errors_exports_and_dispatch_normalization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, configured: dict[str, Any]
) -> None:
    assert cli.name == "role"
    assert cli.dispatch(argparse.Namespace(), context()) is None
    with pytest.raises(OperationalError, match="Invalid IAM role"):
        cli._role_name("bad/name", context())
    with pytest.raises(OperationalError, match="does not belong"):
        cli._role_name("arn:aws:iam::210987654321:role/Other", context())
    with pytest.raises(OperationalError, match="KEY=VALUE"):
        cli._parse_tags(["bad"])
    with pytest.raises(OperationalError, match="more than once"):
        cli._parse_tags(["x=1", "x=2"])
    with pytest.raises(OperationalError, match="requires --output"):
        cli._export(
            POLICY,
            SimpleNamespace(
                format="yaml", metadata="sidecar", output=None, sidecar=None
            ),
            "Read",
        )
    output = tmp_path / "read.yaml"
    sidecar = tmp_path / "meta.yaml"
    result = cli._export(
        POLICY,
        SimpleNamespace(
            format="yaml", metadata="sidecar", output=output, sidecar=sidecar
        ),
        "Read",
    )
    assert len(result.data["files"]) == 2
    monkeypatch.delenv("EDITOR", raising=False)
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setattr(cli._state, "root", lambda: tmp_path)
    with pytest.raises(OperationalError, match="VISUAL"):
        cli._edit_document(POLICY, "Read")
    configured["naming"]["resources"]["role"] = {"prefix": "X", "enforcement": "error"}
    with pytest.raises(OperationalError, match="violates"):
        cli._configured_name(
            "Agent",
            argparse.Namespace(
                case=None, prefix=None, suffix=None, naming_enforcement=None
            ),
            context(),
        )


def test_execution_role_reference_case_and_confirmation_helpers(
    monkeypatch: pytest.MonkeyPatch, configured: dict[str, Any]
) -> None:
    recorder = SimpleNamespace(calls=[])

    def mutate(**params: Any) -> None:
        recorder.calls.append(params)

    recorder.mutate = mutate
    plan = roles.MutationPlan(
        "test", ("x",), (roles.Operation("iam", "mutate", {"value": 1}),)
    )
    roles.execute_plan(plan, lambda _name: recorder)
    assert recorder.calls == [{"value": 1}]
    with pytest.raises(OperationalError, match="Invalid IAM role ARN"):
        cli._role_name("arn:aws:iam::bad:role/X", context())
    assert cli._account_name(context(iam=FakeIam())) == "prod"
    configured["accounts"] = {}
    assert cli._account_name(context()) is None
    assert cli._apply_case("", "snake") == ""
    assert cli._apply_case("hello world", "snake") == "hello_world"
    assert cli._apply_case("hello world", "kebab") == "hello-world"
    monkeypatch.setattr(cli.sys, "stdin", Tty(True))
    monkeypatch.setattr(cli, "_input", lambda _prompt: "Agent")
    assert cli._confirm_exact("delete", "Agent", yes=False)


def test_document_and_trust_creation_variants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: Any
) -> None:
    del harness
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(OperationalError, match="Invalid JSON"):
        cli._load_document(invalid, SimpleNamespace(metadata="none", sidecar=None))
    policy = tmp_path / "trust.yaml"
    policy.write_text(yaml.safe_dump(TRUST), encoding="utf-8")
    args = parse(["create", "Agent", "--trust-policy", str(policy)])
    assert cli._trust_for_create(args, context()) == TRUST
    with pytest.raises(OperationalError, match="only one"):
        cli._trust_for_create(
            parse(
                [
                    "create",
                    "Agent",
                    "--trust-policy",
                    str(policy),
                    "--trust-caller",
                ]
            ),
            context(),
        )
    monkeypatch.setattr(cli.sys, "stdin", Tty(True))
    interactive = cli._trust_for_create(parse(["create", "Agent"]), context())
    assert interactive["Statement"][0]["Principal"]["AWS"] == CALLER


def test_caller_trust_shapes_and_policy_resolution_errors(harness: Any) -> None:
    del harness
    ctx = context()
    assert cli._caller_trust(
        role_snapshot(trust={"Statement": TRUST["Statement"][0]}), ctx
    )
    assert cli._caller_trust(role_snapshot(trust={"Statement": "bad"}), ctx) is None
    denied = role_snapshot(
        trust={
            "Statement": [
                {"Effect": "Deny", "Principal": {"AWS": CALLER}},
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": CALLER},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"x": "y"}},
                },
            ]
        }
    )
    assert cli._caller_trust(denied, ctx) is None
    assert cli._resolve_policy_arn("arn:aws:iam::aws:policy/X", ctx).endswith("/X")
    with pytest.raises(OperationalError, match="partition"):
        cli._resolve_policy_arn("arn:aws-cn:iam::aws:policy/X", ctx)
    with pytest.raises(OperationalError, match="authenticated caller account"):
        cli._resolve_policy_arn("arn:aws:iam::999999999999:policy/X", ctx)
    sensitive_path = "C:/private/agent-policy.json"
    with pytest.raises(
        OperationalError, match="Invalid IAM managed-policy ARN"
    ) as caught:
        cli._resolve_policy_arn(f"arn:aws:s3:::{sensitive_path}", ctx)
    assert sensitive_path not in str(caught.value)
    empty = FakeIam()
    empty.policy_pages = Paginator([{"Policies": []}])
    with pytest.raises(OperationalError, match="not found"):
        cli._resolve_policy_arn("Missing", context(iam=empty))
    ambiguous = FakeIam()
    ambiguous.policy_pages = Paginator(
        [
            {
                "Policies": [
                    {"PolicyName": "Read", "Arn": "arn:one"},
                    {"PolicyName": "Read", "Arn": "arn:two"},
                ]
            }
        ]
    )
    with pytest.raises(OperationalError, match="ambiguous"):
        cli._resolve_policy_arn("Read", context(iam=ambiguous))


@pytest.mark.parametrize(
    ("partition", "region", "domain"),
    [
        ("aws", "us-west-2", "us-west-2.console.aws.amazon.com"),
        ("aws-cn", "cn-north-1", "cn-north-1.console.amazonaws.cn"),
        (
            "aws-us-gov",
            "us-gov-west-1",
            "us-gov-west-1.console.amazonaws-us-gov.com",
        ),
    ],
)
def test_console_links_use_verified_partition_and_canonical_region(
    partition: str, region: str, domain: str
) -> None:
    ctx = SimpleNamespace(partition=partition, region_name=region)
    url = cli._console_url(ctx, "Agent")
    assert url.startswith(f"https://{domain}/")
    assert f"region={region}" in url


def test_principal_resolution_forms_and_user_failure(
    configured: dict[str, Any],
) -> None:
    del configured
    ctx = context()
    root = f"arn:aws:iam::{ACCOUNT_ID}:root"
    assert cli._principal("principal", root, None, ctx).kind == "account"
    assert cli._principal("account", "prod", None, ctx).account_id == ACCOUNT_ID
    assert (
        cli._principal("account", "210987654321", None, ctx).account_id
        == "210987654321"
    )
    assert cli._principal("role", "prod:Other", None, ctx).arn.endswith(
        "role/team/Other"
    )

    class BadUserIam(FakeIam):
        def get_user(self, **params: Any) -> dict[str, Any]:
            del params
            raise client_error("NoSuchEntity")

    with pytest.raises(OperationalError, match="Unable to resolve IAM user"):
        cli._principal("user", "missing", None, context(iam=BadUserIam()))


def test_simple_trust_add_group_existing_and_group_errors(harness: Any) -> None:
    _, plans = harness
    added = cli.dispatch(parse(["trust", "add", "role", "Agent", "Other"]), context())
    assert added is not None
    assert plans[-1].kind == "trust-set"
    iam = FakeIam()
    iam.group_policy_exists = True
    snapshot = cli._group_snapshot("Agents", context(iam=iam))
    assert snapshot.exists
    assert snapshot.role_arns == (ROLE_ARN,)

    class BadGroupIam(FakeIam):
        def get_group(self, **params: Any) -> dict[str, Any]:
            del params
            raise client_error("NoSuchEntity")

    with pytest.raises(OperationalError, match="Unable to resolve IAM group"):
        cli._group_snapshot("Missing", context(iam=BadGroupIam()))


def test_inline_missing_cancel_drift_and_probe_denial(
    tmp_path: Path, harness: Any
) -> None:
    service, _ = harness
    with pytest.raises(OperationalError, match="NoSuchEntity"):
        cli.dispatch(parse(["inline-policy", "get", "Agent", "Missing"]), context())
    captured = cli.dispatch(
        parse(["inline-policy", "delete", "Agent", "Read"]), context()
    )
    assert captured is not None
    assert captured.code == "IAM_ROLE_INLINE_MUTATED"
    source = tmp_path / "new.json"
    source.write_text(json.dumps(POLICY), encoding="utf-8")
    calls = 0
    original = service.get_inline_policy

    def drift(name: str, policy: str) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        value = original(name, policy)
        return {"Version": "changed", "Statement": []} if calls > 1 else value

    service.get_inline_policy = drift  # type: ignore[method-assign]
    with pytest.raises(OperationalError, match="changed before"):
        cli.dispatch(
            parse(["inline-policy", "put", "Agent", "Read", str(source)]),
            context(),
        )
    checked = cli.dispatch(
        parse(["trust", "check", "Agent", "--probe"]),
        context(sts=FakeSts(fail=True)),
    )
    assert checked is not None
    assert checked.data["probe"]["ok"] is False


def test_editor_failure_help_cancellations_and_error_normalization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: Any
) -> None:
    del harness
    monkeypatch.setenv("EDITOR", "fake")
    monkeypatch.setattr(cli._state, "root", lambda: tmp_path)
    monkeypatch.setattr(
        cli,
        "_editor_runner",
        lambda _command, **_kwargs: SimpleNamespace(returncode=2),
    )
    with pytest.raises(OperationalError, match="status 2"):
        cli._edit_document(POLICY, "Read")
    inline_help = cli.dispatch(parse(["inline-policy"]), context())
    trust_help = cli.dispatch(parse(["trust"]), context())
    assert inline_help is not None and inline_help.exit_code == 2
    assert trust_help is not None and trust_help.exit_code == 2
    ownership = cli.dispatch(parse(["release", "Agent"]), context())
    assert ownership is not None and ownership.code == "IAM_ROLE_OWNERSHIP"
    assert cli._dispatch(argparse.Namespace(role_command="unknown"), context()) is None

    monkeypatch.setattr(
        cli,
        "_dispatch",
        lambda _args, _context: (_ for _ in ()).throw(roles.IamRoleError("bad")),
    )
    with pytest.raises(OperationalError, match="bad"):
        cli.dispatch(argparse.Namespace(), context())
    monkeypatch.setattr(
        cli,
        "_dispatch",
        lambda _args, _context: (_ for _ in ()).throw(client_error("Denied")),
    )
    with pytest.raises(OperationalError, match="AWS IAM"):
        cli.dispatch(argparse.Namespace(), context())


def test_all_mutations_fail_closed_and_preview_exact_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = roles.MutationPlan(
        "trust-set",
        (ROLE_ARN,),
        (
            roles.Operation(
                "iam",
                "update_assume_role_policy",
                {"RoleName": "Agent", "PolicyDocument": json.dumps(TRUST)},
                "update_assume_role_policy",
                {"RoleName": "Agent", "PolicyDocument": json.dumps(TRUST)},
            ),
        ),
    )
    monkeypatch.setattr(cli.sys, "stdin", Tty(False))
    assert not cli._confirm_plan(argparse.Namespace(yes=False), plan)
    monkeypatch.setattr(cli.sys, "stdin", Tty(True))
    prompts: list[str] = []
    monkeypatch.setattr(cli, "_input", lambda prompt: prompts.append(prompt) or "no")
    assert not cli._confirm_plan(argparse.Namespace(yes=False), plan)
    assert "trust-set" in prompts[0] and ROLE_ARN in prompts[0]
    monkeypatch.setattr(cli, "_input", lambda _prompt: "yes")
    assert cli._confirm_plan(argparse.Namespace(yes=False), plan)
    delete_plan = roles.plan_delete_role(
        role_snapshot(
            attached_policies=(), inline_policies=(), inline_policy_documents={}
        )
    )
    assert not cli._confirm_plan(argparse.Namespace(yes=False), delete_plan)
    monkeypatch.setattr(cli, "_input", lambda _prompt: "Agent")
    assert cli._confirm_plan(argparse.Namespace(yes=False), delete_plan)
    _configs.configure_output(json_output=True)
    try:
        assert not cli._confirm_plan(argparse.Namespace(yes=False), plan)
        assert cli._confirm_plan(argparse.Namespace(yes=True), plan)
    finally:
        _configs.configure_output(json_output=False)


class JournalIam:
    def __init__(self, *, crash: bool = False) -> None:
        self.tags: dict[str, str] = {}
        self.crash = crash
        self.calls: list[str] = []

    def tag_role(self, **params: Any) -> None:
        self.calls.append("tag_role")
        for tag in params["Tags"]:
            self.tags[tag["Key"]] = tag["Value"]
        if self.crash:
            self.crash = False
            raise KeyboardInterrupt

    def untag_role(self, **params: Any) -> None:
        self.calls.append("untag_role")
        for key in params["TagKeys"]:
            self.tags.pop(key, None)


def test_role_execution_journals_before_aws_and_recovers_crash_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli._state, "root", lambda: tmp_path)
    recovery.clear_handlers()
    iam = JournalIam(crash=True)
    ctx = context(iam=iam)
    plan = roles.plan_put_tags("Agent", {"team": "platform"}, current={})
    with pytest.raises(KeyboardInterrupt):
        cli._execute(plan, ctx, argparse.Namespace(yes=True))
    pending = recovery.list_journals()
    assert len(pending) == 1 and pending[0]["status"] == "active"
    journal_id = str(pending[0]["id"])
    journal = recovery.get_journal(journal_id)
    assert journal["partition"] == "aws"
    assert journal["steps"][0]["status"] == "pending"
    assert iam.tags == {"team": "platform"}
    recovery.rollback_journal(journal_id, ctx)
    assert iam.tags == {}
    assert recovery.get_journal(journal_id)["status"] == "rolled_back"

    iam.crash = True
    with pytest.raises(KeyboardInterrupt):
        cli._execute(plan, ctx, argparse.Namespace(yes=True))
    second = next(
        item for item in recovery.list_journals() if item["status"] == "active"
    )
    recovery.continue_journal(str(second["id"]), ctx)
    assert iam.tags == {"team": "platform"}
    assert recovery.get_journal(str(second["id"]))["status"] == "completed"


def test_expected_role_hash_is_enforced_before_journaling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli._state, "root", lambda: tmp_path)
    before = role_snapshot(description="before")
    after = role_snapshot(description="concurrent")
    plan = roles.plan_update_role(
        before,
        roles.RoleSpec(
            before.name,
            before.trust,
            path=before.path,
            description="desired",
            tags={},
            owner=CALLER,
        ),
    )
    monkeypatch.setattr(cli, "_service", lambda _context: FakeService(after))
    with pytest.raises(OperationalError, match="changed after planning"):
        cli._execute(plan, context(), argparse.Namespace(yes=True))
    assert recovery.list_journals() == []


def test_role_delete_recovery_stops_at_irreversible_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli._state, "root", lambda: tmp_path)
    recovery.clear_handlers()
    cli.ensure_role_recovery_handlers()
    journal = recovery.begin_journal("iam-role", ACCOUNT_ID, "role-delete")
    step_id = journal.record_before_mutation(
        "delete-role--none",
        forward={"params": {"RoleName": "Agent"}},
        compensation={"params": {"RoleName": "Agent", "ExpectedRoleId": "RID"}},
    )
    journal.mark_completed(step_id)
    journal.finish()

    class MissingRoleService:
        def get_role(self, _name: str) -> roles.RoleSnapshot:
            raise client_error("NoSuchEntity")

    monkeypatch.setattr(cli, "_service", lambda _context: MissingRoleService())
    with pytest.raises(OperationalError, match=r"irreversible.*commit point"):
        recovery.rollback_journal(journal.id, context())

    pending = recovery.begin_journal("iam-role", ACCOUNT_ID, "role-delete")
    pending.record_before_mutation(
        "delete-role--none",
        forward={"params": {"RoleName": "Agent"}},
        compensation={"params": {"RoleName": "Agent", "ExpectedRoleId": "AIDAEXAMPLE"}},
    )
    monkeypatch.setattr(cli, "_service", lambda _context: FakeService())
    recovery.rollback_journal(pending.id, context())
    assert recovery.get_journal(pending.id)["status"] == "rolled_back"


def test_role_create_receipt_guards_continue_and_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli._state, "root", lambda: tmp_path)
    recovery.clear_handlers()
    cli.ensure_role_recovery_handlers()
    spec = roles.RoleSpec("Agent", TRUST, owner=CALLER)
    plan = roles.plan_create_role(spec)
    params = dict(plan.operations[0].params)

    class CreateIam:
        def __init__(self, *, crash: bool = False) -> None:
            self.exists = False
            self.role_id = "AIDACREATED"
            self.crash = crash
            self.deletes: list[str] = []

        def create_role(self, **_params: Any) -> dict[str, object]:
            if self.exists:
                raise client_error("EntityAlreadyExists")
            self.exists = True
            if self.crash:
                self.crash = False
                raise KeyboardInterrupt
            return {"Role": {"RoleId": self.role_id}}

        def delete_role(self, **request: Any) -> None:
            self.deletes.append(str(request["RoleName"]))
            self.exists = False

    class ReceiptService:
        def __init__(self, iam: CreateIam) -> None:
            self.iam = iam

        def get_role(self, _name: str) -> roles.RoleSnapshot:
            if not self.iam.exists:
                raise client_error("NoSuchEntity")
            return role_snapshot(
                description=None,
                attached_policies=(),
                inline_policies=(),
                inline_policy_documents={},
                tags={
                    roles.MANAGED_TAG: "true",
                    roles.OWNER_TAG: CALLER,
                    roles.ORIGIN_TAG: "created",
                },
                role_id=self.iam.role_id,
            )

    iam = CreateIam()
    ctx = context(iam=iam)
    monkeypatch.setattr(cli, "_service", lambda _context: ReceiptService(iam))
    journal = cli._execute(plan, ctx, argparse.Namespace(yes=True))
    assert journal is not None
    stored = recovery.get_journal(journal.id)
    assert stored["steps"][0]["effect"] == {"roleId": "AIDACREATED"}
    assert cli._create_role_with_receipt(
        {"params": params, "effect": {"roleId": "AIDACREATED"}}, ctx
    ) == {"roleId": "AIDACREATED"}

    exact_iam = CreateIam()
    exact_context = context(iam=exact_iam)
    monkeypatch.setattr(cli, "_service", lambda _context: ReceiptService(exact_iam))
    exact_journal = cli._execute(plan, exact_context, argparse.Namespace(yes=True))
    assert exact_journal is not None
    recovery.rollback_journal(exact_journal.id, exact_context)
    recovery.rollback_journal(exact_journal.id, exact_context)
    assert exact_iam.deletes == ["Agent"]

    monkeypatch.setattr(cli, "_service", lambda _context: ReceiptService(iam))
    iam.role_id = "AIDASPOOFED"
    with pytest.raises(OperationalError, match="compensation step"):
        recovery.rollback_journal(journal.id, ctx)
    assert iam.deletes == []

    crashing = CreateIam(crash=True)
    crash_context = context(iam=crashing)
    monkeypatch.setattr(cli, "_service", lambda _context: ReceiptService(crashing))
    with pytest.raises(KeyboardInterrupt):
        cli._execute(plan, crash_context, argparse.Namespace(yes=True))
    pending = next(
        item for item in recovery.list_journals() if item["status"] == "active"
    )
    pending_data = recovery.get_journal(str(pending["id"]))
    assert "effect" not in pending_data["steps"][0]
    with pytest.raises(OperationalError, match="forward step"):
        recovery.continue_journal(str(pending["id"]), crash_context)
    assert crashing.deletes == []


def test_role_create_receipt_allows_exact_rollback_and_rejects_spoofed_continue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli._state, "root", lambda: tmp_path)
    recovery.clear_handlers()
    cli.ensure_role_recovery_handlers()
    spec = roles.RoleSpec("Agent", TRUST, owner=CALLER)
    plan = roles.plan_create_role(spec)
    params = dict(plan.operations[0].params)

    class ExistingIam:
        def __init__(self) -> None:
            self.deletes: list[str] = []

        def create_role(self, **_params: Any) -> object:
            raise client_error("EntityAlreadyExists")

        def delete_role(self, **request: Any) -> None:
            self.deletes.append(str(request["RoleName"]))

    iam = ExistingIam()
    ctx = context(iam=iam)
    exact = role_snapshot(
        description=None,
        attached_policies=(),
        inline_policies=(),
        inline_policy_documents={},
        tags={
            roles.MANAGED_TAG: "true",
            roles.OWNER_TAG: CALLER,
            roles.ORIGIN_TAG: "created",
        },
        role_id="AIDARECEIPT",
    )
    monkeypatch.setattr(cli, "_service", lambda _context: FakeService(exact))
    assert cli._create_role_with_receipt(
        {"params": params, "effect": {"roleId": "AIDARECEIPT"}}, ctx
    ) == {"roleId": "AIDARECEIPT"}
    with pytest.raises(OperationalError, match="no durable AWS RoleId receipt"):
        cli._create_role_with_receipt({"params": params}, ctx)

    cli._delete_created_role_with_receipt(
        {"params": {"RoleName": "Agent"}, "effect": {"roleId": "AIDARECEIPT"}},
        ctx,
    )
    assert iam.deletes == ["Agent"]


def test_reserved_tags_and_account_aliases_are_case_insensitive(
    configured: dict[str, Any],
) -> None:
    with pytest.raises(OperationalError, match="Reserved"):
        cli._parse_tags(["hacksaws:managed=false"])
    assert cli._principal("account", "PROD", None, context()).account_id == ACCOUNT_ID


def test_owned_publication_rejects_collisions_and_version_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arn = f"arn:aws:iam::{ACCOUNT_ID}:policy/hacksaws/AgentPolicy"
    unmanaged = managed.ManagedPolicyRecord(
        managed.ManagedPolicyArn.parse(arn),
        "PID",
        "AgentPolicy",
        "/hacksaws/",
        "v1",
        0,
        0,
        (),
        POLICY,
    )
    monkeypatch.setattr(cli, "_managed_service", lambda _context: object())
    monkeypatch.setattr(cli, "_managed_record", lambda _service, _arn: unmanaged)
    with pytest.raises(OperationalError, match="not the exact"):
        cli._owned_publish_attach_plan(
            role_snapshot(attached_policies=()),
            "AgentPolicy",
            POLICY,
            "/hacksaws/",
            context(),
        )

    wrong_identity = replace(
        unmanaged,
        tags=(
            managed.Tag("hacksaws:managed-by", "hacksaws"),
            managed.Tag("hacksaws:resource-kind", "managed-policy"),
            managed.Tag("hacksaws:resource-id", "different-feature-object"),
        ),
    )
    monkeypatch.setattr(cli, "_managed_record", lambda _service, _arn: wrong_identity)
    with pytest.raises(
        OperationalError, match=r"different-feature-object|not the exact"
    ):
        cli._owned_publish_attach_plan(
            role_snapshot(attached_policies=()),
            "AgentPolicy",
            POLICY,
            "/hacksaws/",
            context(),
        )


def test_recovery_iam_call_is_idempotent_and_collision_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class IamCalls:
        def __init__(self) -> None:
            self.failure = "NoSuchEntity"

        def delete_role(self, **_params: Any) -> None:
            raise client_error(self.failure)

        def create_role(self, **_params: Any) -> None:
            raise client_error("EntityAlreadyExists")

    iam = IamCalls()
    ctx = context(iam=iam)
    with pytest.raises(OperationalError, match="parameters are invalid"):
        cli._iam_call(ctx, "delete_role", {"params": "bad"})
    cli._iam_call(ctx, "delete_role", {"params": {"RoleName": "missing"}})
    iam.failure = "AccessDenied"
    with pytest.raises(ClientError):
        cli._iam_call(ctx, "delete_role", {"params": {"RoleName": "Agent"}})

    params = {
        "RoleName": "Agent",
        "Path": "/hacksaws/",
        "AssumeRolePolicyDocument": json.dumps(TRUST),
        "MaxSessionDuration": 3600,
        "Tags": [
            {"Key": roles.MANAGED_TAG, "Value": "true"},
            {"Key": roles.OWNER_TAG, "Value": CALLER},
        ],
    }
    monkeypatch.setattr(cli, "_service", lambda _context: FakeService())
    with pytest.raises(ClientError):
        cli._iam_call(ctx, "create_role", {"params": params})


def test_owned_publication_create_restore_and_attach_plan_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arn = f"arn:aws:iam::{ACCOUNT_ID}:policy/hacksaws/AgentPolicy"
    current_document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }
    resource_id = f"role-attachment-{roles.document_hash(arn)[:24]}"
    versions = tuple(
        managed.PolicyVersionRecord(
            f"v{index}",
            index == 5,
            None,
            current_document
            if index == 5
            else {"Statement": [], "Version": "2012-10-17"},
        )
        for index in range(1, 6)
    )
    record = managed.ManagedPolicyRecord(
        managed.ManagedPolicyArn.parse(arn),
        "PID",
        "AgentPolicy",
        "/hacksaws/",
        "v1",
        0,
        0,
        (
            managed.Tag("hacksaws:managed-by", "hacksaws"),
            managed.Tag("hacksaws:resource-kind", "managed-policy"),
            managed.Tag("hacksaws:resource-id", resource_id),
        ),
        current_document,
        versions,
    )

    class ManagedService:
        def plan_publish(self, *_args: Any, **_kwargs: Any) -> object:
            return object()

        def policy_dependencies(self, _arn: str) -> managed.PolicyDependencies:
            return managed.PolicyDependencies()

    service = ManagedService()
    before_versions: list[dict[str, object]] = [
        {
            "id": version.version_id,
            "default": version.is_default,
            "document": version.document,
        }
        for version in versions
    ]
    before: dict[str, object] = {
        "exists": True,
        "arn": arn,
        "name": "AgentPolicy",
        "path": "/hacksaws/",
        "description": None,
        "tags": [tag.as_request() for tag in record.tags],
        "versions": before_versions,
        "dependencies": {
            "permissionUsers": [],
            "permissionGroups": [],
            "permissionRoles": [],
            "boundaryUsers": [],
            "boundaryRoles": [],
        },
    }
    after = {
        **before,
        "versions": [
            *before_versions[1:-1],
            {"id": "v5", "default": False, "document": current_document},
            {"id": "pending", "default": True, "document": POLICY},
        ],
    }
    monkeypatch.setattr(cli, "_managed_service", lambda _context: service)
    monkeypatch.setattr(cli, "_managed_record", lambda _service, _arn: record)
    monkeypatch.setattr(
        cli.policy_cli, "_change_states", lambda _service, _change: (after, before)
    )
    plan = cli._owned_publish_attach_plan(
        role_snapshot(attached_policies=()),
        "AgentPolicy",
        POLICY,
        "/hacksaws/",
        context(),
    )
    assert plan.kind == "policy-publish-attach"
    assert [operation.client for operation in plan.operations] == [
        "managed_policy",
        "iam",
    ]
    publication = cli._materialize_managed_operation(plan.operations[0], context())
    assert publication.compensate_params is not None
    compensation = publication.compensate_params["State"]
    assert isinstance(compensation, dict)
    assert len(compensation["versions"]) == 5
    assert sum(item["default"] is True for item in compensation["versions"]) == 1
    assert all(item["document"] is not None for item in compensation["versions"])

    changed_ids = {
        **before,
        "versions": [
            {**item, "id": f"new-{index}"} for index, item in enumerate(before_versions)
        ],
    }
    assert cli._policy_state_hash(before) == cli._policy_state_hash(changed_ids)
    absent = {"exists": False, "arn": arn}
    assert cli._policy_state_hash(absent) == cli._policy_state_hash(dict(absent))

    reconciled: list[dict[str, object]] = []
    observed_states = iter((before, after, after, before))
    monkeypatch.setattr(cli, "_policy_state", lambda *_args: next(observed_states))
    monkeypatch.setattr(
        cli.policy_cli,
        "_reconcile_policy",
        lambda state, _context: reconciled.append(dict(state)),
    )
    assert publication.compensate_params is not None
    cli._publish_owned_policy(publication.params, context())
    cli._restore_owned_policy(publication.compensate_params, context())
    assert reconciled == [after, before]

    with pytest.raises(OperationalError, match="state is invalid"):
        cli._publish_owned_policy({}, context())

    class CreateService:
        def plan_create(self, *_args: Any, **_kwargs: Any) -> object:
            return object()

    monkeypatch.setattr(cli, "_managed_service", lambda _context: CreateService())
    monkeypatch.setattr(cli, "_managed_record", lambda _service, _arn: None)
    monkeypatch.setattr(
        cli.policy_cli,
        "_change_states",
        lambda _service, _change: (after, absent),
    )
    created = cli._materialize_managed_operation(plan.operations[0], context())
    assert created.params["ExpectedStateHash"] == cli._policy_state_hash(absent)

    monkeypatch.setattr(
        cli.policy_cli,
        "_reconcile_policy",
        lambda _state, _context: None,
    )
    cli._publish_owned_policy(
        {
            "State": absent,
            "ExpectedStateHash": cli._policy_state_hash(absent),
            "ResourceId": resource_id,
        },
        context(),
    )
    with pytest.raises(OperationalError, match="changed after planning"):
        cli._publish_owned_policy(
            {
                "State": after,
                "ExpectedStateHash": "drifted",
                "ResourceId": resource_id,
            },
            context(),
        )
    with pytest.raises(OperationalError, match="reconciliation was incomplete"):
        cli._publish_owned_policy(
            {
                "State": after,
                "ExpectedStateHash": cli._policy_state_hash(absent),
                "ResourceId": resource_id,
            },
            context(),
        )


def test_dry_run_editor_does_not_create_policy_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EDITOR", "editor")
    monkeypatch.setattr(cli._state, "root", lambda: tmp_path / "state")
    monkeypatch.setattr(
        cli,
        "_editor_runner",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
    )

    assert cli._edit_document(POLICY, "Agent-trust", write_backup=False) == POLICY
    assert not (tmp_path / "state" / "backups").exists()
