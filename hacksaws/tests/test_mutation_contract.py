"""Tests for shared mutation rendering and deterministic CLI input resolution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from botocore.exceptions import ClientError
from botocore.exceptions import EndpointConnectionError

from hacksaws import _audit
from hacksaws import _configs
from hacksaws import _iam_role_cli
from hacksaws import _iam_roles as roles
from hacksaws import _mutation_view
from hacksaws import _resource_input
from hacksaws._configs import OperationalError

ACCOUNT = "123456789012"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/Agent"


def _context() -> Any:  # noqa: ANN401
    return SimpleNamespace(
        account_id=ACCOUNT,
        partition="aws",
        arn=f"arn:aws:iam::{ACCOUNT}:user/scott",
        session=SimpleNamespace(region_name="us-west-2"),
    )


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "test")


def test_name_file_resolves_both_orders_and_explicit_flags(tmp_path: Path) -> None:
    document = tmp_path / "policy.yaml"
    document.write_text("Version: '2012-10-17'", encoding="utf-8")

    first = _resource_input.resolve_name_file(("ReadOnly", str(document)))
    second = _resource_input.resolve_name_file((str(document), "ReadOnly"))
    explicit = _resource_input.resolve_name_file(
        (), explicit_name="ReadOnly", explicit_file=document
    )
    named = _resource_input.resolve_name_file(
        (str(document),), explicit_name="ReadOnly"
    )
    filed = _resource_input.resolve_name_file(("ReadOnly",), explicit_file=document)

    assert first == second == explicit == named == filed
    assert first.name == "ReadOnly"
    assert first.file == document


@pytest.mark.parametrize(
    ("values", "name", "file"),
    [
        (("ReadOnly",), "ReadOnly", None),
        (("policy.json",), None, Path("policy.json")),
        (("-",), None, Path("-")),
        ((r"C:\policies\agent.toml",), None, Path(r"C:\policies\agent.toml")),
    ],
)
def test_name_file_single_value_classification(
    values: tuple[str, ...], name: str | None, file: Path | None
) -> None:
    resolved = _resource_input.resolve_name_file(
        values, require_name=False, require_file=False
    )
    assert resolved.name == name
    assert resolved.file == file


def test_name_file_rejects_ambiguous_or_missing_inputs() -> None:
    with pytest.raises(OperationalError, match="at most"):
        _resource_input.resolve_name_file(("one", "two", "three"))
    with pytest.raises(OperationalError, match="Unable to distinguish"):
        _resource_input.resolve_name_file(("one", "two"))
    with pytest.raises(OperationalError, match="Missing NAME"):
        _resource_input.resolve_name_file(())
    with pytest.raises(OperationalError, match="Missing FILE"):
        _resource_input.resolve_name_file(("name",))
    with pytest.raises(OperationalError, match="already"):
        _resource_input.resolve_name_file(
            ("extra",), explicit_name="name", explicit_file="file.json"
        )
    with pytest.raises(OperationalError, match="cannot be combined"):
        _resource_input.resolve_name_file(("one", "two"), explicit_name="name")


def test_reference_or_file_requires_one_input(tmp_path: Path) -> None:
    document = tmp_path / "policy.json"
    document.write_text("{}", encoding="utf-8")
    assert (
        _resource_input.resolve_reference_or_file(("ReadOnly",)).reference == "ReadOnly"
    )
    assert (
        _resource_input.resolve_reference_or_file(
            (), explicit_reference="ReadOnly"
        ).reference
        == "ReadOnly"
    )
    assert _resource_input.resolve_reference_or_file((str(document),)).file == document
    assert (
        _resource_input.resolve_reference_or_file((), explicit_file=document).file
        == document
    )
    with pytest.raises(OperationalError, match="exactly one"):
        _resource_input.resolve_reference_or_file(())
    with pytest.raises(OperationalError, match="exactly one"):
        _resource_input.resolve_reference_or_file(
            ("ReadOnly",), explicit_reference="Other"
        )


def test_shared_mutation_contract_has_stable_human_and_json_shapes() -> None:
    plan = _mutation_view.ChangeView(
        operation="role-update",
        resource_type="IAM role",
        name="Agent",
        classification="planned",
        arn="arn:aws:iam::123456789012:role/Agent",
        account_id="123456789012",
        partition="aws",
        ownership="current",
        origin="created",
        before_exists=True,
        after_exists=True,
        changes=(_mutation_view.FieldChange("description", "old", "new"),),
        actions=(_mutation_view.ActionView("iam", "update_role", "update role Agent"),),
        dependencies=(
            _mutation_view.DependencyView("attached policy", "ReadOnly", "preserved"),
        ),
        warnings=("Review this change.",),
        confirmation="type exactly 'yes'",
    )
    data = _mutation_view.change_data(plan)
    text = _mutation_view.change_text(plan)
    assert data["changes"] == [
        {"field": "description", "before": "old", "after": "new"}
    ]
    assert "old → new" in text
    assert "iam:update_role" in text
    assert "ReadOnly" in text

    result = _mutation_view.MutationResultView(
        "updated",
        "IAM role",
        "Agent",
        arn=plan.arn,
        resource_id="ARO123",
        console_url="https://example.invalid/role",
        journal_id="journal-1",
        applied_actions=("iam:update_role",),
        warnings=("Review this change.",),
        plan=plan,
        details={"resultCode": "IAM_ROLE_UPDATED"},
    )
    result_data = _mutation_view.result_data(result)
    result_text = _mutation_view.result_text(result)
    resource = result_data["resource"]
    assert isinstance(resource, dict)
    assert resource["id"] == "ARO123"
    assert result_data["plan"] == data
    assert "Recovery journal: journal-1" in result_text
    assert "Applied: iam:update_role" in result_text


def test_shared_mutation_contract_escapes_terminal_controls() -> None:
    view = _mutation_view.ChangeView(
        "role-tag",
        "IAM role",
        "Agent\x1b[31m",
        "no-change",
        changes=(_mutation_view.FieldChange("enabled", before=True, after=False),),
    )
    text = _mutation_view.change_text(view)
    assert "\x1b" not in text
    assert "yes → no" in text
    result = _mutation_view.MutationResultView(
        "no-change", "IAM role", "Agent", plan=view
    )
    assert "remote state already matched" in _mutation_view.result_text(result)
    empty = _mutation_view.ChangeView("role-update", "IAM role", "Agent", "no-change")
    assert "No field changes." in _mutation_view.change_text(empty)
    assert "None." in _mutation_view.change_text(empty)


def test_role_plan_adapter_hashes_documents_and_never_renders_them() -> None:
    current = roles.RoleSnapshot(
        "Agent",
        "arn:aws:iam::123456789012:role/Agent",
        "/",
        {"Version": "2012-10-17", "Statement": []},
        description="old",
        tags={roles.MANAGED_TAG: "true", roles.OWNER_TAG: "scott"},
        attached_policies=("arn:aws:iam::123456789012:policy/ReadOnly",),
    )
    desired = roles.RoleSpec(
        "Agent",
        {"Version": "2012-10-17", "Statement": [{"Effect": "Deny"}]},
        path="/",
        description="new",
        owner="scott",
    )
    view = _iam_role_cli._role_plan_view(roles.plan_update_role(current, desired))
    data = _mutation_view.change_data(view)
    rendered = _mutation_view.change_text(view)
    assert view.account_id == "123456789012"
    assert any(change.field == "trust document SHA-256" for change in view.changes)
    assert "Statement" not in rendered
    assert "PolicyDocument" not in str(data)
    assert view.dependencies[0].resource.endswith("ReadOnly")


def test_role_delete_view_lists_dependencies_and_name_confirmation() -> None:
    current = roles.RoleSnapshot(
        "Agent",
        "arn:aws:iam::123456789012:role/Agent",
        "/hacksaws/",
        {"Version": "2012-10-17", "Statement": []},
        permissions_boundary="arn:aws:iam::123456789012:policy/Boundary",
        tags={roles.MANAGED_TAG: "true", roles.OWNER_TAG: "scott"},
        attached_policies=("arn:aws:iam::aws:policy/ReadOnlyAccess",),
        inline_policies=("Inline",),
        inline_policy_documents={"Inline": {"Version": "2012-10-17", "Statement": []}},
        instance_profiles=("Profile",),
    )
    plan = roles.plan_delete_role(
        current,
        cascade=True,
        remove_from_instance_profiles=True,
    )
    view = _iam_role_cli._role_plan_view(
        roles.MutationPlan(
            plan.kind,
            plan.resources,
            plan.operations,
            plan.expected,
            plan.warnings,
            before=current,
        )
    )
    assert view.confirmation == "type role name 'Agent'"
    assert view.after_exists is False
    assert len(view.dependencies) == 4
    assert view.actions[-1].destructive is True


def test_role_operation_adapter_covers_each_safe_effect_without_documents() -> None:
    policy = f"arn:aws:iam::{ACCOUNT}:policy/ReadOnly"
    document = {"Version": "2012-10-17", "Statement": []}
    operations = (
        roles.Operation("iam", "attach_role_policy", {"PolicyArn": policy}),
        roles.Operation("iam", "detach_role_policy", {"PolicyArn": policy}),
        roles.Operation("iam", "put_role_policy", {"PolicyName": "Inline"}),
        roles.Operation("iam", "delete_role_policy", {"PolicyName": "Inline"}),
        roles.Operation(
            "iam",
            "update_assume_role_policy",
            {"PolicyDocument": json.dumps(document)},
        ),
        roles.Operation(
            "iam", "update_assume_role_policy", {"PolicyDocument": document}
        ),
        roles.Operation(
            "iam",
            "tag_role",
            {
                "Tags": [
                    {"Key": "Project", "Value": "TAG-VALUE-MUST-NOT-LEAK"},
                    "ignored",
                ]
            },
        ),
        roles.Operation("iam", "untag_role", {"TagKeys": ["Old"]}),
        roles.Operation(
            "iam",
            "remove_role_from_instance_profile",
            {"InstanceProfileName": "AgentProfile"},
        ),
    )
    plan = roles.MutationPlan(
        "role-mixed",
        (ROLE_ARN, policy),
        operations,
        expected={"trust": "old-digest"},
    )
    view = _iam_role_cli._role_plan_view(plan)
    fields = {change.field for change in view.changes}
    assert f"attached policy {policy}" in fields
    assert "inline policy Inline" in fields
    assert "tag Project value SHA-256" in fields
    assert "tag Old" in fields
    assert any(change.after == "updated" for change in view.changes)
    assert view.actions[-1].summary.endswith("AgentProfile")
    assert view.dependencies[-1].resource == policy
    encoded = json.dumps(_mutation_view.change_data(view))
    assert "TAG-VALUE-MUST-NOT-LEAK" not in encoded


def test_role_plan_view_handles_snapshot_after_and_unknown_identity() -> None:
    after = roles.RoleSnapshot(
        "Agent",
        ROLE_ARN,
        "/hacksaws/",
        {"Version": "2012-10-17", "Statement": []},
        tags={
            roles.MANAGED_TAG: "true",
            roles.OWNER_TAG: "scott",
            roles.ORIGIN_TAG: "adopted",
            roles.AUDIT_TAG: "audit",
        },
    )
    view = _iam_role_cli._role_plan_view(
        roles.MutationPlan("role-adopt", (ROLE_ARN,), (), after=after)
    )
    assert view.ownership == "current"
    assert view.origin == "adopted"
    assert view.classification == "no-change"
    unknown = _iam_role_cli._role_plan_view(
        roles.MutationPlan("trust-retained", (), ())
    )
    assert unknown.name == "unknown"
    assert unknown.before_exists is True
    assert _iam_role_cli._state_changes(None, None) == ()
    assert _iam_role_cli._role_state_values(None) == {}


def test_role_confirmation_semantics_cover_all_mechanisms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    update = roles.MutationPlan(
        "role-update",
        ("Agent",),
        (roles.Operation("iam", "update_role", {"RoleName": "Agent"}),),
    )
    delete = roles.MutationPlan(
        "role-delete",
        (ROLE_ARN,),
        (roles.Operation("iam", "delete_role", {"RoleName": "Agent"}),),
    )
    assert _iam_role_cli._confirm_plan(
        argparse.Namespace(), roles.MutationPlan("noop", (), ())
    )
    assert _iam_role_cli._confirm_plan(argparse.Namespace(yes=True), update)
    assert _audit.confirmation() == "yes-flag:bypassed"

    monkeypatch.setattr(_iam_role_cli.sys.stdin, "isatty", lambda: False)
    assert not _iam_role_cli._confirm_plan(argparse.Namespace(), update)
    assert _audit.confirmation() == "exact-yes:unavailable"
    assert not _iam_role_cli._confirm_plan(argparse.Namespace(json=True), delete)
    assert _audit.confirmation() == "resource-name:unavailable"

    monkeypatch.setattr(_iam_role_cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(_iam_role_cli, "_input", lambda _prompt: "Agent")
    assert _iam_role_cli._confirm_plan(argparse.Namespace(), delete)
    assert _audit.confirmation() == "resource-name:accepted"
    monkeypatch.setattr(_iam_role_cli, "_input", lambda _prompt: "wrong")
    assert not _iam_role_cli._confirm_plan(argparse.Namespace(), delete)
    assert _audit.confirmation() == "resource-name:declined"
    monkeypatch.setattr(_iam_role_cli, "_input", lambda _prompt: "yes")
    assert _iam_role_cli._confirm_plan(argparse.Namespace(), update)
    assert _audit.confirmation() == "exact-yes:accepted"
    monkeypatch.setattr(_iam_role_cli, "_input", lambda _prompt: "no")
    assert not _iam_role_cli._confirm_plan(argparse.Namespace(), update)
    assert _audit.confirmation() == "exact-yes:declined"


def test_role_execute_prepares_each_recovery_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: list[tuple[str, dict[str, object], dict[str, object]]] = []

    class Journal:
        id = "journal-1"

        def record_before_mutation(
            self,
            handler: str,
            *,
            forward: dict[str, object],
            compensation: dict[str, object],
        ) -> None:
            recorded.append((handler, forward, compensation))

    continued: list[str] = []
    monkeypatch.setattr(
        _iam_role_cli, "_materialize_managed_operations", lambda plan, _context: plan
    )
    monkeypatch.setattr(_iam_role_cli, "_confirm_plan", lambda _args, _plan: True)
    monkeypatch.setattr(
        _iam_role_cli, "_assert_preconditions", lambda _plan, _context: None
    )
    monkeypatch.setattr(_iam_role_cli, "ensure_role_recovery_handlers", lambda: None)
    monkeypatch.setattr(
        _iam_role_cli.recovery, "begin_journal", lambda *_args, **_kwargs: Journal()
    )
    monkeypatch.setattr(
        _iam_role_cli.recovery,
        "continue_journal",
        lambda journal_id, _context: continued.append(journal_id),
    )
    operations = (
        roles.Operation(
            "managed_policy",
            "publish",
            {"State": {"exists": True}},
            compensate_params={"State": {"exists": False}},
        ),
        roles.Operation(
            "iam",
            "create_role",
            {"RoleName": "Agent"},
            "delete_role",
            {"RoleName": "Agent"},
        ),
        roles.Operation(
            "iam",
            "attach_role_policy",
            {"RoleName": "Agent", "PolicyArn": "arn:policy"},
            "detach_role_policy",
            {"RoleName": "Agent", "PolicyArn": "arn:policy"},
        ),
    )
    args = argparse.Namespace(yes=True)
    journal = _iam_role_cli._execute(
        roles.MutationPlan("role-create", ("Agent",), operations), _context(), args
    )
    assert journal is not None
    assert journal.id == "journal-1"
    assert [item[0] for item in recorded] == [
        "publish-owned-policy--restore-owned-policy",
        "create-role-with-receipt",
        "attach-role-policy--detach-role-policy",
    ]
    assert recorded[1][2]["effectSourceStep"] == "self"
    assert continued == ["journal-1"]
    assert args._mutation_journal_id == "journal-1"


def test_role_execute_dry_run_cancel_noop_and_unknown_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        _iam_role_cli, "_materialize_managed_operations", lambda plan, _context: plan
    )
    noop = roles.MutationPlan("noop", ("Agent",), ())
    monkeypatch.setattr(_iam_role_cli, "_confirm_plan", lambda _args, _plan: True)
    assert _iam_role_cli._execute(noop, _context(), argparse.Namespace()) is None
    with pytest.raises(_iam_role_cli._DryRunCompletedError):
        _iam_role_cli._execute(noop, _context(), argparse.Namespace(dry_run=True))

    operation = roles.Operation("iam", "unknown", {})
    plan = roles.MutationPlan("unknown", ("Agent",), (operation,))
    monkeypatch.setattr(_iam_role_cli, "_confirm_plan", lambda _args, _plan: False)
    with pytest.raises(_iam_role_cli._MutationCancelledError):
        _iam_role_cli._execute(plan, _context(), argparse.Namespace())
    monkeypatch.setattr(_iam_role_cli, "_confirm_plan", lambda _args, _plan: True)
    monkeypatch.setattr(
        _iam_role_cli, "_assert_preconditions", lambda _plan, _context: None
    )
    monkeypatch.setattr(_iam_role_cli, "ensure_role_recovery_handlers", lambda: None)
    with pytest.raises(OperationalError, match="no whitelisted recovery handler"):
        _iam_role_cli._execute(plan, _context(), argparse.Namespace())


def test_role_argument_normalization_flag_forms_and_errors(tmp_path: Path) -> None:
    document = tmp_path / "policy.yaml"
    document.write_text("Version: '2012-10-17'", encoding="utf-8")
    attach = argparse.Namespace(
        role_command="attach",
        policy_input=None,
        policy_reference=None,
        policy_file=document,
    )
    _iam_role_cli.normalize_arguments(attach)
    assert attach.policy == str(document)
    inline = argparse.Namespace(
        role_command="inline-policy",
        role_inline_action="put",
        policy_inputs=[str(document)],
        explicit_policy_name="Inline",
        explicit_file=None,
    )
    _iam_role_cli.normalize_arguments(inline)
    assert inline.policy == "Inline"
    assert inline.file == document
    trust = argparse.Namespace(
        role_command="trust",
        role_trust_action="set",
        trust_inputs=["Agent"],
        explicit_role=None,
        explicit_file=document,
    )
    _iam_role_cli.normalize_arguments(trust)
    assert trust.role == "Agent"
    assert trust.file == document
    missing = argparse.Namespace(
        role_command="attach",
        policy_input=None,
        policy_reference=None,
        policy_file=tmp_path / "missing.json",
    )
    with pytest.raises(OperationalError, match="does not exist"):
        _iam_role_cli.normalize_arguments(missing)
    untouched = argparse.Namespace(role_command="list")
    _iam_role_cli.normalize_arguments(untouched)


@pytest.mark.parametrize(
    ("code", "operations", "expected"),
    [
        ("IAM_ROLE_COLLISION", True, "conflict"),
        ("IAM_ROLE_MUTATION_CANCELLED", True, "cancelled"),
        ("IAM_ROLE_NO_CHANGE", True, "no-change"),
        ("IAM_ROLE_UPDATED", False, "no-change"),
        ("IAM_ROLE_CREATED", True, "created"),
        ("IAM_ROLE_DELETED", True, "deleted"),
        ("IAM_ROLE_POLICY_ATTACH", True, "updated"),
        ("IAM_ROLE_COMPLETE", True, "applied"),
    ],
)
def test_role_result_classification(code: str, operations: bool, expected: str) -> None:
    items = (
        (roles.Operation("iam", "update_role", {"RoleName": "Agent"}),)
        if operations
        else ()
    )
    assert (
        _iam_role_cli._result_classification(
            _configs.Result(code, "done"),
            roles.MutationPlan("role-update", ("Agent",), items),
        )
        == expected
    )


def test_role_result_presentation_preserves_envelope_and_safe_details() -> None:
    operation = roles.Operation("iam", "update_role", {"RoleName": "Agent"})
    plan = roles.MutationPlan("role-update", (ROLE_ARN,), (operation,))
    original = _configs.Result(
        "IAM_ROLE_UPDATED",
        "old",
        data={
            "arn": ROLE_ARN,
            "roleId": "ARO123",
            "consoleUrl": "https://console.example/Agent",
            "warning": "Naming warning",
            "trust": {"SECRET": "must-not-render"},
        },
        details={"detail": True},
        repairs=["repair"],
        kind="success",
    )
    args = argparse.Namespace(_mutation_journal_id="journal-1")
    presented = _iam_role_cli._present_role_result(original, plan, args, _context())
    assert presented.code == original.code
    assert presented.details == original.details
    assert presented.repairs == original.repairs
    assert presented.kind == "success"
    assert isinstance(presented.data, dict)
    assert presented.data["journalId"] == "journal-1"
    resource = presented.data["resource"]
    assert isinstance(resource, dict)
    assert resource["id"] == "ARO123"
    assert "SECRET" not in str(presented.data)
    assert "Naming warning" in presented.message
    assert (
        _iam_role_cli._present_role_result(
            original, None, argparse.Namespace(), _context()
        )
        is original
    )
    fallback = _iam_role_cli._present_role_result(
        _configs.Result("IAM_ROLE_UPDATED", "old", data="not-a-map"),
        plan,
        argparse.Namespace(),
        _context(),
    )
    assert "AWS Console: https://us-west-2" in fallback.message


def test_role_dispatch_translates_expected_error_families(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_iam_role_cli, "normalize_arguments", lambda _args: None)
    args = argparse.Namespace()
    monkeypatch.setattr(_iam_role_cli, "_dispatch", lambda _args, _context: None)
    assert _iam_role_cli.dispatch(args, _context()) is None

    error = OperationalError("already normalized")

    def operational(*_args: object) -> None:
        raise error

    monkeypatch.setattr(_iam_role_cli, "_dispatch", operational)
    with pytest.raises(OperationalError) as captured:
        _iam_role_cli.dispatch(args, _context())
    assert captured.value is error

    conflict = roles.ConflictError("role conflict")

    def role_error(*_args: object) -> None:
        raise conflict

    monkeypatch.setattr(_iam_role_cli, "_dispatch", role_error)
    with pytest.raises(OperationalError, match="role conflict"):
        _iam_role_cli.dispatch(args, _context())

    def aws_error(*_args: object) -> None:
        raise EndpointConnectionError(endpoint_url="https://iam.invalid")

    monkeypatch.setattr(_iam_role_cli, "_dispatch", aws_error)
    with pytest.raises(OperationalError, match="AWS IAM role operation failed"):
        _iam_role_cli.dispatch(args, _context())
