"""Focused tests for the managed-policy CLI adapter."""

from __future__ import annotations

import argparse
import json
import tomllib
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC
from datetime import datetime
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from hacksaws import _iam_policy_cli as cli
from hacksaws import _iam_recovery
from hacksaws import _state
from hacksaws._iam_managed_policies import ChangeAction
from hacksaws._iam_managed_policies import DiagnosticSeverity
from hacksaws._iam_managed_policies import EntityReference
from hacksaws._iam_managed_policies import ImmutablePolicyError
from hacksaws._iam_managed_policies import ManagedPolicyArn
from hacksaws._iam_managed_policies import ManagedPolicyRecord
from hacksaws._iam_managed_policies import OperationJournal
from hacksaws._iam_managed_policies import OperationPlan
from hacksaws._iam_managed_policies import PackedPolicyDiagnostic
from hacksaws._iam_managed_policies import PackedPolicyProbeError
from hacksaws._iam_managed_policies import PackedPolicyWarning
from hacksaws._iam_managed_policies import PolicyChangePlan
from hacksaws._iam_managed_policies import PolicyDeletionPlan
from hacksaws._iam_managed_policies import PolicyDependencies
from hacksaws._iam_managed_policies import PolicyDriftError
from hacksaws._iam_managed_policies import PolicyScope
from hacksaws._iam_managed_policies import PolicyValidationError
from hacksaws._iam_managed_policies import PolicyVersionRecord
from hacksaws._iam_managed_policies import PublishResult
from hacksaws._iam_managed_policies import RepairAction
from hacksaws._iam_managed_policies import ResolutionResult
from hacksaws._iam_managed_policies import Tag
from hacksaws._iam_managed_policies import TagChangePlan
from hacksaws._iam_managed_policies import ValidationDiagnostic
from hacksaws._iam_managed_policies import ValidationReport
from hacksaws._iam_policy_documents import JsonValue
from hacksaws._iam_policy_documents import PolicyFormat

ACCOUNT = "123456789012"
ARN = f"arn:aws:iam::{ACCOUNT}:policy/hacksaws/AgentRead"
AWS_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
NOW = datetime(2026, 8, 1, tzinfo=UTC)
DOCUMENT: dict[str, JsonValue] = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "logs:GetLogEvents", "Resource": "*"}],
}
_REAL_DURABLE_RECONCILE = cli._durable_reconcile


def record(
    *, aws: bool = False, owned: bool = True, document: bool = True
) -> ManagedPolicyRecord:
    arn = ManagedPolicyArn.parse(AWS_ARN if aws else ARN)
    tags = (
        (
            Tag("hacksaws:managed-by", "hacksaws"),
            Tag("hacksaws:resource-id", "resource-1"),
            Tag("hacksaws:resource-kind", "managed-policy"),
        )
        if owned and not aws
        else ()
    )
    version = PolicyVersionRecord(
        version_id="v1",
        is_default=True,
        created_at=NOW,
        document=DOCUMENT if document else None,
    )
    return ManagedPolicyRecord(
        arn=arn,
        policy_id="ANPA123",
        name=arn.name,
        path=arn.path,
        default_version_id="v1",
        attachment_count=2,
        permissions_boundary_usage_count=1,
        tags=tags,
        document=DOCUMENT if document else None,
        versions=(version,),
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    cli.register(value)
    return value


def context() -> SimpleNamespace:
    return SimpleNamespace(
        iam=Mock(),
        sts=Mock(),
        access_analyzer=Mock(),
        account_id=ACCOUNT,
        partition="aws",
    )


def service() -> Mock:
    value = Mock()
    value.account_id = ACCOUNT
    value.partition = "aws"
    item = record()
    value.resolve.return_value = ResolutionResult("AgentRead", (item,))
    value.get_policy.return_value = item
    value.policy_dependencies.return_value = PolicyDependencies()
    value.list_policies.return_value = (
        item,
        record(aws=True, owned=False),
    )
    return value


@pytest.fixture(autouse=True)
def stub_durable_reconcile(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep adapter tests local; recovery integration is covered separately."""
    cli._configs.configure_output()
    monkeypatch.setattr(cli, "_durable_reconcile", lambda *_args: "journal-1")
    yield
    cli._configs.configure_output()


@pytest.mark.parametrize(
    ("argv", "action"),
    [
        (["create", "p.json"], "create"),
        (["publish", "p.json"], "create"),
        (["list", "*Read*", "--wide"], "list"),
        (["get", "ReadOnlyAccess"], "get"),
        (["export", "ReadOnlyAccess"], "export"),
        (["update", "ReadOnlyAccess", "p.yaml"], "update"),
        (["edit", "ReadOnlyAccess"], "edit"),
        (["versions", "ReadOnlyAccess"], "versions"),
        (["rollback", "ReadOnlyAccess", "v1"], "rollback"),
        (["remove", "ReadOnlyAccess"], "delete"),
        (
            [
                "check",
                "ReadOnlyAccess",
                "--role",
                "arn:aws:iam::123456789012:role/Test",
            ],
            "check",
        ),
        (["tag", "set", "ReadOnlyAccess", "--tag", "env=test"], "tag"),
        (["adopt", "ReadOnlyAccess"], "adopt"),
        (["release", "ReadOnlyAccess"], "release"),
    ],
)
def test_registers_locked_grammar(argv: list[str], action: str) -> None:
    assert parser().parse_args(argv).policy_action == action


def test_loads_json_yaml_toml_and_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for suffix, content in (
        ("json", json.dumps(DOCUMENT)),
        ("yaml", "Version: '2012-10-17'\nStatement: []\n"),
        ("toml", "Version = '2012-10-17'\nStatement = []\n"),
    ):
        path = tmp_path / f"policy.{suffix}"
        path.write_text(content, encoding="utf-8")
        args = parser().parse_args(["create", str(path)])
        assert cli._load_from_file(args, str(path)).document["Version"] == "2012-10-17"

    monkeypatch.setattr(cli.sys, "stdin", StringIO(json.dumps(DOCUMENT)))
    args = parser().parse_args(["create", "-", "FromStdin", "--format", "json"])
    assert cli._load_from_file(args, "-").document == DOCUMENT


def test_stdin_requires_format(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.sys, "stdin", StringIO("{}"))
    result = cli.dispatch(parser().parse_args(["create", "-"]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_ERROR"
    assert result.exit_code == 3


def test_toml_export_round_trips() -> None:
    encoded = cli._serialize(DOCUMENT, PolicyFormat.TOML)
    assert tomllib.loads(encoded) == DOCUMENT


def test_create_uses_naming_tags_and_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "agent-read.json"
    path.write_text(json.dumps(DOCUMENT), encoding="utf-8")
    fake = service()
    fake.resolve.return_value = ResolutionResult("custom:AgentRead", ())
    plan = PolicyChangePlan(
        OperationPlan("plan", ChangeAction.CREATE, "Create AgentRead.", ()),
        None,
        "AgentRead",
        "/hacksaws/",
        DOCUMENT,
        None,
        (),
    )
    fake.plan_create.return_value = plan
    fake.execute_change.return_value = PublishResult(
        ChangeAction.CREATE, record(), OperationJournal("plan", [])
    )
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    monkeypatch.setattr(cli._state, "load_config", _state.default_config)
    args = parser().parse_args(["create", str(path), "--tag", "team=agents", "--yes"])
    result = cli.dispatch(args, context())
    assert result is not None
    assert result.code == "IAM_POLICY_CHANGED"
    options = fake.plan_create.call_args.kwargs["options"]
    assert fake.plan_create.call_args.args[0] == "AgentRead"
    assert options.user_tags == (Tag("team", "agents"),)


def test_create_reports_no_change_and_conflict_requires_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "AgentRead.json"
    path.write_text(json.dumps(DOCUMENT), encoding="utf-8")
    fake = service()
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    monkeypatch.setattr(cli._state, "load_config", _state.default_config)
    result = cli.dispatch(parser().parse_args(["create", str(path)]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_NO_CHANGE"

    path.write_text(json.dumps({**DOCUMENT, "Statement": []}), encoding="utf-8")
    result = cli.dispatch(parser().parse_args(["create", str(path)]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_COLLISION"


def test_generated_create_name_can_be_accepted_edited_or_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "agent-read.yaml"
    path.write_text("Version: '2012-10-17'\nStatement: []\n", encoding="utf-8")
    loaded = cli.load_policy_input(path)
    args = argparse.Namespace(name=None, file=str(path), account=None)
    monkeypatch.setattr(cli._state, "load_config", _state.default_config)
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(isatty=lambda: True))

    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    assert cli._create_name(args, loaded)[0] == "AgentRead"

    answers = iter(["edit", "TeamAgentRead"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    assert cli._create_name(args, loaded)[0] == "TeamAgentRead"

    monkeypatch.setattr("builtins.input", lambda _prompt: "cancel")
    with pytest.raises(cli.PolicyInputError, match="cancelled"):
        cli._create_name(args, loaded)

    monkeypatch.setattr("builtins.input", lambda _prompt: "unknown")
    with pytest.raises(cli.PolicyInputError, match="Accept, Edit, or Cancel"):
        cli._create_name(args, loaded)

    answers = iter(["edit", ""])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    with pytest.raises(cli.PolicyInputError, match="cannot be empty"):
        cli._create_name(args, loaded)


def test_list_uses_scope_patterns_and_dynamic_legend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = service()
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(
        parser().parse_args(["list", "*Read*", "--all", "--wide"]), context()
    )
    assert result is not None
    assert "AWS-managed" in result.message
    assert "Hacksaws-owned" in result.message
    assert result.data["view"] == "wide"
    fake.list_policies.assert_called_once_with(scope=PolicyScope.ALL, include_tags=True)


def test_get_and_versions_resolve_to_arn(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = service()
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(parser().parse_args(["get", "AgentRead"]), context())
    assert result is not None
    assert ARN in result.message
    result = cli.dispatch(parser().parse_args(["versions", "AgentRead"]), context())
    assert result is not None
    assert "v1" in result.message


def test_export_defaults_yaml_and_writes_nested_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = service()
    fake.export_policy.return_value = SimpleNamespace(
        policy=record(), active_document=DOCUMENT, versions=()
    )
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    output = tmp_path / "export.yaml"
    result = cli.dispatch(
        parser().parse_args(
            ["export", "AgentRead", str(output), "--metadata", "nested"]
        ),
        context(),
    )
    assert result is not None
    assert result.code == "IAM_POLICY_EXPORT"
    loaded = __import__("yaml").safe_load(output.read_text(encoding="utf-8"))
    assert loaded["metadata"]["name"] == "AgentRead"
    assert loaded["policy"] == DOCUMENT


def test_export_sidecar_requires_file(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = service()
    fake.export_policy.return_value = SimpleNamespace(
        policy=record(), active_document=DOCUMENT, versions=()
    )
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(
        parser().parse_args(["export", "AgentRead", "--metadata", "sidecar"]),
        context(),
    )
    assert result is not None
    assert result.code == "IAM_POLICY_ERROR"


def test_noninteractive_update_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(DOCUMENT), encoding="utf-8")
    fake = service()
    plan = PolicyChangePlan(
        OperationPlan("plan", ChangeAction.UPDATE, "Update policy.", ()),
        ManagedPolicyArn.parse(ARN),
        "AgentRead",
        "/hacksaws/",
        DOCUMENT,
        None,
        (),
        expected_default_version_id="v1",
        validation=ValidationReport(),
    )
    fake.plan_publish.return_value = plan
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    monkeypatch.setattr(cli.sys, "stdin", StringIO())
    result = cli.dispatch(
        parser().parse_args(["update", "AgentRead", str(path)]), context()
    )
    assert result is not None
    assert result.code == "IAM_POLICY_CANCELLED"
    fake.execute_change.assert_not_called()


def test_ambiguous_reference_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = service()
    fake.resolve.return_value = ResolutionResult(
        "ReadOnlyAccess", (record(), record(aws=True, owned=False))
    )
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    monkeypatch.setattr(cli.sys, "stdin", StringIO())
    result = cli.dispatch(parser().parse_args(["get", "ReadOnlyAccess"]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_ERROR"
    assert "ambiguous" in result.message


def test_tag_set_and_reserved_safeguard(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = service()
    selected_context = context()
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(
        parser().parse_args(["tag", "set", "AgentRead", "--tag", "env=test", "--yes"]),
        selected_context,
    )
    assert result is not None
    assert result.code == "IAM_POLICY_TAG_CHANGED"
    assert result.data["journalId"] == "journal-1"
    result = cli.dispatch(
        parser().parse_args(
            [
                "tag",
                "set",
                "AgentRead",
                "--tag",
                "hacksaws:managed-by=other",
                "--yes",
            ]
        ),
        selected_context,
    )
    assert result is not None
    assert result.code == "IAM_POLICY_ERROR"


def test_delete_requires_owned_or_explicit_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = service()
    fake.plan_delete.return_value = SimpleNamespace(
        policy=record(owned=False),
        dependencies=SimpleNamespace(
            permission_users=(),
            permission_groups=(),
            permission_roles=(),
            boundary_users=(),
            boundary_roles=(),
            empty=True,
        ),
        operation=OperationPlan("plan", ChangeAction.DELETE, "Delete policy.", ()),
        executable=True,
    )
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(
        parser().parse_args(["delete", "AgentRead", "--yes"]), context()
    )
    assert result is not None
    assert result.code == "IAM_POLICY_UNMANAGED"
    fake.execute_delete.assert_not_called()


def test_packed_policy_failure_is_structured(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = service()
    fake.get_policy.return_value = record()
    fake.validate_policy.return_value = ValidationReport()
    fake.probe_assume_role.side_effect = PackedPolicyProbeError(
        PackedPolicyDiagnostic(
            "PackedPolicyTooLarge",
            "Packed session policy is too large.",
            101,
            (RepairAction("reduce-policy", "policy", "Reduce policy size.", None),),
        )
    )
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(
        parser().parse_args(
            [
                "check",
                "AgentRead",
                "--role",
                f"arn:aws:iam::{ACCOUNT}:role/AgentSession",
            ]
        ),
        context(),
    )
    assert result is not None
    assert result.code == "IAM_POLICY_PACKED_TOO_LARGE"
    assert result.data["packedPolicySize"] == 101


def test_dispatch_returns_none_when_no_leaf() -> None:
    assert cli.dispatch(argparse.Namespace(), context()) is None


def test_tag_parser_rejects_invalid_and_duplicate_values() -> None:
    with pytest.raises(ValueError, match="KEY=VALUE"):
        cli._tags(["broken"])
    with pytest.raises(ValueError, match="more than once"):
        cli._tags(["Env=one", "env=two"])


def test_metadata_and_format_precedence(tmp_path: Path) -> None:
    nested = tmp_path / "nested.data"
    nested.write_text(
        json.dumps({"metadata": {"name": "Nested"}, "policy": DOCUMENT}),
        encoding="utf-8",
    )
    args = parser().parse_args(
        ["create", str(nested), "--format", "json", "--metadata", "nested"]
    )
    loaded = cli._load_from_file(args, str(nested))
    assert loaded.metadata.name == "Nested"
    assert loaded.document == DOCUMENT
    assert (
        cli._output_format(argparse.Namespace(format="json", output="policy.yaml"))
        is PolicyFormat.JSON
    )
    assert (
        cli._output_format(argparse.Namespace(format=None, output="unknown.ext"))
        is PolicyFormat.YAML
    )


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("Pascal", "PreAgentReadPost"),
        ("camel", "PreagentReadPost"),
        ("snake", "Preagent_readPost"),
        ("kebab", "Preagent-readPost"),
    ],
)
def test_naming_cases(case: str, expected: str) -> None:
    assert (
        cli._named("agent-read", {"case": case, "prefix": "Pre", "suffix": "Post"})
        == expected
    )


def test_ambiguous_reference_can_be_selected_interactively(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = service()
    fake.resolve.return_value = ResolutionResult(
        "ReadOnlyAccess", (record(), record(aws=True, owned=False))
    )
    terminal = StringIO()
    terminal.isatty = lambda: True
    monkeypatch.setattr(cli.sys, "stdin", terminal)
    monkeypatch.setattr("builtins.input", lambda _: "2")
    assert cli._select(fake, "ReadOnlyAccess").arn.value == AWS_ARN
    monkeypatch.setattr("builtins.input", lambda _: "bogus")
    with pytest.raises(RuntimeError, match="valid policy selection"):
        cli._select(fake, "ReadOnlyAccess")


def test_sidecar_export_and_stdout_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = service()
    fake.export_policy.return_value = SimpleNamespace(
        policy=record(), active_document=DOCUMENT, versions=()
    )
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    output = tmp_path / "policy.json"
    result = cli.dispatch(
        parser().parse_args(
            ["export", "AgentRead", str(output), "--metadata", "sidecar"]
        ),
        context(),
    )
    assert result is not None
    sidecar = tmp_path / "policy.metadata.json"
    assert sidecar.exists()
    assert json.loads(sidecar.read_text(encoding="utf-8"))["name"] == "AgentRead"
    result = cli.dispatch(
        parser().parse_args(["export", "AgentRead", "--format", "json"]),
        context(),
    )
    assert result is not None
    assert json.loads(result.message) == DOCUMENT


def test_edit_success_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = service()
    fake.export_policy.return_value = SimpleNamespace(
        policy=record(), active_document=DOCUMENT, versions=()
    )
    plan = PolicyChangePlan(
        OperationPlan("plan", ChangeAction.NOOP, "Unchanged.", ()),
        ManagedPolicyArn.parse(ARN),
        "AgentRead",
        "/hacksaws/",
        DOCUMENT,
        None,
        (),
        validation=ValidationReport(),
    )
    fake.plan_publish.return_value = plan
    fake.execute_change.return_value = PublishResult(
        ChangeAction.NOOP, record(), OperationJournal("plan", [])
    )
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    monkeypatch.setattr(
        cli.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0)
    )
    result = cli.dispatch(parser().parse_args(["edit", "AgentRead"]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_CHANGED"
    monkeypatch.setattr(
        cli.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=7)
    )
    result = cli.dispatch(parser().parse_args(["edit", "AgentRead"]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_EDITOR_FAILED"


def test_rollback_and_owned_delete_execute(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = service()
    rollback_plan = PolicyChangePlan(
        OperationPlan("rollback", ChangeAction.NOOP, "Already selected.", ()),
        ManagedPolicyArn.parse(ARN),
        "AgentRead",
        "/hacksaws/",
        DOCUMENT,
        None,
        (),
        validation=ValidationReport(),
    )
    fake.plan_rollback.return_value = rollback_plan
    fake.execute_change.return_value = PublishResult(
        ChangeAction.NOOP, record(), OperationJournal("rollback", [])
    )
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(
        parser().parse_args(["rollback", "AgentRead", "v1", "--yes"]), context()
    )
    assert result is not None
    assert result.code == "IAM_POLICY_CHANGED"

    dependencies = PolicyDependencies(
        permission_roles=(EntityReference("Role", "Agent", "R1"),)
    )
    delete_plan = PolicyDeletionPlan(
        policy=record(),
        dependencies=dependencies,
        operation=OperationPlan("delete", ChangeAction.DELETE, "Delete policy.", ()),
        cascade=True,
    )
    fake.plan_delete.return_value = delete_plan
    fake.policy_dependencies.return_value = dependencies
    result = cli.dispatch(
        parser().parse_args(["delete", "AgentRead", "--cascade", "--yes"]),
        context(),
    )
    assert result is not None
    assert result.code == "IAM_POLICY_DELETED"
    assert result.data["dependencies"]["permissionRoles"] == ["Agent"]


def test_check_success_warning_and_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = service()
    warning = ValidationDiagnostic(
        DiagnosticSeverity.WARNING, "WARN", "Educational warning."
    )
    fake.validate_policy.return_value = ValidationReport((warning,))
    fake.probe_assume_role.return_value = SimpleNamespace(
        role_arn=f"arn:aws:iam::{ACCOUNT}:role/AgentSession",
        assumed_role_arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/AgentSession/check",
        expires_at=NOW,
        packed_policy_size=85,
        warning=PackedPolicyWarning(85, 80, "Packed policy is at 85% capacity."),
    )
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(
        parser().parse_args(
            [
                "check",
                "AgentRead",
                "--role",
                f"arn:aws:iam::{ACCOUNT}:role/AgentSession",
            ]
        ),
        context(),
    )
    assert result is not None
    assert result.code == "IAM_POLICY_CHECK"
    assert "85%" in result.message

    error = ValidationDiagnostic(DiagnosticSeverity.ERROR, "DENIED", "Invalid.")
    fake.validate_policy.return_value = ValidationReport((error,))
    result = cli.dispatch(parser().parse_args(["check", "AgentRead"]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_CHECK_FAILED"


def test_tag_list_remove_and_ownership(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = service()
    selected_context = context()
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(
        parser().parse_args(["tag", "list", "AgentRead"]), selected_context
    )
    assert result is not None
    assert result.code == "IAM_POLICY_TAG_LIST"
    result = cli.dispatch(
        parser().parse_args(["tag", "remove", "AgentRead", "environment", "--yes"]),
        selected_context,
    )
    assert result is not None
    assert result.data["journalId"] == "journal-1"

    ownership_plan = TagChangePlan(
        record(),
        OperationPlan("ownership", ChangeAction.ADOPT, "Adopt policy.", ()),
        (),
        (),
        "digest",
    )
    fake.plan_adopt.return_value = ownership_plan
    fake.execute_tag_change.return_value = SimpleNamespace(policy=record())
    result = cli.dispatch(
        parser().parse_args(["adopt", "AgentRead", "--yes"]), context()
    )
    assert result is not None
    assert result.code == "IAM_POLICY_OWNERSHIP_CHANGED"
    fake.plan_release.return_value = ownership_plan
    result = cli.dispatch(
        parser().parse_args(["release", "AgentRead", "--yes"]), context()
    )
    assert result is not None
    assert result.data["action"] == "release"


def test_dispatch_normalizes_drift_and_unknown_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = service()
    fake.get_policy.side_effect = PolicyDriftError("changed after planning")
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(parser().parse_args(["get", "AgentRead"]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_DRIFT"
    result = cli.dispatch(argparse.Namespace(policy_action="unknown"), context())
    assert result is not None
    assert result.code == "IAM_POLICY_HELP"


def test_stored_policy_drives_update(monkeypatch: pytest.MonkeyPatch) -> None:
    stored = SimpleNamespace(
        document=DOCUMENT,
        metadata=SimpleNamespace(name="StoredRead"),
    )
    monkeypatch.setattr(cli, "_stored_policy", lambda _: stored)
    args = parser().parse_args(
        ["update", "AgentRead", "--from-stored", "StoredRead", "--yes"]
    )
    reference, loaded = cli._loaded_update(args)
    assert reference == "AgentRead"
    assert loaded.document == DOCUMENT
    with pytest.raises(ValueError, match="cannot be combined"):
        cli._loaded_update(
            argparse.Namespace(
                from_stored="StoredRead",
                policy_or_file="AgentRead",
                file="policy.json",
            )
        )


def test_toml_scalars_and_unrepresentable_shape() -> None:
    with pytest.raises(ValueError, match="no null value"):
        cli._toml_scalar(None)
    truth = True
    assert cli._toml_scalar(truth) == "true"
    assert cli._toml_scalar(3) == "3"
    assert cli._toml_scalar(["a", 2]) == '["a", 2]'
    with pytest.raises(ValueError, match="losslessly"):
        cli._toml_scalar({"nested": "value"})


def test_validation_failure_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    diagnostic = ValidationDiagnostic(
        DiagnosticSeverity.ERROR,
        "INVALID",
        "Policy is invalid.",
        "Statement",
        RepairAction("rewrite", "Statement", "Rewrite the statement."),
    )
    plan = PolicyChangePlan(
        OperationPlan("plan", ChangeAction.UPDATE, "Update.", ()),
        ManagedPolicyArn.parse(ARN),
        "AgentRead",
        "/hacksaws/",
        DOCUMENT,
        None,
        (),
        validation=ValidationReport((diagnostic,)),
    )
    fake = service()
    monkeypatch.setattr(cli.sys, "stdin", StringIO())
    result = cli._execute_plan(fake, plan, argparse.Namespace(yes=False), context())
    assert result.code == "IAM_POLICY_VALIDATION_FAILED"
    assert fake.execute_change.call_count == 0


def test_policy_dry_run_returns_plan_without_confirmation_or_journal() -> None:
    plan = PolicyChangePlan(
        OperationPlan("plan", ChangeAction.UPDATE, "Update AgentRead.", ()),
        ManagedPolicyArn.parse(ARN),
        "AgentRead",
        "/hacksaws/",
        {**DOCUMENT, "Statement": []},
        None,
        (),
        validation=ValidationReport(),
    )
    fake = service()
    result = cli._execute_plan(
        fake,
        plan,
        argparse.Namespace(yes=False, dry_run=True),
        context(),
    )
    assert result.code == "IAM_POLICY_DRY_RUN"
    assert result.data["dryRun"] is True
    assert result.data["classification"] == "planned"
    assert fake.execute_change.call_count == 0


def test_missing_reference_and_missing_document_are_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = service()
    fake.resolve.return_value = ResolutionResult("missing", ())
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(parser().parse_args(["get", "missing"]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_ERROR"

    fake.resolve.return_value = ResolutionResult("AgentRead", (record(),))
    fake.get_policy.return_value = record(document=False)
    result = cli.dispatch(parser().parse_args(["check", "AgentRead"]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_ERROR"


def test_tag_help_empty_set_and_aws_immutable(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = service()
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(
        argparse.Namespace(policy_action="tag", policy_tag_action=None), context()
    )
    assert result is not None
    assert result.code == "IAM_POLICY_TAG_HELP"
    result = cli.dispatch(
        parser().parse_args(["tag", "set", "AgentRead", "--yes"]), context()
    )
    assert result is not None
    assert result.code == "IAM_POLICY_ERROR"
    fake.get_policy.return_value = record(aws=True, owned=False)
    result = cli.dispatch(
        parser().parse_args(["tag", "set", "AgentRead", "--tag", "env=test", "--yes"]),
        context(),
    )
    assert result is not None
    assert result.code == "IAM_POLICY_IMMUTABLE"


def test_delete_dependencies_and_confirmation_are_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = service()
    dependency = PolicyDependencies(
        permission_roles=(EntityReference("Role", "Agent", "R1"),)
    )
    fake.plan_delete.return_value = PolicyDeletionPlan(
        policy=record(),
        dependencies=dependency,
        operation=OperationPlan("delete", ChangeAction.DELETE, "Delete policy.", ()),
        cascade=False,
    )
    fake.policy_dependencies.return_value = PolicyDependencies()
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(
        parser().parse_args(["delete", "AgentRead", "--yes"]), context()
    )
    assert result is not None
    assert result.code == "IAM_POLICY_DEPENDENCIES"

    fake.plan_delete.return_value = PolicyDeletionPlan(
        policy=record(),
        dependencies=PolicyDependencies(),
        operation=OperationPlan("delete", ChangeAction.DELETE, "Delete policy.", ()),
        cascade=False,
    )
    monkeypatch.setattr(cli.sys, "stdin", StringIO())
    result = cli.dispatch(parser().parse_args(["delete", "AgentRead"]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_CANCELLED"


def test_dispatch_normalizes_immutable_and_os_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = service()
    fake.get_policy.side_effect = ImmutablePolicyError("immutable")
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(parser().parse_args(["get", "AgentRead"]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_IMMUTABLE"
    fake.get_policy.side_effect = OSError("offline")
    result = cli.dispatch(parser().parse_args(["get", "AgentRead"]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_AWS_ERROR"


def test_stored_and_metadata_inferred_updates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _state.default_config()
    config["policies"]["StoredRead"] = {
        "file": "stored_session_policies/StoredRead.yaml"
    }
    policy_path = tmp_path / "stored_session_policies" / "StoredRead.yaml"
    policy_path.parent.mkdir()
    policy_path.write_text(
        cli._serialize(DOCUMENT, PolicyFormat.YAML), encoding="utf-8"
    )
    monkeypatch.setattr(cli._state, "root", lambda: tmp_path)
    monkeypatch.setattr(cli._state, "load_config", lambda: config)
    stored = cli._stored_policy("StoredRead")
    assert stored.metadata.name == "StoredRead"
    assert stored.document == DOCUMENT

    nested = tmp_path / "update.yaml"
    nested.write_text(
        cli._serialize(
            {"metadata": {"name": "AgentRead"}, "policy": DOCUMENT},
            PolicyFormat.YAML,
        ),
        encoding="utf-8",
    )
    args = parser().parse_args(["update", str(nested), "--metadata", "nested"])
    reference, loaded = cli._loaded_update(args)
    assert reference == "AgentRead"
    assert loaded.document == DOCUMENT

    result = cli._export(
        argparse.Namespace(
            policy="stored:StoredRead",
            format=None,
            output=None,
            metadata="nested",
            metadata_file=None,
            all_versions=False,
        ),
        service(),
    )
    assert result.data["provenance"] == "stored"
    assert "StoredRead" in result.message


def test_naming_enforcement_and_exact_interactive_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded = SimpleNamespace(metadata=SimpleNamespace(name=None))
    args = argparse.Namespace(name="Explicit", file="policy.json")
    config = _state.default_config()
    config["naming"]["resources"]["policy"] = {
        "prefix": "Managed",
        "enforcement": "warn",
    }
    monkeypatch.setattr(cli._state, "load_config", lambda: config)
    selected, warnings = cli._create_name(args, loaded)
    assert selected == "Explicit"
    assert warnings
    config["naming"]["resources"]["policy"]["enforcement"] = "error"
    with pytest.raises(ValueError, match="configured name"):
        cli._create_name(args, loaded)

    terminal = StringIO()
    terminal.isatty = lambda: True
    monkeypatch.setattr(cli.sys, "stdin", terminal)
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert not cli._confirm(argparse.Namespace(yes=False), "Continue?")
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    assert cli._confirm(argparse.Namespace(yes=False), "Continue?")


def test_interactive_version_repair_replans_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repair = RepairAction(
        "set-version",
        "Version",
        "Set current IAM policy language version.",
        "2012-10-17",
    )
    warning = ValidationDiagnostic(
        DiagnosticSeverity.WARNING,
        "OLD_VERSION",
        "Old version.",
        "Version",
        repair,
    )
    old_document: dict[str, JsonValue] = {"Version": "2008-10-17", "Statement": []}
    plan = PolicyChangePlan(
        OperationPlan("create", ChangeAction.CREATE, "Create policy.", ()),
        None,
        "AgentRead",
        "/hacksaws/",
        old_document,
        "Description",
        (Tag("team", "agents"),),
        validation=ValidationReport((warning,)),
    )
    replacement = PolicyChangePlan(
        OperationPlan("create", ChangeAction.NOOP, "No change.", ()),
        ManagedPolicyArn.parse(ARN),
        "AgentRead",
        "/hacksaws/",
        DOCUMENT,
        None,
        (),
    )
    fake = service()
    fake.plan_create.return_value = replacement
    terminal = StringIO()
    terminal.isatty = lambda: True
    monkeypatch.setattr(cli.sys, "stdin", terminal)
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    updated = cli._repair(plan, argparse.Namespace(yes=False), fake)
    assert updated is replacement
    assert fake.plan_create.call_args.args[1]["Version"] == "2012-10-17"


def test_dispatch_normalizes_service_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = ValidationReport(
        (ValidationDiagnostic(DiagnosticSeverity.ERROR, "INVALID", "Invalid policy."),)
    )
    fake = service()
    fake.get_policy.side_effect = PolicyValidationError(report)
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(parser().parse_args(["get", "AgentRead"]), context())
    assert result is not None
    assert result.code == "IAM_POLICY_VALIDATION_FAILED"
    assert result.data["diagnostics"][0]["code"] == "INVALID"


def test_check_probes_the_exact_selected_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = service()
    fake.validate_policy.return_value = ValidationReport()
    fake.probe_assume_role.return_value = SimpleNamespace(
        role_arn=f"arn:aws:iam::{ACCOUNT}:role/AgentSession",
        assumed_role_arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/AgentSession/check",
        expires_at=NOW,
        packed_policy_size=12,
        warning=None,
    )
    monkeypatch.setattr(cli, "_service", lambda _: fake)

    result = cli.dispatch(
        parser().parse_args(["check", "AgentRead", "--role", "AgentSession"]),
        context(),
    )

    assert result is not None
    assert result.data["probe"]["packedPolicySize"] == 12
    assert fake.probe_assume_role.call_args.args == (
        f"arn:aws:iam::{ACCOUNT}:role/AgentSession",
        DOCUMENT,
    )
    assert fake.probe_assume_role.call_args.kwargs["options"].duration_seconds == 900


def test_edit_fails_if_default_version_or_document_drifted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = service()
    initial = record()
    changed_document: dict[str, JsonValue] = {
        "Version": "2012-10-17",
        "Statement": [],
    }
    changed = replace(
        initial,
        default_version_id="v2",
        document=changed_document,
    )
    fake.export_policy.return_value = SimpleNamespace(
        policy=initial, active_document=DOCUMENT, versions=()
    )
    fake.get_policy.return_value = changed
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
    )

    result = cli.dispatch(parser().parse_args(["edit", "AgentRead"]), context())

    assert result is not None
    assert result.code == "IAM_POLICY_DRIFT"
    fake.plan_publish.assert_not_called()


def test_export_all_versions_is_lossless_and_preserves_description(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    changed_document: dict[str, JsonValue] = {
        "Version": "2012-10-17",
        "Statement": [],
    }
    versions = (
        PolicyVersionRecord(
            version_id="v1",
            is_default=False,
            created_at=NOW,
            document=DOCUMENT,
        ),
        PolicyVersionRecord(
            version_id="v2",
            is_default=True,
            created_at=NOW,
            document=changed_document,
        ),
    )
    item = replace(
        record(),
        description="Read CloudWatch safely.",
        default_version_id="v2",
        document=changed_document,
        versions=versions,
    )
    fake = service()
    fake.export_policy.return_value = SimpleNamespace(
        policy=item, active_document=changed_document, versions=versions
    )
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    output = tmp_path / "all.json"

    result = cli.dispatch(
        parser().parse_args(
            [
                "export",
                "AgentRead",
                str(output),
                "--format",
                "json",
                "--metadata",
                "nested",
                "--all-versions",
            ]
        ),
        context(),
    )

    assert result is not None
    exported = json.loads(output.read_text(encoding="utf-8"))
    assert exported["metadata"]["description"] == "Read CloudWatch safely."
    assert exported["policy"] == changed_document
    assert exported["versions"] == [
        {
            "id": "v1",
            "default": False,
            "createdAt": NOW.isoformat(),
            "policy": DOCUMENT,
        },
        {
            "id": "v2",
            "default": True,
            "createdAt": NOW.isoformat(),
            "policy": changed_document,
        },
    ]


def test_delete_requires_explicit_boundary_removal_and_snapshots_preview(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dependencies = PolicyDependencies(
        permission_roles=(EntityReference("Role", "Reader", "R1"),),
        boundary_users=(EntityReference("User", "Restricted", "U1"),),
    )
    plan = PolicyDeletionPlan(
        record(),
        dependencies,
        OperationPlan("delete", ChangeAction.DELETE, "Delete policy.", ()),
        cascade=True,
    )
    fake = service()
    fake.plan_delete.return_value = plan
    fake.policy_dependencies.return_value = dependencies
    monkeypatch.setattr(cli, "_service", lambda _: fake)

    blocked = cli.dispatch(
        parser().parse_args(["delete", "AgentRead", "--cascade", "--yes"]),
        context(),
    )
    assert blocked is not None
    assert blocked.code == "IAM_POLICY_BOUNDARIES"

    snapshots: list[tuple[dict[str, object], dict[str, object]]] = []
    monkeypatch.setattr(
        cli,
        "_durable_reconcile",
        lambda _context, _operation, forward, compensation: (
            snapshots.append((dict(forward), dict(compensation))) or "delete-journal"
        ),
    )
    deleted = cli.dispatch(
        parser().parse_args(
            [
                "delete",
                "AgentRead",
                "--cascade",
                "--remove-boundaries",
                "--yes",
            ]
        ),
        context(),
    )
    assert deleted is not None
    assert deleted.code == "IAM_POLICY_DELETED"
    assert deleted.data["preview"]["attachments"]["roles"] == ["Reader"]
    assert deleted.data["preview"]["permissionBoundaries"]["users"] == ["Restricted"]
    assert deleted.data["preview"]["versions"][0]["id"] == "v1"
    assert snapshots[0][0]["exists"] is False
    assert snapshots[0][1]["dependencies"]["boundaryUsers"] == [
        {"type": "User", "name": "Restricted", "id": "U1"}
    ]
    assert snapshots[0][1]["versions"][0]["document"] == DOCUMENT


def test_delete_rechecks_ownership_after_fresh_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planned = record()
    plan = PolicyDeletionPlan(
        planned,
        PolicyDependencies(),
        OperationPlan("delete", ChangeAction.DELETE, "Delete policy.", ()),
        cascade=True,
    )
    fake = service()
    fake.plan_delete.return_value = plan
    fake.get_policy.return_value = replace(planned, tags=())
    fake.policy_dependencies.return_value = PolicyDependencies()
    monkeypatch.setattr(cli, "_service", lambda _: fake)

    result = cli.dispatch(
        parser().parse_args(["delete", "AgentRead", "--cascade", "--yes"]),
        context(),
    )

    assert result is not None
    assert result.code == "IAM_POLICY_UNMANAGED"
    assert "changed after deletion planning" in result.message


def test_json_mode_never_prompts_and_tag_changes_detect_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal = StringIO()
    terminal.isatty = lambda: True
    monkeypatch.setattr(cli.sys, "stdin", terminal)
    monkeypatch.setattr(cli._configs, "json_output_enabled", lambda: True)
    monkeypatch.setattr(
        "builtins.input",
        lambda _prompt: pytest.fail("JSON mode must not prompt"),
    )
    assert not cli._confirm(argparse.Namespace(yes=False), "Continue?")
    assert not cli._confirm_exact(argparse.Namespace(yes=False), "Delete?", "AgentRead")

    fake = service()
    original = record()
    drifted = replace(original, tags=(*original.tags, Tag("changed", "yes")))
    fake.get_policy.side_effect = [original, drifted]
    monkeypatch.setattr(cli, "_service", lambda _: fake)
    result = cli.dispatch(
        parser().parse_args(
            ["tag", "set", "AgentRead", "--tag", "environment=test", "--yes"]
        ),
        context(),
    )
    assert result is not None
    assert result.code == "IAM_POLICY_DRIFT"


def test_durable_policy_state_is_written_before_forward_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    _iam_recovery.clear_handlers()
    dependencies = PolicyDependencies(
        permission_users=(EntityReference("User", "Human", "U1"),)
    )
    forward = cli._policy_state(record(), dependencies=dependencies)
    compensation = cli._absent_state(ARN, "AgentRead", "/hacksaws/")
    observed: dict[str, object] = {}

    def crash(journal_id: str, _context: object) -> None:
        observed.update(_iam_recovery.get_journal(journal_id))
        raise RuntimeError("simulated crash before AWS")  # noqa: TRY003

    monkeypatch.setattr(_iam_recovery, "continue_journal", crash)
    with pytest.raises(RuntimeError, match="simulated crash"):
        _REAL_DURABLE_RECONCILE(context(), "update", forward, compensation)

    assert observed["status"] == "active"
    assert observed["partition"] == "aws"
    steps = observed["steps"]
    assert isinstance(steps, list)
    create_step, reconcile_step = steps
    assert create_step["status"] == "pending"
    assert create_step["forward"]["target"]["versions"][0]["document"] == DOCUMENT
    assert create_step["forward"]["target"]["dependencies"]["permissionUsers"] == []
    assert reconcile_step["status"] == "pending"
    assert reconcile_step["forward"]["target"]["dependencies"]["permissionUsers"] == [
        {"type": "User", "name": "Human", "id": "U1"}
    ]
    assert create_step["compensation"]["effectSourceStep"] == "self"
    assert reconcile_step["forward"]["effectSourceStep"] == create_step["id"]

    monkeypatch.setattr(
        _iam_recovery,
        "continue_journal",
        lambda journal_id, _context: _iam_recovery.get_journal(journal_id),
    )
    completed_id = _REAL_DURABLE_RECONCILE(context(), "update", forward, compensation)
    assert _iam_recovery.get_journal(completed_id)["steps"][0]["status"] == "pending"


def test_update_and_rollback_states_capture_complete_compensation() -> None:
    fake = service()
    current = record()
    fake.get_policy.return_value = current
    update = PolicyChangePlan(
        OperationPlan("update", ChangeAction.UPDATE, "Update policy.", ()),
        ManagedPolicyArn.parse(ARN),
        "AgentRead",
        "/hacksaws/",
        {"Version": "2012-10-17", "Statement": []},
        current.description,
        current.tags,
        expected_default_version_id="v1",
        expected_digest=cli.policy_digest(DOCUMENT),
    )

    forward, compensation = cli._change_states(fake, update)

    assert compensation["versions"][0]["document"] == DOCUMENT
    assert forward["versions"][0]["default"] is False
    assert forward["versions"][1] == {
        "id": "pending",
        "default": True,
        "document": {"Version": "2012-10-17", "Statement": []},
    }
    assert cli._semantic_diff(fake, update)

    versions = (
        current.versions[0],
        PolicyVersionRecord(
            version_id="v2",
            is_default=False,
            created_at=NOW,
            document={"Version": "2012-10-17", "Statement": []},
        ),
    )
    fake.get_policy.return_value = replace(current, versions=versions)
    rollback = replace(
        update,
        operation=OperationPlan(
            "rollback", ChangeAction.ROLLBACK, "Rollback policy.", ()
        ),
        document={"Version": "2012-10-17", "Statement": []},
        rollback_version_id="v2",
    )
    rolled_forward, rolled_compensation = cli._change_states(fake, rollback)
    assert [item["default"] for item in rolled_forward["versions"]] == [False, True]
    assert [item["default"] for item in rolled_compensation["versions"]] == [
        True,
        False,
    ]


def test_recovery_state_schema_rejects_identity_losing_payloads() -> None:
    with pytest.raises(cli.OperationalError, match="tags are invalid"):
        cli._state_tags({"tags": [{}]})
    with pytest.raises(cli.OperationalError, match="dependencies are invalid"):
        cli._state_dependencies({"dependencies": []})
    with pytest.raises(cli.OperationalError, match="dependencies are invalid"):
        cli._state_dependencies({"dependencies": {"permissionUsers": {}}})
    with pytest.raises(cli.OperationalError, match="retain principal identity IDs"):
        cli._state_dependencies({"dependencies": {"permissionUsers": ["Human"]}})
    with pytest.raises(cli.OperationalError, match="dependencies are invalid"):
        cli._state_dependencies(
            {
                "dependencies": {
                    "permissionUsers": [{"type": "User", "name": "Human", "id": ""}]
                }
            }
        )
    valid_version = {
        "id": "v1",
        "default": True,
        "document": DOCUMENT,
    }
    with pytest.raises(cli.OperationalError, match="versions are invalid"):
        cli._versions_match(
            {"versions": [valid_version]},
            {"versions": [{**valid_version, "id": None}]},
        )


def test_recovery_checkpoint_helpers_reject_states_outside_exact_path() -> None:
    base = cli._policy_state(record(), dependencies=PolicyDependencies())

    wrong_document = json.loads(json.dumps(base))
    wrong_document["versions"][0]["document"] = {
        "Version": "2012-10-17",
        "Statement": [],
    }
    assert not cli._versions_subset(base, wrong_document)
    assert not cli._identity_matches(
        cli._absent_state(ARN, "AgentRead", "/hacksaws/"), base
    )
    wrong_path = {**base, "path": "/other/"}
    assert not cli._identity_matches(wrong_path, base)
    assert not cli._valid_existing_checkpoint(wrong_path, base, base)

    role_dependency = PolicyDependencies(
        permission_roles=(EntityReference("Role", "Reader", "R1"),)
    )
    with_dependency = cli._policy_state(record(), dependencies=role_dependency)
    assert not cli._valid_existing_checkpoint(base, base, with_dependency)
    assert not cli._valid_existing_checkpoint(with_dependency, base, base)

    extra_tag = json.loads(json.dumps(base))
    extra_tag["tags"].append({"Key": "concurrent", "Value": "yes"})
    assert not cli._valid_existing_checkpoint(extra_tag, base, base)
    changed_tag = json.loads(json.dumps(base))
    changed_tag["tags"][0]["Value"] = "someone-else"
    assert not cli._valid_existing_checkpoint(changed_tag, base, base)
    assert not cli._valid_existing_checkpoint(wrong_document, base, base)

    version_two = {
        "id": "v2",
        "default": False,
        "document": {"Version": "2012-10-17", "Statement": []},
    }
    two_versions = {**base, "versions": [*cli._state_versions(base), version_two]}
    missing_shared = {**base, "versions": [version_two]}
    assert not cli._valid_existing_checkpoint(
        missing_shared, two_versions, two_versions
    )
    absent = cli._absent_state(ARN, "AgentRead", "/hacksaws/")
    assert not cli._valid_transition_checkpoint(absent, absent, absent)
    assert not cli._states_match(
        absent,
        cli._absent_state("arn:aws:iam::123456789012:policy/Other", "Other", "/"),
    )


def test_recovery_helper_fail_closed_and_idempotent_edges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected_context = context()
    fake = service()
    expected = cli._policy_state(record(), dependencies=PolicyDependencies())

    monkeypatch.setattr(cli, "_policy_exists", lambda *_args: False)
    cli._delete_live_policy(selected_context, fake, ARN, expected)
    monkeypatch.setattr(cli, "_policy_exists", lambda *_args: True)
    monkeypatch.setattr(cli, "_live_policy_state", lambda *_args: expected)
    with pytest.raises(PolicyDriftError, match="before deletion"):
        cli._delete_live_policy(
            selected_context, fake, ARN, {**expected, "path": "/drift/"}
        )

    all_default_versions = tuple(
        PolicyVersionRecord(
            version_id=f"v{number}",
            is_default=True,
            created_at=NOW,
            document={"Version": "2012-10-17", "Statement": []},
        )
        for number in range(1, 6)
    )
    with pytest.raises(cli.OperationalError, match="No nondefault"):
        cli._ensure_version_capacity(
            selected_context,
            replace(record(), versions=all_default_versions),
            set(),
        )

    cli._restore_dependencies(selected_context, fake, ARN, None)
    dependency = PolicyDependencies(
        permission_users=(EntityReference("User", "Human", "U1"),)
    )
    fake.policy_dependencies.return_value = dependency
    cli._restore_dependencies(
        selected_context, fake, ARN, cli._dependency_payload(dependency)
    )
    selected_context.iam.get_user.side_effect = ClientError(
        {"Error": {"Code": "NoSuchEntity", "Message": "missing"}}, "GetUser"
    )
    with pytest.raises(PolicyDriftError, match="missing user"):
        cli._verify_principal_identity(selected_context, "User", "Missing", "U1")

    with pytest.raises(cli.OperationalError, match="exact expected and target"):
        cli._reconcile_policy({}, selected_context)
    with pytest.raises(cli.OperationalError, match="state ARNs do not match"):
        cli._reconcile_policy(
            {
                "expected": cli._absent_state(ARN, "AgentRead", "/hacksaws/"),
                "target": cli._absent_state(
                    "arn:aws:iam::123456789012:policy/Other", "Other", "/"
                ),
            },
            selected_context,
        )

    monkeypatch.setattr(cli, "_service", lambda _context: fake)
    monkeypatch.setattr(cli, "_live_policy_state", lambda *_args: expected)
    target = {**expected, "versions": []}
    with pytest.raises(cli.OperationalError, match="no default document"):
        cli._reconcile_policy(
            {"expected": expected, "target": target}, selected_context
        )


def test_policy_adapter_fail_closed_helper_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (
        cli._metadata_mode(argparse.Namespace(metadata=None, metadata_file=Path("x")))
        is cli.MetadataMode.SIDECAR
    )
    terminal = StringIO()
    terminal.isatty = lambda: True
    monkeypatch.setattr(cli.sys, "stdin", terminal)
    monkeypatch.setattr(cli._configs, "json_output_enabled", lambda: False)
    monkeypatch.setattr("builtins.input", lambda _prompt: "AgentRead")
    assert cli._confirm_exact(
        argparse.Namespace(yes=False), "Delete policy?", "AgentRead"
    )
    create_plan = PolicyChangePlan(
        OperationPlan("create", ChangeAction.CREATE, "Create.", ()),
        None,
        "AgentRead",
        "/hacksaws/",
        DOCUMENT,
        None,
        (),
    )
    assert cli._semantic_diff(service(), create_plan) == []
    with pytest.raises(ValueError, match="requires POLICY FILE"):
        cli._loaded_update(
            argparse.Namespace(from_stored=None, policy_or_file=None, file=None)
        )
