"""Focused contract tests for the central IAM CLI scaffold."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Self

import boto3
import pytest
from botocore.exceptions import ClientError

from hacksaws import _configs
from hacksaws import _iam_cleanup
from hacksaws import _iam_cli
from hacksaws import _iam_recovery
from hacksaws import _state


class _Client:
    def __init__(self, account: str = "123456789012") -> None:
        self.account = account

    def get_caller_identity(self) -> dict[str, str]:
        return {
            "Account": self.account,
            "Arn": f"arn:aws:iam::{self.account}:user/test",
        }


class _Frozen:
    access_key = "SELECTEDACCESS"
    secret_key = "selected-secret"  # noqa: S105
    token = "selected-token"  # noqa: S105


class _Credentials:
    def get_frozen_credentials(self) -> _Frozen:
        return _Frozen()


class _Session:
    region_name = "us-west-2"

    def __init__(self, account: str = "123456789012") -> None:
        self.account = account

    def get_credentials(self) -> _Credentials:
        return _Credentials()

    def client(self, name: str) -> _Client:
        assert name in {"iam", "sts", "accessanalyzer"}
        return _Client(self.account)


def _account_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    data = _state.default_config()
    data["accounts"]["Prod"] = {"id": "123456789012", "partition": "aws"}
    _state.save_config(data)


def test_context_binds_selected_files_and_verifies_expected_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _account_config(tmp_path, monkeypatch)
    monkeypatch.setenv("AWS_CONFIG_FILE", "before-config")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "before-credentials")
    monkeypatch.setenv("AWS_PROFILE", "before-profile")
    selected = tmp_path / "aws-west"
    selected.mkdir()
    observed: dict[str, str | None] = {}
    calls: list[dict[str, object]] = []

    def factory(**kwargs: object) -> _Session:
        calls.append(kwargs)
        observed["config"] = os.environ.get("AWS_CONFIG_FILE")
        observed["credentials"] = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
        observed["profile"] = os.environ.get("AWS_PROFILE")
        return _Session()

    context = _iam_cli.IamCommandContext.create(
        argparse.Namespace(
            profile="deploy",
            location="west",
            directory=str(selected),
            target=None,
            account="Prod",
            region="us-west-2",
        ),
        session_factory=factory,
    )
    assert context.account_id == "123456789012"
    assert context.config_path == selected / "config"
    assert observed == {
        "config": str(selected / "config"),
        "credentials": str(selected / "credentials"),
        "profile": None,
    }
    assert calls == [
        {"profile_name": "deploy", "region_name": "us-west-2"},
        {
            "aws_access_key_id": "SELECTEDACCESS",
            "aws_secret_access_key": "selected-secret",
            "aws_session_token": "selected-token",
            "region_name": "us-west-2",
        },
    ]
    assert os.environ["AWS_CONFIG_FILE"] == "before-config"
    assert os.environ["AWS_SHARED_CREDENTIALS_FILE"] == "before-credentials"
    assert os.environ["AWS_PROFILE"] == "before-profile"


def test_context_rejects_selected_account_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _account_config(tmp_path, monkeypatch)

    class WrongSession(_Session):
        def __init__(self) -> None:
            super().__init__("999999999999")

    with pytest.raises(_configs.OperationalError, match="selected account requires"):
        _iam_cli.IamCommandContext.create(
            argparse.Namespace(
                profile="default",
                location="default",
                directory=str(tmp_path / "aws"),
                target=None,
                account="Prod",
                region=None,
            ),
            session_factory=lambda **_kwargs: WrongSession(),
        )


def test_iam_remote_alias_help_json_error_and_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _account_config(tmp_path, monkeypatch)
    from hacksaws import _cli

    _iam_cli.clear_adapters()
    assert _cli.console_main(["iam", "policy"]).code == "IAM_LEAF_HELP"
    assert _cli.console_main(["remote", "policy"]).code == "IAM_LEAF_HELP"
    result = _cli.console_main(["iam", "recovery", "list", "--json"])
    rendered = json.loads(capsys.readouterr().out)
    assert result.code == "IAM_RECOVERY_LIST"
    assert rendered["schemaVersion"] == 1
    assert rendered["data"] == {"journals": [], "count": 0}
    bad = _cli.console_main(["iam", "recovery", "nope", "--json"])
    assert bad.exit_code == _configs.EXIT_USAGE
    assert json.loads(capsys.readouterr().err)["code"] == "ARGUMENT_ERROR"


def test_root_selectors_survive_a_leaf_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _account_config(tmp_path, monkeypatch)
    from hacksaws import _cli

    namespace = _cli._create_parser().parse_args(
        ["iam", "--profile", "source", "--location", "west", "policy"]
    )
    assert namespace.profile == "source"
    assert namespace.location == "west"


def test_terminal_iam_selectors_cleanup_aliases_and_no_abbreviations() -> None:
    from hacksaws import _cli

    parser = _cli._create_parser()
    policy = parser.parse_args(
        [
            "iam",
            "policy",
            "create",
            "policy.yaml",
            "--profile",
            "admin",
            "--location",
            "horizon",
            "--dry-run",
        ]
    )
    assert policy.profile == "admin"
    assert policy.location == "horizon"
    assert policy.dry_run is True

    for prefix in (["cleanup"], ["iam", "cleanup"], ["remote", "cleanup"]):
        cleanup = parser.parse_args([*prefix, "*Agent*", "--policies", "--dry-run"])
        assert cleanup.iam_action == "cleanup"
        assert cleanup.patterns == ["*Agent*"]
        assert cleanup.policies is True

    with pytest.raises(SystemExit):
        parser.parse_args(["iam", "policy", "get", "Agent", "--prof", "admin"])


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (
            ["iam", "--profile", "one", "policy", "get", "Agent", "--profile", "two"],
            "profile only once",
        ),
        (
            ["iam", "policy", "get", "Agent", "--location", "x", "-d", "aws"],
            "select the same AWS folder",
        ),
        (
            ["iam", "policy", "get", "Agent", "--target", "prod", "--profile", "admin"],
            "cannot be combined",
        ),
    ],
)
def test_selector_preflight_rejects_duplicates_and_conflicts(
    arguments: list[str], message: str
) -> None:
    with pytest.raises(_configs.OperationalError, match=message):
        _iam_cli.validate_selector_arguments(arguments)


def _inventory_item() -> _iam_cleanup.InventoryItem:
    return _iam_cleanup.InventoryItem(
        resource_type=_iam_cleanup.ResourceType.POLICY,
        name="AgentRead",
        arn="arn:aws:iam::123456789012:policy/hacksaws/AgentRead",
        resource_id="ANPA1",
        origin=_iam_cleanup.OwnershipOrigin.CREATED,
        owned=True,
        path="/hacksaws/",
        dependencies={"roles": ("Agent",)},
    )


def test_iam_inventory_and_cleanup_cli_results(monkeypatch: pytest.MonkeyPatch) -> None:
    item = _inventory_item()
    inventory = _iam_cleanup.IamInventory(
        "123456789012", "aws", "arn:aws:iam::123456789012:user/test", (item,)
    )
    planned = _iam_cleanup.CleanupPlan(
        inventory.account_id,
        inventory.partition,
        inventory.caller_arn,
        _iam_cleanup.CleanupOptions(patterns=("*Agent*",), dry_run=True),
        (item,),
        (),
    )
    cleaned = _iam_cleanup.CleanupResult(
        classification=_iam_cleanup.ResultClassification.CLEANED,
        journal_id="journal",
        completed=(item.key,),
        failed=(),
        remaining=(),
        lnt=True,
    )

    class Service:
        def __init__(self, _context: object) -> None:
            pass

        def inventory_summary(
            self,
            query: _iam_cleanup.InventoryQuery,
            *,
            progress: object = None,
        ) -> _iam_cleanup.InventorySummary:
            del progress
            return _iam_cleanup.InventorySummary(
                inventory.account_id,
                inventory.partition,
                inventory.caller_arn,
                inventory.items,
                details_complete=query.details,
            )

        def plan(
            self, _options: _iam_cleanup.CleanupOptions
        ) -> _iam_cleanup.CleanupPlan:
            return planned

        def execute(
            self, _plan: _iam_cleanup.CleanupPlan
        ) -> _iam_cleanup.CleanupResult:
            return cleaned

    monkeypatch.setattr(_iam_cli._iam_cleanup, "CleanupService", Service)
    context = SimpleNamespace()
    listed = _iam_cli.inventory_result(
        argparse.Namespace(
            patterns=["*Agent*"],
            roles=False,
            policies=True,
            group_grants=False,
            created=False,
            adopted=False,
            smoke=False,
            smoke_run=None,
            wide=True,
            all_account=False,
            details=True,
        ),
        context,
    )
    assert listed.code == "IAM_INVENTORY"
    assert "ANPA" not in listed.message
    assert "AgentRead" in listed.message
    assert isinstance(listed.data, dict)
    assert listed.data["detailsComplete"] is True

    dry_run = _iam_cli.cleanup_result(
        argparse.Namespace(
            patterns=["*Agent*"],
            all=False,
            roles=False,
            policies=True,
            group_grants=False,
            created=False,
            adopted=False,
            smoke=False,
            smoke_run=None,
            cascade=False,
            remove_boundaries=False,
            remove_from_instance_profiles=False,
            dry_run=True,
            yes=False,
        ),
        context,
    )
    assert dry_run.code == "IAM_CLEANUP_PLAN"
    assert dry_run.data["classification"] == "planned"

    execute_args = argparse.Namespace(
        patterns=["*Agent*"],
        all=False,
        roles=False,
        policies=True,
        group_grants=False,
        created=False,
        adopted=False,
        smoke=False,
        smoke_run=None,
        cascade=False,
        remove_boundaries=False,
        remove_from_instance_profiles=False,
        dry_run=False,
        yes=True,
    )
    applied = _iam_cli.cleanup_result(execute_args, context)
    assert applied.code == "IAM_CLEANUP_COMPLETE"
    assert applied.data["result"]["leaveNoTrace"] is True


def test_cleanup_requires_explicit_selection_and_rejects_all_with_patterns() -> None:
    base = {
        "patterns": [],
        "all": False,
        "roles": False,
        "policies": False,
        "group_grants": False,
        "created": False,
        "adopted": False,
        "smoke": False,
        "smoke_run": None,
        "cascade": False,
        "remove_boundaries": False,
        "remove_from_instance_profiles": False,
        "dry_run": True,
        "yes": False,
    }
    with pytest.raises(_configs.OperationalError, match="requires PATTERN"):
        _iam_cli.cleanup_result(argparse.Namespace(**base), SimpleNamespace())
    with pytest.raises(_configs.OperationalError, match="conflicts"):
        _iam_cli.cleanup_result(
            argparse.Namespace(**{**base, "patterns": ["*"], "all": True}),
            SimpleNamespace(),
        )


def test_cleanup_blocked_confirmation_and_partial_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = _inventory_item()
    options = _iam_cleanup.CleanupOptions(patterns=("*",), dry_run=False)
    blocker = _iam_cleanup.CleanupBlocker(item.key, "dependency", "retained role")
    blocked = _iam_cleanup.CleanupPlan(
        "123456789012",
        "aws",
        "arn:aws:iam::123456789012:user/test",
        options,
        (item,),
        (),
        (blocker,),
    )
    planned = replace(blocked, blockers=())
    partial = _iam_cleanup.CleanupResult(
        classification=_iam_cleanup.ResultClassification.PARTIAL,
        journal_id="journal",
        completed=(),
        failed=(item.key,),
        remaining=(item.key,),
        lnt=False,
    )
    selected_plan = blocked

    class Service:
        def __init__(self, _context: object) -> None:
            pass

        def plan(
            self, _options: _iam_cleanup.CleanupOptions
        ) -> _iam_cleanup.CleanupPlan:
            return selected_plan

        def execute(
            self, _plan: _iam_cleanup.CleanupPlan
        ) -> _iam_cleanup.CleanupResult:
            return partial

    monkeypatch.setattr(_iam_cli._iam_cleanup, "CleanupService", Service)
    args = argparse.Namespace(
        patterns=["*"],
        all=False,
        roles=True,
        policies=False,
        group_grants=True,
        created=True,
        adopted=True,
        smoke=False,
        smoke_run=None,
        cascade=False,
        remove_boundaries=False,
        remove_from_instance_profiles=False,
        dry_run=False,
        yes=False,
    )
    result = _iam_cli.cleanup_result(args, SimpleNamespace())
    assert result.code == "IAM_CLEANUP_PLAN"
    assert result.exit_code == 2

    selected_plan = planned
    monkeypatch.setattr(_iam_cli.os, "isatty", lambda _fd: False)
    result = _iam_cli.cleanup_result(args, SimpleNamespace())
    assert result.code == "IAM_CLEANUP_CONFIRMATION_REQUIRED"

    args.yes = True
    result = _iam_cli.cleanup_result(args, SimpleNamespace())
    assert result.code == "IAM_CLEANUP_PARTIAL"
    assert result.exit_code == 2


def test_inventory_rendering_and_central_dispatch_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = _inventory_item().as_dict()
    assert "🧪" not in _iam_cli._inventory_text([item], wide=False)
    assert _iam_cli._inventory_text([], wide=False).startswith("No matching")
    context = SimpleNamespace()
    monkeypatch.setattr(_iam_cli.IamCommandContext, "create", lambda _args: context)
    monkeypatch.setattr(
        _iam_cli,
        "inventory_result",
        lambda _args, _context, **_options: _configs.Result(
            "LISTED", "listed", data={"count": 1}
        ),
    )
    monkeypatch.setattr(
        _iam_cli,
        "cleanup_result",
        lambda _args, _context: _configs.Result("CLEANED", "cleaned"),
    )
    assert (
        _iam_cli.dispatch(argparse.Namespace(iam_action="list", progress=False)).code
        == "LISTED"
    )
    cleanup_args = argparse.Namespace(iam_action="cleanup")
    assert _iam_cli.dispatch(cleanup_args).code == "CLEANED"
    assert _iam_cli.dispatch_root_cleanup(cleanup_args).code == "CLEANED"


def test_inventory_empty_scope_warnings_and_details_rendering() -> None:
    owned_query = _iam_cleanup.InventoryQuery()
    empty = _iam_cleanup.InventorySummary(
        "123456789012",
        "aws",
        "arn:aws:iam::123456789012:user/test",
        (),
        ("Unable to validate role bad\x1b[31m.\nOmitted.",),
    )
    rendered = _iam_cli._inventory_text(
        [], wide=False, query=owned_query, summary=empty
    )
    assert "AWS account 123456789012 (aws)" in rendered
    assert "--all-account" in rendered
    assert "untagged legacy" in rendered
    assert "Warnings:" in rendered
    assert "\x1b" not in rendered
    assert "\nOmitted" not in rendered

    all_account = replace(owned_query, all_account=True, owned_only=False)
    rendered = _iam_cli._inventory_text(
        [], wide=False, query=all_account, summary=replace(empty, warnings=())
    )
    assert "Scope: all-account" in rendered
    assert "cannot be classified" not in rendered

    item = _inventory_item().as_dict()
    detailed = _iam_cli._inventory_text(
        [item],
        wide=False,
        query=replace(owned_query, details=True),
        summary=replace(empty, items=(_inventory_item(),), details_complete=True),
    )
    assert "Deps" in detailed


def test_inventory_cli_json_query_flags_and_progress_contract(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from hacksaws import _cli
    from hacksaws import _sessions

    queries: list[_iam_cleanup.InventoryQuery] = []
    item = _inventory_item()

    class Service:
        def __init__(self, _context: object) -> None:
            pass

        def inventory_summary(
            self,
            query: _iam_cleanup.InventoryQuery,
            *,
            progress: object = None,
        ) -> _iam_cleanup.InventorySummary:
            queries.append(query)
            if callable(progress):
                progress(
                    _iam_cleanup.InventoryProgress(
                        _iam_cleanup.InventoryPhase.FILTER,
                        "Filters applied:",
                        matches=1,
                    )
                )
            return _iam_cleanup.InventorySummary(
                "123456789012",
                "aws",
                "arn:aws:iam::123456789012:user/test",
                (item,),
                details_complete=query.details,
                scope="all-account" if query.all_account else "canonical",
            )

    monkeypatch.setattr(_iam_cli._iam_cleanup, "CleanupService", Service)
    monkeypatch.setattr(
        _iam_cli.IamCommandContext,
        "create",
        lambda _args: SimpleNamespace(),
    )
    monkeypatch.setattr(_sessions, "recover_journal", lambda: None)
    result = _cli.console_main(
        [
            "iam",
            "list",
            "*Agent*",
            "--roles",
            "--all-account",
            "--progress",
            "--json",
        ]
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    envelope = json.loads(captured.out)
    assert result.code == "IAM_INVENTORY"
    assert envelope["data"]["detailsComplete"] is False
    assert envelope["data"]["inventoryComplete"] is True
    assert envelope["data"]["scope"] == "all-account"
    assert "dependencies" not in envelope["data"]["items"][0]
    assert queries[0].patterns == ("*Agent*",)
    assert queries[0].resource_types == frozenset({_iam_cleanup.ResourceType.ROLE})
    assert queries[0].all_account is True
    assert queries[0].origins == frozenset()
    explicit_origin = _cli._create_parser().parse_args(
        ["iam", "list", "--all-account", "--created"]
    )
    assert _iam_cli._inventory_query(explicit_origin).origins == frozenset(
        {_iam_cleanup.OwnershipOrigin.CREATED}
    )


def test_inventory_progress_modes_help_and_interruption(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from hacksaws import _cli

    help_result = _cli.console_main(["iam", "list", "--help"])
    help_text = capsys.readouterr().out
    assert help_result.exit_code == 0
    assert "--all-account" in help_text
    assert "--details" in help_text
    assert "--progress" in help_text
    assert "--no-progress" in help_text
    with pytest.raises(SystemExit):
        _cli._create_parser().parse_args(["iam", "list", "--progress", "--no-progress"])

    monkeypatch.setattr(
        _iam_cli.IamCommandContext,
        "create",
        lambda _args: (_ for _ in ()).throw(KeyboardInterrupt),
    )
    interrupted = _iam_cli._inventory_command_result(argparse.Namespace(progress=False))
    assert interrupted.code == "IAM_INVENTORY_INTERRUPTED"
    assert interrupted.exit_code == _configs.EXIT_INTERRUPTED
    assert "No AWS resources were changed" in interrupted.message
    assert "Verifying AWS identity" in interrupted.message

    monkeypatch.setattr(
        _iam_cli.IamCommandContext,
        "create",
        lambda _args: SimpleNamespace(),
    )

    def fail_inventory(*_args: object, **_kwargs: object) -> _configs.Result:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "ListRoles",
        )

    monkeypatch.setattr(_iam_cli, "inventory_result", fail_inventory)
    with pytest.raises(_configs.OperationalError, match="Unable to inspect"):
        _iam_cli._inventory_command_result(argparse.Namespace(progress=False))


def test_inventory_reporter_lifecycle_maps_modes_and_semantic_phases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    modes: list[str] = []
    messages: list[str] = []
    exits: list[bool] = []

    class Reporter:
        message = "Working…"

        def __init__(self, _options: object, *, mode: str) -> None:
            modes.append(mode)

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_error: object) -> None:
            exits.append(True)

        def start(self, message: str) -> Reporter:
            self.message = message
            messages.append(message)
            return self

        def update(self, message: str) -> None:
            self.message = message
            messages.append(message)

    def result(
        _args: argparse.Namespace,
        _context: object,
        *,
        progress: object,
    ) -> _configs.Result:
        assert callable(progress)
        progress(
            _iam_cleanup.InventoryProgress(
                _iam_cleanup.InventoryPhase.OWNERSHIP,
                "Ownership complete:",
                inspected=2,
                owned=1,
            )
        )
        return _configs.Result("IAM_INVENTORY", "done", data={"count": 1})

    monkeypatch.setattr(_iam_cli._output, "ProgressReporter", Reporter)
    monkeypatch.setattr(
        _iam_cli.IamCommandContext, "create", lambda _args: SimpleNamespace()
    )
    monkeypatch.setattr(_iam_cli, "inventory_result", result)
    for selected in (True, False, None):
        assert (
            _iam_cli._inventory_command_result(
                argparse.Namespace(progress=selected)
            ).code
            == "IAM_INVENTORY"
        )
    assert modes == ["always", "never", "auto"]
    assert len(exits) == 3
    assert messages.count("Verifying AWS identity…") == 3
    assert messages.count("Ownership complete: 2 inspected, 1 owned") == 3
    assert messages.count("Rendering 1 resources…") == 3


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        (
            _iam_cleanup.InventoryProgress(
                _iam_cleanup.InventoryPhase.DISCOVERY,
                "Discovery complete:",
                candidates=1,
            ),
            "Discovery complete: 1 candidate",
        ),
        (
            _iam_cleanup.InventoryProgress(
                _iam_cleanup.InventoryPhase.OWNERSHIP,
                "Validating ownership:",
                completed=0,
                total=1,
            ),
            "Validating ownership: 0/1",
        ),
        (
            _iam_cleanup.InventoryProgress(
                _iam_cleanup.InventoryPhase.OWNERSHIP,
                "Ownership complete:",
                inspected=1,
                owned=0,
            ),
            "Ownership complete: 1 inspected, 0 owned",
        ),
        (
            _iam_cleanup.InventoryProgress(
                _iam_cleanup.InventoryPhase.FILTER,
                "Filters applied:",
                matches=0,
            ),
            "Filters applied: 0 matches",
        ),
    ],
)
def test_inventory_progress_text_uses_phase_specific_counts(
    event: _iam_cleanup.InventoryProgress, expected: str
) -> None:
    assert _iam_cli._inventory_progress_text(event) == expected


def test_iam_adapter_registration_rejects_duplicate_names() -> None:
    class Adapter:
        name = "test-adapter"

        def register(self, _parser: argparse.ArgumentParser) -> None:
            pass

        def dispatch(
            self, _args: argparse.Namespace, _context: _iam_cli.IamCommandContext
        ) -> _configs.Result | None:
            return None

    adapter = Adapter()
    _iam_cli.clear_adapters()
    try:
        _iam_cli.register_adapter(adapter)
        with pytest.raises(ValueError, match="test-adapter"):
            _iam_cli.register_adapter(adapter)
    finally:
        _iam_cli.clear_adapters()


def test_recovery_get_and_empty_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _account_config(tmp_path, monkeypatch)
    monkeypatch.delenv("AWS_CONFIG_FILE", raising=False)
    monkeypatch.delenv("AWS_SHARED_CREDENTIALS_FILE", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with _iam_cli.credential_environment(tmp_path / "config", tmp_path / "credentials"):
        assert os.environ["AWS_CONFIG_FILE"].endswith("config")
    assert "AWS_CONFIG_FILE" not in os.environ
    _iam_recovery.clear_handlers()
    _iam_recovery.register_handler(
        "policy",
        "create",
        forward=lambda _payload, _context: None,
        compensate=lambda _payload, _context: None,
    )
    journal = _iam_recovery.begin_journal(
        "policy", "123456789012", "create-policy", journal_id="recoverable"
    )
    get = _iam_cli.recovery_result(
        argparse.Namespace(recovery_action="get", journal_id=journal.id)
    )
    assert json.loads(get.message)["status"] == "active"


def test_credential_environment_restores_every_provider_variable_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = {
        key: f"before-{index}"
        for index, key in enumerate(_iam_cli._CREDENTIAL_ENVIRONMENT_KEYS)
    }
    for key, value in before.items():
        monkeypatch.setenv(key, value)
    config = tmp_path / "selected-config"
    credentials = tmp_path / "selected-credentials"
    with _iam_cli.credential_environment(config, credentials):
        assert os.environ["AWS_CONFIG_FILE"] == str(config)
        assert os.environ["AWS_SHARED_CREDENTIALS_FILE"] == str(credentials)
        assert os.environ["AWS_EC2_METADATA_DISABLED"] == "true"
        for key in _iam_cli._CREDENTIAL_ENVIRONMENT_KEYS[2:]:
            if key != "AWS_EC2_METADATA_DISABLED":
                assert key not in os.environ
    assert {
        key: os.environ.get(key) for key in _iam_cli._CREDENTIAL_ENVIRONMENT_KEYS
    } == before


def test_real_botocore_clients_ignore_all_ambient_endpoint_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "selected-endpoints"
    selected.mkdir()
    selected.joinpath("config").write_text(
        "[profile deploy]\nregion = us-west-2\n", encoding="utf-8"
    )
    selected.joinpath("credentials").write_text(
        "[deploy]\naws_access_key_id = SELECTEDACCESS\n"
        "aws_secret_access_key = selected-secret\n",
        encoding="utf-8",
    )
    endpoint_keys = [
        key
        for key in _iam_cli._CREDENTIAL_ENVIRONMENT_KEYS
        if key.startswith("AWS_ENDPOINT_URL")
    ]
    for key in endpoint_keys:
        monkeypatch.setenv(key, "https://attacker.invalid")

    with _iam_cli.credential_environment(selected / "config", selected / "credentials"):
        session = boto3.Session(profile_name="deploy")
        endpoints = {
            name: session.client(name).meta.endpoint_url
            for name in ("sts", "iam", "accessanalyzer")
        }

    assert all("attacker.invalid" not in endpoint for endpoint in endpoints.values())
    assert all(os.environ[key] == "https://attacker.invalid" for key in endpoint_keys)


@pytest.mark.parametrize("ambient_has_profile", [True, False])
def test_real_boto3_provider_freezes_only_selected_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ambient_has_profile: bool,
) -> None:
    """Ambient same-profile credentials cannot replace the explicitly selected file."""
    _account_config(tmp_path, monkeypatch)
    selected = tmp_path / "selected"
    ambient = tmp_path / "ambient"
    selected.mkdir()
    ambient.mkdir()
    selected.joinpath("config").write_text(
        "[profile deploy]\nregion = us-west-2\n", encoding="utf-8"
    )
    selected.joinpath("credentials").write_text(
        "[deploy]\naws_access_key_id = SELECTEDACCESS\n"
        "aws_secret_access_key = selected-secret\n",
        encoding="utf-8",
    )
    ambient.joinpath("config").write_text(
        "[profile deploy]\nregion = us-east-1\n" if ambient_has_profile else "",
        encoding="utf-8",
    )
    ambient.joinpath("credentials").write_text(
        "[deploy]\naws_access_key_id = AMBIENTACCESS\n"
        "aws_secret_access_key = ambient-secret\n"
        if ambient_has_profile
        else "",
        encoding="utf-8",
    )
    monkeypatch.setenv("AWS_CONFIG_FILE", str(ambient / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(ambient / "credentials"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ENVACCESS")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
    endpoint_keys = [
        key
        for key in _iam_cli._CREDENTIAL_ENVIRONMENT_KEYS
        if key.startswith("AWS_ENDPOINT_URL")
    ]
    for key in endpoint_keys:
        monkeypatch.setenv(key, "https://attacker.invalid")
    explicit_calls: list[dict[str, object]] = []

    class ObservingClient(_Client):
        def __init__(self) -> None:
            super().__init__()
            self.endpoint_override = next(
                (os.environ.get(key) for key in endpoint_keys if os.environ.get(key)),
                None,
            )
            assert self.endpoint_override is None

        def get_caller_identity(self) -> dict[str, str]:
            assert os.environ["AWS_CONFIG_FILE"] == str(selected / "config")
            assert "AWS_ACCESS_KEY_ID" not in os.environ
            return super().get_caller_identity()

        def mutation(self) -> None:
            assert self.endpoint_override is None

    class ObservingSession(_Session):
        def client(self, name: str) -> _Client:
            assert os.environ["AWS_CONFIG_FILE"] == str(selected / "config")
            return ObservingClient()

    def factory(**kwargs: object) -> object:
        if "profile_name" in kwargs:
            return boto3.Session(
                profile_name=str(kwargs["profile_name"]),
                region_name=(
                    str(kwargs["region_name"])
                    if kwargs.get("region_name") is not None
                    else None
                ),
            )
        explicit_calls.append(kwargs)
        assert os.environ["AWS_CONFIG_FILE"] == str(selected / "config")
        assert "AWS_ACCESS_KEY_ID" not in os.environ
        return ObservingSession()

    context = _iam_cli.IamCommandContext.create(
        argparse.Namespace(
            profile="deploy",
            location="default",
            directory=str(selected),
            target=None,
            account="Prod",
            region=None,
        ),
        session_factory=factory,
    )
    assert context.account_id == "123456789012"
    assert explicit_calls[0]["aws_access_key_id"] == "SELECTEDACCESS"
    assert explicit_calls[0]["aws_secret_access_key"] == "selected-secret"  # noqa: S105
    assert explicit_calls[0]["region_name"] == "us-west-2"
    assert os.environ["AWS_CONFIG_FILE"] == str(ambient / "config")
    assert os.environ["AWS_ACCESS_KEY_ID"] == "ENVACCESS"
    context.iam.mutation()
    assert all(os.environ[key] == "https://attacker.invalid" for key in endpoint_keys)


def test_context_reports_missing_credentials_and_invalid_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _account_config(tmp_path, monkeypatch)

    class MissingSession:
        region_name = None

        def get_credentials(self) -> None:
            return None

    args = argparse.Namespace(
        profile="missing",
        location="default",
        directory=str(tmp_path / "selected"),
        target=None,
        account=None,
        region=None,
    )
    with pytest.raises(_configs.OperationalError, match="has no credentials"):
        _iam_cli.IamCommandContext.create(
            args, session_factory=lambda **_kwargs: MissingSession()
        )

    class InvalidClient(_Client):
        def get_caller_identity(self) -> dict[str, str]:
            return {"Account": "invalid", "Arn": "also-invalid"}

    class InvalidSession(_Session):
        def client(self, name: str) -> _Client:
            return InvalidClient() if name == "sts" else _Client()

    with pytest.raises(_configs.OperationalError, match="GetCallerIdentity"):
        _iam_cli.IamCommandContext.create(
            args, session_factory=lambda **_kwargs: InvalidSession()
        )


def test_target_source_and_recovery_executor_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _account_config(tmp_path, monkeypatch)
    data = _state.load_config()
    data["targets"]["Ops"] = {
        "source_account": "Prod",
        "source_profile": "operator",
        "source_directory": str(tmp_path / "target-aws"),
        "destination_location": "default",
        "destination_profile": "default",
        "boundary": None,
    }
    _state.save_config(data)
    selector = _configs.CredentialSelector(target="+Ops")
    directory, profile, account = _iam_cli._selected_source(
        selector, argparse.Namespace(account=None)
    )
    assert directory == (tmp_path / "target-aws").absolute()
    assert profile == "operator"
    assert account is not None
    assert account["id"] == "123456789012"

    context = SimpleNamespace(account_id="123456789012")
    monkeypatch.setattr(_iam_cli.IamCommandContext, "create", lambda _args: context)
    monkeypatch.setattr(
        _iam_recovery,
        "get_journal",
        lambda journal_id: {"id": journal_id, "serviceType": "role"},
    )
    monkeypatch.setattr(
        _iam_recovery,
        "continue_journal",
        lambda journal_id, received: {
            "id": journal_id,
            "contextMatches": received is context,
        },
    )
    monkeypatch.setattr(
        _iam_recovery,
        "rollback_journal",
        lambda journal_id, received: {
            "id": journal_id,
            "contextMatches": received is context,
        },
    )
    common = {
        "journal_id": "journal",
        "profile": "default",
        "location": "default",
        "directory": None,
        "target": None,
        "account": None,
        "region": None,
    }
    continued = _iam_cli.recovery_result(
        argparse.Namespace(recovery_action="continue", **common)
    )
    rolled_back = _iam_cli.recovery_result(
        argparse.Namespace(recovery_action="rollback", **common)
    )
    assert continued.data == {"id": "journal", "contextMatches": True}
    assert rolled_back.data == {"id": "journal", "contextMatches": True}


def test_dispatch_handles_missing_and_declining_adapters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = argparse.Namespace(iam_action="policy", policy_action="list")
    _iam_cli.clear_adapters()
    assert _iam_cli.dispatch(args).code == "IAM_LEAF_HELP"

    class DecliningAdapter:
        name = "policy"

        def register(self, _parser: argparse.ArgumentParser) -> None:
            pass

        def dispatch(
            self, _args: argparse.Namespace, _context: object
        ) -> _configs.Result | None:
            return None

    _iam_cli.register_adapter(DecliningAdapter())
    monkeypatch.setattr(
        _iam_cli.IamCommandContext,
        "create",
        lambda _args: SimpleNamespace(account_id="123456789012"),
    )
    assert _iam_cli.dispatch(args).code == "IAM_LEAF_HELP"


def test_selector_validation_covers_local_account_and_config_commands() -> None:
    with pytest.raises(_configs.OperationalError, match="cannot be combined"):
        _iam_cli.validate_selector_arguments(
            [
                "account",
                "add",
                "Prod",
                "123456789012",
                "--target",
                "prod",
                "--profile",
                "admin",
            ]
        )
    with pytest.raises(_configs.OperationalError, match="same AWS folder"):
        _iam_cli.validate_selector_arguments(
            [
                "config",
                "check",
                "--location",
                "horizon",
                "--directory",
                "C:/aws",
            ]
        )


def test_cleanup_account_mismatch_is_safety_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_args: argparse.Namespace) -> None:
        message = (
            "Selected IAM credentials identify aws:111111111111, but the selected "
            "account requires aws:222222222222."
        )
        raise _configs.OperationalError(message)

    monkeypatch.setattr(_iam_cli.IamCommandContext, "create", fail)

    result = _iam_cli.dispatch_root_cleanup(argparse.Namespace())

    assert result.code == "IAM_CLEANUP_SAFETY_REFUSAL"
    assert result.exit_code == 3
