"""Security and crash-safety contracts for shared IAM recovery."""

# Tests intentionally simulate failures, prompts, and secret-shaped field rejection.
# ruff: noqa: SIM117, T201, TRY003

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest

from hacksaws import _cli
from hacksaws import _configs
from hacksaws import _iam_cli
from hacksaws import _iam_policy_cli
from hacksaws import _iam_recovery
from hacksaws import _sessions


@pytest.fixture(autouse=True)
def isolated_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    _configs.configure_output()
    _iam_recovery.clear_handlers()
    yield
    _configs.configure_output()


def _context(account: str = "123456789012") -> SimpleNamespace:
    return SimpleNamespace(account_id=account, partition="aws")


def _handler(
    calls: list[tuple[str, object]],
    *,
    fail_forward: list[bool] | None = None,
    fail_compensation: list[bool] | None = None,
) -> None:
    def forward(payload: object, _context: object) -> None:
        calls.append(("forward", payload))
        if fail_forward and fail_forward.pop(0):
            raise RuntimeError("simulated forward crash")

    def compensate(payload: object, _context: object) -> None:
        calls.append(("compensate", payload))
        if fail_compensation and fail_compensation.pop(0):
            raise RuntimeError("simulated compensation crash")

    _iam_recovery.register_handler(
        "policy", "mutation", forward=forward, compensate=compensate
    )


def test_journal_schema_lifecycle_and_credential_rejection() -> None:
    calls: list[tuple[str, object]] = []
    _handler(calls)
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "publish", journal_id="operation-1"
    )
    step = handle.record_before_mutation(
        "mutation",
        forward={"policyArn": "arn:aws:iam::123456789012:policy/Test"},
        compensation={"deleteVersion": "v2"},
    )
    journal = _iam_recovery.get_journal(handle.id)
    assert journal["schemaVersion"] == 1
    assert journal["serviceType"] == "policy"
    assert journal["accountId"] == "123456789012"
    assert journal["steps"][0]["status"] == "pending"
    with pytest.raises(_configs.OperationalError, match="pending steps"):
        handle.finish()
    handle.mark_completed(step)
    handle.finish()
    assert _iam_recovery.get_journal(handle.id)["status"] == "completed"
    with pytest.raises(_configs.OperationalError, match="credential field"):
        _iam_recovery.begin_journal(
            "policy", "123456789012", "unsafe", journal_id="unsafe"
        ).record_before_mutation(
            "mutation",
            forward={"aws_secret_access_key": "never-write-this"},
            compensation={},
        )
    persisted = _iam_recovery._journal_path(handle.id).read_text(encoding="utf-8")
    assert "selected-secret" not in persisted


def test_continue_resumes_only_pending_steps_after_crash() -> None:
    calls: list[tuple[str, object]] = []
    _handler(calls)
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "update", journal_id="resume"
    )
    completed = handle.record_before_mutation(
        "mutation", forward={"number": 1}, compensation={"number": 1}
    )
    handle.mark_completed(completed)
    pending = handle.record_before_mutation(
        "mutation", forward={"number": 2}, compensation={"number": 2}
    )

    recovered = _iam_recovery.continue_journal(handle.id, _context())

    assert calls == [("forward", {"number": 2})]
    assert recovered["status"] == "completed"
    assert (
        next(step for step in recovered["steps"] if step["id"] == pending)["status"]
        == "completed"
    )


def test_forward_failure_is_durable_and_retryable() -> None:
    calls: list[tuple[str, object]] = []
    _handler(calls, fail_forward=[True, False])
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "retry", journal_id="forward-failure"
    )
    handle.record_before_mutation(
        "mutation", forward={"attempt": 1}, compensation={"undo": 1}
    )
    with pytest.raises(_configs.OperationalError, match="forward step"):
        _iam_recovery.continue_journal(handle.id, _context())
    failed = _iam_recovery.get_journal(handle.id)
    assert failed["status"] == "failed"
    assert failed["steps"][0]["status"] == "pending"
    assert failed["failure"]["type"] == "RuntimeError"
    recovered = _iam_recovery.continue_journal(handle.id, _context())
    assert recovered["status"] == "completed"
    assert len(calls) == 2


def test_rollback_compensates_completed_steps_in_reverse_and_can_resume() -> None:
    calls: list[tuple[str, object]] = []
    _handler(calls, fail_compensation=[True, False])
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "rollback", journal_id="rollback"
    )
    first = handle.record_before_mutation(
        "mutation", forward={"number": 1}, compensation={"number": 1}
    )
    handle.mark_completed(first)
    second = handle.record_before_mutation(
        "mutation", forward={"number": 2}, compensation={"number": 2}
    )
    handle.mark_completed(second)
    handle.record_before_mutation(
        "mutation", forward={"number": 3}, compensation={"number": 3}
    )
    with pytest.raises(_configs.OperationalError, match="compensation step"):
        _iam_recovery.rollback_journal(handle.id, _context())
    assert _iam_recovery.get_journal(handle.id)["status"] == "failed"

    recovered = _iam_recovery.rollback_journal(handle.id, _context())

    assert calls == [
        ("compensate", {"number": 3}),
        ("compensate", {"number": 3}),
        ("compensate", {"number": 2}),
        ("compensate", {"number": 1}),
    ]
    assert recovered["status"] == "rolled_back"
    assert [step["status"] for step in recovered["steps"]] == [
        "rolled_back",
        "rolled_back",
        "rolled_back",
    ]


def test_rollback_compensates_crash_after_aws_before_mark_and_noop() -> None:
    resources: set[str] = set()
    calls: list[str] = []

    def compensate(payload: Mapping[str, object], _context: object) -> None:
        name = str(payload["name"])
        calls.append(name)
        resources.discard(name)

    _iam_recovery.register_handler(
        "policy",
        "delete-if-present",
        forward=lambda _payload, _context: None,
        compensate=compensate,
    )
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "ambiguous-crash", journal_id="ambiguous"
    )
    handle.record_before_mutation(
        "delete-if-present",
        forward={"name": "never-created"},
        compensation={"name": "never-created"},
    )
    handle.record_before_mutation(
        "delete-if-present",
        forward={"name": "aws-applied"},
        compensation={"name": "aws-applied"},
    )
    # Simulate AWS success followed by a process crash before mark_completed().
    resources.add("aws-applied")

    recovered = _iam_recovery.rollback_journal(handle.id, _context())

    assert calls == ["aws-applied", "never-created"]
    assert resources == set()
    assert recovered["status"] == "rolled_back"
    assert [step["status"] for step in recovered["steps"]] == [
        "rolled_back",
        "rolled_back",
    ]


def test_account_binding_whitelist_and_corrupt_diagnostics() -> None:
    calls: list[tuple[str, object]] = []
    _handler(calls)
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "bound", journal_id="bound"
    )
    handle.record_before_mutation(
        "mutation", forward={"safe": True}, compensation={"safe": True}
    )
    with pytest.raises(_configs.OperationalError, match="do not match") as mismatch:
        _iam_recovery.continue_journal(handle.id, _context("999999999999"))
    assert mismatch.value.details == {
        "journalAccountId": "123456789012",
        "callerAccountId": "999999999999",
    }
    _iam_recovery.clear_handlers()
    with pytest.raises(_configs.OperationalError, match="No whitelisted"):
        _iam_recovery.continue_journal(handle.id, _context())

    corrupt = _iam_recovery.recovery_root() / "corrupt.json"
    corrupt.write_text("{not-json", encoding="utf-8")
    listed = _iam_recovery.list_journals()
    assert (
        next(item for item in listed if item["id"] == "corrupt")["status"] == "corrupt"
    )
    with pytest.raises(_configs.OperationalError, match="Unable to read") as error:
        _iam_recovery.get_journal("corrupt")
    assert error.value.repairs


@pytest.mark.parametrize("operation", ["continue", "rollback"])
def test_generic_recovery_requires_exact_recorded_partition(operation: str) -> None:
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "partition-bound", journal_id=f"bound-{operation}"
    )
    assert _iam_recovery.get_journal(handle.id)["partition"] == "aws"
    action = (
        _iam_recovery.continue_journal
        if operation == "continue"
        else _iam_recovery.rollback_journal
    )
    with pytest.raises(
        _configs.OperationalError, match="journal partition"
    ) as mismatch:
        action(
            handle.id,
            SimpleNamespace(account_id="123456789012", partition="aws-cn"),
        )
    assert mismatch.value.details == {
        "journalPartition": "aws",
        "callerPartition": "aws-cn",
    }

    path = _iam_recovery._journal_path(handle.id)
    journal = json.loads(path.read_text(encoding="utf-8"))
    journal.pop("partition")
    path.write_text(json.dumps(journal), encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="no recorded AWS partition"):
        action(handle.id, _context())


def test_lock_prevents_concurrent_journal_transition() -> None:
    calls: list[tuple[str, object]] = []
    _handler(calls)
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "locked", journal_id="locked"
    )
    with _iam_recovery._locked(handle.id):
        with pytest.raises(_configs.OperationalError, match="busy"):
            with _iam_recovery._locked(handle.id, timeout=0):
                pass


def test_json_mode_is_noninteractive_single_envelope_and_preserves_details(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    legacy_called = False

    def legacy_recovery() -> None:
        nonlocal legacy_called
        legacy_called = True

    def noisy_dispatch(_args: argparse.Namespace) -> _configs.Result:
        print("incidental stdout")
        print("incidental stderr", file=sys.stderr)
        input("must never reach the terminal: ")
        raise _configs.OperationalError(
            "structured failure",
            data={"journalId": "x"},
            details={"step": "create"},
            repairs=["retry with --yes"],
        )

    monkeypatch.setattr(_sessions, "recover_journal", legacy_recovery)
    monkeypatch.setattr(_iam_cli, "dispatch", noisy_dispatch)
    result = _cli.console_main(["iam", "recovery", "list", "--json"])
    captured = capsys.readouterr()
    assert result.code == "OPERATIONAL_ERROR"
    assert captured.out == ""
    envelope = json.loads(captured.err)
    assert envelope["error"] == {
        "message": "Error: structured failure",
        "exitCode": 1,
        "data": {"journalId": "x"},
        "details": {"step": "create"},
        "repairs": ["retry with --yes"],
    }
    assert not legacy_called


def test_cli_recovery_requires_identifier_with_structured_repair(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = _cli.console_main(["iam", "recovery", "get", "--json"])
    envelope = json.loads(capsys.readouterr().err)
    assert result.exit_code == _configs.EXIT_ERROR
    assert envelope["error"]["repairs"] == [
        "Run 'hacksaws iam recovery list' to find journal IDs."
    ]


def test_payload_registration_and_begin_validation_edges() -> None:
    assert _iam_recovery._safe_payload([1, (True, None)]) == [1, [True, None]]
    with pytest.raises(_configs.OperationalError, match="keys must be text"):
        _iam_recovery._safe_payload({1: "bad"})
    with pytest.raises(_configs.OperationalError, match="only JSON values"):
        _iam_recovery._safe_payload(object())
    with pytest.raises(_configs.OperationalError, match="Invalid IAM recovery journal"):
        _iam_recovery.get_journal("../escape")
    with pytest.raises(ValueError, match="portable IDs"):
        _iam_recovery.register_handler(
            "bad service",
            "handler",
            forward=lambda _p, _c: None,
            compensate=lambda _p, _c: None,
        )
    calls: list[tuple[str, object]] = []
    _handler(calls)
    with pytest.raises(ValueError, match="already registered"):
        _handler(calls)
    with pytest.raises(_configs.OperationalError, match="service type"):
        _iam_recovery.begin_journal("bad service", "123456789012", "bad")
    with pytest.raises(_configs.OperationalError, match="account ID"):
        _iam_recovery.begin_journal("policy", "not-account", "bad")
    generated = _iam_recovery.begin_journal("policy", "123456789012", "generated")
    assert len(generated.id) == 32
    with pytest.raises(_configs.OperationalError, match="already exists"):
        _iam_recovery.begin_journal(
            "policy", "123456789012", "duplicate", journal_id=generated.id
        )
    with pytest.raises(_configs.OperationalError, match="was not found"):
        _iam_recovery.get_journal("missing")


def test_schema_validation_diagnostics_cover_each_corrupt_shape() -> None:
    calls: list[tuple[str, object]] = []
    _handler(calls)
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "schema", journal_id="schema"
    )
    path = _iam_recovery._journal_path(handle.id)
    valid = _iam_recovery.get_journal(handle.id)
    variants: list[tuple[object, str]] = [
        ({}, "invalid schema"),
        ({**valid, "schemaVersion": 99}, "unsupported schema"),
        ({**valid, "status": "unknown"}, "invalid status or steps"),
        ({**valid, "steps": [{}]}, "invalid step"),
        (
            {
                **valid,
                "steps": [
                    {
                        "id": "x",
                        "handler": "mutation",
                        "status": "unknown",
                        "forward": {},
                        "compensation": {},
                    }
                ],
            },
            "invalid step status",
        ),
    ]
    for document, message in variants:
        path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(_configs.OperationalError, match=message):
            _iam_recovery.get_journal(handle.id)
    path.write_text(json.dumps(valid), encoding="utf-8")


def test_manual_failure_illegal_transitions_and_stale_lock() -> None:
    calls: list[tuple[str, object]] = []
    _handler(calls)
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "manual", journal_id="manual"
    )
    step = handle.record_before_mutation(
        "mutation", forward={"step": 1}, compensation={"step": 1}
    )
    handle.mark_failure(RuntimeError("manual crash"), step_id=step)
    failed = _iam_recovery.get_journal(handle.id)
    assert failed["status"] == "failed"
    assert failed["steps"][0]["failure"]["type"] == "RuntimeError"
    with pytest.raises(_configs.OperationalError, match="was not found"):
        handle.mark_completed("missing-step")
    handle.mark_completed(step)
    handle.finish()
    with pytest.raises(_configs.OperationalError, match="Cannot append"):
        handle.record_before_mutation(
            "mutation", forward={"late": True}, compensation={}
        )

    other = _iam_recovery.begin_journal(
        "policy", "123456789012", "unregistered", journal_id="unregistered"
    )
    with pytest.raises(_configs.OperationalError, match="not registered"):
        other.record_before_mutation("missing", forward={}, compensation={})

    lock_path = _iam_recovery.recovery_root() / ".locks" / "stale.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("not-a-pid\n", encoding="ascii")
    with _iam_recovery._locked("stale", timeout=0):
        assert lock_path.exists()
    assert not lock_path.exists()


def test_marking_rolled_back_step_completed_is_rejected() -> None:
    calls: list[tuple[str, object]] = []
    _handler(calls)
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "rolled", journal_id="rolled"
    )
    step = handle.record_before_mutation(
        "mutation", forward={"step": 1}, compensation={"step": 1}
    )
    handle.mark_completed(step)
    _iam_recovery.rollback_journal(handle.id, _context())
    with pytest.raises(_configs.OperationalError, match="is rolled back"):
        handle.mark_completed(step)
    with pytest.raises(_configs.OperationalError, match="do not match"):
        _iam_recovery.rollback_journal(handle.id, _context("999999999999"))


def test_central_recovery_registers_policy_handler_after_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _iam_policy_cli.ensure_recovery_handlers()
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "restart", journal_id="policy-restart"
    )
    handle.record_before_mutation(
        "reconcile",
        forward={"state": "forward"},
        compensation={"state": "before"},
    )
    _iam_recovery.clear_handlers()
    calls: list[object] = []
    monkeypatch.setattr(
        _iam_policy_cli,
        "_reconcile_policy",
        lambda payload, _context: calls.append(payload),
    )
    monkeypatch.setattr(_iam_cli.IamCommandContext, "create", lambda _args: _context())

    result = _iam_cli.recovery_result(
        argparse.Namespace(
            recovery_action="continue",
            journal_id=handle.id,
        )
    )

    assert result.code == "IAM_RECOVERY_CONTINUE"
    assert calls == [{"state": "forward"}]
    assert isinstance(result.data, dict)
    assert result.data["status"] == "completed"


def test_invalid_journal_id_cannot_touch_escape_target() -> None:
    directory = _iam_recovery.recovery_root()
    directory.mkdir(parents=True)
    victim = directory / "victim.lock"
    victim.write_text("not-a-pid\n", encoding="ascii")
    before = victim.read_bytes()

    for action in (
        lambda: _iam_recovery.get_journal("../victim"),
        lambda: _iam_recovery.begin_journal(
            "policy", "123456789012", "escape", journal_id="../victim"
        ),
    ):
        with pytest.raises(_configs.OperationalError, match="Invalid IAM recovery"):
            action()

    assert victim.read_bytes() == before
    assert not (directory / ".locks").exists()
    assert sorted(path.name for path in directory.iterdir()) == ["victim.lock"]


def test_embedded_journal_id_mismatch_is_rejected_before_execution() -> None:
    calls: list[tuple[str, object]] = []
    _handler(calls)
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "identity", journal_id="requested"
    )
    handle.record_before_mutation(
        "mutation", forward={"safe": True}, compensation={"safe": True}
    )
    path = _iam_recovery._journal_path(handle.id)
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["id"] = "different"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    before = path.read_bytes()

    with pytest.raises(_configs.OperationalError, match="does not match its filename"):
        _iam_recovery.continue_journal(handle.id, _context())

    assert calls == []
    assert path.read_bytes() == before
    assert not _iam_recovery._journal_path("different").exists()


@pytest.mark.parametrize("journal_status", ["rolling_back", "rolled_back"])
def test_continue_rejects_journals_that_entered_rollback(
    journal_status: str,
) -> None:
    calls: list[tuple[str, object]] = []
    _handler(calls)
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "state", journal_id=f"state-{journal_status}"
    )
    handle.record_before_mutation(
        "mutation", forward={"step": 1}, compensation={"step": 1}
    )
    path = _iam_recovery._journal_path(handle.id)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["status"] = journal_status
    path.write_text(json.dumps(document), encoding="utf-8")
    before = path.read_bytes()

    with pytest.raises(_configs.OperationalError, match="entered rollback"):
        _iam_recovery.continue_journal(handle.id, _context())

    assert calls == []
    assert path.read_bytes() == before


def test_continue_rejects_rolled_back_step_mixture_and_completed_pending() -> None:
    calls: list[tuple[str, object]] = []
    _handler(calls)
    handle = _iam_recovery.begin_journal(
        "policy", "123456789012", "mixture", journal_id="mixture"
    )
    handle.record_before_mutation(
        "mutation", forward={"step": 1}, compensation={"step": 1}
    )
    handle.record_before_mutation(
        "mutation", forward={"step": 2}, compensation={"step": 2}
    )
    path = _iam_recovery._journal_path(handle.id)
    mixture = json.loads(path.read_text(encoding="utf-8"))
    mixture["status"] = "failed"
    mixture["steps"][0]["status"] = "rolled_back"
    path.write_text(json.dumps(mixture), encoding="utf-8")
    before = path.read_bytes()
    with pytest.raises(_configs.OperationalError, match="entered rollback"):
        _iam_recovery.continue_journal(handle.id, _context())
    assert calls == []
    assert path.read_bytes() == before

    mixture["status"] = "completed"
    mixture["steps"][0]["status"] = "completed"
    path.write_text(json.dumps(mixture), encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="contains pending steps"):
        _iam_recovery.continue_journal(handle.id, _context())
    assert calls == []
