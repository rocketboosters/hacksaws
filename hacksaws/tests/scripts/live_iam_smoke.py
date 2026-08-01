"""Explicitly opt-in lifecycle smoke test for a disposable AWS IAM account.

This module is not collected by pytest and must never be added to ordinary CI.
It refuses to call AWS unless the destructive opt-in, exact account guard, and
saved credential target are all supplied.
"""

# ruff: noqa: TRY003

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import uuid
from collections.abc import Callable
from pathlib import Path

from botocore.exceptions import ClientError

from hacksaws import _cli
from hacksaws import _iam_cli

IAM_PATH = "/hacksaws-test/"
OPT_IN = "HACKSAWS_LIVE_AWS"
ACCOUNT = "HACKSAWS_LIVE_AWS_ACCOUNT_ID"
CLEANUP = "HACKSAWS_LIVE_AWS_CLEANUP"
TARGET = "HACKSAWS_LIVE_AWS_TARGET"


def _run(arguments: list[str]) -> None:
    result = _cli.console_main(arguments)
    if result.exit_code:
        raise RuntimeError(
            f"Live IAM smoke command failed ({result.code}): "
            f"hacksaws {' '.join(arguments)}"
        )


def _selectors(expected: str, target: str) -> list[str]:
    return ["--target", target, "--account", expected]


def _absent(call: Callable[..., object], **kwargs: str) -> bool:
    try:
        call(**kwargs)
    except ClientError as error:
        return error.response.get("Error", {}).get("Code") == "NoSuchEntity"
    return False


def main() -> int:
    """Create, exercise, clean, and verify one uniquely tagged IAM fixture set."""
    expected = os.environ.get(ACCOUNT, "")
    target = os.environ.get(TARGET, "")
    if (
        os.environ.get(OPT_IN) != "1"
        or os.environ.get(CLEANUP) != "1"
        or not expected
        or not target
    ):
        raise SystemExit(
            "Refusing live AWS smoke test; set "
            f"{OPT_IN}=1, {CLEANUP}=1, {ACCOUNT}=12-digit-account-id, and "
            f"{TARGET}=saved-target."
        )
    if not expected.isdigit() or len(expected) != 12:
        raise SystemExit(f"{ACCOUNT} must be a 12-digit AWS account ID.")

    selector_args = _selectors(expected, target)
    context = _iam_cli.IamCommandContext.create(
        argparse.Namespace(
            profile="default",
            location="default",
            directory=None,
            target=target,
            account=expected,
            region=None,
        )
    )
    if context.account_id != expected:
        raise SystemExit(
            f"Refusing account {context.account_id}; expected guarded account "
            f"{expected}."
        )

    run_id = uuid.uuid4().hex
    role_name = f"HacksawsSmokeRole{run_id[:12]}"
    policy_name = f"HacksawsSmokePolicy{run_id[:12]}"
    policy_arn = (
        f"arn:{context.partition}:iam::{expected}:policy{IAM_PATH}{policy_name}"
    )
    smoke_tags = [
        {"Key": "hacksaws:smoke", "Value": "true"},
        {"Key": "hacksaws:run-id", "Value": run_id},
    ]
    cleaned = False

    with tempfile.TemporaryDirectory(prefix="hacksaws-live-smoke-") as temporary:
        directory = Path(temporary)
        policy_file = directory / "managed-policy.json"
        updated_policy_file = directory / "managed-policy-updated.json"
        inline_file = directory / "inline-policy.json"
        base_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:GetCallerIdentity",
                    "Resource": "*",
                }
            ],
        }
        updated_document = {
            **base_document,
            "Statement": [
                *base_document["Statement"],
                {
                    "Effect": "Allow",
                    "Action": "iam:GetRole",
                    "Resource": (
                        f"arn:{context.partition}:iam::{expected}:"
                        f"role{IAM_PATH}{role_name}"
                    ),
                },
            ],
        }
        policy_file.write_text(json.dumps(base_document), encoding="utf-8")
        updated_policy_file.write_text(json.dumps(updated_document), encoding="utf-8")
        inline_file.write_text(json.dumps(base_document), encoding="utf-8")

        try:
            _run(
                [
                    "iam",
                    "role",
                    "create",
                    role_name,
                    "--path",
                    IAM_PATH,
                    "--trust-caller",
                    *selector_args,
                    "--yes",
                ]
            )
            context.iam.tag_role(RoleName=role_name, Tags=smoke_tags)
            _run(
                [
                    "iam",
                    "policy",
                    "create",
                    str(policy_file),
                    policy_name,
                    "--path",
                    IAM_PATH,
                    "--local-validation-only",
                    *selector_args,
                    "--yes",
                ]
            )
            context.iam.tag_policy(PolicyArn=policy_arn, Tags=smoke_tags)
            _run(
                [
                    "iam",
                    "role",
                    "attach",
                    role_name,
                    policy_arn,
                    *selector_args,
                    "--yes",
                ]
            )
            _run(
                [
                    "iam",
                    "role",
                    "inline-policy",
                    "put",
                    role_name,
                    "SmokeInline",
                    str(inline_file),
                    *selector_args,
                    "--yes",
                ]
            )
            _run(
                [
                    "iam",
                    "policy",
                    "update",
                    policy_name,
                    str(updated_policy_file),
                    "--local-validation-only",
                    *selector_args,
                    "--yes",
                ]
            )
            cleanup_args = [
                "cleanup",
                "--smoke-run",
                run_id,
                "--cascade",
                *selector_args,
            ]
            _run([*cleanup_args, "--dry-run"])
            _run([*cleanup_args, "--yes"])
            cleaned = True
        finally:
            if not cleaned:
                try:
                    _run(
                        [
                            "cleanup",
                            role_name,
                            policy_name,
                            "--cascade",
                            *selector_args,
                            "--yes",
                        ]
                    )
                except Exception as error:  # noqa: BLE001
                    sys.stderr.write(
                        "Emergency cleanup failed; run the printed recovery command: "
                        f"{error}\n"
                    )

    if not _absent(context.iam.get_role, RoleName=role_name) or not _absent(
        context.iam.get_policy, PolicyArn=policy_arn
    ):
        raise RuntimeError(
            "Live IAM smoke cleanup did not leave both resources absent."
        )
    sys.stdout.write(
        f"Verified lifecycle and absence for account {expected}, target {target}, "
        f"and smoke run {run_id}.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
