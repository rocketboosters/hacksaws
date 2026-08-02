"""High-value public and error-path coverage closure tests."""

from __future__ import annotations

import argparse
import configparser
import importlib
import subprocess
import tomllib
from copy import deepcopy
from importlib import metadata
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError
from coverage.results import should_fail_under

import hacksaws
from hacksaws import _aws
from hacksaws import _configs
from hacksaws import _duration
from hacksaws import _ecr
from hacksaws import _policies
from hacksaws import _state
from hacksaws import _test_runner
from scripts import prettier

ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/Guard"
POLICY = b'Version: "2012-10-17"\nStatement: []\n'


def _context(directory: Path, **overrides: object) -> _configs.Context:
    values: dict[str, object] = {
        "directory": str(directory),
        "profile": "dev",
        "aws_account_name": None,
        "podman": False,
        "ecr_region": [],
        "lifespan": 3600,
        "mfa_code": "123456",
    }
    values.update(overrides)
    return _configs.Context(argparse.Namespace(**values))


def _base_config() -> dict[str, Any]:
    return _state.default_config()


def _account_config() -> dict[str, Any]:
    data = _state.default_config()
    data["accounts"]["Prod"] = {"id": ACCOUNT, "partition": "aws"}
    return data


def _boundary_config() -> dict[str, Any]:
    data = _account_config()
    data["boundaries"]["Guard"] = {
        "role_arn": ROLE,
        "account": "Prod",
        "verified": False,
    }
    return data


def _target_config() -> dict[str, Any]:
    data = _account_config()
    data["targets"]["Prod"] = {
        "source_account": "Prod",
        "source_directory": str(Path.cwd().absolute()),
    }
    return data


def test_package_version_falls_back_to_pyproject() -> None:
    with patch("importlib.metadata.version", side_effect=metadata.PackageNotFoundError):
        reloaded = importlib.reload(hacksaws)
    assert reloaded.__version__ == "0.4.0"


def test_coverage_gate_uses_two_decimal_precision() -> None:
    project = Path(__file__).parents[2] / "pyproject.toml"
    with project.open("rb") as stream:
        configuration = tomllib.load(stream)
    precision = configuration["tool"]["coverage"]["report"]["precision"]

    assert precision == 2
    assert should_fail_under(94.99, 95, precision) is True
    assert should_fail_under(95.00, 95, precision) is False
    assert "--cov-fail-under=95" in _test_runner.PYTEST_ARGUMENTS


def test_task_leaves_follow_toolbelt_calling_convention() -> None:
    project = Path(__file__).parents[2] / "pyproject.toml"
    with project.open("rb") as stream:
        configuration = tomllib.load(stream)
    tasks = configuration["tool"]["taskipy"]["tasks"]

    assert tasks["format_ruff"] == "uvx ruff format"
    assert tasks["format_prettier"] == "python scripts/prettier.py write"
    assert tasks["lint_ruff_format"] == "uvx ruff format --check"
    assert tasks["lint_ruff"] == "uvx ruff check"
    assert tasks["lint_mypy"] == (
        "mypy --install-types --non-interactive --ignore-missing-imports"
    )
    assert tasks["lint_prettier"] == "python scripts/prettier.py check"
    for name, command in tasks.items():
        if name.startswith(("format_", "lint_")):
            assert not command.endswith(" .")
    assert tasks["format"] == "task format_ruff . && task format_prettier ."
    assert tasks["check"] == "task format && task lint && task test"


def test_typed_marker_and_build_metadata() -> None:
    project = Path(__file__).parents[2] / "pyproject.toml"
    with project.open("rb") as stream:
        configuration = tomllib.load(stream)

    assert configuration["project"]["name"] == "hacksaws"
    assert configuration["project"]["scripts"]["hacksaws"] == "hacksaws:main"
    assert "Typing :: Typed" in configuration["project"]["classifiers"]
    assert configuration["tool"]["hatch"]["build"]["artifacts"] == ["hacksaws/py.typed"]
    assert project.with_name("hacksaws").joinpath("py.typed").is_file()


def test_prettier_wrapper_forwards_paths_without_scanning_ignored_cache() -> None:
    git_result: subprocess.CompletedProcess[bytes] = subprocess.CompletedProcess(
        ["git"],
        0,
        b"README.md\0CHEATSHEET.md\0.tmp/pytest-cache/inaccessible\0",
    )
    prettier_result: subprocess.CompletedProcess[bytes] = subprocess.CompletedProcess(
        ["npx"], 0
    )
    with (
        patch(
            "scripts.prettier.subprocess.run",
            side_effect=[git_result, prettier_result],
        ) as run,
        patch("scripts.prettier.shutil.which", side_effect=["git", "npx"]),
    ):
        assert prettier.main(["check", "docs", "."]) == 0

    assert run.call_args_list[0].args[0][-3:] == ["--", "docs", "."]
    assert run.call_args_list[1].args[0] == [
        "npx",
        "prettier",
        "--check",
        "--ignore-unknown",
        "--",
        "README.md",
        "CHEATSHEET.md",
    ]
    assert not any(".cache" in argument for argument in run.call_args_list[1].args[0])

    ignored = (
        Path(__file__).parents[2].joinpath(".gitignore").read_text(encoding="utf-8")
    )
    assert ".tmp/" in ignored.splitlines()


def test_prettier_wrapper_terminates_options_before_git_filenames() -> None:
    git_result: subprocess.CompletedProcess[bytes] = subprocess.CompletedProcess(
        ["git"], 0, b"--foo.md\0"
    )
    prettier_result: subprocess.CompletedProcess[bytes] = subprocess.CompletedProcess(
        ["npx"], 0
    )
    with (
        patch(
            "scripts.prettier.subprocess.run",
            side_effect=[git_result, prettier_result],
        ) as run,
        patch("scripts.prettier.shutil.which", side_effect=["git", "npx"]),
        patch("scripts.prettier.os.path.isfile", return_value=True),
    ):
        assert prettier.main(["write", "."]) == 0

    prettier_command = run.call_args_list[1].args[0]
    assert prettier_command[-2:] == ["--", "--foo.md"]


def test_prettier_wrapper_handles_no_candidates_and_propagates_errors() -> None:
    no_files: subprocess.CompletedProcess[bytes] = subprocess.CompletedProcess(
        ["git"], 0, b""
    )
    with (
        patch("scripts.prettier.subprocess.run", return_value=no_files) as run,
        patch("scripts.prettier.shutil.which", return_value="git"),
    ):
        assert prettier.main(["write", "."]) == 0
    run.assert_called_once()

    git_error: subprocess.CompletedProcess[bytes] = subprocess.CompletedProcess(
        ["git"], 3, b""
    )
    with (
        patch("scripts.prettier.subprocess.run", return_value=git_error),
        patch("scripts.prettier.shutil.which", return_value="git"),
    ):
        assert prettier.main(["check", "."]) == 3

    files: subprocess.CompletedProcess[bytes] = subprocess.CompletedProcess(
        ["git"], 0, b"README.md\0"
    )
    prettier_error: subprocess.CompletedProcess[bytes] = subprocess.CompletedProcess(
        ["npx"], 7
    )
    with (
        patch(
            "scripts.prettier.subprocess.run",
            side_effect=[files, prettier_error],
        ),
        patch("scripts.prettier.shutil.which", side_effect=["git", "npx"]),
    ):
        assert prettier.main(["check", "."]) == 7


def test_aws_ini_helpers_translate_parser_write_and_profile_errors(
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "invalid"
    invalid.write_text("not-an-ini", encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="Unable to parse"):
        _aws._read_config(invalid, description="test")

    parser = configparser.ConfigParser()
    with (
        patch.object(Path, "open", side_effect=OSError("read only")),
        pytest.raises(_configs.OperationalError, match="Unable to write"),
    ):
        _aws._write_config(tmp_path / "output", parser, description="test")
    with pytest.raises(_configs.OperationalError, match="missing"):
        _aws._profile_section(parser, "dev", description="test")


def test_aws_logout_translates_backup_removal_failure(tmp_path: Path) -> None:
    context = _context(tmp_path)
    (tmp_path / "credentials").write_text(
        "[dev]\naws_access_key_id = current\naws_secret_access_key = current\n"
    )
    context.storage_path.write_text(
        "[dev]\naws_access_key_id = original\naws_secret_access_key = original\n"
    )
    real_unlink = Path.unlink

    def fail_backup(path: Path, *, missing_ok: bool = False) -> None:
        if path == context.storage_path:
            raise OSError("locked")
        real_unlink(path, missing_ok=missing_ok)

    with (
        patch.object(Path, "unlink", autospec=True, side_effect=fail_backup),
        pytest.raises(_configs.OperationalError, match="Unable to remove"),
    ):
        _aws.logout(context)
    restored = configparser.ConfigParser()
    restored.read(context.credentials_path)
    assert restored["dev"]["aws_access_key_id"] == "original"


def test_aws_login_translates_sts_client_failure(tmp_path: Path) -> None:
    context = _context(tmp_path)
    (tmp_path / "config").write_text(
        "[profile dev]\nmfa_serial = arn:aws:iam::123456789012:mfa/dev\n"
    )
    client_error = ClientError(
        {"Error": {"Code": "Denied", "Message": "bad token"}}, "GetSessionToken"
    )
    session = MagicMock()
    session.client.return_value.get_session_token.side_effect = client_error
    with (
        patch("hacksaws._aws.boto3.Session", return_value=session),
        pytest.raises(_configs.OperationalError, match="Unable to start MFA"),
    ):
        _aws.login(context)


def test_config_models_cover_identity_defaults_and_aws_failure(tmp_path: Path) -> None:
    context = _context(tmp_path, profile=None, aws_account_name="team", podman=True)
    assert context.profile == "default"
    assert context.container_engine == "podman"
    assert context.aws_directory.name == ".aws-team"

    account = _configs.AwsAccount(
        {"Account": ACCOUNT, "Arn": "x", "UserId": 123}, "us-east-1", ()
    )
    assert account.user_id is None
    assert account.partition == "aws"
    with (
        patch(
            "hacksaws._configs.boto3.Session",
            side_effect=ClientError(
                {"Error": {"Code": "Denied", "Message": "no"}}, "Session"
            ),
        ),
        pytest.raises(_configs.OperationalError, match="Unable to load AWS profile"),
    ):
        _configs.AwsAccount.from_context(context)


def test_duration_rejects_quantization_overflow_and_subsecond_count() -> None:
    huge = f"{'9' * 10000}h"
    with pytest.raises(_configs.OperationalError, match="Invalid duration"):
        _duration.parse_duration(huge)
    with pytest.raises(_configs.OperationalError, match="round to a positive"):
        _duration.parse_count("0.1", 1)


def test_ecr_client_error_is_operational() -> None:
    context = _context(Path.cwd())
    session = MagicMock()
    session.client.side_effect = ClientError(
        {"Error": {"Code": "Denied", "Message": "no"}}, "GetAuthorizationToken"
    )
    with pytest.raises(_configs.OperationalError, match="Unable to get an ECR token"):
        _ecr._do_login(
            context,
            account_id=ACCOUNT,
            region_name="us-east-1",
            session=session,
        )


def _invalid_cases() -> list[tuple[dict[str, Any] | object, str]]:
    policy = _base_config()
    policy["policies"]["Read"] = {"file": "wrong", "description": 3}

    cases: list[tuple[dict[str, Any] | object, str]] = [
        ([], "JSON object"),
        ({**_base_config(), "accounts": []}, "must be an object"),
        ({**_base_config(), "cache": {"other": 1}}, "accepts only"),
        ({**_base_config(), "accounts": {"Prod": "bad"}}, "must be an object"),
        (
            {
                **_base_config(),
                "accounts": {"Prod": {"id": ACCOUNT, "partition": "aws", "other": 1}},
            },
            "Unknown account",
        ),
        (
            {
                **_base_config(),
                "accounts": {
                    "Prod": {
                        "id": ACCOUNT,
                        "partition": "aws",
                        "description": 1,
                    }
                },
            },
            "description must be text",
        ),
        (
            {
                **_base_config(),
                "accounts": {
                    "Prod": {"id": ACCOUNT, "partition": "aws", "unverified": False}
                },
            },
            "unverified must be true",
        ),
        (policy, "canonical stored YAML"),
    ]

    boundary_mutations: list[tuple[dict[str, Any], str]] = [
        ({"other": 1}, "Unknown boundary"),
        ({"account": 7}, "account reference must be text"),
        ({"account": "Missing"}, "missing account"),
        ({"policy": 7}, "policy reference must be text"),
        ({"policy": "not-a-policy.txt"}, "neither a stored policy"),
        ({"external_id": 7}, "external_id must be text"),
        ({"verified": "yes"}, "verified must be boolean"),
    ]
    for mutation, message in boundary_mutations:
        data = _boundary_config()
        data["boundaries"]["Guard"].update(mutation)
        cases.append((data, message))

    target_mutations: list[tuple[dict[str, Any], str]] = [
        ({"other": 1}, "Unknown target"),
        ({"source_account": 7}, "source_account reference must be text"),
        ({"source_directory": None}, "exactly one source"),
        (
            {"destination_location": "a", "destination_directory": str(Path.cwd())},
            "are exclusive",
        ),
        ({"destination_profile": "out"}, "requires a destination"),
        ({"source_profile": 7}, "source_profile must be text"),
        ({"source_directory": "relative"}, "must be an absolute path"),
        ({"boundary": 7}, "boundary reference must be text"),
        ({"boundary": "Missing"}, "references missing boundary"),
    ]
    for mutation, message in target_mutations:
        data = _target_config()
        data["targets"]["Prod"].update(mutation)
        if "source_directory" in mutation and mutation["source_directory"] is None:
            data["targets"]["Prod"].pop("source_directory")
        cases.append((data, message))
    return cases


@pytest.mark.parametrize(("data", "message"), _invalid_cases())
def test_state_validation_rejects_malformed_resource_shapes(
    data: dict[str, Any] | object, message: str
) -> None:
    with pytest.raises(_configs.OperationalError, match=message):
        _state._validate_config(deepcopy(data))


def test_state_path_create_secure_duplicate_and_session_read_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    assert _state.aws_directory("team").name == ".aws-team"
    with patch.object(Path, "chmod", side_effect=OSError("unsupported")):
        _state._secure(tmp_path)
    created = _state.load_config(create=True)
    assert created == _state.default_config()
    assert (_state.root() / "config.json").exists()

    duplicate = _account_config()
    with pytest.raises(_configs.OperationalError, match="already exists"):
        _state.add_resource(
            duplicate,
            "account",
            "prod",
            {"id": ACCOUNT, "partition": "aws"},
        )
    _state.sessions_path().write_text("not-json", encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="Unable to read session"):
        _state.load_sessions()


def test_stored_policy_rename_updates_file_metadata_references_and_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "state"))
    source = tmp_path / "read.yaml"
    source.write_bytes(POLICY)
    _policies.add_stored("Read", source)
    config = _state.load_config()
    config["accounts"]["Prod"] = {"id": ACCOUNT, "partition": "aws"}
    config["boundaries"]["Guard"] = {
        "role_arn": ROLE,
        "account": "Prod",
        "policy": "Read",
        "verified": False,
    }
    _state.save_config(config)
    _state.save_sessions({"destination": {"policy": "Read", "backup": [], "ecr": []}})

    _policies.rename_stored("Read", "View")

    renamed = _state.load_config()
    assert renamed["policies"] == {
        "View": {"file": "stored_session_policies/View.yaml"}
    }
    assert renamed["boundaries"]["Guard"]["policy"] == "View"
    assert _state.load_sessions()["destination"]["policy"] == "View"
    assert not (_policies.stored_directory() / "Read.yaml").exists()
    assert (_policies.stored_directory() / "View.yaml").read_bytes() == POLICY
