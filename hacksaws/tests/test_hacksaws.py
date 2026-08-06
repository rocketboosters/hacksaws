"""Behavioral tests for the Hacksaws command-line package."""

from __future__ import annotations

import argparse
import configparser
import subprocess
import tomllib
from contextlib import ExitStack
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock
from unittest.mock import call
from unittest.mock import patch

import boto3
import pytest
from botocore.stub import Stubber

import hacksaws
from hacksaws import _aws
from hacksaws import _configs
from hacksaws import _ecr
from hacksaws import _sessions
from hacksaws import _state

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mypy_boto3_ecr.client import ECRClient
    from mypy_boto3_sts.client import STSClient

ACCOUNT_ID = "123456789012"
PROFILE = "developers"
MFA_SERIAL = f"arn:aws:iam::{ACCOUNT_ID}:mfa/example"
STATIC_ACCESS_KEY = "AKIASTATICEXAMPLE"
STATIC_SECRET_KEY = "static-" + "value"
TEMPORARY_ACCESS_KEY = "ASIATEMPORARY0000"
TEMPORARY_SECRET_KEY = "temporary-" + "value"
SESSION_TOKEN = "session-" + "value"


def _write_ini(path: Path, data: dict[str, dict[str, str]]) -> None:
    parser = configparser.ConfigParser()
    parser.read_dict(data)
    with path.open("w", encoding="utf-8") as stream:
        parser.write(stream)


def _read_ini(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read(path)
    return parser


def _prepare_aws_directory(path: Path) -> None:
    _write_ini(
        path / "config",
        {
            f"profile {PROFILE}": {
                "region": "us-west-2",
                "mfa_serial": MFA_SERIAL,
            },
        },
    )
    _write_ini(
        path / "credentials",
        {
            PROFILE: {
                "aws_access_key_id": STATIC_ACCESS_KEY,
                "aws_secret_access_key": STATIC_SECRET_KEY,
            },
        },
    )


def _context(
    directory: Path,
    *,
    action: str = "login",
    ecr: bool = False,
    podman: bool = False,
    regions: list[str] | None = None,
) -> _configs.Context:
    return _configs.Context(
        argparse.Namespace(
            access_type="mfa",
            action=action,
            profile=PROFILE,
            mfa_code="123456",
            lifespan=43200,
            ecr=ecr,
            podman=podman,
            ecr_region=regions,
            directory=str(directory),
            aws_account_name=None,
        ),
    )


def _sts_client() -> STSClient:
    session = boto3.Session(
        aws_access_key_id=STATIC_ACCESS_KEY,
        aws_secret_access_key=STATIC_SECRET_KEY,
        region_name="us-west-2",
    )
    return session.client("sts")


def _ecr_client(region_name: str) -> ECRClient:
    session = boto3.Session(
        aws_access_key_id=STATIC_ACCESS_KEY,
        aws_secret_access_key=STATIC_SECRET_KEY,
        region_name=region_name,
    )
    return session.client("ecr")


def _session(*, region_name: str, clients: Mapping[str, object]) -> MagicMock:
    session = MagicMock()
    session.region_name = region_name
    session.client.side_effect = clients.__getitem__
    return session


def _authenticated_session(*, clients: Mapping[str, object] | None = None) -> MagicMock:
    """Return an MFA-authenticated session with deterministic frozen credentials."""
    session = _session(region_name="us-west-2", clients=clients or {})
    frozen = session.get_credentials.return_value.get_frozen_credentials.return_value
    frozen.access_key = TEMPORARY_ACCESS_KEY
    frozen.secret_key = TEMPORARY_SECRET_KEY
    frozen.token = SESSION_TOKEN
    return session


def _identity_response() -> dict[str, str]:
    return {
        "UserId": "AIDAEXAMPLE",
        "Account": ACCOUNT_ID,
        "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/example",
    }


def _temporary_credentials() -> dict[str, object]:
    return {
        "AccessKeyId": TEMPORARY_ACCESS_KEY,
        "SecretAccessKey": TEMPORARY_SECRET_KEY,
        "SessionToken": SESSION_TOKEN,
        "Expiration": datetime.now(UTC) + timedelta(hours=12),
    }


def test_version_and_main_exit_status() -> None:
    """Expose the project version and pass the result status to the shell."""
    with Path(__file__).parents[2].joinpath("pyproject.toml").open("rb") as stream:
        assert tomllib.load(stream)["project"]["version"] == "0.4.2"
    assert hacksaws.__version__ == "0.4.2"
    with patch(
        "hacksaws.console_main",
        return_value=_configs.Result("ERROR", "", exit_code=7),
    ):
        assert hacksaws.main() == 7


def test_top_level_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Return success after argparse renders top-level help."""
    result = hacksaws.console_main(["--help"])
    captured = capsys.readouterr()

    assert result.code == "HELP"
    assert result.exit_code == 0
    assert "usage: hacksaws" in captured.out
    assert captured.err == ""


def test_invalid_argument(capsys: pytest.CaptureFixture[str]) -> None:
    """Return argparse's nonzero status for malformed input."""
    result = hacksaws.console_main(["mfa", "login"])
    captured = capsys.readouterr()

    assert result.code == "ARGUMENT_ERROR"
    assert result.exit_code == 2
    assert "the following arguments are required" in captured.err


def test_no_arguments_prints_help_and_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Explain incomplete top-level invocations and return a failure."""
    result = hacksaws.console_main([])
    captured = capsys.readouterr()

    assert result.code == "ACCESS_TYPE_HELP"
    assert result.exit_code == 2
    assert "usage: hacksaws" in captured.out
    assert captured.err == "Not enough arguments.\n"


@pytest.mark.parametrize(
    ("alias", "canonical"),
    [("in", "login"), ("out", "logout")],
)
def test_action_aliases_are_preserved(alias: str, canonical: str) -> None:
    """Accept the documented short aliases for MFA actions."""
    observed_action = ""

    def inspect_context(context: _configs.Context) -> _configs.Result:
        nonlocal observed_action
        observed_action = context.args.action
        return _configs.Result("OK", "")

    arguments = ["mfa", alias, PROFILE]
    if canonical == "login":
        arguments.append("123456")
    with patch("hacksaws._cli._run_mfa", side_effect=inspect_context):
        result = hacksaws.console_main(arguments)

    assert result.exit_code == 0
    assert observed_action == alias


@pytest.mark.parametrize(
    ("action", "required_arguments"),
    [
        ("login", [PROFILE, "123456"]),
        ("in", [PROFILE, "123456"]),
        ("logout", [PROFILE]),
        ("out", [PROFILE]),
    ],
)
def test_container_engine_parser_defaults(
    action: str,
    required_arguments: list[str],
) -> None:
    """Default to Docker and keep Podman independent from ECR selection."""
    parser = hacksaws._cli._create_parser()
    default_context = _configs.Context(
        parser.parse_args(["mfa", action, *required_arguments]),
    )
    podman_context = _configs.Context(
        parser.parse_args(["mfa", action, *required_arguments, "--podman"]),
    )

    assert default_context.container_engine == "docker"
    assert default_context.args.ecr is False
    assert default_context.args.podman is False
    assert podman_context.container_engine == "podman"
    assert podman_context.args.ecr is False
    assert podman_context.args.podman is True


def test_podman_without_ecr_does_not_run_container_commands(
    tmp_path: Path,
) -> None:
    """Treat --podman only as the engine choice for an explicit ECR operation."""
    context = _context(tmp_path, podman=True)
    with (
        patch(
            "hacksaws._sessions.mfa_login",
            return_value=_configs.Result("MFA_LOGIN", "logged in"),
        ),
        patch("hacksaws._ecr.logout") as ecr_logout,
        patch("hacksaws._ecr.login") as ecr_login,
    ):
        result = hacksaws._cli._run_mfa(context)

    assert result.exit_code == 0
    ecr_logout.assert_not_called()
    ecr_login.assert_not_called()


def test_mfa_without_action_prints_command_help(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reject an MFA command that omits its action."""
    result = hacksaws.console_main(["mfa"])
    captured = capsys.readouterr()

    assert result.code == "MFA_HELP"
    assert result.exit_code == 2
    assert "usage: hacksaws mfa" in captured.out
    assert "Not enough arguments specified" in captured.err


def test_login_exchanges_and_stores_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Persist MFA credentials while retaining the original section for logout."""
    _prepare_aws_directory(tmp_path)
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "hacksaws-home"))
    _state.save_config(_state.default_config())
    raw = MagicMock(region_name="us-west-2")
    intermediate = _authenticated_session()
    source_config = _sessions._read_ini(tmp_path / "config")

    with (
        patch(
            "hacksaws._sessions._persistent_source",
            return_value=(raw, source_config),
        ),
        patch(
            "hacksaws._sessions._identity",
            return_value=(ACCOUNT_ID, "aws", _identity_response()["Arn"]),
        ),
        patch("hacksaws._sessions._mfa_session", return_value=intermediate),
    ):
        result = hacksaws.console_main(
            [
                "mfa",
                "login",
                PROFILE,
                "123456",
                "--directory",
                str(tmp_path),
            ],
        )

    credentials = _read_ini(tmp_path / "credentials")
    assert result.code == "MFA_LOGIN"
    assert result.exit_code == 0
    assert credentials[PROFILE] == {
        "aws_access_key_id": TEMPORARY_ACCESS_KEY,
        "aws_secret_access_key": TEMPORARY_SECRET_KEY,
        "aws_session_token": SESSION_TOKEN,
    }
    managed = _state.load_sessions()[f"{tmp_path.absolute()}::{PROFILE}"]
    assert managed["section_backup"]["credentials"]["original"]["values"] == {
        "aws_access_key_id": STATIC_ACCESS_KEY,
        "aws_secret_access_key": STATIC_SECRET_KEY,
    }


def test_logout_restores_credentials(tmp_path: Path) -> None:
    """Restore static credentials, remove the backup, and retain the profile."""
    _prepare_aws_directory(tmp_path)
    _write_ini(
        tmp_path / "credentials",
        {
            PROFILE: {
                "aws_access_key_id": TEMPORARY_ACCESS_KEY,
                "aws_secret_access_key": TEMPORARY_SECRET_KEY,
                "aws_session_token": SESSION_TOKEN,
            },
        },
    )
    _write_ini(
        tmp_path / f"{PROFILE}.store.credentials",
        {
            PROFILE: {
                "aws_access_key_id": STATIC_ACCESS_KEY,
                "aws_secret_access_key": STATIC_SECRET_KEY,
            },
        },
    )
    identity_client = _sts_client()
    identity_stubber = Stubber(identity_client)
    identity_stubber.add_response("get_caller_identity", _identity_response(), {})

    with (
        identity_stubber,
        patch(
            "boto3.Session",
            return_value=_session(
                region_name="us-west-2",
                clients={"sts": identity_client},
            ),
        ),
    ):
        result = hacksaws.console_main(
            ["mfa", "out", PROFILE, "--directory", str(tmp_path)],
        )

    credentials = _read_ini(tmp_path / "credentials")
    assert result.code == "MFA_LOGOUT"
    assert credentials[PROFILE] == {
        "aws_access_key_id": STATIC_ACCESS_KEY,
        "aws_secret_access_key": STATIC_SECRET_KEY,
    }
    assert not (tmp_path / f"{PROFILE}.store.credentials").exists()


@pytest.mark.parametrize(
    ("engine", "podman"),
    [("docker", False), ("podman", True)],
)
def test_ecr_regions_and_container_commands_are_ordered_and_exact(
    tmp_path: Path,
    engine: str,
    podman: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run exact engine commands in primary-first, duplicate-free region order."""
    _prepare_aws_directory(tmp_path)
    regions = ["us-east-1", "us-west-2", "eu-west-1", "us-east-1"]
    ordered_regions = ["us-west-2", "us-east-1", "eu-west-1"]

    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path / "hacksaws-home"))
    _state.save_config(_state.default_config())
    raw = MagicMock(region_name="us-west-2")
    regional_clients: dict[str, object] = {}
    stack = ExitStack()
    for region in ordered_regions:
        ecr_client = _ecr_client(region)
        ecr_stubber = Stubber(ecr_client)
        ecr_stubber.add_response(
            "get_authorization_token",
            {
                "authorizationData": [
                    {
                        "authorizationToken": "QVdTOmVjci1wYXNzd29yZA==",
                        "expiresAt": datetime.now(UTC) + timedelta(hours=12),
                        "proxyEndpoint": (
                            f"https://{ACCOUNT_ID}.dkr.ecr.{region}.amazonaws.com"
                        ),
                    },
                ],
            },
            {"registryIds": [ACCOUNT_ID]},
        )
        stack.enter_context(ecr_stubber)
        regional_clients[region] = ecr_client
    intermediate = _authenticated_session()
    intermediate.client.side_effect = lambda service, *, region_name: (
        regional_clients[region_name] if service == "ecr" else None
    )
    source_config = _sessions._read_ini(tmp_path / "config")

    arguments = [
        "mfa",
        "in",
        PROFILE,
        "123456",
        "--directory",
        str(tmp_path),
        "--ecr",
    ]
    for region in regions:
        arguments.extend(["--ecr-region", region])
    if podman:
        arguments.append("--podman")

    with (
        stack,
        patch(
            "hacksaws._sessions._persistent_source",
            return_value=(raw, source_config),
        ),
        patch(
            "hacksaws._sessions._identity",
            return_value=(ACCOUNT_ID, "aws", _identity_response()["Arn"]),
        ),
        patch("hacksaws._sessions._mfa_session", return_value=intermediate),
        patch("subprocess.run") as subprocess_run,
    ):
        result = hacksaws.console_main(arguments)

    registries = [
        f"{ACCOUNT_ID}.dkr.ecr.{region}.amazonaws.com" for region in ordered_regions
    ]
    expected_calls = [
        *[
            call(
                [
                    engine,
                    "login",
                    "--username=AWS",
                    "--password-stdin",
                    registry,
                ],
                input=b"ecr-password",
                check=True,
            )
            for registry in registries
        ],
    ]
    assert result.exit_code == 0
    assert subprocess_run.call_args_list == expected_calls


@pytest.mark.parametrize("action", ["logout", "out"])
@pytest.mark.parametrize(
    ("engine", "podman"),
    [("docker", False), ("podman", True)],
)
def test_explicit_ecr_logout_is_strict(
    tmp_path: Path,
    action: str,
    engine: str,
    podman: bool,
) -> None:
    """Run explicit Docker and Podman logout commands with check enabled."""
    _prepare_aws_directory(tmp_path)
    identity_client = _sts_client()
    identity_stubber = Stubber(identity_client)
    identity_stubber.add_response("get_caller_identity", _identity_response(), {})
    arguments = [
        "mfa",
        action,
        PROFILE,
        "--directory",
        str(tmp_path),
        "--ecr",
    ]
    if podman:
        arguments.append("--podman")

    with (
        identity_stubber,
        patch(
            "boto3.Session",
            return_value=_session(
                region_name="us-west-2",
                clients={"sts": identity_client},
            ),
        ),
        patch("subprocess.run") as subprocess_run,
    ):
        result = hacksaws.console_main(arguments)

    assert result.exit_code == 0
    subprocess_run.assert_not_called()


def test_known_configuration_failure_is_concise(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Convert a missing AWS config into stderr and a nonzero result."""
    _write_ini(
        tmp_path / "credentials",
        {
            PROFILE: {
                "aws_access_key_id": STATIC_ACCESS_KEY,
                "aws_secret_access_key": STATIC_SECRET_KEY,
            },
        },
    )
    identity_client = _sts_client()
    identity_stubber = Stubber(identity_client)
    identity_stubber.add_response("get_caller_identity", _identity_response(), {})

    with (
        identity_stubber,
        patch(
            "boto3.Session",
            return_value=_session(
                region_name="us-west-2",
                clients={"sts": identity_client},
            ),
        ),
    ):
        result = hacksaws.console_main(
            [
                "mfa",
                "login",
                PROFILE,
                "123456",
                "--directory",
                str(tmp_path),
                "--region",
                "us-west-2",
            ],
        )

    captured = capsys.readouterr()
    assert result.code == "OPERATIONAL_ERROR"
    assert result.exit_code == 1
    assert captured.err.startswith(
        f"Error: Profile '{PROFILE}' does not define mfa_serial."
    )
    assert "Traceback" not in captured.err


def test_aws_failure_is_concise(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Convert a known AWS service failure into stderr and a nonzero result."""
    _prepare_aws_directory(tmp_path)
    identity_client = _sts_client()
    identity_stubber = Stubber(identity_client)
    identity_stubber.add_client_error(
        "get_caller_identity",
        service_error_code="ExpiredToken",
        service_message="The security token has expired.",
        http_status_code=403,
        expected_params={},
    )

    with (
        identity_stubber,
        patch(
            "boto3.Session",
            return_value=_session(
                region_name="us-west-2",
                clients={"sts": identity_client},
            ),
        ),
    ):
        result = hacksaws.console_main(
            ["mfa", "logout", PROFILE, "--directory", str(tmp_path)],
        )

    captured = capsys.readouterr()
    assert result.code == "LOGOUT_NO_STATE"
    assert result.exit_code == 0
    assert captured.err == ""
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    ("engine", "podman", "failure", "message"),
    [
        (
            "docker",
            False,
            FileNotFoundError(),
            "Docker is not installed or is not available on PATH.",
        ),
        (
            "podman",
            True,
            FileNotFoundError(),
            "Podman is not installed or is not available on PATH.",
        ),
        (
            "docker",
            False,
            PermissionError("access denied"),
            "Unable to run Docker: access denied",
        ),
        (
            "podman",
            True,
            PermissionError("access denied"),
            "Unable to run Podman: access denied",
        ),
        (
            "docker",
            False,
            subprocess.CalledProcessError(9, ["docker"]),
            "Docker command failed with exit code 9.",
        ),
        (
            "podman",
            True,
            subprocess.CalledProcessError(9, ["podman"]),
            "Podman command failed with exit code 9.",
        ),
    ],
)
def test_container_engine_failures_are_normalized(
    tmp_path: Path,
    engine: str,
    podman: bool,
    failure: OSError | subprocess.CalledProcessError,
    message: str,
) -> None:
    """Normalize expected launch and nonzero failures for both engines."""
    context = _context(
        tmp_path,
        action="logout",
        ecr=True,
        podman=podman,
    )
    with (
        patch("subprocess.run", side_effect=failure) as subprocess_run,
        pytest.raises(_configs.OperationalError, match=f"^{message}$"),
    ):
        _ecr.logout(
            context,
            _configs.AwsAccount(
                identity_response=_identity_response(),
                region_name="us-west-2",
                ecr_additional_regions=(),
            ),
        )

    registry = f"{ACCOUNT_ID}.dkr.ecr.us-west-2.amazonaws.com"
    subprocess_run.assert_called_once_with(
        [engine, "logout", registry],
        input=None,
        check=True,
    )


@pytest.mark.parametrize(
    ("podman", "failure", "message"),
    [
        (
            False,
            FileNotFoundError(),
            "Docker is not installed or is not available on PATH.",
        ),
        (
            True,
            FileNotFoundError(),
            "Podman is not installed or is not available on PATH.",
        ),
        (
            False,
            PermissionError("access denied"),
            "Unable to run Docker: access denied",
        ),
        (
            True,
            PermissionError("access denied"),
            "Unable to run Podman: access denied",
        ),
    ],
)
def test_non_strict_logout_still_normalizes_launch_failures(
    tmp_path: Path,
    podman: bool,
    failure: OSError,
    message: str,
) -> None:
    """Do not suppress missing or unlaunchable engines during pre-login cleanup."""
    context = _context(tmp_path, ecr=True, podman=podman)
    account = _configs.AwsAccount(
        identity_response=_identity_response(),
        region_name="us-west-2",
        ecr_additional_regions=(),
    )

    with (
        patch("subprocess.run", side_effect=failure),
        pytest.raises(_configs.OperationalError, match=f"^{message}$"),
    ):
        _ecr.logout(context, account, check=False)


@pytest.mark.parametrize(
    ("engine", "podman"),
    [("docker", False), ("podman", True)],
)
def test_container_engine_launch_os_error_is_concise_through_cli(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    engine: str,
    podman: bool,
) -> None:
    """Convert an engine launch permission error through the complete CLI path."""
    _prepare_aws_directory(tmp_path)
    identity_client = _sts_client()
    identity_stubber = Stubber(identity_client)
    identity_stubber.add_response("get_caller_identity", _identity_response(), {})

    with (
        identity_stubber,
        patch(
            "boto3.Session",
            return_value=_session(
                region_name="us-west-2",
                clients={"sts": identity_client},
            ),
        ),
        patch("subprocess.run", side_effect=PermissionError("access denied")),
    ):
        arguments = [
            "mfa",
            "logout",
            PROFILE,
            "--directory",
            str(tmp_path),
            "--ecr",
        ]
        if podman:
            arguments.append("--podman")
        result = hacksaws.console_main(arguments)

    captured = capsys.readouterr()
    assert result.code == "LOGOUT_NO_STATE"
    assert result.exit_code == 0
    assert captured.err == ""
    assert "Traceback" not in captured.err


def test_unexpected_failures_remain_visible() -> None:
    """Allow programming errors to retain their traceback for diagnosis."""
    with (
        patch("hacksaws._cli._run_mfa", side_effect=RuntimeError("bug")),
        pytest.raises(RuntimeError, match="bug"),
    ):
        hacksaws.console_main(["mfa", "logout", PROFILE])


def test_context_account_name_overrides_directory(tmp_path: Path) -> None:
    """Preserve the account-name directory alias behavior."""
    context = _context(tmp_path)
    context.args.aws_account_name = "sandbox"

    assert context.aws_directory == Path("~/.aws-sandbox").expanduser().absolute()


def test_direct_aws_logout_is_noop_without_backup(tmp_path: Path) -> None:
    """Permit logout when no temporary credential backup exists."""
    _aws.logout(_context(tmp_path, action="logout"))
