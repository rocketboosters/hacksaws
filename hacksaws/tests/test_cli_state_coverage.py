"""Behavior coverage for configuration state and its command-line controls."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from hacksaws import _cli
from hacksaws import _configs
from hacksaws import _state

ACCOUNT_ID = "123456789012"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/ReadOnly"


@pytest.fixture
def state_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Give every persisted configuration test an isolated state directory."""
    home = tmp_path / "state"
    monkeypatch.setenv("HACKSAWS_HOME", str(home))
    return home


def _run(arguments: list[str]) -> _configs.Result:
    return _cli.console_main(arguments)


def _add_account(name: str = "Prod") -> _configs.Result:
    return _run(
        ["account", "add", name, ACCOUNT_ID, "--partition", "aws", "--no-verify"]
    )


def _seed_connected(state_home: Path) -> None:
    data = _state.default_config()
    data["accounts"]["Prod"] = {"id": ACCOUNT_ID, "partition": "aws"}
    data["boundaries"]["Guard"] = {
        "role_arn": ROLE_ARN,
        "account": "Prod",
        "policy": "Guard",
        "external_id": "original",
        "duration": 900,
        "verified": False,
    }
    data["targets"]["Deploy"] = {
        "source_account": "Prod",
        "source_profile": "source",
        "source_directory": str((state_home / "source").absolute()),
        "destination_location": "old",
        "destination_profile": "destination",
        "boundary": "Guard",
    }
    data["policies"]["Guard"] = {
        "file": "stored_session_policies/Guard.yaml",
    }
    _state.save_config(data)


def test_resource_cli_add_get_list_update_and_clear(state_home: Path) -> None:
    assert _add_account().code == "RESOURCE_SAVED"
    assert (
        _run(
            [
                "boundary",
                "add",
                "Guard",
                "ReadOnly",
                "--account",
                "Prod",
                "--no-verify",
                "--external-id",
                "initial",
                "--duration",
                "15m",
            ]
        ).exit_code
        == 0
    )
    source = state_home / "source"
    assert (
        _run(
            [
                "target",
                "add",
                "Deploy",
                "--source-account",
                "Prod",
                "--source-directory",
                str(source),
                "--to",
                "west:release",
                "--boundary",
                "Guard",
                "--description",
                "deployment target",
            ]
        ).exit_code
        == 0
    )

    listing = _run(["target", "list", "--json"])
    fetched = _run(["target", "get", "deploy", "--json"])
    assert json.loads(listing.message)[0]["name"] == "Deploy"
    assert json.loads(fetched.message)["destination_profile"] == "release"

    assert (
        _run(
            [
                "boundary",
                "update",
                "Guard",
                "--role",
                "Updated",
                "--no-verify",
                "--policy",
                "local-policy.yaml",
                "--external-id",
                "changed",
                "--duration",
                "1h",
                "--description",
                "guard boundary",
            ]
        ).exit_code
        == 0
    )
    assert (
        _run(
            [
                "boundary",
                "update",
                "Guard",
                "--clear-policy",
                "--clear-external-id",
                "--clear-duration",
                "--clear-description",
            ]
        ).exit_code
        == 0
    )
    assert (
        _run(
            [
                "target",
                "update",
                "Deploy",
                "--source-location",
                "build",
                "--to-directory",
                str(state_home / "destination"),
                "--to-profile",
                "writer",
                "--clear-boundary",
            ]
        ).exit_code
        == 0
    )
    assert (
        _run(
            ["target", "update", "Deploy", "--clear-destination", "--clear-description"]
        ).exit_code
        == 0
    )

    data = _state.load_config()
    assert data["boundaries"]["Guard"] == {
        "role_arn": f"arn:aws:iam::{ACCOUNT_ID}:role/Updated",
        "account": "Prod",
        "verified": False,
    }
    assert data["targets"]["Deploy"] == {
        "source_account": "Prod",
        "source_profile": "default",
        "source_location": "build",
    }


def test_verified_account_and_boundary_adds_use_authoritative_identity(
    state_home: Path,
) -> None:
    identity = (ACCOUNT_ID, "aws", "arn:aws:iam::123456789012:user/test")
    iam = MagicMock()
    iam.get_role.return_value = {"Role": {"Arn": ROLE_ARN}}
    session = MagicMock()
    session.client.return_value = iam
    with (
        patch("hacksaws._sessions._identity", return_value=identity) as get_identity,
        patch("hacksaws._cli.boto3.Session", return_value=session),
    ):
        assert _run(["account", "add", "Verified", ACCOUNT_ID]).exit_code == 0
        assert (
            _run(
                ["boundary", "add", "Read", "ReadOnly", "--account", "Verified"]
            ).exit_code
            == 0
        )
    get_identity.assert_called_once()
    iam.get_role.assert_called_once_with(RoleName="ReadOnly")
    assert _state.load_config()["boundaries"]["Read"]["verified"] is True


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["account", "add", "Prod", ACCOUNT_ID, "--no-verify"], "--partition"),
        (
            [
                "boundary",
                "add",
                "Bad",
                "arn:aws:iam::999999999999:role/Wrong",
                "--account",
                "Prod",
                "--no-verify",
            ],
            "conflicts",
        ),
        (
            [
                "target",
                "add",
                "Bad",
                "--source-account",
                "Prod",
                "--to-directory",
                "somewhere",
            ],
            "requires --to-profile",
        ),
    ],
)
def test_resource_cli_reports_validation_errors(
    state_home: Path,
    arguments: list[str],
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if arguments[0] != "account":
        _add_account()
    result = _run(arguments)
    assert result.code == "OPERATIONAL_ERROR"
    assert message in capsys.readouterr().err


def test_resource_rename_updates_references_and_active_session(
    state_home: Path,
) -> None:
    _seed_connected(state_home)
    _state.save_sessions(
        {
            "destination": {
                "target_account": "Prod",
                "boundary": "Guard",
                "target": "Deploy",
                "policy": "Guard",
            }
        }
    )
    for kind, old, new in (
        ("account", "Prod", "Production"),
        ("boundary", "Guard", "Boundary"),
        ("target", "Deploy", "Release"),
    ):
        assert _run([kind, "rename", old, new]).exit_code == 0

    data = _state.load_config()
    session = _state.load_sessions()["destination"]
    assert data["boundaries"]["Boundary"]["account"] == "Production"
    assert data["boundaries"]["Boundary"]["policy"] == "Guard"
    assert data["targets"]["Release"]["boundary"] == "Boundary"
    assert session == {
        "target_account": "Production",
        "boundary": "Boundary",
        "target": "Release",
        "policy": "Guard",
    }


def test_state_references_block_remove_then_allow_it(state_home: Path) -> None:
    _seed_connected(state_home)
    _state.save_sessions({"destination": {"target": "Deploy"}})
    data = _state.load_config()
    assert _state.references(data, "account", "prod") == [
        "boundary:Guard",
        "target:Deploy",
    ]
    with pytest.raises(_configs.OperationalError, match="referenced by target:Deploy"):
        _state.remove_resource(data, "boundary", "Guard")
    with pytest.raises(_configs.OperationalError, match="session:destination"):
        _state.remove_resource(data, "target", "Deploy")

    _state.save_sessions({})
    _state.remove_resource(data, "target", "Deploy")
    _state.remove_resource(data, "boundary", "Guard")
    _state.remove_resource(data, "policy", "Guard")
    _state.remove_resource(data, "account", "Prod")
    assert all(
        not data[name] for name in ("accounts", "boundaries", "targets", "policies")
    )


def test_cascade_requires_confirmation_and_rejects_active_sessions(
    state_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_connected(state_home)
    data = _state.load_config()
    with pytest.raises(_configs.OperationalError, match="requires --yes"):
        _cli._cascade_remove(data, "account", "Prod", yes=False)

    _state.save_sessions({"destination": {"target_account": "Prod"}})
    with pytest.raises(_configs.OperationalError, match="Log out first"):
        _cli._cascade_remove(data, "account", "Prod", yes=True)

    _state.save_sessions({})
    monkeypatch.setattr(_cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "no")
    with pytest.raises(_configs.OperationalError, match="cancelled"):
        _cli._cascade_remove(data, "account", "Prod", yes=False)


def test_cascade_removes_policy_file_and_rolls_back_on_save_error(
    state_home: Path,
) -> None:
    _seed_connected(state_home)
    policy = state_home / "stored_session_policies" / "Guard.yaml"
    policy.parent.mkdir(parents=True)
    policy.write_text("Version: '2012-10-17'\nStatement: []\n", encoding="utf-8")
    original = (state_home / "config.json").read_bytes()
    data = _state.load_config()
    with (
        patch("hacksaws._state.save_config", side_effect=OSError("no disk")),
        pytest.raises(OSError, match="no disk"),
    ):
        _cli._cascade_remove(data, "policy", "Guard", yes=True)
    assert (state_home / "config.json").read_bytes() == original
    assert policy.exists()

    assert "Guard" in _cli._cascade_remove(
        _state.load_config(), "policy", "Guard", yes=True
    )
    assert not policy.exists()


def test_policy_cache_config_status_and_logout_dispatch(state_home: Path) -> None:
    document = state_home / "document.yaml"
    document.parent.mkdir(parents=True)
    document.write_text("Version: '2012-10-17'\nStatement: []\n", encoding="utf-8")
    assert (
        _run(
            ["policy", "add", "Read", str(document), "--description", "read"]
        ).exit_code
        == 0
    )
    assert (
        json.loads(_run(["policy", "get", "read", "--json"]).message)["name"] == "Read"
    )
    with patch("hacksaws._policies.rename_stored") as rename:
        assert _run(["policy", "rename", "Read", "Reader"]).exit_code == 0
    rename.assert_called_once_with("Read", "Reader")
    assert _run(["policy", "list"]).code == "POLICY_LIST"
    assert _run(["policy", "remove", "Read"]).exit_code == 0

    assert _run(["cache", "set", "max-age", "0s"]).code == "CACHE_SET"
    cache_root = state_home / "policy-cache"
    cache_root.mkdir()
    (cache_root / "one.json").write_text("{}", encoding="utf-8")
    assert json.loads(_run(["cache", "get", "--json"]).message) == {
        "max_age": 0,
        "entries": 1,
    }
    assert _run(["cache", "clear", "--yes"]).code == "CACHE_CLEAR"

    _add_account()
    assert (
        json.loads(_run(["config", "show", "--account", "prod", "--json"]).message)[
            "account"
        ]["name"]
        == "Prod"
    )
    with (
        patch("hacksaws._sessions.status", return_value={"sessions": []}),
        patch("hacksaws._cli._run_logout", return_value=_configs.Result("OUT", "ok")),
    ):
        assert json.loads(_run(["status", "--json"]).message) == {"sessions": []}
        assert _run(["logout"]).code == "OUT"


def test_console_dispatches_config_branches_and_known_errors(
    state_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _state.save_config(_state.default_config())
    with (
        patch("hacksaws._sessions.explain_target", return_value={"target": "Prod"}),
        patch("hacksaws._sessions.check_config", return_value={"errors": ["bad"]}),
        patch(
            "hacksaws._sessions.fix_config",
            return_value=_configs.Result("FIX", "fixed"),
        ),
        patch("hacksaws._sessions.export_config", return_value=state_home / "out.zip"),
        patch("hacksaws._sessions.import_config", return_value="imported"),
    ):
        assert json.loads(_run(["config", "explain", "Prod", "--json"]).message) == {
            "target": "Prod"
        }
        assert _run(["config", "check"]).exit_code == 1
        assert _run(["config", "fix", "--yes"]).code == "FIX"
        assert _run(["config", "export"]).code == "CONFIG_EXPORT"
        assert (
            _run(["config", "import", "in.zip", "--replace", "--yes"]).message
            == "imported"
        )
    assert _run(["account", "get", "Missing"]).code == "OPERATIONAL_ERROR"
    assert "does not exist" in capsys.readouterr().err
    assert _run(["not-a-command"]).code == "ARGUMENT_ERROR"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda data: data.update(extra=True), "Unknown config"),
        (lambda data: data.update(schema_version=True), "Unsupported"),
        (lambda data: data.update(cache={"max_age": True}), "non-negative"),
        (
            lambda data: data["accounts"].update(
                {"Prod": {"id": "short", "partition": "moon"}}
            ),
            "12-digit",
        ),
        (
            lambda data: data["targets"].update(
                {"Bad": {"source_account": "missing", "source_location": "default"}}
            ),
            "missing source account",
        ),
        (
            lambda data: data["accounts"].update(
                {
                    "Prod": {"id": ACCOUNT_ID, "partition": "aws"},
                    "prod": {"id": ACCOUNT_ID, "partition": "aws"},
                }
            ),
            "Duplicate case-insensitive",
        ),
    ],
)
def test_state_strict_schema_rejects_invalid_resources(
    change: object, message: str
) -> None:
    data = _state.default_config()
    change(data)  # type: ignore[operator]
    with pytest.raises(_configs.OperationalError, match=message):
        _state.save_config(data)


def test_state_helpers_cover_locations_arns_and_io_errors(
    state_home: Path,
) -> None:
    assert _state.collection_name("boundary") == "boundaries"
    assert _state.normalize_location(None) == "default"
    assert _state.parse_role_arn(ROLE_ARN)[:2] == ("aws", ACCOUNT_ID)
    with pytest.raises(_configs.OperationalError, match="Invalid resource"):
        _state.validate_name("bad name")
    with pytest.raises(_configs.OperationalError, match="AWS location must be text"):
        _state.normalize_location(7)  # type: ignore[arg-type]
    with pytest.raises(_configs.OperationalError, match="canonical IAM"):
        _state.parse_role_arn("not-an-arn")

    (state_home / "config.json").parent.mkdir(parents=True)
    (state_home / "config.json").write_text("not json", encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="Unable to read"):
        _state.load_config()
    (state_home / "sessions.json").write_text("[]", encoding="utf-8")
    with pytest.raises(_configs.OperationalError, match="Invalid session state"):
        _state.load_sessions()


def test_state_rename_rejects_collisions_without_rewriting(state_home: Path) -> None:
    data = _state.default_config()
    data["accounts"] = {
        "Prod": {"id": ACCOUNT_ID, "partition": "aws"},
        "Other": {"id": "999999999999", "partition": "aws"},
    }
    before = json.loads(json.dumps(data))
    with pytest.raises(_configs.OperationalError, match="already exists"):
        _state.rename_resource(data, "account", "Prod", "Other")
    assert data == before
