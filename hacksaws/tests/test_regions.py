"""Offline coverage for canonical AWS region discovery and configuration."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from hacksaws import _cli
from hacksaws import _regions
from hacksaws import _sessions
from hacksaws import _state


@pytest.fixture
def state_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep region configuration tests outside the real user state root."""
    monkeypatch.setenv("HACKSAWS_HOME", str(tmp_path))
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    return tmp_path


def test_registry_is_deterministic_and_operational_by_default() -> None:
    operational = _regions.region_registry()
    all_regions = _regions.region_registry(all_partitions=True)

    assert operational == tuple(sorted(operational, key=lambda item: item.name))
    assert {item.partition for item in operational} <= _regions.OPERATIONAL_PARTITIONS
    assert set(operational) <= set(all_regions)
    oregon = next(item for item in operational if item.name == "us-west-2")
    assert oregon.compact_alias == "usw2"
    assert "oregon" in oregon.geography_aliases


@pytest.mark.parametrize(
    ("value", "source"),
    [
        ("us-west-2", "canonical"),
        ("usw2", "compact"),
        ("Oregon", "geography"),
        ("Pacific", "custom"),
    ],
)
def test_resolution_accepts_all_supported_input_forms(value: str, source: str) -> None:
    result = _regions.resolve_region(
        value, custom_aliases={"pacific": {"region": "us-west-2"}}
    )

    assert result.canonical == "us-west-2"
    assert result.partition == "aws"
    assert result.source == source


def test_unknown_escape_requires_canonical_shape_and_partition() -> None:
    with pytest.raises(_regions.RegionError) as alias_error:
        _regions.resolve_region("future-west", allow_unknown=True)
    assert alias_error.value.code == "REGION_INVALID"

    accepted = _regions.resolve_region("us-future-1", allow_unknown=True)
    assert accepted.known is False
    assert accepted.partition == "aws"
    assert accepted.warning

    with pytest.raises(_regions.RegionError) as mismatch:
        _regions.resolve_region("cn-future-1", partition="aws", allow_unknown=True)
    assert mismatch.value.code == "REGION_PARTITION_MISMATCH"
    gov = _regions.resolve_region("us-gov-future-1", allow_unknown=True)
    assert gov.partition == "aws-us-gov"

    with pytest.raises(_regions.RegionError) as unknown_partition:
        _regions.resolve_region("zz-future-1", allow_unknown=True)
    assert unknown_partition.value.code == "REGION_PARTITION_UNKNOWN"

    with pytest.raises(_regions.RegionError) as nonoperational_partition:
        _regions.resolve_region("us-iso-future-1", allow_unknown=True)
    assert nonoperational_partition.value.code == "REGION_PARTITION_UNSUPPORTED"


def test_compact_helper_and_noninteractive_invalid_branch() -> None:
    assert _regions._compact_candidate("invalid") == ""
    with pytest.raises(_regions.RegionError) as invalid:
        _regions.resolve_region_input("bad-alias", interactive=False)
    assert invalid.value.code == "REGION_INVALID"


@pytest.mark.parametrize(
    "aliases",
    [
        {"oregon": {"region": "us-east-1"}},
        {"Pacific Coast": {"region": "us-west-2"}},
        {"pacific": {"region": "oregon"}},
        {"pacific": {"region": "us-west-2", "extra": True}},
    ],
)
def test_custom_aliases_cannot_shadow_chain_or_use_invalid_shape(
    aliases: dict[str, object],
) -> None:
    with pytest.raises(_regions.RegionError):
        _regions.validate_custom_aliases(aliases)


def test_alias_helpers_cover_legacy_input_and_normalized_collisions() -> None:
    assert _regions.custom_alias_map({"pacific": "US-WEST-2"}) == {
        "pacific": ("us-west-2", None)
    }
    assert _regions.builtin_aliases()["oregon"] == ("us-west-2",)
    with pytest.raises(_regions.RegionError, match="unique normalized names"):
        _regions.validate_custom_aliases(
            {
                "west coast": {"region": "us-west-2"},
                "west-coast": {"region": "us-west-2"},
            }
        )
    with pytest.raises(_regions.RegionError, match="description must be text"):
        _regions.validate_custom_aliases(
            {"pacific": {"region": "us-west-2", "description": 1}}
        )


def test_resolution_rejects_blank_missing_custom_target_and_ambiguity() -> None:
    with pytest.raises(_regions.RegionError, match="cannot be blank"):
        _regions.resolve_region(" ")
    with pytest.raises(_regions.RegionError, match="references unavailable"):
        _regions.resolve_region(
            "future", custom_aliases={"future": {"region": "us-future-1"}}
        )

    west = _regions.resolve_region("us-west-2")
    east = _regions.resolve_region("us-east-1")
    west_info = next(
        item for item in _regions.region_registry() if item.name == west.canonical
    )
    east_info = next(
        item for item in _regions.region_registry() if item.name == east.canonical
    )
    registry = (
        {west.canonical: west_info, east.canonical: east_info},
        {"ambiguous": [(west_info, "geography"), (east_info, "geography")]},
    )
    with (
        patch("hacksaws._regions._registry_maps", return_value=registry),
        pytest.raises(_regions.RegionError) as ambiguous,
    ):
        _regions.resolve_region("ambiguous")
    assert ambiguous.value.code == "REGION_AMBIGUOUS"


def test_nonoperational_partition_is_discovery_only() -> None:
    unsupported = next(
        (
            item
            for item in _regions.region_registry(all_partitions=True)
            if not item.operational
        ),
        None,
    )
    if unsupported is None:
        pytest.skip("Bundled Botocore metadata has no non-operational partition")
    with pytest.raises(_regions.RegionError) as caught:
        _regions.resolve_region(unsupported.name)
    assert caught.value.code == "REGION_PARTITION_UNSUPPORTED"
    assert (
        _regions.resolve_region(unsupported.name, allow_non_operational=True).canonical
        == unsupported.name
    )
    with pytest.raises(_regions.RegionError) as alias_error:
        _regions.validate_custom_aliases({"isolated": {"region": unsupported.name}})
    assert alias_error.value.code == "REGION_PARTITION_UNSUPPORTED"


def test_interactive_repair_lists_and_retries() -> None:
    answers = iter(["?", "oregon"])
    output: list[str] = []

    result = _regions.resolve_region_input(
        "not-a-region",
        interactive=True,
        input_fn=lambda _prompt: next(answers),
        output_fn=lambda value: output.append(str(value)),
    )

    assert result.canonical == "us-west-2"
    assert any("Available regions" in line for line in output)


def test_interactive_cancel_eof_attempt_limit_and_default() -> None:
    defaulted = _regions.resolve_region_input(None, interactive=True, default="oregon")
    assert defaulted.canonical == "us-west-2"
    with pytest.raises(_regions.RegionError) as quit_error:
        _regions.resolve_region_input(
            None, interactive=True, input_fn=lambda _prompt: "quit"
        )
    assert quit_error.value.code == "REGION_CANCELLED"
    with pytest.raises(_regions.RegionError) as eof_error:
        _regions.resolve_region_input(
            None,
            interactive=True,
            input_fn=lambda _prompt: (_ for _ in ()).throw(EOFError),
        )
    assert eof_error.value.code == "REGION_CANCELLED"
    with pytest.raises(_regions.RegionError) as attempts_error:
        _regions.resolve_region_input(
            "bad",
            interactive=True,
            max_attempts=1,
            input_fn=lambda _prompt: "still-bad",
            output_fn=lambda _value: None,
        )
    assert attempts_error.value.code == "REGION_ATTEMPTS_EXCEEDED"


def test_noninteractive_error_is_structured() -> None:
    with pytest.raises(_regions.RegionError) as caught:
        _regions.resolve_region_input(None, interactive=False)

    assert caught.value.code == "REGION_REQUIRED"
    assert caught.value.data == {"code": "REGION_REQUIRED", "candidates": []}
    assert caught.value.repairs


def test_preference_order_and_environment_persistence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_REGION", "oregon")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "virginia")

    explicit = _regions.resolve_region_preference(
        explicit="ohio",
        target="us-east-1",
        destination="us-west-1",
    )
    environment = _regions.resolve_region_preference(destination="us-east-1")
    environment_without_destination = _regions.resolve_region_preference()

    assert (explicit.canonical, explicit.source) == ("us-east-2", "explicit")
    assert explicit.persist_to_destination is True
    assert (environment.canonical, environment.source) == (
        "us-west-2",
        "aws-region-env",
    )
    assert environment.persist_to_destination is False
    assert environment_without_destination.persist_to_destination is True


def test_preference_falls_through_to_prompt() -> None:
    with patch(
        "hacksaws._regions.resolve_region_input",
        return_value=_regions.resolve_region("oregon"),
    ) as prompt:
        preference = _regions.resolve_region_preference(interactive=True)
    assert preference.source == "prompt"
    assert preference.canonical == "us-west-2"
    prompt.assert_called_once()


def test_service_validation_and_canonical_deduplication() -> None:
    values = _regions.canonicalize_regions(
        ["oregon", "usw2", "virginia"], service="ecr"
    )

    assert tuple(item.canonical for item in values) == ("us-west-2", "us-east-1")
    with pytest.raises(_regions.RegionError) as unsupported:
        _regions.validate_service_region(
            _regions.resolve_region("ap-southeast-7"), "iam"
        )
    assert unsupported.value.code == "REGION_SERVICE_UNAVAILABLE"
    unknown = _regions.resolve_region("us-future-1", allow_unknown=True)
    assert (
        _regions.validate_service_region(unknown, "ecr", allow_unknown=True) is unknown
    )
    with pytest.raises(_regions.RegionError, match="Cannot verify"):
        _regions.validate_service_region(unknown, "ecr")
    assert (
        _regions.validate_service_region(
            _regions.resolve_region("us-east-1"), "signin"
        ).canonical
        == "us-east-1"
    )


def test_schema_persists_canonical_regions_and_alias_metadata(
    state_home: Path,
) -> None:
    data = _state.default_config()
    data["aws"] = {
        "region": "us-east-1",
        "region_aliases": {
            "pacific": {"region": "us-west-2", "description": "West coast"}
        },
    }
    data["accounts"]["Prod"] = {
        "id": "123456789012",
        "partition": "aws",
        "region": "us-east-2",
    }
    data["targets"]["Agent"] = {
        "source_account": "Prod",
        "source_profile": "admin",
        "source_location": "default",
        "region": "us-west-2",
    }

    _state.save_config(data)
    loaded = _state.load_config()

    assert loaded["aws"]["region"] == "us-east-1"
    assert loaded["accounts"]["Prod"]["region"] == "us-east-2"
    assert loaded["targets"]["Agent"]["region"] == "us-west-2"
    assert (state_home / "config.json").exists()


def test_config_export_import_preserves_canonical_region_configuration(
    state_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _state.default_config()
    data["aws"] = {
        "region": "us-east-1",
        "region_aliases": {"pacific": {"region": "us-west-2"}},
    }
    data["accounts"]["Prod"] = {
        "id": "123456789012",
        "partition": "aws",
        "region": "us-east-2",
    }
    data["targets"]["Agent"] = {
        "source_account": "Prod",
        "source_profile": "admin",
        "source_location": "default",
        "region": "us-west-2",
    }
    _state.save_config(data)
    archive = _sessions.export_config(str(tmp_path / "portable.zip"))

    imported_home = tmp_path / "imported"
    monkeypatch.setenv("HACKSAWS_HOME", str(imported_home))
    local = _state.default_config()
    local["aws"]["region"] = "us-west-1"
    _state.save_config(local)
    with pytest.raises(Exception, match="config:aws"):
        _sessions.import_config(archive, replace=False, yes=True)
    assert _state.load_config()["aws"]["region"] == "us-west-1"

    _sessions.import_config(archive, replace=True, yes=True)

    imported = _state.load_config()
    assert imported["aws"] == data["aws"]
    assert imported["accounts"]["Prod"]["region"] == "us-east-2"
    assert imported["targets"]["Agent"]["region"] == "us-west-2"


def test_schema_rejects_aliases_in_canonical_fields() -> None:
    data = _state.default_config()
    data["aws"]["region"] = "oregon"

    with pytest.raises(Exception, match="must store canonical region"):
        _state.save_config(data)

    data["aws"]["region"] = "US-WEST-2"
    with pytest.raises(Exception, match="must store canonical region"):
        _state.save_config(data)


def test_region_alias_cli_crud_and_explain(
    state_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    added = _cli.console_main(
        ["region", "alias", "add", "pacific", "oregon", "--description", "West"]
    )
    capsys.readouterr()
    explained = _cli.console_main(["region", "explain", "pacific", "--json"])
    rendered = json.loads(capsys.readouterr().out)

    assert added.code == "REGION_ALIAS_SAVED"
    assert explained.code == "REGION_EXPLAIN"
    assert rendered["data"]["region"] == "us-west-2"
    assert _state.load_config()["aws"]["region_aliases"]["pacific"] == {
        "region": "us-west-2",
        "description": "West",
    }
    assert (
        _cli.console_main(
            ["region", "alias", "rename", "pacific", "west-coast"]
        ).exit_code
        == 0
    )
    assert _cli.console_main(["region", "alias", "remove", "west-coast"]).exit_code == 0


def test_region_alias_cli_list_get_update_and_conflicts(
    state_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        _cli.console_main(
            ["region", "alias", "add", "pacific", "oregon", "--description", "West"]
        ).exit_code
        == 0
    )
    capsys.readouterr()

    listed = _cli.console_main(["region", "alias", "list", "pac*", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert listed.code == "REGION_ALIAS_LIST"
    assert payload["data"][0]["alias"] == "pacific"

    fetched = _cli.console_main(["region", "alias", "get", "PACIFIC", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert fetched.code == "REGION_ALIAS_GET"
    assert payload["data"]["description"] == "West"

    assert (
        _cli.console_main(
            ["region", "alias", "update", "pacific", "--region", "ohio"]
        ).exit_code
        == 0
    )
    assert _state.load_config()["aws"]["region_aliases"]["pacific"] == {
        "region": "us-east-2",
        "description": "West",
    }
    assert (
        _cli.console_main(
            ["region", "alias", "update", "pacific", "--clear-description"]
        ).exit_code
        == 0
    )
    assert _state.load_config()["aws"]["region_aliases"]["pacific"] == {
        "region": "us-east-2"
    }

    assert (
        _cli.console_main(["region", "alias", "add", "atlantic", "virginia"]).exit_code
        == 0
    )
    conflict = _cli.console_main(["region", "alias", "rename", "pacific", "atlantic"])
    invalid = _cli.console_main(["region", "alias", "add", "Bad Alias", "ohio"])
    missing = _cli.console_main(["region", "alias", "get", "missing"])
    assert conflict.code == "REGION_ALIAS_CONFLICT"
    assert invalid.code == "REGION_ALIAS_INVALID"
    assert missing.code == "REGION_ALIAS_NOT_FOUND"
    assert _cli.console_main(["region", "alias", "list", "atlantic"]).exit_code == 0
    duplicate = _cli.console_main(["region", "alias", "add", "atlantic", "us-east-2"])
    invalid_rename = _cli.console_main(
        ["region", "alias", "rename", "atlantic", "Bad Alias"]
    )
    assert duplicate.code == "REGION_ALIAS_CONFLICT"
    assert invalid_rename.code == "REGION_ALIAS_INVALID"


def test_region_list_scopes_filters_and_help(
    state_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = _state.default_config()
    data["accounts"]["Prod"] = {
        "id": "123456789012",
        "partition": "aws",
    }
    data["aws"]["region_aliases"]["pacific"] = {"region": "us-west-2"}
    _state.save_config(data)

    listed = _cli.console_main(
        ["region", "list", "pac*", "--account", "prod", "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert listed.code == "REGION_LIST"
    assert payload["data"] == [
        {
            "region": "us-west-2",
            "name": "US West (Oregon)",
            "partition": "aws",
            "operational": True,
            "compact": "usw2",
            "geography": ["oregon"],
            "custom": ["pacific"],
        }
    ]
    unknown = _cli.console_main(["region", "list", "--partition", "not-a-partition"])
    assert unknown.code == "REGION_PARTITION_UNKNOWN"
    assert _cli.console_main(["region"]).code == "REGION_HELP"
    assert _cli.console_main(["region", "alias"]).code == "REGION_ALIAS_HELP"
    assert _cli.console_main(["region", "list", "oregon"]).exit_code == 0


def test_account_target_and_config_region_cli_store_canonical_values(
    state_home: Path,
) -> None:
    assert (
        _cli.console_main(["region", "alias", "add", "pacific", "oregon"]).exit_code
        == 0
    )
    assert (
        _cli.console_main(
            [
                "account",
                "add",
                "Prod",
                "123456789012",
                "--partition",
                "aws",
                "--no-verify",
                "--region",
                "pacific",
            ]
        ).exit_code
        == 0
    )
    assert (
        _cli.console_main(
            [
                "target",
                "add",
                "Agent",
                "--source-account",
                "Prod",
                "--region",
                "virginia",
            ]
        ).exit_code
        == 0
    )
    assert _cli.console_main(["config", "set", "aws.region", "ohio"]).exit_code == 0

    loaded = _state.load_config()
    assert loaded["accounts"]["Prod"]["region"] == "us-west-2"
    assert loaded["targets"]["Agent"]["region"] == "us-east-1"
    assert loaded["aws"]["region"] == "us-east-2"

    assert (
        _cli.console_main(
            ["account", "update", "Prod", "--region", "ohio", "--no-verify"]
        ).exit_code
        == 0
    )
    assert (
        _cli.console_main(["target", "update", "Agent", "--region", "oregon"]).exit_code
        == 0
    )
    loaded = _state.load_config()
    assert loaded["accounts"]["Prod"]["region"] == "us-east-2"
    assert loaded["targets"]["Agent"]["region"] == "us-west-2"

    assert (
        _cli.console_main(
            ["account", "update", "Prod", "--clear-region", "--no-verify"]
        ).exit_code
        == 0
    )
    assert (
        _cli.console_main(["target", "update", "Agent", "--clear-region"]).exit_code
        == 0
    )
    loaded = _state.load_config()
    assert "region" not in loaded["accounts"]["Prod"]
    assert "region" not in loaded["targets"]["Agent"]


def test_config_option_alias_crud_uses_canonical_target(state_home: Path) -> None:
    region_key = "aws.region_aliases.pacific.region"
    description_key = "aws.region_aliases.pacific.description"

    assert _cli.console_main(["config", "set", region_key, "oregon"]).exit_code == 0
    assert (
        _cli.console_main(
            ["config", "option", "set", description_key, "West"]
        ).exit_code
        == 0
    )
    assert _state.load_config()["aws"]["region_aliases"]["pacific"] == {
        "region": "us-west-2",
        "description": "West",
    }
    assert _cli.console_main(["config", "reset", description_key]).exit_code == 0
    assert _cli.console_main(["config", "reset", region_key]).exit_code == 0
    assert _state.load_config()["aws"]["region_aliases"] == {}


def test_direct_region_config_options_and_teaching_commands(
    state_home: Path,
) -> None:
    data = _state.default_config()
    data["accounts"]["Prod"] = {"id": "123456789012", "partition": "aws"}
    data["targets"]["Agent"] = {
        "source_account": "Prod",
        "source_profile": "admin",
        "source_location": "default",
    }
    _state.save_config(data)

    assert (
        _cli.console_main(["config", "set", "accounts.Prod.region", "oregon"]).exit_code
        == 0
    )
    assert (
        _cli.console_main(["config", "set", "targets.Agent.region", "ohio"]).exit_code
        == 0
    )
    assert _cli.console_main(["config", "get", "aws.region"]).exit_code == 0
    assert _cli.console_main(["config", "option", "list"]).exit_code == 0
    assert (
        _cli.console_main(["config", "option", "explain", "aws.region"]).exit_code == 0
    )
    assert (
        _cli.console_main(["config", "option", "explain", "unknown.setting"]).exit_code
        != 0
    )
    assert _cli.console_main(["config", "option"]).code == "CONFIG_OPTION_HELP"
    assert _cli.console_main(["config", "set", "aws.region", "null"]).exit_code == 0

    loaded = _state.load_config()
    assert loaded["accounts"]["Prod"]["region"] == "us-west-2"
    assert loaded["targets"]["Agent"]["region"] == "us-east-2"
    assert loaded["aws"]["region"] is None


def test_unknown_config_region_requires_explicit_escape(state_home: Path) -> None:
    refused = _cli.console_main(["config", "set", "aws.region", "us-future-1"])
    accepted = _cli.console_main(
        [
            "config",
            "set",
            "aws.region",
            "us-future-1",
            "--allow-unknown-region",
        ]
    )

    assert refused.code == "REGION_UNKNOWN"
    assert accepted.exit_code == 0
    assert _state.load_config()["aws"]["region"] == "us-future-1"


def test_region_cli_reports_specific_error_code(
    state_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = _cli.console_main(["region", "explain", "future-west", "--json"])
    rendered = json.loads(capsys.readouterr().err)

    assert result.code == "REGION_INVALID"
    assert rendered["code"] == "REGION_INVALID"
    assert rendered["error"]["data"]["code"] == "REGION_INVALID"
    assert rendered["error"]["data"]["candidates"]
    assert rendered["error"]["repairs"]


def test_region_parser_help_documents_unknown_escape() -> None:
    parser = _cli._create_parser()
    with patch("sys.stdout") as stdout, pytest.raises(SystemExit):
        parser.parse_args(["region", "explain", "--help"])
    assert "--allow-unknown-region" in "".join(
        str(call.args[0]) for call in stdout.write.call_args_list if call.args
    )

    with patch("sys.stdout") as stdout, pytest.raises(SystemExit):
        parser.parse_args(["profile", "region", "set", "--help"])
    profile_help = "".join(
        str(call.args[0]) for call in stdout.write.call_args_list if call.args
    )
    assert "Canonical region or compact, geography, or custom alias" in " ".join(
        profile_help.split()
    )

    with pytest.raises(SystemExit):
        parser.parse_args(
            ["target", "update", "Agent", "--region", "oregon", "--clear-region"]
        )
