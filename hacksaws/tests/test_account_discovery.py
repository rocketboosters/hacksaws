"""Security and behavior tests for intermediate account discovery."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.exceptions import EndpointConnectionError

from hacksaws import _account_discovery
from hacksaws import _configs
from hacksaws import _state

SOURCE_ID = "111111111111"
TARGET_ID = "222222222222"


class _Paginator:
    def __init__(self, pages: object) -> None:
        self.pages = pages

    def paginate(self) -> object:
        if isinstance(self.pages, BaseException):
            raise self.pages
        return self.pages


@dataclass
class _Sts:
    account_id: str = SOURCE_ID
    partition: str = "aws"
    error: BaseException | None = None

    def get_caller_identity(self) -> dict[str, str]:
        if self.error:
            raise self.error
        return {
            "Account": self.account_id,
            "Arn": f"arn:{self.partition}:iam::{self.account_id}:user/test",
            "UserId": "not-persisted",
        }


@dataclass
class _RawSts:
    response: object

    def get_caller_identity(self) -> object:
        return self.response


@dataclass
class _Iam:
    pages: object

    def get_paginator(self, operation: str) -> _Paginator:
        assert operation == "list_account_aliases"
        return _Paginator(self.pages)


@dataclass
class _Account:
    response: object
    calls: list[dict[str, str]]

    def get_account_information(self, **kwargs: str) -> object:
        self.calls.append(kwargs)
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


@dataclass
class _Organizations:
    response: object
    calls: list[str]

    def describe_account(self, *, AccountId: str) -> object:
        self.calls.append(AccountId)
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


class _Session:
    def __init__(self, **clients: object) -> None:
        self.clients = clients
        self.calls: list[str] = []
        self.configs: list[object] = []

    def client(self, service_name: str, **kwargs: object) -> object:
        self.calls.append(service_name)
        self.configs.append(kwargs.get("config"))
        return self.clients[service_name]


def error(
    code: str, message: str = "secret request-id email@example.com"
) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": message},
        },
        "OptionalLookup",
    )


def configured() -> dict[str, object]:
    return _state.default_config()


def same_account_session(
    *,
    pages: object | None = None,
    account_response: object | None = None,
    partition: str = "aws",
) -> _Session:
    return _Session(
        sts=_Sts(partition=partition),
        iam=_Iam([{"AccountAliases": ["source-alias"]}] if pages is None else pages),
        account=_Account(
            {"AccountId": SOURCE_ID, "AccountName": "Source Production"}
            if account_response is None
            else account_response,
            [],
        ),
    )


def test_same_account_uses_paginated_alias_for_key_and_account_name_for_display() -> (
    None
):
    session = same_account_session(
        pages=[{"AccountAliases": []}, {"AccountAliases": ["source-alias"]}]
    )

    result = _account_discovery.discover_account(session, configured())

    assert result.account_id == SOURCE_ID
    assert result.partition == "aws"
    assert result.key == "source-alias"
    assert result.key_source == "iam-alias"
    assert result.display_name == "Source Production"
    assert result.display_source == "account-name"
    assert result.identity.verified is True
    assert result.account_record() == {
        "id": SOURCE_ID,
        "partition": "aws",
        "display_name": "Source Production",
        "display_source": "account-name",
    }
    assert session.calls == ["sts", "iam", "account"]
    assert all(
        isinstance(config, Config)
        and getattr(config, "retries", {}).get("mode") == "standard"
        for config in session.configs
    )


def test_explicit_key_skips_optional_providers_and_collision_uses_full_id() -> None:
    config = configured()
    config["accounts"] = {
        "Production": {"id": TARGET_ID, "partition": "aws"},
    }
    session = _Session(sts=_Sts())

    result = _account_discovery.discover_account(
        session,
        config,
        explicit_name="Production",
    )

    assert result.key == f"Production-{SOURCE_ID}"
    assert result.key_source == "user"
    assert result.display_name == "Production"
    assert result.display_source == "user"
    assert result.notices[0].reason == "collision"
    assert session.calls == ["sts"]


def test_existing_identity_is_stable_and_user_display_is_never_overwritten() -> None:
    config = configured()
    existing = {
        "id": SOURCE_ID,
        "partition": "aws",
        "display_name": "My Production",
        "display_source": "user",
        "description": "keep",
    }
    config["accounts"] = {"StableKey": existing}
    session = _Session(sts=_Sts())

    result = _account_discovery.discover_account(
        session,
        config,
        explicit_name="IgnoredRename",
    )

    assert result.key == "StableKey"
    assert result.key_source == "existing"
    assert result.display_name == "My Production"
    assert result.display_source == "user"
    assert result.account_record() == existing
    assert session.calls == ["sts"]


def test_cross_account_uses_only_intermediate_organizations_lookup() -> None:
    organizations = _Organizations(
        {
            "Account": {
                "Id": TARGET_ID,
                "Name": "Target / Production",
                "Email": "must-not-persist@example.com",
            }
        },
        [],
    )
    session = _Session(sts=_Sts(), organizations=organizations)

    result = _account_discovery.discover_account(
        session,
        configured(),
        role_arn=f"arn:aws:iam::{TARGET_ID}:role/AgentSession",
    )

    assert result.source_identity.account_id == SOURCE_ID
    assert result.account_id == TARGET_ID
    assert result.key == "target-production"
    assert result.display_name == "Target / Production"
    assert result.display_source == "organizations"
    assert result.identity.verified is False
    assert result.account_record()["unverified"] is True
    assert organizations.calls == [TARGET_ID]
    assert session.calls == ["sts", "organizations"]
    assert "Email" not in str(result.as_dict())


def test_cross_account_optional_account_api_is_explicit_and_uses_target_id() -> None:
    organizations = _Organizations(error("AccessDeniedException"), [])
    account = _Account({"AccountName": "Target Fallback"}, [])
    session = _Session(sts=_Sts(), organizations=organizations, account=account)

    result = _account_discovery.discover_account(
        session,
        configured(),
        role_arn=f"arn:aws:iam::{TARGET_ID}:role/AgentSession",
        allow_cross_account_api=True,
    )

    assert result.key == "target-fallback"
    assert result.display_source == "account-name"
    assert account.calls == [{"AccountId": TARGET_ID}]
    assert [notice.reason for notice in result.notices] == ["denied"]


@pytest.mark.parametrize(
    ("code", "reason"),
    [
        ("AccessDenied", "denied"),
        ("AccessDeniedException", "denied"),
        ("AWSOrganizationsNotInUseException", "unavailable"),
        ("AccountNotFoundException", "unavailable"),
        ("TooManyRequestsException", "throttled"),
        ("ThrottlingException", "throttled"),
        ("ServiceException", "service-error"),
    ],
)
def test_provider_error_matrix_is_sanitized(code: str, reason: str) -> None:
    session = same_account_session(
        pages=error(code),
        account_response=error(code),
    )

    result = _account_discovery.discover_account(session, configured())

    assert result.key == f"account-{SOURCE_ID}"
    assert [notice.reason for notice in result.notices] == [reason, reason]
    rendered = str(result.as_dict())
    assert "secret" not in rendered
    assert "request-id" not in rendered
    assert "example.com" not in rendered


def test_transport_failure_is_nonfatal_for_optional_sources() -> None:
    unavailable = EndpointConnectionError(endpoint_url="https://not-shown.invalid")
    session = same_account_session(pages=unavailable, account_response=unavailable)

    result = _account_discovery.discover_account(session, configured())

    assert result.key == f"account-{SOURCE_ID}"
    assert {notice.reason for notice in result.notices} == {"service-error"}
    assert "not-shown" not in str(result.as_dict())


@pytest.mark.parametrize(
    "pages",
    [
        [{"AccountAliases": ["one", "two"]}],
        [{"AccountAliases": "not-a-list"}],
        ["not-a-page"],
        [{"AccountAliases": ["bad\x1b[31m/alias"]}],
    ],
)
def test_malformed_aliases_are_ignored(pages: object) -> None:
    session = same_account_session(
        pages=pages,
        account_response={"AccountName": "Safe Account"},
    )

    result = _account_discovery.discover_account(session, configured())

    assert result.key == "safe-account"
    assert result.notices[0].reason == "invalid-response"


def test_untrusted_account_name_is_terminal_safe_and_slugged() -> None:
    session = same_account_session(
        pages=[{"AccountAliases": []}],
        account_response={"AccountName": "\x1b[31mPrød\u202e\n / Billing\x00 Account"},
    )

    result = _account_discovery.discover_account(session, configured())

    assert result.display_name == "Prød / Billing Account"
    assert result.key == "prd-billing-account"
    assert "\x1b" not in str(result.as_dict())
    assert "\u202e" not in str(result.as_dict())


def test_missing_names_fall_back_to_account_id_without_failure() -> None:
    session = same_account_session(
        pages=[{"AccountAliases": []}], account_response={"AccountName": None}
    )

    result = _account_discovery.discover_account(session, configured())

    assert result.key == f"account-{SOURCE_ID}"
    assert result.key_source == "account-id"
    assert result.display_source == "account-id"
    assert result.notices[0].provider == "account"


def test_cross_account_does_not_fall_back_to_source_alias_or_account_api() -> None:
    session = _Session(
        sts=_Sts(),
        organizations=_Organizations(error("AccessDeniedException"), []),
        iam=_Iam([{"AccountAliases": ["source-alias"]}]),
        account=_Account({"AccountName": "Source Name"}, []),
    )

    result = _account_discovery.discover_account(
        session,
        configured(),
        role_arn=f"arn:aws:iam::{TARGET_ID}:role/AgentSession",
    )

    assert result.key == f"account-{TARGET_ID}"
    assert session.calls == ["sts", "organizations"]


def test_account_record_can_be_marked_verified_after_role_identity_check() -> None:
    session = _Session(
        sts=_Sts(),
        organizations=_Organizations(
            {"Account": {"Id": TARGET_ID, "Name": "Target"}}, []
        ),
    )
    result = _account_discovery.discover_account(
        session,
        configured(),
        role_arn=f"arn:aws:iam::{TARGET_ID}:role/AgentSession",
    )

    assert "unverified" not in result.account_record(verified=True)


def test_same_account_partition_is_taken_from_sts_arn() -> None:
    session = same_account_session(partition="aws-cn")

    result = _account_discovery.discover_account(session, configured())

    assert result.partition == "aws-cn"


def test_cross_partition_role_is_rejected_before_optional_lookups() -> None:
    session = _Session(sts=_Sts())

    with pytest.raises(_configs.OperationalError, match="partition"):
        _account_discovery.discover_account(
            session,
            configured(),
            role_arn=f"arn:aws-cn:iam::{TARGET_ID}:role/AgentSession",
        )
    assert session.calls == ["sts"]


def test_sts_errors_and_malformed_identity_are_sanitized() -> None:
    session = _Session(sts=_Sts(error=error("AccessDenied", "do-not-show")))
    with pytest.raises(_configs.OperationalError) as failure:
        _account_discovery.discover_account(session, configured())
    assert "do-not-show" not in str(failure.value)

    malformed = _Session(sts=_Sts(account_id="invalid"))
    with pytest.raises(_configs.OperationalError, match="account ID"):
        _account_discovery.discover_account(malformed, configured())


@pytest.mark.parametrize(
    ("response", "message"),
    [
        ([], "invalid intermediate identity"),
        ({"Account": SOURCE_ID}, "identity ARN"),
        ({"Account": SOURCE_ID, "Arn": "not-an-arn"}, "identity ARN"),
    ],
)
def test_malformed_sts_response_shapes_are_rejected(
    response: object, message: str
) -> None:
    session = _Session(sts=_RawSts(response))
    with pytest.raises(_configs.OperationalError, match=message):
        _account_discovery.discover_account(session, configured())


def test_discovery_rejects_invalid_or_ambiguous_account_collections() -> None:
    session = _Session(sts=_Sts())
    with pytest.raises(_configs.OperationalError, match="accounts must be"):
        _account_discovery.discover_account(session, {"accounts": []})

    duplicates = configured()
    duplicates["accounts"] = {
        "One": {"id": SOURCE_ID, "partition": "aws"},
        "Two": {"id": SOURCE_ID, "partition": "aws"},
    }
    with pytest.raises(_configs.OperationalError, match="multiple names"):
        _account_discovery.discover_account(_Session(sts=_Sts()), duplicates)


def test_optional_provider_response_shapes_are_best_effort() -> None:
    same = same_account_session(account_response=[])
    same_result = _account_discovery.discover_account(same, configured())
    assert same_result.display_name == "source-alias"
    assert same_result.notices[0].provider == "account"

    for response in (
        {},
        {"Account": {"Id": SOURCE_ID, "Name": "Wrong"}},
        {"Account": {"Id": TARGET_ID}},
    ):
        session = _Session(sts=_Sts(), organizations=_Organizations(response, []))
        result = _account_discovery.discover_account(
            session,
            configured(),
            role_arn=f"arn:aws:iam::{TARGET_ID}:role/AgentSession",
        )
        assert result.key == f"account-{TARGET_ID}"
        assert result.notices[0].reason == "invalid-response"


def test_unique_key_defensively_rejects_exhausted_collision_forms() -> None:
    config = configured()
    config["accounts"] = {
        "prod": {"id": "333333333333", "partition": "aws"},
        f"prod-{SOURCE_ID}": {"id": "444444444444", "partition": "aws"},
        f"prod-aws-{SOURCE_ID}": {"id": "555555555555", "partition": "aws"},
    }
    identity = _account_discovery.AccountIdentity(
        partition="aws",
        account_id=SOURCE_ID,
        arn=f"arn:aws:iam::{SOURCE_ID}:user/test",
        verified=True,
    )
    with pytest.raises(_configs.OperationalError, match="unique account key"):
        _account_discovery._unique_key(config, "prod", identity)

    with pytest.raises(_configs.OperationalError, match="accounts must be"):
        _account_discovery._unique_key({"accounts": []}, "prod", identity)


@pytest.mark.parametrize(
    "record",
    [
        {
            "id": SOURCE_ID,
            "partition": "aws",
            "display_name": "Missing Source",
        },
        {
            "id": SOURCE_ID,
            "partition": "aws",
            "display_source": "user",
        },
        {
            "id": SOURCE_ID,
            "partition": "aws",
            "display_name": "Unsafe\nName",
            "display_source": "user",
        },
        {
            "id": SOURCE_ID,
            "partition": "aws",
            "display_name": "Name",
            "display_source": "unknown",
        },
    ],
)
def test_account_display_schema_rejects_invalid_metadata(
    record: dict[str, str],
) -> None:
    config = _state.default_config()
    config["accounts"]["Bad"] = record
    with pytest.raises(_configs.OperationalError):
        _state._validate_config(config)


def test_account_schema_rejects_duplicate_stable_identity() -> None:
    config = _state.default_config()
    config["accounts"] = {
        "One": {"id": SOURCE_ID, "partition": "aws"},
        "Two": {"id": SOURCE_ID, "partition": "aws"},
    }
    with pytest.raises(_configs.OperationalError, match="same AWS identity"):
        _state._validate_config(config)


def test_partition_collision_suffix_remains_deterministic() -> None:
    config = configured()
    config["accounts"] = {
        "prod": {"id": "999999999999", "partition": "aws"},
        f"prod-{SOURCE_ID}": {"id": SOURCE_ID, "partition": "aws-cn"},
    }
    session = _Session(
        sts=_Sts(),
        iam=_Iam([{"AccountAliases": ["prod"]}]),
        account=_Account({}, []),
    )

    result = _account_discovery.discover_account(session, config)

    assert result.key == f"prod-aws-{SOURCE_ID}"
