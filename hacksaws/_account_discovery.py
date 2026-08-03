"""Best-effort AWS account metadata discovery using intermediate credentials."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from typing import Literal
from typing import Protocol

from botocore.config import Config
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from hacksaws import _state
from hacksaws._configs import OperationalError

LabelSource = Literal[
    "user",
    "existing",
    "iam-alias",
    "account-name",
    "organizations",
    "account-id",
]
NoticeReason = Literal[
    "denied",
    "unavailable",
    "throttled",
    "service-error",
    "invalid-response",
    "collision",
]
Provider = Literal["iam", "account", "organizations", "config"]

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_THROTTLING_CODES = {
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "RequestLimitExceeded",
}
_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "AuthorizationError",
    "UnauthorizedException",
}
_UNAVAILABLE_CODES = {
    "AccountNotFoundException",
    "AWSOrganizationsNotInUseException",
    "ResourceNotFoundException",
}
_CLIENT_CONFIG = Config(
    retries={"mode": "standard", "total_max_attempts": 3},
)
_ARN_PARTS = 3
_MAX_ALIAS_PAGES = 10


class IntermediateSession(Protocol):
    """Minimum boto3-compatible session surface used during discovery."""

    def client(self, service_name: str, **kwargs: object) -> Any:
        """Create an AWS service client."""


@dataclass(frozen=True, slots=True)
class AccountIdentity:
    """Stable AWS account identity independent of mutable friendly labels."""

    partition: str
    account_id: str
    arn: str
    verified: bool


@dataclass(frozen=True, slots=True)
class AccountDiscoveryNotice:
    """Sanitized non-fatal provider or naming notice."""

    provider: Provider
    reason: NoticeReason
    message: str

    def as_dict(self) -> dict[str, str]:
        """Return a stable machine-output adapter with no AWS exception details."""
        return {
            "provider": self.provider,
            "reason": self.reason,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class AccountDiscovery:
    """Resolved account key, identity, display metadata, and non-fatal notices."""

    identity: AccountIdentity
    source_identity: AccountIdentity
    key: str
    key_source: LabelSource
    display_name: str
    display_source: LabelSource
    existing: bool
    notices: tuple[AccountDiscoveryNotice, ...] = ()
    _existing_record: Mapping[str, object] | None = None

    @property
    def account_id(self) -> str:
        """Return the resolved account ID for integration adapters."""
        return self.identity.account_id

    @property
    def partition(self) -> str:
        """Return the resolved AWS partition for integration adapters."""
        return self.identity.partition

    def account_record(self, *, verified: bool | None = None) -> dict[str, object]:
        """Return schema-safe persistent metadata, excluding transient notices."""
        if self._existing_record is not None:
            record = dict(self._existing_record)
        else:
            record = {
                "id": self.account_id,
                "partition": self.partition,
                "display_name": self.display_name,
                "display_source": self.display_source,
            }
        is_verified = self.identity.verified if verified is None else verified
        if is_verified:
            record.pop("unverified", None)
        else:
            record["unverified"] = True
        return record

    def as_dict(self) -> dict[str, object]:
        """Return a typed operational-output adapter without provider payloads."""
        return {
            "accountId": self.account_id,
            "partition": self.partition,
            "key": self.key,
            "keySource": self.key_source,
            "displayName": self.display_name,
            "displaySource": self.display_source,
            "existing": self.existing,
            "verified": self.identity.verified,
            "notices": [notice.as_dict() for notice in self.notices],
        }


def _safe_display(value: object) -> str | None:
    """Normalize untrusted provider text for terminal and config display."""
    if not isinstance(value, str):
        return None
    without_ansi = _ANSI_RE.sub("", value)
    characters = (
        " " if unicodedata.category(character).startswith("C") else character
        for character in without_ansi
    )
    normalized = " ".join("".join(characters).split())
    return normalized[:128].rstrip() or None


def _slug(value: str) -> str | None:
    """Convert safe display text to a portable Hacksaws resource key."""
    ascii_value = (
        unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    )
    slug = _SLUG_RE.sub("-", ascii_value.casefold()).strip("-")
    return slug[:64].rstrip("-") or None


def _notice(provider: Provider, error: BaseException) -> AccountDiscoveryNotice:
    """Classify an AWS provider failure without leaking its raw response."""
    reason: NoticeReason = "service-error"
    if isinstance(error, ClientError):
        response = error.response if isinstance(error.response, dict) else {}
        error_data = response.get("Error", {})
        code = error_data.get("Code") if isinstance(error_data, dict) else None
        if code in _DENIED_CODES:
            reason = "denied"
        elif code in _UNAVAILABLE_CODES:
            reason = "unavailable"
        elif code in _THROTTLING_CODES:
            reason = "throttled"
    messages = {
        "denied": "AWS did not allow this optional account-name lookup.",
        "unavailable": "This optional AWS account-name source is unavailable.",
        "throttled": "AWS throttled this optional account-name lookup.",
        "service-error": "AWS could not complete this optional account-name lookup.",
        "invalid-response": "AWS returned unusable optional account-name metadata.",
        "collision": (
            "The discovered account key was disambiguated with its account ID."
        ),
    }
    return AccountDiscoveryNotice(provider, reason, messages[reason])


def _invalid_response(provider: Provider) -> AccountDiscoveryNotice:
    return AccountDiscoveryNotice(
        provider,
        "invalid-response",
        "AWS returned unusable optional account-name metadata.",
    )


def _client(session: IntermediateSession, service: str) -> Any:
    """Create a retry-configured client, tolerating minimal session adapters.

    Real boto3 sessions accept ``config``.  The small session adapters used by
    embedders and tests sometimes intentionally expose only ``client(name)``;
    retaining that compatibility keeps account registration best-effort and
    prevents it from affecting a successful credential exchange.
    """
    try:
        return session.client(service, config=_CLIENT_CONFIG)
    except TypeError:
        return session.client(service)


def _source_identity(session: IntermediateSession) -> AccountIdentity:
    """Verify the intermediate caller; this is the only required discovery call."""
    try:
        response = _client(session, "sts").get_caller_identity()
    except (AttributeError, BotoCoreError, ClientError, KeyError, TypeError) as error:
        raise OperationalError(
            "Unable to verify the intermediate AWS account identity."
        ) from error
    if not isinstance(response, Mapping):
        raise OperationalError("AWS returned an invalid intermediate identity.")
    account_id = response.get("Account")
    arn = response.get("Arn")
    if not isinstance(account_id, str) or not re.fullmatch(r"\d{12}", account_id):
        raise OperationalError("AWS returned an invalid intermediate account ID.")
    if not isinstance(arn, str):
        raise OperationalError("AWS returned an invalid intermediate identity ARN.")
    parts = arn.split(":", 2)
    if (
        len(parts) != _ARN_PARTS
        or parts[0] != "arn"
        or parts[1] not in _state.PARTITIONS
    ):
        raise OperationalError("AWS returned an invalid intermediate identity ARN.")
    return AccountIdentity(
        partition=parts[1], account_id=account_id, arn=arn, verified=True
    )


def _target_identity(source: AccountIdentity, role_arn: str | None) -> AccountIdentity:
    if role_arn is None:
        return source
    partition, account_id, _ = _state.parse_role_arn(role_arn)
    if partition != source.partition:
        raise OperationalError(
            "Role ARN partition does not match the intermediate AWS identity."
        )
    return AccountIdentity(
        partition=partition,
        account_id=account_id,
        arn=role_arn,
        verified=account_id == source.account_id,
    )


def _existing_account(
    config: Mapping[str, object], identity: AccountIdentity
) -> tuple[str, Mapping[str, object]] | None:
    accounts = config.get("accounts", {})
    if not isinstance(accounts, Mapping):
        raise OperationalError("Config accounts must be an object.")
    matches = [
        (name, record)
        for name, record in accounts.items()
        if isinstance(name, str)
        and isinstance(record, Mapping)
        and record.get("id") == identity.account_id
        and record.get("partition") == identity.partition
    ]
    if len(matches) > 1:
        raise OperationalError(
            "Configuration contains multiple names for the same AWS account identity."
        )
    return matches[0] if matches else None


def _iam_alias(
    session: IntermediateSession,
) -> tuple[str | None, list[AccountDiscoveryNotice]]:
    notices: list[AccountDiscoveryNotice] = []
    aliases: list[str] = []
    try:
        pages = _client(session, "iam").get_paginator("list_account_aliases").paginate()
        for index, page in enumerate(pages):
            if index >= _MAX_ALIAS_PAGES or not isinstance(page, Mapping):
                notices.append(_invalid_response("iam"))
                return None, notices
            values = page.get("AccountAliases", [])
            if not isinstance(values, list) or any(
                not isinstance(value, str) for value in values
            ):
                notices.append(_invalid_response("iam"))
                return None, notices
            aliases.extend(values)
    except (BotoCoreError, ClientError) as error:
        notices.append(_notice("iam", error))
        return None, notices
    if not aliases:
        return None, notices
    if len(aliases) != 1:
        notices.append(_invalid_response("iam"))
        return None, notices
    alias = _safe_display(aliases[0])
    if alias is None or not _state.NAME_RE.fullmatch(alias):
        notices.append(_invalid_response("iam"))
        return None, notices
    return alias, notices


def _account_name(
    session: IntermediateSession, *, account_id: str | None = None
) -> tuple[str | None, list[AccountDiscoveryNotice]]:
    notices: list[AccountDiscoveryNotice] = []
    try:
        client = _client(session, "account")
        response = (
            client.get_account_information(AccountId=account_id)
            if account_id is not None
            else client.get_account_information()
        )
    except (BotoCoreError, ClientError) as error:
        notices.append(_notice("account", error))
        return None, notices
    if not isinstance(response, Mapping):
        notices.append(_invalid_response("account"))
        return None, notices
    name = _safe_display(response.get("AccountName"))
    if name is None:
        notices.append(_invalid_response("account"))
    return name, notices


def _organization_name(
    session: IntermediateSession, account_id: str
) -> tuple[str | None, list[AccountDiscoveryNotice]]:
    notices: list[AccountDiscoveryNotice] = []
    try:
        response = _client(session, "organizations").describe_account(
            AccountId=account_id
        )
    except (BotoCoreError, ClientError) as error:
        notices.append(_notice("organizations", error))
        return None, notices
    if not isinstance(response, Mapping) or not isinstance(
        response.get("Account"), Mapping
    ):
        notices.append(_invalid_response("organizations"))
        return None, notices
    account = response["Account"]
    if account.get("Id") not in {None, account_id}:
        notices.append(_invalid_response("organizations"))
        return None, notices
    name = _safe_display(account.get("Name"))
    if name is None:
        notices.append(_invalid_response("organizations"))
    return name, notices


def _unique_key(
    config: Mapping[str, object], candidate: str, identity: AccountIdentity
) -> tuple[str, AccountDiscoveryNotice | None]:
    accounts = config.get("accounts", {})
    if not isinstance(accounts, Mapping):
        raise OperationalError("Config accounts must be an object.")
    folded = {str(name).casefold() for name in accounts}
    if candidate.casefold() not in folded:
        return candidate, None
    suffix = f"-{identity.account_id}"
    disambiguated = f"{candidate[: 64 - len(suffix)].rstrip('-')}{suffix}"
    if disambiguated.casefold() in folded:
        partition_suffix = f"-{identity.partition}-{identity.account_id}"
        disambiguated = (
            f"{candidate[: 64 - len(partition_suffix)].rstrip('-')}{partition_suffix}"
        )
    if disambiguated.casefold() in folded:
        raise OperationalError(
            "Unable to derive a unique account key from the verified AWS identity."
        )
    return disambiguated, AccountDiscoveryNotice(
        "config",
        "collision",
        "The discovered account key was disambiguated with its account ID.",
    )


def discover_account(
    session: IntermediateSession,
    config: Mapping[str, object],
    *,
    explicit_name: str | None = None,
    role_arn: str | None = None,
    allow_cross_account_api: bool = False,
) -> AccountDiscovery:
    """Discover one account using only the supplied intermediate credentials."""
    source = _source_identity(session)
    identity = _target_identity(source, role_arn)
    existing = _existing_account(config, identity)
    if existing is not None:
        key, record = existing
        display = _safe_display(record.get("display_name")) or key
        source_value = record.get("display_source", "existing")
        existing_display_source: LabelSource = (
            source_value
            if source_value
            in {
                "user",
                "iam-alias",
                "account-name",
                "organizations",
                "account-id",
            }
            else "existing"
        )
        return AccountDiscovery(
            identity=identity,
            source_identity=source,
            key=key,
            key_source="existing",
            display_name=display,
            display_source=existing_display_source,
            existing=True,
            _existing_record=record,
        )

    if explicit_name is not None:
        candidate = _state.validate_name(explicit_name, kind="account")
        key, collision = _unique_key(config, candidate, identity)
        explicit_notices = (collision,) if collision is not None else ()
        return AccountDiscovery(
            identity=identity,
            source_identity=source,
            key=key,
            key_source="user",
            display_name=candidate,
            display_source="user",
            existing=False,
            notices=explicit_notices,
        )

    notices: list[AccountDiscoveryNotice] = []
    alias: str | None = None
    account_name: str | None = None
    account_name_source: LabelSource = "account-name"
    if identity.account_id == source.account_id:
        alias, provider_notices = _iam_alias(session)
        notices.extend(provider_notices)
        account_name, provider_notices = _account_name(session)
        notices.extend(provider_notices)
    else:
        account_name, provider_notices = _organization_name(
            session, identity.account_id
        )
        notices.extend(provider_notices)
        account_name_source = "organizations"
        if account_name is None and allow_cross_account_api:
            account_name, provider_notices = _account_name(
                session, account_id=identity.account_id
            )
            notices.extend(provider_notices)
            account_name_source = "account-name"

    slug = _slug(account_name) if account_name else None
    candidate = alias or slug or f"account-{identity.account_id}"
    key_source: LabelSource = (
        "iam-alias" if alias else account_name_source if slug else "account-id"
    )
    display = account_name or alias or candidate
    display_source: LabelSource = (
        account_name_source if account_name else "iam-alias" if alias else "account-id"
    )
    key, collision = _unique_key(config, candidate, identity)
    if collision is not None:
        notices.append(collision)
    return AccountDiscovery(
        identity=identity,
        source_identity=source,
        key=key,
        key_source=key_source,
        display_name=display,
        display_source=display_source,
        existing=False,
        notices=tuple(notices),
    )
