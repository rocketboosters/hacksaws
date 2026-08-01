# Hacksaws

[![Checks](https://github.com/rocketboosters/hacksaws/actions/workflows/checks.yaml/badge.svg)](https://github.com/rocketboosters/hacksaws/actions/workflows/checks.yaml)
[![PyPI version](https://img.shields.io/pypi/v/hacksaws.svg)](https://pypi.org/project/hacksaws/)
[![License](https://img.shields.io/pypi/l/hacksaws.svg)](https://github.com/rocketboosters/hacksaws/blob/main/LICENSE)

Hacksaws is an AWS credential switcher and **agentic blast-radius manager**. It
can obtain credentials with MFA or AWS CLI browser sign-in, then optionally
assumes one deliberately constrained role and installs those credentials only at
an explicit destination profile. The intended contract is simple: automation
receives the smallest practical permission set, for a bounded time, in a
location you chose. A saved target is a secure preset, not a loose collection of
defaults; it cannot be overridden at login time.

The only supported executable is `hacksaws`. See [CHEATSHEET.md](CHEATSHEET.md)
for the compact command reference.

## Install

```shell
uv tool install hacksaws
# or
python -m pip install hacksaws
```

Hacksaws requires Python 3.13 or 3.14. Browser sign-in requires AWS CLI **v2.32
or newer** on `PATH`.

## Security model and local secrets

Hacksaws has three useful credential tiers:

1. **Native/source credentials** — the profile’s original static, SSO,
   credential-process, or AWS CLI browser-login credentials. These are broad
   enough to start the flow and may have an unbounded provider-controlled
   lifetime.
2. **MFA intermediate credentials** — `hacksaws mfa login` exchanges static
   source keys for an STS session (`--lifespan`, default 12 hours). When a role
   boundary is requested, these are only an intermediate credential tier.
3. **Boundary credentials** — an STS `AssumeRole` session for the selected role,
   optionally reduced further by a session policy and bounded by the selected
   duration. This is what is written to the destination profile for the agent or
   tool.

Browser login has two related lifecycles. Without a role, `pk`/`web` leaves AWS
CLI’s native browser credentials in their normal, provider-controlled lifecycle;
Hacksaws cannot truthfully shorten or attest their lifetime. With a
role/boundary, it first performs native browser login and then writes a
**staged, bounded AssumeRole session** to the destination. `pk` and `web` wrap
`aws login` rather than implement a browser or passkey protocol; they cannot
prove that a passkey was used.

The source credential entry and its `PROFILE.store.credentials` backup can be
read by the same OS user while a legacy MFA login is active. Treat the source
AWS directory and `~/.hacksaws` as sensitive user data. Hacksaws uses
user-scoped files where the platform supports it, but it is not a vault and
cannot prevent another process running as the same OS user from reading
credentials. Configuration, exports, and status deliberately never print access
keys, secret keys, session tokens, or ECR passwords. An external ID is not an
AWS credential, but it is configuration data and is visible to that same OS user
and in configuration exports.

## Quick start: a constrained agent identity

Create a target-account identity and a narrow stored session policy:

```shell
hacksaws account add prod 123456789012 --description "production"
hacksaws policy add deploy-readonly policies/deploy-readonly.yaml \
  --description "agent's production scope"
hacksaws boundary add prod-readonly AgentReadOnly \
  --account prod --policy deploy-readonly --duration 45m \
  --description "production role with a 45-minute ceiling"

hacksaws target add prod-agent \
  --source-account prod --source-profile human \
  --source-location default --to agent:default --boundary prod-readonly

hacksaws pk login --target +prod-agent
```

The `+` makes a saved target unmistakable. `--target prod-agent` is accepted as
shorthand and normalized to `+prod-agent`; `+prod-agent` is preferred in scripts
and reviews. Login to a target may not override its source, destination, role,
or policy.

Check the planned resolution before logging in:

```shell
hacksaws config explain +prod-agent
hacksaws config check --target +prod-agent --remote
hacksaws status
```

## Authentication commands

### MFA

The legacy direct flow replaces a source profile’s static credentials with an
MFA STS session and preserves the original entry in `PROFILE.store.credentials`
until logout:

```shell
hacksaws mfa login engineering 123456 --lifespan 43200
hacksaws mfa logout engineering
```

`mfa in` and `mfa out` are aliases. `--lifespan` is a legacy MFA-session
duration in seconds; its default is 43,200 (12 hours). AWS and account policy
can impose a lower maximum.

Use MFA as a source for a staged role session by selecting a boundary, direct
role, or target:

```shell
hacksaws mfa login human 123456 --as prod-readonly
hacksaws mfa login human 123456 --role AgentReadOnly --account prod \
  --policy policies/deploy-readonly.yaml --duration 45m
hacksaws mfa login +prod-agent 123456
# Universal named alternative:
hacksaws mfa login 123456 --target prod-agent
```

The target supplies the saved source and destination plan. Supplying a role-only
operand for an unbounded target is rejected before authentication; those flags
can never silently produce a broad native login.

### Browser (`pk` and `web`)

`pk` and `web` are equivalent browser-login command families, each wrapping AWS
CLI `aws login`. Use the one your team has standardized on:

```shell
hacksaws pk login human
hacksaws web in human --as prod-readonly --duration 45m
hacksaws pk login --target +prod-agent
hacksaws web logout human
```

`login` has the alias `in`; `logout` has the alias `out`. `--remote` asks the
browser flow to perform remote validation/probing when supported. Browser
commands default the source profile to `default`.

### Destinations and locations

The source directory is `--directory`/`--dir` (default `~/.aws`).
`--name`/`--account-name NAME` is a source-directory shortcut for `~/.aws-NAME`.

For a staged role login, choose exactly one destination form:

```shell
# Logical location and profile: ~/.aws-agent, profile agent
hacksaws pk login human --as prod-readonly --to agent:agent

# Explicit directory requires its destination profile
hacksaws pk login human --as prod-readonly \
  --to-directory /secure/aws-agent --to-profile agent
```

`--to LOCATION:PROFILE` is mutually exclusive with `--to-directory` and
`--to-profile`; `--to-directory` always requires `--to-profile`. Logical
`default` and `.` both mean `~/.aws`; every other logical location `NAME` means
`~/.aws-NAME`. Location names use portable resource-name characters only (1–64
letters/digits/`.`, `_`, `-`, beginning with a letter or digit), so they cannot
contain path separators, drive prefixes, or traversal. Use `--directory` or
`--to-directory` for arbitrary filesystem paths.

Use `hacksaws logout PROFILE` as a top-level logout convenience, or the matching
authentication-family logout. Add `--ecr` and optionally `--podman` when ECR
container-engine logout is wanted.

## Roles, trust, and policies

A **boundary** names a target account, role ARN, optional external ID, optional
duration, and optional session policy. A boundary may be same-account or
cross-account. It does not create AWS IAM resources; configure both source
permission and target trust first.

Source identity policy: permit the human/source role to assume the target role.
Replace the ARN with your source principal and target role ARN.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123456789012:role/AgentReadOnly"
    }
  ]
}
```

Target role trust policy for a same-account source role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/HumanOperator" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

For a cross-account role, the target account’s trust policy must name the source
account principal (or a narrowly selected source role). Add an external-ID
condition when your trust model requires it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/HumanOperator" },
      "Action": "sts:AssumeRole",
      "Condition": { "StringEquals": { "sts:ExternalId": "vendor-opaque-id" } }
    }
  ]
}
```

Then save the same value with `--external-id` on `boundary add`, or supply it
for an ad hoc role login. It is passed only to `AssumeRole`.

The target role’s identity policies still determine the maximum permission. A
session policy can only further reduce it. Therefore `--policy` requires a
role/boundary/target; it is never interpreted as a general local permission
system.

### Policy resolution and the 2048-character limit

For `--policy VALUE`, resolution order is: an explicit policy ARN, a file path
(`.json`, `.yaml`/`.yml`, or `.toml`, including paths with a slash), a stored
policy name, then a remote IAM policy name. JSON, YAML, and TOML documents must
contain IAM `Version` and `Statement`; inline documents are canonicalized to
compact JSON.

Stored policies are held under `~/.hacksaws/stored_session_policies`. YAML is
preserved verbatim on store; JSON and TOML are converted to YAML. Local and
stored documents, AWS-managed policies, and remotely resolved policies are
recorded in the local inspection cache. `cache max-age 0s` disables cache reads;
`cache clear` removes cached records.

Customer-managed policy ARNs must belong to the **target role account** and are
passed as managed session-policy ARNs. AWS-managed policy ARNs are fetched and
used as inline policy documents, so they are subject to STS’s 2,048-character
inline-session-policy limit. For example,
`arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess` may fail if its expanded
compact policy is over 2,048 characters; the error tells you to use a
same-account customer-managed policy ARN instead. A remote bare policy name is
rejected if it is ambiguous between AWS-managed and customer-managed policies.

## Named configuration

All named resources are case-insensitively unique and accept safe names.
`--description` is supported on account, boundary, target, and stored policy
records.

```shell
# Account IDs are paired with immutable AWS partitions.
hacksaws account add prod 123456789012 --partition aws
hacksaws account add gov 210987654321 --partition aws-us-gov
hacksaws account add china 109876543210 --partition aws-cn

# A short role is expanded using the account's partition and ID.
hacksaws boundary add prod-readonly AgentReadOnly --account prod \
  --policy deploy-readonly --external-id vendor-opaque-id --duration 45m

hacksaws target add prod-agent --source-account prod --source-profile human \
  --source-location . --to agent:default --boundary prod-readonly
```

An account’s partition is part of its identity because an account number alone
cannot construct correct ARN strings in commercial AWS, GovCloud, and China.
`account add` infers the partition from verified caller identity. An explicit
unverified save requires both `--no-verify` and `--partition`. Do not mix an ARN
from one partition with an account declared in another.

Use `add`, `update`, `get`, `list`, `rename`, and `remove` for accounts,
boundaries, and targets. `remove` refuses resources with live configuration or
session references. `--cascade` previews whole-resource dependent deletion and
requires interactive confirmation; noninteractive use requires `--yes`. It still
refuses active session references. `--json` is available for `get` and `list`.

Boundaries can change `--policy`, `--external-id`, and `--duration`, or clear
them with `--clear-policy`, `--clear-external-id`, and `--clear-duration`.
Targets can change or `--clear-boundary`. Accounts, boundaries, and targets can
change a description with `update ... --description TEXT` or clear it with
`--clear-description`; stored-policy descriptions are supplied on `policy add`
or `policy update`.

## Durations

AssumeRole duration accepts one of these mutually exclusive forms:

```shell
--duration 45m       # --ttl is an alias
--htl 1.5            # hours-to-live
--mtl 90             # minutes-to-live
--stl 5400           # seconds-to-live
```

Decimal values are rounded conventionally to whole seconds and must be positive.
Boundary sessions must be at least 900 seconds; chained role sessions are capped
at 3,600 seconds. A boundary duration is its normal default; an ad hoc duration
is used for that login. AWS role configuration can still enforce a lower
maximum. `--ttl`, `--duration`, `--htl`, `--mtl`, and `--stl` are role-only
options and fail without a role/boundary/target.

## Inspect, repair, and move configuration

```shell
hacksaws status
hacksaws status --json
hacksaws config show
hacksaws config show --account prod --json
hacksaws config explain +prod-agent
hacksaws config check --target +prod-agent --remote
hacksaws config fix --account prod

hacksaws config export hacksaws-config.zip
hacksaws config import hacksaws-config.zip
hacksaws config import hacksaws-config.zip --replace --yes
```

`status` reports active destinations, auth method, source and target identities,
boundary, role, policy provenance, expiration/remaining time, and recorded ECR
state—never credentials. `config show` displays declared configuration;
`config explain` shows a target’s resolved plan; `check` validates locally and
can verify configured remote accounts and roles with `--remote`; `fix` writes a
timestamped backup then normalizes the configuration without changing security
references. `--probe` performs an explicit 900-second AssumeRole test with a
deny-all session policy, discards the returned credentials, and writes no
session files. `fix` reports unresolved issues with a nonzero status; in an
interactive terminal it offers repair/leave/remove per issue and never detaches
a boundary or weakens a security reference automatically.

Export creates a portable archive containing configuration and stored-policy
files, with checksums; it excludes credentials, active-session metadata, and the
cache. Import requires an exact manifest/member set, verifies every checksum,
validates all content in memory, previews conflicts, and then atomically merges.
Interactive replacement asks for confirmation; noninteractive replacement uses
`--replace --yes`. Referenced external policy files are bundled and promoted to
deterministically named stored YAML policies during import.

## ECR

Add `--ecr` to a login to authenticate Docker, or `--podman` to select Podman.
Repeat `--ecr-region REGION` for more registries; the profile’s primary region
is first.

```shell
hacksaws pk login human --as prod-readonly --ecr --ecr-region us-west-2
hacksaws mfa login human 123456 --ecr --podman
```

Important: ECR deliberately gets its authorization token with the **broad
intermediate/source session**, before the boundary is installed. This makes
container authentication useful even when the boundary excludes ECR, but it also
means the resulting container-engine registry credential is outside that
boundary’s blast-radius guarantee. ECR and AWS destination updates are treated
transactionally where possible; a failed container login or credential write can
trigger rollback/recovery. Verify state with `hacksaws status` and run explicit
ECR logout when needed.

Plain `hacksaws logout` restores AWS state but deliberately leaves recorded ECR
authorization installed and retains its cleanup record. Run
`hacksaws logout --ecr` (with the original `--podman` choice when applicable) to
remove only registries recorded by Hacksaws. Hacksaws does not pre-logout before
login because Docker exposes no safe portable way to distinguish and restore a
preexisting authorization.

## Policy cache

```shell
hacksaws cache get
hacksaws cache get --json
hacksaws cache set max-age 30m
hacksaws cache set max-age 0s
hacksaws cache clear --yes
```

`max-age` is the local policy-inspection-cache age, not a credential duration.

## Setup checklist

1. Install AWS CLI v2.32+ if using browser login and configure the source
   profile normally.
2. For MFA, set `mfa_serial` in the matching AWS config profile and retain an
   eligible source credential in its credentials file.
3. Create the source `sts:AssumeRole` permission, target trust relationship, and
   target role policies in IAM.
4. Add accounts with the correct partitions; add stored policies, boundaries,
   and targets.
5. Run `hacksaws config check --target +NAME --remote` before first use.
6. Start with a short boundary duration and a read-only session policy; inspect
   with `hacksaws status`.

## Manual live-AWS smoke matrix

The normal automated suite uses mocked boto3/AWS CLI/container commands and
makes no live AWS calls. Keep live checks opt-in and run them only in disposable
or carefully scoped test accounts:

| Scenario                 | Manual assertion                                                                                                     |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| MFA direct profile       | Login writes an MFA session, logout restores the original source entry.                                              |
| Browser native           | `pk login`/`web login` invokes AWS CLI v2.32+ and preserves the provider’s normal lifecycle.                         |
| Same-account boundary    | Source can assume the trusted role; session policy reduces access; expiry is reported.                               |
| Cross-account boundary   | Source permission, target trust, and external ID are all required.                                                   |
| Policy forms             | File, stored policy, customer ARN, AWS-managed ARN, cache hit/miss, and 2048-character failure behave as documented. |
| Destination and rollback | `default`/`.` and named locations resolve correctly; a forced write/ECR failure recovers cleanly.                    |
| ECR                      | Docker and Podman receive a registry login from the intermediate credentials and explicit logout removes it.         |

## Development

```shell
uv sync --locked --all-groups
npm ci
uv run task format
uv run test
uv run task test
uv run task check
uv run task build
```

`uv run test` and `uv run task test` share the same full pytest command and
enforce at least 95% aggregate line coverage.

## License

MIT. See [LICENSE](LICENSE).
