# Hacksaws cheatsheet

The canonical executable is `hacksaws`. Names are case-insensitive, portable
1–64-character identifiers (`A-Z`, `a-z`, `0-9`, `.`, `_`, `-`; leading
letter/digit).

## Authentication

```shell
# MFA: login/in, logout/out
hacksaws mfa login PROFILE MFA_CODE [-l SECONDS|--lifespan SECONDS]
hacksaws mfa in PROFILE MFA_CODE
hacksaws mfa in +TARGET MFA_CODE
hacksaws mfa in MFA_CODE --target TARGET
hacksaws mfa logout [PROFILE]
hacksaws mfa out [PROFILE]

# Browser AWS CLI login (AWS CLI v2.32+): login/in, logout/out
hacksaws pk login [PROFILE]
hacksaws pk in [PROFILE]
hacksaws pk logout [PROFILE]
hacksaws web login [PROFILE]
hacksaws web out [PROFILE]

# Top-level logout convenience
hacksaws logout [PROFILE]
```

Shared login flags:

```text
--target +NAME                 saved secure preset (NAME is accepted)
-d, --dir, --directory PATH   source AWS directory (default ~/.aws)
-n, --name, --account-name N  source directory shortcut: ~/.aws-N
--to LOCATION:PROFILE          destination logical AWS location/profile
--to-directory PATH --to-profile PROFILE
--boundary NAME, --as NAME     saved role boundary
--role ROLE_OR_ARN --account ACCOUNT
--policy VALUE                 role-only policy (ARN, path, stored, remote name)
--external-id VALUE            AssumeRole only
--session-name NAME            AssumeRole only
--region REGION
--duration VALUE, --ttl VALUE  role-only duration (e.g. 45m)
--htl N | --mtl N | --stl N    role-only hours/minutes/seconds aliases
--ecr [--podman] [--ecr-region REGION]...
--remote                       browser login only
```

Examples:

```shell
hacksaws mfa login human 123456 --as prod-readonly --duration 45m
hacksaws pk login +prod-agent
hacksaws web login default --role AgentReadOnly --account prod --to agent:default
hacksaws logout agent --ecr --podman
```

`default` and `.` are `~/.aws`; logical `team` is `~/.aws-team`. `--to` cannot
be combined with `--to-directory`/`--to-profile`; `--to-directory` requires
`--to-profile`. Role-only options fail unless the invocation resolves a concrete
role; an unbounded target is not enough. Saved targets reject source,
destination, role, policy, account, external-ID, and session-name overrides.
Only duration may override a saved boundary; an unbounded target may add one
named `--boundary`/`--as`.

## Named resources

All of account, boundary, and target support:

```shell
hacksaws KIND add NAME ... [--description TEXT]
hacksaws KIND update NAME [--description TEXT|--clear-description] ...
hacksaws KIND get NAME [--json]
hacksaws KIND list [--json]
hacksaws KIND rename NAME NEW_NAME
hacksaws KIND remove NAME [--cascade] [--yes]
```

```shell
# Accounts
hacksaws account add NAME ACCOUNT_ID --partition aws|aws-us-gov|aws-cn \
  [--profile PROFILE|--target +TARGET] [--no-verify] [--description TEXT]
hacksaws account update NAME [--profile PROFILE|--target +TARGET] [--no-verify]

# Boundaries
hacksaws boundary add NAME ROLE --account ACCOUNT [--policy VALUE] \
  [--external-id VALUE] [--duration 45m] [--no-verify] [--description TEXT]
hacksaws boundary update NAME [--policy VALUE|--clear-policy] \
  [--external-id VALUE|--clear-external-id] \
  [--duration VALUE|--clear-duration]

# Targets
hacksaws target add NAME --source-account ACCOUNT [--source-profile PROFILE] \
  [--source-location LOCATION|--source-directory PATH] \
  [--to LOCATION:PROFILE|--to-directory PATH --to-profile PROFILE] \
  [--boundary BOUNDARY] [--description TEXT]
hacksaws target update NAME [--boundary NAME|--clear-boundary]
```

## Policies

```shell
hacksaws policy add NAME FILE [--format json|yaml|yml|toml] [--description TEXT]
hacksaws policy update NAME FILE [--format json|yaml|yml|toml] [--description TEXT]
hacksaws policy get NAME [--json]
hacksaws policy list [--json]
hacksaws policy rename NAME NEW_NAME
hacksaws policy remove NAME [--json]

# Read policy input from stdin: format is required.
some-command | hacksaws policy add NAME - --format yaml
```

`--policy` resolves: policy ARN → path → stored name → remote IAM name. Customer
ARNs must be in the target role account. AWS-managed documents are inline and
can exceed STS’s 2,048-character limit.

## Cache, inspection, and portability

```shell
hacksaws cache get [max-age] [--json]
hacksaws cache set max-age DURATION
hacksaws cache clear [--yes]

hacksaws status [--json]
hacksaws config show [--account ACCOUNT] [--json]
hacksaws config explain +TARGET [--json]
hacksaws config check [--profile PROFILE|--target +TARGET] [--remote] [--probe] \
  [--account ACCOUNT] [--no-verify] [--json]
hacksaws config fix [--account ACCOUNT] [--yes]
hacksaws config export [ARCHIVE.zip]
hacksaws config import ARCHIVE.zip [--replace] [--yes]
```

Durations: `45m`, `1.5hours`, `90sec`; `--htl 1.5`, `--mtl 90`, and `--stl 5400`
are equivalent duration forms. Boundary sessions require at least 900 seconds;
role chaining caps them at 3,600 seconds. `cache set max-age 0s` disables cache
reads.

`config check --probe` calls AssumeRole with a deny-all policy and discards the
credentials. `config fix` backs up first, returns nonzero for unresolved issues,
and offers repair/leave/remove interactively without weakening boundaries.
Import validates an exact checksummed archive and previews conflicts;
noninteractive replacement requires `--replace --yes`.

## Common compact workflows

```shell
# Create a staged production preset.
hacksaws account add prod 123456789012
hacksaws policy add readonly policy.yaml
hacksaws boundary add prod-ro AgentReadOnly --account prod --policy readonly --duration 45m
hacksaws target add prod-agent --source-account prod --source-profile human \
  --to agent:default --boundary prod-ro
hacksaws config check --target +prod-agent --remote
hacksaws pk login --target +prod-agent
hacksaws status --json
hacksaws pk logout agent

# Archive configuration before moving computers.
hacksaws config export hacksaws-config.zip
hacksaws config import hacksaws-config.zip
```

## Development tests

`uv run test` and `uv run task test` run the same full pytest suite. Both fail
unless aggregate line coverage is at least 95%.
