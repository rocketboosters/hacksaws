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

`+NAME` is the documented target shorthand, but any leading non-alphanumeric
character selects target `NAME`; choose a prefix that is convenient in your
shell. `--target NAME` is always the unambiguous flag form.

## Assume from an existing session

```shell
hacksaws assume SOURCE --role ROLE_OR_ARN \
  (--self | --to LOCATION:PROFILE | --to-profile PROFILE | \
   --to-directory PATH --to-profile PROFILE) [OPTIONS]
hacksaws assume SOURCE --boundary NAME (--self | --to ... | --to-profile ...)
hacksaws assume +TARGET [OPTIONS]
hacksaws assume --target TARGET [OPTIONS]
```

Common options:

```text
-n, --name LOCATION           source ~/.aws-LOCATION
--policy VALUE                ARN, path, stored name, or remote policy name
--external-id VALUE           role trust external ID
--account NAME_OR_ID          assert target account
--session-name NAME           CloudTrail-visible role session name
--region REGION               credential resolution and installed region
--to-directory PATH           explicit directory; requires --to-profile
--duration/--ttl, --htl/--mtl/--stl
--keep-source                 retain the live source after successful handoff
--keep-ecr                    retain tracked ECR authorization
--replace                     allow an existing unmanaged destination
--yes                         approve the secret-free plan noninteractively
```

The destination is mandatory. `--self` is explicit in-place replacement and
conflicts with `--keep-source`; spelling the same endpoint with `--to` emits an
extra warning. Managed sources are cleared by default. Unmanaged sources require
`--keep-source` and cannot be used in place. There is no assume `--force`.

Saved targets reject source and destination overrides, including `--self`.
Bounded targets also reject role/policy/account overrides. An unbounded target
may add a saved `--boundary`/`--as`, but no direct role, policy, account,
external ID, session name, or region. Duration and lifecycle controls remain
available. Noninteractive and JSON executions require `--yes`. AWS requires a
minimum 900-second session; role chaining caps duration at 3,600 seconds.

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
hacksaws cache status [--json]
hacksaws cache list [PATTERN]... [--fresh|--stale|--invalid] [--origin ORIGIN]
hacksaws cache show ENTRY [--json]
hacksaws cache get [max-age] [--json]
hacksaws cache set max-age DURATION
hacksaws cache clear [PATTERN]... [--stale|--all] [--yes]

hacksaws status [--json]
hacksaws status [--verify]
hacksaws profile list [PATTERN]... [--verify] [--wide] [--json]
hacksaws logout PROFILE [--name LOCATION] [--force] [--keep-ecr]
hacksaws logout --all [--except PATTERN]... [--force] [--keep-ecr]
hacksaws config show [--account ACCOUNT] [--json]
hacksaws config explain +TARGET [--json]
hacksaws config check [--profile PROFILE|--target +TARGET] [--remote] [--probe] \
  [--account ACCOUNT] [--no-verify] [--json]
hacksaws config fix [--account ACCOUNT] \
  [--profile PROFILE|--target +TARGET] [--location LOCATION|-d DIRECTORY] \
  [--remote] [--probe] [--no-verify] [--yes]
hacksaws config export [ARCHIVE.zip]
hacksaws config import ARCHIVE.zip [--replace] [--yes]
```

Human `status` output is a compact, dynamic table. `LOCATION` is hidden when all
rows use the default location; `TTL` is hidden when no displayed session has a
meaningful expiry; and `VERIFY` is hidden unless `--verify` returns a useful STS
result. After one blank line, a single filtered-row summary reports state counts
in stable order, for example `State: 1 🟢active | 1 🔴expired`. Auth and scope
meanings/examples live in `hacksaws status --help`. Scopes use friendly labels:
`Role (@Preset) → Policy` shows the actual IAM role, an optional Hacksaws
boundary preset, and its restrictive session policy. TTL is populated only for
active/expiring rows with a positive meaningful expiry; all other rows are
blank, and the column disappears when every row is blank. `verified` means STS
returned the recorded account/partition/role; `mismatch` and `error` are
distinct. Untrusted names and AWS diagnostics cannot inject ANSI or terminal
controls. Use `--json` for stable raw lifecycle fields such as
`remaining_seconds` and IAM references; human symbols and key text never enter
JSON.

Durations: `45m`, `1.5hours`, `90sec`; `--htl 1.5`, `--mtl 90`, and `--stl 5400`
are equivalent duration forms. Boundary sessions require at least 900 seconds;
role chaining caps them at 3,600 seconds. `cache set max-age 0s` disables cache
reads.

`config check --probe` calls AssumeRole with a deny-all policy and discards the
credentials. `config fix` backs up first, returns nonzero for unresolved issues,
and offers repair/leave/remove interactively without weakening boundaries.
Import validates an exact checksummed archive and previews conflicts;
noninteractive replacement requires `--replace --yes`.

## Output and configuration foundations

Every command accepts these global output flags before or after command words
(but never after `--`):

```shell
hacksaws status --color auto
hacksaws config show --no-color
hacksaws status --json
```

`--color` is `auto`, `always`, or `never`; `--no-color` is `never`. Auto mode
requires a TTY and honours `NO_COLOR` and `TERM=dumb`. JSON writes one stable
envelope with `schemaVersion: 1`, `ok`, `code`, and either `data` or `error`.
Human diagnostics use stderr; JSON diagnostics do too. Exit status is 0 for
success, 1 for an operational error, 2 for invalid syntax or an incomplete or
dependency-blocked cleanup, 3 for a policy/safety refusal, 4 for a declined
confirmation, and 130 for interruption.

Schema version remains **1**. Inspect and set portable configuration values:

```shell
hacksaws config options
hacksaws config option get output.color --json
hacksaws config set output.color never
hacksaws config set naming.resources.role.prefix managed-
hacksaws config reset naming.resources.role.prefix
```

Naming resolves in this order: built-in defaults, `naming.global`, a resource
override, an account override, an account/resource override, then an explicit
command value. Defaults are Pascal case with empty prefix/suffix and `off`
enforcement. `iam.path` defaults to `/hacksaws/`; packed-policy warning defaults
to 80 percent with enforcement `off`. Accounts may carry a `credential_target`,
but selecting it never logs in implicitly.

## Remote IAM

`iam` is canonical and `remote` is an exact alias. The local `policy` command
above remains separate from remote IAM managed policies. The parser and verified
credential context are shared by the registered policy and role adapters:

```text
hacksaws iam|remote policy TERMINAL_COMMAND ... [selectors] [safety]
hacksaws iam|remote role TERMINAL_COMMAND ... [selectors] [safety]
hacksaws iam|remote list [PATTERN]... [type/origin/smoke filters] [selectors]
hacksaws cleanup SELECTION [type/origin/smoke filters] [selectors] [safety]
hacksaws iam|remote cleanup SELECTION [same filters/selectors/safety]
hacksaws iam|remote recovery list
hacksaws iam|remote [same selectors] recovery get JOURNAL_ID
hacksaws iam|remote [same selectors] recovery continue|rollback JOURNAL_ID
```

Selectors are visible on and should normally be placed on each terminal command:

```text
--profile PROFILE              AWS profile (default: default)
--location NAME                ~/.aws-NAME (`default` and `.` mean ~/.aws)
-d, --directory PATH           explicit AWS config directory
--target NAME                  saved source; conflicts with profile/location/directory
--account NAME_OR_ID           account assertion; may combine with --target
--region REGION                regional clients and console links
--dry-run                      normal mutation: validate/plan, never mutate or journal
--yes                          exact noninteractive approval (mutations only)
```

Selector abbreviations and duplicates are rejected. `--location` conflicts with
`--directory`; `--profile` composes with either one.

### Inventory and Leave No Trace cleanup

```shell
hacksaws iam list [PATTERN]... [--roles] [--policies] [--group-grants] \
  [--created] [--adopted] [--smoke] [--smoke-run RUN_ID] [--compact|--wide] \
  [--all-account] [--details] [--progress|--no-progress]

hacksaws cleanup PATTERN... [--roles] [--policies] [--group-grants] \
  [--created] [--adopted] [--cascade] [--remove-boundaries] \
  [--remove-from-instance-profiles] [--dry-run|--yes]
hacksaws cleanup --all [same filters and safety options]
hacksaws cleanup --smoke [same filters and safety options]
hacksaws cleanup --smoke-run RUN_ID [same filters and safety options]
```

Patterns are case-insensitive fnmatch expressions and are ORed. `--all`
conflicts with patterns. No type flags means all supported types. No origin
flags means created and adopted resources. Smoke selectors further narrow
matches. Cleanup orders group grants, roles, then policies; blocked/transient
work does not prevent independent resources from being attempted.

Inventory verifies live ownership tags within the canonical `/hacksaws/` paths
by default. That fast scope can miss adopted resources elsewhere, custom or
changed paths, and untagged legacy resources. `--all-account` performs the
comprehensive supported-resource scan and includes resources Hacksaws does not
own; untagged legacy resources still cannot be classified as Hacksaws-owned.
Explicit `--created` or `--adopted` filters still narrow an all-account scan.
`--details` performs the additional dependency lookups; `--wide` only changes
presentation. Progress is delayed and written to stderr for human terminals.
`--progress` forces plain stderr milestones, `--no-progress` suppresses them,
and JSON mode always remains quiet until its single envelope. Summary JSON
reports `detailsComplete: false` and omits dependency fields unless `--details`
is selected. `scope` identifies `canonical` or `all-account`, while
`inventoryComplete: false` means warnings describe candidates that were omitted.

Cleanup exit codes: `0` complete/executable plan, `1` input/auth/planning
failure, `2` partial or dependency-blocked, `3` safety refusal.

The shared IAM context resolves and freezes credentials while `AWS_CONFIG_FILE`
and `AWS_SHARED_CREDENTIALS_FILE` are bound to the selected
profile/location/directory. It creates IAM, STS, and Access Analyzer clients and
verifies `sts:GetCallerIdentity` inside that same scope, restores every ambient
credential-provider variable exactly afterward, and rejects a caller
account/partition mismatch. Use a saved target only when its source account is
the intended management account; no selector performs an implicit login.

Normal remote mutations use schema-one journals under
`~/.hacksaws/iam-recovery/`, separate from the login transaction journal. Each
step is written atomically before its AWS mutation and contains only a
whitelisted handler name plus forward and compensation payloads—never
credentials. `continue` resumes pending forward steps in order; `rollback`
reconciles and compensates pending or completed steps in reverse order. Both
require credentials for the journal's recorded account. Corrupt journals are
reported and preserved for inspection. `--json` is always noninteractive and
emits exactly one result envelope; destructive machine-mode commands still
require `--yes`.

Recovery `continue` and `rollback` do not accept `--dry-run`: they resume an
existing journal. Every journal is bound to both AWS account and partition.
Completed cleanup receipts have their recovery payloads scrubbed, so they are
diagnostic records and cannot be rolled back. After an irreversible IAM identity
deletion, recovery fails closed and reports manual rebuild requirements instead
of recreating a same-named resource with a different principal ID.

Available policy leaves are `create`/`publish`, `list`, `get`, `export`,
`update`/`edit`, `versions`, `rollback`, `delete`/`remove`, `check`, `tag`,
`adopt`, and `release`. Role leaves are `create`, `get`, `list`, `update`,
`delete`, `attach`, `detach`, `adopt`, `release`, `tag`, `inline-policy`, and
`trust`. IAM is the source of truth for those remote objects. Stored Hacksaws
policies are local documents; managed IAM policies are versioned IAM resources;
inline role policies are bound to one role; STS session policies are ephemeral
and subject to packed-policy limits. Do not treat these as interchangeable.

### Role command reference

```text
hacksaws iam role create ROLE [--trust-caller|--trust-policy FILE]
  [--description TEXT] [--path IAM_PATH] [--permissions-boundary POLICY]
  [--tag KEY=VALUE]... [naming/metadata/duration options] [--replace]
  [selectors] [--dry-run] [--yes]
hacksaws iam role get ROLE [selectors]
hacksaws iam role list [PATTERN]... [--custom|--all|--service]
  [--wide] [--probe] [selectors]
hacksaws iam role update ROLE [--description TEXT|--clear-description]
  [--permissions-boundary POLICY|--clear-permissions-boundary]
  [--trust-policy FILE] [metadata/duration options] [selectors] [--dry-run] [--yes]
hacksaws iam role delete ROLE [--cascade] [--remove-from-instance-profiles]
  [--unmanaged] [--service-role] [selectors] [--dry-run] [--yes]
hacksaws iam role attach ROLE POLICY [--inline] [--policy-name NAME]
  [--path IAM_PATH] [metadata options] [selectors] [--dry-run] [--yes]
hacksaws iam role detach ROLE POLICY [selectors] [--dry-run] [--yes]
hacksaws iam role adopt ROLE [--owner NAME] [--audit-id ID]
  [selectors] [--dry-run] [--yes]
hacksaws iam role release ROLE [selectors] [--dry-run] [--yes]
hacksaws iam role tag list ROLE [selectors]
hacksaws iam role tag set ROLE KEY=VALUE... [selectors] [--dry-run] [--yes]
hacksaws iam role tag remove ROLE KEY... [selectors] [--dry-run] [--yes]
hacksaws iam role inline-policy list ROLE [selectors]
hacksaws iam role inline-policy get ROLE POLICY [selectors]
hacksaws iam role inline-policy export ROLE POLICY [--output|-o OUTPUT]
  [format/metadata options]
hacksaws iam role inline-policy put ROLE POLICY FILE [metadata options]
  [selectors] [--dry-run] [--yes]
hacksaws iam role inline-policy edit|delete ROLE POLICY
  [selectors] [--dry-run] [--yes]
hacksaws iam role trust get ROLE [selectors]
hacksaws iam role trust set ROLE FILE [metadata options] [selectors] [--dry-run] [--yes]
hacksaws iam role trust edit ROLE [selectors] [--dry-run] [--yes]
hacksaws iam role trust export ROLE [--output|-o OUTPUT]
  [format/metadata options] [selectors]
hacksaws iam role trust check ROLE [--probe] [selectors]
hacksaws iam role trust add|remove user|role|account|principal ROLE PRINCIPAL
  [principal/condition options] [selectors] [--dry-run] [--yes]
hacksaws iam role trust add|remove group-members GROUP MEMBER...
  [selectors] [--dry-run] [--yes]
hacksaws iam role trust sync group-members GROUP [MEMBER]...
  [selectors] [--dry-run] [--yes]
hacksaws iam role trust grant|revoke group ROLE GROUP
  [selectors] [--dry-run] [--yes]
```

### Managed-policy command reference

```text
hacksaws iam policy create|publish FILE [NAME] [selectors]
  [--description TEXT] [--path IAM_PATH] [--replace]
  [--format json|yaml|toml] [--metadata none|nested|sidecar]
  [--metadata-file FILE] [--tag KEY=VALUE]... [--local-validation-only]
  [--replace] [--dry-run] [--yes]
hacksaws iam policy list [PATTERN]... [--custom|--aws|--all] [selectors]
  [--compact|--wide]
hacksaws iam policy get POLICY [selectors]
hacksaws iam policy export POLICY [OUTPUT] [selectors]
  [--format json|yaml|toml] [--metadata none|nested|sidecar]
  [--metadata-file FILE] [--all-versions]
hacksaws iam policy update [POLICY] FILE [selectors]
  [--from-stored NAME] [input options] [--dry-run] [--yes]
hacksaws iam policy edit POLICY [selectors] [--format json|yaml|toml]
  [--local-validation-only] [--dry-run] [--yes]
hacksaws iam policy versions POLICY [selectors]
hacksaws iam policy rollback POLICY VERSION [selectors] [--dry-run] [--yes]
hacksaws iam policy delete|remove POLICY [selectors] [--cascade]
  [--remove-boundaries] [--allow-unmanaged] [--dry-run] [--yes]
hacksaws iam policy check POLICY [selectors] [--role ARN_OR_NAME]
  [--local-validation-only]
hacksaws iam policy tag list POLICY [selectors]
hacksaws iam policy tag set POLICY --tag KEY=VALUE... [selectors] [--dry-run] [--yes]
hacksaws iam policy tag remove POLICY KEY... [selectors] [--dry-run] [--yes]
hacksaws iam policy adopt POLICY [--tag KEY=VALUE]... [selectors] [--dry-run] [--yes]
hacksaws iam policy release POLICY [selectors] [--dry-run] [--yes]
```

`POLICY` accepts the adapter's account- and partition-safe ARN/name resolution.
AWS-managed policies may be inspected, exported, validated, and checked, but
cannot be created, updated, tagged, adopted, released, rolled back, or deleted.
Hacksaws preserves a customer-managed policy's description and never rewrites or
"optimizes" policy statements. `export --all-versions` serializes every retained
document with its version ID, default marker, creation time, active policy, and
optional metadata; treat exports and recovery journals as security-sensitive
configuration even though neither contains AWS credentials.

`check --role` submits the selected policy document exactly as an inline STS
session policy using STS's minimum 900-second role session, reports AWS's real
`PackedPolicySize`, and discards returned credentials. It does not substitute a
deny-all probe. The call still creates a short-lived AWS session and requires
`sts:AssumeRole`; use `--local-validation-only` to skip AWS-side validation and
omit `--role` to skip the STS probe.

Every managed-policy mutation records its complete forward and compensation
state before the first AWS call. That includes retained version documents and
default selection, tags, policy and ownership IDs, dependency principal IDs, and
deletion restoration data. Continue/rollback accepts only the exact predecessor,
exact intended result, or an exact ordered AWS-call stage left by an interrupted
mutation; partial atomic tag batches and out-of-order dependency removals are
drift, not recovery checkpoints. A create's actual AWS PolicyId is receipted
before destructive compensation; a crash before that receipt fails closed and
preserves the present policy for manual recovery. Restoring an attachment or
permissions boundary also requires the same current IAM principal ID, not merely
the same user/group/role name. If a process is interrupted, inspect the journal
before choosing `continue` or `rollback`; both operations are account-bound and
idempotent.

Deletion prints the exact user/group/role attachments, user/role permissions
boundaries, and retained versions before its stronger confirmation. `--cascade`
authorizes attachment removal, but permissions-boundary assignments additionally
require `--remove-boundaries`; unmanaged policies additionally require
`--allow-unmanaged`. Interactive deletion requires typing the exact policy name.
Noninteractive and JSON invocations never prompt and therefore require `--yes`.

`DeletePolicy` is the irreversible managed-policy identity commit point because
AWS cannot recreate the original PolicyId. Rollback repairs partial deletion
only before that call succeeds. Afterward it leaves the ARN absent, performs no
`CreatePolicy` or dependency restoration, and reports the manual rebuild
requirement; `continue` remains an idempotent absent-state verification.

Tag changes use an optimistic tag snapshot and fail if tags drift before
publish. `tag set` and `tag remove` reject every `hacksaws:` key; use `adopt`
and `release` for the reserved ownership/audit tags. Editor updates likewise
fail if either the exported default version or its document digest changes while
the editor is open.

Role names are IAM role names (up to 64 characters) and ARNs include partition,
account, path, and role name, for example
`arn:aws:iam::123456789012:role/hacksaws/Agent`. Trust principals must be
durable IAM users, roles, services, or explicit account roots—never wildcards or
an STS assumed-role session where a durable principal is required. Group changes
affect membership only; they do not silently replace role trust or policy
attachments. Every role mutation shows its resource/action plan and requires
typing `yes`; CI, JSON, and non-TTY use must explicitly pass `--yes`. Trust
input rejects wildcard principals and `NotPrincipal`. Named same-account roles
are resolved with `iam:GetRole` so paths are retained; cross-account roles
require an exact ARN. Generic tag commands cannot change reserved `hacksaws:`
tags.

Role creation journals the immutable AWS `RoleId` as its effect receipt.
Recovery never adopts or deletes a same-name role from matching
tags/configuration alone. If AWS creation succeeds but the process stops before
the receipt is durable, preserve the role and recover manually; automated
continuation and rollback fail closed. A receipt-backed rollback deletes only
the exact matching `RoleId`.

Role deletion is the exception to the ordinary interactive confirmation text:
type the exact role name because deletion crosses an irreversible AWS principal-
identity commit point. `--yes` remains the explicit automation form. Recovery
can restore dependency removals if the role still has its original IAM role ID,
but it will stop for manual recovery after deletion rather than recreate a
same-named, different principal and claim success.

```shell
# Core role lifecycle
hacksaws iam role create Agent --trust-caller
hacksaws iam role update Agent --trust-policy trust.yaml --yes
hacksaws iam role get Agent
hacksaws iam role list --wide
hacksaws iam role delete Agent --cascade --yes

# Managed and inline permissions
hacksaws iam role attach Agent ReadOnlyAccess --yes
hacksaws iam role attach Agent ./agent-policy.yaml --policy-name AgentPolicy --yes
hacksaws iam role detach Agent ReadOnlyAccess --yes
hacksaws iam role inline-policy put Agent LocalRead ./read.yaml --yes
hacksaws iam role inline-policy edit Agent LocalRead --yes
hacksaws iam role inline-policy delete Agent LocalRead --yes

# Exact trust and durable IAM-group grants
hacksaws iam role trust add role Agent Operator --yes
hacksaws iam role trust add role Agent arn:aws:iam::210987654321:role/team/Operator --yes
hacksaws iam role trust grant group Agent Agents --yes
hacksaws iam role trust revoke group Agent Agents --yes
hacksaws iam role trust sync group-members Agents Agent DebugAgent --yes
```

Local managed-policy attachment and group grants publish only tagged,
Hacksaws-owned policies whose resource kind and resource ID exactly match the
intended attachment or group. They refuse every other ARN collision, preserve
unrelated aggregate-policy statements, snapshot all version documents/default
state for durable reconciliation, and are rerunnable. Group trust uses the
distinct `HacksawsGroupAccount` statement and preserves unrelated account-root
trust. Group revoke retains that owned statement only while another exact, live,
attached group aggregate still references the role.

For `iam role list --probe`, `denied` means STS explicitly rejected
authorization. Network, throttling, expired-credential, and other operational
failures are shown as `indeterminate`, with details, rather than being
mislabeled as denials.

Remote IAM leaves require only the needed IAM actions on the `/hacksaws/` path
plus `sts:GetCallerIdentity`; add `iam:PassRole` only when a workflow actually
needs it. Permissions boundaries, service-control policies, cross-account trust,
IAM limits (including managed-policy version count and STS packed policy size),
and eventual consistency are AWS constraints, not bypassed by Hacksaws. Run
`hacksaws iam recovery list` before retrying an interrupted remote mutation;
inspect with `get JOURNAL_ID`, then choose `continue JOURNAL_ID` or
`rollback JOURNAL_ID`.

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

```shell
mpx --me check
uv run task check
uv run test
uv run task test
uvx --from . hacksaws --help
```

The MPX check and direct task check run format, lint, then test. Literal
`uv run test` is development-only; it and `uv run task test` forward additional
pytest arguments and fail unless aggregate line coverage is at least 95.00%.
Built packages provide the `hacksaws` command and the `py.typed` marker. Use
`uvx --from . hacksaws ...` for a source checkout; `uvx hacksaws ...` is the
package-index form once a release has been published.
