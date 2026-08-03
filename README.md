# Hacksaws

Hacksaws is an AWS login and IAM lifecycle CLI built for humans working beside
agents. It can authenticate with MFA or AWS browser login, then optionally
assume a role with a session policy so the credentials left on disk have a
smaller blast radius than the credentials used to obtain them.

It also manages the accounts, targets, boundaries, reusable policies, IAM roles,
and customer-managed policies used by that workflow. Every remote mutation is
account-scoped, previewed, and recoverable where AWS permits it.

## Install and run

Python 3.13 or newer is required. Run the published CLI without installing it:

```shell
uvx hacksaws --help
```

For development:

```shell
git clone https://github.com/rocketboosters/hacksaws.git
cd hacksaws
uv sync
uv run hacksaws --help
uv run test
```

`uv run test` is the repository quality gate. It runs formatting, linting, type
checking, the warning-free test suite, and enforces at least 95% coverage.

## Quick start

Browser login needs no pre-existing profile. Hacksaws creates the destination
profile when needed:

```shell
hacksaws web in debug
aws sts get-caller-identity --profile debug
```

Regions accept canonical names and friendly aliases. Hacksaws explains the
resolution and always persists the canonical AWS name:

```shell
hacksaws region explain oregon
# Canonical region: us-west-2
```

`pk` is an exact alias for `web`:

```shell
hacksaws pk in admin --name horizon
```

MFA login starts from persistent source credentials:

```shell
hacksaws mfa in admin --name horizon 123456
```

Omit the code in an interactive terminal for a hidden prompt, or use
`--mfa-code-stdin` to read one line from standard input. JSON and other
non-interactive use never prompts.

The source above is profile `admin` in `~/.aws-horizon`. To write temporary
credentials somewhere else, use `--to LOCATION:PROFILE`:

```shell
hacksaws mfa in admin --name horizon --to default:debug 123456
```

`.` and `default` both mean the default AWS directory or profile in their
respective position.

## Boundary sessions

A boundary assumes a role after authentication. With no `--policy`, the role's
full permissions are used. Supplying a policy creates an intersected session:
AWS allows only actions permitted by both the role and the session policy.

```shell
hacksaws web in debug \
  --role AgentSession \
  --policy CloudWatchReadOnlyAccess
```

Policies may be AWS/customer-managed policy names, ARNs, stored-policy names, or
local JSON/YAML/TOML files. Hacksaws resolves and minifies the document before
calling `AssumeRole`. AWS also applies a separate packed-policy limit; Hacksaws
reports that limit explicitly but does not rewrite policy semantics.

Save role/policy/duration combinations as boundaries and full login presets as
targets:

```shell
hacksaws boundary add cloudwatch AgentSession \
  --account prod --policy CloudWatchReadOnlyAccess --duration 1h

hacksaws target add hacw \
  --source-account prod --source-profile admin \
  --source-location horizon --boundary cloudwatch

hacksaws web in +hacw
# Equivalent explicit spelling:
hacksaws web in --target hacw
```

A successful login can also teach Hacksaws the complete reusable target:

```shell
hacksaws web in debug --role AgentSession \
  --policy CloudWatchReadOnlyAccess --save=debug-agent
hacksaws web in +debug-agent
```

Use bare `--save` in an interactive terminal to choose the name after the
credentials are committed. Automation must use `--save=NAME` or
`--save-name NAME`. See [Saving login workflows](docs/saved-targets.md) for
account discovery, advanced naming, local-policy storage, and recovery from a
successful session whose configuration save did not complete.

Durations accept forms such as `15m`, `15minutes`, `1h`, `hour`, `600s`, and
`600seconds`. Rigid aliases `--htl`, `--mtl`, and `--stl` accept floating-point
hours, minutes, and seconds; sub-second results round to whole seconds.

If credentials are already logged in, constrain them without repeating the
authentication step:

```shell
hacksaws assume admin --name horizon \
  --role AgentSession --policy CloudWatchReadOnlyAccess \
  --to default:agent
```

For a destination profile in the same AWS location,
`hacksaws assume SOURCE DEST --role ...` is the short form of
`--to-profile DEST`.

The destination is always explicit. The source is removed after a successful
handoff unless `--keep-source` is deliberate; use `--self` for an intentional
in-place replacement. See [Assume a role](docs/assume-role.md) for destination,
confirmation, ECR, and automation safeguards.

## Inspect before acting

The human views are compact tables. Add global `--json` for automation and
`--no-color` when ANSI styling is undesirable:

```shell
hacksaws status
hacksaws profile list
hacksaws profile list --verify
hacksaws iam list --profile admin --wide
hacksaws cache status
hacksaws config show
hacksaws history list --since 24h
```

`iam list` verifies live ownership tags within the canonical `/hacksaws/` paths
by default. That fast scope can miss adopted resources elsewhere, custom or
changed paths, and untagged legacy resources; add `--all-account` for the
comprehensive supported-resource scan. Add `--details` when dependency
information is worth the additional AWS calls. Human terminals receive delayed
progress on stderr while stdout remains safe to pipe; use `--progress` to force
plain milestones or `--no-progress` to suppress them. JSON mode is always quiet
until its single result envelope.

Local history records redacted command families, outcomes, timings, and
validated identifiers—not raw arguments, output, prompts, paths, policy
documents, or credentials. Use `hacksaws history status` to inspect retention
and health. See [Local command history](docs/history.md) for the full security
contract, filters, exports, and clearing behavior.

Global output flags may appear anywhere before `--`:

```shell
hacksaws --json iam policy list
hacksaws iam policy list --color never
```

## Remote IAM lifecycle

`iam` and `remote` are exact aliases. Credential selectors belong on terminal
commands, so the following is intentionally supported:

```shell
hacksaws iam policy create agent.yaml --profile admin --dry-run
hacksaws iam policy create agent.yaml --profile admin --yes
hacksaws iam role create AgentSession --profile admin --trust-caller --dry-run
```

Create commands never silently overwrite a differing resource. An identical
resource reports `NO CHANGE`; a difference reports `CONFLICT`. Use the normal
`update` command, or deliberate `create --replace` plus confirmation.

Normal remote IAM mutations accept `--dry-run`. A dry run performs discovery,
validation, collision checks, and planning, but creates no recovery journal and
changes neither AWS nor local state. Recovery `continue` and `rollback` commands
resume an already-journaled operation and therefore do not accept `--dry-run`.

Mutation previews and results use one credential-free contract: exact resource
identity and ownership, scalar before/after changes, ordered AWS actions,
dependencies, warnings, confirmation, applied actions, resource IDs/ARNs,
console links, and recovery journal IDs. Policy documents and tag values are
represented only by non-reversible summaries.

## Leave No Trace cleanup

Cleanup deletes only resources whose Hacksaws ownership can be established in
the selected account. A pattern, `--all`, `--smoke`, or `--smoke-run` is
mandatory. With no type flags, all supported types are considered.

```shell
hacksaws cleanup "*ServiceBuzz*" --policies --profile admin --dry-run
hacksaws cleanup --all --profile admin --dry-run
hacksaws cleanup --smoke --profile admin --yes
```

`--roles`, `--policies`, and `--group-grants` narrow resource types. `--created`
and `--adopted` narrow ownership origin. Cross-retained dependencies require
explicit `--cascade`, `--remove-boundaries`, or
`--remove-from-instance-profiles` consent. `hacksaws iam cleanup` and
`hacksaws remote cleanup` use the same planner and executor.

## Log out safely

Logout removes Hacksaws-managed live credentials without contacting an AWS
logout endpoint. It never stores the intermediate MFA-authenticated credentials
used to assume a boundary role.

```shell
hacksaws logout debug
hacksaws logout --all
hacksaws logout --all --except "default:prod*" --except "+hacw"
```

Tracked ECR logins are removed by default; use `--keep-ecr` deliberately.
Unknown external profiles are never altered.

## Credential threat model

The MFA workflow involves three distinct credentials:

1. Persistent unauthenticated source credentials remain on the device. Give them
   only the permissions needed to perform MFA/session bootstrap, because a local
   agent may be able to read them.
2. MFA-authenticated intermediate credentials exist only while login and any ECR
   login are being completed. They are not backed up when a boundary is used.
3. Boundary credentials are the role/session-policy credentials written to the
   destination for the user or agent.

Browser login similarly uses its authenticated credentials only to complete the
requested workflow, then leaves the final requested credentials at the target.

## Configure an assumable role

The role trust policy must allow the login identity to call `sts:AssumeRole`.
Hacksaws can generate the common caller-specific policy:

```shell
hacksaws iam role create AgentSession --trust-caller --profile admin
```

The equivalent trust statement is:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:user/alice" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

The caller also needs an identity policy permitting `sts:AssumeRole` on the
role. A group cannot be an IAM trust principal. Hacksaws can instead grant a
group through a managed group policy, or expand the group's current users into
individual trust principals. See the trust guide before choosing between those
models.

## Learn more

- [Command cheat sheet](CHEATSHEET.md)
- [Login pathways](docs/login.md)
- [Saving login workflows](docs/saved-targets.md)
- [Assume a role from an existing session](docs/assume-role.md)
- [Profiles, status, and logout](docs/profiles-and-sessions.md)
- [IAM policies](docs/iam-policies.md)
- [IAM roles and trust](docs/iam-roles-and-trust.md)
- [Cleanup and Leave No Trace](docs/cleanup.md)
- [Configuration](docs/configuration.md)
- [Regions and aliases](docs/regions.md)
- [Policy cache](docs/cache.md)
- [Local command history](docs/history.md)
- [Security model](docs/security-model.md)
- [Automation and JSON](docs/automation-and-json.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Development and smoke tests](docs/development-and-smoke-tests.md)

Run `hacksaws COMMAND --help` at any level. The CLI is the canonical command
reference and includes selector, safety, confirmation, and repair guidance.
