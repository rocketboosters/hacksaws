# Assume a role from an existing session

`hacksaws assume` starts from credentials that are already logged in, calls
`sts:AssumeRole`, writes the constrained credentials to an explicit destination,
and normally removes the live source session. It does not perform MFA or browser
authentication itself.

```shell
hacksaws assume admin --name horizon \
  --role AgentSession \
  --policy CloudWatchReadOnlyAccess \
  --to default:agent
```

The source above is profile `admin` in `~/.aws-horizon`; the destination is
profile `agent` in `~/.aws`. Use `--to-profile agent` to write into the source
location, or a bounded target such as `hacksaws assume +prod-agent` to load the
source, destination, role, and optional policy together.

## Destination safety

A destination is mandatory. Choose exactly one:

- `--to LOCATION:PROFILE` writes to a fully explicit endpoint.
- `--to-profile PROFILE` uses the source location.
- `--to-directory PATH --to-profile PROFILE` uses an explicit AWS directory.
- `--self` deliberately replaces the source profile in place.
- A saved target supplies its configured destination and rejects destination
  overrides, including `--self`.

`--to-directory` requires `--to-profile`; that pair conflicts with `--to` and
`--self`. `--self` also conflicts with `--keep-source`. The verbose
same-endpoint spelling, such as `--to horizon:admin`, is accepted, but its plan
includes an additional warning and requires the same exact approval. In-place
assumption obtains the new credentials before atomically installing them and
keeps only the pre-login backup needed for eventual logout; it does not persist
the broader authenticated credentials as a second live profile.

Hacksaws replaces a managed destination only after checking that its managed
sections have not drifted. An existing unmanaged destination is refused unless
`--replace` is supplied. There is deliberately no general `--force` option for
assumption.

## Source and ECR lifecycle

After a successful write, Hacksaws removes a managed source session by default.
Use `--keep-source` only when both sessions are intentionally needed. An
unmanaged source cannot be safely removed, so it requires `--keep-source`; an
unmanaged source also cannot be used with `--self`.

Tracked ECR authorization associated with replaced or removed sessions is logged
out after the credential transaction. `--keep-ecr` preserves it deliberately.
ECR cleanup failure is reported as tracked residue without rolling back
already-installed role credentials.

## Role contract

Choose one role source:

- `--role NAME_OR_ARN` selects a concrete IAM role.
- `--boundary NAME` or `--as NAME` loads a saved role plus its optional policy,
  external ID, and duration.
- A bounded target loads its saved boundary.

An unbounded target may add one saved boundary, but no direct role, policy,
account, external ID, session name, or region. A bounded target is a secure
preset: its source, destination, role, policy, account, external ID, and session
name cannot be overridden. Lifecycle and duration options may still be selected
for the invocation.

`--policy` accepts a policy ARN, local path, stored-policy name, or remote
policy name. It can only reduce the role session's permissions. `--external-id`,
`--session-name`, `--account`, and `--region` provide the corresponding role and
resolution assertions.

Durations accept `--duration` / `--ttl` values such as `45m`, or rigid `--htl`,
`--mtl`, and `--stl` floating-point forms. AWS requires at least 900 seconds.
Role chaining caps a session at 3,600 seconds, and the role's
`MaxSessionDuration` may impose another ceiling.

## Preview, confirmation, and automation

Before calling `AssumeRole`, Hacksaws resolves the source identity, role,
account, partition, destination ownership, policy reference, effective duration,
and lifecycle actions into one prepared plan. Human mode displays that plan and
accepts only the exact answer `yes`. Execution uses the same prepared plan
rather than resolving configuration again. Immediately before mutation, Hacksaws
rechecks the source, destination, cache, and referenced configuration
fingerprints; a change aborts the command and requires a fresh preview. Use
`--yes` to approve the plan noninteractively; JSON mode and other noninteractive
input require that flag.

```shell
hacksaws assume admin --role AgentSession --to default:agent --yes --json
```

Preview and result JSON never include access keys, secret keys, session tokens,
credential backups, or policy documents. Account or partition disagreement is a
hard failure before local credential mutation.
