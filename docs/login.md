# Login pathways

## Browser login (`web` / `pk`)

Browser login uses the AWS CLI login credential provider and does not require an
existing profile. Hacksaws creates both the config and credentials destinations
when needed. The package includes the Botocore CRT dependency required to verify
these credentials.

```shell
hacksaws web in debug
hacksaws pk in default --name default
```

`web` and `pk` are equivalent. `in` aliases `login`; `out` aliases `logout`.

Hacksaws tracks the browser cache by stable, hashed login lineage rather than
storing its tokens. Normal AWS access/refresh-token rotation is accepted only
after STS verifies the same account, partition, and principal. A different
client/DPoP login generation is preserved as residue for review—even with
`--force`—and compare-and-delete preserves a cache that refreshes concurrently.

## MFA login

MFA requires persistent source credentials. `PROFILE --name LOCATION` selects
the source profile and `~/.aws-LOCATION` directory.

```shell
hacksaws mfa in admin --name horizon 123456
hacksaws mfa in admin --name horizon --to default:debug 123456
```

In an interactive terminal, omit `123456` for a hidden MFA prompt. Use
`--mfa-code-stdin` to read exactly one line from standard input. Supplying both
forms is an error; JSON and non-TTY use require a positional or stdin code and
never prompt. History records only that a code was provided and whether its
source was argument, stdin, or prompt.

The source credentials should have only bootstrap permissions. See
[Security model](security-model.md).

For compatibility with MFA sessions created by older Hacksaws releases, login
uses a valid managed original first, then the matching
`PROFILE.store.credentials` legacy backup, and finally a live static profile
when no saved provenance exists. It never treats credentials containing a
session token as long-lived. A successful in-place renewal migrates the legacy
backup into managed logout/re-login provenance; a separate `--to` destination
leaves the source and its legacy backup untouched.

If an expired live MFA session has no usable managed original or matching legacy
backup, restore that profile's original static credentials or its matching
legacy backup, then run the same MFA login command again.

## Roles and session policies

`--role ARN_OR_NAME` assumes a role after authentication. `--policy` optionally
intersects that role with a session policy:

```shell
hacksaws web in debug --role AgentSession --policy ./agent.yaml
```

`--boundary NAME` / `--as NAME` loads a saved role, policy, external ID, and
duration. `+NAME` or `--target NAME` loads a complete saved login preset. `+` is
the documented shorthand prefix, but any leading non-alphanumeric character is
accepted so users can choose one their shell handles conveniently; the remaining
characters are the target name.

ECR login deliberately uses the intermediate authenticated credentials before
the final boundary credentials replace them.

To constrain credentials that are already logged in without repeating MFA or
browser authentication, use the standalone [`hacksaws assume`](assume-role.md)
workflow.

## Save a successful workflow

Add `--save=NAME` or `--save-name NAME` to `mfa in`, `web`/`pk in`, or `assume`
to create the account, optional boundary, and target configuration needed to
repeat the workflow as `+NAME`:

```shell
hacksaws web in debug --role AgentSession \
  --policy CloudWatchReadOnlyAccess --save=debug-agent
hacksaws web in +debug-agent
```

Bare `--save` defers the name prompt until after credential commit. It is
available only in an interactive terminal; JSON and noninteractive execution
must supply a name and fail before authentication otherwise. The separated form
`--save NAME` is deliberately rejected as ambiguous.

Authentication and configuration persistence are separate transactions. A
cancelled or failed post-login save does not discard valid credentials. The
result clearly reports the partial success and provides a
`target add --from-session` recovery command. See
[Saving login workflows](saved-targets.md) for the complete contract.

## Destination aliases

`.` and `default` mean `~/.aws` when used as locations and the `default` profile
when used as profiles. `--to .:.` and `--to default:default` are equivalent.
