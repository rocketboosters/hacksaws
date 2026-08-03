# Saving login workflows

A successful MFA login, browser login, or role assumption can be saved as a
reusable target. The next run uses `+NAME` or `--target NAME` instead of
repeating the source, destination, role, policy, and duration choices.

```shell
hacksaws web in debug \
  --role AgentSession \
  --policy CloudWatchReadOnlyAccess \
  --save=debug-agent

hacksaws web in +debug-agent
```

`--save=NAME` is the concise noninteractive spelling. `--save-name NAME` is the
equivalent separate-token form. Bare `--save` asks for a name only after the
credential transaction succeeds. `--save NAME` is intentionally rejected so a
positional profile or MFA code cannot silently become a target name.

JSON and other noninteractive execution never prompts. Bare `--save` fails with
exit code 2 and `SAVE_NAME_REQUIRED` before AWS authentication begins.

## What is saved

Hacksaws creates a small configuration graph:

- one source account, keyed independently from its friendly display metadata;
- a second account when the assumed role belongs to another account;
- a boundary when the workflow assumes a role, including its optional policy and
  duration; and
- a target containing the source and destination profile locations plus the
  optional boundary.

No live credentials, browser tokens, MFA codes, ECR authorization, or other
login state is copied into configuration. External IDs are omitted unless the
user explicitly supplies `--save-external-id`. A local session policy must be
copied into stored policy storage: use `--store-policy-as NAME`, or choose a
name when prompted interactively. Remote and already-stored policies retain
their canonical reusable references.

Advanced names are available when an organization's conventions require them:

```text
--save-source-account NAME
--save-role-account NAME
--save-boundary NAME
--save-external-id
--store-policy-as NAME
```

These controls require a save request. Existing resources are reused only when
their stable identity and complete saved values match. A collision with
different settings fails; Hacksaws never silently overwrites or mutates shared
configuration.

## Account discovery

Discovery runs with the intermediate authenticated credentials, before a
boundary replaces them. Boundary credentials are never used to teach Hacksaws
about the broader source identity.

Every successful MFA, browser, and assume command registers or reuses its
verified account records, even without `--save`. This account registration is
reported independently from the optional target bundle: machine results expose
`accountRegistration` counts plus `bundleRequested` and `bundleSaved`, so an
ordinary login never implies that a target was saved. History records the two
outcomes as separate safe event families.

The verified AWS partition and 12-digit account ID are the stable identity.
Hacksaws prefers an explicit save-name override, then an existing unique account
record for that identity, an IAM account alias, an Organizations account name,
and finally `account-ACCOUNT_ID`. A role or policy ARN supplies its owning
account directly. For cross-account roles, a source-account IAM alias is never
misapplied to the role account; Organizations discovery is used when allowed,
otherwise the account-ID fallback is deterministic.

Denied optional discovery calls produce a neutral note. Unexpected service
failures produce a warning. Neither prevents a valid login or save because the
verified account-ID fallback remains available. Display names never replace the
stable identity or automatically rename an existing account record.

## Credential commit and partial success

The login/assume transaction completes before interactive naming and final
configuration persistence. This keeps the user's valid authenticated or bounded
credentials even if they cancel the save, a name collides after discovery, or a
configuration write cannot complete. Hacksaws reports that as successful
authentication with an incomplete configuration save; it does not claim that the
entire command was rolled back.

Recover from the active, Hacksaws-managed session without authenticating again:

```shell
hacksaws target add debug-agent --from-session debug
hacksaws target add debug-agent --from-session admin --location horizon
hacksaws target add debug-agent --from-session debug \
  --policy ./agent.yaml --store-policy-as debug-agent-policy
```

Use `-d/--directory` instead of `--location` for an explicit AWS directory.
Manual source/destination shape fields cannot be mixed with `--from-session`.
`--policy` and `--external-id` are recovery-only inputs for metadata that active
session state intentionally does not retain; persist an external ID only with
the additional `--save-external-id` consent flag.

Recovery requires a usable active session managed by Hacksaws and is idempotent.
It does not authenticate, assume another role, or change the live credentials.
