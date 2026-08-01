# Cleanup and Leave No Trace

Cleanup operates in exactly one verified AWS account and only selects resources
whose Hacksaws ownership is established. It never deletes IAM users, groups,
instance-profile containers, service-linked roles, AWS-managed policies, or
local configuration.

```shell
hacksaws cleanup "*ServiceBuzz*" --policies --profile admin --dry-run
hacksaws iam cleanup --all --profile admin --dry-run
hacksaws remote cleanup --smoke-run RUN_ID --profile admin --yes
```

Patterns are case-insensitive fnmatch expressions and are ORed. Type and origin
filters narrow that selection. `--smoke` and `--smoke-run` are additional AND
filters. `--all` conflicts with patterns and never grants dependency consent.

Selected internal dependencies are ordered automatically: group grants, roles,
then policies. Dependencies on retained resources require `--cascade`,
`--remove-boundaries`, or `--remove-from-instance-profiles`. Transient AWS
failures are retried at the bottom of the ready queue up to three times; other
independent resources continue.

Exit codes are stable:

- `0`: success or executable dry run, including no matches.
- `1`: input, authentication, or planning failure before mutation.
- `2`: partial execution or dependency-blocked residue.
- `3`: ownership/account safety could not be proven.

In JSON, a plan's `classification` is `planned`, `no-matches`, or `blocked`.
After execution, the nested result classification is `cleaned`, `partial`,
`blocked`, or `recovery-required`.

AWS audit trails remain. A minimal credential-free local receipt remains for
diagnosis, while temporary policy/trust recovery material is removed after a
successful cleanup. That scrubbed completed receipt can be inspected but cannot
be rolled back because its compensation payloads no longer exist. If cleanup
crosses an irreversible IAM identity deletion and then fails, recovery reports
the remaining manual rebuild instead of recreating a same-named, different
principal and claiming success.
