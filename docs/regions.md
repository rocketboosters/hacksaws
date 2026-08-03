# Regions and aliases

Hacksaws resolves AWS regions once, before creating AWS sessions, and carries
the canonical region through authentication, STS identity checks, IAM helpers,
ECR login, generated console links, and destination profile configuration. This
avoids one command accidentally using different regions at different stages.

## Discover and explain

```shell
hacksaws region list
hacksaws region list "*west*" "*oregon*"
hacksaws region explain usw2
hacksaws region explain oregon
hacksaws region list --account production
hacksaws region list --partition aws-cn
hacksaws region list --all-partitions
```

`region list` shows the canonical name, AWS description, partition,
collision-free compact alias, curated geography aliases, and custom aliases.
Patterns use case-insensitive fnmatch syntax and multiple patterns are ORed.
`--account` limits results to that configured account's partition. Add global
`--json` for stable machine-readable output.

Hacksaws discovers every partition in the installed Botocore metadata. It can
operate only in `aws`, `aws-cn`, and `aws-us-gov`; `--all-partitions` is for
discovery and explanation, not permission to run AWS operations elsewhere.

## Accepted inputs

Every region-bearing command accepts:

- canonical names, such as `us-west-2`;
- collision-free compact aliases, such as `usw2`;
- curated, unambiguous geography aliases, such as `oregon`;
- global custom aliases configured by the user.

Aliases are input-only. Configuration and AWS profiles always receive the
canonical name, so changing or removing an alias never changes existing saved
consumers.

Manage portable custom aliases with:

```shell
hacksaws region alias add pacific us-west-2 --description "Primary west region"
hacksaws region alias list "pac*"
hacksaws region alias get pacific
hacksaws region alias update pacific --region us-west-1
hacksaws region alias rename pacific west-coast
hacksaws region alias remove west-coast
```

Custom aliases use normalized lower-kebab-case. They cannot shadow a canonical
name or built-in alias, point to another alias, or target a region absent from
Botocore. Those rules prevent alias chains and machine-dependent resolution.

## Resolution precedence

The effective region is the first available value in this exact order:

1. command `--region`;
2. `AWS_REGION`;
3. `AWS_DEFAULT_REGION`;
4. saved target region;
5. existing destination AWS profile region;
6. source AWS profile region;
7. configured account preference;
8. global `aws.region` setting;
9. a Hacksaws-owned interactive prompt.

An environment-selected region is written to the destination only when that
destination does not already store a region. All other selected values are
persisted canonically where the workflow installs a region.

If nothing resolves, an interactive terminal prompts with retry, suggestions,
`?` to list candidates, and `q` to cancel. Non-interactive and JSON execution
never prompts; it returns a structured `REGION_REQUIRED`, `REGION_INVALID`, or
`REGION_UNKNOWN` error with candidates and repair guidance.

## Saved preferences

```shell
# Global fallback
hacksaws config set aws.region oregon
hacksaws config reset aws.region

# Account preference
hacksaws account update production --region ohio
hacksaws account update production --clear-region

# Highest-priority saved target preference
hacksaws target update prod-agent --region pacific
hacksaws target update prod-agent --clear-region
```

Inspect or deliberately change the physical region stored on an AWS profile:

```shell
hacksaws profile region get --profile debug
hacksaws profile region set oregon --profile debug
hacksaws profile region clear --profile debug
```

The profile command accepts the usual `--profile`, `--location`/`--directory`,
or saved `--target` selector. Updates are transactional. For a Hacksaws-managed
session, Hacksaws also rebases its logout metadata so a later logout preserves
the deliberate change. Clearing is refused for a live native-browser profile,
because the AWS browser credential provider requires a physical region; log out
first in that case.

`hacksaws config show` includes account, target, global, and alias information.
`config options` documents the dotted settings; direct equivalents such as
`config set accounts.production.region ohio` and
`config reset targets.prod-agent.region` are supported.

## New regions and service validation

Botocore metadata can lag a newly announced canonical region. Use
`--allow-unknown-region` only when the exact canonical-shaped value is known:

```shell
hacksaws region explain us-future-1 --allow-unknown-region
hacksaws iam policy list --region us-future-1 --allow-unknown-region
```

The escape hatch never accepts alias-like input such as `future-west`, never
bypasses account partition checks, and emits a warning because service support
could not be verified. Without the flag, unknown values fail before credentials
or AWS mutations are attempted.

IAM/remote/cleanup uses the canonical region for credential refresh, STS
identity, regional helpers, and partition-correct console links. A region whose
partition differs from the authenticated caller is rejected. Repeated
`--ecr-region` values accept the same aliases, are canonicalized and
deduplicated in input order after the effective primary region, and are checked
for ECR support. ECR login still uses the intermediate authenticated credentials
before any boundary role is assumed.
