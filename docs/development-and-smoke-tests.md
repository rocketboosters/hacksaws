# Development and smoke tests

Run the complete local quality gate:

```shell
uv sync
uv run test
```

The gate checks Ruff formatting/linting, mypy, Prettier, warning-free tests,
95%+ coverage, package build, and an installed-wheel CLI smoke check. The task
layout follows Camber Ops conventions and works with `mpx --me check`.

Live IAM smoke tests are explicit and never run in ordinary CI. They require an
account/target guard, create a tagged role and customer-managed policy under
`/hacksaws-test/`, exercise trust/inline/managed attachment/version behavior,
then run cleanup dry-run, cleanup, and absence verification.

Set all four guards explicitly before invoking the live marker:

```shell
HACKSAWS_LIVE_AWS=1 \
HACKSAWS_LIVE_AWS_CLEANUP=1 \
HACKSAWS_LIVE_AWS_ACCOUNT_ID=123456789012 \
HACKSAWS_LIVE_AWS_TARGET=smoke-admin \
uv run pytest -m live_aws
```

The account ID must exactly match the target's caller identity. The target must
be a named Hacksaws target; ambient/default credentials are never accepted by
the harness. Keep the target dedicated to a disposable test account.

Smoke resources carry `hacksaws:smoke=true` and a unique smoke-run ID. If a run
fails, use the printed recovery command:

```shell
hacksaws cleanup --smoke-run RUN_ID --target TARGET --dry-run
hacksaws cleanup --smoke-run RUN_ID --target TARGET --yes
```

Group, permissions-boundary, and instance-profile smoke fixtures require
separate opt-in disposable containers.
