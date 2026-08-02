# Automation and JSON

Place `--json` anywhere before the literal `--` to receive one versioned result
envelope on stdout or stderr. Prompts are disabled in JSON mode. Mutations that
would prompt require explicit `--yes`; create collisions additionally require
`--replace` where supported.

Progress is suppressed in JSON mode, even when `--progress` is present, so the
selected stream still contains exactly one envelope. Human progress uses stderr
and never contaminates a final table written to stdout. Inventory summary JSON
uses `detailsComplete: false` and omits dependency fields unless `--details` was
explicitly requested; progress timing and transient counts are never part of the
stable envelope. `scope` is `canonical` or `all-account`;
`inventoryComplete: false` means one or more candidates were omitted and the
`warnings` array explains why. Explicit `--created` or `--adopted` filters still
narrow an `--all-account` inventory; `detailsComplete` reports whether
dependency-detail inclusion was requested, not whether warnings occurred.

```shell
hacksaws --json iam policy create agent.yaml --profile admin --dry-run
hacksaws iam list --profile admin --json
hacksaws cleanup --all --profile admin --dry-run --json
hacksaws assume admin --role AgentSession --to default:agent --yes --json
```

Global color controls are `--color auto|always|never` and `--no-color`.
Automation should inspect both numeric exit codes and symbolic result codes or
classifications. Cleanup plan JSON uses `planned`, `no-matches`, or `blocked`.
Executed cleanup results use `cleaned`, `partial`, `blocked`, or
`recovery-required`; the outer result code additionally distinguishes a safety
refusal. See [cleanup.md](cleanup.md).

Dry runs on normal remote mutations perform remote reads and validation but
create no journal and make no AWS or local mutation. They can therefore fail
when credentials, account assertions, references, validation, or dependencies
are invalid. Recovery `continue` and `rollback` resume an existing journal and
do not offer dry-run mode.

`hacksaws assume` always performs a secret-free preflight. JSON and other
noninteractive invocations require `--yes` before `AssumeRole` or local
mutation; the envelope contains endpoint, identity, role, account, partition,
and lifecycle metadata but never credentials, backups, or policy documents.
