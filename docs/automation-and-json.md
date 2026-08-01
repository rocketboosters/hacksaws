# Automation and JSON

Place `--json` anywhere before the literal `--` to receive one versioned result
envelope on stdout or stderr. Prompts are disabled in JSON mode. Mutations that
would prompt require explicit `--yes`; create collisions additionally require
`--replace` where supported.

```shell
hacksaws --json iam policy create agent.yaml --profile admin --dry-run
hacksaws iam list --profile admin --json
hacksaws cleanup --all --profile admin --dry-run --json
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
