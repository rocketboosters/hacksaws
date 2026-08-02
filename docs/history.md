# Local command history

Hacksaws keeps a local, credential-free command history so people and agents can
understand what was attempted without retaining the material used to perform it.
It is enabled by default and stored in `~/.hacksaws/history/history.db`.

## What is recorded

Every CLI invocation receives a lifecycle record before argument parsing. After
successful parsing, Hacksaws adds only positively allowlisted metadata:

- the canonical command family and a recognized alias;
- validated profile, location, account, target, and IAM resource identifiers;
- safe booleans and enums such as dry-run, format, and output mode;
- input roles and formats, never file paths or file contents;
- whether an MFA code or external ID was supplied, never its value;
- semantic confirmation state, outcome, result code, timing, and safe counts;
- unresolved recovery state, which is protected from automatic retention and
  manual clear operations.

Hacksaws never stores raw command-line arguments, stdout, stderr, result or
exception text, prompts or responses, environment variables, working
directories, file paths, policy documents, credentials, MFA codes, external IDs,
or other secret values. History is diagnostic only: a history-write failure
never changes the command result or corrupts JSON output.

The database uses SQLite WAL mode and an additive `PRAGMA user_version` schema.
An invocation begins as `running` and is atomically finalized as completed,
interrupted, or crashed. A running invocation older than 24 hours is marked
abandoned during routine maintenance.

## Inspect history

```shell
hacksaws history list
hacksaws history list --wide --since 7d --outcome operational-error
hacksaws history search "*ServiceBuzz*" "*iam.policy*"
hacksaws history show 12ab34cd
hacksaws history report --since 30d --account 123456789012
hacksaws history status
hacksaws history check
```

`list` and `search` default to the 50 newest completed records. Filters include
`--since`, `--until`, `--command`, `--outcome`, `--account`, `--resource`, and
`--limit`. Times may be ISO timestamps or durations meaning “that long ago.”
Duration units accept the same seconds/minutes/hours grammar as session duration
plus days and weeks, including `600s`, `15minutes`, `24h`, `7d`, and `2weeks`.
Add `--include-running` when diagnosing an active process.

`show` accepts a complete history ID or an unambiguous prefix of at least four
hexadecimal characters. Its human view includes a reconstructed command
template. File and secret inputs appear only as placeholders, so the template is
useful for teaching without becoming a credential-recovery mechanism.

Every command accepts global `--json`. Machine mode retains the same single
Hacksaws result envelope used by the rest of the CLI.

## Export history

```shell
# Deterministic JSON Lines on stdout
hacksaws history export --format jsonl --since 7d

# One JSON array in a file
hacksaws history export --format json --output history.json
```

Exports contain the same redacted records returned by `history list`; export
does not re-read command output or policy documents. JSON Lines is the default.
When `--output` is omitted, the export is written to stdout. In global JSON
mode, records are returned inside the standard result envelope.

## Retention and clearing

Defaults retain resolved records for 90 days, up to 10,000 entries and 50 MiB of
logical record size. Maintenance runs at most daily after command completion.
Oldest eligible records are removed first. Running commands and unresolved
recovery records are never removed by retention or `history clear`.

```shell
hacksaws history clear --before 30d --dry-run
hacksaws history clear --before 30d
hacksaws history clear --all --yes
```

Without `--dry-run` or `--yes`, an interactive clear requires typing exactly
`yes`. JSON and non-interactive execution require `--yes`.

The settings are self-documented by `hacksaws config options` and may be managed
like other configuration values:

```shell
hacksaws config get history.enabled
hacksaws config set history.enabled false
hacksaws config set history.max_age 2592000
hacksaws config set history.max_entries 5000
hacksaws config set history.max_bytes 26214400
```

The three limits are positive integers expressed in seconds, entries, and bytes.
Disabling history prevents new records; it does not delete existing history. Use
`history clear` for explicit removal.
