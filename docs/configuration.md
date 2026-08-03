# Configuration

Hacksaws stores first-class configuration in `~/.hacksaws/config.json`. Accounts
scope boundaries, naming rules, validation, check/fix, and remote IAM
operations. Targets save login source/destination choices; boundaries save role,
policy, external ID, and duration choices.

```shell
hacksaws account add prod 123456789012 --profile admin
hacksaws account list
hacksaws account rename prod production
hacksaws boundary add logs AgentSession --account prod --policy LogsRead
hacksaws target add debug --source-account prod --source-profile admin
hacksaws target update debug --region oregon
hacksaws config set aws.region us-east-2
hacksaws config show --account prod
hacksaws config explain debug
hacksaws config check --account prod --profile admin --remote
hacksaws config fix --account prod --profile admin --remote
hacksaws config fix --account prod --target prod-admin --remote --probe
```

Both `check` and `fix` accept `--profile`, `--location`, `--directory`, or a
saved `--target` to select account credentials. `--no-verify` skips individual
resource verification where supported. `--probe` implies remote checking and
performs a deny-all AssumeRole probe before offering interactive repairs.

`config option list` teaches every supported setting with a short description.
Naming rules have global account defaults and policy/role overrides for prefix,
suffix, case, path, and enforcement.

Region preferences are also first-class settings. Values supplied through the
CLI may be canonical names or aliases; the configuration always stores the
canonical region. Global custom aliases are input-only and portable across
accounts:

```shell
hacksaws region alias add pacific us-west-2 --description "Primary west region"
hacksaws account update prod --region pacific
hacksaws target update debug --region oregon
hacksaws config get aws.region
hacksaws config reset targets.debug.region
```

The schema-one region fields are `aws.region`, `aws.region_aliases`, optional
`accounts.NAME.region`, and optional `targets.NAME.region`. `config export`
includes them, and `config import`, `check`, and `fix` validate canonical
storage, alias collisions, and account partition compatibility. See
[Regions and aliases](regions.md) for precedence and discovery commands.

Local history settings are first-class options as well:

```shell
hacksaws config get history.enabled
hacksaws config set history.enabled false
hacksaws config set history.max_age 7776000
hacksaws config set history.max_entries 10000
hacksaws config set history.max_bytes 52428800
```

The limits use seconds, entries, and bytes. See
[Local command history](history.md) for the redaction and retention contract.

`config export` creates a portable zip excluding temporary caches.
`config import` validates the complete archive before replacing state.
