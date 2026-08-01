# Configuration

Hacksaws stores first-class configuration in `~/.hacksaws/configs.json`.
Accounts scope boundaries, naming rules, validation, check/fix, and remote IAM
operations. Targets save login source/destination choices; boundaries save role,
policy, external ID, and duration choices.

```shell
hacksaws account add prod 123456789012 --profile admin
hacksaws account list
hacksaws account rename prod production
hacksaws boundary add logs AgentSession --account prod --policy LogsRead
hacksaws target add debug --source-account prod --source-profile admin
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

`config export` creates a portable zip excluding temporary caches.
`config import` validates the complete archive before replacing state.
