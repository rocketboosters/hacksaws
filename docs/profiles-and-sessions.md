# Profiles, sessions, and logout

`hacksaws profile list` scans the default `~/.aws`, immediate `~/.aws-*`
directories, configured target directories, and active Hacksaws destinations. It
reports profile configuration and conservative credential states.

Without `--verify`, external profiles are `configured · unverified`. With
`--verify`, Hacksaws calls STS and reports verified, invalid, or unknown without
guessing from token shape.

Hacksaws-owned sessions may be active, expiring, expired, drifted, or missing
when its metadata and fingerprints prove that state:

```shell
hacksaws status
hacksaws status --verify
hacksaws profile list --verify
```

Logout uses profile-section compare-and-swap. Unrelated file sections survive;
drifted managed sections are skipped unless `--force` is explicit.

```shell
hacksaws logout debug
hacksaws logout --all
hacksaws logout --all --except "horizon:prod*" --except "+hacw"
```

`--except` requires `--all`. Patterns match canonical `location:profile` names
and target aliases. Tracked ECR logins are removed unless `--keep-ecr` is used.

`hacksaws assume` normally clears its managed source after installing the role
credentials at the destination. `--keep-source` deliberately retains both;
`--self` performs an in-place handoff and therefore cannot keep a second live
source. See [Assume a role](assume-role.md).
