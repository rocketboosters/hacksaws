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

The human `status` view is intentionally compact and changes only to fit the
filtered sessions being shown:

- `LOCATION` is omitted when every result is in the default AWS location. In a
  mixed result, `default` is written explicitly.
- `STATE` is one symbol. After one blank line, a single stable-order summary
  counts only the filtered rows, for example `State: 1 🟢active | 1 🔴expired`.
- `AUTH` uses `web`, `web→role`, `mfa`, `mfa→role`, `role`, `legacy`, or
  `unknown`. `hacksaws status --help` explains each complete login path.
- `SCOPE` uses friendly role and policy labels instead of IAM ARNs. A saved
  Hacksaws boundary preset is shown after the actual role as `Role (@Preset)`;
  `@Preset` is local configuration, not an IAM permissions boundary or a second
  role. `Role → Policy` means the session policy restricts the role: effective
  access is the intersection, never the union, of their permissions.
- `TTL` appears only when at least one displayed active or expiring session has
  a positive, meaningful expiry. It uses `<1m`, nearest-minute values below two
  hours, and nearest-hour values from two hours onward. Expired, invalid,
  residue, missing, drifted, legacy, and unknown rows stay blank.
- `VERIFY` appears only when `--verify` produced a useful STS result. `verified`
  means the returned account, partition, and expected role matched the recorded
  session; `mismatch` and `error` remain distinct. A mismatch detail names the
  actual account or role safely inside the mismatch cell. Sessions for which
  verification does not apply have a blank cell rather than a dash.

Profile, location, role, boundary, policy, and AWS diagnostic text is untrusted
terminal input. Hacksaws removes ANSI escapes and control characters before
measuring or rendering the table; `--no-color`, `NO_COLOR`, `TERM=dumb`, and
redirected output cannot be bypassed by stored names or AWS responses.

These are presentation rules only. `hacksaws status --json` retains the stable,
secret-free lifecycle data, including raw state names, IAM references, and
`remaining_seconds`; it never includes table symbols or key text.

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
