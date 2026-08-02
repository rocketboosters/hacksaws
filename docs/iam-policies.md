# IAM policies

Remote commands live under `hacksaws iam policy` (`remote` is an alias).

```shell
hacksaws iam policy create agent.yaml AgentRead --profile admin --dry-run
hacksaws iam policy list "*Agent*" --custom --profile admin
hacksaws iam policy get AgentRead --profile admin
hacksaws iam policy export AgentRead agent.yaml --metadata nested --profile admin
hacksaws iam policy update AgentRead agent.yaml --profile admin
hacksaws iam policy versions AgentRead --profile admin
hacksaws iam policy delete AgentRead --profile admin
```

References accept names or ARNs. Create checks AWS first: identical state is
`NO CHANGE`; different state is `CONFLICT`. Prefer `update`; use `--replace`
only for a deliberate create-style replacement preview.

Policy files accept JSON, YAML, and TOML. Export metadata modes are:

- `nested`: top-level `metadata` and `policy` keys in one file.
- `sidecar`: bare policy plus a separate metadata file.
- `none`: bare IAM policy document.

Create accepts `NAME FILE` or `FILE NAME`; omit the name to derive it from the
filename. `--name NAME --file FILE` is the explicit form. Update accepts
`POLICY FILE` in either unambiguous order and provides `--policy` / `--file` for
the explicit form. Path syntax, a supported extension, or an existing local file
identifies the file; ambiguous input fails before AWS access.

All mutations accept `--dry-run`. AWS Access Analyzer validation is used unless
`--local-validation-only` is explicit.

`create --replace` never adopts an unowned name collision. Use `adopt` as a
separate reviewed mutation. Adoption reconciles the protected Hacksaws ownership
tags while preserving the policy document and unrelated tags; `release` removes
only protected ownership tags. Legacy partial ownership is never silently
inferred—run `adopt --dry-run` to review its exact tag repair.

Local reusable documents use `hacksaws policy add|get|list|update|remove|rename`
and are stored as YAML under `~/.hacksaws/stored_session_policies`.
