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

All mutations accept `--dry-run`. AWS Access Analyzer validation is used unless
`--local-validation-only` is explicit.

Local reusable documents use `hacksaws policy add|get|list|update|remove|rename`
and are stored as YAML under `~/.hacksaws/stored_session_policies`.
