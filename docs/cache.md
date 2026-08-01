# Policy cache

Resolved remote session policies are minified and cached under
`~/.hacksaws/policy-cache`. Local policy inputs are refreshed every time,
converted to canonical minified JSON, and passed through the same cache loading
path. Remote cache hits are always disclosed.

```shell
hacksaws cache status
hacksaws cache list
hacksaws cache list "*CloudWatch*" --fresh
hacksaws cache show ENTRY
hacksaws cache get
hacksaws cache get max-age
hacksaws cache set max-age 4h
hacksaws cache clear --stale
hacksaws cache clear --all --yes
```

The cache does not bypass AWS's inline session-policy size or packed-policy
limits. Browser-login provider state is session state, not policy-cache state,
and is handled by status/logout commands.
