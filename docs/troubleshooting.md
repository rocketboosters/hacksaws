# Troubleshooting

## Browser profile was not created

Run the current package with `uvx hacksaws` or `uv run hacksaws`. Browser login
verification requires the Botocore CRT extra, which is a project dependency.
Hacksaws rolls back partially written browser-login state when verification
fails.

## `PackedPolicyTooLarge`

AWS compresses session policies, policy ARNs, and session tags into a separate
packed representation. A minified document below the plaintext character limit
can still exceed this packed limit. Publish the policy as a customer-managed
policy and attach it to the role, or reduce role/session-tag complexity.
Hacksaws deliberately does not rewrite policy statements.

## Policy changed but the session did not

The remote policy cache may still be fresh. `hacksaws cache list` identifies
fresh/stale entries and `hacksaws cache clear PATTERN` invalidates selected
entries.

## A mutation was interrupted

```shell
hacksaws iam recovery list
hacksaws iam recovery get JOURNAL_ID
hacksaws iam recovery continue JOURNAL_ID --profile admin
hacksaws iam recovery rollback JOURNAL_ID --profile admin
```

Never delete a recovery journal manually while its AWS outcome is uncertain.

### Cleanup recovery decisions

Inspect the journal with `recovery get` before choosing a direction, and use
credentials for the journal's exact AWS account and partition.

- Use `continue` when cleanup is still the intended outcome and the journal has
  pending or retryable forward work. Cleanup resumes its dependency-aware queue,
  retries eligible failures, and verifies that selected resources are absent.
- A successfully completed cleanup has `payloadsScrubbed: true`. It is a
  credential-free diagnostic receipt: `continue` is an idempotent success check,
  but `rollback` is intentionally unavailable because the compensation payloads
  were removed.
- IAM role and policy deletion crosses an irreversible identity commit point.
  AWS cannot recreate the original `RoleId` or `PolicyId`; Hacksaws will not
  create a same-named replacement and claim that rollback succeeded.
- Manual remediation is required when the result is `recovery-required`, an
  irreversible delete succeeded before a later step failed, AWS absence cannot
  be proven, the recorded account/partition is missing or mismatched, or
  resource drift prevents safe replay. Preserve the journal, inspect the
  remaining AWS resources, and rebuild only after reviewing the reported
  completed, failed, and remaining steps.
