# Security model

Hacksaws reduces credential blast radius; it cannot make readable credentials
secret from a process with equivalent filesystem access.

For MFA login, persistent unauthenticated source credentials remain available.
They should permit only the MFA/bootstrap operations required by the workflow.
MFA-authenticated intermediate credentials are not backed up when a role or
policy boundary is used. Only the final boundary credentials are written to the
agent-facing destination.

Session policies are intersections, not grants: the assumed role must already
permit an action, and the session policy may only remove access. AWS enforces
both a plaintext session-policy limit and a separate packed binary limit.
Hacksaws detects and explains these failures but does not transform policy
semantics.

Remote mutations verify caller identity and expected account before planning.
Hacksaws tags created/adopted resources, uses immutable AWS resource IDs in
recovery checks, detects drift before mutation, and refuses destructive action
when ownership cannot be proven.

Logout never preserves intermediate authenticated credentials. It edits only the
managed profile section using fingerprints and leaves unrelated file data
untouched.

Standalone role assumption follows the same contract. The assumed credentials
are obtained before the local transaction begins; then the destination is
installed and the managed source is removed unless `--keep-source` was explicit.
In-place `--self` retains only the pre-login backup required by logout, not a
second copy of the broader authenticated session. Preview and JSON surfaces omit
credential values, backups, and policy documents.

An assumption confirmation is bound to one immutable prepared plan. Hacksaws
does not re-resolve a target, boundary, role, policy, duration, or endpoint
after approval, and it aborts if source, destination, cache, or configuration
state changes before the credential transaction begins.
