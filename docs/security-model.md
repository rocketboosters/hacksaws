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
