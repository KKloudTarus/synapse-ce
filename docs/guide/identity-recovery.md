# Identity recovery

Break-glass recovery is for restoring organization identity administration when the normal SSO
path cannot be used. It issues a short-lived `break_glass` browser session. That credential can
perform only the recovery actions in the authorization allowlist; it cannot read assessment data,
run scans, manage integrations, or mint ordinary credentials.

An organization administrator with a fresh browser authentication, or the deployment bootstrap
operator, configures the policy and rotates an activation secret. The secret is generated with 256
bits of randomness, shown once, and stored only as a SHA-256 digest. Rotating it consumes every
previous usable activation for that membership.

Activation consumes the exact digest and creates the break-glass session in one database
transaction. It cannot be replayed. Sessions expire within 15 minutes and are bound to the active
administrator membership and current person and membership epochs.

Every successful activation creates an immutable, non-secret alert obligation in the same
transaction and appends audit evidence. The obligation is retained even if normal notifications
are disabled, paused, or have no matching rules. Delivery uses the dedicated SMTP method and has
persisted `pending`, `delivered`, and `exhausted` states with bounded retry attempts, so worker
restarts do not lose it.

When recovery is required, an alert destination must be configured and the recorded rehearsal
must be no more than 30 days old. Review exhausted alert obligations and rehearse before the
policy becomes stale.
