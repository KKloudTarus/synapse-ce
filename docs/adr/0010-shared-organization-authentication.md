# Shared organization authentication

The fixed-tenant BFF authenticates legacy users and sessions. The identity foundation already models
persons, memberships, connections, credentials and revocation epochs, but those records do not yet
authenticate requests. Shared organization authentication uses a separate application service over
these records, with common protocol, cryptographic, cookie and authorization primitives.

The following invariants govern implementation and delivery:

- Exact credential routing identifies a tenant and kind; a tenant-bound authoritative read verifies
  credential, session, person, membership, connection, current policy and epochs on every request.
- Upstream authentication time and session lineage origin are separate immutable values. Rotation
  preserves both; the twelve-hour lineage boundary is exclusive.
- Approved exact connection subjects establish identity. Email and groups never locate a person,
  create membership, restore suspended access or grant a role.
- Protocol transactions bind purpose, immutable connection revision, nonce, PKCE S256 and initiating
  session. Consumption precedes exchange; a failed exchange cannot reuse state.
- Session and administration commands lock policy before dependent identity rows. Switching and
  replay lock both tenant policies in lexical order before source and destination rows. Only the
  narrow switch command store may rebind transaction-local RLS. Ordinary repositories
  continue to reject a nested tenant mismatch. No network call occurs while locks are held.
- Required destination SSO needs that destination's own approved connection proof for the same
  person. A missing proof returns `reauthentication_required` without changing either session.
- Response-loss recovery uses an exact same-key/same-payload, short-lived locator. Retained session
  and CSRF material is authenticated-encrypted; revocation or logout invalidates recovery.
- Recovery activation, audit and a nonsecret retained alert obligation commit atomically. The
  resulting credential retains its recovery-only kind through transport and authorization.
- Native writes require declared cutover. Read and mutation tenant sets are subset validated;
  enterprise identity stays disabled by default. A failure in an enabled enterprise path is terminal
  and cannot be retried through legacy authentication.

Persistence commands own consequential audits and uniqueness/revision rechecks. OIDC adapters emit
bounded neutral verified evidence and use bounded HTTPS clients that validate every resolved and
dialed address, disable ambient proxies and redirects, and cap decoded responses. Provider discovery
is lazy so an outage cannot prevent startup. Invitation mailbox challenges use the existing security
verification sender rather than customizable notification content.

Extending legacy session records would conflate user and person identity and could miss epoch
revocation. Duplicating HTTP cookies, authorization decisions or notification frameworks would create
independent security owners. The chosen boundary keeps the existing constructors and flag-off path
while exposing only narrow enterprise commands through application ports.

Rollout is migrate-first, expand/backfill/shadow, subset canary reads, declaration, then native
mutations. Before declaration, abort leaves legacy authentication authoritative. After declaration,
rollback requires paired backups or a forward fix; disabling a feature flag does not make native
identity data representable in legacy users. Deterministic OIDC conformance, real PostgreSQL RLS and
race/fault tests, browser flows and the abort drill are required before the delivery gate.
