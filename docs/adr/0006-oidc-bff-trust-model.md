# ADR 0006 — OIDC BFF trust model

**Status:** Accepted · **Date:** 2026-08-20 · **Deciders:** Issue #592

## Context

Browser sign-in needs OIDC without turning browser-held tokens or tenant-provided claims into an
application trust boundary. Synapse already authorizes actions through its existing roles and supports
bearer authentication for machine clients. The BFF must remain safe when API replicas scale horizontally.

## Decision

Browser OIDC uses a backend-for-frontend (BFF) model:

- The BFF performs the authorization-code flow and keeps provider tokens server-side. It accepts an
  identity only when the configured issuer and subject both exactly match an approved identity record.
  Matching issuer alone, matching a mutable display claim, wildcard subjects, and email-domain matching
  are not authorization.
- Each deployment has one fixed Synapse tenant for browser sessions. The BFF does not choose a tenant
  from an OIDC claim, request parameter, host header, or client-side state.
- A matched identity maps only to an explicitly allowlisted existing role: `admin`, `consultant`,
  `reviewer`, or `read-only`. Unknown, missing, or newly asserted provider roles deny sign-in; the BFF
  never creates roles or expands privileges from provider claims.
- The browser receives only an opaque, high-entropy session identifier in a `Secure`, `HttpOnly` cookie.
  Session identity, expiry, revocation state, and role live in a shared durable session store so any API
  replica can validate or revoke the session. No bearer or OIDC token is exposed to browser JavaScript.
- The BFF validates OIDC state and nonce, uses redirect URI allowlisting, and requires a session-bound
  CSRF token for every browser-authenticated state-changing request. CSRF validation is independent of
  cookie `SameSite` behavior.
- Existing `Authorization: Bearer` machine authentication remains unchanged. It does not become an OIDC
  browser fallback and retains its current principal and authorization semantics.

## Consequences

- Identity and role allowlists require explicit operator administration and audit records.
- OIDC discovery or claim changes cannot silently widen tenant or role access.
- Session storage, key rotation, expiry, logout, and replica-safe revocation are production dependencies.
- Browser and machine access are distinct paths through the same authorization chokepoint described in
  [Security model](../guide/security.md).
