> Canonical source: [`docs/adr/0004-cspm-helper-authorization.md`](https://github.com/KKloudTarus/synapse-ce/blob/main/docs/adr/0004-cspm-helper-authorization.md). Do not edit this published mirror directly.

# ADR 0004 — CSPM helper authorization boundary

**Status:** Accepted · **Date:** 2026-08-12 · **Deciders:** CSPM issue #429

## Context

Live AWS, Azure, and Google Cloud inventory needs provider SDKs and credentials, but those capabilities must not run inside `synapse-api` or `synapse-worker`. Network containment cannot infer provider API intent from encrypted HTTPS traffic.

## Decision

Provider SDKs run only in the SHA-256-pinned `synapse-cspm` helper inside the default-deny sandbox. The worker resolves the engagement credential and sends it through an inherited pipe; it never places secret material in argv, environment values, queue payloads, logs, or evidence.

Authorization is cooperative at the HTTPS operation boundary: before each provider request, the helper sends provider, canonical scope, category, and operation name to the parent over inherited file descriptors. The parent rechecks the active engagement, authorization window, exact target scope, and rules of engagement. It also denies operation names outside a provider-specific read-only allowlist. Only an allowed decision lets the helper issue the request.

The boundary has independent controls: the helper binary is authoritatively pinned, cloud credentials are read-only, provider egress hosts are explicitly allowlisted, sandboxing and kernel egress enforcement fail closed, and normalized output is redacted before publication.

Vulnerability-provider `allow_private_network` configuration is a separate, administrator-reviewed SSRF exception for approved internal mirrors. It permits private destination addresses only; loopback, link-local, cloud metadata, unspecified, multicast, carrier-grade NAT (`100.64.0.0/10`), and IPv4-mapped representations of those blocked address classes remain denied.

Google OAuth token refresh is routed through the parent-side authorization callback and remains limited to the exact `oauth2.googleapis.com/token` operation inside the sandbox's explicitly configured egress boundary. Azure token acquisition passes through the authorization-aware transport and is allowlisted only for the tenant OAuth token endpoint.

## Consequences

- An unexpected or mutating operation is denied even if a connector attempts it.
- Scope or authorization revocation between queueing and execution fails closed.
- Adding a new provider operation requires an explicit read-only allowlist update and test.
- The parent does not inspect TLS payloads; helper pinning, credential permissions, and default-deny egress remain part of the trust boundary.
