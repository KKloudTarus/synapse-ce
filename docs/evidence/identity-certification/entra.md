# Microsoft Entra ID certification

This worksheet covers the public-cloud Entra v2 profile in
[issue #1518](https://github.com/KKloudTarus/synapse-ce/issues/1518). The
[live run](entra-live-run.md) separates hosted browser observations from signed
protocol conformance tests. The functional journeys and final reviews have passed. Durable runtime state is
recorded separately in the private deployment journal.

## Connection boundary

Configure the issuer as `https://login.microsoftonline.com/<directory-guid>/v2.0`,
using the canonical lowercase directory GUID. The issuer remains the token
authority in every discovery mode. `entra_discovery_mode` selects tenant-specific
metadata (`""`), `common`, or `organizations`. Alias discovery requires Microsoft's
exact issuer template and the matching alias endpoints. Authorization and token
exchange still use the approved directory's endpoints.

The signed token must contain that exact issuer and a string `tid` matching the
configured directory. Each signing key must have either that exact issuer or the
recognized tenant issuer template before it enters the verification cache. A
foreign key with a duplicate `kid` cannot borrow an approved key's scope. Audience,
nonce, expiry, signature, and fresh upstream authentication checks remain active.
Group, email, UPN, and display-name claims cannot select a person or membership.

Canonical Entra metadata may omit the PKCE capability field. The client still
sends an S256 challenge and its bound exchange verifier. Explicit null, malformed,
empty, or plain-only capability declarations fail. The omission exception does
not apply to arbitrary providers or mismatched Entra endpoints.

An existing connection can change metadata mode through a new draft, successful
provider Test, and activation. Saving a draft leaves the active mode unchanged.
Activation fences older pending transactions while existing local sessions retain
their authority. Initial provisioning fixes the mode with its first draft;
credential correction cannot change it. Legacy issuer-only adoption cannot opt
into alias discovery.

## Evidence map

| Flow | Evidence | Current result |
| --- | --- | --- |
| Configuration, Test, activation | Real hosted directory through all three metadata modes; activation attempted before Test | Passed; untested draft refused, tenant-specific mode restored |
| Approved login and unknown subject | Two hosted accounts; guest refused before additive linking | Passed; no JIT person or membership |
| First and additional enrollment | Explicit invitations in an isolated local tenant | Passed; first admin and same-person additional readonly, revoked invitation denied |
| Mailbox fallback | Real subject-bound Mailpit challenges, invalid code, sender outage and retry | Passed; same invitation retried after sender restoration, authority preserved |
| Additive linking and destination proof | Existing guest person, source readonly and destination member | Passed; one authenticator added, person and roles retained |
| Fresh authentication and outage retry | Microsoft email OTP, persisted authentication time, reversible API DNS fault | Passed; valid local session retained, fresh proof obtained after retry |
| Issuer, directory and signing-key scope | Signed adapter conformance with wrong/missing/malformed `tid`, per-key issuer filtering and duplicate `kid` | Passed; these are local protocol tests, not forged Microsoft tokens |
| Discovery and immutable settings | Strict metadata tests, connection lifecycle and initial provisioning persistence tests | Passed |
| Logout, disable and recovery | Hosted logout, disable, Auth0 fallback, Entra Test/reactivation and login | Passed; Required and all membership authority unchanged |

The broader Foundation denial/race and mailbox-delivery evidence remains in the
[Auth0](auth0-live-run.md) and [Keycloak](keycloak-live-run.md) records. Those shared
results are not relabeled as hosted Entra executions. Repeated theme sweeps and
destructive hosted identity remapping are outside the user's accepted functional
verification scope.
