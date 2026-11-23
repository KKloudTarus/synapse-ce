# Certifying Keycloak realms (#1517)

The demands this certification proves, and the connection lifecycle it runs through, are in
[Certifying an identity provider](../../guide/identity-provider-certification.md). That page is read from
the code; this worksheet records the hosted observations and maintained native conformance used
for the accepted release scope. The shared foundation is inherited from the reviewed Auth0 delivery;
Keycloak adds no separate production identity or authorization path.

## Connection

| Field | Value |
| --- | --- |
| Issuer | `https://challenges-burke-pacific-survivors.trycloudflare.com/realms/synapse-e2e` (current process-bound sandbox origin) |
| Client ID | `synapse-e2e` (existing synthetic confidential client) |
| Client secret | sealed per tenant and connection; never returned by any API |
| Redirect URL | `https://127.0.0.1:8446/api/auth/enterprise/callback` |

Read the issuer from the provider's own discovery document before saving the connection. An issuer that
differs by one path segment fails at callback time, not at save time.

## Provider setup

- Create a confidential client in the realm with the standard flow enabled and the authorization-code grant.
- Set the valid redirect URI to the deployment's exact callback, `https://127.0.0.1:8446/api/auth/enterprise/callback`.
- Keep the client's PKCE method as S256; the client always sends a code challenge.
- Leave the realm's `email_verified` mapper on, and confirm the realm issues `auth_time` for a `max_age` request.

## Repeatable protocol and admission gate

On Linux with Docker, Python 3 and the Go version from `go.mod`, run:

```sh
make keycloak-integration
```

The runner uses pinned Keycloak 26.8.1 and PostgreSQL images, creates isolated temporary networks
and databases, generates synthetic credentials for that run, and removes its containers and
networks on success, failure, SIGINT or SIGTERM. It does not read the retained browser sandbox,
provider accounts or credentials. Missing dependencies and a missing required test are failures.

The tagged Go test uses the existing private OIDC test-client seam with a local TLS proxy, while
retaining real Keycloak discovery, S256 authorization-code exchange, signed-token verification and
PostgreSQL-backed enterprise approval/admission. It also changes the real native client secret,
rejects the old credential, tests and activates the replacement, preserves the existing linked
person/role, and verifies that disabling the connection invalidates its prior session epoch.
Production construction continues to use the safe
client that rejects private addresses. This test seam is not a deployment override or a proof of
public DNS/SSRF transport. The separate live public-HTTPS runs cover that deployment boundary.

The CI job `Keycloak enterprise conformance` runs the same command for pull requests and pushes
to `main` and `release/**`. The Release workflow requires the same reusable gate before publishing
binaries or images. Protocol/admission coverage and recorded live browser evidence remain
separate requirements; a passing automated gate does not fill an unobserved worksheet cell.

The [recorded local run](keycloak-conformance-run.json) passed both layouts against a clean source
archive, with the inherited local issuer patch excluded. Fault checks also verified failure when
the child exits unsuccessfully or reports no required test, and cleanup after SIGTERM. Hosted CI
results must be observed separately after pushing this change.

## Worksheet

| Cell | What proves it | Observed | Evidence |
| --- | --- | --- | --- |
| Approved sign-in | A person with an approved link signs in and reaches the expected membership and role. | Passed for the existing linked readonly person before and after signing-key rotation. | [Signing-key run](keycloak-live-run.md#signing-key-overlap-and-login) |
| Unknown subject | An authenticated identity with no approved link is denied; no person, membership or session is created. | Passed before the first Keycloak enrollment: real provider login was denied with authority unchanged at 3 persons / 4 memberships / 4 authenticators. | [Enrollment run](keycloak-live-run.md#enrollment-and-local-session-lifecycle) |
| First enrollment | The first approved user accepts an explicit invitation, then signs in normally. | First Keycloak profile user accepted its approved readonly invitation, then ordinary login and Profile reauthentication reached the same person. Tenant administration already existed through Auth0. | [Enrollment run](keycloak-live-run.md#enrollment-and-local-session-lifecycle) |
| Additional enrollment | A second user enrolls the same way; an existing signed-in person keeps its membership role. | Both new users enrolled readonly; later both existing signed-in persons accepted default invitations without changing person or prior roles. | [Enrollment run](keycloak-live-run.md#enrollment-and-local-session-lifecycle) |
| Mailbox proof | Record whether `email_verified` arrived as the JSON boolean `true`, or the subject-bound mailbox challenge was used. | Controlled false provider flag led to a subject-bound Mailpit challenge; sender outage and wrong code denied admission, restoration and a new correct code succeeded. Controlled true flag led to direct admission with no challenge. Raw JWTs were not retained; claim inference is disclosed. | [Mailbox run](keycloak-live-run.md#mailbox-proof-and-existing-person-enrollment) |
| Fresh authentication | A sensitive action forces a real re-authentication and returns `auth_time` inside 15 minutes. Record the provider's prompt behaviour. | Actual password prompt during destination switch returned validated authentication time 13:45:18 UTC; admitted session created four seconds later. | [Signing-key run](keycloak-live-run.md#signing-key-overlap-and-login) |
| Stale or missing auth_time | A proof older than 15 minutes, or an ID token without `auth_time`, leaves access unchanged and offers a retry. | Real provider omission and stale-time controls both denied the destination while source reload worked; restoring the original mapper and retry reached the same readonly person. Old integer claim was 1,267 seconds old at observation. Controlled mapper inference disclosed; raw JWT not retained. | [Missing-time run](keycloak-live-run.md#missing-authentication-time-and-retry), [stale-time run](keycloak-live-run.md#stale-authentication-time-and-retry) |
| Destination proof | Switching to a required-SSO organization uses that organization's approved enabled connection and the same person. | Existing default readonly person selected the secondary Keycloak connection, completed its real callback and reached the same person/readonly role in Required secondary. No new membership or authority change during switch. | [Mailbox run](keycloak-live-run.md#mailbox-proof-and-existing-person-enrollment) |
| Issuer and key boundary | A token from another realm cannot reuse the approved connection. Overlapping signing keys retain existing links. | Real RS256 overlap and later login passed without API restart. Native real-provider tests cover ordinary/custom base paths and wrong-realm denial; the retained public custom-path discovery and signed connection Test also passed. | [Signing-key run](keycloak-live-run.md#signing-key-overlap-and-login), [conformance run](keycloak-conformance-run.json), [accepted scope](keycloak-live-run.md#accepted-release-scope) |
| Subject remap | A changed or remapped subject is denied rather than reused on the existing link. | Real pairwise remap denied the callback while independent Auth0 source access survived; restoring the mapper returned the same readonly person. Explicit additive linking is covered by the shared hosted linking journey and subject-bound admission conformance; no extra sandbox grant is required for release. | [Pairwise remap run](keycloak-live-run.md#pairwise-subject-remap-and-restoration), [accepted scope](keycloak-live-run.md#accepted-release-scope) |
| Provider outage | With the provider unreachable, new federation fails usefully, locally valid sessions keep working, and retry recovers. | Real provider stop preserved local Dashboard/Profile reload. Provider reauthentication and signed-out Connect failed without granting access, then recovered after restore. Real token503 controls also exercised useful dependency errors and approved retry. The accepted shared source and its provenance now ship through the reviewed Auth0 foundation. | [Outage run](keycloak-live-run.md#provider-outage-and-reauthentication-recovery), [Connect run](keycloak-live-run.md#signed-out-connect-during-provider-outage), [accepted scope](keycloak-live-run.md#accepted-release-scope) |
| Local logout | Logout revokes the Synapse session. Record whether the provider session survived. | Local logout left no active session for the first Keycloak person; later ordinary login authenticated the same person. Subsequent reauthentication reused recent provider SSO; no provider-session termination claimed. | [Enrollment run](keycloak-live-run.md#enrollment-and-local-session-lifecycle), [Required recovery](keycloak-live-run.md#required-canary-disable-and-recovery) |
| Activation and rollback | Per-organization activation, disable and recovery leave other organizations unchanged. | Native Test/Activate passed in both tenants; draft/disabled/other-tenant choices were excluded and revoked invitations denied. The Required canary passed disable, independent Auth0 fallback, Test/reactivation and ordinary readonly login with authority and policies preserved. Native conformance verifies actual old-credential epoch rejection. | [Enrollment run](keycloak-live-run.md#enrollment-and-local-session-lifecycle), [Required recovery](keycloak-live-run.md#required-canary-disable-and-recovery) |
| Console states | Shared controls support keyboard/focus, loading, validation, denial, dependency error and reachable retry. | Actual browser journeys and maintained frontend regressions cover these states, including focused issuer correction, provider refusal/recovery, invitation proof and required-destination choice. Repeated theme sweeps were excluded from release scope. | [Accepted scope](keycloak-live-run.md#accepted-release-scope) |

## Open questions for this provider

- The production client still rejects private destinations. The existing strict public HTTPS gateway covers that boundary; native conformance's private test seam is not a deployment override. The current Quick Tunnel hostname is process-bound and must never be silently replaced under an existing connection.
- Real password reauthentication supplied fresh `auth_time`; controlled omission/staleness was denied with source access and retry preserved.
- Synapse local logout revokes only its local session. Upstream provider SSO may survive; no global or realm-wide logout guarantee is claimed.

## Recording the run

Name the provider build or tenant the run used, and keep captures beside this file. Redact the client
secret, any token and the full issuer host where it identifies a customer. A screenshot that shows a
credential is not evidence; it is an incident.
