# Certifying Keycloak realms (#1517)

The demands this certification proves, and the connection lifecycle it runs through, are in
[Certifying an identity provider](../../guide/identity-provider-certification.md). That page is read from
the code; this worksheet is where one provider's observations are recorded. A cell left blank is a cell
that blocks support for this profile.

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
PostgreSQL-backed enterprise approval/admission. Production construction continues to use the safe
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
| Issuer and key boundary | A token from another authorization server, realm, tenant or environment of this provider is denied. Rotate the signing key and show discovery picking it up. | Key overlap and actual login after RS256 signer rotation passed without API restart. Automated real-provider tests pass both base paths and wrong-realm denial through a private TLS fixture; full public-browser realm setup remains open. | [Signing-key run](keycloak-live-run.md#signing-key-overlap-and-login), [conformance run](keycloak-conformance-run.json) |
| Subject remap | A changed or remapped subject is denied rather than reused on the existing link. | Passed for a real pairwise remap of the existing Keycloak account: callback denied, independent Auth0 source usable; restore returned to the same secondary readonly person. Approved pairwise enrollment/linking remains open. | [Pairwise remap run](keycloak-live-run.md#pairwise-subject-remap-and-restoration) |
| Provider outage | With the provider unreachable, new federation fails usefully, locally valid sessions keep working, and retry recovers. | Real provider stop preserved local Dashboard/Profile reload and active proofs. Reauthentication reached an external 504; Back to Profile and retry after restore returned the same readonly person with fresh proof. Signed-out Connect also failed without a session during outage and recovered through ordinary SSO. A separate six-file candidate also passed restored-source and signed-out token503 denial/retry; current generalized error copy has focused frontend tests. Complete canary recovery remains open. | [Outage run](keycloak-live-run.md#provider-outage-and-reauthentication-recovery), [Connect run](keycloak-live-run.md#signed-out-connect-during-provider-outage) |
| Local logout | Logout revokes the Synapse session. Record whether the provider session survived. | Local logout left no active session for the first Keycloak person; later ordinary login authenticated the same person. Subsequent reauthentication reused recent provider SSO; no provider-session termination claimed. | [Enrollment run](keycloak-live-run.md#enrollment-and-local-session-lifecycle) |
| Activation and rollback | Per-organization activation, disable and recovery leave other organizations unchanged. | Native Test and Activate passed in both canary tenants; default draft was excluded from Connect until activation and a revoked invitation was denied. Existing Auth0 connections and secondary Required policy were preserved. Full disable/recovery/rollback remains open for this profile. | [Enrollment run](keycloak-live-run.md#enrollment-and-local-session-lifecycle) |
| Console states | Settings / Authentication and Connect in light and dark, desktop and mobile, with loading, validation, denied, dependency-error and retry states. |  |  |

## Open questions for this provider

- The realm host must be publicly resolvable. The OIDC client refuses a loopback, private, unique-local or cloud-metadata answer with no override, so a realm published only on an internal network cannot be certified. This is the recorded blocker on the issue: resolve it by publishing the realm, not by relaxing the client.
- Confirm whether the realm returns `auth_time` for every client or only when the authentication flow re-prompts.
- Record what a realm-level logout does to the Synapse session and the reverse.

## Recording the run

Name the provider build or tenant the run used, and keep captures beside this file. Redact the client
secret, any token and the full issuer host where it identifies a customer. A screenshot that shows a
credential is not evidence; it is an incident.
