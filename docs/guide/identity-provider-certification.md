# Certifying an identity provider

A provider is certified by evidence, not by code. Synapse has one OIDC client and one connection
model; an Okta, Google Workspace, Auth0, PingOne or Keycloak connection is the same record with a
different issuer. There is no provider adapter and no vendor switch in policy, so certifying a
provider means proving that this client's fixed demands hold against that provider, and recording
the evidence.

This page is the shared half of the per-provider certification issues (#1517, #1519, #1520, #1521,
#1522): what the client requires, what the connection lifecycle enforces, and the worksheet each
certification fills in. The provider sections at the end carry only what can be stated without a
tenant; every behavioural cell is answered during certification, not assumed here.

## What the client demands

Every item below is enforced in `internal/infrastructure/oidc/provider.go` and
`internal/usecase/identityenterprise`. A provider that cannot satisfy one of them cannot be
certified, whatever its documentation claims.

| Demand | Detail |
| --- | --- |
| HTTPS issuer, exact match | The connection stores the issuer with no query, fragment, credentials or trailing slash. The `iss` claim must equal it exactly. A provider that issues tokens under a different host or path than its configured issuer fails here. |
| Public addresses only | Discovery resolves the issuer host and refuses a loopback, private, unique-local or cloud-metadata answer, with no override. See [identity foundation rollout](identity-foundation-rollout.md#where-the-provider-has-to-be-reachable-from). |
| Discovery | `<issuer>/.well-known/openid-configuration` is read by the client. The client follows no provider redirect and ignores ambient proxy settings. A failed discovery enters a cooldown, so a misconfigured issuer does not hammer the provider. |
| PKCE S256 and nonce | Every authorization sends both. A returned ID token whose `nonce` does not match the stored one is refused. |
| `max_age=900` and `auth_time` | Every enterprise authorization, sign-in included, asks for authentication no older than 15 minutes, so the provider must re-authenticate the person and return an integral numeric `auth_time`. A missing, non-numeric, future or stale value is refused, and the callback refuses again against the same 15-minute window. |
| `azp` | When the ID token carries `azp`, or carries more than one audience, `azp` must equal the connection's client ID. |
| `at_hash` | When the ID token carries `at_hash`, it is verified against the access token. |
| `email_verified` | Only the JSON boolean `true` counts. The string `"true"`, a missing claim or a verified-elsewhere claim leaves the address unverified, and enrollment then needs the subject-bound mailbox challenge. No other claim is ever read as proof of mailbox ownership. |
| Subject | A non-empty `sub`. The link is to that exact subject; a remapped or recycled subject is a different identity and is denied rather than reused. |
| Logout | Logout is local: the Synapse session is revoked. The client sends no RP-initiated logout, so a provider session can survive a Synapse logout, and that limit belongs in the provider's certification record. |
| Groups | Provider groups and custom claims never create a membership or assign a role. `SYNAPSE_OIDC_GROUP_ROLE_MAPPING` is accepted and ignored. |

## What the connection lifecycle enforces

| Step | Rule |
| --- | --- |
| Draft | An administrator with a browser session authenticated in the last 15 minutes saves the issuer, client ID and client secret. The secret is sealed per tenant and connection and is never returned by any API. The redirect URL is the deployment's fixed callback; a connection cannot choose its own. |
| Test | A test runs the real authorization and callback against the draft. Its result is bound to the connection revision and expires one hour after it passes. |
| Activate | Activation requires the revision that passed the test. Editing the connection changes the revision, which invalidates the test, so an edited connection cannot be activated on an older proof. |
| Disable | Disabling rejects the sessions that connection authenticated, without touching other organizations or weakening required SSO elsewhere. |
| Rollback | A disabled or superseded connection leaves locally valid sessions and allowed existing credentials usable, which is what a provider outage must also leave standing. |

## The certification worksheet

Each per-provider issue lists the same cells. A certification is complete when every cell is filled
with a real observation, and the record names the provider build or tenant it came from.

| Cell | What proves it |
| --- | --- |
| Approved sign-in | A person with an approved link signs in through the provider and reaches the expected membership and role. |
| Unknown subject | An authenticated provider identity with no approved link is denied, with no person, membership or session created. |
| Enrollment | First and additional users accept an explicit invitation, then sign in normally. Record whether the provider's `email_verified` carried the mailbox proof or the subject-bound challenge was used. |
| Fresh authentication | A sensitive action forces a real provider re-authentication and returns `auth_time` inside 15 minutes. Record the provider's own prompt behaviour, and what a stale or missing `auth_time` produced. |
| Destination proof | Switching to a required-SSO organization uses that organization's approved enabled connection and the same person; a missing or wrong destination proof does not switch. |
| Issuer and key boundary | A token from another authorization server, realm, tenant or environment of the same provider is denied. Rotate the signing key and show that discovery picks up the new key without manual work. |
| Subject remap | A changed or remapped subject is denied rather than reused on the existing link. |
| Outage | With the provider unreachable, new federation fails with a useful error, locally valid sessions keep working, and retry recovers. |
| Local logout | Logout revokes the Synapse session. Record whether the provider session survived. |
| Activation and rollback | Per-organization activation, disable and recovery leave other organizations unchanged. |

Console cells, in light and dark at desktop and mobile width, come from the shared Settings /
Authentication and Connect screens. They are shared surfaces: a provider certification records
their behaviour and does not add a vendor-specific screen.

## Provider notes

The issuer below is a starting point. Read the real value from the provider's own discovery
document before saving a connection, because an issuer that differs by one path segment fails the
exact-match rule at callback time rather than at save time.

| Provider | Issuer shape | Open questions for its certification |
| --- | --- | --- |
| Keycloak (#1517) | `https://<host>/realms/<realm>` | The realm host must be publicly resolvable. A realm published only on an internal network cannot be certified; this is the blocker recorded on the issue. |
| Okta Workforce (#1519) | Org server `https://<org>.okta.com`; custom authorization server `https://<org>.okta.com/oauth2/<serverId>` | Treat each authorization server as its own issuer and key boundary. Confirm `auth_time` under `max_age` on both server types, and which one carries the claims the deployment expects. |
| Google Workspace (#1520) | `https://accounts.google.com` | One issuer serves every Google tenant, so the hosted-domain restriction and the approved-link check carry the organization boundary. Confirm `auth_time` behaviour and what re-authentication a `max_age` of 900 seconds actually triggers. |
| Auth0 (#1521) | `https://<tenant>.<region>.auth0.com` or the tenant's custom domain | A custom domain changes the issuer, so a connection saved against one and tokens issued by the other is exactly the mismatch the exact-match rule refuses. Confirm organization-scoped logins keep one stable subject. |
| PingOne (#1522) | `https://auth.pingone.<region-tld>/<environmentId>/as` | Confirm the environment's issuer in its application configuration, including custom-domain environments, and whether a regional domain change alters the issuer. |

Sources for the issuer shapes: Okta's org authorization server documentation and its custom
authorization server path, and PingOne's discovery document URI page. Both state the shape only;
neither certifies the behaviour cells above.
