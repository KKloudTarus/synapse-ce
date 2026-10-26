# Certifying Auth0 tenant and organization connections (#1521)

This worksheet tracks the acceptance criteria in [issue #1521](https://github.com/KKloudTarus/synapse-ce/issues/1521).
[The live run record](auth0-live-run.md) distinguishes hosted observations, conformance evidence,
and the accepted post-merge follow-up. Its accepted scope is the configured canonical tenant
and organization profile; it does not certify an unconfigured custom domain.

## Connection

| Field | Value |
| --- | --- |
| Issuer | `https://<tenant>.<region>.auth0.com` or the tenant's custom domain |
| Client ID | the application's client ID |
| Client secret | sealed per tenant and connection; never returned by any API |
| Redirect URL | the deployment's fixed callback, not chosen per connection |

Read the issuer from the provider's own discovery document before saving the connection. An issuer that
differs by one path segment fails at callback time, not at save time.

## Provider setup

- Create a Regular Web Application and enable the authorization-code grant.
- Add the deployment's exact callback as an allowed callback URL.
- Decide whether the connection uses the canonical tenant domain or the custom domain, and use that exact value as the issuer.

### Organization restriction

When using Auth0 Organizations, set the optional **Auth0 organization ID** in the connection
draft. The API field is `auth0_organization_id`. Use the stable, case-sensitive `org_…` ID;
an organization name, email domain or callback parameter cannot select this boundary.
The setting controls both the `organization` authorization parameter and exact comparison with
the signed ID token's `org_id`. Missing, null, malformed or different organization proof fails
before a connection test or authentication succeeds. An unrestricted connection accepts ordinary
tenant tokens without `org_id`; an unsolicited `org_id` is refused rather than silently trusted.
See [Auth0's token guidance](https://auth0.com/docs/manage-users/organizations/using-tokens).

The restriction is immutable alongside issuer, client ID and callback. Secret rotation with the
same restriction creates a new settings revision. Adding, removing or changing the restriction
requires a different connection identity. The existing schema allows only one exact issuer per
Synapse tenant, so replacing an existing same-issuer connection is currently blocked. Initial
restricted profiles need a genuinely new tenant without legacy issuer adoption. Do not alter a
trust row, concatenate the organization into the issuer, or run issuer-only legacy backfill over
a restricted connection to work around that limit.

Older binaries ignore the additional settings JSON. They must not serve login, test,
administration or callback traffic against a restricted dataset. Disabling a connection is not a
rollback fence because connection tests can still use disabled connections. Before storing a
restriction, isolate the dataset and pin every serving and administrative instance to a supporting
candidate. Recovery must keep that supporting boundary, or close all traffic and select a complete
pre-feature dataset before starting an older binary. This profile does not certify mixed-version
rollout. Local protocol and persistence tests are conformance evidence; the live worksheet below
still requires real provider results.

## Worksheet

| Cell | What proves it | Observed | Evidence |
| --- | --- | --- | --- |
| Approved sign-in | A person with an approved link signs in and reaches the expected membership and role. | Passed for native enrollment and the isolated legacy handover. | [Admission and handover](auth0-live-run.md#admission-and-handover) |
| Unknown subject | An authenticated identity with no approved link is denied; no person, membership or session is created. | Passed; correct-subject retry also passed. | [Admission and handover](auth0-live-run.md#admission-and-handover) |
| First enrollment | The first approved user accepts an explicit invitation, then signs in normally. | Passed. | [Admission and handover](auth0-live-run.md#admission-and-handover) |
| Additional enrollment | A second user enrolls the same way; an existing signed-in person keeps its membership role. | Passed: source readonly, destination member. | [Admission and handover](auth0-live-run.md#admission-and-handover) |
| Mailbox proof | Record whether `email_verified` arrived as the JSON boolean `true`, or the subject-bound mailbox challenge was used. | Direct verified-email path passed by production-branch inference. Real unverified-email fallback, SMTP outage, same-invitation retry, superseded-code denial and ordinary later login passed. | [Mailbox fallback and delivery retry](auth0-live-run.md#mailbox-fallback-and-delivery-retry) |
| Expired invitation | An invitation expiring during provider authentication cannot admit; an expired code cannot begin again. | Passed in the isolated database with a disclosed historical fixture and real elapsed deadline. Matching unexpired control admitted readonly through hosted Auth0. | [Invitation expiry](auth0-live-run.md#invitation-expiry) |
| Fresh authentication | A sensitive action forces a real re-authentication and returns `auth_time` inside 15 minutes. Record the provider's prompt behaviour. | Passed; real Google chooser/organization consent returned fresh proof. | [Proof and organization boundaries](auth0-live-run.md#proof-and-organization-boundaries) |
| Stale or missing auth_time | A proof older than 15 minutes, or an ID token without `auth_time`, leaves access unchanged and offers a retry. | Real provider exchange was refused after request-only `max_age` omission; exact missing-versus-stale claim subtype was not captured. | [Proof and organization boundaries](auth0-live-run.md#proof-and-organization-boundaries) |
| Initiating proof for linking | An aged source cannot begin an additive link; real reauthentication restores the action without changing authority. | Passed with natural time: stale Profile guidance, server denial at 926 seconds, fresh Keycloak proof and retry reaching Auth0. No age-only pending-callback claim. | [Additive Auth0 linking](auth0-live-run.md#additive-auth0-linking) |
| Destination proof | Switching to a required-SSO organization uses that organization's approved enabled connection and the same person. | Passed: same-person switch, wrong person, cancellation, pending Auth0 revision change and Keycloak disable; both race denials preserved source access and successful retry retained destination roles. | [Pending destination callback changes](auth0-live-run.md#pending-destination-callback-changes) |
| Issuer and key boundary | Keep the exact configured issuer and immutable connection trust; reject an unapproved organization or identity. | Hosted same-subject/wrong-organization denial passed; signed issuer and immutable-trust conformance supplement it. Custom domains are outside the accepted hosted scope. Signing-key rotation is an explicit post-merge follow-up. | [Accepted scope and follow-up](auth0-live-run.md#accepted-release-scope-and-follow-up) |
| Subject and claim changes | A different subject cannot acquire the existing link through matching profile claims. | Hosted unknown-subject denial and provider email change/restored login passed with unchanged identity and roles, supplemented by subject-bound admission tests. Destructive hosted remapping is not required by the accepted scope. | [Provider email change](auth0-live-run.md#provider-email-change), [accepted scope](auth0-live-run.md#accepted-release-scope-and-follow-up) |
| Client-secret lifecycle | Configuration revisions retain immutable trust and existing links. | Auth0 revision handling passed; native Keycloak secret replacement exercises the shared OIDC adapter. Hosted Auth0 credential replacement was not performed. | [Accepted scope and follow-up](auth0-live-run.md#accepted-release-scope-and-follow-up) |
| Provider outage | With the provider unreachable, new federation fails usefully, locally valid sessions keep working, and retry recovers. | Passed with a reversible API connectivity fault, including a separate additive-link outage and real callback after retry. | [Availability and recovery](auth0-live-run.md#availability-and-recovery), [additive Auth0 linking](auth0-live-run.md#additive-auth0-linking) |
| Local logout | Logout revokes the Synapse session. Record whether the provider session survived. | Passed; Auth0/Google SSO survived local logout. | [Availability and recovery](auth0-live-run.md#availability-and-recovery) |
| Activation and rollback | Per-organization activation, disable and recovery leave other organizations unchanged. | Passed, including last-admin guard and restoration of Required policy. | [Availability and recovery](auth0-live-run.md#availability-and-recovery) |
| Console states | Settings / Authentication and Connect loading, validation, denied, dependency-error and retry states, with keyboard/focus checks. | Functional Edge journeys passed, including linking, invitation, session rotation, later login, denial and recovery. Issuer validation focuses the input and provides correction; dependency failures keep a usable approved retry. Repeated theme sweeps were excluded from release scope. | [Additive Auth0 linking](auth0-live-run.md#additive-auth0-linking), [invitation denial and lifecycle](auth0-live-run.md#invitation-denial-and-lifecycle) |

## Open questions for this provider

- Hosted custom domains are not configured or certified in this release. Exact issuer matching remains mandatory and covered by conformance tests.
- Organization-scoped hosted evidence retained the same `sub` across the approved and denied organizations.
- Real reauthentication under `max_age` supplied fresh `auth_time`; Auth0/Google SSO can survive local Synapse logout.

## Recording the run

Name the provider build or tenant the run used, and keep captures beside this file. Redact the client
secret, any token and the full issuer host where it identifies a customer. A screenshot that shows a
credential is not evidence; it is an incident.
