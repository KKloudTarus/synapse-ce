# Certifying Auth0 tenant and organization connections (#1521)

This worksheet tracks the acceptance criteria in [issue #1521](https://github.com/KKloudTarus/synapse-ce/issues/1521).
[The live run record](auth0-live-run.md) distinguishes observed behavior from remaining work.
An incomplete cell does not establish support for that profile.

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
| Destination proof | Switching to a required-SSO organization uses that organization's approved enabled connection and the same person. | Correct subject, wrong person and provider cancellation passed; pending-callback revision/disable race remains. | [Proof and organization boundaries](auth0-live-run.md#proof-and-organization-boundaries) |
| Issuer and key boundary | A token from another authorization server, realm, tenant or environment of this provider is denied. Rotate the signing key and show discovery picking it up. | Wrong Auth0 organization passed. Other issuer/custom-domain proof remains; owner deferred signing-key rotation until after merge. | [Remaining acceptance](auth0-live-run.md#remaining-acceptance) |
| Subject remap | A changed or remapped subject is denied rather than reused on the existing link. | Unknown-subject denial passed; actual provider-side remap/email change remains. | [Remaining acceptance](auth0-live-run.md#remaining-acceptance) |
| Provider outage | With the provider unreachable, new federation fails usefully, locally valid sessions keep working, and retry recovers. | Passed with a reversible API connectivity fault, including a separate additive-link outage and real callback after retry. | [Availability and recovery](auth0-live-run.md#availability-and-recovery), [additive Auth0 linking](auth0-live-run.md#additive-auth0-linking) |
| Local logout | Logout revokes the Synapse session. Record whether the provider session survived. | Passed; Auth0/Google SSO survived local logout. | [Availability and recovery](auth0-live-run.md#availability-and-recovery) |
| Activation and rollback | Per-organization activation, disable and recovery leave other organizations unchanged. | Passed, including last-admin guard and restoration of Required policy. | [Availability and recovery](auth0-live-run.md#availability-and-recovery) |
| Console states | Settings / Authentication and Connect in light and dark, desktop and mobile, with loading, validation, denied, dependency-error and retry states. | Functional Edge journeys and additive Auth0 linking passed, including session rotation, later login and several denial paths; remaining linking/invitation cases stay open. Owner excluded theme sweeps. | [Additive Auth0 linking](auth0-live-run.md#additive-auth0-linking), [invitation denial and lifecycle](auth0-live-run.md#invitation-denial-and-lifecycle) |

## Open questions for this provider

- A custom domain changes the issuer. Prove that a connection saved against one domain refuses tokens issued by the other, which is the exact-match rule working as intended.
- Confirm organization-scoped logins keep one stable `sub` for the same person across organizations.
- Confirm `auth_time` under `max_age`, and what Auth0's own session policy does to the prompt.

## Recording the run

Name the provider build or tenant the run used, and keep captures beside this file. Redact the client
secret, any token and the full issuer host where it identifies a customer. A screenshot that shows a
credential is not evidence; it is an incident.
