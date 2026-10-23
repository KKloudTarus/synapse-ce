# Certifying PingOne regional and custom-domain issuers (#1522)

The demands this certification proves, and the connection lifecycle it runs through, are in
[Certifying an identity provider](../../guide/identity-provider-certification.md). That page is read from
the code; this worksheet is where one provider's observations are recorded. A cell left blank is a cell
that blocks support for this profile.

## Connection

| Field | Value |
| --- | --- |
| Issuer | `https://auth.pingone.<region-tld>/<environmentId>/as` |
| Client ID | the application's client ID |
| Client secret | sealed per tenant and connection; never returned by any API |
| Redirect URL | the deployment's fixed callback, not chosen per connection |

Read the issuer from the provider's own discovery document before saving the connection. An issuer that
differs by one path segment fails at callback time, not at save time.

## Provider setup

- Create a Web application in the environment with the authorization-code grant and PKCE.
- Add the deployment's exact callback as a redirect URI.
- Read the issuer from the application's own configuration panel rather than assembling it by hand.

## Worksheet

| Cell | What proves it | Observed | Evidence |
| --- | --- | --- | --- |
| Approved sign-in | A person with an approved link signs in and reaches the expected membership and role. |  |  |
| Unknown subject | An authenticated identity with no approved link is denied; no person, membership or session is created. |  |  |
| First enrollment | The first approved user accepts an explicit invitation, then signs in normally. |  |  |
| Additional enrollment | A second user enrolls the same way; an existing signed-in person keeps its membership role. |  |  |
| Mailbox proof | Record whether `email_verified` arrived as the JSON boolean `true`, or the subject-bound mailbox challenge was used. |  |  |
| Fresh authentication | A sensitive action forces a real re-authentication and returns `auth_time` inside 15 minutes. Record the provider's prompt behaviour. |  |  |
| Stale or missing auth_time | A proof older than 15 minutes, or an ID token without `auth_time`, leaves access unchanged and offers a retry. |  |  |
| Destination proof | Switching to a required-SSO organization uses that organization's approved enabled connection and the same person. |  |  |
| Issuer and key boundary | A token from another authorization server, realm, tenant or environment of this provider is denied. Rotate the signing key and show discovery picking it up. |  |  |
| Subject remap | A changed or remapped subject is denied rather than reused on the existing link. |  |  |
| Provider outage | With the provider unreachable, new federation fails usefully, locally valid sessions keep working, and retry recovers. |  |  |
| Local logout | Logout revokes the Synapse session. Record whether the provider session survived. |  |  |
| Activation and rollback | Per-organization activation, disable and recovery leave other organizations unchanged. |  |  |
| Console states | Settings / Authentication and Connect in light and dark, desktop and mobile, with loading, validation, denied, dependency-error and retry states. |  |  |

## Open questions for this provider

- Confirm whether a custom domain or a regional change alters the issuer, and prove a token from another environment is denied.
- Confirm `auth_time` under `max_age`.
- Record the environment's own session and logout behaviour against the local Synapse logout.

## Recording the run

Name the provider build or tenant the run used, and keep captures beside this file. Redact the client
secret, any token and the full issuer host where it identifies a customer. A screenshot that shows a
credential is not evidence; it is an incident.
