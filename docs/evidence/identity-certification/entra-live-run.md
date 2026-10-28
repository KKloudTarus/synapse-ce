# Entra live acceptance record

Observed on 2026-10-28 using an existing free Entra directory, one single-tenant
sandbox application, two approved accounts, and trusted loopback HTTPS. The second
account was invited as a guest without directory roles or groups. Consent was
personal, not organization-wide. No license, subscription, card, or paid trial was
added. Secrets, tokens, invitation tickets, and personal account identifiers are
excluded from this record.

## Build and evidence scope

The candidate starts from `90e78ecaa9fbf98d260fe79ea0bc487d2d6fb1ef` and adds
controlled alias discovery, directory and per-key issuer checks, settings
persistence, and shared configuration controls. The private runtime journal pins
the API/web images, source hashes, and pre-preview database backup. The candidate
uses a private journal for the final release gate and durable promotion.

The local observations below used the candidate API and web images. The earlier
owner-account activation and linking also have a retained record from the base
build. They are not presented as a rerun of every path on the candidate.

## Hosted configuration cycle

The active tenant-specific connection received a `common` draft. Activating it
before Test was refused while the prior revision stayed active. A real Microsoft
callback passed Test; activation and ordinary logout/login then succeeded. The
same sequence passed for `organizations`, followed by a tested return to
tenant-specific mode. The resulting connection was enabled at revision 4, version
8, epoch 1. Existing persons, memberships, roles, policies, and other connections
were unchanged throughout the cycle.

Private evidence: `mode-cycle.json`, the four
`native-connection-revision-entra-*-active/restored` observations, and screenshots
of the untested-draft denial, each activation, and each ordinary login.

## Guest identity and destination proof

Before linking, the newly redeemed guest completed Microsoft authentication and
received Synapse's unapproved-identity denial. Counts remained five persons, eight
memberships, and eleven authenticators. Signing into the existing person through
Auth0 and linking Entra added exactly one authenticator. It created no person or
membership and changed no role.

The person retained readonly membership in the source organization and member
membership in the destination. Switching back to the required-SSO destination
requested its approved provider proof. Choosing Entra returned the same person
with the destination member role. Local logout and a later ordinary Entra login
also succeeded.

The directory owner's local person is an administrator only in the secondary
tenant. A separate same-email readonly person exists in the default tenant; email
matching was not used to merge those persons.

Private evidence: `guest-functional.json`, `guest-person-before-link.json`,
`native-connection-revision-entra-guest-denied.json`,
`native-connection-revision-entra-guest-linked.json`, and
`native-connection-revision-entra-destination-proof.json`.

## Outage and fresh authentication

A temporary DNS override on the candidate API resolved the Entra host to loopback.
The existing outbound-address guard rejected it. Reloading the guest's Profile
still worked with its local session; starting Entra reauthentication displayed
an authentication-unavailable message with a reachable retry.

The override was removed and the API restored. The first callback after Microsoft
email OTP was denied while preserving the prior session. A new reauthentication
attempt with the same guest succeeded. The persisted session recorded upstream
authentication at 12:07:22 UTC and successful callback/session creation at
12:12:48 UTC. The exact cause of the first callback denial was not captured; it is
not classified as a specific token-claim failure. The successful retry and retained
authority are directly observed.

Private evidence: `outage.json` (restored), `guest-functional.json`,
`native-connection-revision-entra-guest-retry-denied.json`, and
`native-connection-revision-entra-guest-retry-success.json`.

## Protocol and persistence conformance

The following tests supplement hosted evidence without claiming that Microsoft
issued deliberately invalid tokens:

- `TestEntraSignedTokenRequiresMatchingDirectory`: correct, wrong, absent, null,
  numeric, and empty `tid` under all three modes.
- `TestEntraSigningKeysAreFilteredIndividuallyBeforeCaching`: exact/template
  issuer scope, missing/foreign/malformed scope, duplicate key IDs in either order,
  and repeated cached verification.
- `TestEntraKeyRefreshRetainsScopeAndOriginalKeyCountLimit`: issuer filtering
  survives refresh and cache hits; oversized key sets are rejected before filtering.
- `TestEntraAliasMetadataIsStrictAndRoutesToTenant` and
  `TestEntraAdvertisedS256RejectsMismatchedEndpoints`: exact alias metadata and
  canonical sign-in routing, including explicitly advertised S256 metadata.
- `TestEntraOmittedMetadataPreservesS256ChallengeAndExchangeVerifier`: real S256
  construction and bound exchange verifier despite omitted capability metadata.
- Shared signed-token issuer/audience/nonce and authentication-time tests, plus
  PostgreSQL connection lifecycle, provisioning retry, and immutable-trust tests.

## Invitation enrollment and mailbox retry

An isolated local enrollment tenant was declared through the supported cutover
CLI. Its Entra draft passed a hosted Test, then was activated after explicit
membership authorization. The first administrator used a one-time invitation,
Microsoft authentication, and an actual subject-bound Mailpit challenge. An invalid
mailbox code was refused; the delivered code completed enrollment. Local logout
and ordinary Entra login then succeeded without the invitation.

The existing guest accepted an additional readonly invitation while signed into
its current person. A revoked diagnostic invitation was refused first. Stopping
the isolated Mailpit sender made the valid invitation callback fail with a
reachable recovery link, retaining the existing session and all nine memberships.
After restoring Mailpit, re-entering the same invitation and authenticating with
Entra produced a real mailbox challenge. Completing it added exactly one readonly
membership while preserving the guest's person, source readonly membership, and
secondary member membership. Local logout and ordinary Entra login also passed.
The first-administrator flow added one person; the additional flow added none.
Final totals were six persons, ten memberships, and fourteen authenticators.

Mailpit has no host-published ports and sent no Internet email. Invitation and
mailbox codes are retained encrypted in the local vault. The diagnostic invitation
remains revoked. Private evidence: `first-admin-functional.json`,
`additional-functional.json`, and the `entra-first-admin-*` and
`entra-additional-*` database observations.

## Disable and recovery

The secondary administrator signed in through Entra and disabled that connection.
The current browser session was immediately rejected and Connect no longer offered
Entra. The connection epoch advanced from 1 to 2. Required SSO remained enabled.
The same administrator signed in through the existing approved Auth0 connection,
performed a real Entra Test, and activated the same revision. Entra reappeared on
Connect, and ordinary Entra login succeeded. All memberships, policies, and other
connections were unchanged. The restored connection is revision 4, version 10,
epoch 2.

The database observation's `active` session flag means only unrevoked and unexpired;
it does not represent enabled-connection or epoch admission. The browser rejection
and epoch change prove disable enforcement without claiming all session rows were
physically revoked. Private evidence: `lifecycle-functional.json` and the
`entra-before-disable`, `entra-disabled`, `entra-fallback-auth0-login`, and
`entra-recovery-*` observations.

## Release status

The affected functional journeys have passed hosted execution, with invalid-token
boundaries covered by signed conformance tests under the user's accepted scope.
Final QA, security, performance, reliability and frontend reviews passed. A shared
control label collision found during review was fixed with per-instance IDs and a
two-instance regression. Durable promotion is recorded in the private runtime
journal.
