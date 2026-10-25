# Auth0 live acceptance record

Observed 2026-10-24 through 2026-10-25 using a sandbox Auth0 tenant, its existing Google and database
connections, and trusted loopback HTTPS. No card, paid feature, or new billable cloud service was added.
This is a progress record, not full provider certification. Personal account identifiers, invitation
codes, client secrets, tokens and raw provider responses are excluded.

## Builds and evidence scope

The functional fixes are published in `9fc23ec47f733c7f984c4fb11d4b35f7bef9c987` and the invitation
UI repair in `e59127612a5b8a0d8148660e79f04d4469d73794`. Tests below span several retained builds;
they are not a claim that every path ran again against the final commit.

| Surface | Tested artifact | Scope |
| --- | --- | --- |
| Earlier durable API | `sha256:4707488f9ef6576264ad2e1d0b0c9f446deea8033bbafe6135b3f38c00ff68ef` | Native Auth0 flows and corrected one-hour connection Test lifetime. Superseded by the mailbox and provider-outage repairs. |
| Isolated legacy candidate API | `sha256:df34d3856b19097afe280a55cb5d42e85ffbd828d3b29b25f0a62487a4b074b9` | Legacy handover, including first configuration of an imported connection. This API is not the durable serving image. |
| Invitation web | `sha256:63c49cb68985dcdcf3c1659130ff3ca553212aa267301d1c019b8d50b85ad4c5` | Exact four changed source-file hashes match the committed bytes; real preview proof preceded final reviews. Later superseded by the mailbox repair. |
| Current durable API | `sha256:fd5aa931698ba575ecd44d740ce837144644dada4471639cd45e289d4628ba74` | Mailbox recovery and authorization-provider outage repairs, published in `89194497` and `0bd9b19a`. |
| Current durable web | `sha256:ebfddcd30ad5ef66adf6494dbd8ba5cecb06afa05614ede261144782c126fb48` | Mailbox continuation preserves the initiating session through reload, retry and completion. |

The local evidence archive retains dated metadata, screenshots, gate reports and source/image
hashes. The following immutable report hashes identify the reviewed checkpoints without exposing
the private archive or credentials:

| Report | SHA-256 |
| --- | --- |
| `identity-legacy-committed-source-gate.json` | `156af79b31c2f90c3df195d49c45931b1f055d6fbad7cb8962032d867971d79e` |
| `identity-invitation-source-gate.json` | `f674a22f4241b92aaf3596b245dfa538069472f6875348e180f9d4ddebab8035` |
| `identity-invitation-promotion.json` | `856d5c2dd451288ce9a550b53ab0688f08226ee15cdd05121e846c9393278ac1` |

## Admission and handover

- First enrollment used an explicit readonly invitation, real approved-organization Auth0 callback,
  and a native browser session to reach Dashboard without an API token.
- A second user enrolled explicitly. Ordinary repeat login used the existing approval; it did not
  create another person or change the first user's membership role/version.
- A signed-in readonly person accepted a member invitation for a second Synapse tenant. The same
  person retained readonly in the source and member in the destination.
- Unknown subjects were denied without just-in-time admission. Retrying with the approved subject
  reached the expected dashboard.
- In an isolated legacy database copy, the original imported connection could be configured,
  tested and activated. Saving the same existing secret created a later draft revision; the
  earlier Test could not activate that revision. Retest and activation succeeded. This was a
  settings-revision test, not a provider client-secret rotation.
- Legacy login, unknown-subject denial, correct-subject retry and session reuse after API/web
  restart passed. Original person, membership, authenticator, cutover and immutable revision-one
  fingerprints remained unchanged. The source database was not reset or migrated by this drill.

Sources: `auth0-first-enrollment-live.json`, `auth0-additional-enrollment-live.json`,
`identity-secondary-required-switch-live.json`, and `identity-legacy-functional.json`.

## Additive Auth0 linking

An existing Keycloak readonly person used Profile to link an explicitly authorized synthetic
Auth0 database user in the approved organization. A real password login returned to Dashboard;
Profile then listed both approved providers. Person and membership counts stayed at five and six,
and authenticators increased from six to seven. The person's membership remained readonly.
The source Keycloak sessions were revoked and a new Auth0 session became active. Local logout
revoked that session; ordinary Auth0 sign-in, without an invitation, returned to the same person
and role. Auth0 SSO survived local logout and displayed organization consent on repeat login.

The password is encrypted in the local vault; a decrypt-and-compare check and actual password
login passed. The database connection was already enabled for the sandbox application. Enabling
it in the approved organization retained disabled automatic membership and organization signup.
The synthetic user's email remains unverified: linking is not evidence of mailbox verification
during enrollment. No additional Synapse membership or elevated role was granted by linking.

Negative journeys also used real hosted Auth0:

- Selecting a Google identity already owned by another person refused the link and kept the
  source readonly session usable, with contextual feedback and a Profile retry link.
- Declining Auth0 consent preserved the source session and all identity authority.
- Logging out the source in a second tab while Auth0 consent was pending caused the returning
  callback to fail without a new session or authenticator. The first logout hit stale CSRF;
  refreshing that tab and successfully logging out preceded callback completion. This proves a
  missing/revoked source case, not an isolated source-age test. Normal Keycloak login recovered.
- Blocking the API's provider egress while a fresh Keycloak session started an Auth0 link
  initially exposed a generic internal error. The repair classifies authorization-URL dependency
  failure as authentication unavailable. A second real outage showed the useful retry message;
  restoring connectivity let the same Profile action reach Auth0 password login and callback.
  Selecting an Auth0 subject already owned by another person was still refused, with the source
  session usable. Counts remained five persons, seven memberships and eight authenticators.
  This proves outage/retry without adding another link; the earlier successful link remains its
  own evidence. Invalid provider metadata also remains unavailable until the operator fixes it.

Connection revisions, policies and membership authority were unchanged by these link journeys.
Session rotation was established from server-side revocation and replacement metadata; browser
cookie values were not read.

The initiating-proof age gate was exercised separately with natural elapsed time. A source proof
3,798 seconds old left Profile usable but replaced linking controls with explicit reauthentication
guidance. Real Keycloak password reauthentication restored the controls. Keeping that Profile open
past the 15-minute boundary and submitting Link identity produced `forbidden` at 926 seconds,
with zero new link transactions and no authority changes. The existing Reauthenticate action
returned fresh upstream proof; the same Link identity action then created one transaction and
reached the real Auth0 login screen. No extra link was completed. This isolates stale proof at
begin; it does not claim an age-only callback race. The previously opened Profile retains generic
`forbidden` feedback, while a newly loaded stale Profile explains the required reauthentication.

The source identities were prepared through two authorized Keycloak readonly invitations. Both
users passed enrollment, local logout, ordinary repeat login and recent-SSO reauthentication;
the unknown subject was refused before enrollment. Those observations cover the shared runtime,
not the separate Keycloak PR's source gate or stable-hostname requirement.

Sources: `auth0-additive-link-functional.json`, `auth0-link-owned-subject-functional.json`,
`auth0-link-negative-functional.json`, `keycloak-enrollment-functional.json`,
`auth0-link-retry-live.json`, and `auth0-link-source-age-live.json`. The outage repair used API candidate
`sha256:fd5aa931698ba575ecd44d740ce837144644dada4471639cd45e289d4628ba74` with the unchanged
mailbox-certified web image. The temporary network topology and prior API were restored after
the journey; no cloud settings, credentials, membership roles or billing changed.

## Proof and organization boundaries

A real Auth0 exchange for the denied organization used the same subject and client as the approved
case. The configured stable organization restriction refused it without admission or a new
successful Test. Restoring the original authorization request made the approved-organization Test
succeed. Only the outgoing organization parameter was changed for this probe; the verifier and
stored restriction were retained.

Fresh reauthentication displayed the Google account chooser and organization consent. The native
session stored recent signed authentication time. In a separate request-only fault, omission of
`max_age` led to a successful provider code exchange followed by Synapse refusal while the source
readonly session remained usable. Restoring the normal request produced fresh proof 19 seconds
old and recovered. No raw token was retained, so the exact stale-versus-missing `auth_time` subtype
is an inference, not a directly inspected claim.

Required destination switching succeeded for the same person with the destination's member role.
Choosing a different person or declining provider consent refused the switch and retained source
readonly access. A connection revision/disable race during a pending destination callback has not
yet been demonstrated in the browser.

Sources: `auth0-wrong-organization-live.json`, `auth0-auth-time-policy-live.json`,
`identity-secondary-required-switch-live.json`, `identity-secondary-required-switch-wrong-person.json`,
and `identity-secondary-required-switch-declined.json`.

## Availability and recovery

A reversible API connectivity fault made new federation show a useful error and retry. The local
session remained usable, local logout still revoked it, and restored connectivity allowed login.
This fault also blocked the private mail service; it is not evidence of an Auth0-side outage or
of enrollment-mailbox fallback.

The Required-policy guard refused disabling the last administrative connection. With the owner's
approved temporary Optional policy in the second tenant, disabling that connection refused new
SSO there while the first tenant still worked. A one-use recovery activation opened the recovery
console; its alert arrived through local SMTP with a matching message hash. Real connection Test,
reactivation, recovery logout, normal Auth0 login and Required-policy restoration passed. No new
person or role was granted by recovery; the recovery code was consumed.

Local Sign out revoked the Synapse session. Auth0/Google SSO survived: ordinary repeat login reached
organization consent without another password entry. Provider-wide logout is not claimed.

Sources: `auth0-provider-outage-live.json`, `identity-secondary-disable-recovery-functional.json`,
`identity-recovery-entry-durable-functional.json`, and `auth0-session-lifecycle-live.json`.

## Invitation denial and lifecycle

A native administrator created and then revoked an invitation for an existing sandbox member.
Submitting that actual code through Profile refused admission. The first run exposed raw
`forbidden` text and Revoke actions on terminal invitations. The committed repair now shows an
invalid/expired/inactive explanation, focuses the error alert for keyboard submission, and shows
Accepted/Revoked lifecycle labels without those invalid actions. Unauthorized, rate-limited and
transient failures have distinct recovery guidance; retries are manual.

The browser proof retained exactly three persons, four memberships and four authenticators, with
unchanged roles, connection settings and Required policy. After guarded web-only promotion,
trusted HTTPS, retained-profile start and the existing browser session still reached Dashboard.
The API container/start time, credential files and database were unchanged.

Validation: 37 tests across four affected suites, TypeScript, targeted ESLint, production build,
and independent integration/frontend reviews passed. The earlier larger change passed its full
Go/web checks and tier-zero review gate. Theme sweeps were excluded at the owner's request;
other browser engines and screen-reader behavior were not independently exercised.

Sources: `identity-invitation-functional.json`, `identity-invitation-final-checks.json`,
`identity-invitation-provenance.json`, and `identity-invitation-promotion.json`.

## Mailbox fallback and delivery retry

An Auth0 database user with an unverified email accepted an explicitly approved readonly
invitation into the first tenant while already signed in readonly in the second tenant. Both
memberships retained the same existing person. This exercises the subject-bound mailbox fallback;
no provider claim was treated as verified mailbox ownership.

Stopping the private Mailpit container caused actual SMTP failure. No message arrived and no
membership or authenticator was added. After Mailpit returned, retrying that same invitation
exposed a duplicate-challenge constraint error. The repair replaces an unused challenge only
while its current invitation remains pending and unexpired. It replaces the digest, prospective
person and expiry together; consumed proofs and inactive invitations cannot be renewed.

The next hosted attempt delivered mail but exposed a browser continuation failure: ordinary
session discovery rotated the initiating cookie before mailbox completion could validate its
exact source binding. The repaired mailbox screen defers that discovery, retains its nonsecret
continuation marker across reload, and resumes ordinary restoration only after completion or
Cancel. The server's exact source binding remains unchanged. Rotation in another tab still
fails closed and requires restarting the invitation.

The final browser run reloaded the mailbox page, refused an earlier delivered code before its
expiry, and accepted the newest code from a real local Mailpit receipt. Counts changed from five
persons/six memberships/seven authenticators to five/seven/eight. Both memberships for that
person remained readonly. Connection revisions, policies and other memberships were unchanged.
The consumed invitation was refused on reuse. Local logout revoked the new session; ordinary
Auth0 password login then succeeded without another invitation. A marker without a pending proof
showed an unavailable-verification message, and Cancel restored the existing session.

Mailpit was private and had no published port; no email went to an external inbox. The SMTP
outage occurred before the repair, so the new unavailable-error classification is separately
covered by a service regression test. This mailbox run does not prove an expired invitation or Gmail
delivery. Password and one-use proofs are encrypted locally and omitted from published evidence.

Sources: `auth0-mailbox-flow-functional.json`, `identity-mailbox-retry-design.json`,
`identity-mailbox-retry-focused.log`, and `identity-mailbox-session-final.log`. The API candidate
was `sha256:5c296e93079bfb543f1837e7e49ad9b76c3b93cb40fa2171c64b1cd409913117`; the web candidate
was `sha256:ebfddcd30ad5ef66adf6494dbd8ba5cecb06afa05614ede261144782c126fb48`.

## Invitation expiry

The current durable API and web were exercised against the retained isolated legacy database,
using its already activated Auth0 connection. A disclosed fixture inserted a new pending readonly
invitation with its creation time seven days before a deadline a few minutes ahead. Normal RLS,
the invitation-route trigger, provider verification and application clocks were retained. No
existing durable invitation or clock was edited; this does not claim that seven days elapsed
since ordinary UI creation.

The browser began authorization at 12:08:23 UTC, while the invitation was still valid, and selected
the matching Google recipient through hosted Auth0. Consent was completed after the invitation's
12:11:57 UTC deadline. The returning callback consumed its transaction before the transaction's
12:18:23 UTC expiry but was denied admission. Person, membership, authenticator, session and
connection/policy observations were unchanged. Re-entering the same invitation code was refused
before another provider transaction, with the current-invitation retry guidance visible.

An otherwise equivalent unexpired readonly invitation for the same recipient then used the same
Auth0 session and connection. Its callback reached Dashboard and admitted one person, membership
and authenticator in the isolated copy, retaining readonly. No mailbox challenge was created;
the verified-email path is inferred from the production branch, without retaining a raw token.
Local logout revoked the control session. This successful control distinguishes expiry rejection
from an unusable provider or recipient.

Two precondition attempts are retained separately: a cookie from the durable database was not
valid in the copy, and provider SSO initially selected a different recipient. Those attempts do
not count as expiry proof. Normal login/logout and provider-local logout prepared the measured
run. Afterward, trusted loopback routing returned to the durable stack, its authority fingerprints
were unchanged, and the isolated API/PostgreSQL services were stopped. No cloud resource, external
email, port or billing was added.

Source: `auth0-invitation-expiry-live.json`, with immutable hashes of the timing, authority,
control and restoration observations. The preserved fixture and encrypted one-use codes are
local evidence; they are not reusable setup credentials.

## Pending destination callback changes

The native administrator screen now offers Update connection for an existing configured
connection. It keeps issuer, client ID and organization trust read-only, starts with an empty
secret, and saves against the selected connection version. Saving appends a draft without
activating it. Cancel, successful save, a stale-version conflict and authoritative reload clear
the secret. Active and pending draft revisions are shown separately.

A real Auth0 administrator saved the retained secret unchanged, tested draft 2 through hosted
Auth0 and left revision 1 active. A second user began a default-readonly to secondary-member
switch at 12:58:25 UTC. While Auth0 consent was pending, an independent restricted recovery
session activated revision 2. Activation consumed the old transaction; completing its real
provider callback was denied while the source readonly session remained usable. Retrying through
revision 2 reached the secondary Dashboard with the same person and member role.

A separate run used the existing person linked to Auth0 and Keycloak. Its readonly source session
began a Keycloak destination switch at 13:06:47 UTC. The recovery operator disabled that connection
before the password callback. The callback was refused and the default readonly session remained
usable. Reactivating the same tested Keycloak revision and retrying admitted that same person
readonly in the secondary tenant. Auth0 stayed enabled and Required policy was never relaxed.

All snapshots retained five persons, seven memberships, eight authenticators, the existing roles
and policies. The recovery alert reached private Mailpit; the recovery session was signed out.
The independent operator used a temporary API replica with the exact localhost public origin,
sharing the durable database and existing credentials. This preserved Origin/CSRF validation and
used the existing trusted loopback listener. The replica was removed, original API/web images
and nginx configuration restored, and trusted API context verified after the drill. No cloud
resource, host port, external email or billing was added.

An initial save with naturally expired administrator proof was refused before a fresh hosted
reauthentication allowed it. A Keycloak browser network-change error recovered through ordinary
reload. Neither precondition is counted as a successful callback race. Resaving the retained
Auth0 secret is not provider client-secret rotation.

The final API binary was identical to the first tested candidate; the final web build corrected
the active/draft label observed during the first save. Focused tests, Go HTTP API tests/vet,
TypeScript, targeted ESLint and both builds passed. The bounded web suite passed 215 files and
1,533 tests before the final label edit; its separate 26-test suite, typecheck and lint then passed.
The earlier unbounded resource-related timeout remains in local evidence. Functional
proof preceded independent security, frontend and integration acceptance review.

Source: `native-connection-revision-functional.json`, binding the observations and screenshots
by SHA-256, and `native-connection-revision-final-images.json`, binding the six changed source
files to the tested API/web images. This closes the pending destination revision/disable race
cell, not the remaining provider lifecycle cells below.

## Remaining acceptance

- A different Auth0 issuer/custom domain and actual subject remap/email change. The current
  Custom Domains screen requires adding a credit card, including for its free-domain option;
  the no-card constraint was preserved and this hosted case remains unproved.
- Signing-key rotation without API restart: explicitly deferred by the owner until after merge
  on 2026-10-25. It has not run and is not counted as passed.
- Actual provider client-secret rotation, distinct from resaving the same sealed credential.

The isolated legacy dataset remains separate from the durable sandbox. Remaining functional work must
finish before its final consolidated acceptance decision; this record does not close #1521.
