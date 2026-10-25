# Keycloak live run

This record describes the existing local Keycloak 26.8.1 synthetic realm through strict public
HTTPS, used by the durable Synapse sandbox. The current API is
`sha256:15be92cbec55907328c1a8db99d4a9f153b54992adc73b3931c712aa4f56ee9a` and web is
`sha256:921e6509aa5abbdf1e40899f37835b4cf90959d49998c1204ad7d98261c91813`, bound to the reviewed
shared source in Auth0 PR #1612 commit `a2de17b9`. The original #1609 executable baseline was
equivalent to the earlier Auth0 baseline, but this run consumes later shared repairs. It does not
claim that the unmodified #1609 source head alone contains those repairs.

## Signing-key overlap and login

On 25 October 2026, the existing linked synthetic person first switched from default readonly to
secondary readonly through a real Keycloak password prompt. The validated upstream authentication
time was 13:45:18 UTC and the resulting session was created at 13:45:22 UTC.

At 13:47:34 UTC, the local Keycloak admin API created a higher-priority generated RS256 signing
component in the same realm. The original signing component was retained. Public HTTPS JWKS
contained both original and new RSA key IDs, and the issuer was unchanged. Keycloak metadata
selected the new RS256 signer; the client/realm ID-token algorithm was RS256.

The existing Synapse session still reached Dashboard after reload. Local logout then revoked it,
and ordinary Keycloak authorization returned through the real callback to the same existing
person and secondary readonly membership. The new callback completed after rotation. Neither API
image nor container start time changed, so this did not rely on restarting the API's verifier.
All observations retained five persons, seven memberships, eight authenticators, connection
revisions, roles and policies, including secondary Required SSO.

The selected signer is inferred from provider active-key metadata, configured algorithm, public
JWKS and the successful post-rotation callback. Raw ID-token headers/claims were not retained.
The public-key overlap is observed directly. The twenty-minute rollback guard was disarmed only
after the browser and persistence assertions passed; the old and new keys remain in the durable
local realm. Explicit rollback remains available and removes only the new component.

No user, membership, client secret, cloud resource, public endpoint or billing was added by this
drill. This does not claim client-secret rotation, a different realm, or changed subject.

Source: `keycloak-jwks-rotation.json`, containing nonsecret public key IDs, exact runtime identity
and hashes of the original observations and screenshots. Private key material was never exported.

![Same readonly person after Keycloak key rotation](keycloak-jwks-after-dashboard.png)

## Pairwise subject remap and restoration

At 14:05 UTC, the existing linked synthetic person signed in through Auth0 to the default
readonly membership. Only the Keycloak synthetic client's default scope assignment was then
changed: a temporary copy retained the original `auth_time` fields and replaced the public-sub
mapper with Keycloak's `oidc-sha256-pairwise-sub-mapper`. The shared `basic` scope, issuer, client
secret, other scopes, users, Synapse connections and policies were untouched. Keycloak added an
explicit `userinfo.token.claim=true` default to the copied authentication-time mapper. The client
had one loopback redirect host and the original scope had no role-scope mappings to omit.

The admin-generated example ID-token payload showed a different subject hash while issuer,
audience, client, email and JSON boolean `email_verified=true` stayed equal. This unsigned preview
was a configuration precondition, not the federation proof; raw callback JWTs were not retained.
A real browser destination switch then forced the same Keycloak user to enter its password.
The callback displayed “The identity you selected is not approved for this action. Your existing
sign-in is still active.” The default Dashboard remained usable after reload. Persistence showed
no new secondary session and preserved the source Auth0 authentication time of 14:05:07 UTC.

Restoration reattached the original `basic` scope, detached and deleted only the temporary scope,
and verified the exact original default and optional scope sets plus the original example subject.
A new ordinary Keycloak callback then reached secondary readonly as the same existing person at
14:08:58 UTC. No API restart occurred. All stages kept five persons, seven memberships and eight
authenticators, unchanged membership roles, connection revisions and policies. The twenty-minute
automatic restore guard was stopped; no remapping remains active. A preflight mapper-default
assertion had previously stopped before attaching the temporary scope and restored it successfully.

This proves denial of a changed pairwise subject on an existing link and recovery after restoring
the original subject. It does not prove approved pairwise enrollment or additive linking.
No membership, credential, cloud resource or billing was added. Nonsecret observations and capture
hashes are in [the remap evidence](keycloak-pairwise-remap.json).
The mapper and example endpoints follow the official [Keycloak mapper reference](https://www.keycloak.org/admin-api/protocol-mappers)
and [Admin REST API](https://www.keycloak.org/docs-api/26.8.1/rest-api/index.html).

![Remapped subject denied while default readonly remains usable](keycloak-pairwise-denied.png)

![Original subject restored and secondary readonly reached](keycloak-pairwise-restored.png)

## Remaining certification

The retained accountless Quick Tunnel provides actual public HTTPS but its hostname depends on
that process. No permanent issuer availability after tunnel replacement is claimed. The stable
hostname decision remains separate; no silent issuer rebinding is allowed.

Other required issue #1517 cells remain open, including cross/custom-base-path realm boundaries,
approved pairwise enrollment/linking, client-secret rotation and the complete shared-flow
matrix. Historical enrollment/outage controls are retained locally but are not all mapped into
this worksheet yet. The owner's theme waiver applies; no theme matrix is claimed. This incremental
run is not a declaration that #1517 is ready to close.
