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

## Remaining certification

The retained accountless Quick Tunnel provides actual public HTTPS but its hostname depends on
that process. No permanent issuer availability after tunnel replacement is claimed. The stable
hostname decision remains separate; no silent issuer rebinding is allowed.

Other required issue #1517 cells remain open, including cross/custom-base-path realm boundaries,
provider subject remap/pairwise behavior, client-secret rotation and the complete shared-flow
matrix. Historical enrollment/outage controls are retained locally but are not all mapped into
this worksheet yet. The owner's theme waiver applies; no theme matrix is claimed. This incremental
run is not a declaration that #1517 is ready to close.
