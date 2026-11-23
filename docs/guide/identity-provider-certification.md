# Certifying an identity provider

Synapse uses a shared OIDC client and tenant-owned connection records. Certification
shows that a particular provider configuration works with that client and the
connection lifecycle. Provider settings, such as an Auth0 organization restriction
or an Entra discovery mode, add checks to this shared contract. They do not grant
membership or roles.

Use this guide with the provider's evidence record. Record the tested revision,
provider tenant or build, connection settings, expected result and observed result.
Keep credentials, authorization codes and private mailbox contents out of published
evidence.

## Client and connection contract

The implementation lives in `internal/infrastructure/oidc`,
`internal/usecase/identityenterprise` and the identity persistence adapters.

| Boundary | Required behavior |
| --- | --- |
| Issuer | Use the provider's exact HTTPS issuer, including a trailing slash when present. Query, fragment and user information are refused. Generic OIDC checks the token issuer exactly. Entra's explicit discovery modes additionally bind the concrete token issuer and tenant claims; see its evidence record. |
| Network | Discovery and provider requests refuse private, loopback, unique-local and metadata destinations. No private-address override is available. A local provider therefore needs a supported public HTTPS endpoint; a loopback Synapse callback does not make private provider discovery acceptable. |
| Discovery | The client reads the well-known discovery document, refuses provider redirects and ignores ambient proxy settings. Failed discovery enters a cooldown. Entra discovery follows its configured mode. |
| Authorization | Every enterprise authorization uses PKCE S256, a nonce and `max_age=900`. The provider may reuse an authentication that is still fresh; a new prompt on every login is not required. |
| Authentication time | The returned `auth_time` must be integral numeric seconds, not in the future, and less than 15 minutes old. Callback admission checks freshness again. Missing or stale proof is refused. |
| Token binding | A present `azp`, or a token with multiple audiences, must identify the client. A present `at_hash` is checked against the access token. The returned nonce must match the saved request. |
| Email | Only JSON boolean `email_verified: true` supplies verified email. An unverified or absent claim cannot satisfy mailbox ownership; enrollment uses the subject-bound mailbox challenge where required. |
| Subject | Links bind the issuer and exact non-empty subject. A different subject does not inherit an existing link. Providers must keep subjects stable and avoid recycling them: an identical recycled issuer/subject cannot be distinguished from the original identity by this client. |
| Membership | An unknown identity receives no just-in-time membership or role. Enrollment requires an explicit invitation; linking requires the existing person's authorization. Groups and custom claims do not assign roles. `SYNAPSE_OIDC_GROUP_ROLE_MAPPING` is accepted and ignored. |
| Logout | Logout revokes the local Synapse session. No RP-initiated provider logout is sent, so the provider session may remain available. |

See [identity foundation rollout](identity-foundation-rollout.md#where-the-provider-has-to-be-reachable-from)
for provider reachability and [identity recovery](identity-recovery.md) for recovery
requirements.

| Lifecycle step | Required behavior |
| --- | --- |
| Draft | An authorized administrator uses fresh authentication or the permitted repair mechanism. The client secret is sealed per tenant and connection and is not returned by connection APIs. The callback is fixed by the deployment. |
| Test | A real authorization and callback test is bound to the draft revision. A passing result expires after one hour. |
| Activate | Activation requires the tested revision and current proof. Editing a draft cannot reuse a test for a different revision. |
| Disable | Disabled connections stop admitting sign-ins and sessions authenticated through them. Admission checks connection state and session epoch; this need not physically revoke every stored session row. Other organizations and their roles remain unchanged. |
| Recovery | Use an independently valid connection or the permitted recovery mechanism. Required-SSO guards still apply. Restore the intended policy and prove ordinary login after recovery. A session from a disabled connection is not a recovery credential. |
| Provider outage | New federation fails without granting access. Locally valid sessions remain usable while their connection and local admission conditions remain valid; retry can recover when the provider returns. |

## Functional evidence before final review

Prove the affected user journey before opening final review. Retain accepted evidence
when the relevant code, provider settings and deployment behavior have not changed.
Builds and mocks alone do not prove a provider login works, but a new run need not
repeat unaffected journeys or an exhaustive theme matrix.

| Journey | Evidence to retain |
| --- | --- |
| Approved sign-in | Real login reaches the expected person, tenant, membership and role. |
| Unknown identity | An authenticated but unlinked subject is denied without a new person, membership or usable session. |
| Enrollment and linking | First and additional users accept approved invitations and subsequently sign in normally. Record whether verified email or a mailbox challenge supplied proof; check the applicable retry path. Linking preserves the existing person's roles. |
| Fresh authentication | Observe provider behavior when existing proof has expired and confirm a fresh `auth_time`. Record stale or missing proof rejection with its actual test method. |
| Tenant switching | A required-SSO destination requires its own enabled, approved connection proof for the same person. Missing or wrong proof does not switch tenants. |
| Provider restriction | Exercise any enabled organization, tenant or authorization-server restriction, including a representative denial. |
| Failure and recovery | Exercise relevant outage/retry, local logout, activation, disable and recovery paths. Confirm that other tenants and memberships are unchanged. |
| Console | Show the affected Settings, Connect, Profile or invitation flow at a usable viewport. Include narrow layouts or another theme when a change affects them; do not duplicate provider runs solely for presentation variants. |

Use signed local conformance tests for adversarial issuer, audience, subject,
`auth_time` and key-boundary cases where changing a hosted provider would be unsafe
or unnecessary. Label these as conformance evidence, separately from real provider
observations. They must exercise the shipped verifier and cannot replace the real
login, enrollment or recovery paths they do not cover.

Record key-refresh behavior and the environment used to test it. A maintainer may
defer hosted signing-key rotation until post-merge cleanup; record that decision
without labeling the hosted rotation as passed or blocking otherwise sufficient
functional acceptance. The same distinction applies to a deferred destructive
subject or credential change. Runtime validation remains mandatory.

Keep any remaining dependency or explicitly deferred provider acceptance visible in
its owning issue. A shared guide or an implementation merge does not certify an
untested provider. Final review covers the ready change and its stated acceptance;
repeat it only when a relevant edit or concrete finding invalidates the evidence.

## Provider evidence

The following records describe tested settings, source revisions and limitations.
They are more specific than an illustrative issuer shape; use the actual discovery
issuer when configuring a new connection.

- [Keycloak certification](https://github.com/KKloudTarus/synapse-ce/blob/213f6c4486e2745ed1a392cb26c6e69c3ffaa619/docs/evidence/identity-certification/keycloak.md) and
  [live run](https://github.com/KKloudTarus/synapse-ce/blob/213f6c4486e2745ed1a392cb26c6e69c3ffaa619/docs/evidence/identity-certification/keycloak-live-run.md).
- [Auth0 certification](https://github.com/KKloudTarus/synapse-ce/blob/213f6c4486e2745ed1a392cb26c6e69c3ffaa619/docs/evidence/identity-certification/auth0.md) and
  [live run](https://github.com/KKloudTarus/synapse-ce/blob/213f6c4486e2745ed1a392cb26c6e69c3ffaa619/docs/evidence/identity-certification/auth0-live-run.md). Preserve the issuer's
  trailing slash and configure the approved organization ID when organization
  restriction is required.
- [Entra certification](https://github.com/KKloudTarus/synapse-ce/blob/213f6c4486e2745ed1a392cb26c6e69c3ffaa619/docs/evidence/identity-certification/entra.md) and
  [live run](https://github.com/KKloudTarus/synapse-ce/blob/213f6c4486e2745ed1a392cb26c6e69c3ffaa619/docs/evidence/identity-certification/entra-live-run.md). Distinguish
  tenant-specific, `common` and `organizations` discovery from the concrete token
  issuer and allowed tenant.

Okta, Google Workspace and PingOne require their own scoped certification records
when a deployment enables them. An issuer example or an existing personal account
is not evidence that an organization's requirements are satisfied.
