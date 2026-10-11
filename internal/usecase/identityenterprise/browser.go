package identityenterprise

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identitysessions"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// BrowserStore shares the authoritative read model and atomic command boundaries.
type BrowserStore interface {
	ports.IdentityCredentialRouter
	ports.IdentitySessionStore
	ports.IdentityMembershipProjection
	ports.IdentityMembershipStore
	ports.IdentityCutoverStore
	ports.IdentityConnectionStore
	ports.IdentityRecoveryStore
	ports.IdentityAPIKeyAuthentication
	ports.IdentityAdmissionStore
	ports.IdentityAdministrationStore
}

type BrowserConfig struct {
	TenantID          shared.ID
	ReadEnabled       func(string) bool
	MutationEnabled   func(string) bool
	SessionTTL        time.Duration
	LegacyBearerGrace time.Duration
}

type Browser struct {
	store     BrowserStore
	protocol  *Service
	admission *AdmissionService
	sessions  *identitysessions.Service
	clock     ports.Clock
	ids       ports.IDGenerator
	cfg       BrowserConfig
}

type denyUnverifiedDestination struct{}

type verifiedDestinationKey struct{}
type verifiedDestination struct {
	proof  CallbackResult
	person shared.ID
}

func (denyUnverifiedDestination) VerifyDestinationProof(ctx context.Context, tenant, connection, person shared.ID, subject string, revision int, at time.Time) error {
	verified, ok := ctx.Value(verifiedDestinationKey{}).(verifiedDestination)
	if ok && verified.person == person && verified.proof.Purpose == ports.IdentityAuthorizationSwitch && verified.proof.ConnectionID == connection && verified.proof.Revision == revision && verified.proof.Subject == subject && !verified.proof.AuthenticatedAt.After(at) && at.Sub(verified.proof.AuthenticatedAt) <= 15*time.Minute {
		return nil
	}
	return shared.ErrForbidden
}

func NewBrowser(store BrowserStore, protocol *Service, admission *AdmissionService, protector ports.IdentitySecretProtector, clock ports.Clock, ids ports.IDGenerator, cfg BrowserConfig) (*Browser, error) {
	if store == nil || protocol == nil || admission == nil || protector == nil || clock == nil || ids == nil || cfg.TenantID.IsZero() || cfg.ReadEnabled == nil || cfg.MutationEnabled == nil || cfg.SessionTTL <= 0 || cfg.SessionTTL > identity.MaxSessionAge {
		return nil, shared.ErrValidation
	}
	sessions, err := identitysessions.NewService(store, denyUnverifiedDestination{}, protector, clock, ids)
	if err != nil {
		return nil, err
	}
	return &Browser{store: store, protocol: protocol, admission: admission, sessions: sessions, clock: clock, ids: ids, cfg: cfg}, nil
}

// CheckAuthority refuses a declared tenant when a binary is unable to serve its durable
// authority. Turning a deployment flag off never restores the legacy writer or resolver.
func (b *Browser) CheckAuthority(ctx context.Context, tenant shared.ID, mutation bool) error {
	state, err := b.store.CutoverState(ctx, tenant)
	if err != nil {
		return fmt.Errorf("read identity authority: %w", err)
	}
	enabled := b.cfg.ReadEnabled(tenant.String())
	if mutation {
		enabled = b.cfg.MutationEnabled(tenant.String())
	}
	if !state.Declared || !enabled {
		return fmt.Errorf("%w: enterprise authority is unavailable for organization", authz.ErrAuthenticationUnavailable)
	}
	return nil
}

// AdministrationEnabled allows explicit deployment bootstrap provisioning while keeping tenant
// mutations inside the configured subset. Ordinary administration requires declared authority.
func (b *Browser) AdministrationEnabled(ctx context.Context, p authz.Principal) error {
	if !b.cfg.MutationEnabled(p.TenantID) {
		return shared.ErrForbidden
	}
	if p.IsBootstrap() {
		return nil
	}
	return b.CheckAuthority(ctx, shared.ID(p.TenantID), true)
}

func (b *Browser) RefuseDeclaredLegacy(ctx context.Context, tenant shared.ID) error {
	state, err := b.store.CutoverState(ctx, tenant)
	if err != nil {
		return fmt.Errorf("read legacy authority fence: %w", authz.ErrAuthenticationUnavailable)
	}
	if state.Declared {
		return authz.ErrCredentialInvalid
	}
	return nil
}

func (b *Browser) Authenticate(ctx context.Context, token, csrf string, unsafe bool) (authz.Principal, error) {
	auth, err := b.sessions.Authenticate(ctx, token, csrf, unsafe)
	if err != nil {
		return authz.Principal{}, err
	}
	if err = b.CheckAuthority(ctx, auth.Session.TenantID, false); err != nil {
		return authz.Principal{}, err
	}
	member, err := b.store.GetMembership(ctx, auth.Session.TenantID, auth.Session.MembershipID)
	if err != nil {
		return authz.Principal{}, fmt.Errorf("read enterprise membership: %w", authz.ErrAuthenticationUnavailable)
	}
	return principalForSession(auth.Session, member), nil
}

func principalForSession(s identity.EnterpriseSession, m ports.IdentityMembership) authz.Principal {
	actor := m.LegacyUserID.String()
	if actor == "" {
		actor = m.ID.String()
	}
	return authz.Principal{ActorID: actor, PersonID: s.PersonID.String(), MembershipID: s.MembershipID.String(), TenantID: s.TenantID.String(), Role: m.Role, Credential: authz.Credential{Kind: authz.CredentialKind(s.Kind), ID: s.ID.String()}, AuthenticatedAt: s.AuthenticatedAt, Provenance: "enterprise_oidc", Epochs: authz.Epochs{Person: s.PersonEpoch, Membership: s.MembershipEpoch, Connection: s.ConnectionEpoch}}
}

func (b *Browser) Discover(ctx context.Context, token string) (identitysessions.CreatedSession, authz.Principal, error) {
	auth, err := b.sessions.Authenticate(ctx, token, "", false)
	if err != nil {
		return identitysessions.CreatedSession{}, authz.Principal{}, err
	}
	if err = b.CheckAuthority(ctx, auth.Session.TenantID, true); err != nil {
		return identitysessions.CreatedSession{}, authz.Principal{}, err
	}
	expires := b.clock.Now().UTC().Add(b.cfg.SessionTTL)
	if cap := auth.Session.OriginAt.Add(identity.MaxSessionAge); expires.After(cap) {
		expires = cap
	}
	if auth.Session.Kind == identity.EnterpriseSessionKindBreakGlass {
		expires = auth.Session.ExpiresAt
	}
	created, err := b.sessions.Rotate(ctx, token, auth.Session, auth.Session.PersonID.String(), expires)
	if err != nil {
		return created, authz.Principal{}, err
	}
	member, err := b.store.GetMembership(ctx, created.Session.TenantID, created.Session.MembershipID)
	return created, principalForSession(created.Session, member), err
}

func (b *Browser) Logout(ctx context.Context, token string) error {
	return b.sessions.Logout(ctx, token, "browser")
}
func (b *Browser) Picker(ctx context.Context, token string) ([]ports.IdentityMembershipChoice, error) {
	return b.sessions.Picker(ctx, token, "", false)
}
func (b *Browser) Route(ctx context.Context, token string) (ports.IdentityCredentialRoute, error) {
	return b.store.RouteCredentialDigest(ctx, admissionDigest(token))
}

func (b *Browser) LegacyBearerGraceDuration() time.Duration { return b.cfg.LegacyBearerGrace }

func (b *Browser) AuthenticateAPIKey(ctx context.Context, token string) (authz.Principal, error) {
	p, err := b.store.AuthenticateIdentityAPIKey(ctx, admissionDigest(token), b.clock.Now().UTC(), b.cfg.LegacyBearerGrace)
	if errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrForbidden) {
		return authz.Principal{}, authz.ErrCredentialInvalid
	}
	if err != nil {
		return authz.Principal{}, authz.ErrAuthenticationUnavailable
	}
	if err = b.CheckAuthority(ctx, shared.ID(p.TenantID), false); err != nil {
		return authz.Principal{}, err
	}
	return p, nil
}

type BrowserAuthorization struct {
	TenantID       shared.ID
	ConnectionID   shared.ID
	Purpose        ports.IdentityAuthorizationPurpose
	CallerNonce    string
	SourceToken    string
	CSRFToken      string
	InvitationCode string
	AdminProof     *ports.IdentityAdminProof
}
type browserIntent struct {
	SourceDigest            string    `json:"source_digest,omitempty"`
	SourceSessionID         shared.ID `json:"source_session_id,omitempty"`
	PersonID                shared.ID `json:"person_id,omitempty"`
	DestinationMembershipID shared.ID `json:"destination_membership_id,omitempty"`
	SourceCSRF              string    `json:"source_csrf,omitempty"`
	RetryKey                string    `json:"retry_key,omitempty"`
	RetryPayload            string    `json:"retry_payload,omitempty"`
	InvitationID            shared.ID `json:"invitation_id,omitempty"`
	InvitationVersion       int       `json:"invitation_version,omitempty"`
	InvitationDigest        string    `json:"invitation_digest,omitempty"`
	NewPersonID             shared.ID `json:"new_person_id,omitempty"`
}

func (b *Browser) Begin(ctx context.Context, in BrowserAuthorization) (BeginResult, error) {
	var invitation ports.IdentityInvitation
	if in.Purpose == ports.IdentityAuthorizationInvitation {
		route, err := b.admission.ResolveInvitation(ctx, in.InvitationCode)
		if err != nil {
			return BeginResult{}, err
		}
		in.TenantID = route.TenantID
		invitation, err = b.store.GetIdentityInvitation(ctx, route.TenantID, route.InvitationID)
		if err != nil {
			return BeginResult{}, err
		}
	}
	if in.TenantID.IsZero() {
		in.TenantID = b.cfg.TenantID
	}
	if !b.cfg.MutationEnabled(in.TenantID.String()) {
		return BeginResult{}, shared.ErrForbidden
	}
	intent := browserIntent{}
	switch in.Purpose {
	case ports.IdentityAuthorizationInvitation:
		if err := b.CheckAuthority(ctx, in.TenantID, true); err != nil {
			return BeginResult{}, err
		}
		intent = browserIntent{InvitationID: invitation.ID, InvitationVersion: invitation.Version, InvitationDigest: admissionDigest(in.InvitationCode), NewPersonID: b.ids.NewID()}
		if in.SourceToken != "" {
			p, err := b.Authenticate(ctx, in.SourceToken, in.CSRFToken, true)
			if err != nil {
				return BeginResult{}, err
			}
			if p.Credential.Kind != authz.KindBrowserSession {
				return BeginResult{}, shared.ErrForbidden
			}
			intent.SourceDigest = admissionDigest(in.SourceToken)
			intent.SourceSessionID = shared.ID(p.Credential.ID)
			intent.PersonID = shared.ID(p.PersonID)
			intent.NewPersonID = ""
		} else if !b.admission.MailboxChallengeAvailable() {
			return BeginResult{}, shared.ErrForbidden
		}
	case ports.IdentityAuthorizationLogin:
		if in.TenantID != b.cfg.TenantID {
			return BeginResult{}, shared.ErrForbidden
		}
		if err := b.CheckAuthority(ctx, in.TenantID, true); err != nil {
			return BeginResult{}, err
		}
	case ports.IdentityAuthorizationLink, ports.IdentityAuthorizationStepUp:
		p, err := b.Authenticate(ctx, in.SourceToken, in.CSRFToken, true)
		if err != nil {
			return BeginResult{}, err
		}
		if p.Credential.Kind != authz.KindBrowserSession || p.TenantID != in.TenantID.String() {
			return BeginResult{}, shared.ErrForbidden
		}
		if in.Purpose == ports.IdentityAuthorizationLink && !authz.RecentlyAuthenticated(p, b.clock.Now()) {
			return BeginResult{}, shared.ErrForbidden
		}
		intent = browserIntent{SourceDigest: admissionDigest(in.SourceToken), SourceSessionID: shared.ID(p.Credential.ID), PersonID: shared.ID(p.PersonID)}
	case ports.IdentityAuthorizationTest:
		if in.AdminProof == nil {
			return BeginResult{}, shared.ErrForbidden
		}
	default:
		return BeginResult{}, shared.ErrValidation
	}
	encoded, err := json.Marshal(intent)
	if err != nil {
		return BeginResult{}, err
	}
	return b.protocol.Begin(ctx, BeginInput{TenantID: in.TenantID, ConnectionID: in.ConnectionID, Purpose: in.Purpose, CallerNonce: in.CallerNonce, Context: encoded, AdminProof: in.AdminProof})
}

type BrowserCallback struct {
	TenantID                              shared.ID
	State, Code, CallerNonce, SourceToken string
}
type BrowserCallbackResult struct {
	Session   identitysessions.CreatedSession
	Principal authz.Principal
	TestOnly  bool
	Pending   *PendingInvitation
}

// PendingInvitation is sealed into a short-lived HttpOnly envelope by the adapter. The verified
// proof and replacement material never appear in application URLs or response JSON.
type PendingInvitation struct {
	Command          ports.IdentityAdmissionCommand
	Token, CSRFToken string
	ExpiresAt        time.Time
}

func (b *Browser) Complete(ctx context.Context, in BrowserCallback) (BrowserCallbackResult, error) {
	proof, err := b.protocol.Callback(ctx, CallbackInput{TenantID: in.TenantID, State: in.State, Code: in.Code, CallerNonce: in.CallerNonce})
	if err != nil {
		return BrowserCallbackResult{}, err
	}
	if proof.Purpose == ports.IdentityAuthorizationTest {
		return BrowserCallbackResult{TestOnly: true}, nil
	}
	if err = b.CheckAuthority(ctx, in.TenantID, true); err != nil {
		return BrowserCallbackResult{}, err
	}
	var intent browserIntent
	if json.Unmarshal(proof.Context, &intent) != nil {
		return BrowserCallbackResult{}, shared.ErrForbidden
	}
	if proof.Purpose == ports.IdentityAuthorizationLink || proof.Purpose == ports.IdentityAuthorizationStepUp || proof.Purpose == ports.IdentityAuthorizationSwitch || proof.Purpose == ports.IdentityAuthorizationInvitation && intent.SourceDigest != "" {
		if subtle.ConstantTimeCompare([]byte(intent.SourceDigest), []byte(admissionDigest(in.SourceToken))) != 1 {
			return BrowserCallbackResult{}, shared.ErrForbidden
		}
		current, err := b.Authenticate(ctx, in.SourceToken, "", false)
		if err != nil {
			return BrowserCallbackResult{}, err
		}
		if current.Credential.ID != intent.SourceSessionID.String() || current.PersonID != intent.PersonID.String() {
			return BrowserCallbackResult{}, shared.ErrForbidden
		}
	}
	if proof.Purpose == ports.IdentityAuthorizationSwitch {
		ctx = context.WithValue(ctx, verifiedDestinationKey{}, verifiedDestination{proof: proof, person: intent.PersonID})
		created, err := b.sessions.Switch(ctx, identitysessions.SwitchInput{SourceToken: in.SourceToken, SourceCSRFToken: intent.SourceCSRF, DestinationTenantID: in.TenantID, DestinationMembershipID: intent.DestinationMembershipID, DestinationConnectionID: proof.ConnectionID, DestinationSubject: proof.Subject, DestinationRevision: proof.Revision, DestinationAuthenticatedAt: proof.AuthenticatedAt, PersonID: intent.PersonID, Kind: identity.EnterpriseSessionKindBrowser, ExpiresAt: b.clock.Now().Add(b.cfg.SessionTTL), PersonEpoch: 1, MembershipEpoch: 1, ConnectionEpoch: 1, RetryKey: intent.RetryKey, RetryPayload: intent.RetryPayload}, "identity-browser")
		if err != nil {
			return BrowserCallbackResult{}, err
		}
		member, err := b.store.GetMembership(ctx, in.TenantID, created.Session.MembershipID)
		if err != nil {
			return BrowserCallbackResult{}, err
		}
		return BrowserCallbackResult{Session: created, Principal: principalForSession(created.Session, member)}, nil
	}
	token, err := admissionSecret()
	if err != nil {
		return BrowserCallbackResult{}, err
	}
	csrf, err := admissionSecret()
	if err != nil {
		return BrowserCallbackResult{}, err
	}
	now := b.clock.Now().UTC()
	command := ports.IdentityAdmissionCommand{Purpose: proof.Purpose, TenantID: in.TenantID, ConnectionID: proof.ConnectionID, ConnectionRevision: proof.Revision, Subject: proof.Subject, AuthenticatedAt: proof.AuthenticatedAt, ExpectedPersonID: intent.PersonID, Actor: "identity-browser", Now: now, Issue: ports.IdentitySessionIssue{Session: identity.EnterpriseSession{ID: b.ids.NewID(), CredentialID: b.ids.NewID(), Kind: identity.EnterpriseSessionKindBrowser, AuthenticatedAt: proof.AuthenticatedAt, OriginAt: now, CreatedAt: now, ExpiresAt: now.Add(b.cfg.SessionTTL), CSRFTokenHash: admissionDigest(csrf)}, CredentialDigest: admissionDigest(token)}}
	command.SourceCredentialDigest = intent.SourceDigest
	command.SourceSessionID = intent.SourceSessionID
	if proof.Purpose == ports.IdentityAuthorizationInvitation {
		command.InvitationID = intent.InvitationID
		command.InvitationVersion = intent.InvitationVersion
		command.InvitationCodeDigest = intent.InvitationDigest
		command.NewPersonID = intent.NewPersonID
		command.DisplayName = strings.TrimSpace(proof.Name)
		if command.DisplayName == "" {
			command.DisplayName = "Invited member"
		}
		if len(command.DisplayName) > 200 {
			command.DisplayName = "Invited member"
		}
		invitation, err := b.store.GetIdentityInvitation(ctx, in.TenantID, intent.InvitationID)
		if err != nil {
			return BrowserCallbackResult{}, err
		}
		mailbox, mailErr := user.NormalizeContactEmail(proof.Email)
		if proof.EmailVerified && mailErr == nil && mailbox == invitation.Recipient {
			command.VerifiedMailbox = mailbox
		} else {
			person := intent.PersonID
			if person.IsZero() {
				person = intent.NewPersonID
			}
			if err := b.admission.SendMailboxChallenge(ctx, ports.IdentityInvitationRoute{TenantID: in.TenantID, InvitationID: intent.InvitationID}, proof.Subject, person); err != nil {
				return BrowserCallbackResult{}, err
			}
			return BrowserCallbackResult{Pending: &PendingInvitation{Command: command, Token: token, CSRFToken: csrf, ExpiresAt: now.Add(10 * time.Minute)}}, nil
		}
	}
	result, err := b.admission.Admit(ctx, AdmitInput{Command: command})
	if err != nil {
		return BrowserCallbackResult{}, err
	}
	return BrowserCallbackResult{Session: identitysessions.CreatedSession{Session: result.Session, Token: token, CSRFToken: csrf}, Principal: principalForSession(result.Session, result.Membership)}, nil
}

func (b *Browser) CompleteInvitation(ctx context.Context, pending PendingInvitation, code, sourceToken string) (BrowserCallbackResult, error) {
	now := b.clock.Now().UTC()
	if !now.Before(pending.ExpiresAt) || !now.Before(pending.Command.AuthenticatedAt.Add(15*time.Minute)) || pending.Command.Purpose != ports.IdentityAuthorizationInvitation || len(code) < 32 || len(code) > 128 {
		return BrowserCallbackResult{}, shared.ErrForbidden
	}
	if err := b.CheckAuthority(ctx, pending.Command.TenantID, true); err != nil {
		return BrowserCallbackResult{}, err
	}
	if pending.Command.SourceCredentialDigest != "" {
		if subtle.ConstantTimeCompare([]byte(admissionDigest(sourceToken)), []byte(pending.Command.SourceCredentialDigest)) != 1 {
			return BrowserCallbackResult{}, shared.ErrForbidden
		}
		// Fresh admission validates source authority atomically; an exact retained retry must
		// also work after that same transaction revoked the initiating credential.
	}
	pending.Command.ChallengeDigest = admissionDigest(code)
	pending.Command.Now = now
	result, err := b.admission.Admit(ctx, AdmitInput{Command: pending.Command})
	if err != nil {
		return BrowserCallbackResult{}, err
	}
	return BrowserCallbackResult{Session: identitysessions.CreatedSession{Session: result.Session, Token: pending.Token, CSRFToken: pending.CSRFToken}, Principal: principalForSession(result.Session, result.Membership)}, nil
}

// Dependency errors are terminal; only a definitive routing miss may use legacy authority.
func IsRouteMiss(err error) bool { return errors.Is(err, shared.ErrNotFound) }

type BrowserSwitchInput struct {
	SourceToken, CSRFToken, RetryKey, CallerNonce string
	TenantID, MembershipID, ConnectionID          shared.ID
}
type BrowserSwitchResult struct {
	Session                  *identitysessions.CreatedSession
	Authorization            *BeginResult
	Connections              []ports.IdentityConnection
	ReauthenticationRequired bool
}

// Switch first tries the exact retained response, then derives destination authority from the
// signed-in person's own projection. A revoked source never authorizes a fresh command.
func (b *Browser) Switch(ctx context.Context, in BrowserSwitchInput) (BrowserSwitchResult, error) {
	if in.TenantID.IsZero() || in.MembershipID.IsZero() || len(in.RetryKey) < 16 || len(in.RetryKey) > 128 {
		return BrowserSwitchResult{}, shared.ErrValidation
	}
	payload, err := json.Marshal(struct{ Tenant, Membership, Connection shared.ID }{in.TenantID, in.MembershipID, in.ConnectionID})
	if err != nil {
		return BrowserSwitchResult{}, err
	}
	replay, err := b.sessions.Replay(ctx, identitysessions.ReplayInput{SourceToken: in.SourceToken, SourceCSRFToken: in.CSRFToken, RetryKey: in.RetryKey, RetryPayload: string(payload)})
	if err == nil {
		if err = b.CheckAuthority(ctx, replay.Session.TenantID, true); err != nil {
			return BrowserSwitchResult{}, err
		}
		return BrowserSwitchResult{Session: &replay}, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return BrowserSwitchResult{}, err
	}
	p, err := b.Authenticate(ctx, in.SourceToken, in.CSRFToken, true)
	if err != nil {
		return BrowserSwitchResult{}, err
	}
	if p.Credential.Kind != authz.KindBrowserSession {
		return BrowserSwitchResult{}, shared.ErrForbidden
	}
	choices, err := b.Picker(ctx, in.SourceToken)
	if err != nil {
		return BrowserSwitchResult{}, err
	}
	allowed := false
	for _, choice := range choices {
		if choice.TenantID == in.TenantID && choice.MembershipID == in.MembershipID {
			allowed = true
			break
		}
	}
	if !allowed {
		return BrowserSwitchResult{}, shared.ErrForbidden
	}
	if err = b.CheckAuthority(ctx, in.TenantID, true); err != nil {
		return BrowserSwitchResult{}, err
	}
	policy, err := b.store.GetIdentityRecoveryPolicy(ctx, in.TenantID)
	if err != nil {
		return BrowserSwitchResult{}, err
	}
	if policy.Organization.Requirement == authz.SSORequired {
		connections, err := b.store.ListIdentityConnections(ctx, in.TenantID, true)
		if err != nil {
			return BrowserSwitchResult{}, err
		}
		if in.ConnectionID.IsZero() {
			return BrowserSwitchResult{ReauthenticationRequired: true, Connections: connections}, nil
		}
		eligible := false
		for _, c := range connections {
			if c.ID == in.ConnectionID {
				eligible = true
				break
			}
		}
		if !eligible {
			return BrowserSwitchResult{}, shared.ErrForbidden
		}
		intent, err := json.Marshal(browserIntent{SourceDigest: admissionDigest(in.SourceToken), SourceSessionID: shared.ID(p.Credential.ID), PersonID: shared.ID(p.PersonID), DestinationMembershipID: in.MembershipID, SourceCSRF: in.CSRFToken, RetryKey: in.RetryKey, RetryPayload: string(payload)})
		if err != nil {
			return BrowserSwitchResult{}, err
		}
		begin, err := b.protocol.Begin(ctx, BeginInput{TenantID: in.TenantID, ConnectionID: in.ConnectionID, Purpose: ports.IdentityAuthorizationSwitch, CallerNonce: in.CallerNonce, Context: intent})
		if err != nil {
			return BrowserSwitchResult{}, err
		}
		return BrowserSwitchResult{Authorization: &begin}, nil
	}
	if policy.Organization.Requirement != authz.SSOOptional || !in.ConnectionID.IsZero() {
		return BrowserSwitchResult{}, shared.ErrForbidden
	}
	created, err := b.sessions.Switch(ctx, identitysessions.SwitchInput{SourceToken: in.SourceToken, SourceCSRFToken: in.CSRFToken, DestinationTenantID: in.TenantID, DestinationMembershipID: in.MembershipID, PersonID: shared.ID(p.PersonID), Kind: identity.EnterpriseSessionKindBrowser, ExpiresAt: b.clock.Now().Add(b.cfg.SessionTTL), PersonEpoch: 1, MembershipEpoch: 1, RetryKey: in.RetryKey, RetryPayload: string(payload)}, p.ActorID)
	if err != nil {
		return BrowserSwitchResult{}, err
	}
	return BrowserSwitchResult{Session: &created}, nil
}
