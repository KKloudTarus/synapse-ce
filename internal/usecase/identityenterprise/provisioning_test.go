package identityenterprise

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type provisioningMemory struct {
	state                         ports.IdentityInitialProvisioning
	beginCalls, draftCalls, tests int
	draft                         ports.IdentityConnectionDraft
}

func (m *provisioningMemory) BeginIdentityProvisioning(_ context.Context, in ports.IdentityProvisioningBegin) (ports.IdentityInitialProvisioning, error) {
	m.beginCalls++
	if m.state.ID.IsZero() {
		m.state = ports.IdentityInitialProvisioning{ID: in.ID, TenantID: in.TenantID, ConnectionID: in.ConnectionID, InvitationID: in.InvitationID, Recipient: in.Recipient, ActorID: in.Principal.ActorID, SourceTenantID: in.Principal.TenantID, CredentialID: in.Principal.Credential.ID, State: "open", Version: 1}
	}
	return m.state, nil
}
func (m *provisioningMemory) ReadIdentityProvisioning(context.Context, ports.IdentityProvisioningProof) (ports.IdentityInitialProvisioning, error) {
	return m.state, nil
}
func (m *provisioningMemory) SaveIdentityProvisioningDraft(_ context.Context, d ports.IdentityConnectionDraft, _ ports.IdentityProvisioningProof) (ports.IdentityInitialProvisioning, error) {
	m.draftCalls++
	m.draft = d
	return m.state, nil
}
func (m *provisioningMemory) RecordIdentityProvisioningTest(context.Context, ports.IdentityConnectionTest, ports.IdentityProvisioningProof) error {
	if m.state.State != "draft" && m.state.State != "tested" {
		return shared.ErrForbidden
	}
	m.tests++
	m.state.State = "tested"
	return nil
}
func (m *provisioningMemory) ActivateIdentityProvisioningConnection(context.Context, int, int, ports.IdentityProvisioningProof) (ports.IdentityInitialProvisioning, error) {
	return m.state, nil
}
func (m *provisioningMemory) IssueIdentityProvisioningInvitation(_ context.Context, in ports.IdentityInvitationCreate, sealed string, _ ports.IdentityProvisioningProof) (ports.IdentityInitialProvisioning, error) {
	if m.state.Invitation == nil {
		m.state.Invitation = &in.Invitation
		m.state.InvitationCodeSealed = sealed
	}
	return m.state, nil
}

func provisioningActor() authz.Principal {
	return authz.Principal{ActorID: authz.BootstrapActorID, TenantID: "default", Role: user.RoleAdmin, Credential: authz.Credential{Kind: authz.KindBootstrap, ID: "current"}}
}
func provisioningService(t *testing.T, store *provisioningMemory, clock ports.Clock, id string) *Provisioning {
	t.Helper()
	s, err := NewProvisioning(store, authProtector{}, clock, &authIDs{}, ProvisioningConfig{CallbackURL: "https://console.example/api/auth/enterprise/callback", BootstrapCredentialID: id, AllowedTenant: func(s string) bool { return s == "destination" }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestProvisioningResumesPinnedOperationAfterProviderRoundTrip(t *testing.T) {
	for _, phase := range []string{"open", "draft", "tested", "active", "invited"} {
		t.Run(phase, func(t *testing.T) {
			now := time.Now().UTC()
			store := &provisioningMemory{}
			s := provisioningService(t, store, authClock{now}, "current")
			original, _, err := s.Begin(t.Context(), provisioningActor(), "destination", "admin@example.test")
			if err != nil {
				t.Fatal(err)
			}
			store.state.State = phase
			resumed, capability, err := s.Begin(t.Context(), provisioningActor(), "destination", "")
			if err != nil || capability == "" || resumed.ID != original.ID || resumed.ConnectionID != original.ConnectionID || resumed.InvitationID != original.InvitationID {
				t.Fatalf("resume of %s lost pinned operation: %v", phase, err)
			}
		})
	}
}

func TestProvisioningRefusesWrongAuthorityBeforeCreatingReservation(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name   string
		change func(*authz.Principal)
		target shared.ID
	}{
		{"api key", func(p *authz.Principal) { p.Credential.Kind = authz.KindAPIKey }, "destination"},
		{"native admin", func(p *authz.Principal) { p.ActorID = "person"; p.Credential.Kind = authz.KindBrowserSession }, "destination"},
		{"missing binding", func(p *authz.Principal) { p.Credential.ID = "" }, "destination"},
		{"old binding", func(p *authz.Principal) { p.Credential.ID = "old" }, "destination"},
		{"readonly", func(p *authz.Principal) { p.Role = user.RoleReadOnly }, "destination"},
		{"unlisted target", func(*authz.Principal) {}, "other"},
		{"own organization", func(*authz.Principal) {}, "default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &provisioningMemory{}
			s := provisioningService(t, m, authClock{now}, "current")
			p := provisioningActor()
			tc.change(&p)
			_, _, err := s.Begin(t.Context(), p, tc.target, "admin@example.test")
			if !errors.Is(err, shared.ErrForbidden) || m.beginCalls != 0 {
				t.Fatalf("unapproved initial authority reached reservation: %v", err)
			}
		})
	}
}

func TestProvisioningCapabilityKeepsActorAndCannotBecomeOrdinaryAdministratorProof(t *testing.T) {
	now := time.Now().UTC()
	m := &provisioningMemory{}
	s := provisioningService(t, m, authClock{now}, "current")
	actor := provisioningActor()
	state, capability, err := s.Begin(t.Context(), actor, "destination", "Admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := s.RequestProof(t.Context(), actor, capability)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Principal != actor || proof.TenantID != "destination" || proof.ID != state.ID || proof.Recipient != state.Recipient {
		t.Fatal("initial capability changed actor or lost pinned target/recipient")
	}
	ordinary := &Connections{protector: authProtector{}, clock: authClock{now}}
	if _, err = ordinary.AdminProof(t.Context(), actor, capability); !errors.Is(err, shared.ErrForbidden) {
		t.Fatal("initial capability became ordinary administrator proof")
	}
	other := actor
	other.TenantID = "foreign"
	if _, err = s.RequestProof(t.Context(), other, capability); !errors.Is(err, shared.ErrForbidden) {
		t.Fatal("capability reused by a different authenticated principal")
	}
}

func TestProvisioningCapabilityExpiresAndOldCredentialCannotCommitCallback(t *testing.T) {
	now := time.Now().UTC()
	clock := &bindingClock{at: now}
	m := &provisioningMemory{}
	s := provisioningService(t, m, clock, "current")
	_, capability, err := s.Begin(t.Context(), provisioningActor(), "destination", "admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	clock.at = now.Add(15 * time.Minute)
	if _, err = s.Proof(t.Context(), capability); !errors.Is(err, shared.ErrForbidden) {
		t.Fatal("expired capability accepted")
	}
	clock.at = now
	replaced := provisioningService(t, m, clock, "replacement")
	if err = replaced.RecordTest(t.Context(), capability, ports.IdentityConnectionTest{TenantID: "destination", ConnectionID: m.state.ConnectionID}); !errors.Is(err, shared.ErrForbidden) || m.tests != 0 {
		t.Fatal("old deployment credential committed a provisioning callback")
	}
	if _, err = s.Proof(t.Context(), "malformed"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatal("malformed capability accepted")
	}
}

func TestProvisioningDraftSealsForPinnedTargetAndInvitationReplayReturnsSameCode(t *testing.T) {
	now := time.Now().UTC()
	m := &provisioningMemory{}
	s := provisioningService(t, m, authClock{now}, "current")
	actor := provisioningActor()
	_, capability, err := s.Begin(t.Context(), actor, "destination", "admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Draft(t.Context(), actor, capability, ConnectionDraftInput{ID: "foreign", DisplayName: " Initial ", Issuer: "https://issuer.example/", ClientID: "client", ClientSecret: "synthetic-only"})
	if err != nil {
		t.Fatal(err)
	}
	if m.draft.TenantID != "destination" || m.draft.ID != m.state.ConnectionID || m.draft.DisplayName != "Initial" || m.draft.Settings.RedirectURL != "https://console.example/api/auth/enterprise/callback" {
		t.Fatal("draft escaped its reserved target or callback")
	}
	one, code, err := s.Invitation(t.Context(), actor, capability)
	if err != nil {
		t.Fatal(err)
	}
	two, replayed, err := s.Invitation(t.Context(), actor, capability)
	if err != nil {
		t.Fatal(err)
	}
	if code == "" || code != replayed || one.Invitation.ID != two.Invitation.ID || one.Invitation.Role != user.RoleAdmin || one.Invitation.Recipient != "admin@example.test" {
		t.Fatal("retry changed the pinned invitation or lost its result")
	}
	m.state.State = "closed"
	_, capability, err = s.Begin(t.Context(), actor, "destination", "")
	if err != nil || capability != "" {
		t.Fatal("closed operation issued more authority")
	}
}

func TestProvisioningNativeTestRecordsOnlyScopedProofAndReturnsToTarget(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	clock := authClock{now}
	m := &provisioningMemory{}
	provisioning := provisioningService(t, m, clock, "current")
	_, capability, err := provisioning.Begin(t.Context(), provisioningActor(), "destination", "admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	m.state.State = "draft"
	connections, tx := &testRecordingConnections{}, &authTransactions{}
	protocol := bindingTestService(t, "current", connections, tx, clock, authFactory{})
	if err = protocol.SetProvisioning(provisioning); err != nil {
		t.Fatal(err)
	}
	start, err := protocol.Begin(t.Context(), BeginInput{TenantID: "destination", ConnectionID: m.state.ConnectionID, Revision: 1, Purpose: ports.IdentityAuthorizationTest, CallerNonce: "browser", ProvisioningToken: capability})
	if err != nil {
		t.Fatal(err)
	}
	state := strings.TrimPrefix(start.AuthorizationURL, "https://issuer.example/auth?state=")
	out, err := protocol.Callback(t.Context(), CallbackInput{TenantID: "destination", State: state, Code: "code", CallerNonce: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	if out.ProvisioningTenantID != "destination" || m.tests != 1 || connections.tests != 0 || !tx.consumed {
		t.Fatal("native Test escaped provisioning scope or omitted one-use state")
	}
}
