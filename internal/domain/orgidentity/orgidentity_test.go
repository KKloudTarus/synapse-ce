package orgidentity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

var identityTestNow = time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

func TestPersonSuspensionStartsNewCredentialEra(t *testing.T) {
	p, err := NewPerson("person-1", "Alice", identityTestNow)
	if err != nil { t.Fatal(err) }
	if err := p.Suspend(1, identityTestNow.Add(time.Minute)); err != nil { t.Fatal(err) }
	if p.Status != PersonSuspended || p.CredentialEpoch != 2 || p.Version != 2 {
		t.Fatalf("suspended person = %+v", p)
	}
	if err := p.Activate(2, identityTestNow.Add(2*time.Minute)); err != nil { t.Fatal(err) }
	if p.Status != PersonActive || p.CredentialEpoch != 3 || p.Version != 3 {
		t.Fatalf("reactivated person reused old credential era: %+v", p)
	}
	if err := p.Suspend(1, identityTestNow.Add(3*time.Minute)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version = %v, want conflict", err)
	}
}

func TestMembershipRemovedIsTerminalAndRoleChangeRevokes(t *testing.T) {
	m, err := NewMembership("tenant-a", "membership-a", "person-a", user.RoleConsultant, identityTestNow)
	if err != nil { t.Fatal(err) }
	if err := m.ChangeRole(user.RoleReviewer, 1, identityTestNow.Add(time.Minute)); err != nil { t.Fatal(err) }
	if m.Role != user.RoleReviewer || m.Epoch != 2 || m.Version != 2 {
		t.Fatalf("role transition = %+v", m)
	}
	if err := m.Remove(2, identityTestNow.Add(2*time.Minute)); err != nil { t.Fatal(err) }
	if m.Status != MembershipRemoved || m.Epoch != 3 { t.Fatalf("removed = %+v", m) }
	if err := m.Activate(3, identityTestNow.Add(3*time.Minute)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("reactivate removed = %v, want forbidden", err)
	}
	if err := m.ChangeRole(user.RoleAdmin, 3, identityTestNow.Add(3*time.Minute)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("mutate removed = %v, want forbidden", err)
	}
}

func TestRoutineConnectionRevisionDoesNotRevokeExistingSessions(t *testing.T) {
	c, err := NewConnection("tenant-a", "connection-a", ProtocolOIDC, "https://issuer.example", identityTestNow)
	if err != nil { t.Fatal(err) }
	if err := c.ActivateRevision(7, true, 1, identityTestNow.Add(time.Minute)); err != nil { t.Fatal(err) }
	if c.ActiveRevision != 7 || c.ConnectionEpoch != 1 || c.Version != 2 {
		t.Fatalf("routine revision changed authority epoch: %+v", c)
	}
	if err := c.SetEnabled(false, 2, identityTestNow.Add(2*time.Minute)); err != nil { t.Fatal(err) }
	if c.Enabled || c.ConnectionEpoch != 2 || c.Version != 3 {
		t.Fatalf("disable did not revoke connection era: %+v", c)
	}
	if err := c.SetEnabled(true, 3, identityTestNow.Add(3*time.Minute)); err != nil { t.Fatal(err) }
	if !c.Enabled || c.ConnectionEpoch != 3 {
		t.Fatalf("re-enable reused pre-disable authority era: %+v", c)
	}
}

func TestConnectionRevisionIsBoundedProtocolNeutralJSON(t *testing.T) {
	r, err := NewConnectionRevision("tenant-a", "connection-a", 1, ProtocolOIDC, json.RawMessage(`{"issuer":"https://issuer.example"}`), "secret-ref", "admin", identityTestNow)
	if err != nil { t.Fatal(err) }
	passed, err := r.WithTestResult(RevisionPassed, json.RawMessage(`{"discovery":true}`), identityTestNow.Add(time.Minute))
	if err != nil { t.Fatal(err) }
	if passed.TestStatus != RevisionPassed || passed.TestedAt == nil || r.TestStatus != RevisionUntested {
		t.Fatalf("immutable result transition original=%+v result=%+v", r, passed)
	}
	if _, err := NewConnectionRevision("tenant-a", "connection-a", 2, ProtocolOIDC, json.RawMessage(`[]`), "", "admin", identityTestNow); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("array configuration = %v, want validation", err)
	}
	tooLarge := json.RawMessage(`{"x":"` + strings.Repeat("a", 33000) + `"}`)
	if _, err := NewConnectionRevision("tenant-a", "connection-a", 2, ProtocolOIDC, tooLarge, "", "admin", identityTestNow); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized configuration = %v, want validation", err)
	}
}

func TestCredentialLocatorContainsNoHumanDiscoveryMaterial(t *testing.T) {
	locator, err := NewCredentialLocator(strings.Repeat("a", 64), "tenant-a", CredentialInvitation, "invite-1")
	if err != nil { t.Fatal(err) }
	if locator.OrganizationID != "tenant-a" || locator.CredentialID != "invite-1" || locator.Kind != CredentialInvitation {
		t.Fatalf("locator = %+v", locator)
	}
	if _, err := NewCredentialLocator("prefix", "tenant-a", CredentialInvitation, "invite-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("partial digest = %v, want validation", err)
	}
}
