package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestEnterpriseSessionValidRequiresCompleteEpochBinding(t *testing.T) {
	now := time.Now().UTC()
	s := EnterpriseSession{ID: "s", TenantID: "t", CredentialID: "c", MembershipID: "m", PersonID: "p", LineageID: "l", Kind: EnterpriseSessionKindBrowser, AuthenticatedAt: now, OriginAt: now, ExpiresAt: now.Add(time.Hour), PersonEpoch: 1, MembershipEpoch: 1, CSRFTokenHash: "digest", CreatedAt: now}
	if err := s.Valid(); err != nil {
		t.Fatal(err)
	}
	s.ConnectionID = shared.ID("conn")
	if !errors.Is(s.Valid(), shared.ErrValidation) {
		t.Fatalf("missing connection epoch error = %v", s.Valid())
	}
	s.ConnectionEpoch = 1
	if err := s.Valid(); err != nil {
		t.Fatal(err)
	}
	if !s.BeyondMaxAge(now.Add(MaxSessionAge)) {
		t.Fatal("max-age boundary must be exclusive")
	}
}
