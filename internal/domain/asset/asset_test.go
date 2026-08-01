package asset

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNewValidatesCategoryIdentity(t *testing.T) {
	now := time.Now()
	a, err := New("asset-1", "tenant-a", "Transfer API", CategoryEndpoint, Identity{Kind: "url", Value: "https://api.example.com/transfers"}, LifecycleActive, "payments", "high", "internet", "confidential", now)
	if err != nil { t.Fatal(err) }
	if a.Identity.Value != "https://api.example.com/transfers" || a.Audit.CreatedAt != now { t.Fatalf("unexpected asset: %+v", a) }
	_, err = New("asset-2", "tenant-a", "Bad endpoint", CategoryEndpoint, Identity{Kind: "url", Value: "https://user:secret@example.com"}, LifecycleActive, "", "", "", "", now)
	if !errors.Is(err, shared.ErrValidation) { t.Fatalf("got %v, want validation error", err) }
}

func TestRelationshipAndLinkRejectInvalidValues(t *testing.T) {
	if _, err := NewRelationship("a", "a", RelationshipContains, time.Now()); !errors.Is(err, shared.ErrValidation) { t.Fatalf("got %v", err) }
	if _, err := NewBusinessServiceLink("", "asset", BusinessServiceOwns, time.Now()); !errors.Is(err, shared.ErrValidation) { t.Fatalf("got %v", err) }
}

func TestNewVersionRejectsUnsafeMetadata(t *testing.T) {
	if _, err := NewVersion("version", "asset", "1.0\nsecret", "scanner", time.Now()); !errors.Is(err, shared.ErrValidation) { t.Fatalf("got %v", err) }
}
