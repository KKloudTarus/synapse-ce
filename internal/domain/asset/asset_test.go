package asset

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestIdentityValidationRejectsSecretsAndInvalidCategoryForms(t *testing.T) {
	cases := []struct {
		name     string
		category Category
		identity Identity
		valid    bool
	}{
		{"repository URL", CategoryRepository, Identity{Kind: "url", Value: "https://github.com/acme/payments.git"}, true},
		{"repository credential", CategoryRepository, Identity{Kind: "url", Value: "https://alice:secret@github.com/acme/payments.git"}, false},
		{"endpoint URL", CategoryEndpoint, Identity{Kind: "url", Value: "https://api.example.com/v1"}, true},
		{"endpoint non URL", CategoryEndpoint, Identity{Kind: "url", Value: "api.example.com"}, false},
		{"image digest", CategoryContainerImage, Identity{Kind: "digest", Value: "registry.example/payments@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, true},
		{"image tag", CategoryContainerImage, Identity{Kind: "digest", Value: "registry.example/payments:latest"}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.identity.Validate(tt.category)
			if (err == nil) != tt.valid {
				t.Fatalf("err=%v valid=%v", err, tt.valid)
			}
		})
	}
	if _, err := New("queue-a", "tenant-a", "Queue", Category("queue"), Identity{Kind: "name", Value: "queue-a"}, time.Now().UTC()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("deferred category error=%v", err)
	}
}

func TestAssetAndLinksValidateBoundedTenantSafeIdentity(t *testing.T) {
	now := time.Now().UTC()
	a, err := New("asset-1", "tenant-a", "Payments API", CategoryAPI, Identity{Kind: "url", Value: "https://api.example.com"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != 1 || a.Lifecycle != LifecyclePlanned {
		t.Fatalf("asset=%+v", a)
	}
	if err := (Relationship{ID: "r1", TenantID: "tenant-a", FromAssetID: a.ID, ToAssetID: a.ID, Type: RelationshipDependsOn, CreatedAt: now}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("self relation error=%v", err)
	}
	if err := (BusinessServiceAssetLink{BusinessServiceID: "service-1", AssetID: a.ID, Role: AssetLinkOwns, CreatedAt: now}).Validate(); err != nil {
		t.Fatal(err)
	}
}
