package asset

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var testNow = time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

func TestKindValid(t *testing.T) {
	for _, k := range []Kind{KindHost, KindWorkload, KindImage, KindCloudAccount, KindStorage, KindExposure, KindIdentity, KindNamespace, KindCluster} {
		if !k.Valid() {
			t.Errorf("kind %q should be valid", k)
		}
	}
	for _, k := range []Kind{"", "server", "vm", "HOST"} {
		if k.Valid() {
			t.Errorf("kind %q should be invalid", k)
		}
	}
}

func TestNewAsset(t *testing.T) {
	tests := []struct {
		name    string
		id      shared.ID
		tenant  shared.ID
		kind    Kind
		key     string
		wantErr bool
	}{
		{"ok", "a1", "t1", KindImage, "sha256:abc", false},
		{"missing id", "", "t1", KindImage, "sha256:abc", true},
		{"empty tenant is deny", "a1", "", KindImage, "sha256:abc", true},
		{"invalid kind", "a1", "t1", "server", "sha256:abc", true},
		{"missing key", "a1", "t1", KindImage, "   ", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := New(tc.id, tc.tenant, tc.kind, tc.key, "", nil, testNow)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("expected ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Name != tc.key {
				t.Errorf("name should default to key %q, got %q", tc.key, got.Name)
			}
			if got.Attributes == nil {
				t.Errorf("attributes should be non-nil")
			}
		})
	}
}

func TestNewAssetCopiesAttributes(t *testing.T) {
	in := map[string]string{"os": "linux"}
	a, err := New("a1", "t1", KindHost, "host-1", "Host 1", in, testNow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	in["os"] = "windows" // mutate caller's map
	if a.Attributes["os"] != "linux" {
		t.Fatalf("asset must copy attributes, got %q", a.Attributes["os"])
	}
}

func TestNewEdge(t *testing.T) {
	tests := []struct {
		name       string
		tenant     shared.ID
		from, to   shared.ID
		kind       EdgeKind
		provenance shared.ID
		confidence EdgeConfidence
		wantErr    bool
	}{
		{"observed", "t1", "a1", "a2", EdgeRuns, "obs1", EdgeObserved, false},
		{"inferred", "t1", "a1", "a2", EdgeRuns, "obs1", EdgeInferred, false},
		{"empty tenant", "", "a1", "a2", EdgeRuns, "obs1", EdgeObserved, true},
		{"missing from", "t1", "", "a2", EdgeRuns, "obs1", EdgeObserved, true},
		{"missing to", "t1", "a1", "", EdgeRuns, "obs1", EdgeObserved, true},
		{"invalid kind", "t1", "a1", "a2", "points_to", "obs1", EdgeObserved, true},
		{"retired member_of kind", "t1", "a1", "a2", "member_of", "obs1", EdgeObserved, true},
		{"missing provenance", "t1", "a1", "a2", EdgeRuns, "", EdgeObserved, true},
		{"missing confidence", "t1", "a1", "a2", EdgeRuns, "obs1", "", true},
		{"invalid confidence", "t1", "a1", "a2", EdgeRuns, "obs1", "certain", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEdge(tc.tenant, tc.from, tc.to, tc.kind, tc.provenance, tc.confidence)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if tc.wantErr && !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("expected ErrValidation, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
