package memory

import (
	"context"
	"testing"
	"time"
)

func TestScannedImageStoreMarkAndQuery(t *testing.T) {
	s := NewScannedImageStore()
	ctx := context.Background()
	now := time.Unix(1700000000, 0).UTC()

	if err := s.MarkScanned(ctx, "tenant-a", "sha256:aaa", now); err != nil {
		t.Fatalf("mark: %v", err)
	}
	if err := s.MarkScanned(ctx, "tenant-a", "sha256:aaa", now); err != nil { // idempotent
		t.Fatalf("re-mark: %v", err)
	}
	if err := s.MarkScanned(ctx, "tenant-a", "sha256:bbb", now); err != nil {
		t.Fatalf("mark bbb: %v", err)
	}

	got, err := s.ScannedDigests(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 || !got["sha256:aaa"] || !got["sha256:bbb"] {
		t.Fatalf("expected {aaa,bbb}, got %v", got)
	}
}

func TestScannedImageStoreTenantIsolation(t *testing.T) {
	s := NewScannedImageStore()
	ctx := context.Background()
	_ = s.MarkScanned(ctx, "tenant-a", "sha256:aaa", time.Unix(0, 0))
	_ = s.MarkScanned(ctx, "tenant-b", "sha256:bbb", time.Unix(0, 0))

	a, _ := s.ScannedDigests(ctx, "tenant-a")
	if a["sha256:bbb"] {
		t.Fatalf("tenant-a must not see tenant-b's digest: %v", a)
	}
	b, _ := s.ScannedDigests(ctx, "tenant-b")
	if b["sha256:aaa"] {
		t.Fatalf("tenant-b must not see tenant-a's digest: %v", b)
	}
}

func TestScannedImageStoreEmptyTenantNormalizesToDefault(t *testing.T) {
	// An empty tenant (single-tenant engagement) and the fleet "default" tenant must land in the same
	// partition so an image scan and the agent that observes it correlate.
	s := NewScannedImageStore()
	ctx := context.Background()
	_ = s.MarkScanned(ctx, "", "sha256:aaa", time.Unix(0, 0)) // recorded by a single-tenant image scan

	got, _ := s.ScannedDigests(ctx, "default") // queried by the fleet "default" agent
	if !got["sha256:aaa"] {
		t.Fatalf("empty tenant and 'default' must share a partition, got %v", got)
	}
	// And the reverse direction.
	_ = s.MarkScanned(ctx, "default", "sha256:bbb", time.Unix(0, 0))
	got2, _ := s.ScannedDigests(ctx, "")
	if !got2["sha256:bbb"] {
		t.Fatalf("'default' and empty tenant must share a partition, got %v", got2)
	}
}
