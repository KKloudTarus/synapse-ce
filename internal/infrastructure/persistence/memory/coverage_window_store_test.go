package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func testCoverageWindow(at time.Time) sensorstate.CoverageWindow {
	window := sensorstate.CoverageWindow{
		AssetID: "asset-1", AgentID: "agent-1", HostID: "host-1", Since: at, Until: at.Add(time.Hour),
		InputDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CreatedAt:   at.Add(2 * time.Hour),
		States: []detection.ClassCoverage{{
			Class: detection.ClassProcess, HostID: "host-1", AgentID: "agent-1", State: detection.StateActive, Since: at,
		}},
	}
	window.Vector = sensorstate.BuildCoverageVector(window)
	window.Revision = sensorstate.RevisionFor(window)
	return window
}

func coverageTenant(id shared.ID) context.Context {
	return shared.WithTenant(context.Background(), id)
}

func TestCoverageWindowStoreIsAppendOnlyIdempotentAndTenantScoped(t *testing.T) {
	store := NewCoverageWindowStore()
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	window := testCoverageWindow(at)
	window.CreatedAt = window.CreatedAt.Add(789 * time.Nanosecond)
	first, err := store.AppendCoverageWindow(coverageTenant("tenant-a"), window)
	if err != nil {
		t.Fatalf("AppendCoverageWindow() error = %v", err)
	}
	if first.CreatedAt.Nanosecond()%int(time.Microsecond) != 0 {
		t.Fatalf("CreatedAt = %s, want PostgreSQL-compatible microsecond precision", first.CreatedAt)
	}

	retry := window
	retry.CreatedAt = retry.CreatedAt.Add(time.Hour)
	got, err := store.AppendCoverageWindow(coverageTenant("tenant-a"), retry)
	if err != nil {
		t.Fatalf("retry AppendCoverageWindow() error = %v", err)
	}
	if !got.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("retry CreatedAt = %s, want first %s", got.CreatedAt, first.CreatedAt)
	}

	got.States[0].State = detection.StateFailed
	got.Vector.Reasons = append(got.Vector.Reasons, "mutated")
	listed, err := store.ListCoverageWindows(coverageTenant("tenant-a"), ports.CoverageWindowQuery{})
	if err != nil {
		t.Fatalf("ListCoverageWindows() error = %v", err)
	}
	if len(listed) != 1 || listed[0].States[0].State != detection.StateActive || len(listed[0].Vector.Reasons) != len(first.Vector.Reasons) {
		t.Fatalf("stored window was mutated through returned slices: %#v", listed)
	}
	other, err := store.ListCoverageWindows(coverageTenant("tenant-b"), ports.CoverageWindowQuery{})
	if err != nil {
		t.Fatalf("other tenant ListCoverageWindows() error = %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("other tenant saw %d windows", len(other))
	}
}

func TestCoverageWindowStoreRejectsRevisionCollision(t *testing.T) {
	store := NewCoverageWindowStore()
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	window := testCoverageWindow(at)
	if _, err := store.AppendCoverageWindow(coverageTenant("tenant-a"), window); err != nil {
		t.Fatalf("AppendCoverageWindow() error = %v", err)
	}

	// Corrupt the stored row to exercise the fail-closed collision guard. A valid
	// caller cannot construct two different immutable facts with one valid revision.
	store.rows["tenant-a"][window.Revision] = sensorstate.CoverageWindow{
		AssetID: "other-asset", Revision: window.Revision, CreatedAt: window.CreatedAt,
	}
	_, err := store.AppendCoverageWindow(coverageTenant("tenant-a"), window)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("collision error = %v, want conflict", err)
	}
}

func TestCoverageWindowStoreRejectsStaleRevisionAfterClassIdentityChange(t *testing.T) {
	store := NewCoverageWindowStore()
	ctx := coverageTenant("tenant-a")
	window := testCoverageWindow(time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC))
	if _, err := store.AppendCoverageWindow(ctx, window); err != nil {
		t.Fatalf("AppendCoverageWindow() error = %v", err)
	}
	changed := window
	changed.States = append([]detection.ClassCoverage(nil), window.States...)
	changed.States[0].AgentID = ""
	if _, err := store.AppendCoverageWindow(ctx, changed); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("stale class identity revision error = %v, want validation", err)
	}
}

func TestCoverageWindowStoreRejectsNoncanonicalRevisionTimestamps(t *testing.T) {
	store := NewCoverageWindowStore()
	window := testCoverageWindow(time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC))
	window.Since = window.Since.Add(time.Nanosecond)
	window.Vector = sensorstate.BuildCoverageVector(window)
	window.Revision = sensorstate.RevisionFor(window)
	if _, err := store.AppendCoverageWindow(coverageTenant("tenant-a"), window); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("AppendCoverageWindow() error = %v, want validation", err)
	}
}

func TestCoverageWindowStoreUsesHalfOpenOverlapAndLimit(t *testing.T) {
	store := NewCoverageWindowStore()
	ctx := coverageTenant("tenant-a")
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	for _, window := range []sensorstate.CoverageWindow{
		testCoverageWindow(at),
		testCoverageWindow(at.Add(time.Hour)),
	} {
		if _, err := store.AppendCoverageWindow(ctx, window); err != nil {
			t.Fatalf("AppendCoverageWindow() error = %v", err)
		}
	}
	windows, err := store.ListCoverageWindows(ctx, ports.CoverageWindowQuery{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1",
		Since: at.Add(time.Hour), Until: at.Add(2 * time.Hour), Limit: 1,
	})
	if err != nil {
		t.Fatalf("ListCoverageWindows() error = %v", err)
	}
	if len(windows) != 1 || !windows[0].Since.Equal(at.Add(time.Hour)) {
		t.Fatalf("windows = %#v, want only window starting at Since", windows)
	}
}

func TestCoverageWindowStoreUsesSharedLimitPolicy(t *testing.T) {
	store := NewCoverageWindowStore()
	ctx := coverageTenant("tenant-a")
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	for i := 0; i <= ports.DefaultCoverageWindowLimit; i++ {
		window := testCoverageWindow(at.Add(time.Duration(i) * time.Hour))
		if _, err := store.AppendCoverageWindow(ctx, window); err != nil {
			t.Fatalf("AppendCoverageWindow() error = %v", err)
		}
	}

	windows, err := store.ListCoverageWindows(ctx, ports.CoverageWindowQuery{})
	if err != nil {
		t.Fatalf("default ListCoverageWindows() error = %v", err)
	}
	if len(windows) != ports.DefaultCoverageWindowLimit {
		t.Fatalf("default rows = %d, want %d", len(windows), ports.DefaultCoverageWindowLimit)
	}
	if _, err := store.ListCoverageWindows(ctx, ports.CoverageWindowQuery{
		Limit: ports.MaxCoverageWindowLimit + 1,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized ListCoverageWindows() error = %v, want validation", err)
	}
}
