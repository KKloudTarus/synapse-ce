package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/accuracy"
)

func TestAccuracyRunStoreRecentOrdersAndLimits(t *testing.T) {
	s := NewAccuracyRunStore()
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Save out of order; Recent must return newest first.
	for i, off := range []int{0, 2, 1} {
		run, err := accuracy.New("run-"+string(rune('a'+i)), base.Add(time.Duration(off)*time.Hour), "v1", "s1", 9, accuracy.Metrics{Precision: 1}, nil)
		if err != nil {
			t.Fatalf("new run: %v", err)
		}
		if err := s.Save(ctx, *run); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	got, err := s.Recent(ctx, 0)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d runs, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].RanAt.Before(got[i].RanAt) {
			t.Errorf("runs not newest-first: %v before %v", got[i-1].RanAt, got[i].RanAt)
		}
	}
	// Limit caps the result.
	limited, err := s.Recent(ctx, 2)
	if err != nil {
		t.Fatalf("recent limit: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("limit 2 returned %d runs", len(limited))
	}
	if !limited[0].RanAt.Equal(base.Add(2 * time.Hour)) {
		t.Errorf("newest run = %v, want %v", limited[0].RanAt, base.Add(2*time.Hour))
	}
}
