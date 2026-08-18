package postgres

import (
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTelemetryGapsCalculation(t *testing.T) {
	input := map[telemetryKey][]uint64{
		{host: "host-1", class: detection.ClassProcess}: {1, 2, 5, 8, 8, 2}, // duplicates & out of order: 1, 2, 5, 8 -> gaps: 2..5 (missing 2), 5..8 (missing 2)
		{host: "host-2", class: detection.ClassNetwork}: {10, 11, 12},       // contiguous -> no gaps
		{host: "host-3", class: detection.ClassFile}:    {1, 4},              // gap: 1..4 (missing 2)
	}

	gaps := telemetryGaps(input)

	// Verify all expected gaps are discovered
	expected := []ports.TelemetrySequenceGap{
		{HostID: "host-1", Class: detection.ClassProcess, Missing: 2, LastSeen: 2, Incoming: 5},
		{HostID: "host-3", Class: detection.ClassFile, Missing: 2, LastSeen: 1, Incoming: 4},
		{HostID: "host-1", Class: detection.ClassProcess, Missing: 2, LastSeen: 5, Incoming: 8},
	}

	// Gaps should be sorted by LastSeen
	for i := 1; i < len(gaps); i++ {
		if gaps[i].LastSeen < gaps[i-1].LastSeen {
			t.Errorf("gaps not sorted by LastSeen: at %d got %d < %d", i, gaps[i].LastSeen, gaps[i-1].LastSeen)
		}
	}

	// Check total gap count
	if len(gaps) != len(expected) {
		t.Fatalf("got %d gaps, want %d: %+v", len(gaps), len(expected), gaps)
	}

	// Check contiguous stream has no gap
	for _, g := range gaps {
		if g.HostID == "host-2" {
			t.Errorf("host-2 has contiguous sequences, should have no gaps: %+v", g)
		}
	}
}

func TestDedupSorted(t *testing.T) {
	cases := []struct {
		name string
		in   []uint64
		want []uint64
	}{
		{"empty", nil, nil},
		{"single", []uint64{5}, []uint64{5}},
		{"already sorted no dups", []uint64{1, 2, 3}, []uint64{1, 2, 3}},
		{"duplicates and unordered", []uint64{4, 2, 4, 1, 2, 3}, []uint64{1, 2, 3, 4}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dedupSorted(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("dedupSorted(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestTelemetryKeyDistinctClassSameHost(t *testing.T) {
	// Distinct classes on the same host must be isolated in different map buckets
	k1 := telemetryKey{host: shared.ID("host-a"), class: detection.ClassProcess}
	k2 := telemetryKey{host: shared.ID("host-a"), class: detection.ClassNetwork}
	if k1 == k2 {
		t.Fatalf("keys with different classes on same host must not equal")
	}

	m := map[telemetryKey][]uint64{
		k1: {1, 2, 3},
		k2: {1, 4},
	}
	gaps := telemetryGaps(m)
	if len(gaps) != 1 {
		t.Fatalf("expected exactly 1 gap from k2, got %d: %+v", len(gaps), gaps)
	}
	if gaps[0].HostID != "host-a" || gaps[0].Class != detection.ClassNetwork || gaps[0].Missing != 2 {
		t.Errorf("unexpected gap: %+v", gaps[0])
	}
}
