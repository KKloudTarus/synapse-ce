package ownadvisory

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type providerFeed struct {
	advisories []advisory.Advisory
	skipped    int
	err        error
}

func (f providerFeed) Each(_ context.Context, emit func(advisory.Advisory) error) (int, error) {
	for _, value := range f.advisories {
		if err := emit(value); err != nil {
			return f.skipped, err
		}
	}
	return f.skipped, f.err
}

func TestFeedProviderEmitsNormalizedObservationRecords(t *testing.T) {
	provider, err := NewFeedProvider("OSV", "source-1", providerFeed{advisories: []advisory.Advisory{{ID: "CVE-2026-1", Summary: "summary"}}, skipped: 2})
	if err != nil {
		t.Fatal(err)
	}
	var records []advisory.ObservationRecord
	checkpoint, stats, err := provider.Fetch(context.Background(), nil, func(record advisory.ObservationRecord) error {
		records = append(records, record)
		return nil
	})
	if err != nil || string(checkpoint) != `{"complete":true}` || stats.Processed != 3 || stats.Skipped != 2 {
		t.Fatalf("checkpoint=%s stats=%+v err=%v", checkpoint, stats, err)
	}
	if len(records) != 1 || records[0].Observation.SourceType != "osv" || records[0].Observation.SourceID != "source-1" || records[0].Observation.RecordID != "CVE-2026-1" {
		t.Fatalf("records=%+v", records)
	}
}

func TestFeedProviderPropagatesEmitAndFeedErrors(t *testing.T) {
	errEmit := errors.New("stop")
	provider, _ := NewFeedProvider("osv", shared.ID("source-1"), providerFeed{advisories: []advisory.Advisory{{ID: "CVE-1"}}})
	if _, _, err := provider.Fetch(context.Background(), nil, func(advisory.ObservationRecord) error { return errEmit }); !errors.Is(err, errEmit) {
		t.Fatalf("emit error=%v", err)
	}
	errFeed := errors.New("feed failed")
	provider, _ = NewFeedProvider("osv", "source-1", providerFeed{err: errFeed})
	if _, _, err := provider.Fetch(context.Background(), nil, func(advisory.ObservationRecord) error { return nil }); !errors.Is(err, errFeed) {
		t.Fatalf("feed error=%v", err)
	}
}
