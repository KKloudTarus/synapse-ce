// Package advisoryingest loads the owned normalized-advisory store from a bulk feed. It is the
// POPULATION half of the owned-advisory vertical: the store (ports.AdvisoryStore) + matcher
// (internal/domain/advisory) + owned DetectionSource (ownadvisory) are all live, but the corpus is empty
// until this ingester runs a feed (a local OSV dump today; a remote OSV/GHSA bulk snapshot later) into the
// store. It is feed- and store-agnostic: pure orchestration over ports.AdvisoryFeed + ports.AdvisoryWriter,
// no infrastructure import. Ingesting reference data is an ops action and is intentionally NOT audited
// (parity with the NVD/KEV/EPSS sync) – the audited, hash-chained ledger is evidence/findings.
package advisoryingest

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Stats reports the outcome of one ingest run. Skipped (unparseable/oversized source entries the feed
// dropped) is surfaced so a partial sync is visible rather than reading as a complete corpus.
type Stats struct {
	Ingested int // advisories successfully upserted into the store
	Skipped  int // source entries the feed could not parse and dropped
}

// Service ingests a bulk advisory feed into the owned store.
type Service struct {
	feed   ports.AdvisoryFeed
	writer ports.AdvisoryWriter
}

// NewService validates its dependencies and returns the ingester.
func NewService(feed ports.AdvisoryFeed, writer ports.AdvisoryWriter) (*Service, error) {
	if feed == nil {
		return nil, fmt.Errorf("%w: advisory feed is nil", shared.ErrValidation)
	}
	if writer == nil {
		return nil, fmt.Errorf("%w: advisory writer is nil", shared.ErrValidation)
	}
	return &Service{feed: feed, writer: writer}, nil
}

// Ingest streams the feed into the store, upserting each advisory. A store write failure is FATAL (it aborts
// the run and is returned with the partial Stats) – a half-loaded corpus that silently swallowed write
// errors would under-report vulnerabilities. Unparseable source entries are skipped by the feed and counted
// in Stats.Skipped (best-effort bulk ingest). The run honors ctx cancellation via the feed.
func (s *Service) Ingest(ctx context.Context) (Stats, error) {
	var st Stats
	skipped, err := s.feed.Each(ctx, func(a advisory.Advisory) error {
		if a.ID == "" {
			// A feed should not yield an id-less advisory; if it does, treat it as a skip rather than a fatal
			// write error (the store would reject it anyway). Defense-in-depth.
			st.Skipped++
			return nil
		}
		if uerr := s.writer.Upsert(ctx, a); uerr != nil {
			return fmt.Errorf("upsert advisory %s: %w", a.ID, uerr)
		}
		st.Ingested++
		return nil
	})
	st.Skipped += skipped
	if err != nil {
		return st, fmt.Errorf("ingest advisory feed: %w", err)
	}
	return st, nil
}
