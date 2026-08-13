package ownadvisory

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilitysource"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// FeedProvider adapts the existing bounded AdvisoryFeed parsers to the continuous
// observation contract. Parser hardening remains in the feed; the monitor owns
// batching, persistence, and checkpoint advancement.
type FeedProvider struct {
	typeName string
	sourceID shared.ID
	feed     ports.AdvisoryFeed
}

// NewRemoteProvider builds the reviewed OSV bulk adapter for one source row.
// The source endpoint is captured in this instance; no source configuration is
// read from a sync request payload.
func NewRemoteProvider(source vulnerabilitysource.Source) (*FeedProvider, error) {
	if source.AdapterType != vulnerabilitysource.AdapterOSV {
		return nil, fmt.Errorf("%w: remote advisory provider does not support %q", shared.ErrValidation, source.AdapterType)
	}
	return NewFeedProvider(string(source.AdapterType), source.ID, NewRemoteFeed(source.Endpoint, source.StringListOption("ecosystems"), safehttp.New(10*time.Minute, source.AllowPrivateNetwork())))
}

func NewFeedProvider(typeName string, sourceID shared.ID, feed ports.AdvisoryFeed) (*FeedProvider, error) {
	if strings.TrimSpace(typeName) == "" || sourceID.IsZero() || feed == nil {
		return nil, fmt.Errorf("%w: invalid advisory feed provider", shared.ErrValidation)
	}
	return &FeedProvider{typeName: strings.ToLower(strings.TrimSpace(typeName)), sourceID: sourceID, feed: feed}, nil
}

var _ ports.VulnerabilityIntelligenceProvider = (*FeedProvider)(nil)

func (p *FeedProvider) Type() string { return p.typeName }

func (p *FeedProvider) Test(ctx context.Context) error {
	tester, ok := p.feed.(interface{ Test(context.Context) error })
	if !ok {
		return fmt.Errorf("%w: provider does not support connection tests", shared.ErrValidation)
	}
	return tester.Test(ctx)
}

func (p *FeedProvider) Fetch(ctx context.Context, _ []byte, emit func(advisory.ObservationRecord) error) ([]byte, ports.ProviderStats, error) {
	var emitted int64
	skipped, err := p.feed.Each(ctx, func(value advisory.Advisory) error {
		if strings.TrimSpace(value.ID) == "" {
			return nil
		}
		record := advisory.ObservationRecord{Observation: advisory.Observation{
			SourceType: p.typeName,
			SourceID:   p.sourceID.String(),
			RecordID:   value.ID,
			Status:     advisory.StatusActive,
			Advisory:   value,
		}}
		if err := emit(record); err != nil {
			return err
		}
		emitted++
		return nil
	})
	stats := ports.ProviderStats{Processed: emitted + int64(skipped), Skipped: int64(skipped)}
	if err != nil {
		return nil, stats, err
	}
	return []byte(`{"complete":true}`), stats, nil
}
