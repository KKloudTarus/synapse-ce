package docpublish

import (
	"context"
	"errors"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type identityCheckingRestrictionProvider struct {
	*releaseProvider
	reads, proofs int
}

func (p *identityCheckingRestrictionProvider) GetDocument(context.Context, string) (ports.DocumentRemoteState, error) {
	p.reads++
	return ports.DocumentRemoteState{}, errors.New("monitor must use the combined identity and ACL proof")
}
func (p *identityCheckingRestrictionProvider) VerifyDocumentRestriction(ctx context.Context, page, container, group string) error {
	p.proofs++
	if page != p.page.ID || container != p.page.Container {
		return &ports.DocumentProviderError{Code: "restriction_unverified"}
	}
	return p.releaseProvider.VerifyDocumentRestriction(ctx, page, container, group)
}
func TestRestrictionMonitorUsesOneIdentityAndACLProof(t *testing.T) {
	for _, changed := range []bool{false, true} {
		f := newReleaseFixture(t)
		intent := f.publish(t)
		f.executeUntilNotPending(t, intent.ID)
		provider := &identityCheckingRestrictionProvider{releaseProvider: f.provider}
		if changed {
			provider.page.Container = "foreign-container"
		}
		f.service.providers = restrictionMonitorProviders{provider}
		f.clock.at = f.clock.at.Add(16 * time.Minute)
		if err := f.service.Tick(context.Background(), "tenant", 5); err != nil {
			t.Fatal(err)
		}
		if provider.reads != 0 || provider.proofs != 1 {
			t.Fatalf("duplicate provider proof: reads=%d proofs=%d", provider.reads, provider.proofs)
		}
		links, err := f.service.Links(context.Background(), "tenant", domain.Engagement, "assessment")
		if err != nil || len(links) != 1 {
			t.Fatalf("links=%d err=%v", len(links), err)
		}
		want := "verified"
		if changed {
			want = "restriction_lost"
		}
		if links[0].RestrictionStatus != want {
			t.Fatalf("identity proof status=%s want %s", links[0].RestrictionStatus, want)
		}
	}
}
