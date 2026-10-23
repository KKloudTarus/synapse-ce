package docpublish

import (
	"context"
	"errors"
	"fmt"
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
		return &ports.DocumentProviderError{Code: "wrong_container", RestrictionLost: true}
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

type classifiedRestrictionProvider struct {
	*releaseProvider
	failure error
}

func (p *classifiedRestrictionProvider) VerifyDocumentRestriction(context.Context, string, string, string) error {
	return p.failure
}

func TestRestrictionMonitorClassifiesObservedLossWithoutProviderCodeAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name, code      string
		lost, ambiguous bool
		want            string
	}{
		{"confluence_acl", "restriction_unverified", true, false, "restriction_lost"},
		{"confluence_public_protection", "public_sharing_unverifiable", true, false, "restriction_lost"},
		{"native_acl", "restricted_sharing_unverified", true, false, "restriction_lost"},
		{"moved_confluence_page", "wrong_container", true, false, "restriction_lost"},
		{"changed_native_identity", "remote_identity_changed", true, false, "restriction_lost"},
		{"incomplete_permissions", "incomplete_permissions", false, false, "unverifiable"},
		{"incomplete_acl", "complete_acl_unverifiable", false, false, "unverifiable"},
		{"transport", "network", false, false, "unverifiable"},
		{"credentials", "permission_denied", false, false, "unverifiable"},
		{"configuration", "invalid_restriction", false, false, "unverifiable"},
		{"code_without_evidence", "restriction_unverified", false, false, "unverifiable"},
		{"ambiguous_evidence", "restriction_unverified", true, true, "unverifiable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReleaseFixture(t)
			intent := f.publish(t)
			f.executeUntilNotPending(t, intent.ID)
			links, err := f.service.Links(context.Background(), "tenant", domain.Engagement, "assessment")
			if err != nil || len(links) != 1 {
				t.Fatalf("links=%v err=%v", links, err)
			}
			failure := &ports.DocumentProviderError{Code: tc.code, RestrictionLost: tc.lost, Ambiguous: tc.ambiguous}
			f.service.providers = restrictionMonitorProviders{&classifiedRestrictionProvider{releaseProvider: f.provider, failure: fmt.Errorf("proof: %w", failure)}}
			if got, _ := f.service.observeRestriction(context.Background(), "tenant", links[0]); got != tc.want {
				t.Fatalf("status=%s want=%s code=%s", got, tc.want, tc.code)
			}
		})
	}
}

func TestRestrictionMonitorHonorsProviderRetryAfter(t *testing.T) {
	f := newReleaseFixture(t)
	intent := f.publish(t)
	f.executeUntilNotPending(t, intent.ID)
	f.service.providers = restrictionMonitorProviders{&classifiedRestrictionProvider{releaseProvider: f.provider, failure: &ports.DocumentProviderError{Code: "rate_limited", Status: 429, RetryAfter: 2 * time.Hour}}}
	f.clock.at = f.clock.at.Add(16 * time.Minute)
	observedAt := f.clock.at
	if err := f.service.checkRestrictions(context.Background(), "tenant", 1); err != nil {
		t.Fatal(err)
	}
	links, err := f.service.Links(context.Background(), "tenant", domain.Engagement, "assessment")
	if err != nil || len(links) != 1 {
		t.Fatalf("links=%v err=%v", links, err)
	}
	if links[0].RestrictionStatus != "unverifiable" || !links[0].RestrictionNextAt.Equal(observedAt.Add(2*time.Hour)) {
		t.Fatalf("throttle checkpoint=%+v", links[0])
	}
}
