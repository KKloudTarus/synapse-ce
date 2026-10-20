package docpublish

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type restrictionMonitorProviders struct{ provider ports.DocumentProvider }

func (p restrictionMonitorProviders) DocumentProvider(context.Context, integration.Integration) (ports.DocumentProvider, error) {
	return p.provider, nil
}

type deadlineAwareRestrictionProvider struct {
	*releaseProvider
	minimumBudget time.Duration
	observed      bool
}

func (p *deadlineAwareRestrictionProvider) VerifyDocumentRestriction(ctx context.Context, pageID, container, group string) error {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= p.minimumBudget {
		return context.DeadlineExceeded
	}
	p.observed = true
	return p.releaseProvider.VerifyDocumentRestriction(ctx, pageID, container, group)
}

type deadlineExhaustingRestrictionProvider struct{ *releaseProvider }

func (p *deadlineExhaustingRestrictionProvider) VerifyDocumentRestriction(ctx context.Context, _, _, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestDocumentTickDetectsRestrictionLossWithoutWritingRemoteContent(t *testing.T) {
	f := newReleaseFixture(t)
	ctx := context.Background()
	release, err := f.service.Publish(ctx, "tenant", f.actor, f.input)
	if err != nil {
		t.Fatal(err)
	}
	if result := f.executeUntilNotPending(t, release.Intent.ID); result.State != writeintent.Done {
		t.Fatalf("publication=%+v", result)
	}
	f.provider.restricted = false
	f.clock.at = f.clock.at.Add(16 * time.Minute)
	writes, uploads, shells, purges := f.provider.writes, f.provider.uploads, f.provider.shells, f.provider.purges
	if err = f.service.Tick(ctx, "tenant", 5); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range f.audit.entries {
		if entry.Action == "document.restriction_lost" {
			found = true
		}
		if strings.Contains(entry.Action, "restriction") && strings.Contains(strings.Join(mapValues(entry.Metadata), " "), "configured-token") {
			t.Fatal("provider material in audit")
		}
	}
	if !found {
		t.Fatal("post-publication restriction loss was not audited")
	}
	if f.provider.writes != writes || f.provider.uploads != uploads || f.provider.shells != shells || f.provider.purges != purges {
		t.Fatal("restriction monitor wrote remote content")
	}
	links, err := f.service.Links(ctx, "tenant", domain.Engagement, "assessment")
	if err != nil || len(links) != 1 {
		t.Fatalf("links=%d err=%v", len(links), err)
	}
	if links[0].RestrictionStatus != "restriction_lost" || links[0].RestrictionCheckedAt == nil {
		t.Fatalf("missing durable warning: %+v", links[0])
	}
	checks := f.provider.checks
	if err = f.service.Tick(ctx, "tenant", 5); err != nil {
		t.Fatal(err)
	}
	if f.provider.checks != checks {
		t.Fatal("monitor ignored retry interval")
	}
	f.provider.restricted = true
	f.clock.at = f.clock.at.Add(6 * time.Minute)
	if err = f.service.Tick(ctx, "tenant", 5); err != nil {
		t.Fatal(err)
	}
	links, _ = f.service.Links(ctx, "tenant", domain.Engagement, "assessment")
	if links[0].RestrictionStatus != "verified" {
		t.Fatalf("corrected provider sharing was not observed: %+v", links[0])
	}
}

func TestDocumentRestrictionClaimsFenceStaleWorkersAndRetiredTargets(t *testing.T) {
	f := newReleaseFixture(t)
	ctx := context.Background()
	intent := f.publish(t)
	if result := f.executeUntilNotPending(t, intent.ID); result.State != writeintent.Done {
		t.Fatalf("publication=%+v", result)
	}
	at := f.clock.at.Add(time.Minute)
	claims, err := f.store.ClaimDocumentRestrictionChecks(ctx, "tenant", 1, at)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim len=%d err=%v", len(claims), err)
	}
	if other, err := f.store.ClaimDocumentRestrictionChecks(ctx, "other", 1, at); err != nil || len(other) != 0 {
		t.Fatalf("foreign claim len=%d err=%v", len(other), err)
	}
	if _, err := f.store.ClaimDocumentRestrictionChecks(shared.WithTenant(ctx, "other"), "tenant", 1, at); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("mismatched tenant err=%v", err)
	}
	if next, err := f.store.ClaimDocumentRestrictionChecks(ctx, "tenant", 1, at); err != nil || len(next) != 0 {
		t.Fatalf("active claim returned again: %v", err)
	}
	newer, err := f.store.ClaimDocumentRestrictionChecks(ctx, "tenant", 1, at.Add(6*time.Minute))
	if err != nil || len(newer) != 1 {
		t.Fatalf("expired claim did not rotate: %v", err)
	}
	if err := f.store.SaveDocumentRestrictionCheck(ctx, "tenant", claims[0], "verified", at, at.Add(time.Hour)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale worker err=%v", err)
	}
	f.clock.at = at.Add(7 * time.Minute)
	purge, err := f.service.Unpublish(ctx, "tenant", f.actor, claims[0].ID, "purge-checked")
	if err != nil {
		t.Fatal(err)
	}
	if result := f.executeUntilNotPending(t, purge.Intent.ID); result.State != writeintent.Done {
		t.Fatalf("purge=%+v", result)
	}
	if err = f.store.SaveDocumentRestrictionCheck(ctx, "tenant", newer[0], "verified", f.clock.at, f.clock.at.Add(time.Hour)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("purged page accepted stale observation: %v", err)
	}
	if next, err := f.store.ClaimDocumentRestrictionChecks(ctx, "tenant", 1, at.Add(24*time.Hour)); err != nil || len(next) != 0 {
		t.Fatalf("retired page swept again: %v", err)
	}
}

func TestDocumentRestrictionMonitorDetectsConfigurationChange(t *testing.T) {
	f := newReleaseFixture(t)
	intent := f.publish(t)
	if result := f.executeUntilNotPending(t, intent.ID); result.State != writeintent.Done {
		t.Fatalf("publication=%+v", result)
	}
	f.provider.afterVerify = func() { f.integration.item.CredentialRevision++ }
	if err := f.service.Tick(context.Background(), "tenant", 1); err != nil {
		t.Fatal(err)
	}
	links, err := f.service.Links(context.Background(), "tenant", domain.Engagement, "assessment")
	if err != nil || len(links) != 1 || links[0].RestrictionStatus != "unverifiable" {
		t.Fatalf("stale configuration proof accepted: %+v %v", links, err)
	}
}

func TestDocumentRestrictionMonitorPersistsVerifiedProofBeyondFormerPerLinkBudget(t *testing.T) {
	f := newReleaseFixture(t)
	intent := f.publish(t)
	if result := f.executeUntilNotPending(t, intent.ID); result.State != writeintent.Done {
		t.Fatalf("publication=%+v", result)
	}
	provider := &deadlineAwareRestrictionProvider{releaseProvider: f.provider, minimumBudget: 2 * time.Second}
	f.service.providers = restrictionMonitorProviders{provider: provider}

	if err := f.service.Tick(context.Background(), "tenant", 1); err != nil {
		t.Fatal(err)
	}
	links, err := f.service.Links(context.Background(), "tenant", domain.Engagement, "assessment")
	if err != nil || len(links) != 1 || links[0].RestrictionStatus != "verified" {
		t.Fatalf("verified proof was not persisted: %+v %v", links, err)
	}
	if !provider.observed {
		t.Fatal("restriction proof did not receive time beyond the former two-second budget")
	}
}

func TestDocumentRestrictionMonitorLeavesSecondDueLinkUnclaimed(t *testing.T) {
	f := newReleaseFixture(t)
	first := f.publish(t)
	if result := f.executeUntilNotPending(t, first.ID); result.State != writeintent.Done {
		t.Fatalf("first publication=%+v", result)
	}
	secondInput := f.input
	secondInput.SourceRef = "assessment-second"
	secondInput.RequestKey = "publish-second"
	second, err := f.service.Publish(context.Background(), "tenant", f.actor, secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if result := f.executeUntilNotPending(t, second.Intent.ID); result.State != writeintent.Done {
		t.Fatalf("second publication=%+v", result)
	}

	if err = f.service.Tick(context.Background(), "tenant", 5); err != nil {
		t.Fatal(err)
	}
	links, err := f.service.Links(context.Background(), "tenant", domain.Engagement, "assessment")
	if err != nil || len(links) != 2 {
		t.Fatalf("links=%d err=%v", len(links), err)
	}
	var unchecked shared.ID
	for _, link := range links {
		switch link.RestrictionStatus {
		case "verified":
		case "unchecked":
			unchecked = link.ID
		default:
			t.Fatalf("unexpected restriction status: %+v", link)
		}
	}
	if unchecked.IsZero() {
		t.Fatal("second due link was claimed during the same tenant pass")
	}
	claims, err := f.store.ClaimDocumentRestrictionChecks(context.Background(), "tenant", 1, f.clock.at)
	if err != nil || len(claims) != 1 || claims[0].ID != unchecked {
		t.Fatalf("next due claim = %+v, want %s; err=%v", claims, unchecked, err)
	}
}

func TestDocumentRestrictionMonitorReservesPassHeadroomForCheckpoint(t *testing.T) {
	f := newReleaseFixture(t)
	intent := f.publish(t)
	if result := f.executeUntilNotPending(t, intent.ID); result.State != writeintent.Done {
		t.Fatalf("publication=%+v", result)
	}
	f.service.providers = restrictionMonitorProviders{provider: &deadlineExhaustingRestrictionProvider{releaseProvider: f.provider}}

	if err := f.service.checkRestrictionsWithBudget(context.Background(), "tenant", 1, 200*time.Millisecond, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	links, err := f.service.Links(context.Background(), "tenant", domain.Engagement, "assessment")
	if err != nil || len(links) != 1 || links[0].RestrictionStatus != "unverifiable" || links[0].RestrictionCheckedAt == nil {
		t.Fatalf("checkpoint was not saved after an exhausted observation: %+v %v", links, err)
	}
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
