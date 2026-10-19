package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTicketGroupFactsUseStoredAttributionAndIsolateScope(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "facts-tenant")
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	engs, findings := NewEngagementRepository(), NewFindingRepository()
	eng, err := engagement.New("facts-eng", "facts-tenant", "Facts", "Test", now)
	if err != nil {
		t.Fatal(err)
	}
	eng.ProjectID = "facts-project"
	if err = engs.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	for _, id := range []shared.ID{"facts-one", "facts-two"} {
		engagementID := eng.ID
		f, err := finding.NewManual(id, engagementID, finding.ManualInput{Title: "prose-host.example must not imply attribution", Severity: shared.SeverityHigh}, now)
		if err != nil {
			t.Fatal(err)
		}
		f.AdvisoryID = "CVE-2026-12345"
		if err = findings.Upsert(ctx, []finding.Finding{f}); err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewTicketStore(engs, findings)
	if err != nil {
		t.Fatal(err)
	}
	mapping := ticketing.Mapping{ID: "facts-map", TenantID: "facts-tenant", IntegrationID: "facts-integration", Scope: ticketing.Project, ScopeID: eng.ProjectID, ProjectKey: "SEC", IssueType: "10001", DataClass: notification.DataClassDetail, GroupingMode: ticketing.GroupingVulnerabilityProject, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err = store.CreateMapping(ctx, "facts-tenant", mapping); err != nil {
		t.Fatal(err)
	}
	group := ports.TicketGroup{ID: "facts-group", MappingID: mapping.ID, ProjectID: eng.ProjectID, Vulnerability: "CVE-2026-12345"}
	store.groups["facts-tenant"] = map[string]ports.TicketGroup{ticketGroupKey(group): group}
	member := ports.TicketGroupMember{EngagementID: eng.ID, FindingID: "facts-one"}
	store.groupMembers["facts-tenant"] = map[shared.ID]map[string]ports.TicketGroupMember{group.ID: {ticketGroupMemberKey(member): member}}
	assets, bindings := NewAssetStore(), NewAttackPathStore()
	a, err := asset.New("facts-asset", "facts-tenant", asset.KindHost, "stored.example", "Stored asset", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = assets.UpsertAsset(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err = bindings.ReplaceBindings(ctx, "facts-tenant", eng.ID, "facts-producer", []attackpath.Binding{{TenantID: "facts-tenant", EngagementID: eng.ID, AssetID: a.ID, FindingID: member.FindingID, TargetKind: attackpath.TargetCanonical, Producer: "facts-producer", Provenance: "facts-provenance", Confidence: asset.EdgeObserved}}); err != nil {
		t.Fatal(err)
	}
	if err = bindings.ReplaceBindings(ctx, "facts-tenant", eng.ID, "inferred-producer", []attackpath.Binding{{TenantID: "facts-tenant", EngagementID: eng.ID, AssetID: a.ID, FindingID: "facts-two", TargetKind: attackpath.TargetCanonical, Producer: "inferred-producer", Provenance: "inferred-provenance", Confidence: asset.EdgeInferred}}); err != nil {
		t.Fatal(err)
	}
	store.SetGroupAssetSources(assets, bindings)
	candidate := ports.TicketGroupMember{EngagementID: eng.ID, FindingID: "facts-two"}
	facts, err := store.GroupTicketFacts(ctx, "facts-tenant", mapping.ID, eng.ProjectID, group.Vulnerability, candidate)
	if err != nil || len(facts) != 2 {
		t.Fatalf("facts=%+v err=%v", facts, err)
	}
	if facts[0].Title == "" || facts[0].Severity != shared.SeverityHigh || facts[0].Status != finding.StatusOpen {
		t.Fatalf("stored facts missing: %+v", facts)
	}
	if facts[0].AssetID != a.ID || facts[0].AssetName != "Stored asset" || facts[1].AssetID != "" || facts[1].AssetName != "" {
		t.Fatalf("attribution was inferred or lost: %+v", facts)
	}
	if _, err = store.GroupTicketFacts(ctx, "other", mapping.ID, eng.ProjectID, group.Vulnerability, candidate); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant facts: %v", err)
	}
	if _, err = store.GroupTicketFacts(ctx, "facts-tenant", mapping.ID, "other-project", group.Vulnerability, candidate); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-project facts: %v", err)
	}
	if _, err = store.GroupTicketFacts(ctx, "facts-tenant", mapping.ID, eng.ProjectID, "CVE-2026-99999", candidate); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("cross-vulnerability facts: %v", err)
	}
}
