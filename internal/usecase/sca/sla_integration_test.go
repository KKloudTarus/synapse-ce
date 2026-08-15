package sca

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/slauc"
)

type slaPipelineClock struct{ at time.Time }

func (clock slaPipelineClock) Now() time.Time { return clock.at }

type slaPipelineIDs struct{}

func (slaPipelineIDs) NewID() shared.ID { return "sla-event" }

type selectiveSLAAssessor struct{ fail shared.ID }

func (assessor selectiveSLAAssessor) AssessFinding(_ context.Context, tenantID shared.ID, item finding.Finding) (sla.View, error) {
	if item.ID == assessor.fail {
		return sla.View{}, errors.New("governance unavailable")
	}
	return sla.View{Assessment: sla.Assessment{TenantID: tenantID, FindingID: item.ID}}, nil
}

func TestAssessFindingSLAsUsesPersistedFindingOrderAndTenant(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	store := memory.NewSLAStore()
	governance, err := slauc.NewService(store, slaPipelineClock{at: now}, slaPipelineIDs{})
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{slaAssessor: governance}
	result := &ScanResult{Findings: []finding.Finding{
		{
			ID: "finding-critical", EngagementID: "eng-1", Kind: finding.KindSCA,
			Severity: shared.SeverityCritical, DedupKey: "vuln:CVE-2026-1:pkg:1.0.0",
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", KEV: true,
			RiskScore: 8.82, FixedVersion: "1.0.1",
		},
		{
			ID: "finding-unfixed", EngagementID: "eng-1", Kind: finding.KindSCA,
			Severity: shared.SeverityMedium, DedupKey: "vuln:CVE-2026-2:pkg:2.0.0",
		},
	}}
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	if err := service.assessFindingSLAs(ctx, result); err != nil {
		t.Fatal(err)
	}
	if len(result.SLAs) != 2 {
		t.Fatalf("SLA count=%d, want 2", len(result.SLAs))
	}
	if result.SLAs[0].Assessment.FindingID != "finding-critical" || result.SLAs[1].Assessment.FindingID != "finding-unfixed" {
		t.Fatalf("SLA order does not match persisted findings: %+v", result.SLAs)
	}
	if result.SLAs[0].Assessment.TenantID != "tenant-a" || math.Abs(result.SLAs[0].Assessment.Inputs.EPSS-0.9) > 1e-9 {
		t.Fatalf("critical SLA lost tenant/risk input: %+v", result.SLAs[0].Assessment)
	}
	if result.SLAs[1].Assessment.Result.Tier != sla.TierException {
		t.Fatalf("unfixed vulnerability tier=%s, want exception", result.SLAs[1].Assessment.Result.Tier)
	}
	for _, item := range result.SLAs {
		current, err := store.Current(ctx, "tenant-a", "eng-1", item.Assessment.FindingID)
		if err != nil {
			t.Fatalf("current SLA %s: %v", item.Assessment.FindingID, err)
		}
		if current.Assessment.ID != item.Assessment.ID || current.Lifecycle.Status != sla.RemediationOpen {
			t.Fatalf("scan result differs from durable current: %+v vs %+v", item, current)
		}
	}
}

func TestAssessFindingSLAsFailsClosedWithoutTenantContext(t *testing.T) {
	governance, err := slauc.NewService(memory.NewSLAStore(), slaPipelineClock{at: time.Now().UTC()}, slaPipelineIDs{})
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{slaAssessor: governance}
	result := &ScanResult{Findings: []finding.Finding{{ID: "finding-1", EngagementID: "eng-1"}}}
	if err := service.assessFindingSLAs(context.Background(), result); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant error=%v, want validation", err)
	}
}

func TestAssessFindingSLAsRetainsPartialEnrichment(t *testing.T) {
	service := &Service{slaAssessor: selectiveSLAAssessor{fail: "finding-2"}}
	result := &ScanResult{Findings: []finding.Finding{
		{ID: "finding-1"}, {ID: "finding-2"}, {ID: "finding-3"},
	}}
	err := service.assessFindingSLAs(shared.WithTenant(context.Background(), "tenant-a"), result)
	if err == nil || !strings.Contains(err.Error(), "finding-2") {
		t.Fatalf("aggregate enrichment error=%v, want failed finding identity", err)
	}
	if len(result.SLAs) != 2 || result.SLAs[0].Assessment.FindingID != "finding-1" ||
		result.SLAs[1].Assessment.FindingID != "finding-3" {
		t.Fatalf("successful SLA enrichments were not retained in order: %+v", result.SLAs)
	}
}
