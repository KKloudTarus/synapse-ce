package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	cmp "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

// Run explicitly against disposable PostgreSQL with SYNAPSE_ASSESSMENT_SCALE_TEST=1.
// Setup uses COPY for validated synthetic artifacts; measurements exercise the
// real comparison service and repositories, not a domain-only benchmark.
func TestPostgresAssessmentComparisonScale100K(t *testing.T) {
	if os.Getenv("SYNAPSE_ASSESSMENT_SCALE_TEST") != "1" {
		t.Skip("opt-in 100k PostgreSQL validation")
	}
	ctx, pool := setupTestDB(t)
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	const count = 100_000
	tenantID := shared.ID("assessment-scale")
	cycleID, baseline, current := createAssessmentComparisonSnapshots(t, ctx, pool, tenantID, "scale")
	now := time.Now().UTC().Truncate(time.Microsecond)
	identities := make([]findinglineage.Identity, count)
	for index := range identities {
		identity, observation := postgresFindingLineagePair(t, tenantID, cycleID, baseline.ID,
			fmt.Sprintf("identity-%06d", index), fmt.Sprintf("observation-%06d", index), fmt.Sprintf("finding-%06d", index), fmt.Sprintf("CVE-2026-%06d", index), now)
		if err := identity.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := observation.Validate(); err != nil {
			t.Fatal(err)
		}
		identities[index] = identity
	}
	columns := func(value string) []string {
		result := strings.Split(value, ",")
		for index := range result {
			result[index] = strings.TrimSpace(result[index])
		}
		return result
	}
	seedAt := time.Now()
	err := WithTenant(ctx, pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"finding_identities"}, columns(findingIdentityColumns), pgx.CopyFromSlice(count, func(index int) ([]any, error) {
			value := identities[index]
			return []any{value.TenantID.String(), value.CycleID.String(), value.ID.String(), value.ProducerKind, value.FindingKind, value.CanonicalizationVersion, value.FingerprintSchemaVersion, value.LineageFingerprint, value.TargetIdentitySchemaVersion, value.TargetIdentityCanonical, value.CanonicalIdentityFields, value.FirstSeenSnapshotID.String(), value.CreatedAt}, nil
		})); err != nil {
			return err
		}
		for _, snapshotID := range []shared.ID{baseline.ID, current.ID} {
			if _, err := tx.CopyFrom(ctx, pgx.Identifier{"finding_observations"}, columns(findingObservationColumns), pgx.CopyFromSlice(count, func(index int) ([]any, error) {
				value := identities[index]
				return []any{tenantID.String(), cycleID.String(), snapshotID.String() + value.ID.String(), snapshotID.String(), value.ID.String(), "sca", "vulnerability", value.TargetIdentityCanonical, fmt.Sprintf("finding-%06d", index), "", "high", nil, "1.0.0", "", "", "", json.RawMessage(`{"tool_name":"scanner"}`), now}, nil
			})); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("seed: %d identities / %d observations in %s", count, 2*count, time.Since(seedAt))
	lineage := NewFindingLineageRepository(pool)
	snapshots := NewAssessmentSnapshotRepository(pool)
	comparisons := NewAssessmentComparisonRepository(pool)
	verification, err := comparisonuc.NewRetestVerificationReader(lineage, snapshots, NewRetestRepository(pool))
	if err != nil {
		t.Fatal(err)
	}
	service, err := comparisonuc.NewService(comparisons, snapshots, NewAssessmentCycleRepository(pool), lineage, NewTenantTransactionRunner(pool), postgresLineageAudit{}, postgresLineageClock{now: now.Add(time.Second)}, &postgresLineageIDs{prefix: "scale"}, verification, nil)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	queued, created, decision, err := service.Queue(ctx, comparisonuc.QueueInput{TenantID: tenantID, BaselineSnapshotID: baseline.ID, CurrentSnapshotID: current.ID, Mode: cmp.ModeLifecycle, FingerprintVersion: 1, RiskModelVersion: 1, Actor: "scale-test"})
	if err != nil || !created || !decision.Allowed {
		t.Fatalf("queue created=%v allowed=%v err=%v", created, decision.Allowed, err)
	}
	queuedAfter := time.Since(started)
	result, err := service.Generate(ctx, comparisonuc.WorkInput{TenantID: tenantID, ComparisonID: queued.ID, Actor: "scale-worker"})
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != count || result.Summary.BaselineCount != count || result.Summary.CurrentCount != count {
		t.Fatalf("scale counts: items=%d summary=%+v", len(result.Items), result.Summary)
	}
	t.Logf("queue=%s generation+queue=%s items=%d", queuedAfter, elapsed, len(result.Items))
	if elapsed > 5*time.Minute {
		t.Fatalf("100k generation exceeded five minutes: %s", elapsed)
	}
	latencies := make([]time.Duration, 20)
	for index := range latencies {
		started := time.Now()
		page, err := comparisons.ListItems(ctx, tenantID, result.ID, ports.AssessmentComparisonItemFilter{AfterPosition: index*100 - 1, Limit: 100, ProducerKind: "sca", FindingKind: "vulnerability"})
		if err != nil || len(page.Items) != 100 || !page.HasMore {
			t.Fatalf("page count=%d err=%v", len(page.Items), err)
		}
		latencies[index] = time.Since(started)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	t.Logf("filtered 100-item pages: n=20 p50=%s p95=%s max=%s", latencies[9], latencies[18], latencies[19])
	if latencies[18] > 2*time.Second {
		t.Fatalf("100k filtered page p95 exceeded two seconds: %s", latencies[18])
	}
	reader, err := cycleuc.NewClosureDecisionReader(lineage, snapshots, NewRetestRepository(pool), NewSLAStore(pool))
	if err != nil {
		t.Fatal(err)
	}
	query := ports.AssessmentClosureReferenceQuery{CycleID: cycleID, SnapshotIDs: []shared.ID{baseline.ID, current.ID}, AsOfAt: now.Add(time.Minute)}
	started = time.Now()
	references, err := reader.ListAssessmentClosureReferences(ctx, tenantID, query)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(references)
	if err != nil || len(references) != 1 || references[0].Kind != "finding_observation_set" || len(encoded) > 1024 {
		t.Fatalf("closure references=%d bytes=%d err=%v", len(references), len(encoded), err)
	}
	t.Logf("closure source collection: %s; %d observations bound in %d-byte reference set", time.Since(started), 2*count, len(encoded))
	started = time.Now()
	if err := reader.ResolveAssessmentClosureReferences(ctx, tenantID, query, references); err != nil {
		t.Fatal(err)
	}
	t.Logf("historical closure source resolution: %s", time.Since(started))
}
