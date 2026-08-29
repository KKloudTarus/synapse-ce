package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCoverageWindowRepository(t *testing.T) {
	pool, ctx, tenant, other, agentID, assetID := coverageWindowPostgresFixture(t)
	repo := mustNewCoverageWindowRepository(t, pool)
	at := time.Now().UTC().Truncate(time.Microsecond)
	window := postgresCoverageWindow(at, agentID, assetID)

	first, err := repo.AppendCoverageWindow(ctx, window)
	if err != nil {
		t.Fatalf("AppendCoverageWindow() error = %v", err)
	}
	retry := window
	retry.CreatedAt = retry.CreatedAt.Add(time.Hour)
	retry.States = append([]detection.ClassCoverage(nil), retry.States...)
	for i, j := 0, len(retry.States)-1; i < j; i, j = i+1, j-1 {
		retry.States[i], retry.States[j] = retry.States[j], retry.States[i]
	}
	got, err := mustNewCoverageWindowRepository(t, pool).AppendCoverageWindow(ctx, retry)
	if err != nil {
		t.Fatalf("restart retry AppendCoverageWindow() error = %v", err)
	}
	if !got.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("retry CreatedAt = %s, want first %s", got.CreatedAt, first.CreatedAt)
	}

	listed, err := repo.ListCoverageWindows(ctx, ports.CoverageWindowQuery{
		AgentID: agentID, AssetID: assetID, HostID: window.HostID,
		Since: window.Since, Until: window.Until, Limit: 1,
	})
	if err != nil {
		t.Fatalf("ListCoverageWindows() error = %v", err)
	}
	if len(listed) != 1 || listed[0].Revision != window.Revision {
		t.Fatalf("listed = %#v, want committed revision", listed)
	}
	atUntil, err := repo.ListCoverageWindows(ctx, ports.CoverageWindowQuery{
		AgentID: agentID, AssetID: assetID, HostID: window.HostID,
		Since: window.Until, Until: window.Until.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("half-open ListCoverageWindows() error = %v", err)
	}
	if len(atUntil) != 0 {
		t.Fatalf("window ending at Since was included: %#v", atUntil)
	}
	otherRows, err := repo.ListCoverageWindows(shared.WithTenant(context.Background(), other), ports.CoverageWindowQuery{})
	if err != nil {
		t.Fatalf("other tenant ListCoverageWindows() error = %v", err)
	}
	if len(otherRows) != 0 {
		t.Fatalf("other tenant saw %d windows", len(otherRows))
	}

	if _, err := pool.Exec(context.Background(), `UPDATE coverage_windows SET gap_count=gap_count+1 WHERE tenant_id=$1 AND revision=$2`, tenant, window.Revision); err == nil {
		t.Fatal("coverage window UPDATE unexpectedly succeeded")
	}
	if _, err := pool.Exec(context.Background(), `DELETE FROM coverage_windows WHERE tenant_id=$1 AND revision=$2`, tenant, window.Revision); err == nil {
		t.Fatal("coverage window DELETE unexpectedly succeeded")
	}
}

func TestCoverageWindowRepositoryRejectsStaleRevisionAfterClassIdentityChange(t *testing.T) {
	pool, ctx, _, _, agentID, assetID := coverageWindowPostgresFixture(t)
	window := postgresCoverageWindow(time.Now().UTC().Truncate(time.Microsecond), agentID, assetID)
	repo := mustNewCoverageWindowRepository(t, pool)
	if _, err := repo.AppendCoverageWindow(ctx, window); err != nil {
		t.Fatalf("AppendCoverageWindow() error = %v", err)
	}
	changed := window
	changed.States = append([]detection.ClassCoverage(nil), window.States...)
	changed.States[0].AgentID = ""
	if _, err := repo.AppendCoverageWindow(ctx, changed); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("stale class identity revision error = %v, want validation", err)
	}
}

func TestCoverageWindowRepositoryConcurrentIdenticalAppend(t *testing.T) {
	pool, ctx, _, _, agentID, assetID := coverageWindowPostgresFixture(t)
	window := postgresCoverageWindow(time.Now().UTC().Truncate(time.Microsecond), agentID, assetID)
	const callers = 12
	results := make(chan sensorstate.CoverageWindow, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			got, err := mustNewCoverageWindowRepository(t, pool).AppendCoverageWindow(ctx, window)
			results <- got
			errs <- err
		})
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent AppendCoverageWindow() error = %v", err)
		}
	}
	var createdAt time.Time
	for got := range results {
		if createdAt.IsZero() {
			createdAt = got.CreatedAt
		} else if !got.CreatedAt.Equal(createdAt) {
			t.Fatalf("concurrent CreatedAt = %s, want %s", got.CreatedAt, createdAt)
		}
	}
	rows, err := mustNewCoverageWindowRepository(t, pool).ListCoverageWindows(ctx, ports.CoverageWindowQuery{})
	if err != nil {
		t.Fatalf("ListCoverageWindows() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("stored rows = %d, want 1", len(rows))
	}
}

func TestCoverageWindowRepositoryRejectsOversizedLimit(t *testing.T) {
	pool, ctx, _, _, _, _ := coverageWindowPostgresFixture(t)
	if _, err := mustNewCoverageWindowRepository(t, pool).ListCoverageWindows(ctx, ports.CoverageWindowQuery{
		Limit: ports.MaxCoverageWindowLimit + 1,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("ListCoverageWindows() error = %v, want validation", err)
	}
}

func TestCoverageWindowRepositoryRejectsNoncanonicalRevisionTimestamps(t *testing.T) {
	pool, ctx, _, _, agentID, assetID := coverageWindowPostgresFixture(t)
	window := postgresCoverageWindow(time.Now().UTC().Truncate(time.Microsecond), agentID, assetID)
	window.States[0].Since = window.States[0].Since.Add(time.Nanosecond)
	window.Vector = sensorstate.BuildCoverageVector(window)
	window.Revision = sensorstate.RevisionFor(window)
	if _, err := mustNewCoverageWindowRepository(t, pool).AppendCoverageWindow(ctx, window); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("AppendCoverageWindow() error = %v, want validation", err)
	}
}

func TestSensorStateRepositorySelectsEffectiveStatePerClass(t *testing.T) {
	pool, ctx, _, _, agentID, assetID := coverageWindowPostgresFixture(t)
	repo := mustNewSensorStateRepository(t, pool)
	since := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	hostID := shared.ID("host-1")
	observation := func(reportID shared.ID, observedAt time.Time, states ...detection.ClassCoverage) sensorstate.Observation {
		return sensorstate.Observation{
			ReportID: reportID, AgentID: agentID, AssetID: assetID, HostID: hostID,
			Kind: sensorstate.RecordSensorState, ObservedAt: observedAt, RecordedAt: observedAt.Add(time.Minute),
			SchemaVersion: 1, PayloadDigest: strings.Repeat("a", 64), SignedContentDigest: strings.Repeat("b", 64),
			States: states,
		}
	}
	state := func(class detection.Class, state detection.ClassState, reason string, at time.Time) detection.ClassCoverage {
		return detection.ClassCoverage{Class: class, HostID: hostID, AgentID: agentID, State: state, Reason: reason, Since: at}
	}
	rows := []sensorstate.Observation{
		observation("process-active", since.Add(-time.Hour), state(detection.ClassProcess, detection.StateActive, "", since.Add(-time.Hour))),
		observation("network-degraded", since.Add(-30*time.Minute), state(detection.ClassNetwork, detection.StateDegraded, "capture backlog", since.Add(-30*time.Minute))),
		observation("multi-class", since.Add(-15*time.Minute),
			state(detection.ClassFile, detection.StateActive, "", since.Add(-15*time.Minute)),
			state(detection.ClassPrivilege, detection.StateActive, "", since.Add(-15*time.Minute))),
		observation("at-since", since, state(detection.ClassProcess, detection.StateActive, "", since)),
		observation("at-until", since.Add(time.Hour), state(detection.ClassNetwork, detection.StateActive, "", since.Add(time.Hour))),
	}
	for _, row := range rows {
		if err := repo.AppendSensorState(ctx, row); err != nil {
			t.Fatalf("append %s: %v", row.ReportID, err)
		}
	}

	got, err := repo.ListCoverageSensorStates(ctx, ports.CoverageSensorStateQuery{
		AgentID: agentID, AssetID: assetID, HostID: hostID,
		Since: since, Until: since.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("ListCoverageSensorStates() error = %v", err)
	}
	want := []shared.ID{"process-active", "network-degraded", "multi-class", "at-since"}
	if len(got) != len(want) {
		t.Fatalf("coverage sensor-state count = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].ReportID != want[i] {
			t.Fatalf("coverage sensor-state[%d] = %q, want %q", i, got[i].ReportID, want[i])
		}
	}
	if len(got[2].States) != 2 {
		t.Fatalf("multi-class observation was duplicated or lost states: %#v", got[2])
	}
}

func coverageWindowPostgresFixture(t *testing.T) (*pgxpool.Pool, context.Context, shared.ID, shared.ID, shared.ID, shared.ID) {
	t.Helper()
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	base := context.Background()
	if err := Migrate(base, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(base, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	suffix := uuid.NewString()
	tenant := shared.ID("coverage-tenant-" + suffix)
	other := shared.ID("coverage-other-" + suffix)
	agentID := shared.ID("coverage-agent-" + suffix)
	assetID := shared.ID("coverage-asset-" + suffix)
	for _, id := range []shared.ID{tenant, other} {
		if _, err := pool.Exec(base, `INSERT INTO tenants(id,name) VALUES($1,$1)`, id); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	if _, err := pool.Exec(base, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$1,$3,'active')`, agentID, tenant, "coverage-token-"+suffix); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	if _, err := pool.Exec(base, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name) VALUES($1,$2,'host',$1,$1)`, assetID, tenant); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		conn, err := pool.Acquire(cleanupCtx)
		if err != nil {
			t.Errorf("acquire coverage cleanup connection: %v", err)
			return
		}
		defer conn.Release()
		if _, err := conn.Exec(cleanupCtx, `SET session_replication_role = replica`); err != nil {
			t.Errorf("disable coverage append-only trigger for cleanup: %v", err)
			return
		}
		defer func() {
			if _, err := conn.Exec(cleanupCtx, `SET session_replication_role = origin`); err != nil {
				t.Errorf("restore coverage append-only trigger for cleanup: %v", err)
			}
		}()
		statements := []struct {
			operation string
			query     string
			args      []any
		}{
			{"coverage windows", `DELETE FROM coverage_windows WHERE tenant_id=$1`, []any{tenant}},
			{"sensor states", `DELETE FROM sensor_state_history WHERE tenant_id=$1`, []any{tenant}},
			{"fleet assets", `DELETE FROM fleet_assets WHERE tenant_id=$1`, []any{tenant}},
			{"fleet agents", `DELETE FROM fleet_agents WHERE tenant_id=$1`, []any{tenant}},
			{"tenants", `DELETE FROM tenants WHERE id=ANY($1)`, []any{[]string{tenant.String(), other.String()}}},
		}
		for _, statement := range statements {
			if _, err := conn.Exec(cleanupCtx, statement.query, statement.args...); err != nil {
				t.Errorf("remove coverage test %s: %v", statement.operation, err)
				return
			}
		}
	})
	return pool, shared.WithTenant(base, tenant), tenant, other, agentID, assetID
}

func postgresCoverageWindow(at time.Time, agentID, assetID shared.ID) sensorstate.CoverageWindow {
	window := sensorstate.CoverageWindow{
		AssetID: assetID, AgentID: agentID, HostID: "host-1",
		Since: at, Until: at.Add(time.Hour),
		InputDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CreatedAt:   at.Add(2 * time.Hour),
		States: []detection.ClassCoverage{
			{Class: detection.ClassProcess, HostID: "host-1", AgentID: agentID, State: detection.StateActive, Since: at},
			{Class: detection.ClassNetwork, HostID: "host-1", AgentID: agentID, State: detection.StateDegraded, Reason: "sensor gap", Since: at},
		},
	}
	window.Vector = sensorstate.BuildCoverageVector(window)
	window.Revision = sensorstate.RevisionFor(window)
	return window
}
