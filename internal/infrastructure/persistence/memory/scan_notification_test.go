package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTerminalScanSnapshotUsesEarlierSameTargetBaselineAndFreezes(t *testing.T) {
	store := NewScanJobStore()
	at := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	makeJob := func(id string, finished time.Time, target string, keys ...string) ports.ScanJob {
		items := make([]finding.Finding, 0, len(keys))
		for _, key := range keys {
			items = append(items, finding.Finding{ID: shared.ID(key), DedupKey: key, Kind: finding.KindSCA, Severity: shared.SeverityHigh})
		}
		return ports.ScanJob{ID: id, EngagementID: "eng", Target: target, Kind: "git", Status: ports.ScanSucceeded, StartedAt: at, FinishedAt: &finished,
			NotificationSnapshot: notification.NewScanSummary("canonical://target", "git", true, items)}
	}
	first := makeJob("a", at.Add(time.Minute), "raw-a", "same", "fixed")
	if err := store.Save(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := makeJob("b", at.Add(2*time.Minute), "raw-b", "same", "new")
	if err := store.Save(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetJob(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotificationSnapshot.DeltaAvailable || got.NotificationSnapshot.New != 1 || got.NotificationSnapshot.Fixed != 1 || got.NotificationSnapshot.BaselineJobID != "a" {
		t.Fatalf("delta = %+v", got.NotificationSnapshot)
	}
	// A status correction cannot replace completion evidence, but controls
	// whether a queued notification remains relevant.
	second.NotificationSnapshot = notification.NewScanSummary("canonical://target", "git", true, nil)
	later := at.Add(3 * time.Minute)
	second.FinishedAt = &later
	second.Status = ports.ScanFailed
	if err := store.Save(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	got, _ = store.GetJob(context.Background(), "b")
	if got.Status != ports.ScanFailed || got.FinishedAt == nil || !got.FinishedAt.Equal(at.Add(2*time.Minute)) || got.NotificationSnapshot.BaselineJobID != "a" || got.NotificationSnapshot.Total != 2 {
		t.Fatalf("terminal snapshot changed: %+v", got.NotificationSnapshot)
	}
	if err := store.Save(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	second.Status = ports.ScanSucceeded
	successRetry := later.Add(time.Minute)
	second.FinishedAt = &successRetry
	second.NotificationSnapshot = notification.NewScanSummary("canonical://target", "git", true, []finding.Finding{{ID: "untrusted", DedupKey: "untrusted", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})
	if err := store.Save(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	got, _ = store.GetJob(context.Background(), "b")
	if got.Status != ports.ScanSucceeded || got.FinishedAt == nil || !got.FinishedAt.Equal(at.Add(2*time.Minute)) || got.NotificationSnapshot.BaselineJobID != "a" || got.NotificationSnapshot.Total != 2 {
		t.Fatalf("terminal retry replaced captured evidence: %+v", got.NotificationSnapshot)
	}
}

func TestTerminalScanSnapshotDoesNotSkipNewerLegacyPredecessor(t *testing.T) {
	store := NewScanJobStore()
	at := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	rawTarget := "https://git.example.test/repo.git"
	targetKey := notification.CanonicalScanTarget(rawTarget, ports.TargetGit)
	makeSummary := func(keys ...string) notification.ScanSummary {
		items := make([]finding.Finding, 0, len(keys))
		for _, key := range keys {
			items = append(items, finding.Finding{ID: shared.ID(key), DedupKey: key, Kind: finding.KindSCA, Severity: shared.SeverityHigh})
		}
		return notification.NewScanSummary(targetKey, ports.TargetGit, true, items)
	}
	firstAt := at.Add(time.Minute)
	if err := store.Save(context.Background(), ports.ScanJob{ID: "known", EngagementID: "eng", Target: rawTarget, Kind: ports.TargetGit, Status: ports.ScanSucceeded, StartedAt: at, FinishedAt: &firstAt, NotificationSnapshot: makeSummary("fixed")}); err != nil {
		t.Fatal(err)
	}
	legacyAt := at.Add(2 * time.Minute)
	if err := store.Save(context.Background(), ports.ScanJob{ID: "legacy", EngagementID: "eng", Target: "https://git.example.test/repo", Kind: ports.TargetGit, Status: ports.ScanSucceeded, StartedAt: at, FinishedAt: &legacyAt}); err != nil {
		t.Fatal(err)
	}
	currentAt := at.Add(3 * time.Minute)
	if err := store.Save(context.Background(), ports.ScanJob{ID: "current", EngagementID: "eng", Target: rawTarget, Kind: ports.TargetGit, Status: ports.ScanSucceeded, StartedAt: at, FinishedAt: &currentAt, NotificationSnapshot: makeSummary("new")}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetJob(context.Background(), "current")
	if err != nil {
		t.Fatal(err)
	}
	if got.NotificationSnapshot.DeltaAvailable || got.NotificationSnapshot.BaselineJobID != "" {
		t.Fatalf("legacy predecessor was skipped: %+v", got.NotificationSnapshot)
	}
}

func TestTerminalScanSnapshotKeepsCaseSensitiveOpaqueTargetsDistinct(t *testing.T) {
	store := NewScanJobStore()
	at := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	makeSummary := func(target, key string) notification.ScanSummary {
		return notification.NewScanSummary(notification.CanonicalScanTarget(target, ports.TargetLocal), ports.TargetLocal, true, []finding.Finding{{ID: shared.ID(key), DedupKey: key, Kind: finding.KindSCA, Severity: shared.SeverityHigh}})
	}
	firstAt := at.Add(time.Minute)
	if err := store.Save(context.Background(), ports.ScanJob{ID: "upper", EngagementID: "eng", Target: "/Repo", Kind: ports.TargetLocal, Status: ports.ScanSucceeded, StartedAt: at, FinishedAt: &firstAt, NotificationSnapshot: makeSummary("/Repo", "fixed")}); err != nil {
		t.Fatal(err)
	}
	lowerAt := at.Add(2 * time.Minute)
	if err := store.Save(context.Background(), ports.ScanJob{ID: "lower", EngagementID: "eng", Target: "/repo", Kind: ports.TargetLocal, Status: ports.ScanSucceeded, StartedAt: at, FinishedAt: &lowerAt}); err != nil {
		t.Fatal(err)
	}
	currentAt := at.Add(3 * time.Minute)
	if err := store.Save(context.Background(), ports.ScanJob{ID: "current", EngagementID: "eng", Target: "/Repo", Kind: ports.TargetLocal, Status: ports.ScanSucceeded, StartedAt: at, FinishedAt: &currentAt, NotificationSnapshot: makeSummary("/Repo", "new")}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetJob(context.Background(), "current")
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotificationSnapshot.DeltaAvailable || got.NotificationSnapshot.BaselineJobID != "upper" {
		t.Fatalf("case-sensitive target comparison = %+v", got.NotificationSnapshot)
	}
}

func TestTerminalScanSnapshotRetryDoesNotRecomputeAgainstLatePredecessor(t *testing.T) {
	store := NewScanJobStore()
	at := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	makeJob := func(id string, finished time.Time, keys ...string) ports.ScanJob {
		items := make([]finding.Finding, 0, len(keys))
		for _, key := range keys {
			items = append(items, finding.Finding{ID: shared.ID(key), DedupKey: key, Kind: finding.KindSCA, Severity: shared.SeverityHigh})
		}
		return ports.ScanJob{ID: id, EngagementID: "eng", Target: "repo", Kind: ports.TargetGit, Status: ports.ScanSucceeded, StartedAt: at, FinishedAt: &finished,
			NotificationSnapshot: notification.NewScanSummary("repo", ports.TargetGit, true, items)}
	}
	first := makeJob("a", at.Add(time.Minute), "fixed")
	late := makeJob("b", at.Add(3*time.Minute), "new")
	if err := store.Save(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), late); err != nil {
		t.Fatal(err)
	}
	inserted := makeJob("c", at.Add(2*time.Minute), "middle")
	if err := store.Save(context.Background(), inserted); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), late); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetJob(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got.NotificationSnapshot.BaselineJobID != "a" || got.NotificationSnapshot.Fixed != 1 || got.NotificationSnapshot.New != 1 {
		t.Fatalf("terminal retry recalculated from a later-inserted predecessor: %+v", got.NotificationSnapshot)
	}
}
