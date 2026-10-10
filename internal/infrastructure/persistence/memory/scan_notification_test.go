package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	first := makeJob("a", at.Add(time.Minute), "canonical://target", "same", "fixed")
	if err := store.Save(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := makeJob("b", at.Add(2*time.Minute), "canonical://target", "same", "new")
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

func TestTerminalScanSnapshotRejectsChangedAdmissionIdentity(t *testing.T) {
	store := NewScanJobStore()
	started := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	job := ports.ScanJob{ID: "identity", EngagementID: "eng", Target: "https://git.example.test/repo.git", Kind: ports.TargetGit, Status: ports.ScanRunning, StartedAt: started}
	if err := store.CreateRunning(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	finished := started.Add(time.Minute)
	job.Status, job.FinishedAt = ports.ScanSucceeded, &finished
	job.NotificationSnapshot = notification.NewScanSummary("https://git.example.test/other", ports.TargetGit, true, nil)
	if err := store.Save(context.Background(), job); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("changed admission identity error=%v, want validation", err)
	}
	stored, err := store.GetJob(context.Background(), job.ID)
	if err != nil || stored.Status != ports.ScanRunning || stored.NotificationSnapshot.TargetKey != "" {
		t.Fatalf("invalid terminal save mutated admitted job: %+v err=%v", stored, err)
	}
}

func TestTerminalScanSnapshotRejectsChangedAdmissionEngagement(t *testing.T) {
	store := NewScanJobStore()
	started := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	job := ports.ScanJob{ID: "identity-engagement", EngagementID: "eng", Target: "repo", Kind: ports.TargetLocal, Status: ports.ScanRunning, StartedAt: started}
	if err := store.CreateRunning(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	finished := started.Add(time.Minute)
	job.EngagementID, job.Status, job.FinishedAt = "other-engagement", ports.ScanSucceeded, &finished
	job.NotificationSnapshot = notification.NewScanSummary("repo", ports.TargetLocal, true, nil)
	if err := store.Save(context.Background(), job); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("changed admission engagement error=%v, want validation", err)
	}
	stored, err := store.GetJob(context.Background(), job.ID)
	if err != nil || stored.EngagementID != "eng" || stored.Status != ports.ScanRunning || stored.NotificationSnapshot.TargetKey != "" {
		t.Fatalf("invalid terminal save mutated admitted job: %+v err=%v", stored, err)
	}
}

func TestTerminalScanSnapshotIsCapturedOnlyByFirstSuccess(t *testing.T) {
	store := NewScanJobStore()
	started := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	finished := started.Add(time.Minute)
	job := ports.ScanJob{ID: "first-success", EngagementID: "eng", Target: "repo", Kind: ports.TargetLocal, Status: ports.ScanFailed, StartedAt: started, FinishedAt: &finished,
		NotificationSnapshot: notification.NewScanSummary("repo", ports.TargetLocal, true, []finding.Finding{scanFindingForNotification("failed", shared.SeverityHigh)})}
	if err := store.Save(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	failed, err := store.GetJob(context.Background(), job.ID)
	if err != nil || failed.NotificationSnapshot.TargetKey != "" {
		t.Fatalf("failed job retained a new snapshot: %+v err=%v", failed, err)
	}
	job.Status = ports.ScanSucceeded
	job.NotificationSnapshot = notification.NewScanSummary("repo", ports.TargetLocal, true, []finding.Finding{scanFindingForNotification("succeeded", shared.SeverityHigh)})
	if err := store.Save(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetJob(context.Background(), job.ID)
	if err != nil || stored.NotificationSnapshot.Total != 1 || stored.NotificationSnapshot.Keys[0] != "succeeded" {
		t.Fatalf("first success was not captured: %+v err=%v", stored.NotificationSnapshot, err)
	}
}

func TestTerminalScanSnapshotBoundsTenThousandLongValidKeys(t *testing.T) {
	store := NewScanJobStore()
	started := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	finished := started.Add(time.Minute)
	items := make([]finding.Finding, 10_000)
	for i := range items {
		key := "path/" + strings.Repeat("module/", 58) + fmt.Sprintf("finding-%05d", i)
		items[i] = scanFindingForNotification(key, shared.SeverityHigh)
	}
	job := ports.ScanJob{
		ID:                   "long-valid-keys",
		EngagementID:         "eng",
		Target:               "repo",
		Kind:                 ports.TargetLocal,
		Status:               ports.ScanSucceeded,
		StartedAt:            started,
		FinishedAt:           &finished,
		NotificationSnapshot: notification.NewScanSummary("repo", ports.TargetLocal, true, items),
	}
	if err := store.Save(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetJob(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(stored.NotificationSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != ports.ScanSucceeded || stored.NotificationSnapshot.Total != len(items) || !stored.NotificationSnapshot.Truncated || stored.NotificationSnapshot.DeltaAvailable || len(stored.NotificationSnapshot.Keys) == 0 || len(encoded) > 768*1024 {
		t.Fatalf("stored bounded snapshot status=%q total=%d truncated=%v delta=%v keys=%d bytes=%d", stored.Status, stored.NotificationSnapshot.Total, stored.NotificationSnapshot.Truncated, stored.NotificationSnapshot.DeltaAvailable, len(stored.NotificationSnapshot.Keys), len(encoded))
	}
}

func scanFindingForNotification(key string, severity shared.Severity) finding.Finding {
	return finding.Finding{ID: shared.ID(key), DedupKey: key, Kind: finding.KindSCA, Severity: severity}
}
