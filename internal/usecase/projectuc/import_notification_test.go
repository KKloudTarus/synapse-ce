package projectuc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// importStatusObserver emulates the notification trigger: only a succeeded
// persisted status can capture scan.completed. It also verifies that the
// corresponding immutable analysis already exists at that exact transition.
type importStatusObserver struct {
	*memory.ScanJobStore
	onCreate func(ports.ScanJob)
	onSave   func(ports.ScanJob)
}

func (s *importStatusObserver) CreateRunning(ctx context.Context, job ports.ScanJob) error {
	if s.onCreate != nil {
		s.onCreate(job)
	}
	return s.ScanJobStore.CreateRunning(ctx, job)
}

func (s *importStatusObserver) Save(ctx context.Context, job ports.ScanJob) error {
	if s.onSave != nil {
		s.onSave(job)
	}
	return s.ScanJobStore.Save(ctx, job)
}

func TestCIImportDoesNotPublishSuccessBeforeAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name          string
		rejectPayload bool
		rejectAudit   bool
		wantFinal     ports.ScanStatus
	}{
		{name: "accepted", wantFinal: ports.ScanSucceeded},
		{name: "recorder_rejected", rejectPayload: true, wantFinal: ports.ScanFailed},
		{name: "audit_rejected", rejectAudit: true, wantFinal: ports.ScanFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			audit := &captureAudit{}
			svc, analyses, baseJobs, _ := newImportServiceWithAudit(t, audit)
			projectID := shared.ID(mustProjectID(t, svc))
			var transitions []ports.ScanStatus
			var captured int
			jobs := &importStatusObserver{ScanJobStore: baseJobs}
			jobs.onCreate = func(job ports.ScanJob) {
				transitions = append(transitions, job.Status)
				if job.Kind != "ci-import" || job.Status != ports.ScanRunning || job.Stage != "importing" || job.FinishedAt != nil {
					t.Errorf("CI import falsely succeeded at admission: %+v", job)
				}
			}
			jobs.onSave = func(job ports.ScanJob) {
				transitions = append(transitions, job.Status)
				if job.FinishedAt == nil {
					t.Error("terminal CI import has no completion timestamp")
				}
				if strings.Contains(job.Error, "never-store-this") {
					t.Error("scan history leaked an internal audit credential")
				}
				if job.Status == ports.ScanSucceeded {
					captured++
					if _, err := analyses.Get(ctx, "tenant", projectID, shared.ID(job.ID)); err != nil {
						t.Errorf("succeeded status was saved before analysis: %v", err)
					}
				} else if job.Status != ports.ScanFailed {
					t.Errorf("unexpected import transition: %+v", job)
				}
			}
			svc.SetScanJobs(jobs)

			result := pipelineResult()
			if tc.rejectPayload {
				result.CodeQuality.Inventory.Files = append(result.CodeQuality.Inventory.Files,
					measure.FileInventory{Path: "src/main.go", Language: "go", CodeLines: 1})
			}
			if tc.rejectAudit {
				audit.fail = errors.New("audit chain unavailable; credential=never-store-this")
			}
			_, err := svc.ImportAnalysis(ctx, "tenant", "project", ImportAnalysisInput{Actor: "ci-bot", Result: result})
			if tc.wantFinal == ports.ScanSucceeded && err != nil {
				t.Fatalf("accepted import error: %v", err)
			}
			if tc.wantFinal == ports.ScanFailed && err == nil {
				t.Fatal("rejected import was accepted")
			}
			if tc.rejectPayload && !strings.Contains(err.Error(), "duplicate canonical file path") {
				t.Errorf("unexpected recorder rejection: %v", err)
			}
			if tc.rejectAudit && !errors.Is(err, audit.fail) {
				t.Errorf("unexpected audit rejection: %v", err)
			}
			if tc.rejectAudit && strings.Contains(err.Error(), "never-store-this") {
				t.Error("HTTP-facing import error leaked internal audit credentials")
			}
			want := fmt.Sprint([]ports.ScanStatus{ports.ScanRunning, tc.wantFinal})
			if fmt.Sprint(transitions) != want {
				t.Fatalf("status transitions = %v, want %s", transitions, want)
			}
			if tc.wantFinal == ports.ScanSucceeded && captured != 1 {
				t.Errorf("accepted import captured %d successes, want one", captured)
			}
			if tc.wantFinal == ports.ScanFailed && captured != 0 {
				t.Errorf("rejected import captured %d false successes", captured)
			}
		})
	}
}
