package sca

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type executionProbe struct{ calls int }

func (p *executionProbe) Resolve(context.Context, string) ([]sbom.Component, error) {
	p.calls++
	return nil, nil
}
func (p *executionProbe) Ecosystem() string { return "test" }
func (p *executionProbe) ResolveEdges(context.Context, string, *sbom.SBOM) (int, error) {
	p.calls++
	return 0, nil
}

func TestForkScanSkipsEveryBuildResolverAndRetainsStaticAnalysis(t *testing.T) {
	for _, restricted := range []bool{true, false} {
		svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
		probes := []*executionProbe{{}, {}, {}, {}, {}}
		svc.SetMavenResolver(probes[0])
		svc.SetGradleResolver(probes[1])
		svc.SetNPMResolver(probes[2])
		svc.AddManifestResolver(probes[3])
		svc.SetGraphResolver(probes[4])
		result, err := svc.ScanWithOptions(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{NoBuildExecution: restricted})
		if err != nil {
			t.Fatal(err)
		}
		if result.SBOM == nil || len(result.Languages) == 0 {
			t.Fatal("static analysis was skipped")
		}
		want := 1
		if restricted {
			want = 0
		}
		for i, p := range probes {
			if p.calls != want {
				t.Errorf("restricted=%v resolver=%d calls=%d want=%d", restricted, i, p.calls, want)
			}
		}
	}
}

type webhookAnalysisCapture struct {
	ci    *projectanalysis.CIContext
	calls int
	fork  bool
}

func (r *webhookAnalysisCapture) RecordProjectAnalysis(_ context.Context, _ shared.ID, _ string, _ time.Time, result *ScanResult) error {
	r.ci = result.WebhookContext
	r.fork = result.WebhookFork
	r.calls++
	return nil
}
func TestDurableWorkerRetainsWebhookContextUntilRecording(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: now}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	recorder := &webhookAnalysisCapture{}
	svc.SetProjectAnalysisRecorder(recorder)
	ci := &projectanalysis.CIContext{Provider: "gitlab", RepoSlug: "trusted/app", PullRequest: "42", TargetBranch: "release/1.0", HeadSHA: "0123456789abcdef0123456789abcdef01234567"}
	err := svc.runScanJob(context.Background(), "hook", "e1", now, ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{Mode: ScanModeFull, ProjectAnalysis: true, NoBuildExecution: true, WebhookContext: ci}, ports.ScanJob{ID: "webhook-job", EngagementID: "e1", Status: ports.ScanRunning})
	if err != nil {
		t.Fatal(err)
	}
	if recorder.calls != 1 || !recorder.fork || recorder.ci == nil || *recorder.ci != *ci {
		t.Fatalf("worker lost webhook context: %+v", recorder)
	}
}
