package projectuc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

type webhookQueueCapture struct {
	ports.JobQueue
	payload []byte
}

func (q *webhookQueueCapture) Enqueue(_ context.Context, _ string, payload []byte) (string, error) {
	q.payload = append([]byte(nil), payload...)
	return "queue-job", nil
}

func TestWebhookMRQueuesStoredRepoActualBaseAndTrustedContext(t *testing.T) {
	svc, analyses, jobs, engagements := newImportService(t)
	ctx := shared.WithTenant(context.Background(), "tenant")
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Git project", Key: "git-project", SourceBinding: project.SourceBinding{Kind: project.SourceGit, Value: "https://gitlab.example.com/trusted/subgroup/app.git", DefaultBranch: "main"}})
	if err != nil {
		t.Fatal(err)
	}
	scanner := scauc.NewService(engagements, nil, nil, nil, jobs, nil, nil, &sequentialIDs{}, ports.Provenance{}, svc.clock, &captureAudit{}, shared.SeverityHigh, 0, nil, nil, nil, nil, nil, nil, nil)
	svc.SetScanner(scanner)
	in := ports.WebhookScanTarget{Provider: "gitlab", Ref: "contributor/fix", SHA: strings.Repeat("a", 40), BaseRef: "release/1.0", MergeRequestNumber: 42, Fork: true, FetchRef: "refs/merge-requests/42/head"}
	if _, err = svc.StartGitLabWebhookAnalysis(ctx, "hook", "tenant", p.ID, in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("inline webhook accepted: %v", err)
	}
	queue := &webhookQueueCapture{}
	scanner.SetQueue(queue)
	job, err := svc.StartGitLabWebhookAnalysis(ctx, "hook", "tenant", p.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Req     ports.AcquireRequest `json:"req"`
		Options scauc.ScanOptions    `json:"options"`
	}
	if err = json.Unmarshal(queue.payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Req.Value != "https://gitlab.example.com/trusted/subgroup/app.git" || payload.Req.BaseRef != "release/1.0" || payload.Req.Commit != in.SHA || !payload.Req.DisableGitCredentials || !payload.Options.NoBuildExecution {
		t.Fatalf("unsafe/wrong acquire options: %+v %+v", payload.Req, payload.Options)
	}
	ci := payload.Options.WebhookContext
	if ci == nil || ci.RepoSlug != "trusted/subgroup/app" || ci.PullRequest != "42" || ci.TargetBranch != "release/1.0" || ci.HeadSHA != in.SHA {
		t.Fatalf("lost SCM context: %+v", ci)
	}
	decorator := &recordingPRDecorator{}
	svc.SetPRDecorator(decorator)
	if _, err := svc.SetPullRequestDecoration(ctx, "alice", "tenant", p.Key, true); err != nil {
		t.Fatal(err)
	}
	result := pipelineResult()
	result.SourceRef = in.Ref
	result.WebhookContext = ci
	result.WebhookFork = in.Fork
	e, err := engagements.GetByProjectID(ctx, "tenant", p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.RecordProjectAnalysis(ctx, e.ID, job.ID, svc.clock.Now(), result); err != nil {
		t.Fatal(err)
	}
	analysis, err := analyses.Get(ctx, "tenant", p.ID, shared.ID(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	if analysis.CI == nil || analysis.CI.PullRequest != "42" || analysis.CI.TargetBranch != "release/1.0" || analysis.Branch() != in.Ref {
		t.Fatalf("analysis lost PR context: %+v", analysis.CI)
	}

	if decorator.calls != 0 {
		t.Fatal("fork analysis triggered forge writes")
	}

}
