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

func TestBitbucketQueuesStoredRepoAndSuppressesForkExecution(t *testing.T) {
	svc, analyses, jobs, engagements := newImportService(t)
	ctx := shared.WithTenant(context.Background(), "tenant")
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Git project", Key: "git-project", SourceBinding: project.SourceBinding{Kind: project.SourceGit, Value: "https://bitbucket.org/trusted/app.git", DefaultBranch: "main"}})
	if err != nil {
		t.Fatal(err)
	}
	scanner := scauc.NewService(engagements, nil, nil, nil, jobs, nil, nil, &sequentialIDs{}, ports.Provenance{}, svc.clock, &captureAudit{}, shared.SeverityHigh, 0, nil, nil, nil, nil, nil, nil, nil)
	svc.SetScanner(scanner)
	in := ports.BitbucketScanTarget{Ref: "contributor/fix", SHA: strings.Repeat("a", 40), BaseRef: "release/1.0", Fork: true, PullRequest: true}
	if _, err = svc.StartBitbucketWebhookAnalysis(ctx, "hook", "tenant", p.ID, in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("inline webhook accepted: %v", err)
	}
	queue := &webhookQueueCapture{}
	scanner.SetQueue(queue)
	job, err := svc.StartBitbucketWebhookAnalysis(ctx, "hook", "tenant", p.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	stale := in
	stale.ResolvedRepository = "https://bitbucket.org/previous/app.git"
	if _, err := svc.StartBitbucketWebhookAnalysis(ctx, "hook", "tenant", p.ID, stale); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("changed source accepted: %v", err)
	}
	var payload struct {
		Req     ports.AcquireRequest `json:"req"`
		Options scauc.ScanOptions    `json:"options"`
	}
	if err = json.Unmarshal(queue.payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Req.Value != "https://bitbucket.org/trusted/app.git" || payload.Req.BaseRef != "release/1.0" || payload.Req.Commit != in.SHA || !payload.Req.DisableGitCredentials || !payload.Options.NoBuildExecution {
		t.Fatalf("unsafe/wrong acquire options: %+v %+v", payload.Req, payload.Options)
	}
	decorator := &recordingPRDecorator{}
	svc.SetPRDecorator(decorator)
	if _, err := svc.SetPullRequestDecoration(ctx, "alice", "tenant", p.Key, true); err != nil {
		t.Fatal(err)
	}
	result := pipelineResult()
	result.SourceRef = in.Ref
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
	if analysis.CI != nil || analysis.Branch() != in.Ref {
		t.Fatalf("unexpected forged PR write context: %+v", analysis.CI)
	}

	if decorator.calls != 0 {
		t.Fatal("fork analysis triggered forge writes")
	}

}

type resolvedBitbucketCommit struct {
	sha, repository string
	fork            bool
	err             error
}

func (r *resolvedBitbucketCommit) ResolveBitbucketCommit(_ context.Context, repository, _ string, fork bool) (string, error) {
	r.repository, r.fork = repository, fork
	return r.sha, r.err
}

func TestBitbucketCommitPreflightUsesStoredSourceAndRejectsMismatchedSHA(t *testing.T) {
	svc, _, _, _ := newImportService(t)
	ctx := shared.WithTenant(context.Background(), "tenant")
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Git project", Key: "git-project", SourceBinding: project.SourceBinding{Kind: project.SourceGit, Value: "https://bitbucket.org/trusted/app.git", DefaultBranch: "main"}})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &resolvedBitbucketCommit{sha: strings.Repeat("a", 40)}
	svc.SetBitbucketCommitResolver(resolver)
	in := ports.BitbucketScanTarget{Ref: "feature/fix", SHA: strings.Repeat("a", 12), BaseRef: "main", PullRequest: true, Fork: true}
	resolved, err := svc.ResolveBitbucketWebhookTarget(ctx, "tenant", p.ID, in)
	if err != nil || resolved.SHA != resolver.sha || resolved.ResolvedRepository != p.SourceBinding.Value || resolver.repository != p.SourceBinding.Value || !resolver.fork {
		t.Fatalf("unsafe preflight: %+v err=%v resolver=%+v", resolved, err, resolver)
	}
	for _, sha := range []string{strings.Repeat("b", 40), strings.Repeat("a", 12), strings.Repeat("a", 12) + strings.Repeat("z", 28)} {
		resolver.sha = sha
		if _, err := svc.ResolveBitbucketWebhookTarget(ctx, "tenant", p.ID, in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("resolved invalid hash %q: %v", sha, err)
		}
	}
	resolver.err = errors.New("lookup unavailable")
	if _, err := svc.ResolveBitbucketWebhookTarget(ctx, "tenant", p.ID, in); err == nil {
		t.Fatal("upstream error ignored")
	}
}
