package memory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func cloudAuthorityFixture() (cloudposture.Run, ports.CloudRunJob) {
	run := cloudposture.Run{ID: "run", TenantID: "tenant", EngagementID: "eng", Actor: "operator", Status: cloudposture.RunQueued, StartedAt: time.Unix(1, 0)}
	job := ports.CloudRunJob{TenantID: run.TenantID, RunID: run.ID, EngagementID: run.EngagementID, Actor: run.Actor, Scopes: []ports.CloudScope{{EngagementID: run.EngagementID, Provider: cloudposture.ProviderAzure, Root: "subscriptions/example", CredentialRef: "vault-reference"}}, ApprovedTargets: []string{"example"}}
	return run, job
}
func enqueueAuthorityFixture(t *testing.T, s *CloudRunStore, run cloudposture.Run, job ports.CloudRunJob, kind string) {
	t.Helper()
	b, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnqueueCloudRun(shared.WithTenant(context.Background(), run.TenantID), run, kind, b); err != nil {
		t.Fatal(err)
	}
}
func TestCloudRunAuthorityReadsOriginalAndIsolatesTenant(t *testing.T) {
	s := NewCloudRunStore()
	s.SetQueue(NewJobQueue(&seqIDs{}, nil))
	run, job := cloudAuthorityFixture()
	enqueueAuthorityFixture(t, s, run, job, "cspm")
	if _, err := s.GetCloudRunJob(context.Background(), "other", run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross tenant: %v", err)
	}
	stored, err := s.GetCloudRunJob(context.Background(), run.TenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored.Scopes[0].Root = "subscriptions/changed"
	stored.ApprovedTargets[0] = "changed"
	again, err := s.GetCloudRunJob(context.Background(), run.TenantID, run.ID)
	if err != nil || again.Scopes[0].Root != job.Scopes[0].Root || again.ApprovedTargets[0] != job.ApprovedTargets[0] {
		t.Fatalf("mutated authority: %+v %v", again, err)
	}
	projection, err := s.GetCloudRunAuthorization(context.Background(), run.TenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "vault-reference") || !projection.Scopes[0].CredentialBound {
		t.Fatal("credential reference exposed or binding missing")
	}
	projection.Scopes[0].Root = "changed"
	projection, err = s.GetCloudRunAuthorization(context.Background(), run.TenantID, run.ID)
	if err != nil || projection.Scopes[0].Root != job.Scopes[0].Root {
		t.Fatalf("projection alias: %v", err)
	}
}
func TestCloudRunAuthorityRejectsMalformedJobs(t *testing.T) {
	tests := []struct {
		name   string
		kind   string
		change func(*ports.CloudRunJob)
	}{
		{"wrong kind", "other", func(*ports.CloudRunJob) {}},
		{"tenant", "cspm", func(j *ports.CloudRunJob) { j.TenantID = "other" }},
		{"run", "cspm", func(j *ports.CloudRunJob) { j.RunID = "other" }},
		{"engagement", "cspm", func(j *ports.CloudRunJob) { j.EngagementID = "other" }},
		{"actor", "cspm", func(j *ports.CloudRunJob) { j.Actor = "other" }},
		{"scope engagement", "cspm", func(j *ports.CloudRunJob) { j.Scopes[0].EngagementID = "other" }},
		{"missing credential", "cspm", func(j *ports.CloudRunJob) { j.Scopes[0].CredentialRef = " " }},
		{"target mismatch", "cspm", func(j *ports.CloudRunJob) { j.ApprovedTargets[0] = "different" }},
		{"target count", "cspm", func(j *ports.CloudRunJob) { j.ApprovedTargets = nil }},
		{"too many", "cspm", func(j *ports.CloudRunJob) {
			for len(j.Scopes) < 33 {
				j.Scopes = append(j.Scopes, j.Scopes[0])
				j.ApprovedTargets = append(j.ApprovedTargets, j.ApprovedTargets[0])
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewCloudRunStore()
			s.SetQueue(NewJobQueue(&seqIDs{}, nil))
			run, job := cloudAuthorityFixture()
			tc.change(&job)
			enqueueAuthorityFixture(t, s, run, job, tc.kind)
			if _, err := s.GetCloudRunJob(context.Background(), run.TenantID, run.ID); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("expected denial: %v", err)
			}
			if _, err := s.GetCloudRunAuthorization(context.Background(), run.TenantID, run.ID); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("expected denial: %v", err)
			}
		})
	}
}
func TestCloudRunEnqueueRollbackDoesNotPublishAuthority(t *testing.T) {
	s := NewCloudRunStore()
	q := NewJobQueue(&seqIDs{}, nil)
	s.SetQueue(q)
	run, job := cloudAuthorityFixture()
	b, _ := json.Marshal(job)
	err := NewTenantTransactionRunner().Run(context.Background(), run.TenantID, func(ctx context.Context) error {
		if err := s.EnqueueCloudRun(ctx, run, "cspm", b); err != nil {
			return err
		}
		if _, err := s.GetCloudRunJob(ctx, run.TenantID, run.ID); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("uncommitted authority exposed: %v", err)
		}
		return errors.New("abort")
	})
	if err == nil {
		t.Fatal("expected rollback")
	}
	if _, err = s.GetCloudRunJob(context.Background(), run.TenantID, run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("authority remained: %v", err)
	}
	claimed, err := q.Claim(context.Background(), time.Minute)
	if err != nil || claimed != nil {
		t.Fatalf("queue published: %v %v", claimed, err)
	}
	if err := NewTenantTransactionRunner().Run(context.Background(), run.TenantID, func(ctx context.Context) error {
		return s.EnqueueCloudRun(ctx, run, "cspm", b)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCloudRunJob(context.Background(), run.TenantID, run.ID); err != nil {
		t.Fatalf("committed authority unavailable: %v", err)
	}
}

func TestCloudRunTerminalCannotBeResurrectedConcurrently(t *testing.T) {
	s := NewCloudRunStore()
	run, _ := cloudAuthorityFixture()
	if err := s.SaveCloudRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	finished := time.Unix(2, 0)
	terminal := run
	terminal.Status = cloudposture.RunCancelled
	terminal.FinishedAt = &finished
	running := run
	running.Status = cloudposture.RunRunning
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _ = s.SaveCloudRun(context.Background(), running) }()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if err := s.SaveCloudRun(context.Background(), terminal); err != nil {
			t.Errorf("cancel: %v", err)
		}
	}()
	close(start)
	wg.Wait()
	got, err := s.GetCloudRun(context.Background(), run.TenantID, run.ID)
	if err != nil || got.Status != cloudposture.RunCancelled {
		t.Fatalf("terminal state lost: %v %v", got.Status, err)
	}
	if err := s.SaveCloudRun(context.Background(), running); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("late save accepted: %v", err)
	}
	completed := terminal
	completed.Status, completed.Complete = cloudposture.RunSucceeded, true
	if err := s.SaveCloudRun(context.Background(), completed); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("late completion accepted: %v", err)
	}
	if err := s.SaveCloudRun(context.Background(), terminal); err != nil {
		t.Fatalf("idempotent retry rejected: %v", err)
	}
}

func TestCloudRunCompetingTerminalOutcomes(t *testing.T) {
	for i := 0; i < 32; i++ {
		s := NewCloudRunStore()
		run, _ := cloudAuthorityFixture()
		if err := s.SaveCloudRun(context.Background(), run); err != nil {
			t.Fatal(err)
		}
		finished := time.Unix(2, 123456789)
		cancelled := run
		cancelled.Status = cloudposture.RunCancelled
		cancelled.FinishedAt = &finished
		succeeded := cancelled
		succeeded.Status = cloudposture.RunSucceeded
		succeeded.Complete = true
		start := make(chan struct{})
		results := make(chan error, 2)
		go func() { <-start; results <- s.SaveCloudRun(context.Background(), cancelled) }()
		go func() { <-start; results <- s.SaveCloudRun(context.Background(), succeeded) }()
		close(start)
		a, b := <-results, <-results
		if !((a == nil && errors.Is(b, shared.ErrForbidden)) || (b == nil && errors.Is(a, shared.ErrForbidden))) {
			t.Fatalf("terminal outcomes: %v %v", a, b)
		}
		stored, err := s.GetCloudRun(context.Background(), run.TenantID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		retry := stored
		retry.CoverageIssues = []cloudposture.CoverageIssue{}
		retry.EvidenceRefs = []cloudposture.EvidenceReference{}
		if err := s.SaveCloudRun(context.Background(), retry); err != nil {
			t.Fatalf("equivalent retry: %v", err)
		}
		changed := retry
		changed.Findings++
		if err := s.SaveCloudRun(context.Background(), changed); (stored.Status == cloudposture.RunCancelled && !errors.Is(err, shared.ErrForbidden)) || (stored.Status != cloudposture.RunCancelled && err != nil) {
			t.Fatalf("changed terminal outcome: %v", err)
		}
	}
}

func TestCloudRunFailedCanBeCorrectedToSucceeded(t *testing.T) {
	s := NewCloudRunStore()
	run, _ := cloudAuthorityFixture()
	finished := time.Unix(2, 0)
	run.Status, run.FinishedAt, run.ErrorCode = cloudposture.RunFailed, &finished, "failed"
	if err := s.SaveCloudRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	run.Status, run.ErrorCode, run.Complete = cloudposture.RunSucceeded, "", true
	if err := s.SaveCloudRun(context.Background(), run); err != nil {
		t.Fatalf("correction rejected: %v", err)
	}
	got, err := s.GetCloudRun(context.Background(), run.TenantID, run.ID)
	if err != nil || got.Status != cloudposture.RunSucceeded || !got.Complete {
		t.Fatalf("correction missing: %v %v", got.Status, err)
	}
}
