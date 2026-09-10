package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceupload"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type retainedSourceFailure struct {
	ports.AssessmentCycleRequestStore
	fail bool
}

var errSourceRetainedCompletion = errors.New("injected retained source completion failure")

func (s *retainedSourceFailure) CompleteAssessmentCycleRequest(ctx context.Context, scope ports.AssessmentCycleRequestScope, hash string, status int, body []byte, at time.Time) error {
	if s.fail {
		s.fail = false
		return errSourceRetainedCompletion
	}
	return s.AssessmentCycleRequestStore.CompleteAssessmentCycleRequest(ctx, scope, hash, status, body, at)
}

type committedSourceFailure struct {
	ports.TenantTransactionRunner
	fail bool
}

func (s *committedSourceFailure) Run(ctx context.Context, tenant shared.ID, operation func(context.Context) error) error {
	err := s.TenantTransactionRunner.Run(ctx, tenant, operation)
	if err == nil && s.fail {
		s.fail = false
		return ErrTenantCommit // Simulate losing acknowledgement of a real commit.
	}
	return err
}

type trackedSourceObjects struct {
	*blob.Memory
	keys []string
}

func (s *trackedSourceObjects) PutObject(ctx context.Context, key string, data io.Reader, size int64) error {
	s.keys = append(s.keys, key)
	return s.Memory.PutObject(ctx, key, data, size)
}

func (s *trackedSourceObjects) live(t *testing.T, ctx context.Context) int {
	t.Helper()
	count := 0
	for _, key := range s.keys {
		reader, err := s.OpenObject(ctx, key)
		if errors.Is(err, shared.ErrNotFound) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = reader.Close()
		count++
	}
	return count
}

type sourceTransactionFixture struct {
	ctx         context.Context
	tenant      shared.ID
	api         *cycleuc.APIService
	engagements *EngagementRepository
	sources     *sourceupload.Store
	objects     *trackedSourceObjects
	completion  *retainedSourceFailure
	commit      *committedSourceFailure
}

func newSourceTransactionFixture(t *testing.T) *sourceTransactionFixture {
	t.Helper()
	ctx, pool := setupTestDB(t)
	tenant := shared.ID("source-transaction-tenant")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	ctx = shared.WithTenant(ctx, tenant)
	repo := NewEngagementRepository(pool)
	cycles := NewAssessmentCycleRepository(pool)
	transactions := NewTenantTransactionRunner(pool)
	clock, ids, audit := idgen.SystemClock{}, idgen.RandomID{}, assessmentCycleNoopAudit{}
	objects := &trackedSourceObjects{Memory: blob.NewMemory()}
	sources := sourceupload.NewStoreWithRepository(objects, NewEngagementSourceRepository(pool), 0)
	engagements := enguc.NewService(repo, clock, ids, audit)
	engagements.SetSourceStore(sources)
	cycleService, err := cycleuc.NewService(cycles, repo, nil, nil, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	completion := &retainedSourceFailure{AssessmentCycleRequestStore: NewAssessmentCycleRequestRepository(pool)}
	commit := &committedSourceFailure{TenantTransactionRunner: transactions}
	api, err := cycleuc.NewAPIService(cycleService, cycles, completion, engagements, commit, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	return &sourceTransactionFixture{ctx: ctx, tenant: tenant, api: api, engagements: repo, sources: sources, objects: objects, completion: completion, commit: commit}
}

func transactionUpload(data string) *cycleuc.SourceUpload {
	return &cycleuc.SourceUpload{Filename: "source.zip", Size: int64(len(data)), SHA256: sourceDigest([]byte(data)), Reader: bytes.NewBufferString(data)}
}

func (f *sourceTransactionFixture) initial(key string) cycleuc.CreateInitialAssessmentInput {
	return cycleuc.CreateInitialAssessmentInput{Request: cycleuc.RetainedRequest{TenantID: f.tenant, Actor: "alice", Route: "/api/v1/engagements", IdempotencyKey: key}, Engagement: enguc.CreateInput{Name: key}, Source: transactionUpload("source archive A")}
}

func TestPostgresAssessmentSourceAPIRollbackDiscardsOnlyUnpublishedUploads(t *testing.T) {
	f := newSourceTransactionFixture(t)
	f.completion.fail = true
	if _, err := f.api.CreateInitialAssessment(f.ctx, f.initial("initial")); !errors.Is(err, errSourceRetainedCompletion) {
		t.Fatalf("initial completion failure = %v", err)
	}
	if live := f.objects.live(t, f.ctx); live != 0 {
		t.Fatalf("failed initial transaction left %d unpublished source objects", live)
	}
	list, err := f.engagements.List(f.ctx, f.tenant)
	if err != nil || len(list) != 0 {
		t.Fatalf("failed initial retained assessments: %d %v", len(list), err)
	}
	created, err := f.api.CreateInitialAssessment(f.ctx, f.initial("initial"))
	if err != nil {
		t.Fatal(err)
	}
	var root engdom.Engagement
	if err := json.Unmarshal(created.Body, &root); err != nil {
		t.Fatal(err)
	}
	root.Status = engdom.StatusCompleted
	if err := f.engagements.Update(f.ctx, &root); err != nil {
		t.Fatal(err)
	}
	parent, err := f.sources.Get(f.ctx, f.tenant, root.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, strategy := range []string{"upload_new", "reuse_current"} {
		f.completion.fail = true
		input := cycleuc.CreateRetestAssessmentInput{Request: cycleuc.RetainedRequest{TenantID: f.tenant, Actor: "bob", Route: "/api/v1/engagements/" + root.ID.String() + "/retests", IdempotencyKey: strategy}, AssessmentID: root.ID, SourceStrategy: strategy}
		if strategy == "upload_new" {
			input.Source = transactionUpload("source archive B")
		} else {
			input.SourceVersionID = parent.VersionID
		}
		if _, err := f.api.CreateRetestAssessment(f.ctx, input); !errors.Is(err, errSourceRetainedCompletion) {
			t.Fatalf("%s completion failure = %v", strategy, err)
		}
		if live := f.objects.live(t, f.ctx); live != 1 {
			t.Fatalf("%s rollback left %d live archives, want only parent", strategy, live)
		}
		got, err := f.sources.GetByVersion(f.ctx, f.tenant, root.ID, parent.VersionID)
		if err != nil || got != parent {
			t.Fatalf("%s rollback changed parent source: %+v %v", strategy, got, err)
		}
		lifecycle, err := f.api.GetLifecycle(f.ctx, f.tenant, root.ID)
		if err != nil || len(lifecycle.Members) != 1 || lifecycle.Cycle.Version != 1 {
			t.Fatalf("%s rollback changed cycle: %+v %v", strategy, lifecycle, err)
		}
	}
}

func TestPostgresAssessmentSourceAPIUnknownCommitRetainsReplayAndArchive(t *testing.T) {
	f := newSourceTransactionFixture(t)
	f.commit.fail = true
	if _, err := f.api.CreateInitialAssessment(f.ctx, f.initial("unknown-commit")); !errors.Is(err, ErrTenantCommit) {
		t.Fatalf("simulated lost commit acknowledgement = %v", err)
	}
	if live := f.objects.live(t, f.ctx); live != 1 {
		t.Fatalf("unknown successful commit retained %d archive objects", live)
	}
	replayed, err := f.api.CreateInitialAssessment(f.ctx, f.initial("unknown-commit"))
	if err != nil || !replayed.Replayed || replayed.StatusCode != 201 {
		t.Fatalf("unknown commit replay = %+v %v", replayed, err)
	}
	var root engdom.Engagement
	if err := json.Unmarshal(replayed.Body, &root); err != nil {
		t.Fatal(err)
	}
	item, err := f.sources.Get(f.ctx, f.tenant, root.ID)
	if err != nil || item.VersionID.IsZero() || len(f.objects.keys) != 1 {
		t.Fatalf("replay lost source or uploaded twice: %+v %v count=%d", item, err, len(f.objects.keys))
	}
	reader, err := f.objects.OpenObject(f.ctx, item.ObjectKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(data) != "source archive A" {
		t.Fatalf("retained source = %q %v", data, err)
	}
}
