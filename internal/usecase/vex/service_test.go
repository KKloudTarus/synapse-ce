package vex

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeEngRepo struct {
	ports.EngagementRepository // embedded: only GetByID is exercised
}

func (fakeEngRepo) GetByID(_ context.Context, id shared.ID) (*engagement.Engagement, error) {
	return &engagement.Engagement{ID: id, Status: engagement.StatusActive}, nil
}
func (fakeEngRepo) GetByIDInTenant(_ context.Context, _ shared.ID, id shared.ID) (*engagement.Engagement, error) {
	return &engagement.Engagement{ID: id, Status: engagement.StatusActive}, nil
}
func (fakeEngRepo) GetByProjectID(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return nil, shared.ErrNotFound
}

type fakeRepo struct {
	ports.FindingRepository // embedded: unused methods panic if called
	list                    []finding.Finding
}

func (r *fakeRepo) ListByEngagement(context.Context, shared.ID) ([]finding.Finding, error) {
	return r.list, nil
}
func (r *fakeRepo) UpdateStatus(_ context.Context, eng, id shared.ID, st finding.Status, ver int) (finding.Finding, error) {
	for i := range r.list {
		if r.list[i].ID == id {
			if r.list[i].EngagementID != eng {
				return finding.Finding{}, shared.ErrNotFound
			}
			if r.list[i].Version != ver {
				return finding.Finding{}, shared.ErrConflict
			}
			r.list[i].Status = st
			r.list[i].Version++
			return r.list[i], nil
		}
	}
	return finding.Finding{}, shared.ErrNotFound
}

type nopAudit struct{}

func (nopAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(0, 0).UTC() }

func newSvc(t *testing.T, findings []finding.Finding) (*Service, *fakeRepo) {
	t.Helper()
	repo := &fakeRepo{list: findings}
	svc, err := NewService(fakeEngRepo{}, repo, nopAudit{}, fixedClock{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return svc, repo
}

func TestApplyNotAffectedSuppresses(t *testing.T) {
	svc, repo := newSvc(t, []finding.Finding{
		{ID: "f1", EngagementID: "e1", DedupKey: "vuln:CVE-2020-1:foo:1.2.3", Status: finding.StatusOpen, Version: 1},
	})
	doc := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
		{"vulnerability":{"name":"CVE-2020-1"},"products":[{"@id":"foo@1.2.3"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`)

	res, err := svc.Apply(context.Background(), "alice", "", "e1", doc)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Matched != 1 || res.Applied != 1 {
		t.Fatalf("res = %+v, want matched=1 applied=1", res)
	}
	if repo.list[0].Status != finding.StatusFalsePos {
		t.Errorf("finding status = %s, want false_positive", repo.list[0].Status)
	}
}

func TestApplyFixedMarksRemediatedAndPurlProductMatches(t *testing.T) {
	svc, repo := newSvc(t, []finding.Finding{
		{ID: "f1", EngagementID: "e1", DedupKey: "vuln:CVE-2021-2:lodash:4.17.20", Status: finding.StatusConfirmed, Version: 3},
	})
	// Product carried as a PURL containing the component name.
	doc := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
		{"vulnerability":{"name":"CVE-2021-2"},"products":[{"@id":"pkg:npm/lodash@4.17.20"}],"status":"fixed"}]}`)

	res, err := svc.Apply(context.Background(), "alice", "", "e1", doc)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Applied != 1 || repo.list[0].Status != finding.StatusRemediated {
		t.Fatalf("res=%+v status=%s", res, repo.list[0].Status)
	}
}

func TestApplyNoMatchLeavesFindings(t *testing.T) {
	svc, repo := newSvc(t, []finding.Finding{
		{ID: "f1", EngagementID: "e1", DedupKey: "vuln:CVE-2020-1:foo:1.2.3", Status: finding.StatusOpen, Version: 1},
	})
	doc := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
		{"vulnerability":{"name":"CVE-9999-9"},"products":[{"@id":"bar@1.0.0"}],"status":"not_affected"}]}`)
	res, err := svc.Apply(context.Background(), "alice", "", "e1", doc)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Matched != 0 || res.Applied != 0 || repo.list[0].Status != finding.StatusOpen {
		t.Errorf("unrelated VEX must not touch findings: res=%+v status=%s", res, repo.list[0].Status)
	}
}

type missingEngRepo struct{ ports.EngagementRepository }

func (missingEngRepo) GetByID(context.Context, shared.ID) (*engagement.Engagement, error) {
	return nil, shared.ErrNotFound
}
func (missingEngRepo) GetByIDInTenant(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return nil, shared.ErrNotFound
}
func (missingEngRepo) GetByProjectID(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return nil, shared.ErrNotFound
}

func TestApplyUnknownEngagement404(t *testing.T) {
	svc, err := NewService(missingEngRepo{}, &fakeRepo{}, nopAudit{}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	doc := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"x@1"}],"status":"fixed"}]}`)
	if _, err := svc.Apply(context.Background(), "alice", "", "nope", doc); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a bogus engagement must surface ErrNotFound, got %v", err)
	}
}

func TestApplyRejectsNonVEX(t *testing.T) {
	svc, _ := newSvc(t, nil)
	if _, err := svc.Apply(context.Background(), "alice", "", "e1", []byte(`{"foo":1}`)); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("non-VEX doc: want ErrValidation, got %v", err)
	}
	if _, err := svc.Apply(context.Background(), "alice", "", "e1", []byte(`not json`)); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bad json: want ErrValidation, got %v", err)
	}
}

// rollbackRunner is a transaction runner over the fake repository: it snapshots the finding list
// before the body runs and restores it when the body fails, which is what a real transaction does.
type rollbackRunner struct{ repo *fakeRepo }

func (r rollbackRunner) Run(ctx context.Context, _ shared.ID, fn func(context.Context) error) error {
	before := append([]finding.Finding(nil), r.repo.list...)
	if err := fn(ctx); err != nil {
		r.repo.list = before
		return err
	}
	return nil
}

// failingAudit fails on the nth append, so a test can break the apply part way through.
type failingAudit struct {
	calls  int
	failAt int
}

func (a *failingAudit) Record(context.Context, ports.AuditEntry) error {
	a.calls++
	if a.calls == a.failAt {
		return errors.New("audit chain conflict")
	}
	return nil
}

// TestApplyIsAtomicWhenAuditFails pins the property the code claims: a VEX apply is one unit. An
// audit failure on the second finding must leave the FIRST finding unchanged too, because a finding
// retired as a false positive with no attributable record is exactly what the append-only audit
// chain exists to prevent.
func TestApplyIsAtomicWhenAuditFails(t *testing.T) {
	findings := []finding.Finding{
		{ID: "f1", EngagementID: "e1", DedupKey: "vuln:CVE-2020-1:foo:1.2.3", Status: finding.StatusOpen, Version: 1},
		{ID: "f2", EngagementID: "e1", DedupKey: "vuln:CVE-2020-1:bar:2.0.0", Status: finding.StatusOpen, Version: 1},
	}
	repo := &fakeRepo{list: findings}
	audit := &failingAudit{failAt: 2}
	svc, err := NewService(fakeEngRepo{}, repo, audit, fixedClock{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	svc.SetTransactionRunner(rollbackRunner{repo: repo})

	doc := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
		{"vulnerability":{"name":"CVE-2020-1"},"products":[{"@id":"foo@1.2.3"},{"@id":"bar@2.0.0"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`)

	res, err := svc.Apply(context.Background(), "alice", "", "e1", doc)
	if err == nil {
		t.Fatal("apply returned nil despite an audit failure")
	}
	for i := range repo.list {
		if repo.list[i].Status != finding.StatusOpen {
			t.Errorf("finding %s = %s after a rolled-back apply, want open", repo.list[i].ID, repo.list[i].Status)
		}
	}
	if res.Applied != 0 {
		t.Errorf("result reports %d applied after a rollback; nothing was applied", res.Applied)
	}
}

// TestApplyWithoutATransactionRunnerStillWorks keeps the in-memory and file deployments working:
// the runner is optional, and its absence must not change the outcome of a successful apply.
func TestApplyWithoutATransactionRunnerStillWorks(t *testing.T) {
	svc, repo := newSvc(t, []finding.Finding{
		{ID: "f1", EngagementID: "e1", DedupKey: "vuln:CVE-2020-1:foo:1.2.3", Status: finding.StatusOpen, Version: 1},
	})
	doc := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
		{"vulnerability":{"name":"CVE-2020-1"},"products":[{"@id":"foo@1.2.3"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`)
	if _, err := svc.Apply(context.Background(), "alice", "", "e1", doc); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if repo.list[0].Status != finding.StatusFalsePos {
		t.Errorf("finding status = %s, want false_positive", repo.list[0].Status)
	}
}
