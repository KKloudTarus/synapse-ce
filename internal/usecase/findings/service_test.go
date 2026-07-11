package findings

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var testNow = time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC)

type fakeRepo struct {
	upserted []finding.Finding
	list     []finding.Finding // returned by ListByEngagement (for AddComment scoping)
	called   bool
	got      finding.Status
	gotVer   int
	assignee string
	ret      finding.Finding
	err      error
}

func (f *fakeRepo) Upsert(_ context.Context, fs []finding.Finding) error {
	f.upserted = append(f.upserted, fs...)
	return nil
}
func (f *fakeRepo) ListByEngagement(context.Context, shared.ID) ([]finding.Finding, error) {
	return f.list, nil
}
func (f *fakeRepo) ListPublishableByEngagement(context.Context, shared.ID) ([]finding.Finding, error) {
	return finding.Publishable(f.list), nil
}
func (f *fakeRepo) UpdateStatus(_ context.Context, _, _ shared.ID, st finding.Status, ver int) (finding.Finding, error) {
	f.called, f.got, f.gotVer = true, st, ver
	return f.ret, f.err
}
func (f *fakeRepo) SetAssignee(_ context.Context, _, _ shared.ID, a string, ver int) (finding.Finding, error) {
	f.called, f.assignee, f.gotVer = true, a, ver
	return f.ret, f.err
}

type fakeComments struct {
	added []finding.Comment
	err   error
}

func (c *fakeComments) Add(_ context.Context, cm finding.Comment) error {
	c.added = append(c.added, cm)
	return c.err
}
func (c *fakeComments) ListByEngagementFinding(context.Context, shared.ID, shared.ID) ([]finding.Comment, error) {
	return c.added, nil
}

type fakeRetests struct{ added []finding.Retest }

func (r *fakeRetests) Add(_ context.Context, rt finding.Retest) error {
	r.added = append(r.added, rt)
	return nil
}
func (r *fakeRetests) ListByEngagementFinding(context.Context, shared.ID, shared.ID) ([]finding.Retest, error) {
	return r.added, nil
}

type fakeAudit struct {
	entries []ports.AuditEntry
	err     error
}

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return a.err
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type fakeIDs struct{ n int }

func (g *fakeIDs) NewID() shared.ID { g.n++; return shared.ID("id-" + strconv.Itoa(g.n)) }

func newSvc(repo ports.FindingRepository, comments ports.CommentRepository, audit ports.AuditLogger) *Service {
	return NewService(repo, comments, &fakeRetests{}, audit, fixedClock{t: testNow}, &fakeIDs{})
}

func TestRecordRetest(t *testing.T) {
	repo := &fakeRepo{ret: finding.Finding{ID: "find1", Status: finding.StatusRemediated, Version: 3}}
	retests := &fakeRetests{}
	audit := &fakeAudit{}
	svc := NewService(repo, &fakeComments{}, retests, audit, fixedClock{t: testNow}, &fakeIDs{})

	rt, f, err := svc.RecordRetest(context.Background(), "eng1", "find1", finding.RetestRemediated, "fixed in v2", "alice", 2)
	if err != nil {
		t.Fatalf("record retest: %v", err)
	}
	if len(retests.added) != 1 || rt.Outcome != finding.RetestRemediated || rt.Tester != "alice" {
		t.Fatalf("retest not recorded correctly: %+v", retests.added)
	}
	// Outcome moved the finding to the implied status, via the version it was given.
	if repo.got != finding.StatusRemediated {
		t.Errorf("finding status = %s, want remediated", repo.got)
	}
	if repo.gotVer != 2 {
		t.Errorf("expected version 2 passed to UpdateStatus, got %d", repo.gotVer)
	}
	if f.Status != finding.StatusRemediated {
		t.Errorf("returned finding status = %s", f.Status)
	}

	// An invalid outcome is rejected before any write.
	if _, _, err := svc.RecordRetest(context.Background(), "eng1", "find1", finding.RetestOutcome("bogus"), "", "alice", 2); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("invalid outcome: want ErrValidation, got %v", err)
	}
}

func TestApplyWriteupDraft(t *testing.T) {
	engID, findID := shared.ID("eng1"), shared.ID("find1")

	t.Run("applies composed prose, preserves other fields, audits", func(t *testing.T) {
		repo := &fakeRepo{list: []finding.Finding{{ID: findID, EngagementID: engID, Description: "old", CWE: "CWE-89", Status: finding.StatusConfirmed}}}
		audit := &fakeAudit{}
		svc := newSvc(repo, &fakeComments{}, audit)
		if err := svc.ApplyWriteupDraft(context.Background(), "user:rev", engID, findID, "new desc", "do the fix"); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if len(repo.upserted) != 1 {
			t.Fatalf("expected 1 upsert, got %d", len(repo.upserted))
		}
		got := repo.upserted[0]
		if got.Description != "new desc\n\nRemediation:\ndo the fix" {
			t.Errorf("composed description wrong: %q", got.Description)
		}
		// other fields preserved (the report's per-finding compliance mapping keys off CWE – must be unchanged)
		if got.CWE != "CWE-89" || got.Status != finding.StatusConfirmed {
			t.Errorf("non-description fields must be preserved: %+v", got)
		}
		if n := len(audit.entries); n != 1 || audit.entries[0].Action != "finding.writeup_applied" {
			t.Errorf("expected one finding.writeup_applied audit, got %+v", audit.entries)
		}
	})

	t.Run("cross-engagement / unknown finding → ErrNotFound, no write, no audit", func(t *testing.T) {
		repo := &fakeRepo{list: []finding.Finding{{ID: "other", EngagementID: engID}}} // findID absent from the engagement
		audit := &fakeAudit{}
		svc := newSvc(repo, &fakeComments{}, audit)
		if err := svc.ApplyWriteupDraft(context.Background(), "user:rev", engID, findID, "x", ""); !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("want ErrNotFound for a finding not in the engagement, got %v", err)
		}
		if len(repo.upserted) != 0 {
			t.Error("a cross-engagement / unknown finding must NOT be written")
		}
		if len(audit.entries) != 0 {
			t.Error("a failed apply must not audit")
		}
	})

	t.Run("empty actor → ErrValidation", func(t *testing.T) {
		repo := &fakeRepo{list: []finding.Finding{{ID: findID, EngagementID: engID}}}
		svc := newSvc(repo, &fakeComments{}, &fakeAudit{})
		if err := svc.ApplyWriteupDraft(context.Background(), "  ", engID, findID, "x", ""); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("want ErrValidation for empty actor, got %v", err)
		}
	})
}

func TestUpdateStatus(t *testing.T) {
	engID, findID := shared.ID("eng1"), shared.ID("find1")

	t.Run("rejects unknown status without touching repo or audit", func(t *testing.T) {
		repo, audit := &fakeRepo{}, &fakeAudit{}
		svc := newSvc(repo, &fakeComments{}, audit)
		if _, err := svc.UpdateStatus(context.Background(), engID, findID, "bogus", "", "operator", 1); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation, got %v", err)
		}
		if repo.called || len(audit.entries) != 0 {
			t.Error("invalid status must not touch repo or audit")
		}
	})

	t.Run("applies a valid status, passes version, audits", func(t *testing.T) {
		repo := &fakeRepo{ret: finding.Finding{ID: findID, Status: finding.StatusConfirmed}}
		audit := &fakeAudit{}
		svc := newSvc(repo, &fakeComments{}, audit)
		got, err := svc.UpdateStatus(context.Background(), engID, findID, finding.StatusConfirmed, "looks real", "alice", 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if repo.got != finding.StatusConfirmed || repo.gotVer != 3 || got.Status != finding.StatusConfirmed {
			t.Errorf("status/version not passed: status=%q ver=%d", repo.got, repo.gotVer)
		}
		if len(audit.entries) != 1 || audit.entries[0].Actor != "alice" || audit.entries[0].Action != "finding.status" {
			t.Errorf("audit attribution mismatch: %+v", audit.entries)
		}
		if audit.entries[0].Metadata["note"] != "looks real" || audit.entries[0].Metadata["engagement"] != engID.String() {
			t.Errorf("audit metadata mismatch: %+v", audit.entries[0].Metadata)
		}
	})

	t.Run("propagates a conflict without auditing", func(t *testing.T) {
		repo := &fakeRepo{err: shared.ErrConflict}
		audit := &fakeAudit{}
		svc := newSvc(repo, &fakeComments{}, audit)
		if _, err := svc.UpdateStatus(context.Background(), engID, findID, finding.StatusConfirmed, "", "operator", 1); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("want ErrConflict, got %v", err)
		}
		if len(audit.entries) != 0 {
			t.Error("no audit entry on conflict")
		}
	})

	t.Run("rejects a blank actor", func(t *testing.T) {
		repo, audit := &fakeRepo{}, &fakeAudit{}
		svc := newSvc(repo, &fakeComments{}, audit)
		if _, err := svc.UpdateStatus(context.Background(), engID, findID, finding.StatusConfirmed, "", "  ", 1); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation, got %v", err)
		}
		if repo.called {
			t.Error("blank actor must not touch repo")
		}
	})
}

func TestCreateManual(t *testing.T) {
	engID := shared.ID("eng1")

	t.Run("derives severity from the CVSS vector and persists + audits", func(t *testing.T) {
		repo, audit := &fakeRepo{}, &fakeAudit{}
		svc := newSvc(repo, &fakeComments{}, audit)
		f, err := svc.Create(context.Background(), "alice", engID, finding.ManualInput{
			Title:      "SQLi in login",
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 9.8 critical
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if f.Severity != shared.SeverityCritical {
			t.Errorf("severity = %q, want critical (derived from vector)", f.Severity)
		}
		if f.Kind != finding.KindManual || len(repo.upserted) != 1 {
			t.Errorf("manual finding not persisted: kind=%q upserts=%d", f.Kind, len(repo.upserted))
		}
		if len(audit.entries) != 1 || audit.entries[0].Action != "finding.created" {
			t.Errorf("create not audited: %+v", audit.entries)
		}
	})

	t.Run("rejects a bad CVSS vector", func(t *testing.T) {
		svc := newSvc(&fakeRepo{}, &fakeComments{}, &fakeAudit{})
		if _, err := svc.Create(context.Background(), "a", engID, finding.ManualInput{Title: "x", CVSSVector: "nope"}); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("want ErrValidation, got %v", err)
		}
	})

	t.Run("requires a title", func(t *testing.T) {
		svc := newSvc(&fakeRepo{}, &fakeComments{}, &fakeAudit{})
		if _, err := svc.Create(context.Background(), "a", engID, finding.ManualInput{Severity: shared.SeverityLow}); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("want ErrValidation, got %v", err)
		}
	})
}

func TestSetAssigneeAndComments(t *testing.T) {
	engID, findID := shared.ID("eng1"), shared.ID("find1")

	t.Run("assign audits finding.assigned", func(t *testing.T) {
		repo := &fakeRepo{ret: finding.Finding{ID: findID, Assignee: "bob"}}
		audit := &fakeAudit{}
		svc := newSvc(repo, &fakeComments{}, audit)
		if _, err := svc.SetAssignee(context.Background(), engID, findID, "bob", "alice", 2); err != nil {
			t.Fatalf("assign: %v", err)
		}
		if repo.assignee != "bob" || repo.gotVer != 2 {
			t.Errorf("assignee/version not passed: %q ver=%d", repo.assignee, repo.gotVer)
		}
		if len(audit.entries) != 1 || audit.entries[0].Action != "finding.assigned" {
			t.Errorf("assign not audited: %+v", audit.entries)
		}
	})

	t.Run("comment persists + audits; empty body rejected; cross-engagement denied", func(t *testing.T) {
		comments := &fakeComments{}
		audit := &fakeAudit{}
		// The finding must be in the engagement for a comment to attach.
		repo := &fakeRepo{list: []finding.Finding{{ID: findID, EngagementID: engID}}}
		svc := newSvc(repo, comments, audit)
		if _, err := svc.AddComment(context.Background(), engID, findID, "needs a retest", "alice"); err != nil {
			t.Fatalf("comment: %v", err)
		}
		// A finding not in this engagement is rejected (no cross-engagement comment).
		if _, err := svc.AddComment(context.Background(), engID, "other-finding", "x", "alice"); !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("cross-engagement comment: want ErrNotFound, got %v", err)
		}
		if len(comments.added) != 1 || comments.added[0].Author != "alice" || comments.added[0].Body != "needs a retest" {
			t.Errorf("comment not persisted: %+v", comments.added)
		}
		if len(audit.entries) != 1 || audit.entries[0].Action != "finding.comment" {
			t.Errorf("comment not audited: %+v", audit.entries)
		}
		if _, err := svc.AddComment(context.Background(), engID, findID, "   ", "alice"); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("empty comment: want ErrValidation, got %v", err)
		}
	})
}

// TestEvidenceBarGatesExploitationPromotion wires the previously-dead Finding.CanPromote
// an exploitation/AI finding may not be CONFIRMED until it clears the
// evidence bar (>= 75); other kinds are never gated.
func TestEvidenceBarGatesExploitationPromotion(t *testing.T) {
	engID, findID := shared.ID("eng1"), shared.ID("find1")
	confirm := func(repo *fakeRepo) error {
		svc := newSvc(repo, &fakeComments{}, &fakeAudit{})
		_, err := svc.UpdateStatus(context.Background(), engID, findID, finding.StatusConfirmed, "", "alice", 1)
		return err
	}

	// Below the bar → blocked before the repo is touched.
	low := &fakeRepo{list: []finding.Finding{{ID: findID, Kind: finding.KindExploitation, EvidenceScore: 40}}}
	if err := confirm(low); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("exploitation finding below the bar must not be confirmable, got %v", err)
	}
	if low.called {
		t.Error("the gate must reject BEFORE touching the repo")
	}

	// At/above the bar → allowed.
	high := &fakeRepo{list: []finding.Finding{{ID: findID, Kind: finding.KindExploitation, EvidenceScore: 80}}, ret: finding.Finding{ID: findID, Status: finding.StatusConfirmed}}
	if err := confirm(high); err != nil {
		t.Fatalf("exploitation finding above the bar must be confirmable: %v", err)
	}
	if !high.called {
		t.Error("a passing finding must reach the repo")
	}

	// A non-exploitation finding is never gated, even with score 0.
	manual := &fakeRepo{list: []finding.Finding{{ID: findID, Kind: finding.KindManual, EvidenceScore: 0}}, ret: finding.Finding{ID: findID, Status: finding.StatusConfirmed}}
	if err := confirm(manual); err != nil {
		t.Fatalf("a non-exploitation finding must not be gated: %v", err)
	}
}
