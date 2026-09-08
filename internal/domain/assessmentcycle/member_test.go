package assessmentcycle_test

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestMemberConstructorsAndValidation(t *testing.T) {
	now := time.Now().UTC()
	tenantID := shared.ID("t-1")
	cycleID := shared.ID("c-1")
	rootID := shared.ID("root-1")
	retestID := shared.ID("retest-1")

	t.Run("initial root member valid", func(t *testing.T) {
		m, err := assessmentcycle.NewInitialMember(tenantID, cycleID, rootID, "alice", now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !m.IsRoot() {
			t.Fatal("expected IsRoot() to be true")
		}
		if m.RetestNumber != 0 {
			t.Errorf("retestNumber = %d, want 0", m.RetestNumber)
		}
		if !m.PredecessorAssessmentID.IsZero() {
			t.Errorf("predecessor = %v, want empty", m.PredecessorAssessmentID)
		}
		if m.RelationshipVersion != 1 {
			t.Errorf("relationshipVersion = %d, want 1", m.RelationshipVersion)
		}
	})

	t.Run("retest member valid", func(t *testing.T) {
		m, err := assessmentcycle.NewRetestMember(tenantID, cycleID, retestID, rootID, 1, "alice", now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m.IsRoot() {
			t.Fatal("expected IsRoot() to be false")
		}
		if m.RetestNumber != 1 {
			t.Errorf("retestNumber = %d, want 1", m.RetestNumber)
		}
		if m.PredecessorAssessmentID != rootID {
			t.Errorf("predecessor = %v, want %v", m.PredecessorAssessmentID, rootID)
		}
	})

	t.Run("invalid member invariants", func(t *testing.T) {
		// Retest with self predecessor
		_, err := assessmentcycle.NewRetestMember(tenantID, cycleID, retestID, retestID, 1, "alice", now)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation for self predecessor, got %v", err)
		}

		// Retest with 0 retest number
		_, err = assessmentcycle.NewRetestMember(tenantID, cycleID, retestID, rootID, 0, "alice", now)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation for 0 retest number, got %v", err)
		}

		// Retest with empty predecessor
		_, err = assessmentcycle.NewRetestMember(tenantID, cycleID, retestID, "", 1, "alice", now)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation for empty predecessor, got %v", err)
		}
	})
}

func TestMemberArchiveAndReparent(t *testing.T) {
	now := time.Now().UTC()
	tenantID := shared.ID("t-1")
	cycleID := shared.ID("c-1")

	root, _ := assessmentcycle.NewInitialMember(tenantID, cycleID, "root", "alice", now)
	retest1, _ := assessmentcycle.NewRetestMember(tenantID, cycleID, "retest-1", "root", 1, "alice", now)

	t.Run("cannot archive root", func(t *testing.T) {
		err := root.Archive(root.RelationshipVersion, now)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation archiving root, got %v", err)
		}
	})

	t.Run("cannot reparent root", func(t *testing.T) {
		err := root.Reparent("retest-1", root.RelationshipVersion)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation reparenting root, got %v", err)
		}
	})

	t.Run("reparent retest member", func(t *testing.T) {
		err := retest1.Reparent("other-parent", retest1.RelationshipVersion)
		if err != nil {
			t.Fatalf("reparent: %v", err)
		}
		if retest1.PredecessorAssessmentID != "other-parent" || retest1.RelationshipVersion != 2 {
			t.Fatalf("predecessor = %v, version = %d", retest1.PredecessorAssessmentID, retest1.RelationshipVersion)
		}
	})

	t.Run("archive retest member", func(t *testing.T) {
		err := retest1.Archive(retest1.RelationshipVersion, now)
		if err != nil {
			t.Fatalf("archive: %v", err)
		}
		if !retest1.IsArchived() || retest1.RelationshipVersion != 3 {
			t.Fatalf("archived = %v, version = %d", retest1.IsArchived(), retest1.RelationshipVersion)
		}

		// Cannot reparent archived member
		err = retest1.Reparent("root", retest1.RelationshipVersion)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation reparenting archived member, got %v", err)
		}
	})
}

func TestMemberGraphHelpers(t *testing.T) {
	now := time.Now().UTC()
	tenantID := shared.ID("t-1")
	cycleID := shared.ID("c-1")

	// Graph:
	// root (0)
	//   ├── A (1)
	//   │    └── B (2)
	//   └── C (3)
	//        └── D (4)
	root, _ := assessmentcycle.NewInitialMember(tenantID, cycleID, "root", "alice", now)
	mA, _ := assessmentcycle.NewRetestMember(tenantID, cycleID, "A", "root", 1, "alice", now)
	mB, _ := assessmentcycle.NewRetestMember(tenantID, cycleID, "B", "A", 2, "alice", now)
	mC, _ := assessmentcycle.NewRetestMember(tenantID, cycleID, "C", "root", 3, "alice", now)
	mD, _ := assessmentcycle.NewRetestMember(tenantID, cycleID, "D", "C", 4, "alice", now)

	members := []assessmentcycle.Member{*root, *mA, *mB, *mC, *mD}

	t.Run("DeriveBranchHeads", func(t *testing.T) {
		heads := assessmentcycle.DeriveBranchHeads(members)
		if len(heads) != 2 {
			t.Fatalf("expected 2 branch heads, got %d", len(heads))
		}
		if heads[0].AssessmentID != "B" || heads[1].AssessmentID != "D" {
			t.Fatalf("branch heads = [%v, %v], want [B, D]", heads[0].AssessmentID, heads[1].AssessmentID)
		}
	})

	t.Run("DeriveBranchHeads with archived leaf", func(t *testing.T) {
		mDArchived := *mD
		_ = mDArchived.Archive(mDArchived.RelationshipVersion, now)
		membersArchived := []assessmentcycle.Member{*root, *mA, *mB, *mC, mDArchived}

		// When D is archived, C becomes an active leaf (branch head)
		heads := assessmentcycle.DeriveBranchHeads(membersArchived)
		if len(heads) != 2 {
			t.Fatalf("expected 2 branch heads, got %d", len(heads))
		}
		if heads[0].AssessmentID != "B" || heads[1].AssessmentID != "C" {
			t.Fatalf("branch heads = [%v, %v], want [B, C]", heads[0].AssessmentID, heads[1].AssessmentID)
		}
	})

	t.Run("DeriveAncestors", func(t *testing.T) {
		ancestors, err := assessmentcycle.DeriveAncestors(members, "B")
		if err != nil {
			t.Fatalf("derive ancestors: %v", err)
		}
		if len(ancestors) != 2 {
			t.Fatalf("expected 2 ancestors, got %d", len(ancestors))
		}
		if ancestors[0].AssessmentID != "A" || ancestors[1].AssessmentID != "root" {
			t.Fatalf("ancestors of B = [%v, %v], want [A, root]", ancestors[0].AssessmentID, ancestors[1].AssessmentID)
		}
	})

	t.Run("DeriveDescendants", func(t *testing.T) {
		descendants, err := assessmentcycle.DeriveDescendants(members, "root")
		if err != nil {
			t.Fatalf("derive descendants: %v", err)
		}
		if len(descendants) != 4 {
			t.Fatalf("expected 4 descendants, got %d", len(descendants))
		}
		if descendants[0].AssessmentID != "A" || descendants[1].AssessmentID != "B" || descendants[2].AssessmentID != "C" || descendants[3].AssessmentID != "D" {
			t.Fatalf("descendants of root = %v", descendants)
		}
	})

	t.Run("IsAncestor", func(t *testing.T) {
		ok, err := assessmentcycle.IsAncestor(members, "root", "B")
		if err != nil || !ok {
			t.Fatalf("expected root to be ancestor of B, got ok=%v, err=%v", ok, err)
		}

		ok, err = assessmentcycle.IsAncestor(members, "A", "B")
		if err != nil || !ok {
			t.Fatalf("expected A to be ancestor of B, got ok=%v, err=%v", ok, err)
		}

		ok, err = assessmentcycle.IsAncestor(members, "B", "A")
		if err != nil || ok {
			t.Fatalf("expected B NOT to be ancestor of A, got ok=%v, err=%v", ok, err)
		}

		ok, err = assessmentcycle.IsAncestor(members, "C", "B")
		if err != nil || ok {
			t.Fatalf("expected C NOT to be ancestor of B, got ok=%v, err=%v", ok, err)
		}
	})
}
