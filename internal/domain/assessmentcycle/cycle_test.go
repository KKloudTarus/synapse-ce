package assessmentcycle_test

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNewAssessmentCycle(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	tenantID := shared.ID("tenant-1")
	cycleID := shared.ID("cycle-1")
	rootID := shared.ID("root-1")

	t.Run("valid standalone cycle", func(t *testing.T) {
		c, err := assessmentcycle.NewAssessmentCycle(
			cycleID, tenantID, "Cycle Alpha",
			assessmentcycle.BoundaryStandalone,
			"", "",
			rootID, "alice", now,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Status != assessmentcycle.StatusOpen {
			t.Errorf("status = %v, want %v", c.Status, assessmentcycle.StatusOpen)
		}
		if c.RootAssessmentID != rootID {
			t.Errorf("root = %v, want %v", c.RootAssessmentID, rootID)
		}
		if c.SelectedHeadAssessmentID != rootID {
			t.Errorf("selected head = %v, want %v", c.SelectedHeadAssessmentID, rootID)
		}
		if c.NextRetestNumber != 1 {
			t.Errorf("nextRetestNumber = %d, want 1", c.NextRetestNumber)
		}
		if c.Version != 1 {
			t.Errorf("version = %d, want 1", c.Version)
		}
	})

	t.Run("invalid missing fields", func(t *testing.T) {
		_, err := assessmentcycle.NewAssessmentCycle("", tenantID, "Name", assessmentcycle.BoundaryStandalone, "", "", rootID, "op", now)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation for empty ID, got %v", err)
		}

		_, err = assessmentcycle.NewAssessmentCycle(cycleID, "", "Name", assessmentcycle.BoundaryStandalone, "", "", rootID, "op", now)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation for empty tenant, got %v", err)
		}

		_, err = assessmentcycle.NewAssessmentCycle(cycleID, tenantID, "Name", assessmentcycle.BoundaryStandalone, "", "", "", "op", now)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation for empty root, got %v", err)
		}

		_, err = assessmentcycle.NewAssessmentCycle(cycleID, tenantID, "", assessmentcycle.BoundaryStandalone, "", "", rootID, "op", now)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation for empty name, got %v", err)
		}
	})
}

func TestAssessmentCycleLifecycleTransitions(t *testing.T) {
	now := time.Now().UTC()
	c, err := assessmentcycle.NewAssessmentCycle(
		"c-1", "t-1", "Cycle",
		assessmentcycle.BoundaryStandalone, "", "",
		"root-1", "alice", now,
	)
	if err != nil {
		t.Fatal(err)
	}

	// open -> completed
	if err := c.Transition(assessmentcycle.StatusCompleted, c.Version, "alice", now); err != nil {
		t.Fatalf("open -> completed: %v", err)
	}
	if c.Status != assessmentcycle.StatusCompleted || c.Version != 2 {
		t.Fatalf("status = %v, version = %d", c.Status, c.Version)
	}

	// completed -> open (reopen)
	if err := c.Transition(assessmentcycle.StatusOpen, c.Version, "alice", now); err != nil {
		t.Fatalf("completed -> open: %v", err)
	}
	if c.Status != assessmentcycle.StatusOpen || c.Version != 3 {
		t.Fatalf("status = %v, version = %d", c.Status, c.Version)
	}

	// open -> archived
	if err := c.Transition(assessmentcycle.StatusArchived, c.Version, "alice", now); err != nil {
		t.Fatalf("open -> archived: %v", err)
	}
	if c.Status != assessmentcycle.StatusArchived || c.Version != 4 {
		t.Fatalf("status = %v, version = %d", c.Status, c.Version)
	}

	// archived -> terminal (cannot transition away)
	if err := c.Transition(assessmentcycle.StatusOpen, c.Version, "alice", now); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation from archived -> open, got %v", err)
	}
	if err := c.Transition(assessmentcycle.StatusCompleted, c.Version, "alice", now); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation from archived -> completed, got %v", err)
	}
}

func TestAssessmentCycleCASConflict(t *testing.T) {
	now := time.Now().UTC()
	c, _ := assessmentcycle.NewAssessmentCycle(
		"c-1", "t-1", "Cycle",
		assessmentcycle.BoundaryStandalone, "", "",
		"root-1", "alice", now,
	)

	// Version is 1, expect 99
	err := c.Transition(assessmentcycle.StatusCompleted, 99, "alice", now)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestAssessmentCycleAdvanceRetest(t *testing.T) {
	now := time.Now().UTC()
	c, _ := assessmentcycle.NewAssessmentCycle(
		"c-1", "t-1", "Cycle",
		assessmentcycle.BoundaryStandalone, "", "",
		"root-1", "alice", now,
	)

	// 1. Create Retest 1 from Root (which is currently selected head)
	num1, err := c.AdvanceRetest("retest-1", "root-1", c.Version, "alice", now)
	if err != nil {
		t.Fatalf("advance retest 1: %v", err)
	}
	if num1 != 1 {
		t.Errorf("allocated number = %d, want 1", num1)
	}
	if c.SelectedHeadAssessmentID != "retest-1" {
		t.Errorf("selected head = %v, want retest-1", c.SelectedHeadAssessmentID)
	}
	if c.NextRetestNumber != 2 {
		t.Errorf("nextRetestNumber = %d, want 2", c.NextRetestNumber)
	}

	// 2. Create Retest 2 from Retest 1 (selected head advances again)
	num2, err := c.AdvanceRetest("retest-2", "retest-1", c.Version, "alice", now)
	if err != nil {
		t.Fatalf("advance retest 2: %v", err)
	}
	if num2 != 2 {
		t.Errorf("allocated number = %d, want 2", num2)
	}
	if c.SelectedHeadAssessmentID != "retest-2" {
		t.Errorf("selected head = %v, want retest-2", c.SelectedHeadAssessmentID)
	}

	// 3. Create Retest 3 from Retest 1 (BRANCH - predecessor is NOT selected head)
	num3, err := c.AdvanceRetest("retest-3", "retest-1", c.Version, "alice", now)
	if err != nil {
		t.Fatalf("advance retest 3: %v", err)
	}
	if num3 != 3 {
		t.Errorf("allocated number = %d, want 3", num3)
	}
	// Selected head MUST REMAIN retest-2
	if c.SelectedHeadAssessmentID != "retest-2" {
		t.Errorf("branch creation modified selected head! got %v, want retest-2", c.SelectedHeadAssessmentID)
	}
}

func TestAssessmentCycleSelectHead(t *testing.T) {
	now := time.Now().UTC()
	c, _ := assessmentcycle.NewAssessmentCycle(
		"c-1", "t-1", "Cycle",
		assessmentcycle.BoundaryStandalone, "", "",
		"root-1", "alice", now,
	)

	// Explicitly select another head
	if err := c.SelectHead("retest-3", c.Version, "alice", now); err != nil {
		t.Fatalf("select head: %v", err)
	}
	if c.SelectedHeadAssessmentID != "retest-3" {
		t.Errorf("selected head = %v, want retest-3", c.SelectedHeadAssessmentID)
	}

	// Cannot select head if cycle is completed
	_ = c.Transition(assessmentcycle.StatusCompleted, c.Version, "alice", now)
	if err := c.SelectHead("root-1", c.Version, "alice", now); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation on completed cycle, got %v", err)
	}
}
