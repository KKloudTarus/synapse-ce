package sbom

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type InventoryWorkState string

const (
	InventoryWorkPending   InventoryWorkState = "pending"
	InventoryWorkRunning   InventoryWorkState = "running"
	InventoryWorkRetry     InventoryWorkState = "retry"
	InventoryWorkCompleted InventoryWorkState = "completed"
	InventoryWorkSkipped   InventoryWorkState = "skipped"
	InventoryWorkPoisoned  InventoryWorkState = "poisoned"
)

func (s InventoryWorkState) Valid() bool {
	switch s {
	case InventoryWorkPending, InventoryWorkRunning, InventoryWorkRetry, InventoryWorkCompleted, InventoryWorkSkipped, InventoryWorkPoisoned:
		return true
	default:
		return false
	}
}

func (s InventoryWorkState) Terminal() bool {
	return s == InventoryWorkCompleted || s == InventoryWorkSkipped || s == InventoryWorkPoisoned
}

type InventoryWork struct {
	Publication   InventoryPublication
	State         InventoryWorkState
	Attempt       int
	Reason        string
	LeaseOwner    string
	LeaseUntil    *time.Time
	NextAttemptAt time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (w InventoryWork) Validate() error {
	if err := w.Publication.Validate(); err != nil {
		return err
	}
	if !w.Publication.Current || !w.State.Valid() || w.Attempt < 0 || w.NextAttemptAt.IsZero() || w.CreatedAt.IsZero() || w.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: invalid inventory correlation work", shared.ErrValidation)
	}
	if w.State == InventoryWorkRunning && (strings.TrimSpace(w.LeaseOwner) == "" || w.LeaseUntil == nil) {
		return fmt.Errorf("%w: running inventory work requires a lease", shared.ErrValidation)
	}
	return nil
}
