package ports

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// PartialWriteError reports an incomplete follow-up after the listed records were persisted.
type PartialWriteError struct {
	Operation string
	IDs       []shared.ID
	Err       error
}

func (e *PartialWriteError) Error() string {
	return fmt.Sprintf("%s persisted %v but follow-up needs repair: %v", e.Operation, e.IDs, e.Err)
}

func (e *PartialWriteError) Unwrap() error { return e.Err }
