package ports

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// UserChoice deliberately excludes email, contacts and credential metadata.
type UserChoice struct {
	ID   shared.ID `json:"id"`
	Name string    `json:"name"`
	Role string    `json:"role"`
}
type UserPickerReader interface {
	ListUserChoices(context.Context, shared.ID, shared.ID, string, shared.ID, int) ([]UserChoice, error)
}
