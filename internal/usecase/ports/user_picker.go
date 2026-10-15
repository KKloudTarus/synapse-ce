package ports

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// UserChoice deliberately excludes email, contacts and credential metadata.
type UserChoice struct {
	ID   shared.ID `json:"id"`
	Name string    `json:"name"`
}
type UserPickerReader interface {
	ListUserChoices(context.Context, shared.ID, shared.ID, string, shared.ID, int) ([]UserChoice, error)
}

// MentionChoiceReader lists the active human viewers that may be selected as
// canonical finding-comment mentions. It is deliberately separate from the
// assignee picker: a viewer may be notified without being eligible to own a
// finding.
type MentionChoiceReader interface {
	ListMentionChoices(context.Context, shared.ID, shared.ID, string, shared.ID, int) ([]UserChoice, error)
}
