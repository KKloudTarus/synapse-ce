package docpublish

import (
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Source identifies stored report data independently of its delivery destination.
// Email and Confluence use the same source renderer and current release policy.
type Source struct {
	SourceKind SourceKind
	SourceRef  string
	Scope      Scope
	ScopeID    shared.ID
}

func (s Source) Validate() error {
	scope, ok := s.SourceKind.Scope()
	if !ok || scope != s.Scope || s.ScopeID.IsZero() || !bounded(s.SourceRef, maxSourceRefBytes) {
		return fmt.Errorf("%w: invalid document source", shared.ErrValidation)
	}
	return nil
}
func (t Target) Source() Source {
	return Source{SourceKind: t.SourceKind, SourceRef: t.SourceRef, Scope: t.Scope, ScopeID: t.ScopeID}
}
