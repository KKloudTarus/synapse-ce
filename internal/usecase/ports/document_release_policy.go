package ports

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CheckDocumentSource rechecks source ownership, lifecycle, current external
// detail policy and all applicable engagement legal holds. Missing facts refuse.
type DocumentSourceReleaseReader interface {
	CheckDocumentSource(context.Context, shared.ID, docpublish.Target) error
}

// DocumentReportReleaseReader applies the identical source controls when no
// remote document target exists, as for an email delivery.
type DocumentReportReleaseReader interface {
	CheckReportSource(context.Context, shared.ID, docpublish.Source) error
}
