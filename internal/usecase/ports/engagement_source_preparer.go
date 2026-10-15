package ports

import (
	"context"
	"io"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
)

// EngagementSourcePreparer separates external archive preparation from the
// metadata binding that must share an engagement lifecycle transaction.
// Prepared packages are immutable. Bind persists only their validated metadata.
type EngagementSourcePreparer interface {
	Prepare(ctx context.Context, tenantID, engagementID shared.ID, filename, actor string, at time.Time, size int64, sha256hex string, src io.Reader) (sourcepackage.Package, error)
	PrepareReuse(ctx context.Context, tenantID, parentEngagementID, childEngagementID, expectedVersionID shared.ID, actor string, at time.Time) (sourcepackage.Package, error)
	Bind(ctx context.Context, item sourcepackage.Package) (sourcepackage.Package, error)
}
