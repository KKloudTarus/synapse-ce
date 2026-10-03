package ports

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"time"
)

type IdentityAPIKeyAuthentication interface {
	AuthenticateIdentityAPIKey(context.Context, string, time.Time, time.Duration) (authz.Principal, error)
}
