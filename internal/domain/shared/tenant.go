package shared

import "context"

type tenantContextKey struct{}

// WithTenant binds an authenticated or durable-job tenant to ctx.
func WithTenant(ctx context.Context, tenantID ID) context.Context {
	return context.WithValue(ctx, tenantContextKey{}, TenantOrDefault(tenantID))
}

// TenantFrom returns the explicitly bound tenant. Missing context is unsafe for RLS persistence.
func TenantFrom(ctx context.Context) (ID, bool) {
	tenantID, ok := ctx.Value(tenantContextKey{}).(ID)
	return tenantID, ok && !tenantID.IsZero()
}
