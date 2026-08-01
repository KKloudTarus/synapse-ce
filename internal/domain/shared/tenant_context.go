package shared

import "context"

type tenantContextKey struct{}

// WithTenant binds the authenticated or durable-job tenant to a context. The
// empty value is the existing default tenant; a missing value is distinguishable
// through TenantFrom and must not be treated as a wildcard.
func WithTenant(ctx context.Context, tenantID ID) context.Context {
	return context.WithValue(ctx, tenantContextKey{}, tenantID)
}

// TenantFrom returns the context tenant and whether a caller explicitly bound
// one. A missing context is unsafe for RLS-backed persistence.
func TenantFrom(ctx context.Context) (ID, bool) {
	tenantID, ok := ctx.Value(tenantContextKey{}).(ID)
	return tenantID, ok
}
