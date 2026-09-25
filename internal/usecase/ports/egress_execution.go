package ports

import "context"

// egressExecutionKey scopes an authoritative execution identity to one pipeline run.
type egressExecutionKey struct{}

// EgressExecution names the control-plane record a sandboxed tool's network authorization binds
// to. The sandbox refuses an egress policy without one, and the privileged broker fails closed on
// an authorization it cannot tie back to state, so a tool that reaches the network during a scan
// has to carry the identity of the scan that asked for it.
type EgressExecution struct {
	Kind string
	ID   string
}

// WithEgressExecution binds an execution identity to ctx for the tools run under it.
//
// It travels in the context because the resolvers are built once at composition time and shared
// across concurrent scans: a field on the resolver would be a race, and widening every resolver
// interface would push a transport concern through four ports that otherwise only describe what
// they resolve.
func WithEgressExecution(ctx context.Context, kind, id string) context.Context {
	return context.WithValue(ctx, egressExecutionKey{}, EgressExecution{Kind: kind, ID: id})
}

// EgressExecutionFrom returns the identity bound to ctx, zero when none is. A caller that finds it
// empty must leave the ToolSpec's fields empty too, so the sandbox refuses the run rather than
// reaching the network under an authorization that ties back to nothing.
func EgressExecutionFrom(ctx context.Context) EgressExecution {
	value, _ := ctx.Value(egressExecutionKey{}).(EgressExecution)
	return value
}
