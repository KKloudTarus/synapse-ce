package ports

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CloudScope identifies one provider root and a vault credential by reference.
type CloudScope struct {
	EngagementID        shared.ID                `json:"engagement_id"`
	Provider            cloudposture.Provider    `json:"provider"`
	Root                string                   `json:"root"`
	CredentialRef       string                   `json:"credential_ref"`
	ScopeKey            string                   `json:"-"`
	ApprovedTarget      string                   `json:"-"`
	Authorize           CloudOperationAuthorizer `json:"-"`
	EgressExecutionKind string                   `json:"-"`
	EgressExecutionID   string                   `json:"-"`
}

// CloudConnector observes one cloud provider without mutation.
// CloudExpectationSource loads normalized file-side expectations for IaC/live drift.
// CloudOperation identifies one read-only provider request at the execution boundary.
type CloudOperation struct {
	Provider cloudposture.Provider
	ScopeKey string
	Category string
	Name     string
}

// CloudOperationAuthorizer rechecks live engagement authority before every provider request.
type CloudOperationAuthorizer func(context.Context, CloudOperation) error

// AuthorizeCloudOperation fails closed when a connector has no execution guard.
func AuthorizeCloudOperation(ctx context.Context, scope CloudScope, category, name string) error {
	if scope.Authorize == nil {
		return fmt.Errorf("%w: cloud operation authorizer is required", shared.ErrForbidden)
	}
	return scope.Authorize(ctx, CloudOperation{Provider: scope.Provider, ScopeKey: scope.ScopeKey, Category: category, Name: name})
}

type CloudExpectationSource interface {
	Expectations(ctx context.Context, tenantID, engagementID shared.ID) ([]cloudposture.Expectation, []cloudposture.CoverageIssue, error)
}

type CloudConnector interface {
	Enumerate(ctx context.Context, scope CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error)
	Evaluate(ctx context.Context, inventory cloudposture.Inventory) ([]cloudposture.PostureFinding, error)
}

// CloudRunStore persists the secret-free durable CSPM lifecycle.
type CloudRunStore interface {
	SaveCloudRun(context.Context, cloudposture.Run) error
	GetCloudRun(context.Context, shared.ID, shared.ID) (cloudposture.Run, error)
}

// CloudRunEnqueuer atomically persists one queued run and its durable job.
type CloudRunEnqueuer interface {
	EnqueueCloudRun(context.Context, cloudposture.Run, string, []byte) error
}
