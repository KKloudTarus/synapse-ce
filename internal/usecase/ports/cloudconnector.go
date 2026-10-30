package ports

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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

// CloudRunJob is the original queued execution spec. CredentialRef is a vault
// reference, never credential material.
type CloudRunJob struct {
	TenantID        shared.ID    `json:"tenant_id"`
	RunID           shared.ID    `json:"run_id"`
	EngagementID    shared.ID    `json:"engagement_id"`
	Actor           string       `json:"actor"`
	Scopes          []CloudScope `json:"scopes"`
	ApprovedTargets []string     `json:"approved_targets"`
}

// CloudRunAuthorization is a credential-free view used by the grant issuer.
type CloudRunAuthorization struct {
	Run    cloudposture.Run
	Scopes []CloudRunAuthorizationScope
}

type CloudRunAuthorizationScope struct {
	Provider        cloudposture.Provider
	Root            string
	ApprovedTarget  string
	CredentialBound bool
}

type CloudRunJobReader interface {
	GetCloudRunJob(context.Context, shared.ID, shared.ID) (CloudRunJob, error)
}

type CloudRunAuthorizationReader interface {
	GetCloudRunAuthorization(context.Context, shared.ID, shared.ID) (CloudRunAuthorization, error)
}

// DecodeCloudRunJob validates persisted authority before exposing it to consumers.
func DecodeCloudRunJob(run cloudposture.Run, kind string, payload []byte) (CloudRunJob, error) {
	var job CloudRunJob
	if kind != "cspm" || json.Unmarshal(payload, &job) != nil {
		return CloudRunJob{}, fmt.Errorf("%w: invalid CSPM job", shared.ErrForbidden)
	}
	if run.Validate() != nil || job.TenantID != run.TenantID || job.RunID != run.ID || job.EngagementID != run.EngagementID || strings.TrimSpace(job.Actor) == "" || job.Actor != run.Actor || len(job.Scopes) == 0 || len(job.Scopes) > 32 || len(job.Scopes) != len(job.ApprovedTargets) {
		return CloudRunJob{}, fmt.Errorf("%w: CSPM job identity or scope mismatch", shared.ErrForbidden)
	}
	seen := make(map[string]struct{}, len(job.Scopes))
	for i, scope := range job.Scopes {
		_, key, err := cloudposture.NormalizeRoot(scope.Provider, scope.Root)
		approvedKey, approvedErr := cloudposture.ScopeKey(scope.Provider, job.ApprovedTargets[i])
		if err != nil || approvedErr != nil || key != approvedKey || scope.EngagementID != run.EngagementID || strings.TrimSpace(scope.CredentialRef) == "" {
			return CloudRunJob{}, fmt.Errorf("%w: invalid CSPM job scope", shared.ErrForbidden)
		}
		if _, ok := seen[key]; ok {
			return CloudRunJob{}, fmt.Errorf("%w: duplicate CSPM job scope", shared.ErrForbidden)
		}
		seen[key] = struct{}{}
	}
	return job, nil
}

func CloudAuthorizationFromJob(run cloudposture.Run, job CloudRunJob) CloudRunAuthorization {
	result := CloudRunAuthorization{Run: run, Scopes: make([]CloudRunAuthorizationScope, len(job.Scopes))}
	for i, scope := range job.Scopes {
		result.Scopes[i] = CloudRunAuthorizationScope{Provider: scope.Provider, Root: scope.Root, ApprovedTarget: job.ApprovedTargets[i], CredentialBound: true}
	}
	return result
}
