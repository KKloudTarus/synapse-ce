package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// PrivacyPolicyResolver authenticates source-redaction content identities against
// immutable tenant history. Delayed telemetry may reference an inactive policy.
type PrivacyPolicyResolver interface {
	PrivacyPolicyByDigest(
		ctx context.Context,
		tenantID shared.ID,
		digest string,
	) (privacy.Assignment, error)
}

// PrivacyPolicyStore persists immutable tenant policy versions and a mutable
// active pointer. Historical digests remain resolvable for delayed telemetry.
type PrivacyPolicyStore interface {
	PrivacyPolicyResolver
	PutPrivacyPolicy(
		ctx context.Context,
		assignment privacy.Assignment,
	) (created bool, err error)
	ActivatePrivacyPolicy(
		ctx context.Context,
		activation privacy.Activation,
	) (privacy.Activation, error)
	ActivePrivacyPolicy(ctx context.Context, tenantID shared.ID) (privacy.Assignment, error)
	PrivacyPolicyHistory(ctx context.Context, tenantID shared.ID) ([]privacy.Assignment, error)
	PrivacyPolicyActivationHistory(ctx context.Context, tenantID shared.ID) ([]privacy.Activation, error)
}
