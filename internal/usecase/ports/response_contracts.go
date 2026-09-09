package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ResponseCommandSigner signs bounded fleet response and halt commands.
type ResponseCommandSigner interface {
	Sign(fleetagent.ResponseCommand) (fleetagent.ResponseCommand, error)
	SignHalt(fleetagent.ResponseHaltCommand) (fleetagent.ResponseHaltCommand, error)
}

// ResponseExecutor is the governed response execution boundary.
type ResponseExecutor interface {
	Identity() string
	Supports(rdom.Kind) bool
	ResolveAgent(context.Context, shared.ID, responsesaga.TargetFingerprint) (shared.ID, error)
	Halt(context.Context, shared.ID, int64) error
	Execute(context.Context, ResponseExecRequest) (ResponseExecOutcome, error)
}

type ResponseExecRequest struct {
	TenantID              shared.ID
	EngagementID          shared.ID
	ActionID              shared.ID
	AgentID               shared.ID
	Action                rdom.Action
	Argv                  []string
	Target                shared.ID
	Fingerprint           responsesaga.TargetFingerprint
	AuthorizationTarget   engagement.Target
	IdempotencyKey        string
	Declared              offensivepolicy.Radius
	IsReversal            bool
	HaltGeneration        int64
	VerificationChallenge string
	IssuedAt              time.Time
	DeadlineAt            time.Time
}

type ResponseExecOutcome struct {
	ObservedRadius         offensivepolicy.Radius
	AffectedCount          int
	AlreadyApplied         bool
	EnforcedHaltGeneration int64
}

type ResponseObservationDispatcher interface {
	EnsureObservation(context.Context, ResponseVerificationRequest) error
}

type ResponseVerificationRequest struct {
	TenantID              shared.ID
	EngagementID          shared.ID
	Action                rdom.Action
	Target                responsesaga.TargetFingerprint
	ExecutorID            string
	ExecutorAgentID       shared.ID
	Reversal              bool
	AttemptKey            string
	VerificationChallenge string
	AttemptedAt           time.Time
	DeadlineAt            time.Time
}

// ResponseActuator is the narrow endpoint side-effect boundary.
type ResponseActuator interface {
	ExecuteResponse(context.Context, fleetagent.ResponseCommand) (ResponseActuatorOutcome, error)
}

type ResponseActuatorOutcome struct {
	ObservedRadius offensivepolicy.Radius
	AffectedCount  int
	AlreadyApplied bool
}

// FleetWorkIssueInput is the transport-neutral work-order issuance DTO.
type FleetWorkIssueInput struct {
	TenantID        shared.ID
	AssetID         shared.ID
	AgentID         shared.ID
	Capability      string
	AuthorizationID shared.ID
	IdempotencyKey  string
	NotAfter        time.Time
	TimeBucket      int64
	ResponseCommand *fleetagent.ResponseCommand
	ResponseHalt    *fleetagent.ResponseHaltCommand
	ResponseObserve *fleetagent.ResponseObservationRequest
}
