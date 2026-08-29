package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const privacyPolicyBodyCap = 64 << 10

type privacyPolicyDTO struct {
	Dispositions  map[string]string `json:"dispositions"`
	RedactSecrets bool              `json:"redact_secrets"`
	MaxArgLen     int               `json:"max_arg_len"`
	MaxArgCount   int               `json:"max_arg_count"`
	MaxPathLen    int               `json:"max_path_len"`
	HashSalt      string            `json:"hash_salt,omitempty"`
	Version       string            `json:"version"`
}

type privacyPolicyAdmissionRequest struct {
	Policy privacyPolicyDTO `json:"policy"`
}

type privacyPolicyActivationRequest struct {
	Digest      string    `json:"digest"`
	OperationID shared.ID `json:"operation_id"`
}

type privacyPolicyAssignmentResponse struct {
	TenantID  string           `json:"tenant_id"`
	Policy    privacyPolicyDTO `json:"policy"`
	Digest    string           `json:"digest"`
	CreatedBy string           `json:"created_by"`
	CreatedAt time.Time        `json:"created_at"`
}

type privacyPolicyAdmissionResponse struct {
	Assignment privacyPolicyAssignmentResponse `json:"assignment"`
	Created    bool                            `json:"created"`
}

type privacyPolicyAssignmentEnvelope struct {
	Assignment privacyPolicyAssignmentResponse `json:"assignment"`
}

type privacyPolicyHistoryResponse struct {
	Assignments []privacyPolicyAssignmentResponse `json:"assignments"`
}

func (dto privacyPolicyDTO) domain() privacy.Policy {
	dispositions := make(map[privacy.FieldCategory]privacy.FieldDisposition, len(dto.Dispositions))
	for category, disposition := range dto.Dispositions {
		dispositions[privacy.FieldCategory(category)] = privacy.FieldDisposition(disposition)
	}
	return privacy.Policy{
		Dispositions:  dispositions,
		RedactSecrets: dto.RedactSecrets,
		MaxArgLen:     dto.MaxArgLen,
		MaxArgCount:   dto.MaxArgCount,
		MaxPathLen:    dto.MaxPathLen,
		HashSalt:      dto.HashSalt,
		Version:       dto.Version,
	}
}

// newPrivacyPolicyDTO renders a policy WITHOUT its hash salt, for the human plane.
//
// SECURITY (Rule 3): HashSalt is what makes DispositionHash pseudonymization resistant
// to dictionary/rainbow attacks over low-entropy telemetry (usernames, paths, comm). A
// human principal who can read hashed telemetry and also learn the salt can
// de-anonymize it offline, so the salt never travels the human read plane — not even to
// the actor who admitted the policy, since history and the active pointer expose
// policies other actors authored. Only the agent plane receives it, and only because
// agents must hash at the source. The digest still identifies the policy exactly, so
// governance callers lose no ability to audit which policy is in force.
func newPrivacyPolicyDTO(policy privacy.Policy) privacyPolicyDTO {
	dto := newAgentPrivacyPolicyDTO(policy)
	dto.HashSalt = ""
	return dto
}

// newAgentPrivacyPolicyDTO renders a policy INCLUDING its hash salt, for the
// agent-authenticated plane only (see fleetRouter.activePrivacyPolicy). An agent
// applies source privacy before the telemetry ever leaves the host, so it genuinely
// needs the salt; that route is agent-credentialed and tenant-checked.
func newAgentPrivacyPolicyDTO(policy privacy.Policy) privacyPolicyDTO {
	dispositions := make(map[string]string, len(policy.Dispositions))
	for category, disposition := range policy.Dispositions {
		dispositions[string(category)] = string(disposition)
	}
	return privacyPolicyDTO{
		Dispositions:  dispositions,
		RedactSecrets: policy.RedactSecrets,
		MaxArgLen:     policy.MaxArgLen,
		MaxArgCount:   policy.MaxArgCount,
		MaxPathLen:    policy.MaxPathLen,
		HashSalt:      policy.HashSalt,
		Version:       policy.Version,
	}
}

// newPrivacyPolicyAssignmentResponse builds the human-plane response (no hash salt).
func newPrivacyPolicyAssignmentResponse(assignment privacy.Assignment) privacyPolicyAssignmentResponse {
	return privacyPolicyAssignmentResponse{
		TenantID:  assignment.TenantID.String(),
		Policy:    newPrivacyPolicyDTO(assignment.Policy),
		Digest:    assignment.Digest,
		CreatedBy: assignment.CreatedBy,
		CreatedAt: assignment.CreatedAt,
	}
}

// newAgentPrivacyPolicyAssignmentResponse builds the agent-plane response, which carries
// the hash salt because the agent redacts at the source.
func newAgentPrivacyPolicyAssignmentResponse(assignment privacy.Assignment) privacyPolicyAssignmentResponse {
	return privacyPolicyAssignmentResponse{
		TenantID:  assignment.TenantID.String(),
		Policy:    newAgentPrivacyPolicyDTO(assignment.Policy),
		Digest:    assignment.Digest,
		CreatedBy: assignment.CreatedBy,
		CreatedAt: assignment.CreatedAt,
	}
}

type privacyPolicyService interface {
	Admit(ctx context.Context, actor string, policy privacy.Policy) (privacy.Assignment, bool, error)
	Activate(ctx context.Context, actor, digest string, operationID shared.ID) (privacy.Assignment, error)
	Active(ctx context.Context) (privacy.Assignment, error)
	History(ctx context.Context) ([]privacy.Assignment, error)
}

// SetPrivacyPolicyService wires tenant privacy-policy governance on the human RBAC plane.
func (rt *Router) SetPrivacyPolicyService(service privacyPolicyService) {
	rt.privacyPolicies = service
}

func (rt *Router) admitPrivacyPolicy(w http.ResponseWriter, r *http.Request) {
	var body privacyPolicyAdmissionRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, privacyPolicyBodyCap))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	assignment, created, err := rt.privacyPolicies.Admit(
		r.Context(),
		PrincipalFrom(r.Context()),
		body.Policy.domain(),
	)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, privacyPolicyAdmissionResponse{
		Assignment: newPrivacyPolicyAssignmentResponse(assignment),
		Created:    created,
	})
}

func (rt *Router) activatePrivacyPolicy(w http.ResponseWriter, r *http.Request) {
	var body privacyPolicyActivationRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, privacyPolicyBodyCap))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || strings.TrimSpace(body.Digest) == "" || body.OperationID.IsZero() {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	assignment, err := rt.privacyPolicies.Activate(
		r.Context(),
		PrincipalFrom(r.Context()),
		body.Digest,
		body.OperationID,
	)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, privacyPolicyAssignmentEnvelope{
		Assignment: newPrivacyPolicyAssignmentResponse(assignment),
	})
}

func (rt *Router) getActivePrivacyPolicy(w http.ResponseWriter, r *http.Request) {
	assignment, err := rt.privacyPolicies.Active(r.Context())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, privacyPolicyAssignmentEnvelope{
		Assignment: newPrivacyPolicyAssignmentResponse(assignment),
	})
}

func (rt *Router) listPrivacyPolicyHistory(w http.ResponseWriter, r *http.Request) {
	assignments, err := rt.privacyPolicies.History(r.Context())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	response := make([]privacyPolicyAssignmentResponse, len(assignments))
	for i, assignment := range assignments {
		response[i] = newPrivacyPolicyAssignmentResponse(assignment)
	}
	writeJSON(w, http.StatusOK, privacyPolicyHistoryResponse{Assignments: response})
}
