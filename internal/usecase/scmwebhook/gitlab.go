package scmwebhook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const gitLabProvider = "gitlab"

var (
	webhookSHA = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	webhookRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
)

type BindingReader interface {
	ListIntegrationBindings(context.Context, shared.ID) ([]integration.Binding, error)
}

type ProjectScanner interface {
	StartGitLabWebhookAnalysis(context.Context, string, shared.ID, shared.ID, ports.WebhookScanTarget) (ports.ScanJob, error)
}

// Receiver dispatches authenticated SCM webhook events without accepting a
// repository URL or tenant identity from the provider payload.
type Receiver struct {
	bindings BindingReader
	projects ProjectScanner
	deduper  ports.InboundWebhookEventDeduper
	clock    ports.Clock
}

func NewReceiver(bindings BindingReader, projects ProjectScanner, deduper ports.InboundWebhookEventDeduper, clock ports.Clock) (*Receiver, error) {
	if bindings == nil || projects == nil || deduper == nil || clock == nil {
		return nil, fmt.Errorf("%w: scm webhook receiver dependencies are required", shared.ErrValidation)
	}
	return &Receiver{bindings: bindings, projects: projects, deduper: deduper, clock: clock}, nil
}

func (r *Receiver) ReceiveInboundWebhook(ctx context.Context, identity ports.InboundWebhookIdentity, event ports.InboundWebhookEvent) error {
	if event.Provider != gitLabProvider {
		return fmt.Errorf("%w: inbound provider is not supported", shared.ErrValidation)
	}
	if identity.OwnerKind != "integration" || identity.OwnerID == "" || identity.TenantID.IsZero() || event.EventID == "" {
		return fmt.Errorf("%w: inbound webhook identity is invalid", shared.ErrValidation)
	}
	target, scan, err := parseGitLab(event.EventType, event.Body)
	if err != nil {
		return err
	}
	if !scan {
		return nil
	}

	digest := sha256.Sum256(event.Body)
	event.PayloadSHA256 = hex.EncodeToString(digest[:])
	_, err = r.deduper.ProcessInboundWebhookEvent(ctx, identity, event, func(txCtx context.Context) error {
		bindings, err := r.bindings.ListIntegrationBindings(txCtx, shared.ID(identity.OwnerID))
		if err != nil {
			return fmt.Errorf("list inbound integration bindings: %w", err)
		}
		projectID, err := oneBoundProject(bindings)
		if err != nil {
			return err
		}
		target.Provider = gitLabProvider
		if _, err := r.projects.StartGitLabWebhookAnalysis(txCtx, "gitlab-webhook", identity.TenantID, projectID, target); err != nil {
			return fmt.Errorf("start GitLab webhook analysis: %w", err)
		}
		return nil
	})
	return err
}

type gitLabTarget = ports.WebhookScanTarget

func parseGitLab(eventType string, body []byte) (gitLabTarget, bool, error) {
	var envelope struct {
		ObjectKind string `json:"object_kind"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return gitLabTarget{}, false, fmt.Errorf("%w: invalid GitLab payload", shared.ErrValidation)
	}
	// A Standard Webhooks signature covers the body, not X-Gitlab-Event.
	// A conflicting header must not alter processing of the signed object kind.
	if envelope.ObjectKind != "" {
		expected := map[string]string{"push": "Push Hook", "merge_request": "Merge Request Hook"}[envelope.ObjectKind]
		if (expected != "" && strings.TrimSpace(eventType) != expected) ||
			(expected == "" && (eventType == "Push Hook" || eventType == "Merge Request Hook")) {
			return gitLabTarget{}, false, fmt.Errorf("%w: GitLab event type does not match payload", shared.ErrValidation)
		}
	}
	switch strings.TrimSpace(eventType) {
	case "Push Hook":
		var payload struct {
			Ref         string  `json:"ref"`
			CheckoutSHA *string `json:"checkout_sha"`
			After       string  `json:"after"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return gitLabTarget{}, false, fmt.Errorf("%w: invalid GitLab push payload", shared.ErrValidation)
		}
		sha := strings.TrimSpace(payload.After)
		if payload.CheckoutSHA != nil && strings.TrimSpace(*payload.CheckoutSHA) != "" {
			sha = strings.TrimSpace(*payload.CheckoutSHA)
		}
		// Branch deletion has no checkout SHA and an all-zero after SHA. It is a
		// valid delivery but there is no source revision to scan.
		if sha == "" || allZeroSHA(sha) {
			return gitLabTarget{}, false, nil
		}
		ref := strings.TrimSpace(payload.Ref)
		ref = strings.TrimPrefix(ref, "refs/heads/")
		if err := validateTarget(ref, sha); err != nil {
			return gitLabTarget{}, false, err
		}
		return gitLabTarget{Ref: ref, SHA: sha}, true, nil

	case "Merge Request Hook":
		var payload struct {
			ObjectAttributes struct {
				IID             int64  `json:"iid"`
				TargetBranch    string `json:"target_branch"`
				Action          string `json:"action"`
				State           string `json:"state"`
				SourceBranch    string `json:"source_branch"`
				SourceProjectID int64  `json:"source_project_id"`
				TargetProjectID int64  `json:"target_project_id"`
				LastCommit      struct {
					ID string `json:"id"`
				} `json:"last_commit"`
			} `json:"object_attributes"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return gitLabTarget{}, false, fmt.Errorf("%w: invalid GitLab merge-request payload", shared.ErrValidation)
		}
		switch payload.ObjectAttributes.State {
		case "closed", "merged":
			return gitLabTarget{}, false, nil
		}
		switch payload.ObjectAttributes.Action {
		case "", "open", "reopen", "update":
		default:
			return gitLabTarget{}, false, nil
		}
		base := strings.TrimSpace(payload.ObjectAttributes.TargetBranch)
		if base != "" {
			if err := validateTarget(base, payload.ObjectAttributes.LastCommit.ID); err != nil {
				return gitLabTarget{}, false, err
			}
		}
		branch := strings.TrimSpace(payload.ObjectAttributes.SourceBranch)
		sha := strings.TrimSpace(payload.ObjectAttributes.LastCommit.ID)
		if err := validateTarget(branch, sha); err != nil {
			return gitLabTarget{}, false, err
		}
		if payload.ObjectAttributes.IID <= 0 {
			return gitLabTarget{}, false, fmt.Errorf("%w: invalid GitLab merge-request iid", shared.ErrValidation)
		}
		// GitLab publishes every MR head through the target repository, including
		// private-fork MRs. Keep the human source branch as Ref for Project history,
		// and carry the target-side server-owned ref only as the acquisition FetchRef.
		fetchRef := fmt.Sprintf("refs/merge-requests/%d/head", payload.ObjectAttributes.IID)
		// Missing project IDs fail safe as fork-like: the only consequence is
		// disabling build-system execution. We never relax fork policy because
		// an optional/malformed payload field was absent.
		fork := payload.ObjectAttributes.SourceProjectID == 0 ||
			payload.ObjectAttributes.TargetProjectID == 0 ||
			payload.ObjectAttributes.SourceProjectID != payload.ObjectAttributes.TargetProjectID
		return gitLabTarget{Ref: branch, FetchRef: fetchRef, SHA: sha, Fork: fork, BaseRef: base, MergeRequestNumber: payload.ObjectAttributes.IID}, true, nil
	default:
		// The endpoint may receive other GitLab hook types during configuration
		// tests. Authenticated unsupported events are acknowledged but never scan.
		return gitLabTarget{}, false, nil
	}
}

func validateTarget(ref, sha string) error {
	if len(ref) == 0 || len(ref) > 255 || !webhookRef.MatchString(ref) ||
		strings.Contains(ref, "..") || strings.Contains(ref, "@{") ||
		strings.HasSuffix(ref, ".lock") || strings.HasSuffix(ref, ".") {
		return fmt.Errorf("%w: invalid GitLab webhook ref", shared.ErrValidation)
	}
	for _, part := range strings.Split(ref, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return fmt.Errorf("%w: invalid GitLab webhook ref", shared.ErrValidation)
		}
	}
	if !webhookSHA.MatchString(sha) {
		return fmt.Errorf("%w: invalid GitLab webhook sha", shared.ErrValidation)
	}
	return nil
}

func allZeroSHA(sha string) bool {
	if len(sha) != 40 && len(sha) != 64 {
		return false
	}
	for _, c := range sha {
		if c != '0' {
			return false
		}
	}
	return true
}

func oneBoundProject(bindings []integration.Binding) (shared.ID, error) {
	var projectID shared.ID
	for _, binding := range bindings {
		if binding.ProjectID.IsZero() {
			continue
		}
		if projectID.IsZero() {
			projectID = binding.ProjectID
			continue
		}
		if binding.ProjectID != projectID {
			// The payload repository URL/ID is intentionally not trusted for
			// routing. A multi-project integration therefore needs distinct
			// webhook endpoints instead of payload-selected project routing.
			return "", fmt.Errorf("%w: inbound integration is bound to multiple projects", shared.ErrConflict)
		}
	}
	if projectID.IsZero() {
		return "", fmt.Errorf("%w: inbound integration has no project binding", shared.ErrNotFound)
	}
	return projectID, nil
}
