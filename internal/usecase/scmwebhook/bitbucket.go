package scmwebhook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type bitbucketProjectScanner interface {
	StartBitbucketWebhookAnalysis(context.Context, string, shared.ID, shared.ID, ports.BitbucketScanTarget) (ports.ScanJob, error)
	ResolveBitbucketWebhookTarget(context.Context, shared.ID, shared.ID, ports.BitbucketScanTarget) (ports.BitbucketScanTarget, error)
}

type BitbucketReceiver struct {
	integrations integrationReader
	projects     bitbucketProjectScanner
	deduper      ports.BitbucketWebhookDeduper
}

var _ ports.InboundWebhookReceiver = (*BitbucketReceiver)(nil)

func NewBitbucketReceiver(integrations integrationReader, projects bitbucketProjectScanner, deduper ports.BitbucketWebhookDeduper) (*BitbucketReceiver, error) {
	if integrations == nil || projects == nil || deduper == nil {
		return nil, fmt.Errorf("%w: Bitbucket webhook dependencies are required", shared.ErrValidation)
	}
	return &BitbucketReceiver{integrations: integrations, projects: projects, deduper: deduper}, nil
}

func (r *BitbucketReceiver) ReceiveInboundWebhook(ctx context.Context, id ports.InboundWebhookIdentity, event ports.InboundWebhookEvent) error {
	if event.Provider != "bitbucket" || id.TenantID.IsZero() || id.OwnerKind != "integration" || id.OwnerID == "" || event.EventID == "" {
		return fmt.Errorf("%w: invalid Bitbucket webhook identity", shared.ErrValidation)
	}
	targets, err := bitbucketScanTargets(event.EventType, event.Body)
	if err != nil || len(targets) == 0 {
		return err
	}
	var resolvedProject shared.ID
	if len(targets[0].SHA) == 12 {
		// Resolve before the deduper takes its transaction/endpoint lock. The
		// binding and persisted source are checked again during atomic enqueue.
		resolvedProject, err = r.boundProject(ctx, id)
		if err != nil {
			return err
		}
		targets[0], err = r.projects.ResolveBitbucketWebhookTarget(ctx, id.TenantID, resolvedProject, targets[0])
		if err != nil {
			return err
		}
	}
	digest := sha256.Sum256(event.Body)
	_, err = r.deduper.AcceptBitbucketWebhook(ctx, id, event.EventID, hex.EncodeToString(digest[:]), func(txCtx context.Context) error {
		projectID, err := r.boundProject(txCtx, id)
		if err != nil {
			return err
		}
		if !resolvedProject.IsZero() && resolvedProject != projectID {
			return fmt.Errorf("%w: Bitbucket binding changed during commit resolution", shared.ErrConflict)
		}
		for _, target := range targets {
			if _, err := r.projects.StartBitbucketWebhookAnalysis(txCtx, "system:bitbucket-webhook", id.TenantID, projectID, target); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func (r *BitbucketReceiver) boundProject(ctx context.Context, id ports.InboundWebhookIdentity) (shared.ID, error) {
	item, err := r.integrations.Get(ctx, id.TenantID, shared.ID(id.OwnerID))
	if err != nil {
		return "", err
	}
	if item.Provider != "bitbucket" || !item.Enabled || item.Archived {
		return "", fmt.Errorf("%w: Bitbucket integration is not active", shared.ErrValidation)
	}
	bindings, err := r.integrations.ListBindings(ctx, id.TenantID, item.ID)
	if err != nil {
		return "", err
	}
	if len(bindings) != 1 || bindings[0].ProjectID.IsZero() {
		return "", fmt.Errorf("%w: Bitbucket inbound integration must bind one Project", shared.ErrValidation)
	}
	return bindings[0].ProjectID, nil
}

func bitbucketScanTargets(eventType string, body []byte) ([]ports.BitbucketScanTarget, error) {
	if eventType != "repo:push" && eventType != "pullrequest:created" && eventType != "pullrequest:updated" {
		return nil, nil
	}
	var payload struct {
		Comment        json.RawMessage `json:"comment"`
		Approval       json.RawMessage `json:"approval"`
		ChangesRequest json.RawMessage `json:"changes_request"`
		Push           *struct {
			Changes []struct {
				Closed bool `json:"closed"`
				New    *struct {
					Type   string `json:"type"`
					Name   string `json:"name"`
					Target struct {
						Hash string `json:"hash"`
					} `json:"target"`
				} `json:"new"`
			} `json:"changes"`
		} `json:"push"`
		PullRequest *struct {
			State  string `json:"state"`
			Source struct {
				Branch struct {
					Name string `json:"name"`
				} `json:"branch"`
				Commit struct {
					Hash string `json:"hash"`
				} `json:"commit"`
				Repository struct {
					UUID string `json:"uuid"`
				} `json:"repository"`
			} `json:"source"`
			Destination struct {
				Branch struct {
					Name string `json:"name"`
				} `json:"branch"`
				Repository struct {
					UUID string `json:"uuid"`
				} `json:"repository"`
			} `json:"destination"`
		} `json:"pullrequest"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: invalid Bitbucket payload", shared.ErrValidation)
	}
	var targets []ports.BitbucketScanTarget
	if eventType == "repo:push" {
		if payload.Push == nil || payload.PullRequest != nil || len(payload.Push.Changes) == 0 || len(payload.Push.Changes) > 100 {
			return nil, fmt.Errorf("%w: invalid Bitbucket push", shared.ErrValidation)
		}
		seen := map[string]bool{}
		for _, change := range payload.Push.Changes {
			if change.Closed || change.New == nil {
				continue
			}
			if change.New.Type == "tag" {
				continue
			}
			if change.New.Type != "branch" {
				return nil, fmt.Errorf("%w: invalid Bitbucket ref type", shared.ErrValidation)
			}
			t := ports.BitbucketScanTarget{Ref: change.New.Name, SHA: change.New.Target.Hash}
			if err := validateBitbucketTarget(t); err != nil {
				return nil, err
			}
			key := t.Ref + ":" + t.SHA
			if !seen[key] {
				targets = append(targets, t)
				seen[key] = true
			}
		}
	} else {
		if payload.PullRequest == nil || payload.Push != nil || payload.Comment != nil || payload.Approval != nil || payload.ChangesRequest != nil {
			return nil, fmt.Errorf("%w: invalid Bitbucket pull request", shared.ErrValidation)
		}
		pr := payload.PullRequest
		if pr.State == "MERGED" || pr.State == "DECLINED" || pr.State == "SUPERSEDED" {
			return nil, nil
		}
		if pr.State != "OPEN" {
			return nil, fmt.Errorf("%w: invalid Bitbucket PR state", shared.ErrValidation)
		}
		// Missing repository identity is restricted too. Repository IDs only
		// decide trust; payload clone URLs never become an acquisition target.
		source, dest := canonicalBitbucketUUID(pr.Source.Repository.UUID), canonicalBitbucketUUID(pr.Destination.Repository.UUID)
		t := ports.BitbucketScanTarget{Ref: pr.Source.Branch.Name, SHA: pr.Source.Commit.Hash, BaseRef: pr.Destination.Branch.Name,
			PullRequest: true, Fork: source == "" || dest == "" || source != dest}
		if err := validateBitbucketTarget(t); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}

func validateBitbucketTarget(t ports.BitbucketScanTarget) error {
	validCommit := githubCommitPattern.MatchString(t.SHA)
	if t.PullRequest && len(t.SHA) == 12 {
		validCommit = true
		for _, c := range t.SHA {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				validCommit = false
			}
		}
	}
	if !validCommit || !validBitbucketRef(t.Ref) || (t.PullRequest && !validBitbucketRef(t.BaseRef)) {
		return fmt.Errorf("%w: invalid Bitbucket ref or commit", shared.ErrValidation)
	}
	return nil
}

func validBitbucketRef(ref string) bool {
	if !githubRefPattern.MatchString(ref) || strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.HasSuffix(ref, ".") {
		return false
	}
	for _, part := range strings.Split(ref, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

func canonicalBitbucketUUID(value string) string {
	if len(value) == 38 && value[0] == '{' && value[37] == '}' {
		value = value[1:37]
	}
	if len(value) != 36 {
		return ""
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return ""
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return ""
		}
	}
	return strings.ToLower(value)
}
