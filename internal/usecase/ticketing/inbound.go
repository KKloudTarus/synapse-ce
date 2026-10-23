package ticketing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ReceiveInboundWebhook reduces an authenticated Jira delivery to local
// observations and proposals. It never writes a finding security status.
func (w *Workflow) ReceiveInboundWebhook(ctx context.Context, identity ports.InboundWebhookIdentity, event ports.InboundWebhookEvent) error {
	if w.inboundDeduper == nil || identity.OwnerKind != "integration" || identity.TenantID.IsZero() || strings.TrimSpace(identity.OwnerID) == "" || (event.Provider != "jira-cloud" && event.Provider != "jira-dc") || strings.TrimSpace(event.EventID) == "" {
		return shared.ErrValidation
	}
	if !isInboundJiraTicketEvent(event.EventType) {
		return nil
	}
	integrationID := shared.ID(identity.OwnerID)
	configStore, ok := w.store.(ports.TicketInboundConfigurationStore)
	if !ok {
		return fmt.Errorf("%w: inbound ticket configuration unavailable", shared.ErrConflict)
	}
	inboundStore, ok := w.store.(ports.TicketInboundStore)
	if !ok {
		return fmt.Errorf("%w: inbound ticket store unavailable", shared.ErrConflict)
	}
	parsed, meaningful, err := parseInboundJira(event.EventType, event.Body)
	if err != nil {
		return err
	}
	if !meaningful {
		return nil
	}
	prepared, e := w.integration(ctx, identity.TenantID, integrationID)
	if e != nil {
		return e
	}
	if !isJiraTicketProvider(prepared.Provider) {
		return shared.ErrValidation
	}
	provider, e := w.providers.TicketProvider(ctx, prepared)
	if e != nil {
		return safeTicketError(e)
	}
	defer closeTicketProvider(provider)
	sanitizer, ok := provider.(ports.TicketExternalTextSanitizer)
	if !ok {
		return fmt.Errorf("%w: provider external text sanitization unavailable", shared.ErrConflict)
	}
	preparedConnection, preparedCredential := prepared.ConnectionRevision, prepared.CredentialRevision
	_, err = w.inboundDeduper.ProcessInboundWebhookEvent(ctx, identity, event, func(txCtx context.Context) error {
		config, configErr := configStore.GetTicketInboundConfiguration(txCtx, identity.TenantID, integrationID)
		if configErr != nil {
			return configErr
		}
		in, integrationErr := w.integration(txCtx, identity.TenantID, integrationID)
		if integrationErr != nil {
			return integrationErr
		}
		if !isJiraTicketProvider(in.Provider) {
			return shared.ErrValidation
		}
		if !config.Enabled || config.ConnectionRevision != in.ConnectionRevision || config.CredentialRevision != in.CredentialRevision || strings.TrimSpace(config.IntegrationAuthor) == "" {
			return shared.ErrForbidden
		}
		if preparedConnection != in.ConnectionRevision || preparedCredential != in.CredentialRevision {
			return shared.ErrConflict
		}
		cleanRemote, e := sanitizer.RedactExternalTicketText(parsed.RemoteID)
		if e != nil || cleanRemote != parsed.RemoteID {
			return shared.ErrValidation
		}
		if parsed.StatusAuthorID != "" {
			clean, cleanErr := sanitizer.RedactExternalTicketText(parsed.StatusAuthorID)
			if cleanErr != nil || clean != parsed.StatusAuthorID {
				parsed.StatusAuthorID, parsed.StatusAuthorKnown = "", false
			}
		}
		if parsed.CommentAuthorID != "" {
			clean, cleanErr := sanitizer.RedactExternalTicketText(parsed.CommentAuthorID)
			if cleanErr != nil || clean != parsed.CommentAuthorID {
				parsed.CommentAuthorID = ""
			}
		}
		if parsed.Comment != "" {
			clean, e := sanitizer.RedactExternalTicketText(parsed.Comment)
			if e != nil || len(clean) > 16<<10 {
				return shared.ErrValidation
			}
			parsed.Comment = clean
		}
		ownStatusWrite := parsed.StatusAuthorKnown && parsed.StatusAuthorID != "" && parsed.StatusAuthorID == config.IntegrationAuthor
		ownComment := parsed.CommentAuthorID != "" && parsed.CommentAuthorID == config.IntegrationAuthor
		targets, resolveErr := inboundStore.ResolveInboundTicket(txCtx, identity.TenantID, integrationID, parsed.RemoteID)
		if resolveErr != nil {
			return resolveErr
		}
		if len(targets) == 0 {
			return nil
		}
		now := w.clock.Now().UTC()
		observations := make([]domain.ExternalTicketObservation, 0, len(targets))
		comments := make([]domain.ExternalTicketComment, 0, len(targets))
		for _, target := range targets {
			if target.Intent.IntegrationID != integrationID {
				return shared.ErrForbidden
			}
			// A webhook is bound to its integration, but that alone cannot prove a
			// recycled Jira key still belongs to this immutable destination.
			if err := w.validateStatusTarget(txCtx, identity.TenantID, target); err != nil {
				continue
			}
			if parsed.StatusCategory != "" {
				observations = append(observations, domain.ExternalTicketObservation{TenantID: identity.TenantID, IntegrationID: integrationID, MappingID: target.Mapping.ID, EngagementID: target.Intent.EngagementID, FindingID: target.Intent.FindingID, RemoteID: parsed.RemoteID, StatusCategory: parsed.StatusCategory, ProviderUpdatedAt: parsed.UpdatedAt, StatusChangedAt: parsed.StatusChangedAt, AuthorID: parsed.StatusAuthorID, StatusAuthorKnown: parsed.StatusAuthorKnown, OwnWrite: ownStatusWrite, CheckedAt: now, Version: 1})
			}
			if parsed.Comment != "" && !ownComment {
				providerCommentID := parsed.CommentID
				if providerCommentID == "" {
					providerCommentID = strings.TrimSpace(event.EventID)
				}
				if len(providerCommentID) > 255 {
					return shared.ErrValidation
				}
				comments = append(comments, domain.ExternalTicketComment{ID: inboundCommentSnapshotID(identity.TenantID, integrationID, target.Intent.EngagementID, target.Intent.FindingID, parsed.RemoteID, providerCommentID, parsed.CommentAt, parsed.Comment), TenantID: identity.TenantID, IntegrationID: integrationID, EngagementID: target.Intent.EngagementID, FindingID: target.Intent.FindingID, RemoteID: parsed.RemoteID, AuthorID: parsed.CommentAuthorID, Body: parsed.Comment, ProviderAt: parsed.CommentAt, CreatedAt: now})
			}
		}
		if len(observations) == 0 && len(comments) == 0 {
			return nil
		}
		if err := inboundStore.ReduceInboundTicket(txCtx, identity.TenantID, observations, comments, now); err != nil {
			return err
		}
		return w.audit.Record(txCtx, ports.AuditEntry{Actor: "integration:" + integrationID.String(), Action: "ticket.inbound.reduced", Target: parsed.RemoteID, At: now, Metadata: map[string]string{"provider": event.Provider, "event_type": event.EventType}})
	})
	return err
}

func (w *Workflow) ListTicketObservations(ctx context.Context, tenant, engagement, finding shared.ID) (ports.TicketInboundView, error) {
	store, ok := w.store.(ports.TicketInboundStore)
	if !ok {
		return ports.TicketInboundView{}, fmt.Errorf("%w: inbound ticket store unavailable", shared.ErrConflict)
	}
	return store.ListInboundTicketView(shared.WithTenant(ctx, tenant), tenant, engagement, finding)
}

func isInboundJiraTicketEvent(eventType string) bool {
	switch strings.TrimSpace(eventType) {
	case "jira:issue_created", "jira:issue_updated", "comment_created", "comment_updated":
		return true
	default:
		return false
	}
}

type inboundJiraEvent struct {
	RemoteID, StatusCategory, StatusAuthorID, CommentID, CommentAuthorID, Comment string
	UpdatedAt, StatusChangedAt, CommentAt                                         time.Time
	StatusAuthorKnown                                                             bool
}

type inboundJiraActor struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
}

func (a inboundJiraActor) id() string {
	if accountID := strings.TrimSpace(a.AccountID); accountID != "" {
		return accountID
	}
	return strings.TrimSpace(a.Name)
}

var inboundJiraKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,254}-[1-9][0-9]{0,18}$`)

// parseInboundJira accepts only the issue state and literal comment text used by
// the reducer. Unknown issue payloads are acknowledged as no-ops.
func parseInboundJira(eventType string, body []byte) (inboundJiraEvent, bool, error) {
	var payload struct {
		Issue struct {
			Key    string `json:"key"`
			Fields struct {
				Updated string `json:"updated"`
				Status  struct {
					StatusCategory struct {
						Key string `json:"key"`
					} `json:"statusCategory"`
				} `json:"status"`
			} `json:"fields"`
		} `json:"issue"`
		User    inboundJiraActor `json:"user"`
		Comment struct {
			ID           string           `json:"id"`
			Author       inboundJiraActor `json:"author"`
			UpdateAuthor inboundJiraActor `json:"updateAuthor"`
			Body         json.RawMessage  `json:"body"`
			Created      string           `json:"created"`
			Updated      string           `json:"updated"`
		} `json:"comment"`
		Changelog struct {
			Created string `json:"created"`
			Total   int    `json:"total"`
			Items   []struct {
				Field string `json:"field"`
			} `json:"items"`
		} `json:"changelog"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return inboundJiraEvent{}, false, shared.ErrValidation
	}
	statusEvent := eventType == "jira:issue_created" || eventType == "jira:issue_updated"
	statusAuthor := payload.User.id()
	out := inboundJiraEvent{RemoteID: strings.TrimSpace(payload.Issue.Key)}
	if !inboundJiraKey.MatchString(out.RemoteID) || (statusEvent && len(statusAuthor) > 255) {
		return inboundJiraEvent{}, false, shared.ErrValidation
	}
	if statusEvent {
		category := strings.TrimSpace(payload.Issue.Fields.Status.StatusCategory.Key)
		if category != "" && category != "new" && category != "indeterminate" && category != "done" {
			return inboundJiraEvent{}, false, shared.ErrValidation
		}
		out.StatusCategory = category
		if payload.Issue.Fields.Updated != "" {
			at, err := parseInboundJiraTime(payload.Issue.Fields.Updated)
			if err != nil {
				return inboundJiraEvent{}, false, shared.ErrValidation
			}
			out.UpdatedAt = at
		}
		if hasStatusChange(payload.Changelog.Items) || (eventType == "jira:issue_created" && payload.Changelog.Total == 0) {
			// Jira's top-level user describes a status-changing issue event only.
			// It is not a comment author: Cloud comment webhooks omit it entirely.
			out.StatusAuthorID, out.StatusAuthorKnown = statusAuthor, statusAuthor != ""
			if payload.Changelog.Created != "" {
				at, err := parseInboundJiraTime(payload.Changelog.Created)
				if err != nil {
					return inboundJiraEvent{}, false, shared.ErrValidation
				}
				out.StatusChangedAt = at
			} else {
				out.StatusChangedAt = out.UpdatedAt
			}
		}
	}
	if len(payload.Comment.Body) > 0 && string(payload.Comment.Body) != "null" {
		text, err := jiraCommentLiteral(payload.Comment.Body)
		if err != nil {
			return inboundJiraEvent{}, false, err
		}
		out.Comment = redact.AuditText(strings.TrimSpace(text), nil)
		if len(out.Comment) > 16<<10 {
			return inboundJiraEvent{}, false, shared.ErrValidation
		}
		out.CommentID = strings.TrimSpace(payload.Comment.ID)
		if len(out.CommentID) > 255 {
			return inboundJiraEvent{}, false, shared.ErrValidation
		}
		// Jira can embed an edited comment in issue_updated before it delivers the
		// matching comment_updated callback. Both shapes describe the same version.
		// A comment_created payload remains a creation even if Jira includes updated.
		isEdit := eventType == "comment_updated" || (eventType == "jira:issue_updated" && strings.TrimSpace(payload.Comment.Updated) != "")
		out.CommentAuthorID = payload.Comment.Author.id()
		stamp := payload.Comment.Created
		if isEdit {
			if updateAuthor := payload.Comment.UpdateAuthor.id(); updateAuthor != "" {
				out.CommentAuthorID = updateAuthor
			}
			stamp = payload.Comment.Updated
		}
		if len(out.CommentAuthorID) > 255 {
			return inboundJiraEvent{}, false, shared.ErrValidation
		}
		if strings.TrimSpace(out.CommentAuthorID) == "" || strings.TrimSpace(stamp) == "" {
			out.Comment, out.CommentAuthorID = "", ""
		} else {
			at, err := parseInboundJiraTime(stamp)
			if err != nil {
				return inboundJiraEvent{}, false, shared.ErrValidation
			}
			out.CommentAt = at
		}
	}
	return out, (statusEvent && out.StatusCategory != "") || out.Comment != "", nil
}

// inboundCommentSnapshotID deduplicates a provider comment version across Jira
// webhook shapes while preserving an append-only snapshot when the provider
// changes its timestamp or literal, redacted body.
func inboundCommentSnapshotID(tenantID, integrationID, engagementID, findingID shared.ID, remoteID, providerCommentID string, revisionAt time.Time, body string) shared.ID {
	payload, _ := json.Marshal(struct {
		TenantID, IntegrationID, EngagementID, FindingID string
		RemoteID, ProviderCommentID, RevisionAt, Body    string
	}{
		TenantID: tenantID.String(), IntegrationID: integrationID.String(), EngagementID: engagementID.String(), FindingID: findingID.String(),
		RemoteID: remoteID, ProviderCommentID: providerCommentID, RevisionAt: revisionAt.UTC().Format(time.RFC3339Nano), Body: body,
	})
	sum := sha256.Sum256(payload)
	return shared.ID("inbound-comment-" + hex.EncodeToString(sum[:16]))
}

func hasStatusChange(items []struct {
	Field string `json:"field"`
}) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Field), "status") {
			return true
		}
	}
	return false
}

func parseInboundJiraTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999-0700"} {
		if at, err := time.Parse(layout, value); err == nil {
			return at.UTC(), nil
		}
	}
	return time.Time{}, shared.ErrValidation
}

// jiraCommentLiteral retains only literal text nodes. Mention nodes and markup
// attributes are intentionally omitted, so an inbound comment cannot persist a
// user mention, rich link target, or provider-specific executable annotation.
func jiraCommentLiteral(raw json.RawMessage) (string, error) {
	if len(raw) > 64<<10 {
		return "", shared.ErrValidation
	}
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		if len(plain) > 16<<10 {
			return "", shared.ErrValidation
		}
		return plain, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", shared.ErrValidation
	}
	var text strings.Builder
	var visit func(any) error
	visit = func(node any) error {
		switch v := node.(type) {
		case []any:
			for _, child := range v {
				if err := visit(child); err != nil {
					return err
				}
			}
		case map[string]any:
			if typ, _ := v["type"].(string); typ == "mention" {
				return nil
			}
			if literal, ok := v["text"].(string); ok {
				if text.Len()+len(literal) > 16<<10 {
					return shared.ErrValidation
				}
				text.WriteString(literal)
			}
			if content, ok := v["content"]; ok {
				return visit(content)
			}
		}
		return nil
	}
	if err := visit(value); err != nil {
		return "", err
	}
	return text.String(), nil
}
