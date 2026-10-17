package ticketing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// tickTicketStatuses polls only provider tickets whose completed create intent
// proves the mapping and destination. It never treats manual links as authority
// to transition an external ticket.
func (w *Workflow) tickTicketStatuses(ctx context.Context, tenant shared.ID, store ports.TicketStatusStore, limit int) (int, error) {
	progressStore, ok := store.(ports.TicketStatusProgressStore)
	if !ok {
		return 0, fmt.Errorf("%w: durable ticket status progress store required", shared.ErrConflict)
	}
	targets, err := store.ListTicketStatusTargets(ctx, tenant, limit)
	if err != nil {
		return 0, err
	}
	created := 0
	for _, target := range targets {
		f, err := w.findings.GetByEngagementAndID(ctx, target.Intent.EngagementID, target.Intent.FindingID)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				continue
			}
			return created, err
		}
		state, source, err := w.ticketSyncStateForTarget(ctx, tenant, target, f)
		if err != nil {
			return created, err
		}
		progress, err := w.ticketStatusProgress(ctx, tenant, progressStore, target, state, source)
		if err != nil {
			if errors.Is(err, shared.ErrConflict) {
				continue
			}
			return created, err
		}
		if err := w.validateStatusTarget(ctx, tenant, target); err != nil {
			if errors.Is(err, shared.ErrConflict) || errors.Is(err, shared.ErrValidation) || errors.Is(err, shared.ErrNotFound) {
				continue
			}
			return created, err
		}
		transition := target.Mapping.StatusTransitions[state]
		if transition == "" {
			continue
		}
		if progress.AppliedState == state && progress.SourceRevision == source {
			continue
		}
		if progress.IntegrationAuthor == "" || progress.TransitionIntentID.IsZero() {
			principal, identityErr := w.ticketIntegrationPrincipal(ctx, tenant, target.Mapping.IntegrationID)
			if identityErr != nil {
				return created, identityErr
			}
			progress.IntegrationAuthor = principal
			progress.CheckedAt = w.clock.Now().UTC()
			progress, err = progressStore.UpdateTicketStatusProgress(ctx, tenant, progress, progress.Version)
			if err != nil {
				if errors.Is(err, shared.ErrConflict) {
					continue
				}
				return created, err
			}
		}
		key := ticketStatusRequestKey(target, progress.Episode, "transition")
		preview, err := w.Preview(ctx, PreviewRequest{TenantID: tenant, MappingID: target.Mapping.ID, FindingID: f.ID, EngagementID: f.EngagementID})
		if err != nil {
			return created, err
		}
		intent, fresh, err := w.openStatusIntent(ctx, tenant, target, preview, state, source, transition, key)
		if err != nil {
			return created, err
		}
		if fresh {
			created++
		}
		if progress.TransitionIntentID.IsZero() {
			progress.TransitionIntentID = intent.ID
			progress.CheckedAt = w.clock.Now().UTC()
			progress, err = progressStore.UpdateTicketStatusProgress(ctx, tenant, progress, progress.Version)
			if err != nil {
				if errors.Is(err, shared.ErrConflict) {
					continue
				}
				return created, err
			}
		}
		// A status transition is deliberately a separate remote operation from the
		// field refresh. A retry can therefore resume the latter only after the
		// transition has been durably acknowledged, and never falls back to Create.
		if intent.State != writeintent.Done {
			continue
		}
		update, fresh, err := w.openStatusUpdateIntent(ctx, tenant, target, preview, source, ticketStatusRequestKey(target, progress.Episode, "update"))
		if err != nil {
			return created, err
		}
		if fresh {
			created++
		}
		if progress.UpdateIntentID.IsZero() {
			progress.UpdateIntentID = update.ID
			progress.CheckedAt = w.clock.Now().UTC()
			if _, err = progressStore.UpdateTicketStatusProgress(ctx, tenant, progress, progress.Version); err != nil && !errors.Is(err, shared.ErrConflict) {
				return created, err
			}
		}
		if update.State == writeintent.Done {
			progress.AppliedState = state
			progress.CheckedAt = w.clock.Now().UTC()
			if _, err = progressStore.UpdateTicketStatusProgress(ctx, tenant, progress, progress.Version); err != nil && !errors.Is(err, shared.ErrConflict) {
				return created, err
			}
		}
	}
	return created, nil
}

func (w *Workflow) ticketIntegrationPrincipal(ctx context.Context, tenant, integrationID shared.ID) (string, error) {
	in, err := w.integration(ctx, tenant, integrationID)
	if err != nil {
		return "", err
	}
	provider, err := w.providers.TicketProvider(ctx, in)
	if err != nil {
		return "", safeTicketError(err)
	}
	defer closeTicketProvider(provider)
	reader, ok := provider.(ports.TicketIdentityReader)
	if !ok {
		return "", fmt.Errorf("%w: Jira integration identity is unavailable", shared.ErrConflict)
	}
	principal, err := reader.TicketIdentity(ctx)
	if err != nil || strings.TrimSpace(principal) == "" {
		if err != nil {
			return "", safeTicketError(err)
		}
		return "", fmt.Errorf("%w: Jira integration identity is empty", shared.ErrConflict)
	}
	return strings.TrimSpace(principal), nil
}

// validateStatusTarget refuses a status write if the completed create command
// was for a different Jira origin or immutable destination. Template and locale
// edits can refresh fields, but cannot retarget an existing remote key.
func (w *Workflow) validateStatusTarget(ctx context.Context, tenant shared.ID, target ports.TicketStatusTarget) error {
	facts, _, err := readTicketSnapshot(target.Intent)
	if err != nil {
		return err
	}
	in, err := w.integration(ctx, tenant, target.Mapping.IntegrationID)
	if err != nil {
		return err
	}
	destination, err := target.Intent.DispatchTarget()
	if err != nil {
		return err
	}
	if facts.Endpoint != in.Endpoint || facts.Provider != in.Provider || destination.ProjectKey != target.Mapping.ProjectKey || destination.IssueType != target.Mapping.IssueType || target.Intent.SecurityLevel != target.Mapping.SecurityLevel || !sameRemoteOrigin(in.Endpoint, target.Intent.RemoteURL) {
		return shared.ErrConflict
	}
	return nil
}

func (w *Workflow) ticketSyncStateForTarget(ctx context.Context, tenant shared.ID, target ports.TicketStatusTarget, candidate finding.Finding) (domain.SyncState, string, error) {
	if target.Mapping.GroupingMode != domain.GroupingVulnerabilityProject || strings.TrimSpace(candidate.AdvisoryID) == "" {
		return w.ticketSyncState(ctx, tenant, candidate)
	}
	reader, ok := w.store.(ports.TicketGroupFactsReader)
	if !ok {
		return "", "", fmt.Errorf("%w: durable ticket group facts required", shared.ErrConflict)
	}
	facts, err := reader.GroupTicketFacts(ctx, tenant, target.Mapping.ID, target.Mapping.ScopeID, strings.TrimSpace(candidate.AdvisoryID), ports.TicketGroupMember{EngagementID: candidate.EngagementID, FindingID: candidate.ID})
	if err != nil {
		return "", "", err
	}
	if len(facts) == 0 {
		return "", "", shared.ErrNotFound
	}
	seen := make(map[shared.ID]struct{}, len(facts))
	parts := make([]string, 0, len(facts))
	states := make([]domain.SyncState, 0, len(facts))
	for _, fact := range facts {
		if _, duplicate := seen[fact.FindingID]; duplicate {
			continue
		}
		seen[fact.FindingID] = struct{}{}
		member, err := w.findings.GetByEngagementAndID(ctx, fact.EngagementID, fact.FindingID)
		if err != nil {
			return "", "", err
		}
		memberState, _, err := w.ticketSyncState(ctx, tenant, member)
		if err != nil {
			return "", "", err
		}
		states = append(states, memberState)
		parts = append(parts, fact.FindingID.String()+":"+string(memberState))
	}
	sort.Strings(parts)
	state := groupedTicketSyncState(states)
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return state, "group:" + hex.EncodeToString(digest[:]), nil
}

// groupedTicketSyncState fails closed toward reopen while any member remains
// active. A group cannot be transitioned to a terminal provider state because
// one constituent happened to finish first.
func groupedTicketSyncState(states []domain.SyncState) domain.SyncState {
	allAccepted, allFalse, allRemediated := true, true, true
	for _, state := range states {
		if state == domain.SyncReopen {
			return domain.SyncReopen
		}
		allAccepted = allAccepted && state == domain.SyncAccepted
		allFalse = allFalse && state == domain.SyncFalsePositive
		allRemediated = allRemediated && state == domain.SyncRemediated
	}
	switch {
	case allAccepted:
		return domain.SyncAccepted
	case allFalse:
		return domain.SyncFalsePositive
	case allRemediated:
		return domain.SyncRemediated
	default:
		// Mixed terminal outcomes require review; presenting the group as open
		// is safer than closing it under an arbitrary member's terminal state.
		return domain.SyncReopen
	}
}

func (w *Workflow) ticketStatusProgress(ctx context.Context, tenant shared.ID, store ports.TicketStatusProgressStore, target ports.TicketStatusTarget, state domain.SyncState, source string) (ports.TicketStatusProgress, error) {
	progress, err := store.GetTicketStatusProgress(ctx, tenant, target.Mapping.ID, target.Intent.EngagementID, target.Intent.FindingID)
	if errors.Is(err, shared.ErrNotFound) {
		progress, _, err = store.CreateTicketStatusProgress(ctx, tenant, ports.TicketStatusProgress{
			TenantID: tenant, MappingID: target.Mapping.ID, EngagementID: target.Intent.EngagementID, FindingID: target.Intent.FindingID,
			DesiredState: state, SourceRevision: source, CheckedAt: w.clock.Now().UTC(),
		})
		return progress, err
	}
	if err != nil {
		return ports.TicketStatusProgress{}, err
	}
	if progress.DesiredState == state && progress.SourceRevision == source {
		progress.CheckedAt = w.clock.Now().UTC()
		return store.UpdateTicketStatusProgress(ctx, tenant, progress, progress.Version)
	}
	// A grouped ticket can gain or lose members without changing its effective
	// provider state. Once that state was applied, refresh the source checkpoint
	// without reopening the same status episode; membership field refreshes use
	// the grouped update path instead of issuing an invalid Open→Open transition.
	if progress.DesiredState == state && progress.AppliedState == state {
		progress.SourceRevision, progress.CheckedAt = source, w.clock.Now().UTC()
		return store.UpdateTicketStatusProgress(ctx, tenant, progress, progress.Version)
	}
	progress.DesiredState, progress.SourceRevision = state, source
	progress.AppliedState, progress.TransitionIntentID, progress.UpdateIntentID = "", "", ""
	progress.Episode++
	progress.CheckedAt = w.clock.Now().UTC()
	return store.UpdateTicketStatusProgress(ctx, tenant, progress, progress.Version)
}

func ticketStatusRequestKey(target ports.TicketStatusTarget, episode int, stage string) string {
	// Stable hash keeps keys within the shared request-key cap even for grouped
	// targets, while retaining all identities that distinguish an episode.
	value := strings.Join([]string{target.Mapping.ID.String(), target.Intent.ID.String(), fmt.Sprintf("%d", episode), stage}, "\x00")
	digest := sha256.Sum256([]byte(value))
	return "status:" + hex.EncodeToString(digest[:])
}

func (w *Workflow) openStatusUpdateIntent(ctx context.Context, tenant shared.ID, target ports.TicketStatusTarget, preview Preview, source, key string) (domain.Intent, bool, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(preview.Payload, &payload); err != nil {
		return domain.Intent{}, false, shared.ErrValidation
	}
	var facts snapshotFacts
	if err := json.Unmarshal(payload["_synapse"], &facts); err != nil {
		return domain.Intent{}, false, shared.ErrValidation
	}
	facts.UpdateRemoteID, facts.UpdateRemoteURL, facts.StatusSource = target.Intent.RemoteID, target.Intent.RemoteURL, source
	payload["_synapse"], _ = json.Marshal(facts)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload["fields"], &fields); err != nil {
		return domain.Intent{}, false, shared.ErrValidation
	}
	// Keep the immutable destination in the durable snapshot for dispatch fencing.
	// readTicketSnapshot removes create-only fields before calling the updater.
	payload["fields"], _ = json.Marshal(fields)
	raw, err := json.Marshal(payload)
	if err != nil {
		return domain.Intent{}, false, shared.ErrValidation
	}
	digest := ticketDigest(raw)
	id := w.ids.NewID()
	var labels []string
	if err := json.Unmarshal(fields["labels"], &labels); err != nil {
		return domain.Intent{}, false, shared.ErrValidation
	}
	labels = append(labels, "synapse-intent-"+id.String())
	fields["labels"], _ = json.Marshal(labels)
	payload["fields"], _ = json.Marshal(fields)
	raw, err = json.Marshal(payload)
	if err != nil {
		return domain.Intent{}, false, shared.ErrValidation
	}
	now := w.clock.Now().UTC()
	i := domain.Intent{
		ID:                 id,
		TenantID:           tenant,
		IntegrationID:      target.Mapping.IntegrationID,
		MappingID:          target.Mapping.ID,
		FindingID:          target.Intent.FindingID,
		EngagementID:       target.Intent.EngagementID,
		Action:             domain.Update,
		RequestKey:         key,
		PayloadDigest:      digest,
		Marker:             "synapse-intent-" + id.String(),
		State:              writeintent.Pending,
		Version:            1,
		Snapshot:           raw,
		MappingVersion:     target.Mapping.Version,
		ConnectionRevision: facts.ConnectionRevision,
		CredentialRevision: facts.CredentialRevision,
		SecurityLevel:      target.Mapping.SecurityLevel,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	entry := ports.AuditEntry{Actor: "system:ticket_status", Action: "ticket.intent.status_update", Target: id.String(), At: now, Metadata: map[string]string{"source": source}}
	return w.intentAudit.CreateOrGetIntentAudited(ctx, tenant, i, entry)
}

func (w *Workflow) ticketSyncState(ctx context.Context, tenant shared.ID, f finding.Finding) (domain.SyncState, string, error) {
	if f.Status == finding.StatusRemediated {
		return domain.SyncRemediated, "finding:remediated", nil
	}
	if f.Status == finding.StatusFalsePos {
		return domain.SyncFalsePositive, "finding:false_positive", nil
	}
	current, err := w.sla.Current(ctx, tenant, f.EngagementID, f.ID)
	if err == nil && current.Lifecycle.EffectiveStatus(w.clock.Now()) == sla.RemediationAcceptedRisk {
		return domain.SyncAccepted, "finding:accepted", nil
	}
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return "", "", err
	}
	return domain.SyncReopen, "finding:reopen", nil
}

func (w *Workflow) openStatusIntent(ctx context.Context, tenant shared.ID, target ports.TicketStatusTarget, preview Preview, state domain.SyncState, source, transition, key string) (domain.Intent, bool, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(preview.Payload, &payload); err != nil {
		return domain.Intent{}, false, shared.ErrValidation
	}
	var facts snapshotFacts
	if json.Unmarshal(payload["_synapse"], &facts) != nil {
		return domain.Intent{}, false, shared.ErrValidation
	}
	id := w.ids.NewID()
	facts.UpdateRemoteID, facts.UpdateRemoteURL = target.Intent.RemoteID, target.Intent.RemoteURL
	facts.StatusTransitionID, facts.StatusSource = transition, source
	facts.StatusComment = ticketStatusComment(state, target.Mapping.Locale)
	payload["_synapse"], _ = json.Marshal(facts)
	raw, _ := json.Marshal(payload)
	digest := ticketDigest(raw)
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload["fields"], &fields) != nil {
		return domain.Intent{}, false, shared.ErrValidation
	}
	var labels []string
	_ = json.Unmarshal(fields["labels"], &labels)
	labels = append(labels, "synapse-intent-"+id.String())
	fields["labels"], _ = json.Marshal(labels)
	payload["fields"], _ = json.Marshal(fields)
	raw, _ = json.Marshal(payload)
	now := w.clock.Now().UTC()
	i := domain.Intent{ID: id, TenantID: tenant, IntegrationID: target.Mapping.IntegrationID, MappingID: target.Mapping.ID, FindingID: target.Intent.FindingID, EngagementID: target.Intent.EngagementID, Action: domain.Transition, RequestKey: key, PayloadDigest: digest, Marker: "synapse-intent-" + id.String(), State: writeintent.Pending, Version: 1, Snapshot: raw, MappingVersion: target.Mapping.Version, ConnectionRevision: facts.ConnectionRevision, CredentialRevision: facts.CredentialRevision, SecurityLevel: target.Mapping.SecurityLevel, CreatedAt: now, UpdatedAt: now}
	entry := ports.AuditEntry{Actor: "system:ticket_status", Action: "ticket.intent.status_transition", Target: id.String(), At: now, Metadata: map[string]string{"state": string(state), "source": source}}
	return w.intentAudit.CreateOrGetIntentAudited(ctx, tenant, i, entry)
}

func ticketStatusComment(state domain.SyncState, locale string) string {
	if strings.EqualFold(locale, "vi") {
		labels := map[domain.SyncState]string{
			domain.SyncRemediated:    "đã khắc phục",
			domain.SyncAccepted:      "đã chấp nhận rủi ro",
			domain.SyncFalsePositive: "dương tính giả",
			domain.SyncReopen:        "mở lại",
		}
		return "Synapse đã đồng bộ trạng thái: " + labels[state]
	}
	labels := map[domain.SyncState]string{
		domain.SyncRemediated:    "remediated",
		domain.SyncAccepted:      "accepted risk",
		domain.SyncFalsePositive: "false positive",
		domain.SyncReopen:        "reopened",
	}
	return "Synapse synchronized status: " + labels[state]
}
