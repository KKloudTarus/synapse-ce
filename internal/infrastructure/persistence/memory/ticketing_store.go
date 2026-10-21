package memory

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TicketStore is an in-memory conformance adapter. PostgreSQL is the durable production store.
// Every map is tenant partitioned and every returned composite value is cloned.
type TicketStore struct {
	mu                    sync.RWMutex
	engagements           *EngagementRepository
	findings              *FindingRepository
	groupAssets           ports.AssetRepository
	groupBindings         ports.AttackPathStore
	mappings              map[shared.ID]map[shared.ID]ticketing.Mapping
	links                 map[shared.ID]map[shared.ID]ticketing.Link
	intents               map[shared.ID]map[shared.ID]ticketing.Intent
	groups                map[shared.ID]map[string]ports.TicketGroup
	groupMembers          map[shared.ID]map[shared.ID]map[string]ports.TicketGroupMember
	breakers              map[string]memoryTicketBreaker
	autoEvents            map[shared.ID][]ports.TicketAutoPushEvent
	autoReceipts          map[shared.ID]map[shared.ID]memoryAutoPushReceipt
	statusProgress        map[shared.ID]map[string]ports.TicketStatusProgress
	inboundConfigurations map[shared.ID]map[shared.ID]ports.TicketInboundConfiguration
	inboundObservations   map[shared.ID]map[string]ticketing.ExternalTicketObservation
	inboundProposals      map[shared.ID][]ticketing.RetestProposal
	inboundComments       map[shared.ID][]ticketing.ExternalTicketComment
	inboundPollProgress   map[shared.ID]map[string]memoryInboundPollProgress
	audit                 ports.AuditLogger
}
type memoryTicketBreaker struct {
	active      shared.ID
	lease, gate *time.Time
	code        string
}
type memoryAutoPushReceipt struct {
	availableAt time.Time
	completed   bool
}
type memoryInboundPollProgress struct {
	checkedAt  time.Time
	nextPollAt time.Time
	version    int
}

var _ ports.TicketStore = (*TicketStore)(nil)
var _ ports.TicketIntentAuditStore = (*TicketStore)(nil)
var _ ports.TicketDispatchStore = (*TicketStore)(nil)
var _ ports.TicketAutoPushStore = (*TicketStore)(nil)
var _ ports.TicketGroupStore = (*TicketStore)(nil)
var _ ports.TicketStatusStore = (*TicketStore)(nil)
var _ ports.TicketStatusProgressStore = (*TicketStore)(nil)

func NewTicketStore(engagements *EngagementRepository, findings *FindingRepository) (*TicketStore, error) {
	if engagements == nil || findings == nil {
		return nil, fmt.Errorf("%w: ticket store requires engagement and finding repositories", shared.ErrValidation)
	}
	return &TicketStore{
		engagements:           engagements,
		findings:              findings,
		mappings:              make(map[shared.ID]map[shared.ID]ticketing.Mapping),
		links:                 make(map[shared.ID]map[shared.ID]ticketing.Link),
		intents:               make(map[shared.ID]map[shared.ID]ticketing.Intent),
		groups:                make(map[shared.ID]map[string]ports.TicketGroup),
		groupMembers:          make(map[shared.ID]map[shared.ID]map[string]ports.TicketGroupMember),
		breakers:              make(map[string]memoryTicketBreaker),
		autoEvents:            make(map[shared.ID][]ports.TicketAutoPushEvent),
		autoReceipts:          make(map[shared.ID]map[shared.ID]memoryAutoPushReceipt),
		statusProgress:        make(map[shared.ID]map[string]ports.TicketStatusProgress),
		inboundConfigurations: make(map[shared.ID]map[shared.ID]ports.TicketInboundConfiguration),
		inboundObservations:   make(map[shared.ID]map[string]ticketing.ExternalTicketObservation),
		inboundProposals:      make(map[shared.ID][]ticketing.RetestProposal),
		inboundComments:       make(map[shared.ID][]ticketing.ExternalTicketComment),
		inboundPollProgress:   make(map[shared.ID]map[string]memoryInboundPollProgress),
	}, nil
}

func ticketStatusProgressKey(mappingID, engagementID, findingID shared.ID) string {
	return mappingID.String() + "\x00" + engagementID.String() + "\x00" + findingID.String()
}

func (s *TicketStore) GetTicketStatusProgress(ctx context.Context, tenant, mappingID, engagementID, findingID shared.ID) (ports.TicketStatusProgress, error) {
	if err := ctx.Err(); err != nil {
		return ports.TicketStatusProgress{}, err
	}
	if tenant.IsZero() || mappingID.IsZero() || engagementID.IsZero() || findingID.IsZero() {
		return ports.TicketStatusProgress{}, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.statusProgress[tenant][ticketStatusProgressKey(mappingID, engagementID, findingID)]
	if !ok {
		return ports.TicketStatusProgress{}, shared.ErrNotFound
	}
	return item, nil
}

func (s *TicketStore) CreateTicketStatusProgress(ctx context.Context, tenant shared.ID, item ports.TicketStatusProgress) (ports.TicketStatusProgress, bool, error) {
	if err := ctx.Err(); err != nil {
		return ports.TicketStatusProgress{}, false, err
	}
	if tenant.IsZero() || item.TenantID != tenant || item.MappingID.IsZero() || item.EngagementID.IsZero() || item.FindingID.IsZero() || !item.DesiredState.Valid() || item.SourceRevision == "" {
		return ports.TicketStatusProgress{}, false, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.statusProgress[tenant] == nil {
		s.statusProgress[tenant] = map[string]ports.TicketStatusProgress{}
	}
	key := ticketStatusProgressKey(item.MappingID, item.EngagementID, item.FindingID)
	if existing, ok := s.statusProgress[tenant][key]; ok {
		return existing, false, nil
	}
	item.Version = 1
	item.Episode = 1
	s.statusProgress[tenant][key] = item
	return item, true, nil
}

func (s *TicketStore) UpdateTicketStatusProgress(ctx context.Context, tenant shared.ID, item ports.TicketStatusProgress, expected int) (ports.TicketStatusProgress, error) {
	if err := ctx.Err(); err != nil {
		return ports.TicketStatusProgress{}, err
	}
	if tenant.IsZero() || item.TenantID != tenant || item.MappingID.IsZero() || item.EngagementID.IsZero() || item.FindingID.IsZero() || expected < 1 || item.Episode < 1 || !item.DesiredState.Valid() || item.SourceRevision == "" {
		return ports.TicketStatusProgress{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ticketStatusProgressKey(item.MappingID, item.EngagementID, item.FindingID)
	existing, ok := s.statusProgress[tenant][key]
	if !ok {
		return ports.TicketStatusProgress{}, shared.ErrNotFound
	}
	if existing.Version != expected {
		return ports.TicketStatusProgress{}, shared.ErrConflict
	}
	item.Version = existing.Version + 1
	s.statusProgress[tenant][key] = item
	return item, nil
}

func ticketGroupKey(g ports.TicketGroup) string {
	return g.MappingID.String() + "\x00" + g.ProjectID.String() + "\x00" + g.Vulnerability
}
func sameTicketGroupDestination(a, b ports.TicketGroup) bool {
	return a.IntegrationID == b.IntegrationID && a.Endpoint == b.Endpoint && a.ProjectKey == b.ProjectKey &&
		a.IssueType == b.IssueType && a.SecurityLevel == b.SecurityLevel
}
func ticketGroupMemberKey(m ports.TicketGroupMember) string {
	return m.EngagementID.String() + "\x00" + m.FindingID.String()
}

func (s *TicketStore) ValidateTicketGroupDestination(ctx context.Context, tenant shared.ID, candidate ports.TicketGroup) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || candidate.TenantID != tenant || candidate.MappingID.IsZero() {
		return shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, existing := range s.groups[tenant] {
		if existing.MappingID == candidate.MappingID && !sameTicketGroupDestination(existing, candidate) {
			return shared.ErrConflict
		}
	}
	return nil
}

func (s *TicketStore) GetTicketGroup(ctx context.Context, tenant, mappingID, projectID shared.ID, vulnerability string) (ports.TicketGroup, bool, error) {
	if err := ctx.Err(); err != nil {
		return ports.TicketGroup{}, false, err
	}
	if tenant.IsZero() || mappingID.IsZero() || projectID.IsZero() || strings.TrimSpace(vulnerability) == "" {
		return ports.TicketGroup{}, false, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	group, ok := s.groups[tenant][mappingID.String()+"\x00"+projectID.String()+"\x00"+vulnerability]
	return group, ok, nil
}

func (s *TicketStore) ListTicketStatusTargets(ctx context.Context, tenant shared.ID, limit int) ([]ports.TicketStatusTarget, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || limit < 1 || limit > 200 {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ports.TicketStatusTarget, 0, limit)
	for _, intent := range s.intents[tenant] {
		if intent.State != writeintent.Done || intent.Action != ticketing.Create || intent.RemoteID == "" {
			continue
		}
		mapping, ok := s.mappings[tenant][intent.MappingID]
		if !ok || len(mapping.StatusTransitions) == 0 {
			continue
		}
		out = append(out, ports.TicketStatusTarget{Mapping: mapping.Clone(), Intent: intent.Clone()})
	}
	slices.SortFunc(out, func(a, b ports.TicketStatusTarget) int {
		left, leftSeen := s.statusProgress[tenant][ticketStatusProgressKey(a.Mapping.ID, a.Intent.EngagementID, a.Intent.FindingID)]
		right, rightSeen := s.statusProgress[tenant][ticketStatusProgressKey(b.Mapping.ID, b.Intent.EngagementID, b.Intent.FindingID)]
		if leftSeen != rightSeen {
			if !leftSeen {
				return -1
			}
			return 1
		}
		leftAt, leftVersion := left.CheckedAt, left.Version
		rightAt, rightVersion := right.CheckedAt, right.Version
		if cmp := leftAt.Compare(rightAt); cmp != 0 {
			return cmp
		}
		if leftVersion != rightVersion {
			return leftVersion - rightVersion
		}
		return strings.Compare(a.Intent.ID.String(), b.Intent.ID.String())
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *TicketStore) CreateOrGetGroupedIntent(ctx context.Context, tenant shared.ID, group ports.TicketGroup, member ports.TicketGroupMember, intent ticketing.Intent, audit ports.AuditEntry) (ticketing.Intent, bool, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, false, err
	}
	if tenant.IsZero() || group.TenantID != tenant || group.ID.IsZero() || group.MappingID != intent.MappingID || group.ProjectID.IsZero() || group.Vulnerability == "" || group.IntegrationID != intent.IntegrationID || group.Endpoint == "" || group.ProjectKey == "" || group.IssueType == "" || member.EngagementID != intent.EngagementID || member.FindingID != intent.FindingID || (intent.Action != ticketing.Create && intent.Action != ticketing.Update) || group.Revision < 0 {
		return ticketing.Intent{}, false, shared.ErrValidation
	}
	if err := intent.Validate(); err != nil {
		return ticketing.Intent{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, old := range s.intents[tenant] {
		if old.IntegrationID == intent.IntegrationID && old.RequestKey == intent.RequestKey {
			if !sameCommand(old, intent) {
				return ticketing.Intent{}, false, shared.ErrConflict
			}
			return old.Clone(), false, nil
		}
	}
	if err := s.validateIntentReferences(ctx, tenant, intent, s.mappings[tenant][intent.MappingID]); err != nil {
		return ticketing.Intent{}, false, err
	}
	key := ticketGroupKey(group)
	persisted, exists := s.groups[tenant][key]
	if exists {
		if !sameTicketGroupDestination(persisted, group) {
			return ticketing.Intent{}, false, shared.ErrConflict
		}
		if persisted.Revision != group.Revision {
			return ticketing.Intent{}, false, fmt.Errorf("%w: %w", shared.ErrConflict, ticketing.ErrGroupBusy)
		}
		previous, ok := s.intents[tenant][persisted.IntentID]
		if !ok {
			return ticketing.Intent{}, false, shared.ErrConflict
		}
		if previous.State != writeintent.Done && previous.State != writeintent.Failed {
			return ticketing.Intent{}, false, fmt.Errorf("%w: %w", shared.ErrConflict, ticketing.ErrGroupBusy)
		}
		if persisted.Remote.ID == "" && previous.State == writeintent.Done {
			persisted.Remote = ticketing.RemoteTicket{ID: previous.RemoteID, URL: previous.RemoteURL}
		}
		if (persisted.Remote.ID != "" && intent.Action != ticketing.Update) || (persisted.Remote.ID == "" && intent.Action != ticketing.Create) {
			return ticketing.Intent{}, false, fmt.Errorf("%w: %w", shared.ErrConflict, ticketing.ErrGroupBusy)
		}
	} else {
		if group.Revision != 0 || intent.Action != ticketing.Create {
			return ticketing.Intent{}, false, shared.ErrConflict
		}
		persisted = group
	}
	if _, duplicate := s.intents[tenant][intent.ID]; duplicate {
		return ticketing.Intent{}, false, shared.ErrConflict
	}
	if err := s.recordTicketAuditLocked(ctx, tenant, &audit); err != nil {
		return ticketing.Intent{}, false, err
	}
	if s.groups[tenant] == nil {
		s.groups[tenant] = make(map[string]ports.TicketGroup)
	}
	if s.groupMembers[tenant] == nil {
		s.groupMembers[tenant] = make(map[shared.ID]map[string]ports.TicketGroupMember)
	}
	if s.groupMembers[tenant][persisted.ID] == nil {
		s.groupMembers[tenant][persisted.ID] = make(map[string]ports.TicketGroupMember)
	}
	if s.intents[tenant] == nil {
		s.intents[tenant] = make(map[shared.ID]ticketing.Intent)
	}
	persisted.IntentID = intent.ID
	persisted.Revision++
	persisted.UpdatedAt = group.UpdatedAt
	s.groups[tenant][key] = persisted
	s.groupMembers[tenant][persisted.ID][ticketGroupMemberKey(member)] = member
	s.intents[tenant][intent.ID] = intent.Clone()
	return intent.Clone(), true, nil
}

func (s *TicketStore) CompleteGroupedIntent(ctx context.Context, tenant, intentID shared.ID, remote ticketing.RemoteTicket, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || intentID.IsZero() || at.IsZero() {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, group := range s.groups[tenant] {
		if group.IntentID == intentID {
			group.Remote, group.UpdatedAt = remote, at
			s.groups[tenant][key] = group
			return nil
		}
	}
	return shared.ErrNotFound
}

// AppendAutoPushEvent is an in-memory adapter seam for development and workflow
// tests. Production reads the notification_events projection in PostgreSQL.
func (s *TicketStore) AppendAutoPushEvent(tenant shared.ID, event ports.TicketAutoPushEvent) error {
	if tenant.IsZero() || event.ID.IsZero() || event.OccurredAt.IsZero() {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, current := range s.autoEvents[tenant] {
		if current.ID == event.ID {
			return nil
		}
	}
	s.autoEvents[tenant] = append(s.autoEvents[tenant], event)
	sort.Slice(s.autoEvents[tenant], func(i, j int) bool {
		a, b := s.autoEvents[tenant][i], s.autoEvents[tenant][j]
		if a.OccurredAt.Equal(b.OccurredAt) {
			return a.ID < b.ID
		}
		return a.OccurredAt.Before(b.OccurredAt)
	})
	return nil
}

func (s *TicketStore) ListAutoPushEvents(ctx context.Context, tenant shared.ID, now time.Time, limit int) ([]ports.TicketAutoPushEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || limit < 1 || limit > 100 {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ports.TicketAutoPushEvent, 0, limit)
	for _, event := range s.autoEvents[tenant] {
		receipt, exists := s.autoReceipts[tenant][event.ID]
		if exists && (receipt.completed || receipt.availableAt.After(now)) {
			continue
		}
		out = append(out, event)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (s *TicketStore) CompleteAutoPushEvent(ctx context.Context, tenant shared.ID, event ports.TicketAutoPushEvent, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || event.ID.IsZero() || event.OccurredAt.IsZero() {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.autoReceipts[tenant] == nil {
		s.autoReceipts[tenant] = make(map[shared.ID]memoryAutoPushReceipt)
	}
	s.autoReceipts[tenant][event.ID] = memoryAutoPushReceipt{availableAt: at, completed: true}
	return nil
}
func (s *TicketStore) DeferAutoPushEvent(ctx context.Context, tenant shared.ID, event ports.TicketAutoPushEvent, retryAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || event.ID.IsZero() || event.OccurredAt.IsZero() || retryAt.IsZero() {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.autoReceipts[tenant] == nil {
		s.autoReceipts[tenant] = make(map[shared.ID]memoryAutoPushReceipt)
	}
	if current := s.autoReceipts[tenant][event.ID]; !current.completed {
		s.autoReceipts[tenant][event.ID] = memoryAutoPushReceipt{availableAt: retryAt}
	}
	return nil
}
func (s *TicketStore) SetAudit(audit ports.AuditLogger) { s.mu.Lock(); s.audit = audit; s.mu.Unlock() }
func ticketBreakerKey(t ticketing.DispatchTuple) string {
	return t.TenantID.String() + "\x00" + t.IntegrationID.String() + "\x00" + t.ProjectKey + "\x00" + t.IssueType
}
func (s *TicketStore) createMapping(ctx context.Context, tenant shared.ID, m ticketing.Mapping, audit *ports.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.GroupingMode == "" {
		m.GroupingMode = ticketing.GroupingFinding
	}
	if err := m.Validate(); err != nil {
		return err
	}
	if tenant.IsZero() || m.TenantID != tenant {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.mappings[tenant] {
		if item.ID == m.ID ||
			(item.IntegrationID == m.IntegrationID && item.Scope == m.Scope && item.ScopeID == m.ScopeID) {
			return shared.ErrConflict
		}
	}
	if s.mappings[tenant] == nil {
		s.mappings[tenant] = make(map[shared.ID]ticketing.Mapping)
	}
	if err := s.recordTicketAuditLocked(ctx, tenant, audit); err != nil {
		return err
	}
	s.mappings[tenant][m.ID] = m.Clone()
	return nil
}
func (s *TicketStore) validateMappingScope(ctx context.Context, tenant shared.ID, m ticketing.Mapping) error {
	tenantCtx := shared.WithTenant(ctx, tenant)
	switch m.Scope {
	case ticketing.Engagement:
		_, err := s.engagements.GetByIDInTenant(tenantCtx, tenant, m.ScopeID)
		return err
	case ticketing.Project:
		_, err := s.engagements.GetByProjectID(tenantCtx, tenant, m.ScopeID)
		return err
	default:
		return shared.ErrValidation
	}
}
func (s *TicketStore) GetMapping(ctx context.Context, tenant, id shared.ID) (ticketing.Mapping, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Mapping{}, err
	}
	if tenant.IsZero() || id.IsZero() {
		return ticketing.Mapping{}, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if item, ok := s.mappings[tenant][id]; ok {
		return item.Clone(), nil
	}
	return ticketing.Mapping{}, shared.ErrNotFound
}
func (s *TicketStore) ListMappings(ctx context.Context, tenant shared.ID, limit int, after shared.ID) ([]ticketing.Mapping, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || limit < 1 || limit > 200 {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ticketing.Mapping, 0, min(limit, len(s.mappings[tenant])))
	for _, item := range s.mappings[tenant] {
		if after.IsZero() || item.ID.String() > after.String() {
			out = append(out, item.Clone())
		}
	}
	slices.SortFunc(out, func(a, b ticketing.Mapping) int { return strings.Compare(a.ID.String(), b.ID.String()) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (s *TicketStore) ListScopedMappings(ctx context.Context, tenant shared.ID, scope ticketing.Scope, scopeID shared.ID, limit int) ([]ticketing.Mapping, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || limit < 1 || limit > 200 {
		return nil, shared.ErrValidation
	}
	if scope == "" {
		if !scopeID.IsZero() {
			return nil, shared.ErrValidation
		}
		return s.ListMappings(ctx, tenant, limit, "")
	}
	if scopeID.IsZero() || (scope != ticketing.Project && scope != ticketing.Engagement) {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ticketing.Mapping, 0, min(limit, len(s.mappings[tenant])))
	for _, m := range s.mappings[tenant] {
		if m.Scope == scope && m.ScopeID == scopeID {
			out = append(out, m.Clone())
		}
	}
	slices.SortFunc(out, func(a, b ticketing.Mapping) int { return strings.Compare(a.ID.String(), b.ID.String()) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (s *TicketStore) ListFindingMappings(ctx context.Context, tenant, engagementID shared.ID, limit int) ([]ticketing.Mapping, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || engagementID.IsZero() || limit < 1 || limit > 200 {
		return nil, shared.ErrValidation
	}
	s.engagements.mu.RLock()
	engagement, owned := s.engagements.data[engagementID]
	s.engagements.mu.RUnlock()
	if !owned || engagement.TenantID != tenant {
		return nil, shared.ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ticketing.Mapping, 0, min(limit, len(s.mappings[tenant])))
	for _, m := range s.mappings[tenant] {
		if (m.Scope == ticketing.Engagement && m.ScopeID == engagementID) || (m.Scope == ticketing.Project && m.ScopeID == engagement.ProjectID) {
			out = append(out, m.Clone())
		}
	}
	slices.SortFunc(out, func(a, b ticketing.Mapping) int { return strings.Compare(a.ID.String(), b.ID.String()) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (s *TicketStore) updateMapping(ctx context.Context, tenant shared.ID, m ticketing.Mapping, expected int, audit *ports.AuditEntry) (ticketing.Mapping, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Mapping{}, err
	}
	if m.GroupingMode == "" {
		m.GroupingMode = ticketing.GroupingFinding
	}
	if err := m.Validate(); err != nil {
		return ticketing.Mapping{}, err
	}
	if tenant.IsZero() || m.TenantID != tenant || expected < 1 {
		return ticketing.Mapping{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.mappings[tenant][m.ID]
	if !ok {
		return ticketing.Mapping{}, shared.ErrNotFound
	}
	if old.Version != expected {
		return ticketing.Mapping{}, shared.ErrConflict
	}
	for _, item := range s.mappings[tenant] {
		if item.ID != m.ID && item.IntegrationID == m.IntegrationID && item.Scope == m.Scope && item.ScopeID == m.ScopeID {
			return ticketing.Mapping{}, shared.ErrConflict
		}
	}
	m.Version = expected + 1
	if err := s.recordTicketAuditLocked(ctx, tenant, audit); err != nil {
		return ticketing.Mapping{}, err
	}
	s.mappings[tenant][m.ID] = m.Clone()
	return m.Clone(), nil
}
func (s *TicketStore) deleteMapping(ctx context.Context, tenant, id shared.ID, expected int, audit *ports.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || id.IsZero() || expected < 1 {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mappings[tenant][id]
	if !ok {
		return shared.ErrNotFound
	}
	if m.Version != expected {
		return shared.ErrConflict
	}
	for _, i := range s.intents[tenant] {
		if i.MappingID == id {
			return shared.ErrConflict
		}
	}
	if err := s.recordTicketAuditLocked(ctx, tenant, audit); err != nil {
		return err
	}
	delete(s.mappings[tenant], id)
	return nil
}
func (s *TicketStore) CreateLink(ctx context.Context, tenant shared.ID, link ticketing.Link) (ticketing.Link, bool, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Link{}, false, err
	}
	if err := link.Validate(); err != nil {
		return ticketing.Link{}, false, err
	}
	if tenant.IsZero() || tenant != link.TenantID {
		return ticketing.Link{}, false, shared.ErrValidation
	}
	if err := s.validateFindingReference(ctx, tenant, link.EngagementID, link.FindingID); err != nil {
		return ticketing.Link{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.links[tenant] {
		if item.FindingID == link.FindingID && item.ExternalURL == link.ExternalURL {
			if item.EngagementID != link.EngagementID || item.IntegrationID != link.IntegrationID || item.ExternalID != link.ExternalID {
				return ticketing.Link{}, false, shared.ErrConflict
			}
			return item, false, nil
		}
		if item.ID == link.ID {
			return ticketing.Link{}, false, shared.ErrConflict
		}
	}
	if s.links[tenant] == nil {
		s.links[tenant] = make(map[shared.ID]ticketing.Link)
	}
	s.links[tenant][link.ID] = link
	return link, true, nil
}
func (s *TicketStore) ListLinks(ctx context.Context, tenant, finding shared.ID) ([]ticketing.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || finding.IsZero() {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ticketing.Link, 0)
	for _, link := range s.links[tenant] {
		if link.FindingID == finding {
			out = append(out, link)
		}
	}
	// Stable order matches PostgreSQL's (created_at DESC, id DESC).
	slices.SortFunc(out, func(a, b ticketing.Link) int {
		if order := b.CreatedAt.Compare(a.CreatedAt); order != 0 {
			return order
		}
		return strings.Compare(b.ID.String(), a.ID.String())
	})
	if len(out) > 100 {
		out = out[:100]
	}
	return out, nil
}
func (s *TicketStore) GetLink(ctx context.Context, tenant, id shared.ID) (ticketing.Link, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Link{}, err
	}
	if tenant.IsZero() || id.IsZero() {
		return ticketing.Link{}, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	link, ok := s.links[tenant][id]
	if !ok {
		return ticketing.Link{}, shared.ErrNotFound
	}
	return link, nil
}
func (s *TicketStore) DeleteLink(ctx context.Context, tenant, id shared.ID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || id.IsZero() {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.links[tenant][id]; !ok {
		return shared.ErrNotFound
	}
	delete(s.links[tenant], id)
	return nil
}
func sameCommand(a, b ticketing.Intent) bool {
	return a.IntegrationID == b.IntegrationID && a.MappingID == b.MappingID &&
		a.FindingID == b.FindingID && a.EngagementID == b.EngagementID && a.Action == b.Action && a.RequestKey == b.RequestKey &&
		a.PayloadDigest == b.PayloadDigest
}

// validateFindingReference uses the concrete parent stores so the memory adapter
// matches the durable composite finding reference. It intentionally reads the
// tenant-owned engagement directly: GetByIDInTenant hides internal project contexts,
// which are valid ticketing parents, while this adapter still must not expose or
// accept another tenant's context.
func (s *TicketStore) validateFindingReference(ctx context.Context, tenant, engagementID, findingID shared.ID) error {
	tenantCtx := shared.WithTenant(ctx, tenant)
	if _, err := s.findings.GetByEngagementAndID(tenantCtx, engagementID, findingID); err != nil {
		return err
	}
	s.engagements.mu.RLock()
	engagement, ok := s.engagements.data[engagementID]
	owned := ok && engagement.TenantID == tenant
	s.engagements.mu.RUnlock()
	if !owned {
		return shared.ErrNotFound
	}
	return nil
}

// validateIntentReferences mirrors the durable adapter's foreign-key boundary before
// the in-memory adapter accepts a command. Project contexts are intentionally loaded
// through GetByProjectID because they are internal and cannot be reached through the
// ordinary tenant-scoped engagement read.
func (s *TicketStore) validateIntentReferences(ctx context.Context, tenant shared.ID, intent ticketing.Intent, mapping ticketing.Mapping) error {
	tenantCtx := shared.WithTenant(ctx, tenant)
	if err := s.validateFindingReference(tenantCtx, tenant, intent.EngagementID, intent.FindingID); err != nil {
		return err
	}
	switch mapping.Scope {
	case ticketing.Engagement:
		if mapping.ScopeID != intent.EngagementID {
			return shared.ErrValidation
		}
		return nil
	case ticketing.Project:
		projectContext, err := s.engagements.GetByProjectID(tenantCtx, tenant, mapping.ScopeID)
		if err != nil {
			return err
		}
		if projectContext.ID != intent.EngagementID {
			return shared.ErrValidation
		}
		return nil
	default:
		return shared.ErrValidation
	}
}

func (s *TicketStore) createOrGetIntent(ctx context.Context, tenant shared.ID, intent ticketing.Intent, audit *ports.AuditEntry) (ticketing.Intent, bool, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, false, err
	}
	if err := intent.Validate(); err != nil {
		return ticketing.Intent{}, false, err
	}
	if tenant.IsZero() || intent.TenantID != tenant || intent.State != writeintent.Pending ||
		intent.Attempts != 0 || intent.Version != 1 || intent.LeaseUntil != nil {
		return ticketing.Intent{}, false, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.intents[tenant] {
		if item.IntegrationID == intent.IntegrationID && item.RequestKey == intent.RequestKey {
			if !sameCommand(item, intent) {
				return ticketing.Intent{}, false, shared.ErrConflict
			}
			return item.Clone(), false, nil
		}
		if item.ID == intent.ID || item.Marker == intent.Marker {
			return ticketing.Intent{}, false, shared.ErrConflict
		}
	}
	mapping, ok := s.mappings[tenant][intent.MappingID]
	if !ok || mapping.IntegrationID != intent.IntegrationID {
		return ticketing.Intent{}, false, shared.ErrNotFound
	}
	if err := s.validateIntentReferences(ctx, tenant, intent, mapping); err != nil {
		return ticketing.Intent{}, false, err
	}
	// Only the audited submit path applies the no-blind-repeat policy. The
	// foundation method deliberately remains available for existing durable
	// command conformance and migration recovery.
	if audit != nil && intent.Action == ticketing.Create {
		if s.audit == nil {
			return ticketing.Intent{}, false, fmt.Errorf("%w: ticket audit logger required", shared.ErrValidation)
		}
		for _, item := range s.intents[tenant] {
			if item.ID != intent.ID && item.IntegrationID == intent.IntegrationID && item.FindingID == intent.FindingID &&
				item.Action == ticketing.Create && (item.State == writeintent.Pending || item.State == writeintent.InFlight || item.State == writeintent.Uncertain) {
				return ticketing.Intent{}, false, shared.ErrConflict
			}
		}
	}
	if s.intents[tenant] == nil {
		s.intents[tenant] = make(map[shared.ID]ticketing.Intent)
	}
	if err := s.recordTicketAuditLocked(ctx, tenant, audit); err != nil {
		return ticketing.Intent{}, false, err
	}
	s.intents[tenant][intent.ID] = intent.Clone()
	return intent.Clone(), true, nil
}
func (s *TicketStore) GetIntent(ctx context.Context, tenant, id shared.ID) (ticketing.Intent, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, err
	}
	if tenant.IsZero() || id.IsZero() {
		return ticketing.Intent{}, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if item, ok := s.intents[tenant][id]; ok {
		return item.Clone(), nil
	}
	return ticketing.Intent{}, shared.ErrNotFound
}
func (s *TicketStore) ListFindingIntents(ctx context.Context, tenant, finding shared.ID, limit int) ([]ticketing.Intent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || finding.IsZero() || limit < 1 || limit > 200 {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ticketing.Intent, 0)
	for _, item := range s.intents[tenant] {
		if item.FindingID == finding {
			out = append(out, item.Clone())
		}
	}
	slices.SortFunc(out, func(a, b ticketing.Intent) int {
		if order := b.CreatedAt.Compare(a.CreatedAt); order != 0 {
			return order
		}
		return strings.Compare(b.ID.String(), a.ID.String())
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (s *TicketStore) ListDueIntents(ctx context.Context, tenant shared.ID, now time.Time, limit int) ([]ticketing.Intent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || now.IsZero() || limit < 1 || limit > 200 {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ticketing.Intent, 0)
	for _, item := range s.intents[tenant] {
		if item.State == writeintent.InFlight && item.LeaseUntil != nil && !now.Before(*item.LeaseUntil) {
			out = append(out, item.Clone())
			continue
		}
		if item.State != writeintent.Pending {
			continue
		}
		tuple, tupleErr := item.DispatchTarget()
		if tupleErr != nil {
			out = append(out, item.Clone())
			continue
		} // worker must fail closed legacy commands.
		b := s.breakers[ticketBreakerKey(tuple)]
		if b.gate != nil && now.Before(*b.gate) {
			continue
		}
		if !b.active.IsZero() && b.lease != nil && now.Before(*b.lease) {
			continue
		}
		out = append(out, item.Clone())
	}
	slices.SortFunc(out, func(a, b ticketing.Intent) int {
		if o := a.UpdatedAt.Compare(b.UpdatedAt); o != 0 {
			return o
		}
		return strings.Compare(a.ID.String(), b.ID.String())
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (s *TicketStore) transitionIntent(ctx context.Context, tenant, id shared.ID, expectedVersion int, change ticketing.IntentTransition, at time.Time, audit *ports.AuditEntry) (ticketing.Intent, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, err
	}
	if tenant.IsZero() || id.IsZero() || expectedVersion < 1 || at.IsZero() {
		return ticketing.Intent{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.intents[tenant][id]
	if !ok {
		return ticketing.Intent{}, shared.ErrNotFound
	}
	if current.Version != expectedVersion {
		return ticketing.Intent{}, shared.ErrConflict
	}
	next, err := current.Apply(change, at)
	if err != nil {
		return ticketing.Intent{}, err
	}
	var replacement *ticketing.Link
	if next.State == writeintent.Done {
		desired, completionErr := next.CompletionLink()
		if completionErr != nil {
			return ticketing.Intent{}, completionErr
		}
		for _, existing := range s.links[tenant] {
			if existing.FindingID != desired.FindingID || existing.ExternalURL != desired.ExternalURL {
				continue
			}
			reconciled, reconcileErr := ticketing.ReconcileLink(existing, desired)
			if reconcileErr != nil {
				return ticketing.Intent{}, reconcileErr
			}
			replacement = &reconciled
			break
		}
		if replacement == nil {
			if existing, exists := s.links[tenant][desired.ID]; exists &&
				(existing.FindingID != desired.FindingID || existing.ExternalURL != desired.ExternalURL) {
				return ticketing.Intent{}, shared.ErrConflict
			}
			replacement = &desired
		}
	}
	if err := s.recordTicketAuditLocked(ctx, tenant, audit); err != nil {
		return ticketing.Intent{}, err
	}
	if replacement != nil {
		if s.links[tenant] == nil {
			s.links[tenant] = make(map[shared.ID]ticketing.Link)
		}
		s.links[tenant][replacement.ID] = *replacement
	}
	s.intents[tenant][id] = next.Clone()
	return next.Clone(), nil
}
func (s *TicketStore) AcquireDispatch(ctx context.Context, tenant, id shared.ID, expected int, now, lease time.Time) (ticketing.Intent, bool, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, false, err
	}
	if tenant.IsZero() || id.IsZero() || expected < 1 || !lease.After(now) {
		return ticketing.Intent{}, false, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.intents[tenant][id]
	if !ok {
		return ticketing.Intent{}, false, shared.ErrNotFound
	}
	if i.Version != expected || i.State != writeintent.Pending {
		return ticketing.Intent{}, false, shared.ErrConflict
	}
	t, err := i.DispatchTarget()
	if err != nil {
		return ticketing.Intent{}, false, err
	}
	k := ticketBreakerKey(t)
	b := s.breakers[k]
	if b.gate != nil && now.Before(*b.gate) {
		return ticketing.Intent{}, false, nil
	}
	if !b.active.IsZero() && b.lease != nil && now.Before(*b.lease) {
		return ticketing.Intent{}, false, nil
	}
	if !b.active.IsZero() && b.lease != nil && !now.Before(*b.lease) {
		old := s.intents[tenant][b.active]
		if old.State == writeintent.InFlight {
			old, err = old.Apply(ticketing.IntentTransition{Event: writeintent.LeaseExpired}, now)
			if err != nil {
				return ticketing.Intent{}, false, err
			}
			s.intents[tenant][old.ID] = old
		}
	}
	next, err := i.Apply(ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		return ticketing.Intent{}, false, err
	}
	s.intents[tenant][id] = next
	b.active = id
	b.lease = &lease
	s.breakers[k] = b
	return next.Clone(), true, nil
}
func (s *TicketStore) FinishDispatch(ctx context.Context, tenant, id shared.ID, expected int, change ticketing.IntentTransition, at time.Time, cooldown *time.Time, code string) (ticketing.Intent, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.intents[tenant][id]
	if !ok {
		return ticketing.Intent{}, shared.ErrNotFound
	}
	if i.Version != expected || i.State != writeintent.InFlight {
		return ticketing.Intent{}, shared.ErrConflict
	}
	t, err := i.DispatchTarget()
	if err != nil {
		return ticketing.Intent{}, err
	}
	k := ticketBreakerKey(t)
	b := s.breakers[k]
	if b.active != id || b.lease == nil || !at.Before(*b.lease) {
		return ticketing.Intent{}, shared.ErrConflict
	}
	next, err := i.Apply(change, at)
	if err != nil {
		return ticketing.Intent{}, err
	}
	var replacement *ticketing.Link
	if next.State == writeintent.Done {
		desired, e := next.CompletionLink()
		if e != nil {
			return ticketing.Intent{}, e
		}
		for _, existing := range s.links[tenant] {
			if existing.FindingID == desired.FindingID && existing.ExternalURL == desired.ExternalURL {
				reconciled, e := ticketing.ReconcileLink(existing, desired)
				if e != nil {
					return ticketing.Intent{}, e
				}
				replacement = &reconciled
				break
			}
		}
		if replacement == nil {
			if existing, exists := s.links[tenant][desired.ID]; exists && (existing.FindingID != desired.FindingID || existing.ExternalURL != desired.ExternalURL) {
				return ticketing.Intent{}, shared.ErrConflict
			}
			replacement = &desired
		}
	}
	if replacement != nil {
		if s.links[tenant] == nil {
			s.links[tenant] = make(map[shared.ID]ticketing.Link)
		}
		s.links[tenant][replacement.ID] = *replacement
	}
	s.intents[tenant][id] = next
	b.active = ""
	b.lease = nil
	b.gate = cooldown
	if code == "http_429" {
		code = "rate_limited"
	}
	b.code = code
	if change.Event == writeintent.Reject && (code == "http_401" || code == "http_403" || (i.Action == ticketing.Create && (code == "http_400" || code == "http_404"))) {
		far := at.AddDate(100, 0, 0)
		b.gate = &far
	}
	s.breakers[k] = b
	return next.Clone(), nil
}
func (s *TicketStore) ResetBreaker(ctx context.Context, tenant, integrationID shared.ID, project, issue string, audit ports.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || integrationID.IsZero() || project == "" || issue == "" || !validTicketAudit(audit) {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := ticketBreakerKey(ticketing.DispatchTuple{TenantID: tenant, IntegrationID: integrationID, ProjectKey: project, IssueType: issue})
	b, ok := s.breakers[k]
	if !ok {
		return shared.ErrNotFound
	}
	if s.audit == nil {
		return fmt.Errorf("%w: ticket audit logger required", shared.ErrValidation)
	}
	if (b.code == "rate_limited" || b.code == "http_429") && b.gate != nil && audit.At.Before(*b.gate) {
		return shared.ErrConflict
	}
	if err := s.audit.Record(shared.WithTenant(ctx, tenant), audit); err != nil {
		return err
	}
	b.gate = nil
	b.code = ""
	s.breakers[k] = b
	return nil
}
