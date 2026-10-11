package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.NotificationTemplateStore = (*NotificationTemplateStore)(nil)

// NotificationTemplateStore is the in-memory ports.NotificationTemplateStore. It applies the same
// rules as the PostgreSQL store (0195): rows are keyed by tenant, versions are never rewritten, and
// at most one template per key is active.
type NotificationTemplateStore struct {
	mu        sync.Mutex
	templates map[templateRef]notification.Template
	versions  map[templateRef][]notification.TemplateVersion
}

type templateRef struct{ tenant, id shared.ID }

// NewNotificationTemplateStore returns an empty store.
func NewNotificationTemplateStore() *NotificationTemplateStore {
	return &NotificationTemplateStore{
		templates: map[templateRef]notification.Template{},
		versions:  map[templateRef][]notification.TemplateVersion{},
	}
}

func (s *NotificationTemplateStore) CreateNotificationTemplate(_ context.Context, t notification.Template, fields map[string]string) (notification.Template, notification.TemplateVersion, error) {
	if err := t.ValidateNew(); err != nil {
		return notification.Template{}, notification.TemplateVersion{}, err
	}
	if err := notification.ValidateTemplateFields(t.Family, fields); err != nil {
		return notification.Template{}, notification.TemplateVersion{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := templateRef{t.TenantID, t.ID}
	if _, exists := s.templates[ref]; exists {
		return notification.Template{}, notification.TemplateVersion{}, fmt.Errorf("%w: notification template %s already exists", shared.ErrConflict, t.ID)
	}
	t.Status, t.LatestVersion, t.ActiveVersion, t.Revision = notification.TemplateDraft, 1, 0, 1
	t.UpdatedAt, t.UpdatedBy = t.CreatedAt, t.CreatedBy
	v := memoryTemplateVersion(t.TenantID, t.ID, 1, fields, t.CreatedAt, t.CreatedBy)
	s.templates[ref] = t
	s.versions[ref] = []notification.TemplateVersion{v}
	return t, cloneTemplateVersion(v), nil
}

func (s *NotificationTemplateStore) AppendNotificationTemplateVersion(_ context.Context, u ports.NotificationTemplateUpdate) (notification.Template, notification.TemplateVersion, error) {
	if err := u.Validate(); err != nil {
		return notification.Template{}, notification.TemplateVersion{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := templateRef{u.TenantID, u.ID}
	head, err := s.lockedHead(ref, u.ExpectedRevision)
	if err != nil {
		return notification.Template{}, notification.TemplateVersion{}, err
	}
	if err := notification.ValidateTemplateFields(head.Family, u.Fields); err != nil {
		return notification.Template{}, notification.TemplateVersion{}, err
	}
	v := memoryTemplateVersion(u.TenantID, u.ID, head.LatestVersion+1, u.Fields, u.At, u.Actor)
	if u.Name != "" {
		head.Name = u.Name
	}
	head.LatestVersion = v.Version
	touchTemplate(&head, u.At, u.Actor)
	s.templates[ref] = head
	s.versions[ref] = append(s.versions[ref], v)
	return head, cloneTemplateVersion(v), nil
}

func (s *NotificationTemplateStore) ActivateNotificationTemplate(_ context.Context, c ports.NotificationTemplateChange) (notification.Template, shared.ID, error) {
	if err := c.Validate(); err != nil {
		return notification.Template{}, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := templateRef{c.TenantID, c.ID}
	head, err := s.lockedHead(ref, c.ExpectedRevision)
	if err != nil {
		return notification.Template{}, "", err
	}
	version := c.Version
	if version == 0 {
		version = head.LatestVersion
	}
	if version > head.LatestVersion {
		return notification.Template{}, "", fmt.Errorf("notification template version %d: %w", version, shared.ErrNotFound)
	}
	var archived shared.ID
	for otherRef, other := range s.templates {
		if otherRef.tenant == c.TenantID && otherRef.id != c.ID && other.Status == notification.TemplateActive && other.TemplateKey == head.TemplateKey {
			other.Status = notification.TemplateArchived
			touchTemplate(&other, c.At, c.Actor)
			s.templates[otherRef] = other
			archived = otherRef.id
		}
	}
	head.Status, head.ActiveVersion = notification.TemplateActive, version
	touchTemplate(&head, c.At, c.Actor)
	s.templates[ref] = head
	return head, archived, nil
}

func (s *NotificationTemplateStore) ArchiveNotificationTemplate(_ context.Context, c ports.NotificationTemplateChange) (notification.Template, error) {
	if err := c.Validate(); err != nil {
		return notification.Template{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := templateRef{c.TenantID, c.ID}
	head, err := s.lockedHead(ref, c.ExpectedRevision)
	if err != nil {
		return notification.Template{}, err
	}
	head.Status = notification.TemplateArchived
	touchTemplate(&head, c.At, c.Actor)
	s.templates[ref] = head
	return head, nil
}

func (s *NotificationTemplateStore) GetNotificationTemplate(_ context.Context, tenant, id shared.ID) (notification.Template, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	head, ok := s.templates[templateRef{tenant, id}]
	if !ok {
		return notification.Template{}, fmt.Errorf("read notification template: %w", shared.ErrNotFound)
	}
	return head, nil
}

func (s *NotificationTemplateStore) ListNotificationTemplates(_ context.Context, tenant shared.ID, q ports.NotificationTemplateQuery) ([]notification.Template, error) {
	limit := ports.ClampNotificationTemplatePage(q.Limit, ports.DefaultNotificationTemplatePage, ports.MaxNotificationTemplatePage)
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []notification.Template
	for ref, head := range s.templates {
		if ref.tenant != tenant || ref.id <= q.AfterID ||
			(q.EventType != "" && head.EventType != q.EventType) || (q.Family != "" && head.Family != q.Family) ||
			(q.Locale != "" && head.Locale != q.Locale) || (q.Status != "" && head.Status != q.Status) {
			continue
		}
		out = append(out, head)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *NotificationTemplateStore) GetNotificationTemplateVersion(_ context.Context, tenant, id shared.ID, version int) (notification.TemplateVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions := s.versions[templateRef{tenant, id}]
	if version < 1 || version > len(versions) {
		return notification.TemplateVersion{}, fmt.Errorf("read notification template version: %w", shared.ErrNotFound)
	}
	return cloneTemplateVersion(versions[version-1]), nil
}

func (s *NotificationTemplateStore) ListNotificationTemplateVersions(_ context.Context, tenant, id shared.ID, before, limit int) ([]notification.TemplateVersion, error) {
	limit = ports.ClampNotificationTemplatePage(limit, ports.DefaultNotificationTemplateVersionPage, ports.MaxNotificationTemplateVersionPage)
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := templateRef{tenant, id}
	if _, ok := s.templates[ref]; !ok {
		return nil, fmt.Errorf("list notification template versions: %w", shared.ErrNotFound)
	}
	versions := s.versions[ref]
	out := []notification.TemplateVersion{}
	for i := len(versions) - 1; i >= 0 && len(out) < limit; i-- {
		if before > 0 && versions[i].Version >= before {
			continue
		}
		out = append(out, cloneTemplateVersion(versions[i]))
	}
	return out, nil
}

func (s *NotificationTemplateStore) ActiveNotificationTemplate(_ context.Context, tenant shared.ID, key notification.TemplateKey) (notification.Template, notification.TemplateVersion, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ref, head := range s.templates {
		if ref.tenant == tenant && head.Status == notification.TemplateActive && head.TemplateKey == key {
			return head, cloneTemplateVersion(s.versions[ref][head.ActiveVersion-1]), true, nil
		}
	}
	return notification.Template{}, notification.TemplateVersion{}, false, nil
}

func (s *NotificationTemplateStore) lockedHead(ref templateRef, expectedRevision int) (notification.Template, error) {
	head, ok := s.templates[ref]
	if !ok {
		return notification.Template{}, fmt.Errorf("notification template: %w", shared.ErrNotFound)
	}
	if head.Revision != expectedRevision {
		return notification.Template{}, fmt.Errorf("%w: notification template revision is stale", shared.ErrConflict)
	}
	return head, nil
}

func touchTemplate(head *notification.Template, at time.Time, actor string) {
	head.Revision++
	head.UpdatedAt, head.UpdatedBy = at, actor
}

func memoryTemplateVersion(tenant, id shared.ID, version int, fields map[string]string, at time.Time, actor string) notification.TemplateVersion {
	copied := notification.CloneFields(fields)
	return notification.TemplateVersion{TenantID: tenant, TemplateID: id, Version: version, Fields: copied,
		Checksum: notification.TemplateChecksum(copied), CreatedAt: at, CreatedBy: actor}
}

func cloneTemplateVersion(v notification.TemplateVersion) notification.TemplateVersion {
	v.Fields = notification.CloneFields(v.Fields)
	return v
}
