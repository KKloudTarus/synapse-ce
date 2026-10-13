package memory

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// NotificationEmailSettingsStore is a narrow in-memory twin for email policy
// usecase tests. Verified contacts can be seeded with SetVerifiedRecipient.
type NotificationEmailSettingsStore struct {
	mu       sync.Mutex
	settings map[shared.ID]ports.NotificationEmailSettings
	domains  map[shared.ID]map[string]time.Time
	contacts map[shared.ID]map[string]bool
}

func NewNotificationEmailSettingsStore() *NotificationEmailSettingsStore {
	return &NotificationEmailSettingsStore{settings: map[shared.ID]ports.NotificationEmailSettings{}, domains: map[shared.ID]map[string]time.Time{}, contacts: map[shared.ID]map[string]bool{}}
}

var _ ports.NotificationEmailSettingsStore = (*NotificationEmailSettingsStore)(nil)

func (s *NotificationEmailSettingsStore) GetNotificationEmailSettings(_ context.Context, tenant shared.ID) (ports.NotificationEmailSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.settings[tenant]
	if !ok {
		return ports.NotificationEmailSettings{TenantID: tenant}, nil
	}
	return value, nil
}

func (s *NotificationEmailSettingsStore) PutNotificationEmailSettings(_ context.Context, value ports.NotificationEmailSettings) (ports.NotificationEmailSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.settings[value.TenantID]
	if (!exists && value.Revision != 1) || (exists && current.Revision+1 != value.Revision) {
		return ports.NotificationEmailSettings{}, fmt.Errorf("notification email settings revision is stale: %w", shared.ErrConflict)
	}
	s.settings[value.TenantID] = value
	safe := value
	safe.Sealed = ""
	return safe, nil
}

func (s *NotificationEmailSettingsStore) ListNotificationEmailDomains(_ context.Context, tenant shared.ID) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]string, 0, len(s.domains[tenant]))
	for domain := range s.domains[tenant] {
		items = append(items, domain)
	}
	sort.Strings(items)
	return items, nil
}

func (s *NotificationEmailSettingsStore) AddNotificationEmailDomain(_ context.Context, tenant shared.ID, domain string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.domains[tenant] == nil {
		s.domains[tenant] = map[string]time.Time{}
	}
	s.domains[tenant][domain] = at
	return nil
}

func (s *NotificationEmailSettingsStore) DeleteNotificationEmailDomain(_ context.Context, tenant shared.ID, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.domains[tenant][domain]; !ok {
		return shared.ErrNotFound
	}
	delete(s.domains[tenant], domain)
	return nil
}

func (s *NotificationEmailSettingsStore) VerifiedNotificationEmailRecipients(_ context.Context, tenant shared.ID, recipients []string) (map[string]bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]bool, len(recipients))
	for _, recipient := range slices.Clone(recipients) {
		normalized, err := userdom.NormalizeContactEmail(recipient)
		if err != nil {
			continue
		}
		if s.contacts[tenant][normalized] {
			result[normalized] = true
		}
	}
	return result, nil
}

func (s *NotificationEmailSettingsStore) SetVerifiedRecipient(tenant shared.ID, recipient string) {
	normalized, err := userdom.NormalizeContactEmail(recipient)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.contacts[tenant] == nil {
		s.contacts[tenant] = map[string]bool{}
	}
	s.contacts[tenant][normalized] = true
}
