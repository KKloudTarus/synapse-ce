package notification

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Data classes per destination (EPIC #1327 D7, #1360). Every channel has a maximum data class, and
// an engagement can lower it for its own events. The class decides which template variables a
// message renders (TemplateContext.Filter).

// Valid reports whether c is one of the three classes.
func (c DataClass) Valid() bool { return c.Rank() > 0 }

// DefaultDataClass is the class a new channel gets. Chat and pager messages land in shared rooms
// and on phones, so they default to signal (event type, severity, counts, link); email and
// webhooks go to a named destination and default to summary.
func DefaultDataClass(t ChannelType) DataClass {
	switch family, _ := FamilyForChannelType(t); family {
	case FamilyChat, FamilyPager:
		return DataClassSignal
	}
	return DataClassSummary
}

// Raises reports whether moving a channel from c to next exposes more data. Raising a class needs
// the administer permission (#1360); lowering it does not.
func (c DataClass) Raises(next DataClass) bool { return next.Rank() > c.Rank() }

// EngagementNotifications is an engagement's override for messages about it that leave Synapse.
type EngagementNotifications string

const (
	// EngagementNotificationsInherit sends at each channel's own class (the default).
	EngagementNotificationsInherit EngagementNotifications = "inherit"
	// EngagementNotificationsSignal caps every channel at signal for this engagement.
	EngagementNotificationsSignal EngagementNotifications = "signal"
	// EngagementNotificationsNone sends nothing external about this engagement.
	EngagementNotificationsNone EngagementNotifications = "none"
)

// Valid reports whether v is one of the three settings.
func (v EngagementNotifications) Valid() bool {
	switch v {
	case EngagementNotificationsInherit, EngagementNotificationsSignal, EngagementNotificationsNone:
		return true
	}
	return false
}

// rank orders the settings by how much they let through: none < signal < inherit.
func (v EngagementNotifications) rank() int {
	switch v {
	case EngagementNotificationsNone:
		return 0
	case EngagementNotificationsSignal:
		return 1
	}
	return 2
}

// Raises reports whether moving an engagement from v to next lets more data out.
func (v EngagementNotifications) Raises(next EngagementNotifications) bool {
	return next.rank() > v.rank()
}

// EngagementNotificationSetting is one engagement's override. An engagement without a stored
// setting inherits (revision 0).
type EngagementNotificationSetting struct {
	TenantID              shared.ID               `json:"-"`
	EngagementID          shared.ID               `json:"engagement_id"`
	ExternalNotifications EngagementNotifications `json:"external_notifications"`
	Revision              int                     `json:"revision"`
	UpdatedAt             *time.Time              `json:"updated_at,omitempty"`
	UpdatedBy             string                  `json:"updated_by,omitempty"`
}

// Validate checks a setting about to be stored.
func (s EngagementNotificationSetting) Validate() error {
	actor := strings.TrimSpace(s.UpdatedBy)
	if s.TenantID.IsZero() || s.EngagementID.IsZero() || !s.ExternalNotifications.Valid() || s.Revision < 1 ||
		s.UpdatedAt == nil || actor == "" || len(actor) > 200 {
		return fmt.Errorf("%w: invalid engagement notification setting", shared.ErrValidation)
	}
	return nil
}

// EffectiveDataClass combines a channel's class with the engagement's setting; the lower wins.
// deliver is false when the engagement allows no external notification at all. An event without an
// engagement passes EngagementNotificationsInherit.
func EffectiveDataClass(channel DataClass, engagement EngagementNotifications) (class DataClass, deliver bool) {
	if !channel.Valid() {
		channel = DataClassSignal
	}
	switch engagement {
	case EngagementNotificationsNone:
		return "", false
	case EngagementNotificationsSignal:
		return DataClassSignal, true
	}
	return channel, true
}

// Filter keeps the variables of the context whose declared class is at most class. A variable the
// event type does not declare is dropped, so a filtered context never carries more than its
// catalog entry describes.
func (c TemplateContext) Filter(spec EventSpec, class DataClass) TemplateContext {
	out := TemplateContext{Vars: map[string]string{}}
	limit := class.Rank()
	for _, v := range spec.Variables {
		value, ok := c.Vars[v.Name]
		if ok && v.ListCap == 0 && v.Class.Rank() <= limit {
			out.Vars[v.Name] = value
		}
	}
	return out
}

func invalidDataClass() error {
	return fmt.Errorf("%w: data class must be signal, summary or detail", shared.ErrValidation)
}
