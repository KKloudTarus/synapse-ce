package config

import "testing"

func TestNotificationSLABreachReminderBounds(t *testing.T) {
	for _, count := range []int{-1, 0, 4, 8, 9} {
		c := Config{NotificationSLABreachMaxReminders: count}
		err := c.ValidateNotificationEvents()
		if (err == nil) != (count >= 0 && count <= 8) {
			t.Fatalf("count=%d error=%v", count, err)
		}
	}
	t.Setenv("SYNAPSE_NOTIFICATION_SLA_BREACH_MAX_REMINDERS", "")
	if got := Load().NotificationSLABreachMaxReminders; got != 4 {
		t.Fatalf("default=%d", got)
	}
	t.Setenv("SYNAPSE_NOTIFICATION_SLA_BREACH_MAX_REMINDERS", "0")
	if got := Load().NotificationSLABreachMaxReminders; got != 0 {
		t.Fatalf("zero override=%d", got)
	}
}
