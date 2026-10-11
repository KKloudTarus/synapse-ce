package notification

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestPermanentChannelFailureCountsOnlyChannelOwnedFinalCodes(t *testing.T) {
	for _, code := range []string{"destination_blocked", "smtp_destination_blocked", "channel_config_invalid", "smtp_recipient_invalid", "http_400", "http_401", "http_403", "http_404", "http_410", "http_499", "smtp_550", "smtp_554"} {
		if !PermanentChannelFailure(code) {
			t.Errorf("%s should count towards a pause", code)
		}
	}
	for _, code := range []string{
		"", "http_408", "http_429", "http_500", "http_503", "http_302", "network_error", "smtp_connect", "smtp_error", "smtp_421", "smtp_451",
		// Operator-side or internal final failures: pausing every channel would not fix them.
		"smtp_not_configured", "smtp_sender_invalid", "smtp_tls_required", "smtp_auth_unavailable", "channel_secret_unavailable",
		// RFC 4954 AUTH replies describe the shared relay credential, not the channel.
		"smtp_530", "smtp_534", "smtp_535", "smtp_538",
		"encode_failed", "request_invalid", "unsupported_channel", "delivery_failed",
		"http_4000", "http_4x0", "smtp_5",
	} {
		if PermanentChannelFailure(code) {
			t.Errorf("%s must not count towards a pause", code)
		}
	}
}

func TestClassifyAttemptNeverCountsARetryableResult(t *testing.T) {
	if got := ClassifyAttempt(true, "", false); got != AttemptDelivered {
		t.Fatalf("delivered = %v", got)
	}
	// A driver that marks a normally permanent code retryable is trusted: retries decide first.
	if got := ClassifyAttempt(false, "destination_blocked", true); got != AttemptIgnored {
		t.Fatalf("retryable destination_blocked = %v", got)
	}
	if got := ClassifyAttempt(false, "destination_blocked", false); got != AttemptPermanent {
		t.Fatalf("final destination_blocked = %v", got)
	}
	if got := ClassifyAttempt(false, "http_503", false); got != AttemptIgnored {
		t.Fatalf("exhausted 5xx = %v", got)
	}
}

func TestChannelHealthCountingRules(t *testing.T) {
	at := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	h := ChannelHealth{State: ChannelActive}

	h, effect := h.Observe(AttemptPermanent, "http_404", at, 3)
	if effect != HealthUpdated || h.ConsecutiveFailures != 1 || h.LastFailureCode != "http_404" || h.LastFailureAt == nil {
		t.Fatalf("permanent failure: %+v effect=%v", h, effect)
	}
	// A transient failure neither increments nor resets.
	h, effect = h.Observe(AttemptIgnored, "http_503", at.Add(time.Minute), 3)
	if effect != HealthUnchanged || h.ConsecutiveFailures != 1 || h.LastFailureCode != "http_404" {
		t.Fatalf("transient failure changed health: %+v effect=%v", h, effect)
	}
	// A success resets the counter but keeps the last failure for the console.
	h, effect = h.Observe(AttemptDelivered, "", at.Add(2*time.Minute), 3)
	if effect != HealthUpdated || h.ConsecutiveFailures != 0 || h.LastFailureCode != "http_404" || h.Paused() {
		t.Fatalf("success did not reset: %+v effect=%v", h, effect)
	}
	if _, effect = h.Observe(AttemptDelivered, "", at, 3); effect != HealthUnchanged {
		t.Fatal("a success at zero failures should not write")
	}
}

func TestChannelHealthPausesExactlyOnceAtThreshold(t *testing.T) {
	at := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	h := ChannelHealth{}
	pauses := 0
	for i := 0; i < 8; i++ {
		var effect HealthEffect
		h, effect = h.Observe(AttemptPermanent, "destination_blocked", at.Add(time.Duration(i)*time.Second), 5)
		if effect == HealthPausedNow {
			pauses++
			if i != 4 {
				t.Fatalf("paused after %d failures, want 5", i+1)
			}
		}
	}
	if pauses != 1 || !h.Paused() || h.ConsecutiveFailures != 5 || h.PausedReason != PauseReasonPermanentFailures || h.PausedAt == nil || !h.PausedAt.Equal(at.Add(4*time.Second)) {
		t.Fatalf("pauses=%d health=%+v", pauses, h)
	}
	// A late success from an attempt already in flight does not resume a paused channel.
	if next, effect := h.Observe(AttemptDelivered, "", at.Add(time.Hour), 5); effect != HealthUnchanged || !next.Paused() || next.ConsecutiveFailures != 5 {
		t.Fatalf("late success changed a paused channel: %+v", next)
	}
}

func TestChannelHealthThresholdZeroCountsWithoutPausing(t *testing.T) {
	h := ChannelHealth{}
	for i := 0; i < MaxPauseThreshold+1; i++ {
		h, _ = h.Observe(AttemptPermanent, "http_404", time.Now(), 0)
	}
	if h.Paused() || h.ConsecutiveFailures != MaxPauseThreshold+1 {
		t.Fatalf("threshold 0 paused or lost count: %+v", h)
	}
	if !ValidPauseThreshold(0) || !ValidPauseThreshold(MaxPauseThreshold) || ValidPauseThreshold(-1) || ValidPauseThreshold(MaxPauseThreshold+1) {
		t.Fatal("threshold bounds changed")
	}
}

func TestChannelHealthResume(t *testing.T) {
	at := time.Now().UTC()
	h := ChannelHealth{State: ChannelPaused, PausedAt: &at, PausedReason: PauseReasonPermanentFailures, ConsecutiveFailures: 5, LastFailureCode: "http_410"}
	next, err := h.Resume()
	if err != nil || next.Paused() || next.PausedAt != nil || next.PausedReason != "" || next.ConsecutiveFailures != 0 || next.LastFailureCode != "http_410" {
		t.Fatalf("resume = %+v, %v", next, err)
	}
	if _, err := next.Resume(); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("resuming an active channel: %v", err)
	}
}

func TestChannelPausedEventCarriesNoDestination(t *testing.T) {
	at := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	h := ChannelHealth{State: ChannelPaused, PausedAt: &at, PausedReason: PauseReasonPermanentFailures, ConsecutiveFailures: 5, LastFailureCode: "destination_blocked"}
	event, err := NewChannelPausedEvent("tenant", "channel", ChannelWebhook, "Ops\nhook", h, "pause-1")
	if err != nil {
		t.Fatal(err)
	}
	event.ID = "event"
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	if event.SourceID != "pause:channel:pause-1" || event.Type != EventChannelPaused {
		t.Fatalf("event identity = %s %s", event.Type, event.SourceID)
	}
	if strings.Contains(string(event.Data), "\\n") || strings.Contains(string(event.Data), "http") {
		t.Fatalf("notice data leaks a control character or URL: %s", event.Data)
	}
	var data ChannelPausedNotice
	if err := json.Unmarshal(event.Data, &data); err != nil || data.Failures != 5 || data.FailureCode != "destination_blocked" {
		t.Fatalf("data = %+v, %v", data, err)
	}
	checkGoProducedData(t, EventChannelPaused, event.Data)
	subject, err := SubjectFromEvent(event)
	if err != nil || !subject.Admins || subject.Link != "/settings/alerting" || !InAppMandatory(EventChannelPaused) {
		t.Fatalf("subject = %+v, %v", subject, err)
	}
	if err := PersonalRoleSupported(EventChannelPaused, RoleTenantAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := NewChannelPausedEvent("tenant", "channel", ChannelWebhook, "x", ChannelHealth{State: ChannelActive}, "pause-1"); err == nil {
		t.Fatal("built a pause notice for an active channel")
	}
}
