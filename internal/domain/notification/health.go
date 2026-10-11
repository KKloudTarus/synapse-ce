package notification

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Channel health (#1464). A channel that keeps failing for a reason retrying cannot fix is paused
// automatically, so the worker stops sending to a broken destination, and tenant administrators
// get one in-app notice. Only an administrator resumes it.
//
// Counting rules:
//   - A delivered attempt resets the counter to zero.
//   - A permanent failure that the channel owns (PermanentChannelFailure) adds one. When the
//     counter reaches the threshold the channel pauses, exactly once.
//   - Every other outcome (a retryable failure such as 408, 429, 5xx, a timeout or a reset, and a
//     final failure the operator owns such as a missing SMTP relay) neither adds nor resets.
//   - While paused, outcomes of attempts that were already in flight change nothing: a late
//     success does not resume the channel and a late failure does not count.

type ChannelHealthState string

const (
	ChannelActive ChannelHealthState = "active"
	ChannelPaused ChannelHealthState = "paused"
)

// PauseReasonPermanentFailures is the only automatic pause reason today. Pause reasons are bounded
// codes; they never carry a destination, a response body or raw error text.
const PauseReasonPermanentFailures = "consecutive_permanent_failures"

const (
	// DefaultPauseThreshold is the number of consecutive permanent failures that pauses a channel.
	DefaultPauseThreshold = 5
	// MaxPauseThreshold bounds SYNAPSE_NOTIFICATION_CHANNEL_PAUSE_THRESHOLD. Zero disables pausing.
	MaxPauseThreshold = 100
)

// ValidPauseThreshold reports whether n is an accepted threshold (zero disables auto-pause).
func ValidPauseThreshold(n int) bool { return n >= 0 && n <= MaxPauseThreshold }

// AttemptClass is how channel health reads one finished attempt.
type AttemptClass int

const (
	// AttemptIgnored neither counts towards a pause nor resets the counter.
	AttemptIgnored AttemptClass = iota
	// AttemptDelivered resets the counter.
	AttemptDelivered
	// AttemptPermanent counts towards a pause.
	AttemptPermanent
)

// ClassifyAttempt maps a finished attempt to its health class. A retryable result never counts,
// whatever its code, so the sender's own classification stays authoritative for retries.
func ClassifyAttempt(delivered bool, code string, retryable bool) AttemptClass {
	switch {
	case delivered:
		return AttemptDelivered
	case retryable:
		return AttemptIgnored
	case PermanentChannelFailure(code):
		return AttemptPermanent
	default:
		return AttemptIgnored
	}
}

// channelFaults are final failure codes a channel's own configuration causes, so repeating the
// send cannot succeed until an administrator changes the channel or its destination. They come
// from internal/infrastructure/notificationsender (http.go, email.go, the drivers) and from
// channel_config.go in the usecase.
var channelFaults = map[string]bool{
	"destination_blocked":      true, // the SSRF guard refused the channel's URL at dial time (#1489)
	"smtp_destination_blocked": true, // the guard refused the relay address
	"channel_config_invalid":   true, // the sealed configuration no longer decodes for its type
	"smtp_recipient_invalid":   true, // a channel recipient is not a valid address
	// Slack bot channels (#1383): Slack answers HTTP 200 with ok:false, so these are the Web API
	// errors that only a new token, scope or conversation fixes.
	"slack_invalid_auth":           true,
	"slack_not_authed":             true,
	"slack_account_inactive":       true,
	"slack_token_revoked":          true,
	"slack_token_expired":          true,
	"slack_missing_scope":          true,
	"slack_not_allowed_token_type": true,
	"slack_channel_not_found":      true,
	"slack_not_in_channel":         true,
	"slack_is_archived":            true,
	"slack_restricted_action":      true,
	"slack_conversation_shared":    true, // the conversation became shared and sharing is not allowed
}

// PermanentChannelFailure reports whether a final failure code is one the channel owns:
// channelFaults, an HTTP 4xx other than 408 and 429 (which the sender retries), or an SMTP 5xx
// reply. Operator-side codes (smtp_not_configured, smtp_sender_invalid, smtp_tls_required,
// smtp_auth_unavailable, channel_secret_unavailable) and internal ones (encode_failed,
// request_invalid, unsupported_channel) do not count: pausing every channel would not fix them.
func PermanentChannelFailure(code string) bool {
	if channelFaults[code] {
		return true
	}
	if n, ok := statusCode(code, "http_"); ok {
		return n >= 400 && n < 500 && n != 408 && n != 429
	}
	if n, ok := statusCode(code, "smtp_"); ok {
		return n >= 500 && n < 600 && !smtpAuthFailure[n]
	}
	return false
}

// smtpAuthFailure are the RFC 4954 replies to AUTH. They describe the operator's relay credential,
// which every email channel shares, so counting them would pause all email channels for a fault no
// channel owns.
var smtpAuthFailure = map[int]bool{530: true, 534: true, 535: true, 538: true}

func statusCode(code, prefix string) (int, bool) {
	rest, ok := strings.CutPrefix(code, prefix)
	if !ok || len(rest) != 3 {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	return n, err == nil
}

// ChannelHealth is the delivery health the worker keeps on a channel. It is system state, not
// configuration: an automatic pause does not bump the channel revision, so an administrator's
// in-flight edit still saves and does not clear the pause.
type ChannelHealth struct {
	State               ChannelHealthState `json:"state"`
	PausedAt            *time.Time         `json:"paused_at,omitempty"`
	PausedReason        string             `json:"paused_reason,omitempty"`
	ConsecutiveFailures int                `json:"consecutive_failures"`
	LastFailureCode     string             `json:"last_failure_code,omitempty"`
	LastFailureAt       *time.Time         `json:"last_failure_at,omitempty"`
}

// Paused reports whether the worker must not send to the channel.
func (h ChannelHealth) Paused() bool { return h.State == ChannelPaused }

// HealthEffect is what one observation did to a channel's health.
type HealthEffect int

const (
	HealthUnchanged HealthEffect = iota
	HealthUpdated
	HealthPausedNow
)

// Observe applies one finished attempt. It returns the next health and whether it changed or
// paused the channel. threshold <= 0 disables pausing; failures are still counted so the console
// shows them.
func (h ChannelHealth) Observe(class AttemptClass, code string, at time.Time, threshold int) (ChannelHealth, HealthEffect) {
	if h.State == "" {
		h.State = ChannelActive
	}
	if h.Paused() {
		return h, HealthUnchanged
	}
	switch class {
	case AttemptDelivered:
		if h.ConsecutiveFailures == 0 {
			return h, HealthUnchanged
		}
		h.ConsecutiveFailures = 0
		return h, HealthUpdated
	case AttemptPermanent:
		at = at.UTC()
		h.ConsecutiveFailures++
		h.LastFailureCode = code
		h.LastFailureAt = &at
		if threshold > 0 && h.ConsecutiveFailures >= threshold {
			h.State = ChannelPaused
			h.PausedAt = &at
			h.PausedReason = PauseReasonPermanentFailures
			return h, HealthPausedNow
		}
		return h, HealthUpdated
	default:
		return h, HealthUnchanged
	}
}

// Resume clears a pause and the counter. Resuming a channel that is not paused is a conflict, so
// two administrators racing on the same button get one success and one clear answer.
func (h ChannelHealth) Resume() (ChannelHealth, error) {
	if !h.Paused() {
		return h, fmt.Errorf("notification channel is not paused: %w", shared.ErrConflict)
	}
	h.State = ChannelActive
	h.PausedAt = nil
	h.PausedReason = ""
	h.ConsecutiveFailures = 0
	return h, nil
}

// Health event actions, kept append-only per channel.
const (
	HealthActionPaused  = "paused"
	HealthActionResumed = "resumed"
)

// ChannelHealthEvent is one row of a channel's pause and resume history. A pause names the
// delivery and attempt that tripped it; a resume names the administrator.
type ChannelHealthEvent struct {
	ID          shared.ID `json:"id"`
	ChannelID   shared.ID `json:"channel_id"`
	Action      string    `json:"action"`
	Reason      string    `json:"reason,omitempty"`
	FailureCode string    `json:"failure_code,omitempty"`
	Failures    int       `json:"failures"`
	DeliveryID  shared.ID `json:"delivery_id,omitempty"`
	AttemptID   shared.ID `json:"attempt_id,omitempty"`
	Actor       string    `json:"actor"`
	OccurredAt  time.Time `json:"occurred_at"`
}

// ChannelPausedNotice is the data of a notification.channel_paused event. It names the channel and
// the failure code only: no destination, recipient, response body or error text.
type ChannelPausedNotice struct {
	Title       string `json:"title"`
	Summary     string `json:"summary"`
	ChannelID   string `json:"channel_id"`
	Class       string `json:"class"`
	Reason      string `json:"reason"`
	FailureCode string `json:"failure_code"`
	Failures    int    `json:"failures"`
}

// NewChannelPausedEvent builds the admin notice for one pause. The source id carries the pause
// event id, so publishing it again for the same pause is a no-op and a later pause notifies again.
func NewChannelPausedEvent(tenant, channel shared.ID, channelType ChannelType, name string, health ChannelHealth, pauseID shared.ID) (Event, error) {
	if tenant.IsZero() || channel.IsZero() || pauseID.IsZero() || !health.Paused() || health.PausedAt == nil {
		return Event{}, fmt.Errorf("%w: channel pause notice requires a paused channel", shared.ErrValidation)
	}
	code := health.LastFailureCode
	if code == "" {
		code = "unknown"
	}
	notice := ChannelPausedNotice{
		Title:       "Notification channel paused",
		Summary:     fmt.Sprintf("%q (%s) stopped sending after %d consecutive permanent failures (last: %s). Fix the destination, then resume the channel in Alerting.", noticeName(name), channelType, health.ConsecutiveFailures, code),
		ChannelID:   channel.String(),
		Class:       string(channelType),
		Reason:      health.PausedReason,
		FailureCode: code,
		Failures:    health.ConsecutiveFailures,
	}
	raw, err := json.Marshal(notice)
	if err != nil {
		return Event{}, err
	}
	return Event{TenantID: tenant, Type: EventChannelPaused, SourceKind: "notification_channel_health", SourceID: "pause:" + channel.String() + ":" + pauseID.String(), SchemaVersion: 1, OccurredAt: health.PausedAt.UTC(), Data: raw}, nil
}

// noticeName keeps an administrator-chosen channel name to one short printable line.
func noticeName(name string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(name) {
		if unicode.IsControl(r) {
			r = ' '
		}
		b.WriteRune(r)
		if b.Len() >= 80 {
			break
		}
	}
	if b.Len() == 0 {
		return "channel"
	}
	return b.String()
}
