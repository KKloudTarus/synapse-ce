// Package alerting turns platform events a defender must act on into delivered notifications. It applies
// the tenant's alert rule, hands each qualifying alert to every configured sink, and audits the outcome
// per sink, so a missed page is visible in the audit log rather than silent. Delivery is best effort by
// design: the event that produced the alert (an incident, a finding) is already durable, and a failing
// webhook must never roll it back or block the pipeline that produced it.
package alerting

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/alerting"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ErrNoSinkAcknowledged is returned by Test when every configured sink refused the test alert.
var ErrNoSinkAcknowledged = errors.New("no alert sink acknowledged the test alert")

// Delivery bounds. Incident notifications leave the request path through a bounded worker set; a
// tenant that produces more alerts than the bucket allows has the excess audited as suppressed rather
// than delivered, so a compromised agent cannot turn correlation into a pager flood.
const (
	// deliveryWorkers is the number of concurrent asynchronous deliveries.
	deliveryWorkers = 4
	// deliveryQueue is how many notifications may wait for a worker before new ones are dropped (and
	// audited as alert.dropped).
	deliveryQueue = 1024
	// tenantAlertsPerMinute is the sustained per-tenant delivery rate; the bucket also holds that many
	// tokens as burst.
	tenantAlertsPerMinute = 60
)

// Service evaluates and delivers alerts.
type Service struct {
	sinks []ports.AlertSink
	rule  alerting.Rule
	audit ports.AuditLogger
	clock ports.Clock
	ids   ports.IDGenerator

	queue    chan func()
	wg       sync.WaitGroup // worker goroutines
	inflight sync.WaitGroup // queued or running deliveries
	mu       sync.Mutex
	buckets  map[shared.ID]*tokenBucket
}

// tokenBucket is a per-tenant rate limiter on delivered alerts.
type tokenBucket struct {
	tokens float64
	last   time.Time
}

func (b *tokenBucket) take(now time.Time) bool {
	elapsed := now.Sub(b.last).Minutes()
	if elapsed > 0 {
		b.tokens += elapsed * tenantAlertsPerMinute
		if b.tokens > tenantAlertsPerMinute {
			b.tokens = tenantAlertsPerMinute
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// NewService validates its dependencies. At least one sink is required: a service with nowhere to deliver
// is a misconfiguration the composition root should refuse, not a silent no-op.
func NewService(sinks []ports.AlertSink, rule alerting.Rule, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	switch {
	case len(sinks) == 0:
		return nil, fmt.Errorf("%w: alerting requires at least one sink", shared.ErrValidation)
	case audit == nil:
		return nil, fmt.Errorf("%w: alerting requires an audit logger", shared.ErrValidation)
	case clock == nil:
		return nil, fmt.Errorf("%w: alerting requires a clock", shared.ErrValidation)
	case ids == nil:
		return nil, fmt.Errorf("%w: alerting requires an id generator", shared.ErrValidation)
	}
	for _, sink := range sinks {
		if sink == nil {
			return nil, fmt.Errorf("%w: alerting sink is nil", shared.ErrValidation)
		}
	}
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	s := &Service{sinks: append([]ports.AlertSink(nil), sinks...), rule: rule, audit: audit, clock: clock, ids: ids,
		queue: make(chan func(), deliveryQueue), buckets: map[shared.ID]*tokenBucket{}}
	for i := 0; i < deliveryWorkers; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	return s, nil
}

func (s *Service) worker() {
	defer s.wg.Done()
	for job := range s.queue {
		job()
	}
}

// Close stops accepting asynchronous notifications and waits for the queued ones to finish.
func (s *Service) Close() {
	s.mu.Lock()
	if s.queue != nil {
		close(s.queue)
		s.queue = nil
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// Flush blocks until every notification queued so far has been delivered. Tests use it; a caller in
// production never waits on delivery.
func (s *Service) Flush() { s.inflight.Wait() }

// enqueue hands a delivery to the workers without blocking the caller. It reports false when the
// queue is full or closed.
func (s *Service) enqueue(job func()) bool {
	s.mu.Lock()
	q := s.queue
	s.mu.Unlock()
	if q == nil {
		return false
	}
	s.inflight.Add(1)
	wrapped := func() {
		defer s.inflight.Done()
		job()
	}
	select {
	case q <- wrapped:
		return true
	default:
		s.inflight.Done()
		return false
	}
}

// allow applies the per-tenant rate limit.
func (s *Service) allow(tenant shared.ID, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[tenant]
	if !ok {
		b = &tokenBucket{tokens: tenantAlertsPerMinute, last: now}
		s.buckets[tenant] = b
	}
	return b.take(now)
}

// Outcome counts what one notification did across sinks. Matched is false when the rule filtered the
// alert out; then nothing was attempted.
type Outcome struct {
	Matched     bool `json:"matched"`
	Delivered   int  `json:"delivered"`
	Failed      int  `json:"failed"`
	AuditFailed int  `json:"audit_failed,omitempty"`
}

// IncidentsCreated notifies each incident correlation opened. It satisfies correlationuc.IncidentNotifier
// and returns nothing on purpose: the incidents are recorded, and the per-sink result is in the audit log.
// Delivery runs on the worker set, detached from the caller's request context, so a slow or dead
// receiver never holds the agent's ingest; the rate limit and a full queue are audited, never silent.
func (s *Service) IncidentsCreated(ctx context.Context, actor string, engagementID shared.ID, created []incident.Incident) {
	tenant := s.tenant(ctx)
	bg := context.WithoutCancel(ctx)
	for _, inc := range created {
		at := inc.CreatedAt
		if at.IsZero() {
			at = s.clock.Now()
		}
		a := alerting.Alert{
			ID:           s.ids.NewID(),
			TenantID:     tenant,
			Kind:         alerting.KindIncidentCreated,
			Severity:     inc.Severity,
			Title:        inc.Title,
			Summary:      strconv.Itoa(len(inc.DetectionIDs)) + " detection(s) correlated on asset " + inc.AssetID.String(),
			EngagementID: engagementID,
			AssetID:      inc.AssetID,
			IncidentID:   inc.ID,
			Link:         "/fleet/incidents/" + inc.ID.String(),
			OccurredAt:   at.UTC(),
		}
		if !s.rule.Matches(a) {
			continue
		}
		if !s.allow(tenant, s.clock.Now()) {
			_ = s.record(ctx, actor, "alert.suppressed", a, "", errRateLimited)
			continue
		}
		if !s.enqueue(func() { s.Notify(bg, actor, a) }) {
			_ = s.record(ctx, actor, "alert.dropped", a, "", errQueueFull)
		}
	}
}

var (
	errRateLimited = errors.New("tenant alert rate limit reached")
	errQueueFull   = errors.New("alert delivery queue is full")
)

// Test delivers a synthetic alert so an operator can prove the configured sinks receive alerts. It
// bypasses the severity rule and reports the outcome; an error means no sink acknowledged it.
func (s *Service) Test(ctx context.Context, actor string) (Outcome, error) {
	now := s.clock.Now().UTC()
	out := s.Notify(ctx, actor, alerting.Alert{
		ID:         s.ids.NewID(),
		TenantID:   s.tenant(ctx),
		Kind:       alerting.KindTest,
		Severity:   shared.SeverityInfo,
		Title:      "Synapse alert delivery test",
		Summary:    "Requested by " + actor + " at " + now.Format(time.RFC3339),
		OccurredAt: now,
	})
	if out.Delivered == 0 {
		return out, ErrNoSinkAcknowledged
	}
	return out, nil
}

// Notify applies the rule and delivers to every sink, auditing each attempt. The alert must validate;
// an invalid alert is a programming error on the producer side and is audited as such.
func (s *Service) Notify(ctx context.Context, actor string, a alerting.Alert) Outcome {
	var out Outcome
	if err := a.Validate(); err != nil {
		out.Failed = len(s.sinks)
		if aerr := s.record(ctx, actor, "alert.invalid", a, "", err); aerr != nil {
			out.AuditFailed++
		}
		return out
	}
	if !s.rule.Matches(a) {
		return out
	}
	out.Matched = true
	for _, sink := range s.sinks {
		err := sink.Deliver(ctx, a)
		action := "alert.delivered"
		if err != nil {
			action = "alert.failed"
			out.Failed++
		} else {
			out.Delivered++
		}
		if aerr := s.record(ctx, actor, action, a, sink.Name(), err); aerr != nil {
			out.AuditFailed++
		}
	}
	return out
}

func (s *Service) record(ctx context.Context, actor, action string, a alerting.Alert, sink string, cause error) error {
	meta := map[string]string{
		"alert_id":  a.ID.String(),
		"kind":      string(a.Kind),
		"severity":  string(a.Severity),
		"tenant_id": a.TenantID.String(),
	}
	if sink != "" {
		meta["sink"] = sink
	}
	if !a.IncidentID.IsZero() {
		meta["incident_id"] = a.IncidentID.String()
	}
	if !a.EngagementID.IsZero() {
		meta["engagement"] = a.EngagementID.String()
	}
	if cause != nil {
		meta["error"] = cause.Error()
	}
	target := a.IncidentID.String()
	if target == "" {
		target = a.ID.String()
	}
	return s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: target, Metadata: meta, At: s.clock.Now().UTC()})
}

func (s *Service) tenant(ctx context.Context) shared.ID {
	tenant, _ := shared.TenantFrom(ctx)
	return shared.TenantOrDefault(tenant)
}
