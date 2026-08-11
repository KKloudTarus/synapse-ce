package sca

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAIEvidenceSealFailureEmitsMetricOutsideDiscardedResult(t *testing.T) {
	store := newAIEvidenceScriptStore()
	storageErr := errors.New("storage unavailable")
	store.appendFailures[1] = storageErr
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	var logs bytes.Buffer
	svc.SetLogger(slog.New(slog.NewJSONHandler(&logs, nil)))
	result := aiEvidenceGateExemptResult(t)

	ref, err := svc.sealEvidenceFailClosed(context.Background(), "operator", "eng-metric", time.Unix(100, 0).UTC(), result)
	assertTypedAIEvidenceFailure(t, ref, err, 1)
	if !errors.Is(err, storageErr) {
		t.Fatalf("typed error must preserve storage failure: %v", err)
	}

	got := logs.String()
	for _, want := range []string{
		`"level":"ERROR"`,
		`"metric":"` + aiEvidenceSealFailureMetricName + `"`,
		`"metric_kind":"counter"`,
		`"metric_value":1`,
		`"engagement":"eng-metric"`,
		`"revoked_exemptions":1`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("failure metric missing %s: %s", want, got)
		}
	}
}

func TestAIEvidenceSealFailureMetricSurvivesErrorOnlyLogLevel(t *testing.T) {
	store := newAIEvidenceScriptStore()
	store.appendFailures[1] = errors.New("storage unavailable")
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	var logs bytes.Buffer
	svc.SetLogger(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))
	result := aiEvidenceGateExemptResult(t)

	_, err := svc.sealEvidenceFailClosed(context.Background(), "operator", "eng-metric-error-level", time.Unix(100, 0).UTC(), result)
	if err == nil {
		t.Fatal("evidence failure must remain fatal")
	}
	if got := strings.Count(logs.String(), `"metric":"`+aiEvidenceSealFailureMetricName+`"`); got != 1 {
		t.Fatalf("error-only logger suppressed failure metric: count=%d logs=%s", got, logs.String())
	}
}

func TestAIEvidenceSealFailureMetricUsesLiveContextAfterRequestCancellation(t *testing.T) {
	store := newAIEvidenceScriptStore()
	store.headFailures[1] = context.Canceled
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	handler := &aiEvidenceContextHandler{}
	svc.SetLogger(slog.New(handler))
	result := aiEvidenceGateExemptResult(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ref, err := svc.sealEvidenceFailClosed(ctx, "operator", "eng-metric-canceled", time.Unix(100, 0).UTC(), result)
	assertTypedAIEvidenceFailure(t, ref, err, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("typed error must preserve request cancellation: %v", err)
	}
	if handler.calls != 1 {
		t.Fatalf("metric handler calls=%d, want 1", handler.calls)
	}
	if handler.ctxErr != nil {
		t.Fatalf("metric inherited canceled request context: %v", handler.ctxErr)
	}
}

func TestAIEvidenceMetricSurvivesAuditFailure(t *testing.T) {
	store := newAIEvidenceScriptStore()
	store.appendFailures[1] = errors.New("storage unavailable")
	audit := &aiEvidenceTestAudit{err: errors.New("audit unavailable")}
	svc := newAIEvidenceService(t, store, audit)
	var logs bytes.Buffer
	svc.SetLogger(slog.New(slog.NewJSONHandler(&logs, nil)))
	result := aiEvidenceGateExemptResult(t)

	_, err := svc.sealEvidenceFailClosed(context.Background(), "operator", "eng-metric-audit", time.Unix(100, 0).UTC(), result)
	if err == nil {
		t.Fatal("audit failure must remain fatal")
	}
	if got := strings.Count(logs.String(), `"metric":"`+aiEvidenceSealFailureMetricName+`"`); got != 1 {
		t.Fatalf("metric count=%d, want 1 despite audit failure: %s", got, logs.String())
	}
}

func TestAIEvidenceMetricDoesNotDoubleEmitAfterRevocation(t *testing.T) {
	store := newAIEvidenceScriptStore()
	store.appendAlways = errors.New("storage unavailable")
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	var logs bytes.Buffer
	svc.SetLogger(slog.New(slog.NewJSONHandler(&logs, nil)))
	result := aiEvidenceGateExemptResult(t)

	_, _ = svc.sealEvidenceFailClosed(context.Background(), "operator", "eng-metric-repeat", time.Unix(100, 0).UTC(), result)
	if got := strings.Count(logs.String(), `"metric":"`+aiEvidenceSealFailureMetricName+`"`); got != 1 {
		t.Fatalf("first metric count=%d, want 1: %s", got, logs.String())
	}
	_, err := svc.sealEvidenceFailClosed(context.Background(), "operator", "eng-metric-repeat", time.Unix(100, 0).UTC(), result)
	if err == nil {
		t.Fatal("evidence outage must remain fatal after authority was already revoked")
	}
	if got := strings.Count(logs.String(), `"metric":"`+aiEvidenceSealFailureMetricName+`"`); got != 1 {
		t.Fatalf("retry double-emitted metric: count=%d logs=%s", got, logs.String())
	}
}

func TestAIEvidenceMetricIsNotEmittedWithoutAIExemption(t *testing.T) {
	store := newAIEvidenceScriptStore()
	store.appendFailures[1] = errors.New("storage unavailable")
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	var logs bytes.Buffer
	svc.SetLogger(slog.New(slog.NewJSONHandler(&logs, nil)))
	result := &ScanResult{Findings: []finding.Finding{{DedupKey: "ordinary"}}}

	_, err := svc.sealEvidenceFailClosed(context.Background(), "operator", "eng-metric-ordinary", time.Unix(100, 0).UTC(), result)
	if err == nil {
		t.Fatal("general evidence failure must remain fatal")
	}
	if strings.Contains(logs.String(), aiEvidenceSealFailureMetricName) {
		t.Fatalf("non-AI evidence failure emitted AI metric: %s", logs.String())
	}
}

func TestAIEvidenceMissingAuditFailsClosed(t *testing.T) {
	store := newAIEvidenceScriptStore()
	storageErr := errors.New("storage unavailable")
	store.appendFailures[1] = storageErr
	backingAudit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, backingAudit)
	svc.audit = nil
	result := aiEvidenceGateExemptResult(t)

	ref, err := svc.sealEvidenceFailClosed(context.Background(), "operator", "eng-no-audit", time.Unix(100, 0).UTC(), result)
	assertTypedAIEvidenceFailure(t, ref, err, 1)
	if !errors.Is(err, storageErr) || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing audit must retain the seal failure and fail validation: %v", err)
	}
	assertAIEvidenceRevoked(t, result)
}

func TestAIEvidenceAuditFallsBackToProvidedTimeWithoutServiceClock(t *testing.T) {
	store := newAIEvidenceScriptStore()
	store.appendFailures[1] = errors.New("storage unavailable")
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	svc.clock = nil
	result := aiEvidenceGateExemptResult(t)
	now := time.Unix(123, 456).UTC()

	ref, err := svc.sealEvidenceFailClosed(context.Background(), "operator", "eng-no-clock", now, result)
	assertTypedAIEvidenceFailure(t, ref, err, 1)
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries=%d, want 1", len(audit.entries))
	}
	if got := audit.entries[0].At; !got.Equal(now) {
		t.Fatalf("audit time=%v, want provided time %v", got, now)
	}
}

type aiEvidenceContextHandler struct {
	calls  int
	ctxErr error
}

func (h *aiEvidenceContextHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *aiEvidenceContextHandler) Handle(ctx context.Context, _ slog.Record) error {
	h.calls++
	h.ctxErr = ctx.Err()
	return nil
}

func (h *aiEvidenceContextHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *aiEvidenceContextHandler) WithGroup(string) slog.Handler      { return h }
