package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
	offensiveuc "github.com/KKloudTarus/synapse-ce/internal/usecase/offensivepolicy"
)

type fakeHalt struct {
	called int
	tenant shared.ID
	actor  string
	reason string
	result offensiveuc.HaltResult
	err    error
}

func (f *fakeHalt) Halt(_ context.Context, tenantID shared.ID, actor, reason string) (offensiveuc.HaltResult, error) {
	f.called++
	f.tenant, f.actor, f.reason = tenantID, actor, reason
	return f.result, f.err
}

func haltRequestFor(t *testing.T, rt *Router, id, role, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/redteam/halt", strings.NewReader(body))
	req = withPrincipal(req, id, role)
	w := httptest.NewRecorder()
	rt.authz(userdom.PermAdminister, rt.haltOffensiveWork)(w, req)
	return w
}

// TestHaltRequiresAdminister: the person who can run offensive work should not be the only one who can
// stop it, so the halt is PermAdminister rather than PermOperate.
func TestHaltRequiresAdminister(t *testing.T) {
	for role, wantStatus := range map[string]int{
		"admin":      http.StatusOK,
		"consultant": http.StatusForbidden,
		"reviewer":   http.StatusForbidden,
		"readonly":   http.StatusForbidden,
		// A machine principal must never be able to pull the switch either, even though halting is a
		// "safe" direction: an agent that can stop the fleet can also stop an authorised assessment.
		"agent": http.StatusForbidden,
	} {
		t.Run(role, func(t *testing.T) {
			h := &fakeHalt{result: offensiveuc.HaltResult{
				RequestedAt: time.Now().UTC(), CompletedAt: time.Now().UTC(), WithinBound: true,
				EstateStopNote: "control plane halted",
			}}
			rt := &Router{log: logging.New("error")}
			rt.SetOffensiveKillSwitch(h)
			w := haltRequestFor(t, rt, "operator", role, `{"reason":"customer asked"}`)
			if w.Code != wantStatus {
				t.Fatalf("role %s got %d, want %d: %s", role, w.Code, wantStatus, w.Body.String())
			}
			if wantStatus != http.StatusOK && h.called != 0 {
				t.Errorf("role %s reached the kill switch despite lacking the permission", role)
			}
		})
	}
}

// TestHaltReportsTheMeasuredDurationAndTheEstateCaveat: the response carries the measured duration, the
// bound it was measured against, and the note that the bound does not cover the estate. An operator
// reading only "halted: true" must not conclude that every host has stopped.
func TestHaltReportsTheMeasuredDurationAndTheEstateCaveat(t *testing.T) {
	start := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	h := &fakeHalt{result: offensiveuc.HaltResult{
		RequestedAt: start, CompletedAt: start.Add(120 * time.Millisecond),
		Duration: 120 * time.Millisecond, WithinBound: true,
		Cancelled:      []shared.ID{"wo-1", "wo-2"},
		EstateStopNote: "control plane halted within 5s; a technique already running on a host stops within one further agent poll interval",
	}}
	rt := &Router{log: logging.New("error")}
	rt.SetOffensiveKillSwitch(h)

	w := haltRequestFor(t, rt, "operator", "admin", `{"reason":"stop"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	var body haltResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Halted || body.DurationMS != 120 {
		t.Errorf("body = %+v", body)
	}
	if body.StatedBoundMS != offensiveuc.HaltBound.Milliseconds() {
		t.Errorf("stated bound = %d, want %d", body.StatedBoundMS, offensiveuc.HaltBound.Milliseconds())
	}
	if len(body.Cancelled) != 2 {
		t.Errorf("cancelled = %v", body.Cancelled)
	}
	if !strings.Contains(body.EstateStopNote, "agent poll interval") {
		t.Errorf("the response does not carry the estate-stop caveat: %q", body.EstateStopNote)
	}
	if h.reason != "stop" {
		t.Errorf("the reason was not passed to the kill switch, got %q", h.reason)
	}
	if h.actor != "operator" {
		t.Errorf("the operator identity was not passed to the kill switch, got %q", h.actor)
	}
}

// TestHaltAnswersFiveHundredWithThePartialResult: a halt that did not fully succeed must not answer 200.
// The operator needs to see which orders are still in flight, so the partial result rides along with the
// error status rather than being replaced by a bare message.
func TestHaltAnswersFiveHundredWithThePartialResult(t *testing.T) {
	h := &fakeHalt{
		result: offensiveuc.HaltResult{
			RequestedAt: time.Now().UTC(), CompletedAt: time.Now().UTC(),
			Cancelled: []shared.ID{"wo-1"}, Failed: map[shared.ID]string{"wo-2": "database unreachable"},
			EstateStopNote: "control plane halted",
		},
		err: errors.New("halt failed for 1 work order(s)"),
	}
	rt := &Router{log: logging.New("error")}
	rt.SetOffensiveKillSwitch(h)

	w := haltRequestFor(t, rt, "operator", "admin", `{"reason":"stop"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("a partial halt must not answer %d", w.Code)
	}
	var body haltResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Halted {
		t.Error("the response claims a clean halt while an order failed")
	}
	if body.Failed["wo-2"] == "" {
		t.Errorf("the response does not name the order still in flight: %+v", body)
	}
}

// TestHaltRejectsAMissingReason: the kill switch refuses a reasonless halt, and the adapter surfaces
// that as a 400 rather than a 500 — it is the operator's input that is wrong.
func TestHaltRejectsAMissingReason(t *testing.T) {
	h := &fakeHalt{err: shared.ErrValidation}
	rt := &Router{log: logging.New("error")}
	rt.SetOffensiveKillSwitch(h)

	w := haltRequestFor(t, rt, "operator", "admin", `{}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a reasonless halt must answer 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHaltRouteAbsentWithoutAKillSwitch: an endpoint that accepts a halt and does nothing is the worst
// possible failure for this control, so the route is not registered when unwired.
func TestHaltRouteAbsentWithoutAKillSwitch(t *testing.T) {
	rt := &Router{log: logging.New("error")}
	rt.SetOffensiveKillSwitch(nil)
	if rt.offensiveHalt != nil {
		t.Fatal("a nil kill switch must leave the route unwired rather than installing a no-op")
	}
}
