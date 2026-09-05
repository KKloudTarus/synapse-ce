package detection

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func dnsEvent(at time.Time, remote string) Event {
	return Event{Class: ClassNetwork, At: at, Host: "h", Network: &NetworkEvent{Proto: "udp", RemoteAddr: remote, RemotePort: 53, Direction: "egress", PID: 3, Comm: "curl"}}
}

func windowedRule(count int, within time.Duration) Rule {
	return Rule{
		ID: "det.test_burst", Version: 1, Class: ClassNetwork, Title: "burst", Severity: shared.SeverityMedium,
		Matcher: Matcher{Class: ClassNetwork, All: []Predicate{{Field: FieldNetRemotePort, Op: OpEquals, Value: "53"}}},
		Window:  &Window{Count: count, Within: within, GroupBy: []Field{FieldNetRemoteAddr}},
	}
}

func TestWindowValidation(t *testing.T) {
	base := windowedRule(3, time.Minute)
	if err := base.Validate(); err != nil {
		t.Fatalf("valid windowed rule rejected: %v", err)
	}
	cases := map[string]Window{
		"count of one":   {Count: 1, Within: time.Minute},
		"no span":        {Count: 3},
		"unknown field":  {Count: 3, Within: time.Minute, GroupBy: []Field{"nope"}},
		"cross-class":    {Count: 3, Within: time.Minute, GroupBy: []Field{FieldProcComm}},
		"over count cap": {Count: MaxWindowCount + 1, Within: time.Minute},
	}
	for name, w := range cases {
		r := base
		w := w
		r.Window = &w
		if err := r.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want ErrValidation", name, err)
		}
	}
}

func TestEvaluatorFiresOnceWhenTheCountIsReachedInsideTheSpan(t *testing.T) {
	ev, err := NewEvaluator([]Rule{windowedRule(3, time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1_000, 0)
	// Two matches: below the count, nothing fires.
	for i := 0; i < 2; i++ {
		if fired := ev.Evaluate(dnsEvent(t0.Add(time.Duration(i)*time.Second), "10.0.0.53")); len(fired) != 0 {
			t.Fatalf("fired below the count: %+v", fired)
		}
	}
	// Third match inside the span fires with the whole burst as evidence, oldest first.
	fired := ev.Evaluate(dnsEvent(t0.Add(2*time.Second), "10.0.0.53"))
	if len(fired) != 1 || fired[0].Rule.ID != "det.test_burst" || len(fired[0].Evidence) != 3 {
		t.Fatalf("fired = %+v", fired)
	}
	if !fired[0].Evidence[0].At.Equal(t0) || !fired[0].Evidence[2].At.Equal(t0.Add(2*time.Second)) {
		t.Fatalf("evidence order = %v", fired[0].Evidence)
	}
	// Firing resets the group: the next event starts a new count.
	if fired := ev.Evaluate(dnsEvent(t0.Add(3*time.Second), "10.0.0.53")); len(fired) != 0 {
		t.Fatalf("fired again right after a burst: %+v", fired)
	}
}

func TestEvaluatorSpanExpiresOldEvents(t *testing.T) {
	ev, _ := NewEvaluator([]Rule{windowedRule(3, time.Minute)})
	t0 := time.Unix(1_000, 0)
	ev.Evaluate(dnsEvent(t0, "10.0.0.53"))
	ev.Evaluate(dnsEvent(t0.Add(30*time.Second), "10.0.0.53"))
	// 61s after the first event: the first has fallen out of the span, so this is the second in span.
	if fired := ev.Evaluate(dnsEvent(t0.Add(61*time.Second), "10.0.0.53")); len(fired) != 0 {
		t.Fatalf("expired event still counted: %+v", fired)
	}
	if fired := ev.Evaluate(dnsEvent(t0.Add(62*time.Second), "10.0.0.53")); len(fired) != 1 {
		t.Fatalf("third in-span event did not fire: %+v", fired)
	}
}

func TestEvaluatorGroupsByField(t *testing.T) {
	ev, _ := NewEvaluator([]Rule{windowedRule(3, time.Minute)})
	t0 := time.Unix(1_000, 0)
	// Six queries spread over three resolvers never reach three for any one of them.
	for i := 0; i < 6; i++ {
		remote := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}[i%3]
		if fired := ev.Evaluate(dnsEvent(t0.Add(time.Duration(i)*time.Second), remote)); len(fired) != 0 {
			t.Fatalf("groups were pooled: %+v", fired)
		}
	}
	// A third to one of them fires for that group only.
	fired := ev.Evaluate(dnsEvent(t0.Add(7*time.Second), "10.0.0.2"))
	if len(fired) != 1 || len(fired[0].Evidence) != 3 {
		t.Fatalf("fired = %+v", fired)
	}
	for _, e := range fired[0].Evidence {
		if e.Network.RemoteAddr != "10.0.0.2" {
			t.Fatalf("evidence from another group: %+v", e)
		}
	}
}

func TestEvaluatorPlainRulesPassThrough(t *testing.T) {
	r, ok := Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("rule missing")
	}
	ev, _ := NewEvaluator([]Rule{r})
	e := Event{Class: ClassProcess, At: time.Unix(1, 0), Host: "h", Process: &ProcessEvent{PID: 2, Comm: "ps", Path: "/usr/bin/ps"}}
	fired := ev.Evaluate(e)
	if len(fired) != 1 || fired[0].Evidence != nil || fired[0].Rule.ID != r.ID {
		t.Fatalf("plain rule = %+v", fired)
	}
	if fired := ev.Evaluate(Event{Class: ClassProcess, At: time.Unix(2, 0), Host: "h", Process: &ProcessEvent{PID: 2, Comm: "bash"}}); len(fired) != 0 {
		t.Fatalf("non-matching event fired: %+v", fired)
	}
}

func TestEvaluatorBoundsGroupsAndEvidence(t *testing.T) {
	r := windowedRule(MaxEvidence+10, time.Hour)
	ev, _ := NewEvaluator([]Rule{r})
	t0 := time.Unix(1_000, 0)
	// One more group than the cap: the stalest group is evicted, the evaluator does not grow unbounded.
	for i := 0; i <= MaxWindowGroups; i++ {
		ev.Evaluate(dnsEvent(t0.Add(time.Duration(i)*time.Millisecond), "10.1."+string(rune('a'+i%26))+"."+string(rune('a'+i/26))))
	}
	if n := ev.perRule[r.ID]; n > MaxWindowGroups {
		t.Fatalf("groups = %d, exceeds cap %d", n, MaxWindowGroups)
	}
	// A burst longer than the evidence cap fires once with the last MaxEvidence events.
	var fired []Fired
	for i := 0; i < MaxEvidence+10; i++ {
		fired = ev.Evaluate(dnsEvent(t0.Add(time.Hour+time.Duration(i)*time.Second), "10.9.9.9"))
	}
	if len(fired) != 1 || len(fired[0].Evidence) != MaxEvidence || fired[0].Observed != MaxEvidence+10 {
		t.Fatalf("large burst = %d fired, %d evidence, observed %d", len(fired), len(fired[0].Evidence), fired[0].Observed)
	}
	d, err := NewBurstDetection(r, "host-1", "agent:1", fired[0].Evidence, fired[0].Observed, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Truncated || d.ObservedCount != MaxEvidence+10 || len(d.Evidence) != MaxEvidence {
		t.Fatalf("burst detection = truncated %v observed %d evidence %d", d.Truncated, d.ObservedCount, len(d.Evidence))
	}
	if !fired[0].Evidence[len(fired[0].Evidence)-1].At.Equal(t0.Add(time.Hour + time.Duration(MaxEvidence+9)*time.Second)) {
		t.Fatalf("evidence is not the most recent events")
	}
}

// The catalogued DNS rule is windowed: one packet is a match, not a detection.
func TestDNSBeaconRuleIsARate(t *testing.T) {
	r, ok := Lookup("det.suspicious_dns_beacon")
	if !ok {
		t.Fatal("rule missing")
	}
	if !r.Windowed() || r.Version != 2 || r.Window.Count < 2 || r.Window.Within <= 0 || len(r.Window.GroupBy) != 1 || r.Window.GroupBy[0] != FieldNetRemoteAddr {
		t.Fatalf("dns rule = %+v window=%+v", r, r.Window)
	}
	ev, _ := NewEvaluator([]Rule{r})
	t0 := time.Unix(1_000, 0)
	for i := 0; i < r.Window.Count-1; i++ {
		if fired := ev.Evaluate(dnsEvent(t0.Add(time.Duration(i)*100*time.Millisecond), "203.0.113.7")); len(fired) != 0 {
			t.Fatalf("fired on packet %d", i+1)
		}
	}
	if fired := ev.Evaluate(dnsEvent(t0.Add(time.Duration(r.Window.Count)*100*time.Millisecond), "203.0.113.7")); len(fired) != 1 {
		t.Fatalf("burst did not fire: %+v", fired)
	}
	// Returned rules are copies: mutating the window does not reach the catalogue.
	r.Window.Count = 1
	again, _ := Lookup("det.suspicious_dns_beacon")
	if again.Window.Count == 1 {
		t.Fatal("catalogue window was mutated through a returned rule")
	}
}
