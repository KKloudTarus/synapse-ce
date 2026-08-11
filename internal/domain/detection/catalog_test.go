package detection

import (
	"testing"
	"time"

	demu "github.com/KKloudTarus/synapse-ce/internal/domain/emulation"
)

// TestCatalogueValidatesAndIsDeterministic is the drift test mirroring the SAST/emulation catalogues:
// the shipped rule set must validate, have no duplicate ids, and be stably ordered, or the build fails
// here rather than shipping a rule that cannot produce a trustworthy detection.
func TestCatalogueValidatesAndIsDeterministic(t *testing.T) {
	a, err := Catalogue()
	if err != nil {
		t.Fatalf("the shipped catalogue does not validate: %v", err)
	}
	if len(a) == 0 {
		t.Fatal("empty catalogue; the drift test would pass vacuously")
	}
	b, _ := Catalogue()
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("catalogue order is not stable at %d: %s vs %s", i, a[i].ID, b[i].ID)
		}
		if i > 0 && a[i-1].ID > a[i].ID {
			t.Fatalf("catalogue is not sorted by id: %s before %s", a[i-1].ID, a[i].ID)
		}
	}
}

// TestEveryClassHasARule ensures each event class ships at least one detection, so the per-class engine
// (and its per-class load/disable tests in the eBPF phase) has something to evaluate.
func TestEveryClassHasARule(t *testing.T) {
	for _, cls := range Classes() {
		rules, err := CatalogueByClass(cls)
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) == 0 {
			t.Errorf("class %s has no catalogued rule", cls)
		}
	}
}

// TestCatalogueReturnsAreImmutable proves a caller cannot reach through a returned rule and mutate the
// package-level catalogue — a runtime-mutable detection rule set would be a security defect, not just a
// style one. It mutates the matcher predicates of a returned rule and confirms a fresh read is unchanged.
func TestCatalogueReturnsAreImmutable(t *testing.T) {
	first, err := Catalogue()
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		for j := range first[i].Matcher.All {
			first[i].Matcher.All[j].Value = "TAMPERED"
			for k := range first[i].Matcher.All[j].Values {
				first[i].Matcher.All[j].Values[k] = "TAMPERED"
			}
		}
	}
	// Lookup and a fresh Catalogue must be untouched.
	r, ok := Lookup("det.credential_file_access")
	if !ok {
		t.Fatal("expected det.credential_file_access")
	}
	for _, p := range r.Matcher.All {
		if p.Value == "TAMPERED" {
			t.Fatal("mutating a returned rule's predicate Value leaked into the catalogue")
		}
		for _, v := range p.Values {
			if v == "TAMPERED" {
				t.Fatal("mutating a returned rule's predicate Values leaked into the catalogue")
			}
		}
	}
	// And the mutated returned rule must no longer match a fixture it originally matched, proving the
	// tamper stayed local to the caller's copy.
	fresh, _ := Catalogue()
	if len(fresh) != len(first) {
		t.Fatal("catalogue length changed across reads")
	}
}

// TestRuleMatchesFixturePerClass is #422's acceptance criterion at the domain level: for each event
// class, a fixture event matches a catalogued rule and yields a detection carrying that evidence. The
// on-kernel load test for each class is a separate infra-phase acceptance.
func TestRuleMatchesFixturePerClass(t *testing.T) {
	now := time.Unix(1000, 0)
	fixtures := []struct {
		ruleID string
		event  Event
	}{
		{"det.process_enumeration", Event{Class: ClassProcess, At: now, Host: "h",
			Process: &ProcessEvent{PID: 2, Comm: "ps", Path: "/usr/bin/ps", Args: []string{"-ef"}}}},
		{"det.suspicious_dns_beacon", Event{Class: ClassNetwork, At: now, Host: "h",
			Network: &NetworkEvent{Proto: "udp", RemoteAddr: "8.8.8.8", RemotePort: 53, Direction: "egress", PID: 3, Comm: "curl"}}},
		{"det.credential_file_access", Event{Class: ClassFile, At: now, Host: "h",
			File: &FileEvent{Path: "/etc/shadow", Op: "read", PID: 4, Comm: "cat"}}},
		{"det.privilege_escalation_to_root", Event{Class: ClassPrivilege, At: now, Host: "h",
			Privilege: &PrivilegeEvent{PID: 5, Comm: "sudo", FromUID: 1000, ToUID: 0, Kind: "setuid"}}},
	}
	for _, f := range fixtures {
		t.Run(f.ruleID, func(t *testing.T) {
			r, ok := Lookup(f.ruleID)
			if !ok {
				t.Fatalf("rule %s not catalogued", f.ruleID)
			}
			if r.Class != f.event.Class {
				t.Fatalf("fixture class %s does not match rule class %s", f.event.Class, r.Class)
			}
			if !r.Match(f.event) {
				t.Fatalf("rule %s did not match its fixture event", f.ruleID)
			}
			d, err := NewDetection(r, "host-1", "agent:vm-1", []Event{f.event}, now)
			if err != nil {
				t.Fatalf("emitting a detection failed: %v", err)
			}
			if d.RuleID != f.ruleID || len(d.Evidence) != 1 {
				t.Fatalf("detection did not carry the matched evidence: %+v", d)
			}
		})
	}
}

// TestEmulationExpectedDetectionsAreCatalogued is the purple linkage (#426 depends on it): every
// detection an emulation technique (#421) expects must exist as a catalogued rule of a real event class.
// Without this, an executed technique could never be reconciled against a detection and would be a
// permanent, unexplained coverage gap.
func TestEmulationExpectedDetectionsAreCatalogued(t *testing.T) {
	techniques, err := demu.Catalogue()
	if err != nil {
		t.Fatalf("emulation catalogue: %v", err)
	}
	for _, tech := range techniques {
		id := tech.Expected.DetectionID
		r, ok := Lookup(id)
		if !ok {
			t.Errorf("emulation technique %s expects detection %q, which has no catalogued rule", tech.ID, id)
			continue
		}
		if !r.Class.Valid() {
			t.Errorf("detection %s for emulation %s has an invalid class %q", id, tech.ID, r.Class)
		}
	}
}
