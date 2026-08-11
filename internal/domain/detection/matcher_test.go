package detection

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func procEvent(comm string, args ...string) Event {
	return Event{Class: ClassProcess, At: time.Unix(1, 0), Host: "h1",
		Process: &ProcessEvent{PID: 10, PPID: 1, Comm: comm, Path: "/usr/bin/" + comm, Args: args, UID: 1000}}
}

func TestMatcherRefusesEmptyOrCrossClassPredicates(t *testing.T) {
	cases := map[string]Matcher{
		"no predicates":     {Class: ClassProcess},
		"unknown class":     {Class: "telepathy", All: []Predicate{{Field: FieldProcComm, Op: OpEquals, Value: "ps"}}},
		"field wrong class": {Class: ClassProcess, All: []Predicate{{Field: FieldNetProto, Op: OpEquals, Value: "udp"}}},
		"string op on num":  {Class: ClassProcess, All: []Predicate{{Field: FieldProcUID, Op: OpPrefix, Value: "10"}}},
		"num op on string":  {Class: ClassProcess, All: []Predicate{{Field: FieldProcComm, Op: OpGTE, Value: "ps"}}},
		"in without values": {Class: ClassProcess, All: []Predicate{{Field: FieldProcComm, Op: OpIn}}},
		"empty value":       {Class: ClassProcess, All: []Predicate{{Field: FieldProcComm, Op: OpEquals}}},
		"non-int numeric":   {Class: ClassProcess, All: []Predicate{{Field: FieldProcUID, Op: OpEquals, Value: "root"}}},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			if err := m.validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

// TestMatchNeverMatchesAcrossClass is the safety property: a matcher for one class never matches an event
// of another, even if the other event happens to have a field with the sought value. A rule matches only
// what it can actually see.
func TestMatchNeverMatchesAcrossClass(t *testing.T) {
	m := Matcher{Class: ClassNetwork, All: []Predicate{{Field: FieldNetProto, Op: OpEquals, Value: "udp"}}}
	if m.Match(procEvent("ps")) {
		t.Fatal("a network matcher matched a process event")
	}
}

func TestMatchStringOps(t *testing.T) {
	e := procEvent("systemctl", "restart", "nginx")
	tests := []struct {
		name string
		p    Predicate
		want bool
	}{
		{"equals hit", Predicate{Field: FieldProcComm, Op: OpEquals, Value: "systemctl"}, true},
		{"equals miss", Predicate{Field: FieldProcComm, Op: OpEquals, Value: "ps"}, false},
		{"prefix hit", Predicate{Field: FieldProcPath, Op: OpPrefix, Value: "/usr/bin/"}, true},
		{"contains hit", Predicate{Field: FieldProcPath, Op: OpContains, Value: "systemctl"}, true},
		{"in hit", Predicate{Field: FieldProcComm, Op: OpIn, Values: []string{"ps", "systemctl"}}, true},
		{"arg any-hit", Predicate{Field: FieldProcArg, Op: OpEquals, Value: "restart"}, true},
		{"arg no-hit", Predicate{Field: FieldProcArg, Op: OpEquals, Value: "stop"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Matcher{Class: ClassProcess, All: []Predicate{tt.p}}
			if got := m.Match(e); got != tt.want {
				t.Fatalf("match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchNumericOps(t *testing.T) {
	e := Event{Class: ClassPrivilege, At: time.Unix(1, 0), Host: "h1",
		Privilege: &PrivilegeEvent{PID: 5, Comm: "sudo", FromUID: 1000, ToUID: 0, Kind: "setuid"}}
	if !(Matcher{Class: ClassPrivilege, All: []Predicate{{Field: FieldPrivToUID, Op: OpEquals, Value: "0"}}}).Match(e) {
		t.Error("to_uid == 0 should match a setuid-to-root event")
	}
	// A predicate over a field the event's class does not carry must not match.
	if (Matcher{Class: ClassPrivilege, All: []Predicate{{Field: FieldPrivToUID, Op: OpGTE, Value: "1"}}}).Match(e) {
		t.Error("to_uid >= 1 should not match to_uid 0")
	}
}

// TestMatchAllPredicatesAreAnded: every predicate must hold. A credential-file rule that names the path
// AND the op must not fire on the right path with the wrong op.
func TestMatchAllPredicatesAreAnded(t *testing.T) {
	m := Matcher{Class: ClassFile, All: []Predicate{
		{Field: FieldFilePath, Op: OpEquals, Value: "/etc/shadow"},
		{Field: FieldFileOp, Op: OpEquals, Value: "read"},
	}}
	read := Event{Class: ClassFile, At: time.Unix(1, 0), Host: "h1", File: &FileEvent{Path: "/etc/shadow", Op: "read"}}
	write := Event{Class: ClassFile, At: time.Unix(1, 0), Host: "h1", File: &FileEvent{Path: "/etc/shadow", Op: "write"}}
	if !m.Match(read) {
		t.Error("both predicates satisfied should match")
	}
	if m.Match(write) {
		t.Error("one predicate failing must not match (AND semantics)")
	}
}
