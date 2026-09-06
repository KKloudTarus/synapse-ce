package detection

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Field is a closed enumeration of the event fields a rule may match over. It is deliberately NOT a
// free-form string key: a rule matches over this known set only, which is what stops a rule from being an
// arbitrary expression over untrusted input. Each field belongs to exactly one Class.
type Field string

const (
	// process
	FieldProcComm Field = "proc.comm"
	FieldProcPath Field = "proc.path"
	FieldProcArg  Field = "proc.arg" // repeated: matches if ANY argv element satisfies the predicate
	FieldProcUID  Field = "proc.uid" // numeric

	// network
	FieldNetProto      Field = "net.proto"
	FieldNetRemoteAddr Field = "net.remote_addr"
	FieldNetRemotePort Field = "net.remote_port" // numeric
	FieldNetDirection  Field = "net.direction"

	// file
	FieldFilePath Field = "file.path"
	FieldFileOp   Field = "file.op"
	FieldFileComm Field = "file.comm"

	// privilege
	FieldPrivComm  Field = "priv.comm"
	FieldPrivCap   Field = "priv.cap"
	FieldPrivKind  Field = "priv.kind"
	FieldPrivToUID Field = "priv.to_uid" // numeric
)

// fieldClass maps a field to the one class it belongs to. The bool is false for an unknown field.
func fieldClass(f Field) (Class, bool) {
	switch f {
	case FieldProcComm, FieldProcPath, FieldProcArg, FieldProcUID:
		return ClassProcess, true
	case FieldNetProto, FieldNetRemoteAddr, FieldNetRemotePort, FieldNetDirection:
		return ClassNetwork, true
	case FieldFilePath, FieldFileOp, FieldFileComm:
		return ClassFile, true
	case FieldPrivComm, FieldPrivCap, FieldPrivKind, FieldPrivToUID:
		return ClassPrivilege, true
	default:
		return "", false
	}
}

// fieldIsNumeric reports whether a field is compared as an integer rather than a string.
func fieldIsNumeric(f Field) bool {
	switch f {
	case FieldProcUID, FieldNetRemotePort, FieldPrivToUID:
		return true
	default:
		return false
	}
}

// Op is a comparison operator. The set is small and total: every op has a defined meaning for the field
// type it is used with, checked by Matcher.validate.
type Op string

const (
	OpEquals   Op = "eq"       // string or numeric equality
	OpPrefix   Op = "prefix"   // string has prefix
	OpContains Op = "contains" // string contains
	OpIn       Op = "in"       // string is one of Values
	OpGTE      Op = "gte"      // numeric >=
)

func (o Op) numeric() bool { return o == OpEquals || o == OpGTE }
func (o Op) stringy() bool {
	switch o {
	case OpEquals, OpPrefix, OpContains, OpIn:
		return true
	default:
		return false
	}
}

// Predicate is one field comparison. Value is used by every op except OpIn, which uses Values.
type Predicate struct {
	Field  Field
	Op     Op
	Value  string
	Values []string
}

// Matcher is the AND of its predicates over one event class. A rule needing OR is expressed as two
// rules — milestone one keeps the matcher language small and total on purpose. An empty predicate list is
// refused: a matcher that matches every event of a class is not a detection rule, it is a firehose.
type Matcher struct {
	Class Class
	All   []Predicate
}

func (m Matcher) validate() error {
	if !m.Class.Valid() {
		return fmt.Errorf("%w: matcher has an unknown class %q", shared.ErrValidation, m.Class)
	}
	if len(m.All) == 0 {
		return fmt.Errorf("%w: matcher for class %s has no predicates", shared.ErrValidation, m.Class)
	}
	for i, p := range m.All {
		cls, ok := fieldClass(p.Field)
		if !ok {
			return fmt.Errorf("%w: predicate %d references unknown field %q", shared.ErrValidation, i, p.Field)
		}
		if cls != m.Class {
			return fmt.Errorf("%w: predicate %d field %q belongs to class %s, not the matcher's class %s",
				shared.ErrValidation, i, p.Field, cls, m.Class)
		}
		numericField := fieldIsNumeric(p.Field)
		switch {
		case numericField && !p.Op.numeric():
			return fmt.Errorf("%w: predicate %d op %q is not valid on numeric field %q", shared.ErrValidation, i, p.Op, p.Field)
		case !numericField && !p.Op.stringy():
			return fmt.Errorf("%w: predicate %d op %q is not valid on string field %q", shared.ErrValidation, i, p.Op, p.Field)
		}
		if p.Op == OpIn {
			if len(p.Values) == 0 {
				return fmt.Errorf("%w: predicate %d op in needs a non-empty value set", shared.ErrValidation, i)
			}
		} else if strings.TrimSpace(p.Value) == "" {
			return fmt.Errorf("%w: predicate %d op %q needs a value", shared.ErrValidation, i, p.Op)
		}
		if numericField {
			if _, err := strconv.Atoi(strings.TrimSpace(p.Value)); err != nil {
				return fmt.Errorf("%w: predicate %d numeric field %q needs an integer value, got %q", shared.ErrValidation, i, p.Field, p.Value)
			}
		}
	}
	return nil
}

// clone returns a deep copy of the matcher: the predicate slice and each predicate's Values slice are
// copied, not aliased, so a returned rule cannot be reached through to mutate the package-level catalogue.
func (m Matcher) clone() Matcher {
	c := m
	if m.All != nil {
		preds := make([]Predicate, len(m.All))
		for i, p := range m.All {
			pc := p
			if p.Values != nil {
				pc.Values = append([]string(nil), p.Values...)
			}
			preds[i] = pc
		}
		c.All = preds
	}
	return c
}

// Match reports whether the event satisfies every predicate. A cross-class event, or one missing the
// field a predicate names, does not match — a rule never matches something it cannot see.
func (m Matcher) Match(e Event) bool {
	if e.Class != m.Class {
		return false
	}
	for _, p := range m.All {
		if !p.match(e) {
			return false
		}
	}
	return true
}

func (p Predicate) match(e Event) bool {
	if fieldIsNumeric(p.Field) {
		got, ok := e.intField(p.Field)
		if !ok {
			return false
		}
		want, err := strconv.Atoi(strings.TrimSpace(p.Value))
		if err != nil {
			return false
		}
		switch p.Op {
		case OpEquals:
			return got == want
		case OpGTE:
			return got >= want
		default:
			return false
		}
	}

	values, ok := e.stringFields(p.Field)
	if !ok {
		return false
	}
	for _, v := range values {
		if p.matchString(v) {
			return true
		}
	}
	return false
}

func (p Predicate) matchString(v string) bool {
	switch p.Op {
	case OpEquals:
		return v == p.Value
	case OpPrefix:
		return strings.HasPrefix(v, p.Value)
	case OpContains:
		return strings.Contains(v, p.Value)
	case OpIn:
		for _, cand := range p.Values {
			if v == cand {
				return true
			}
		}
		return false
	default:
		return false
	}
}
