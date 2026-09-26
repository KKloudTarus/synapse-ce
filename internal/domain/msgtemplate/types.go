package msgtemplate

// kind is a set of possible static types. A value whose type depends on runtime data (the result of
// and/or) carries several bits; a parameter accepts a value only when every possible type fits.
type kind uint8

const (
	kString kind = 1 << iota
	kInt
	kFloat
	kBool
	kList
	kScalar = kString | kInt | kFloat | kBool
)

// single reports whether exactly one type is possible.
func (k kind) single() bool { return k != 0 && k&(k-1) == 0 }

// value is the static type of an expression. list names the list variable when kind is kList.
type value struct {
	kind kind
	list string
}

func (v value) isList() bool { return v.kind == kList }

var (
	stringValue = value{kind: kString}
	intValue    = value{kind: kInt}
	floatValue  = value{kind: kFloat}
	boolValue   = value{kind: kBool}
)

// funcSpec is the static signature of an allowlisted function. params holds the accepted kinds per
// argument; a variadic function repeats its last entry. A pipeline passes its value as the last
// argument, so list parameters come last.
type funcSpec struct {
	params   []kind
	min      int
	variadic bool
	result   kind
	// sameKind requires every argument to have one identical basic type (eq, ne): text/template
	// cannot compare values of different kinds.
	sameKind bool
	// union returns the union of the argument kinds (and, or return one of their arguments).
	union bool
}

// funcSpecs is the complete function allowlist. eq, ne, and, or and not are text/template
// builtins; every other builtin (call, print, printf, println, index, slice, len, html, js,
// urlquery) is rejected because it is absent here. funcMap in funcs.go implements the rest.
var funcSpecs = map[string]funcSpec{
	"default":        {params: []kind{kString, kString}, min: 2, result: kString},
	"upper":          {params: []kind{kString}, min: 1, result: kString},
	"lower":          {params: []kind{kString}, min: 1, result: kString},
	"truncate":       {params: []kind{kInt, kString}, min: 2, result: kString},
	"join":           {params: []kind{kString, kString, kList}, min: 3, result: kString},
	"severity_label": {params: []kind{kString}, min: 1, result: kString},
	"count":          {params: []kind{kList}, min: 1, result: kInt},
	"plural":         {params: []kind{kInt | kString, kString, kString}, min: 3, result: kString},
	"eq":             {params: []kind{kScalar}, min: 2, variadic: true, result: kBool, sameKind: true},
	"ne":             {params: []kind{kScalar, kScalar}, min: 2, result: kBool, sameKind: true},
	"and":            {params: []kind{kScalar}, min: 1, variadic: true, union: true},
	"or":             {params: []kind{kScalar}, min: 1, variadic: true, union: true},
	"not":            {params: []kind{kScalar}, min: 1, result: kBool},
}

// check type-checks a call and returns its result type, or the rejection code.
func (s funcSpec) check(args []value) (value, Code, bool) {
	if len(args) < s.min || (!s.variadic && len(args) > len(s.params)) {
		return value{}, CodeWrongArgumentCount, false
	}
	var union kind
	for i, arg := range args {
		accepts := s.params[min(i, len(s.params)-1)]
		if arg.kind&^accepts != 0 {
			if arg.isList() || accepts == kList {
				return value{}, CodeListMisuse, false
			}
			return value{}, CodeArgumentType, false
		}
		if s.sameKind && (arg.kind != args[0].kind || !arg.kind.single()) {
			return value{}, CodeArgumentType, false
		}
		union |= arg.kind
	}
	if s.union {
		return value{kind: union}, "", true
	}
	return value{kind: s.result}, "", true
}
