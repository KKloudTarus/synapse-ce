package taint

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/javaprogram"
)

// TestJavaReceiverMutatorCarriesTaint pins the statement-form builder pattern, which is how Java assembles a
// query across lines rather than in one chained expression:
//
//	String p = request.getParameter("q");
//	StringBuilder sb = new StringBuilder();
//	sb.append(p);                 // result discarded, so only the receiver carries p
//	stmt.executeQuery(sb.toString());
//
// The chained form already worked, because an unmodeled call propagates its arguments into its RESULT. This
// form needs the argument to reach the RECEIVER, which is what ReceiverMutators adds. Without it the flow
// stops at the append and the query reads clean.
func TestJavaReceiverMutatorCarriesTaint(t *testing.T) {
	p := jPos()
	scope := jHandID()
	values := []javaprogram.Value{
		{ID: "v-src", ScopeID: scope, Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: p},
		{ID: "v-param", ScopeID: scope, Kind: javaprogram.ValueReference, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"p"}}, Pos: p},
		{ID: "v-sb", ScopeID: scope, Kind: javaprogram.ValueReference, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"sb"}}, Pos: p},
		{ID: "v-appended", ScopeID: scope, Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: p},
		{ID: "v-sql", ScopeID: scope, Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: p},
	}
	flows := []javaprogram.ValueFlow{{FromID: "v-src", ToID: "v-param", Kind: javaprogram.FlowAssignment, Pos: p}}
	calls := []javaprogram.Call{
		// String p = request.getParameter("q")
		{ID: "c-src", CallerID: scope, Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"request", "getParameter"}}, ResultID: "v-src", Pos: p},
		// sb.append(p) as a STATEMENT: the result is thrown away, so only the receiver can carry the taint.
		{ID: "c-append", CallerID: scope, Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"sb", "append"}},
			ReceiverValueID: "v-sb", ResultID: "v-appended",
			Arguments: []javaprogram.Argument{{Value: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"p"}}, ValueID: "v-param", Pos: p}}, Pos: p},
		// sb.toString() reads the receiver back out.
		{ID: "c-tostring", CallerID: scope, Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"sb", "toString"}},
			ReceiverValueID: "v-sb", ResultID: "v-sql", Pos: p},
		// stmt.executeQuery(sql)
		{ID: "c-sink", CallerID: scope, Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"stmt", "executeQuery"}},
			Arguments: []javaprogram.Argument{{Value: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, ValueID: "v-sql", Pos: p}}, Pos: p},
	}
	doc := javaSkeleton(nil, values, flows, calls, nil)
	if got := javaRules(t, doc); !got["java-taint-sql-statement"] {
		t.Fatalf("statement-form builder taint did not reach the SQL sink; rules=%v", got)
	}
}

// TestJavaReceiverMutatorIsNotASetterFloor pins the exclusion. A bean setter is not a container mutator, and
// admitting it would carry taint into every aggregate a codebase assigns an untrusted field to.
func TestJavaReceiverMutatorIsNotASetterFloor(t *testing.T) {
	for _, name := range []string{"setName", "set", "write", "toString"} {
		if containsString(DefaultJavaCatalog().ReceiverMutators, name) {
			t.Fatalf("%q must not be a receiver mutator: it does not carry an absorb-the-argument contract", name)
		}
	}
}
