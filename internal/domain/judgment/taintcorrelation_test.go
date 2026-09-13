package judgment

import (
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
)

func TestCorrelateTaintSink(t *testing.T) {
	index := map[shared.ID][]string{
		"finding-a": {"github.com/vuln/lib.Parse", "github.com/vuln/lib.Decode"},
		"finding-b": {"github.com/other/pkg.Safe"},
	}

	// A sink that IS a finding's vulnerable symbol resolves to that finding only.
	if got := CorrelateTaintSink(symbolcanon.Go, "github.com/vuln/lib.Decode", index); !reflect.DeepEqual(got, []shared.ID{"finding-a"}) {
		t.Errorf("sink into a vulnerable symbol must resolve to its finding, got %v", got)
	}
	// A sink that is NOT any finding's vulnerable symbol fabricates no link.
	if got := CorrelateTaintSink(symbolcanon.Go, "github.com/app/handler.Serve", index); len(got) != 0 {
		t.Errorf("a non-advisory sink must resolve to nothing, got %v", got)
	}
	// An empty sink frame resolves to nothing.
	if got := CorrelateTaintSink(symbolcanon.Go, "", index); len(got) != 0 {
		t.Errorf("an empty sink must resolve to nothing, got %v", got)
	}
	// A mangled sink frame is never a correlation key.
	if got := CorrelateTaintSink(symbolcanon.Go, "_ZN3vuln3libE", index); len(got) != 0 {
		t.Errorf("a mangled sink must resolve to nothing, got %v", got)
	}
	// A bare single-segment sink/advisory symbol is not a sound identity: no correlation, even if the
	// bare tokens are equal (guards against a coincidental "Parse" == "Parse" fabrication).
	bare := map[shared.ID][]string{"finding-c": {"Parse"}}
	if got := CorrelateTaintSink(symbolcanon.Go, "Parse", bare); len(got) != 0 {
		t.Errorf("a bare one-segment symbol must not correlate, got %v", got)
	}
}

// TestCorrelateTaintSinkMultipleFindingsSortedDedup: a sink symbol shared by two findings' advisories
// resolves to both, sorted and de-duplicated, so the result is deterministic across map iteration order.
func TestCorrelateTaintSinkMultipleFindingsSortedDedup(t *testing.T) {
	index := map[shared.ID][]string{
		"finding-z": {"pkg.Vuln"},
		"finding-a": {"pkg.Vuln", "pkg.Vuln"}, // duplicate symbol on one finding must not duplicate the id
	}
	got := CorrelateTaintSink(symbolcanon.Go, "pkg.Vuln", index)
	if !reflect.DeepEqual(got, []shared.ID{"finding-a", "finding-z"}) {
		t.Errorf("want both findings sorted, got %v", got)
	}
}
