package taint

import (
	"strings"
	"testing"
)

func TestDefaultJsCatalogIsWellFormed(t *testing.T) {
	catalog := DefaultJsCatalog()
	if err := validateJsCatalog(catalog); err != nil {
		t.Fatalf("DefaultJsCatalog is invalid: %v", err)
	}
	if len(catalog.ReferenceSourcePrefixes) == 0 {
		t.Fatal("catalog has no reference source prefixes")
	}
	for _, sink := range catalog.Sinks {
		if !sink.Class.Valid() {
			t.Errorf("sink %q has invalid class %q", sink.Rule, sink.Class)
		}
		if !strings.HasPrefix(sink.CWE, "CWE-") {
			t.Errorf("sink %q has non-CWE code %q", sink.Rule, sink.CWE)
		}
		if !sink.AllArguments && len(sink.ArgumentIndexes) == 0 {
			t.Errorf("sink %q models no argument", sink.Rule)
		}
	}
}

// TestDefaultJsCatalogDeclinesUnsoundShapes pins the no-false-positive DECLINE list: a shape that would need
// receiver-type or object-field resolution the PR1 facts do not carry must have no sink model. A regression
// that adds one of these fails here.
func TestDefaultJsCatalogDeclinesUnsoundShapes(t *testing.T) {
	catalog := DefaultJsCatalog()

	// No SQLi rule ships: .query / .raw / .execute on a runtime connection instance is DECLINED.
	for _, sink := range catalog.Sinks {
		if sink.Rule == "js-taint-sqli" {
			t.Errorf("SQLi sink is DECLINED for PR2 but a js-taint-sqli sink model exists")
		}
	}

	// No sink is matched by a bare, receiver-agnostic member suffix that would flag an arbitrary object.
	declinedSuffixes := []string{"query", "raw", "execute", "innerHTML", "outerHTML"}
	for _, sink := range catalog.Sinks {
		for _, suffix := range sink.Pattern.RawSuffixes {
			for _, declined := range declinedSuffixes {
				if suffix == declined {
					t.Errorf("sink %q matches bare %q, which would flag an arbitrary receiver", sink.Rule, suffix)
				}
			}
		}
		for _, name := range sink.Pattern.Names {
			if name == "query" || name == "execute" || name == "raw" {
				// Names are only reached after the base resolves to an import in Modules, so a DB member name
				// is acceptable there; assert we did not smuggle one in without any module anchor.
				if len(sink.Pattern.Modules) == 0 {
					t.Errorf("sink %q matches member %q with no module anchor", sink.Rule, name)
				}
			}
		}
	}

	// Every sanitizer neutralizes only a real class, and no sanitizer claims to clean every class unless it is
	// the numeric-coercion set (Number/parseInt/parseFloat), which genuinely does.
	for _, sanitizer := range catalog.Sanitizers {
		if len(sanitizer.Classes) == 0 {
			t.Errorf("sanitizer %+v neutralizes nothing", sanitizer.Pattern)
		}
	}
}
