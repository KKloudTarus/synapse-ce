package ownadvisory

import (
	"bytes"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

func TestOVALSnapshotKeepsHighestBoundaryPerArchitectureAcrossDocuments(t *testing.T) {
	facts := []struct {
		arch    string
		version string
	}{
		{arch: "aarch64", version: "3-1"},
		{arch: "x86_64", version: "1-1"},
		{arch: "x86_64", version: "2-1"},
	}
	documents := make([][]byte, len(facts))
	for index, fact := range facts {
		doc := sleArchDoc(
			sleArchDefinition("202654369", "oval:test:archfixed", "libacl1-2.4.0-150000.4.6.1 is installed"),
			"("+fact.arch+")",
		)
		doc = bytes.ReplaceAll(doc, []byte("for aarch64,ppc64le,s390x,x86_64"), []byte("for "+fact.arch))
		documents[index] = bytes.ReplaceAll(doc, []byte("2.4.0-150000.4.6.1"), []byte(fact.version))
	}
	for _, order := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		ordered := make([][]byte, len(order))
		for index, factIndex := range order {
			ordered[index] = documents[factIndex]
		}
		advs, err := ParseOVALSnapshot(ordered)
		if err != nil {
			t.Fatalf("order %v: parse snapshot: %v", order, err)
		}
		if len(advs) != 1 || len(advs[0].Affected) != 2 {
			t.Fatalf("order %v: want two architecture bindings, got %+v", order, advs)
		}
		got := map[string]string{}
		for _, affected := range advs[0].Affected {
			got[strings.Join(affected.Architectures, ",")] = affected.FixedVersion
		}
		if got["aarch64"] != "0:3-1" || got["x86_64"] != "0:2-1" {
			t.Errorf("order %v: architecture boundaries = %v", order, got)
		}
		if matched, fixed := advs[0].Match("SUSE:15.6", "libacl1", "0:1.5-1", "x86_64"); !matched || fixed != "0:2-1" {
			t.Errorf("order %v: x86_64 below the later boundary must match with fix 0:2-1, got matched=%v fixed=%q", order, matched, fixed)
		}
		if matched, _ := advs[0].Match("SUSE:15.6", "libacl1", "0:2-1", "x86_64"); matched {
			t.Errorf("order %v: x86_64 at its fixed boundary must not match", order)
		}
	}
}

func TestRPMOvalBindingsKeepHighestBoundaryPerArchitectureInEveryOrder(t *testing.T) {
	facts := []advisory.AffectedPackage{
		{Ecosystem: "SUSE:15.6", Package: "libacl1", Architectures: []string{"aarch64"}, FixedVersion: "0:3-1"},
		{Ecosystem: "SUSE:15.6", Package: "libacl1", Architectures: []string{"x86_64"}, FixedVersion: "0:1-1"},
		{Ecosystem: "SUSE:15.6", Package: "libacl1", Architectures: []string{"x86_64"}, FixedVersion: "0:2-1"},
	}
	orders := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, order := range orders {
		acc := newRPMOvalAcc()
		for _, index := range order {
			acc.merge(facts[index])
		}
		if acc.conflicts["SUSE:15.6\x00libacl1"] {
			t.Fatalf("order %v unexpectedly conflicted", order)
		}
		for key, want := range map[string]string{
			"SUSE:15.6\x00libacl1\x00aarch64": "0:3-1",
			"SUSE:15.6\x00libacl1\x00x86_64":  "0:2-1",
		} {
			if got := acc.bindings[key].FixedVersion; got != want {
				t.Errorf("order %v binding %q fixed version = %q, want %q", order, key, got, want)
			}
		}
	}
}

func TestSUSELifecycleKeepsHighestBoundaryPerArchitectureInEveryOrder(t *testing.T) {
	facts := []struct {
		arch    string
		version string
	}{
		{arch: "aarch64", version: "0:3-1"},
		{arch: "x86_64", version: "0:1-1"},
		{arch: "x86_64", version: "0:2-1"},
	}
	orders := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, order := range orders {
		var clauses, tests, states strings.Builder
		for _, index := range order {
			fact := facts[index]
			id := string(rune('a' + index))
			clauses.WriteString(`<criteria operator="AND">
				<criteria operator="OR"><criterion test_ref="oval:test:product" comment="SUSE Linux Enterprise Server 15 SP6 is installed"/></criteria>
				<criteria operator="OR"><criterion test_ref="oval:test:fixed-` + id + `" comment="libacl1-` + strings.TrimPrefix(fact.version, "0:") + ` is installed"/></criteria>
			</criteria>`)
			tests.WriteString(`<linux:rpminfo_test id="oval:test:fixed-` + id + `" check="at least one" comment="libacl1 is &lt;` + fact.version + `"><linux:object object_ref="oval:obj:package"/><linux:state state_ref="oval:state:fixed-` + id + `"/></linux:rpminfo_test>`)
			states.WriteString(`<linux:rpminfo_state id="oval:state:fixed-` + id + `"><linux:arch datatype="string" operation="pattern match">(` + fact.arch + `)</linux:arch><linux:evr datatype="evr_string" operation="less than">` + fact.version + `</linux:evr></linux:rpminfo_state>`)
		}
		doc := oracleDoc(`<definitions>
			<definition id="oval:org.opensuse.security:def:boundary" version="1" class="vulnerability">
				<metadata><title>CVE-2026-54369</title><affected family="unix"><platform>SUSE Linux Enterprise Server 15 SP6</platform></affected></metadata>
				<criteria operator="OR">` + clauses.String() + `</criteria>
			</definition>
		</definitions>
		<tests>
			<linux:rpminfo_test id="oval:test:product" check="at least one" comment="sles-release is ==15.6"><linux:object object_ref="oval:obj:product"/><linux:state state_ref="oval:state:product"/></linux:rpminfo_test>` + tests.String() + `
		</tests>
		<objects>
			<linux:rpminfo_object id="oval:obj:product"><linux:name>sles-release</linux:name></linux:rpminfo_object>
			<linux:rpminfo_object id="oval:obj:package"><linux:name>libacl1</linux:name></linux:rpminfo_object>
		</objects>
		<states>
			<linux:rpminfo_state id="oval:state:product"><linux:version operation="equals">15.6</linux:version></linux:rpminfo_state>` + states.String() + `
		</states>`)
		advs, err := ParseOVAL(doc)
		if err != nil {
			t.Fatalf("order %v: parse OVAL: %v", order, err)
		}
		if len(advs) != 1 || len(advs[0].Affected) != 2 {
			t.Fatalf("order %v: want two architecture bindings, got %+v", order, advs)
		}
		got := map[string]string{}
		for _, affected := range advs[0].Affected {
			got[strings.Join(affected.Architectures, ",")] = affected.FixedVersion
		}
		if got["aarch64"] != "0:3-1" || got["x86_64"] != "0:2-1" {
			t.Errorf("order %v: architecture boundaries = %v", order, got)
		}
		if matched, fixed := advs[0].Match("SUSE:15.6", "libacl1", "0:1.5-1", "x86_64"); !matched || fixed != "0:2-1" {
			t.Errorf("order %v: x86_64 below the later boundary must match with fix 0:2-1, got matched=%v fixed=%q", order, matched, fixed)
		}
		if matched, _ := advs[0].Match("SUSE:15.6", "libacl1", "0:2-1", "x86_64"); matched {
			t.Errorf("order %v: x86_64 at its fixed boundary must not match", order)
		}
	}
}
