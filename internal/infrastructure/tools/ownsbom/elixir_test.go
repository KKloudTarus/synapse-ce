package ownsbom

import (
	"context"
	"testing"
)

const mixLock = `%{
  "bandit": {:hex, :bandit, "1.5.7", "hashA", [:mix], [{:hpax, "~> 0.2", [hex: :hpax, optional: false]}], "hexpm", "hashB"},
  "phoenix": {:hex, :phoenix, "1.7.14", "hashC", [:mix], [], "hexpm", "hashD"},
  "local_dep": {:path, "../local", []},
  "git_dep": {:git, "https://example.com/x.git", "abc123", []},
}
`

func TestElixirParseMixLock(t *testing.T) {
	comps, deps, err := (Elixir{}).Parse(context.Background(), ParseInput{Path: "mix.lock", Content: []byte(mixLock)})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if deps != nil {
		t.Errorf("mix.lock yields components, not edges; got %+v", deps)
	}
	got := map[string]string{}
	purl := map[string]string{}
	for _, c := range comps {
		got[c.Name] = c.Version
		purl[c.Name] = c.PURL
	}
	if got["bandit"] != "1.5.7" || got["phoenix"] != "1.7.14" {
		t.Errorf("hex deps not parsed: %v", got)
	}
	if purl["phoenix"] != "pkg:hex/phoenix@1.7.14" {
		t.Errorf("hex PURL wrong: %q", purl["phoenix"])
	}
	//:path and:git deps are not Hex packages → not cataloged.
	if _, ok := got["local_dep"]; ok {
		t.Error(":path dep must be skipped (no Hex version)")
	}
	if _, ok := got["git_dep"]; ok {
		t.Error(":git dep must be skipped (no Hex version)")
	}
	if len(comps) != 2 {
		t.Errorf("want exactly 2 hex components, got %d", len(comps))
	}
}

// mixLockOptional exercises real edges: parent depends on req_child (optional: false) and opt_child
// (optional: true), both catalogued top-level entries so the edges are emitted (unlike mixLock's hpax).
const mixLockOptional = `%{
  "parent": {:hex, :parent, "1.0.0", "h", [:mix], [{:req_child, "~> 1.0", [hex: :req_child, optional: false]}, {:opt_child, "~> 2.0", [hex: :opt_child, optional: true]}], "hexpm", "h"},
  "req_child": {:hex, :req_child, "1.2.0", "h", [:mix], [], "hexpm", "h"},
  "opt_child": {:hex, :opt_child, "2.3.0", "h", [:mix], [], "hexpm", "h"},
}
`

// A parent-declared `optional: true` dep must be emitted as a separate Dependency with Optional set, while
// `optional: false` (or no flag) stays a required edge (#1036).
func TestElixirMixLockOptionalEdges(t *testing.T) {
	_, deps, err := (Elixir{}).Parse(context.Background(), ParseInput{Path: "mix.lock", Content: []byte(mixLockOptional)})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	const parent = "pkg:hex/parent@1.0.0"
	gotReq, gotOpt := map[string]bool{}, map[string]bool{}
	for _, d := range deps {
		if d.Ref != parent {
			continue
		}
		for _, on := range d.DependsOn {
			if d.Optional {
				gotOpt[on] = true
			} else {
				gotReq[on] = true
			}
		}
	}
	if !gotReq["pkg:hex/req_child@1.2.0"] || gotOpt["pkg:hex/req_child@1.2.0"] {
		t.Errorf("req_child must be a REQUIRED edge; required=%v optional=%v", gotReq, gotOpt)
	}
	if !gotOpt["pkg:hex/opt_child@2.3.0"] || gotReq["pkg:hex/opt_child@2.3.0"] {
		t.Errorf("opt_child must be an OPTIONAL edge; required=%v optional=%v", gotReq, gotOpt)
	}
}

func TestElixirMarkersAndEcosystem(t *testing.T) {
	e := Elixir{}
	if e.Ecosystem() != "hex" {
		t.Errorf("Ecosystem() = %q, want hex", e.Ecosystem())
	}
	if len(e.Markers()) != 1 || e.Markers()[0] != "mix.lock" {
		t.Errorf("Markers() = %v, want [mix.lock]", e.Markers())
	}
}

func TestDefaultRegistryIncludesElixir(t *testing.T) {
	r, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry: %v", err)
	}
	if _, ok := r.byMarker["mix.lock"]; !ok {
		t.Error("the default registry must claim mix.lock (Elixir/Hex coverage)")
	}
}
