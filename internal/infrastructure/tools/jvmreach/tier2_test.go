package jvmreach

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestTier2ReferencedAffectedMethodRaises(t *testing.T) {
	a := NewTier2(false)
	analysis, err := a.Analyze(context.Background(), filepath.Join("testdata", "target"), []string{tier2TestSymbol("com.deplib.Helper.v")})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 1 || !analysis.Results[0].Reachable {
		t.Fatalf("results=%+v, want one reachable result", analysis.Results)
	}
	if len(analysis.Results[0].Path) < 2 {
		t.Fatalf("path=%v, want app -> affected method", analysis.Results[0].Path)
	}
}

func TestTier2RequiresExactMavenCoordinate(t *testing.T) {
	a := NewTier2(false)
	wrong := "pkg:maven/com.other/deplib@1.0.0" + tier2SubjectSeparator + "com.deplib.Helper.v"
	analysis, err := a.Analyze(context.Background(), filepath.Join("testdata", "target"), []string{wrong})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 0 {
		t.Fatalf("same symbol under wrong Maven coordinate must not raise, got %+v", analysis.Results)
	}
}

func TestTier2UnreachedNeverReturnsNegative(t *testing.T) {
	a := NewTier2(false)
	analysis, err := a.Analyze(context.Background(), filepath.Join("testdata", "target"), []string{tier2TestSymbol("com.deplib.Helper.neverCalled")})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 0 {
		t.Fatalf("raise-only analyzer must omit an unreached symbol, got %+v", analysis.Results)
	}
}

func TestTier2RequiresMavenAttribution(t *testing.T) {
	root := t.TempDir()
	classes := filepath.Join(root, "target", "classes", "com", "demo")
	if err := os.MkdirAll(classes, 0o755); err != nil {
		t.Fatal(err)
	}
	app, err := os.ReadFile(filepath.Join("testdata", "target", "classes", "com", "demo", "App.class"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(classes, "App.class"), app, 0o644); err != nil {
		t.Fatal(err)
	}
	deps := filepath.Join(root, "target", "dependency")
	if err := os.MkdirAll(deps, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := stripPomProperties(
		filepath.Join("testdata", "target", "dependency", "deplib-1.0.jar"),
		filepath.Join(deps, "deplib-1.0.jar"),
	); err != nil {
		t.Fatal(err)
	}

	analysis, err := NewTier2(false).Analyze(context.Background(), filepath.Join(root, "target"), []string{tier2TestSymbol("com.deplib.Helper.v")})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 0 {
		t.Fatalf("jar without pom.properties must not be attributable, got %+v", analysis.Results)
	}
}

func TestTier2NotBuiltProducesNoCoverageVerdict(t *testing.T) {
	root := t.TempDir()
	analysis, err := NewTier2(false).Analyze(context.Background(), root, []string{tier2TestSymbol("com.deplib.Helper.v")})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 0 || len(analysis.Entrypoints) != 0 {
		t.Fatalf("not-built target must mint nothing, got %+v", analysis)
	}
}

func TestPointsToRejectsLooseNearbyAllocation(t *testing.T) {
	cp := parsedCP{
		utf8:      map[uint16]string{1: "pkg/A", 2: "<init>", 3: "()V"},
		classes:   map[uint16]uint16{10: 1},
		members:   map[uint16]cpMember{20: {classIndex: 10, nameType: 30}},
		nameTypes: map[uint16]cpNameType{30: {name: 2, desc: 3}},
	}
	loose := []instruction{{op: 0xbb, cpIndex: 10}, {op: 0xb8, cpIndex: 99}, {op: 0x4b}}
	if class, _, known := storedReferenceSource(loose, 2, cp); class != "" || known {
		t.Fatalf("loose nearby allocation must stay unknown, got class=%q known=%v", class, known)
	}
	exact := []instruction{{op: 0xbb, cpIndex: 10}, {op: 0x59}, {op: 0xb7, cpIndex: 20}, {op: 0x4b}}
	if class, _, known := storedReferenceSource(exact, 3, cp); class != "pkg/A" || !known {
		t.Fatalf("exact constructor allocation not recognized: class=%q known=%v", class, known)
	}
}

func stripPomProperties(src, dst string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(out)
	for _, f := range zr.File {
		if filepath.Base(f.Name) == "pom.properties" {
			continue
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		w, err := zw.CreateHeader(&f.FileHeader)
		if err != nil {
			r.Close()
			return err
		}
		_, err = io.Copy(w, r)
		r.Close()
		if err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return out.Close()
}

func TestCHAVirtualDispatchAndPointsToFallback(t *testing.T) {
	g := newMethodGraph()
	g.classes["pkg/I"] = &classModel{name: "pkg/I", methods: map[string]*methodModel{methodSig("run", "()V"): {owner: "pkg/I", name: "run", desc: "()V"}}}
	g.classes["pkg/A"] = &classModel{name: "pkg/A", interfaces: []string{"pkg/I"}, methods: map[string]*methodModel{methodSig("run", "()V"): {owner: "pkg/A", name: "run", desc: "()V"}}}
	g.classes["pkg/B"] = &classModel{name: "pkg/B", interfaces: []string{"pkg/I"}, methods: map[string]*methodModel{methodSig("run", "()V"): {owner: "pkg/B", name: "run", desc: "()V"}}}
	cha := g.resolveCall(callSite{opcode: 0xb9, owner: "pkg/I", name: "run", desc: "()V", receiverUnknown: true}, false)
	if !contains(cha, fullMethodKey("pkg/A", "run", "()V")) || !contains(cha, fullMethodKey("pkg/B", "run", "()V")) {
		t.Fatalf("CHA targets=%v, want both implementations", cha)
	}
	pt := g.resolveCall(callSite{opcode: 0xb9, owner: "pkg/I", name: "run", desc: "()V", receiverTypes: []string{"pkg/A"}}, true)
	if !contains(pt, fullMethodKey("pkg/A", "run", "()V")) || contains(pt, fullMethodKey("pkg/B", "run", "()V")) {
		t.Fatalf("points-to targets=%v, want only A", pt)
	}
	fallback := g.resolveCall(callSite{opcode: 0xb9, owner: "pkg/I", name: "run", desc: "()V", receiverTypes: []string{"pkg/A"}, receiverUnknown: true}, true)
	if !contains(fallback, fullMethodKey("pkg/B", "run", "()V")) {
		t.Fatalf("unknown receiver must fall back to CHA, got %v", fallback)
	}
}

func TestBlindProxyAlsoMarksReflection(t *testing.T) {
	blind := map[string]bool{}
	markBlindCall(blind, callSite{opcode: 0xb8, owner: "java/lang/reflect/Proxy", name: "newProxyInstance"})
	if !blind["proxy"] || !blind["reflection"] {
		t.Fatalf("blind=%v", blind)
	}
}

func tier2TestSymbol(symbol string) string {
	return "pkg:maven/com.deplib/deplib@1.0.0" + tier2SubjectSeparator + symbol
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
