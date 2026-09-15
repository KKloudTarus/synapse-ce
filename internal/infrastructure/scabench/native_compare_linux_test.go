//go:build linux

package scabench

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type nativeComparisonRunner struct {
	specs   []ports.ToolSpec
	results []ports.ToolResult
}

func (runner *nativeComparisonRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	runner.specs = append(runner.specs, spec)
	if len(runner.results) == 0 {
		return ports.ToolResult{}, fmt.Errorf("unexpected target-native command")
	}
	result := runner.results[0]
	runner.results = runner.results[1:]
	return result, nil
}

func TestTargetNativeVersionComparatorUsesDPKGArgvInsidePinnedTarget(t *testing.T) {
	runner := &nativeComparisonRunner{results: []ports.ToolResult{{ExitCode: 1}, {ExitCode: 0}}}
	comparator, err := NewTargetNativeVersionComparator(runner, digestByte('a'))
	if err != nil {
		t.Fatal(err)
	}
	result, err := comparator.CompareNativeVersion(context.Background(), ports.NativeVersionComparisonRequest{TargetDigest: digestByte('a'), Family: ports.NativePackageDeb, LeftEVR: "1:1.0-1", RightEVR: "1:1.0-1"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Relation != 0 || !validNativeDigest(result.ExecutionDigest) {
		t.Fatalf("native dpkg result = %+v", result)
	}
	if len(runner.specs) != 2 {
		t.Fatalf("dpkg command count = %d, want 2", len(runner.specs))
	}
	for index, want := range [][]string{{"--compare-versions", "1:1.0-1", "lt", "1:1.0-1"}, {"--compare-versions", "1:1.0-1", "eq", "1:1.0-1"}} {
		if runner.specs[index].Name != "/usr/bin/dpkg" || fmt.Sprint(runner.specs[index].Args) != fmt.Sprint(want) || runner.specs[index].HostNetwork {
			t.Fatalf("dpkg spec %d = %+v, want argv %v", index, runner.specs[index], want)
		}
	}
}

func TestTargetNativeVersionComparatorUsesConstantRPMLuaProgramAndEnvData(t *testing.T) {
	runner := &nativeComparisonRunner{results: []ports.ToolResult{{ExitCode: 0, Stdout: []byte("-1\n")}}}
	comparator, err := NewTargetNativeVersionComparator(runner, digestByte('b'))
	if err != nil {
		t.Fatal(err)
	}
	result, err := comparator.CompareNativeVersion(context.Background(), ports.NativeVersionComparisonRequest{TargetDigest: digestByte('b'), Family: ports.NativePackageRPM, LeftEVR: "0:1.0-1", RightEVR: "0:2.0-1"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Relation != -1 || len(runner.specs) != 1 {
		t.Fatalf("native rpm result/specs = %+v/%+v", result, runner.specs)
	}
	spec := runner.specs[0]
	if spec.Name != "/usr/bin/rpm" || fmt.Sprint(spec.Args) != fmt.Sprint([]string{"--eval", rpmVerCmpProgram}) || spec.HostNetwork {
		t.Fatalf("rpm Lua spec = %+v", spec)
	}
	if fmt.Sprint(spec.Env) != fmt.Sprint([]string{"SYNAPSE_SCA_RPM_LEFT_EVR=0:1.0-1", "SYNAPSE_SCA_RPM_RIGHT_EVR=0:2.0-1"}) || strings.Contains(spec.Args[1], "0:1.0-1") || strings.Contains(spec.Args[1], "0:2.0-1") {
		t.Fatalf("rpm argv/env dataflow = %+v", spec)
	}
}

func TestTargetNativeVersionComparatorFailsClosedForMalformedRPMLuaOutput(t *testing.T) {
	runner := &nativeComparisonRunner{results: []ports.ToolResult{{ExitCode: 0, Stdout: []byte("unexpected")}}}
	comparator, err := NewTargetNativeVersionComparator(runner, digestByte('c'))
	if err != nil {
		t.Fatal(err)
	}
	_, err = comparator.CompareNativeVersion(context.Background(), ports.NativeVersionComparisonRequest{TargetDigest: digestByte('c'), Family: ports.NativePackageRPM, LeftEVR: "0:1-1", RightEVR: "0:2-1"})
	if err == nil {
		t.Fatal("RPM comparator accepted malformed target-native Lua output")
	}
	if len(runner.specs) != 1 {
		t.Fatalf("rpm comparator ran extra commands: %+v", runner.specs)
	}
}
