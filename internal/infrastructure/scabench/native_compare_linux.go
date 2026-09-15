//go:build linux

package scabench

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// TargetNativeVersionComparator delegates only to a runner configured for the
// digest-pinned target environment. It never falls back to host or Go semantic
// comparison. The normal capture path does not construct this comparator; the
// trusted native-evidence phase supplies its target runner explicitly.
type TargetNativeVersionComparator struct {
	runner       ports.ToolRunner
	targetDigest string
	dpkgPath     string
	rpmPath      string
}

var _ ports.NativeVersionComparator = (*TargetNativeVersionComparator)(nil)

// rpmVerCmpProgram is a constant program. Inputs cross the process boundary in
// environment variables, never by interpolation into Lua or RPM macro source.
const rpmVerCmpProgram = `%{lua:
local left = os.getenv("SYNAPSE_SCA_RPM_LEFT_EVR")
local right = os.getenv("SYNAPSE_SCA_RPM_RIGHT_EVR")
if not rpm.vercmp or not left or not right then error("rpm.vercmp inputs unavailable") end
local relation = rpm.vercmp(left, right)
if relation < 0 then print("-1") elseif relation > 0 then print("1") else print("0") end
}`

func NewTargetNativeVersionComparator(runner ports.ToolRunner, targetDigest string) (*TargetNativeVersionComparator, error) {
	if runner == nil {
		return nil, fmt.Errorf("%w: target runner is required", ErrTargetNativeComparisonUnavailable)
	}
	if !validNativeDigest(targetDigest) {
		return nil, fmt.Errorf("%w: target digest is invalid", ErrTargetNativeComparisonUnavailable)
	}
	return &TargetNativeVersionComparator{
		runner:       runner,
		targetDigest: targetDigest,
		dpkgPath:     "/usr/bin/dpkg",
		rpmPath:      "/usr/bin/rpm",
	}, nil
}

func (comparator *TargetNativeVersionComparator) CompareNativeVersion(ctx context.Context, request ports.NativeVersionComparisonRequest) (ports.NativeVersionComparisonResult, error) {
	if comparator == nil || comparator.runner == nil {
		return ports.NativeVersionComparisonResult{}, fmt.Errorf("%w: target runner is required", ErrTargetNativeComparisonUnavailable)
	}
	if err := validateNativeVersionRequest(request); err != nil {
		return ports.NativeVersionComparisonResult{}, err
	}
	if request.TargetDigest != comparator.targetDigest {
		return ports.NativeVersionComparisonResult{}, fmt.Errorf("%w: request target digest does not match pinned target", ErrTargetNativeComparisonUnavailable)
	}
	switch request.Family {
	case ports.NativePackageDeb:
		var results []ports.ToolResult
		relation, compared, err := comparator.compareOperators(ctx, comparator.dpkgPath, "--compare-versions", request.LeftEVR, request.RightEVR, &results)
		if err != nil {
			return ports.NativeVersionComparisonResult{}, fmt.Errorf("target-native dpkg comparison: %w", err)
		}
		operators := []string{"lt", "eq", "gt"}
		specs := make([]ports.ToolSpec, 0, len(compared))
		for index := range compared {
			specs = append(specs, ports.ToolSpec{Name: comparator.dpkgPath, Args: []string{"--compare-versions", request.LeftEVR, operators[index], request.RightEVR}, MaxOutputBytes: 16 << 10, HostNetwork: false})
		}
		return ports.NativeVersionComparisonResult{Relation: relation, ExecutionDigest: nativeExecutionDigest(request, specs, results)}, nil
	case ports.NativePackageRPM:
		spec := ports.ToolSpec{
			Name: comparator.rpmPath, Args: []string{"--eval", rpmVerCmpProgram},
			Env:            []string{"SYNAPSE_SCA_RPM_LEFT_EVR=" + request.LeftEVR, "SYNAPSE_SCA_RPM_RIGHT_EVR=" + request.RightEVR},
			MaxOutputBytes: 16 << 10, HostNetwork: false,
		}
		result, err := comparator.runner.Run(ctx, spec)
		if err != nil {
			return ports.NativeVersionComparisonResult{}, fmt.Errorf("target-native rpm Lua comparison: %w", err)
		}
		if result.ExitCode != 0 {
			return ports.NativeVersionComparisonResult{}, fmt.Errorf("%w: rpm Lua comparator exited %d", ErrTargetNativeComparisonUnavailable, result.ExitCode)
		}
		relation, err := parseRPMRelation(result.Stdout)
		if err != nil {
			return ports.NativeVersionComparisonResult{}, fmt.Errorf("%w: %v", ErrTargetNativeComparisonUnavailable, err)
		}
		return ports.NativeVersionComparisonResult{Relation: relation, ExecutionDigest: nativeExecutionDigest(request, []ports.ToolSpec{spec}, []ports.ToolResult{result})}, nil
	default:
		return ports.NativeVersionComparisonResult{}, fmt.Errorf("%w: unsupported package family", ErrTargetNativeComparisonUnavailable)
	}
}

func (comparator *TargetNativeVersionComparator) compareOperators(ctx context.Context, binary, flag, left, right string, allResults *[]ports.ToolResult) (int, []ports.ToolResult, error) {
	operators := []struct {
		argument string
		relation int
	}{
		{argument: "lt", relation: -1},
		{argument: "eq", relation: 0},
		{argument: "gt", relation: 1},
	}
	results := make([]ports.ToolResult, 0, len(operators))
	for _, operator := range operators {
		result, err := comparator.runner.Run(ctx, ports.ToolSpec{
			Name:           binary,
			Args:           []string{flag, left, operator.argument, right},
			MaxOutputBytes: 16 << 10,
			HostNetwork:    false,
		})
		results = append(results, result)
		*allResults = append(*allResults, result)
		if err != nil {
			return 0, results, err
		}
		if result.ExitCode == 0 {
			return operator.relation, results, nil
		}
		if result.ExitCode != 1 {
			return 0, results, fmt.Errorf("target comparator exited %d", result.ExitCode)
		}
	}
	return 0, results, fmt.Errorf("target comparator returned no relation")
}

func parseRPMRelation(stdout []byte) (int, error) {
	switch strings.TrimSpace(string(stdout)) {
	case "-1":
		return -1, nil
	case "0":
		return 0, nil
	case "1":
		return 1, nil
	default:
		return 0, fmt.Errorf("rpm Lua comparator did not emit -1, 0, or 1")
	}
}

type nativeInvocationIdentity struct {
	Name string   `json:"name"`
	Args []string `json:"args"`
	Env  []string `json:"env"`
}

func nativeExecutionDigest(request ports.NativeVersionComparisonRequest, specs []ports.ToolSpec, results []ports.ToolResult) string {
	invocations := make([]nativeInvocationIdentity, 0, len(specs))
	for _, spec := range specs {
		identity := nativeInvocationIdentity{Name: spec.Name, Args: append([]string(nil), spec.Args...)}
		for _, value := range spec.Env {
			key, raw, ok := strings.Cut(value, "=")
			if !ok || key == "" {
				return ""
			}
			identity.Env = append(identity.Env, key+"="+bench.SHA256Digest([]byte(raw)))
		}
		invocations = append(invocations, identity)
	}
	value := struct {
		TargetDigest string                     `json:"target_digest"`
		Family       ports.NativePackageFamily  `json:"family"`
		LeftEVR      string                     `json:"left_evr"`
		RightEVR     string                     `json:"right_evr"`
		Invocations  []nativeInvocationIdentity `json:"invocations"`
		Results      []ports.ToolResult         `json:"results"`
	}{TargetDigest: request.TargetDigest, Family: request.Family, LeftEVR: request.LeftEVR, RightEVR: request.RightEVR, Invocations: invocations, Results: results}
	body, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return bench.SHA256Digest(body)
}
