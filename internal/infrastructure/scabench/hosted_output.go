package scabench

import (
	"errors"
	"fmt"
	"strings"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// HostedExternalOutputMaxBytes bounds one scanner output accepted by the hosted
// comparator route before strict decoding.
const HostedExternalOutputMaxBytes int64 = bench.MaxJSONBytes

// ParseHostedExternalOutput converts one bounded comparator scan output into
// canonical benchmark findings. It accepts only the external comparator engines
// used by the hosted route and deliberately returns no observation or evidence
// state: callers must construct and validate those separately.
func ParseHostedExternalOutput(engine bench.Engine, target bench.Target, expectedVersion string, scanOutput, osvVersionProbe []byte) ([]bench.Finding, error) {
	if strings.TrimSpace(expectedVersion) == "" {
		return nil, errors.New("expected engine version is required")
	}
	if len(scanOutput) == 0 {
		return nil, errors.New("scanner output is required")
	}
	if int64(len(scanOutput)) > HostedExternalOutputMaxBytes {
		return nil, fmt.Errorf("scanner output exceeds %d byte limit", HostedExternalOutputMaxBytes)
	}
	if int64(len(osvVersionProbe)) > HostedExternalOutputMaxBytes {
		return nil, fmt.Errorf("OSV version probe exceeds %d byte limit", HostedExternalOutputMaxBytes)
	}

	switch engine {
	case bench.EngineGrype, bench.EngineTrivy:
		findings, err := parseEngine(engine, expectedVersion, scanOutput, target, nil, "")
		if err != nil {
			return nil, fmt.Errorf("parse %s output: %w", engine, err)
		}
		return canonicalFindings(findings), nil
	case bench.EngineOSVScanner:
		if len(osvVersionProbe) == 0 {
			return nil, errors.New("OSV version probe output is required")
		}
		version, err := parseOSVVersion(osvVersionProbe)
		if err != nil || version != expectedVersion {
			return nil, fmt.Errorf("validate OSV scanner version: %w", errVersionMismatch)
		}
		findings, err := parseEngine(engine, expectedVersion, scanOutput, target, nil, "")
		if err != nil {
			return nil, fmt.Errorf("parse %s output: %w", engine, err)
		}
		return canonicalFindings(findings), nil
	default:
		return nil, fmt.Errorf("unsupported hosted external engine %q", engine)
	}
}
