// Package scabridge carries the legacy SCA benchmark (internal/usecase/scabench) into the engine-neutral
// core (#1640). The oracle becomes a truth set and each engine's observation becomes a neutral observation,
// so the core scores the owned engine and every comparator through one code path. The legacy scorer
// stays as it is; TestBridgeReproducesLegacyCells pins the two to the same counts.
//
// Unit kinds are "component-advisory/<purl type>", derived from the component alone. The legacy oracle
// records expected coverage per case and engine; the bridge turns it into a per-engine capability list
// and refuses an oracle whose coverage differs within one unit kind, which a capability list cannot say.
package scabridge

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchcore"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// UnitKindPrefix names the SCA relation unit: one component at one version against one advisory.
const UnitKindPrefix = "component-advisory/"

// NormalizationID names the deterministic normalization both sides use: scabench.BenchmarkKey.
const NormalizationID = "scabench-structural-component-advisory-v1"

// normalizationSpec states the policy NormalizationDigest identifies. A change to what the bridge emits
// as an identity changes this text, so it changes the digest a manifest froze.
const normalizationSpec = NormalizationID + `: identity is {ecosystem, package, version, advisory} from
scabench.BenchmarkKey(component, advisory). The component's structural identity comes from its purl; the
advisory is scabench's canonical representative. Values are emitted as BenchmarkKey returns them; the core
compares them exactly. An oracle alias becomes an alternate identity of its unit. A finding whose purl or
advisory BenchmarkKey refuses is unmapped.`

// NormalizationDigest identifies normalizationSpec. Every observation the bridge emits carries it, and a
// scorecard binds only observations whose normalization matches the profile's matching policy.
var NormalizationDigest = benchmark.SHA256Digest([]byte(normalizationSpec))

// ErrBridge is wrapped by every bridge failure.
var ErrBridge = errors.New("sca bridge")

// UnitKind derives a component's unit kind from its purl type.
func UnitKind(component scabench.Component) (string, error) {
	purl := strings.TrimSpace(component.PURL)
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", fmt.Errorf("%w: component purl %q has no pkg scheme", ErrBridge, purl)
	}
	kind, _, ok := strings.Cut(rest, "/")
	if !ok || kind == "" {
		return "", fmt.Errorf("%w: component purl %q has no type", ErrBridge, purl)
	}
	return UnitKindPrefix + strings.ToLower(kind), nil
}

func identity(component scabench.Component, advisory string) (map[string]string, error) {
	key, err := scabench.BenchmarkKey(component, advisory)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBridge, err)
	}
	return map[string]string{"ecosystem": key.Ecosystem, "package": key.Package, "version": key.Version, "advisory": key.Advisory}, nil
}

// Truth converts the legacy oracle over the catalog's targets. Affected is positive; fixed, not_affected
// and withdrawn are negative. The legacy reduction treats a finding outside the oracle as unknown, so the
// truth set is open-world. Each target becomes a subject with its image digest.
func Truth(profileID, version string, catalog scabench.Catalog, oracle scabench.Oracle) (benchcore.TruthSet, error) {
	out := benchcore.TruthSet{SchemaVersion: benchcore.TruthSchemaVersion, ProfileID: profileID, Version: version}
	for _, target := range catalog.Targets {
		out.Subjects = append(out.Subjects, benchcore.Subject{ID: target.ID, Digest: target.Digest})
	}
	for _, c := range oracle.Cases {
		kind, err := UnitKind(c.Component)
		if err != nil {
			return benchcore.TruthSet{}, err
		}
		primary, err := identity(c.Component, c.AdvisoryID)
		if err != nil {
			return benchcore.TruthSet{}, err
		}
		unit := benchcore.TruthUnit{ID: c.ID, SubjectID: c.TargetID, UnitKind: kind, Identity: primary,
			Provenance: string(c.Provenance), Authorship: strings.Join(c.LabelerIDs, ",")}
		seen := map[string]bool{primary["advisory"]: true}
		for _, alias := range c.Aliases {
			alternate, err := identity(c.Component, alias)
			if err != nil {
				return benchcore.TruthSet{}, err
			}
			if seen[alternate["advisory"]] {
				continue
			}
			seen[alternate["advisory"]] = true
			unit.AlternateIdentities = append(unit.AlternateIdentities, alternate)
		}
		switch c.Truth {
		case scabench.TruthAffected:
			unit.Label = benchcore.LabelPositive
		case scabench.TruthFixed, scabench.TruthNotAffected, scabench.TruthWithdrawn:
			unit.Label = benchcore.LabelNegative
		default:
			return benchcore.TruthSet{}, fmt.Errorf("%w: case %q has truth %q", ErrBridge, c.ID, c.Truth)
		}
		for _, citation := range c.Citations {
			unit.Citations = append(unit.Citations, citation.Reference+"@"+citation.Digest)
		}
		out.Units = append(out.Units, unit)
	}
	if err := out.Validate(); err != nil {
		return benchcore.TruthSet{}, err
	}
	return out, nil
}

// Capabilities turns the oracle's expected coverage into one capability list per engine: the unit kinds
// on which every case is expected covered for that engine.
func Capabilities(oracle scabench.Oracle) (map[scabench.Engine][]string, error) {
	type cell struct {
		engine scabench.Engine
		kind   string
	}
	coverage := map[cell]scabench.Coverage{}
	for _, c := range oracle.Cases {
		kind, err := UnitKind(c.Component)
		if err != nil {
			return nil, err
		}
		for _, engine := range scabench.Engines() {
			got := c.ExpectedCoverage[engine]
			key := cell{engine, kind}
			if prior, ok := coverage[key]; ok && prior != got {
				return nil, fmt.Errorf("%w: %s coverage of %s is %s on one case and %s on another; a capability list cannot express it", ErrBridge, engine, kind, prior, got)
			}
			coverage[key] = got
		}
	}
	out := map[scabench.Engine][]string{}
	for key, got := range coverage {
		if got == scabench.CoverageCovered {
			out[key.engine] = append(out[key.engine], key.kind)
		}
	}
	for engine := range out {
		sort.Strings(out[engine])
	}
	return out, nil
}

// Observation converts one legacy observation. It sees no oracle: findings are normalized with the same
// structural key the legacy scorer uses, and aliases are the truth set's business. A finding whose
// component cannot be normalized is reported as unmapped rather than guessed.
func Observation(profileID string, o scabench.Observation, capabilities []string) (benchcore.Observation, error) {
	out := benchcore.Observation{
		SchemaVersion: benchcore.ObservationSchemaVersion,
		ProfileID:     profileID,
		Engine: benchcore.EngineIdentity{
			EngineID:           string(o.Engine),
			AdapterID:          "scabench-" + string(o.Engine),
			AdapterVersion:     o.EngineVersion,
			ScoredComponent:    benchcore.ScoredComponent{ID: string(o.Engine), Provenance: o.EngineBinaryDigest},
			BinaryDigest:       o.EngineBinaryDigest,
			DataSnapshotDigest: o.DatabaseDigest,
			ConfigDigest:       o.ConfigDigest,
			EnvironmentDigest:  o.EnvironmentDigest,
		},
		Subject:              benchcore.Subject{ID: o.TargetID, Digest: o.TargetDigest},
		DeclaredCapabilities: append([]string(nil), capabilities...),
		Normalization:        benchcore.Identity{ID: NormalizationID, Digest: NormalizationDigest},
		RawEvidenceDigest:    o.RawOutputDigest,
	}
	switch o.State {
	case scabench.ObservationComplete:
		out.State = benchcore.StateComplete
	case scabench.ObservationIncomplete:
		out.State = benchcore.StateIncomplete
	case scabench.ObservationUnsupported:
		out.State = benchcore.StateUnsupported
	case scabench.ObservationUnknown:
		out.State = benchcore.StateUnknown
	default:
		return benchcore.Observation{}, fmt.Errorf("%w: observation state %q", ErrBridge, o.State)
	}
	for _, f := range o.Findings {
		kind, kindErr := UnitKind(f.Component)
		id, idErr := identity(f.Component, f.AdvisoryID)
		if err := errors.Join(kindErr, idErr); err != nil {
			out.Unmapped = append(out.Unmapped, benchcore.Unmapped{RawRef: f.Component.PURL + " " + f.AdvisoryID, Reason: err.Error()})
			continue
		}
		out.Findings = append(out.Findings, benchcore.Finding{UnitKind: kind, Identity: id})
	}
	if err := out.Validate(); err != nil {
		return benchcore.Observation{}, err
	}
	return out, nil
}
