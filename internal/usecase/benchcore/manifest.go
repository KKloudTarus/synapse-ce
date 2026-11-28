package benchcore

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// ManifestSchemaVersion names the closure-scope manifest document.
const ManifestSchemaVersion = "synapse-benchmark-closure-manifest-v1"

// Dispositions a profile or a lane may carry. Required profiles must execute before the EPIC closes; a
// conditional or optional one needs a published trigger and rationale.
const (
	DispositionRequired    = "required"
	DispositionConditional = "conditional"
	DispositionOptional    = "optional"
)

// Authorization statuses for a lane that needs a licence, rules of engagement or a lab.
const (
	AuthorizationObtained    = "obtained"
	AuthorizationNotObtained = "not_obtained"
	AuthorizationNone        = "none"
)

// ClosureManifest freezes the scope of a benchmark claim: the work packages, every profile with its
// population, truth, scorer and enrolled engines, the control suites that validate the scorer, and the
// lanes that need external authorization. Its digest is recorded in every run-start receipt and
// scorecard, so a result cannot be attributed to a scope that was written after the run.
type ClosureManifest struct {
	SchemaVersion       string                 `json:"schema_version"`
	ManifestID          string                 `json:"manifest_id"`
	Revision            int                    `json:"revision"`
	Supersedes          *Succession            `json:"supersedes,omitempty"`
	Claim               string                 `json:"claim"`
	PopulationStatement string                 `json:"population_statement"`
	WorkPackages        map[string]WorkPackage `json:"work_packages"`
	Profiles            []Profile              `json:"profiles"`
	ControlSuites       []ControlSuite         `json:"control_suites"`
	Lanes               []Lane                 `json:"lanes"`
}

// WorkPackage is one of the EPIC's A to G packages.
type WorkPackage struct {
	Summary  string `json:"summary"`
	Required bool   `json:"required"`
}

// Succession records which manifest revision this one replaces and every scope change it makes.
type Succession struct {
	Revision             int      `json:"revision"`
	Digest               string   `json:"digest"`
	ScopeChangeRationale string   `json:"scope_change_rationale"`
	Changes              []string `json:"changes"`
}

// Identity names a versioned, digested input: a corpus, a truth set, a scorer or a matching policy.
type Identity struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest"`
}

// Population states what a profile measures over.
type Population struct {
	Subjects   int `json:"subjects"`
	TruthUnits int `json:"truth_units"`
	Positives  int `json:"positives"`
	Negatives  int `json:"negatives"`
}

// Thresholds are the absolute criteria a standalone scorecard is graded against.
type Thresholds struct {
	MinimumRecall    float64 `json:"minimum_recall"`
	MinimumPrecision float64 `json:"minimum_precision"`
	MaximumUnknown   float64 `json:"maximum_unknown"`
	MarginRationale  string  `json:"margin_rationale"`
}

// Support is the minimum truth support a profile needs before its cells carry weight.
type Support struct {
	Positives int    `json:"positives"`
	Negatives int    `json:"negatives"`
	Rationale string `json:"rationale"`
}

// Enrollment freezes one engine's identity and declared capabilities for a profile before measurement.
type Enrollment struct {
	EngineID             string          `json:"engine_id"`
	AdapterID            string          `json:"adapter_id"`
	ScoredComponent      ScoredComponent `json:"scored_component"`
	DeclaredCapabilities []string        `json:"declared_capabilities"`
}

// ScoredComponent names the part of an engine a profile scores and where it comes from.
type ScoredComponent struct {
	ID         string `json:"id"`
	Provenance string `json:"provenance"`
}

// Authorization records what a lane needs before it may execute and whether it has it.
type Authorization struct {
	Kind   string `json:"kind"`
	Record string `json:"record,omitempty"`
	Status string `json:"status"`
}

// LegacyEvidence labels captures made before the manifest existed. They are migration evidence, never
// a retroactively preregistered result.
type LegacyEvidence struct {
	Label                   string `json:"label"`
	SourcePath              string `json:"source_path"`
	Cells                   int    `json:"cells"`
	InventoryDigestClaimed  string `json:"inventory_digest_claimed,omitempty"`
	InventoryDigestVerified bool   `json:"inventory_digest_verified"`
}

// Profile is one task family measured one way.
type Profile struct {
	ID                     string          `json:"id"`
	WorkPackages           []string        `json:"work_packages"`
	TaskFamily             string          `json:"task_family"`
	UnitKinds              []string        `json:"unit_kinds"`
	ClosedWorld            bool            `json:"closed_world"`
	Population             Population      `json:"population"`
	SupportedScope         string          `json:"supported_scope"`
	Corpus                 Identity        `json:"corpus"`
	Truth                  Identity        `json:"truth"`
	Scorer                 Identity        `json:"scorer"`
	MatchingPolicy         Identity        `json:"matching_policy"`
	Thresholds             Thresholds      `json:"thresholds"`
	MinimumTruthSupport    Support         `json:"minimum_truth_support"`
	RequiredEnrollment     []Enrollment    `json:"required_enrollment"`
	Disposition            string          `json:"disposition"`
	Trigger                string          `json:"trigger,omitempty"`
	Rationale              string          `json:"rationale,omitempty"`
	ExecutionAuthorization Authorization   `json:"execution_authorization"`
	LegacyEvidence         *LegacyEvidence `json:"legacy_evidence,omitempty"`
}

// ControlSuite is a benchmark self-test with a known expected outcome.
type ControlSuite struct {
	ID                    string `json:"id"`
	Version               string `json:"version"`
	WorkPackage           string `json:"work_package"`
	FixtureDigest         string `json:"fixture_digest"`
	ExpectedOutcomeDigest string `json:"expected_outcome_digest"`
}

// Lane groups profiles that execute under one authorization.
type Lane struct {
	ID                  string   `json:"id"`
	ProfileIDs          []string `json:"profile_ids"`
	Disposition         string   `json:"disposition"`
	AuthorizationStatus string   `json:"authorization_status"`
	ResourceRecord      string   `json:"resource_record,omitempty"`
}

// ErrInvalidManifest is wrapped by every validation failure.
var ErrInvalidManifest = errors.New("invalid closure manifest")

// Validate rejects a manifest that could not bind a result: a generic profile with no concrete corpus,
// truth or scorer digest, a profile with no enrolled engine, a non-required profile without a published
// trigger and rationale, and duplicate ids.
func (m ClosureManifest) Validate() error {
	var problems []string
	if m.SchemaVersion != ManifestSchemaVersion {
		problems = append(problems, fmt.Sprintf("schema_version %q is not %q", m.SchemaVersion, ManifestSchemaVersion))
	}
	if strings.TrimSpace(m.ManifestID) == "" {
		problems = append(problems, "manifest_id is required")
	}
	if m.Revision < 1 {
		problems = append(problems, "revision must be at least 1")
	}
	if m.Revision > 1 && m.Supersedes == nil {
		problems = append(problems, "a revision after the first must name the manifest it supersedes")
	}
	if m.Supersedes != nil && (m.Supersedes.Revision != m.Revision-1 || m.Supersedes.Digest == "") {
		problems = append(problems, "supersedes must name the previous revision and its digest")
	}
	if strings.TrimSpace(m.Claim) == "" {
		problems = append(problems, "claim is required")
	}
	for _, pkg := range []string{"A", "B", "C", "D", "E", "F", "G"} {
		if _, ok := m.WorkPackages[pkg]; !ok {
			problems = append(problems, "work_packages lacks "+pkg)
		}
	}
	if len(m.Profiles) == 0 {
		problems = append(problems, "at least one profile is required")
	}
	profileIDs := map[string]bool{}
	for _, p := range m.Profiles {
		if profileIDs[p.ID] {
			problems = append(problems, "profile "+p.ID+" is listed twice")
		}
		profileIDs[p.ID] = true
		problems = append(problems, p.validate(m.WorkPackages)...)
	}
	suiteIDs := map[string]bool{}
	for _, s := range m.ControlSuites {
		if suiteIDs[s.ID] {
			problems = append(problems, "control suite "+s.ID+" is listed twice")
		}
		suiteIDs[s.ID] = true
		if s.ID == "" || s.Version == "" || s.FixtureDigest == "" || s.ExpectedOutcomeDigest == "" {
			problems = append(problems, "control suite "+s.ID+" needs id, version, fixture_digest and expected_outcome_digest")
		}
	}
	laneIDs := map[string]bool{}
	for _, l := range m.Lanes {
		if laneIDs[l.ID] {
			problems = append(problems, "lane "+l.ID+" is listed twice")
		}
		laneIDs[l.ID] = true
		for _, id := range l.ProfileIDs {
			if !profileIDs[id] {
				problems = append(problems, "lane "+l.ID+" names unknown profile "+id)
			}
		}
		if l.Disposition != DispositionRequired && l.Disposition != DispositionConditional && l.Disposition != DispositionOptional {
			problems = append(problems, "lane "+l.ID+" has disposition "+l.Disposition)
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("%w: %s", ErrInvalidManifest, strings.Join(problems, "; "))
}

func (p Profile) validate(packages map[string]WorkPackage) []string {
	var problems []string
	prefix := "profile " + p.ID + ": "
	if strings.TrimSpace(p.ID) == "" {
		problems = append(problems, "a profile has no id")
	}
	if len(p.WorkPackages) == 0 {
		problems = append(problems, prefix+"names no work package")
	}
	for _, pkg := range p.WorkPackages {
		if _, ok := packages[pkg]; !ok {
			problems = append(problems, prefix+"names unknown work package "+pkg)
		}
	}
	if p.TaskFamily == "" || len(p.UnitKinds) == 0 {
		problems = append(problems, prefix+"needs task_family and unit_kinds")
	}
	kinds := map[string]bool{}
	for _, k := range p.UnitKinds {
		if !canonicalKind(k) {
			problems = append(problems, prefix+"unit kind "+k+" is not lower-case and trimmed")
		}
		kinds[k] = true
	}
	for name, id := range map[string]Identity{"corpus": p.Corpus, "truth": p.Truth, "scorer": p.Scorer, "matching_policy": p.MatchingPolicy} {
		if id.ID == "" || id.Digest == "" {
			problems = append(problems, prefix+name+" needs an id and a digest; a generic declaration is not a frozen input")
		}
	}
	if p.Population.TruthUnits <= 0 || p.Population.Subjects <= 0 {
		problems = append(problems, prefix+"population must state subjects and truth units")
	}
	if p.MinimumTruthSupport.Positives <= 0 || p.MinimumTruthSupport.Rationale == "" {
		problems = append(problems, prefix+"minimum_truth_support needs a positive count and a rationale")
	}
	if len(p.RequiredEnrollment) == 0 {
		problems = append(problems, prefix+"enrolls no engine")
	}
	engines := map[string]bool{}
	for _, e := range p.RequiredEnrollment {
		if e.EngineID == "" || e.AdapterID == "" || e.ScoredComponent.ID == "" {
			problems = append(problems, prefix+"an enrollment needs engine_id, adapter_id and scored_component.id")
		}
		if engines[e.EngineID] {
			problems = append(problems, prefix+"engine "+e.EngineID+" is enrolled twice")
		}
		for _, c := range e.DeclaredCapabilities {
			if !kinds[c] {
				problems = append(problems, prefix+"engine "+e.EngineID+" declares capability "+c+", which is not a unit kind of the profile")
			}
		}
		engines[e.EngineID] = true
	}
	switch p.Disposition {
	case DispositionRequired:
	case DispositionConditional, DispositionOptional:
		if strings.TrimSpace(p.Trigger) == "" || strings.TrimSpace(p.Rationale) == "" {
			problems = append(problems, prefix+p.Disposition+" needs a published trigger and rationale; unavailable access or a poor result is not one")
		}
	default:
		problems = append(problems, prefix+"disposition "+p.Disposition+" is not required, conditional or optional")
	}
	switch p.ExecutionAuthorization.Status {
	case AuthorizationObtained, AuthorizationNotObtained, AuthorizationNone:
	default:
		problems = append(problems, prefix+"execution_authorization.status "+p.ExecutionAuthorization.Status+" is unknown")
	}
	if p.LegacyEvidence != nil && p.LegacyEvidence.Label != "migration/regression" {
		problems = append(problems, prefix+"legacy evidence must be labelled migration/regression")
	}
	return problems
}

// Canonical returns a copy with every order-insensitive slice sorted, so two manifests that differ only
// in list order share a digest.
func (m ClosureManifest) Canonical() ClosureManifest {
	out := m
	out.Profiles = append([]Profile(nil), m.Profiles...)
	for i := range out.Profiles {
		out.Profiles[i] = out.Profiles[i].canonical()
	}
	sort.Slice(out.Profiles, func(i, j int) bool { return out.Profiles[i].ID < out.Profiles[j].ID })
	out.ControlSuites = append([]ControlSuite(nil), m.ControlSuites...)
	sort.Slice(out.ControlSuites, func(i, j int) bool { return out.ControlSuites[i].ID < out.ControlSuites[j].ID })
	out.Lanes = append([]Lane(nil), m.Lanes...)
	for i := range out.Lanes {
		out.Lanes[i].ProfileIDs = sortedStrings(out.Lanes[i].ProfileIDs)
	}
	sort.Slice(out.Lanes, func(i, j int) bool { return out.Lanes[i].ID < out.Lanes[j].ID })
	if m.Supersedes != nil {
		s := *m.Supersedes
		s.Changes = sortedStrings(s.Changes)
		out.Supersedes = &s
	}
	return out
}

func (p Profile) canonical() Profile {
	out := p
	out.WorkPackages = sortedStrings(p.WorkPackages)
	out.UnitKinds = sortedStrings(p.UnitKinds)
	out.RequiredEnrollment = append([]Enrollment(nil), p.RequiredEnrollment...)
	for i := range out.RequiredEnrollment {
		out.RequiredEnrollment[i].DeclaredCapabilities = sortedStrings(out.RequiredEnrollment[i].DeclaredCapabilities)
	}
	sort.Slice(out.RequiredEnrollment, func(i, j int) bool { return out.RequiredEnrollment[i].EngineID < out.RequiredEnrollment[j].EngineID })
	return out
}

// DigestManifest is the manifest's identity: the digest of its canonical JSON.
func DigestManifest(m ClosureManifest) (string, error) {
	encoded, err := benchmark.CanonicalJSON(m.Canonical())
	if err != nil {
		return "", err
	}
	return benchmark.SHA256Digest(encoded), nil
}

// DigestEnrollment freezes a profile's enrolled engines and capabilities; a scorecard carries it so an
// enrollment or capability change after the run is detected.
func DigestEnrollment(p Profile) (string, error) {
	encoded, err := benchmark.CanonicalJSON(p.canonical().RequiredEnrollment)
	if err != nil {
		return "", err
	}
	return benchmark.SHA256Digest(encoded), nil
}

// Profile returns the profile with the given id.
func (m ClosureManifest) Profile(id string) (Profile, bool) {
	for _, p := range m.Profiles {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
