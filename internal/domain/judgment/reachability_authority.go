package judgment

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SuppressionDisposition is the closed policy vocabulary for a reachability result.
type SuppressionDisposition string

const (
	SuppressionEligible   SuppressionDisposition = "eligible"
	SuppressionRaiseOnly  SuppressionDisposition = "raise_only"
	SuppressionProhibited SuppressionDisposition = "prohibited"
)

// Valid reports whether the suppression disposition is known.
func (d SuppressionDisposition) Valid() bool {
	switch d {
	case SuppressionEligible, SuppressionRaiseOnly, SuppressionProhibited:
		return true
	}
	return false
}

// ReachabilityCohort is the closed cohort vocabulary used by the authority policy.
type ReachabilityCohort string

const (
	CohortGo         ReachabilityCohort = "go"
	CohortPython     ReachabilityCohort = "python"
	CohortJavaScript ReachabilityCohort = "javascript"
	CohortRust       ReachabilityCohort = "rust"
	CohortPHP        ReachabilityCohort = "php"
	CohortRuby       ReachabilityCohort = "ruby"
	CohortDotNet     ReachabilityCohort = "dotnet"
	CohortCpp        ReachabilityCohort = "c_cpp"
	CohortJVM        ReachabilityCohort = "jvm"
	CohortRuntime    ReachabilityCohort = "runtime"
)

// ReachabilityMode is the closed mode vocabulary used by the authority policy.
type ReachabilityMode string

const (
	ModeSourceTier2       ReachabilityMode = "source_tier2"
	ModeBinary            ReachabilityMode = "binary"
	ModeImport            ReachabilityMode = "import"
	ModeSemantic          ReachabilityMode = "semantic"
	ModeBuildAwareImport  ReachabilityMode = "build_aware_import"
	ModeLexical           ReachabilityMode = "lexical"
	ModeInterprocedural   ReachabilityMode = "interprocedural"
	ModeSymbolsTier2      ReachabilityMode = "symbols_tier2"
	ModeCoarse            ReachabilityMode = "coarse"
	ModeTier2             ReachabilityMode = "tier2"
	ModeRuntimeLibraryUse ReachabilityMode = "library_loads"
)

// CohortModePolicyKey is one closed reachability cohort and mode pair.
type CohortModePolicyKey struct {
	cohort ReachabilityCohort
	mode   ReachabilityMode
}

// NewCohortModePolicyKey validates a cohort/mode pair against the closed initial
// authority-policy vocabulary.
func NewCohortModePolicyKey(cohort, mode string) (CohortModePolicyKey, error) {
	key := CohortModePolicyKey{cohort: ReachabilityCohort(cohort), mode: ReachabilityMode(mode)}
	if !key.Valid() {
		return CohortModePolicyKey{}, fmt.Errorf("%w: unknown reachability cohort/mode %q/%q", shared.ErrValidation, cohort, mode)
	}
	return key, nil
}

// Cohort returns the policy cohort.
func (k CohortModePolicyKey) Cohort() string { return string(k.cohort) }

// Mode returns the policy mode.
func (k CohortModePolicyKey) Mode() string { return string(k.mode) }

// String returns the canonical cohort/mode form.
func (k CohortModePolicyKey) String() string { return string(k.cohort) + "/" + string(k.mode) }

// Valid reports whether this is one of the closed policy keys.
func (k CohortModePolicyKey) Valid() bool {
	switch k.cohort {
	case CohortGo:
		return k.mode == ModeSourceTier2 || k.mode == ModeBinary
	case CohortPython:
		return k.mode == ModeImport || k.mode == ModeSemantic
	case CohortJavaScript:
		return k.mode == ModeImport || k.mode == ModeLexical || k.mode == ModeInterprocedural
	case CohortRust, CohortPHP, CohortRuby:
		return k.mode == ModeImport || k.mode == ModeSymbolsTier2
	case CohortDotNet:
		return k.mode == ModeBuildAwareImport || k.mode == ModeSymbolsTier2
	case CohortCpp:
		return k.mode == ModeSymbolsTier2
	case CohortJVM:
		return k.mode == ModeCoarse || k.mode == ModeTier2
	case CohortRuntime:
		return k.mode == ModeRuntimeLibraryUse
	}
	return false
}

// SuppressionAuthorityKind is the machine-readable kind of an approval authority.
type SuppressionAuthorityKind string

const SuppressionAuthorityProcedural SuppressionAuthorityKind = "procedural"

// SuppressionAuthority describes the nature of suppression authority. The frozen
// policy is procedural only; it does not claim cryptographic origin authentication.
type SuppressionAuthority struct {
	Kind                SuppressionAuthorityKind
	OriginAuthenticated bool
}

// ProceduralSuppressionAuthority returns the only authority accepted by the
// initial policy registry.
func ProceduralSuppressionAuthority() SuppressionAuthority {
	return SuppressionAuthority{Kind: SuppressionAuthorityProcedural, OriginAuthenticated: false}
}

// Validate reports whether the authority is the expected non-origin-authenticated
// procedural authority.
func (a SuppressionAuthority) Validate() error {
	if a.Kind != SuppressionAuthorityProcedural {
		return fmt.Errorf("%w: suppression authority must be procedural", shared.ErrValidation)
	}
	if a.OriginAuthenticated {
		return fmt.Errorf("%w: suppression authority may not claim origin authentication", shared.ErrValidation)
	}
	return nil
}

// SuppressionApproval binds a completeness contract to the distinct actors that
// may propose and verify a suppression-eligible judgment.
type SuppressionApproval struct {
	proposer  string
	verifier  string
	contract  CompletenessContract
	authority SuppressionAuthority
}

// NewSuppressionApproval validates an approved, distinct proposer/verifier pair.
func NewSuppressionApproval(proposer, verifier string, contract CompletenessContract, authority SuppressionAuthority) (SuppressionApproval, error) {
	approval := SuppressionApproval{
		proposer:  proposer,
		verifier:  verifier,
		contract:  cloneCompletenessContract(contract),
		authority: authority,
	}
	if err := approval.Validate(); err != nil {
		return SuppressionApproval{}, err
	}
	return approval, nil
}

// Proposer returns the approved proposer actor identity.
func (a SuppressionApproval) Proposer() string { return a.proposer }

// Verifier returns the approved verifier actor identity.
func (a SuppressionApproval) Verifier() string { return a.verifier }

// Contract returns the immutable completeness contract.
func (a SuppressionApproval) Contract() CompletenessContract {
	return cloneCompletenessContract(a.contract)
}

// Authority returns the machine-readable authority metadata.
func (a SuppressionApproval) Authority() SuppressionAuthority { return a.authority }

// Validate reports whether the approval itself is well formed.
func (a SuppressionApproval) Validate() error {
	if !validActorIdentity(a.proposer) || !validActorIdentity(a.verifier) {
		return fmt.Errorf("%w: suppression approval requires proposer and verifier identities", shared.ErrValidation)
	}
	if a.proposer == a.verifier {
		return fmt.Errorf("%w: suppression proposer and verifier must differ", shared.ErrValidation)
	}
	if !a.contract.Valid() {
		return fmt.Errorf("%w: suppression approval requires a valid completeness contract", shared.ErrValidation)
	}
	if err := a.authority.Validate(); err != nil {
		return err
	}
	return nil
}

// SuppressionAuthorityRequest is the identity evidence a future consumer must
// supply before using an eligible policy to suppress a finding.
type SuppressionAuthorityRequest struct {
	Snapshot       ReachabilitySnapshotIdentity
	ContractID     string
	ContractDigest string
	Proposer       string
	Verifier       string
	Authority      SuppressionAuthority
}

// ReachabilityAuthorityPolicy is one immutable closed policy entry.
type ReachabilityAuthorityPolicy struct {
	key         CohortModePolicyKey
	disposition SuppressionDisposition
	approval    *SuppressionApproval
}

// NewReachabilityAuthorityPolicy validates a frozen policy entry. Only the four
// initial eligible keys may hold approval metadata; all other keys must carry none.
func NewReachabilityAuthorityPolicy(key CohortModePolicyKey, disposition SuppressionDisposition, approval *SuppressionApproval) (ReachabilityAuthorityPolicy, error) {
	policy := ReachabilityAuthorityPolicy{key: key, disposition: disposition}
	if !key.Valid() {
		return ReachabilityAuthorityPolicy{}, fmt.Errorf("%w: unknown reachability cohort/mode %q", shared.ErrValidation, key.String())
	}
	if !disposition.Valid() {
		return ReachabilityAuthorityPolicy{}, fmt.Errorf("%w: unknown suppression disposition %q", shared.ErrValidation, disposition)
	}
	if disposition != frozenDisposition(key) {
		return ReachabilityAuthorityPolicy{}, fmt.Errorf("%w: suppression disposition for %s does not match the frozen policy", shared.ErrValidation, key)
	}
	if disposition != SuppressionEligible {
		if approval != nil {
			return ReachabilityAuthorityPolicy{}, fmt.Errorf("%w: %s policy may not carry approval metadata", shared.ErrValidation, disposition)
		}
		return policy, nil
	}
	if approval == nil {
		return ReachabilityAuthorityPolicy{}, fmt.Errorf("%w: eligible policy requires approval metadata", shared.ErrValidation)
	}
	if err := approval.Validate(); err != nil {
		return ReachabilityAuthorityPolicy{}, err
	}
	expectedProposer, expectedVerifier, eligible := approvedActorPair(key)
	if !eligible || approval.proposer != expectedProposer || approval.verifier != expectedVerifier {
		return ReachabilityAuthorityPolicy{}, fmt.Errorf("%w: unapproved proposer/verifier pair for %s", shared.ErrValidation, key)
	}
	if err := approval.contract.ValidateFor(requiredCompletenessObligations(key)); err != nil {
		return ReachabilityAuthorityPolicy{}, fmt.Errorf("%w: %s", shared.ErrValidation, err)
	}
	clonedApproval := cloneSuppressionApproval(*approval)
	policy.approval = &clonedApproval
	return policy, nil
}

// Key returns the closed cohort/mode policy key.
func (p ReachabilityAuthorityPolicy) Key() CohortModePolicyKey { return p.key }

// Disposition returns the frozen suppression disposition.
func (p ReachabilityAuthorityPolicy) Disposition() SuppressionDisposition { return p.disposition }

// Approval returns the policy approval metadata only for eligible entries.
func (p ReachabilityAuthorityPolicy) Approval() (SuppressionApproval, bool) {
	if p.approval == nil {
		return SuppressionApproval{}, false
	}
	return cloneSuppressionApproval(*p.approval), true
}

// ValidateSuppression fails closed unless the request snapshot equals the
// independently resolved active snapshot, and all other frozen authority evidence
// matches this eligible policy.
func (p ReachabilityAuthorityPolicy) ValidateSuppression(active ReachabilitySnapshotIdentity, request SuppressionAuthorityRequest) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.disposition != SuppressionEligible || p.approval == nil {
		return fmt.Errorf("%w: %s is not suppression eligible", shared.ErrForbidden, p.key)
	}
	if err := request.Snapshot.ValidateMatch(active); err != nil {
		return err
	}
	if !p.approval.contract.Matches(request.ContractID, request.ContractDigest) {
		return fmt.Errorf("%w: stale or mismatched completeness contract identity", shared.ErrValidation)
	}
	if request.Proposer != p.approval.proposer || request.Verifier != p.approval.verifier {
		return fmt.Errorf("%w: unapproved suppression proposer/verifier pair", shared.ErrForbidden)
	}
	if request.Authority != p.approval.authority {
		return fmt.Errorf("%w: suppression authority does not match frozen policy metadata", shared.ErrForbidden)
	}
	if err := request.Authority.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate reports whether the frozen entry is structurally valid.
func (p ReachabilityAuthorityPolicy) Validate() error {
	if !p.key.Valid() || !p.disposition.Valid() || p.disposition != frozenDisposition(p.key) {
		return fmt.Errorf("%w: invalid frozen reachability authority policy", shared.ErrValidation)
	}
	if p.disposition == SuppressionEligible {
		if p.approval == nil {
			return fmt.Errorf("%w: eligible policy lacks approval metadata", shared.ErrValidation)
		}
		if err := p.approval.Validate(); err != nil {
			return err
		}
		expectedProposer, expectedVerifier, eligible := approvedActorPair(p.key)
		if !eligible || p.approval.proposer != expectedProposer || p.approval.verifier != expectedVerifier {
			return fmt.Errorf("%w: unapproved proposer/verifier pair for %s", shared.ErrValidation, p.key)
		}
		return p.approval.contract.ValidateFor(requiredCompletenessObligations(p.key))
	}
	if p.approval != nil {
		return fmt.Errorf("%w: non-eligible policy carries approval metadata", shared.ErrValidation)
	}
	return nil
}

// ReachabilityAuthorityRegistry is an immutable registry of every initial
// reachability cohort/mode policy.
type ReachabilityAuthorityRegistry struct {
	policies map[CohortModePolicyKey]ReachabilityAuthorityPolicy
	ordered  []ReachabilityAuthorityPolicy
}

// NewReachabilityAuthorityRegistry validates exact, duplicate-free coverage of the
// closed initial cohort/mode inventory.
func NewReachabilityAuthorityRegistry(entries []ReachabilityAuthorityPolicy) (ReachabilityAuthorityRegistry, error) {
	if len(entries) != len(initialPolicyKeys()) {
		return ReachabilityAuthorityRegistry{}, fmt.Errorf("%w: reachability authority registry requires exact closed coverage", shared.ErrValidation)
	}
	policies := make(map[CohortModePolicyKey]ReachabilityAuthorityPolicy, len(entries))
	ordered := make([]ReachabilityAuthorityPolicy, 0, len(entries))
	for _, entry := range entries {
		if !entry.key.Valid() {
			return ReachabilityAuthorityRegistry{}, fmt.Errorf("%w: unknown reachability authority key %q", shared.ErrValidation, entry.key)
		}
		if _, exists := policies[entry.key]; exists {
			return ReachabilityAuthorityRegistry{}, fmt.Errorf("%w: duplicate reachability authority key %q", shared.ErrValidation, entry.key)
		}
		if err := entry.Validate(); err != nil {
			return ReachabilityAuthorityRegistry{}, err
		}
		clonedEntry := cloneReachabilityAuthorityPolicy(entry)
		policies[clonedEntry.key] = clonedEntry
		ordered = append(ordered, clonedEntry)
	}
	for _, key := range initialPolicyKeys() {
		if _, exists := policies[key]; !exists {
			return ReachabilityAuthorityRegistry{}, fmt.Errorf("%w: missing reachability authority key %q", shared.ErrValidation, key)
		}
	}
	return ReachabilityAuthorityRegistry{policies: policies, ordered: ordered}, nil
}

// NewInitialReachabilityAuthorityRegistry returns the complete immutable initial
// authority policy. It contains no mutable package-level registry state.
func NewInitialReachabilityAuthorityRegistry() (ReachabilityAuthorityRegistry, error) {
	entries := make([]ReachabilityAuthorityPolicy, 0, len(initialPolicyKeys()))
	for _, key := range initialPolicyKeys() {
		disposition := frozenDisposition(key)
		var approval *SuppressionApproval
		if disposition == SuppressionEligible {
			contract, err := initialCompletenessContract(key)
			if err != nil {
				return ReachabilityAuthorityRegistry{}, err
			}
			proposer, verifier, _ := approvedActorPair(key)
			created, err := NewSuppressionApproval(proposer, verifier, contract, ProceduralSuppressionAuthority())
			if err != nil {
				return ReachabilityAuthorityRegistry{}, err
			}
			approval = &created
		}
		entry, err := NewReachabilityAuthorityPolicy(key, disposition, approval)
		if err != nil {
			return ReachabilityAuthorityRegistry{}, err
		}
		entries = append(entries, entry)
	}
	return NewReachabilityAuthorityRegistry(entries)
}

// Lookup finds a frozen authority policy by its cohort and mode, rejecting unknown
// pairs before any policy can be considered.
func (r ReachabilityAuthorityRegistry) Lookup(cohort, mode string) (ReachabilityAuthorityPolicy, error) {
	key, err := NewCohortModePolicyKey(cohort, mode)
	if err != nil {
		return ReachabilityAuthorityPolicy{}, err
	}
	return r.LookupKey(key)
}

// LookupKey finds a frozen authority policy by a validated closed key.
func (r ReachabilityAuthorityRegistry) LookupKey(key CohortModePolicyKey) (ReachabilityAuthorityPolicy, error) {
	if !key.Valid() {
		return ReachabilityAuthorityPolicy{}, fmt.Errorf("%w: unknown reachability cohort/mode %q", shared.ErrValidation, key)
	}
	if err := r.Validate(); err != nil {
		return ReachabilityAuthorityPolicy{}, err
	}
	policy, exists := r.policies[key]
	if !exists {
		return ReachabilityAuthorityPolicy{}, fmt.Errorf("%w: reachability authority policy %q", shared.ErrNotFound, key)
	}
	return cloneReachabilityAuthorityPolicy(policy), nil
}

// Policies returns an ordered copy of all frozen policy entries.
func (r ReachabilityAuthorityRegistry) Policies() []ReachabilityAuthorityPolicy {
	entries := make([]ReachabilityAuthorityPolicy, len(r.ordered))
	for index, entry := range r.ordered {
		entries[index] = cloneReachabilityAuthorityPolicy(entry)
	}
	return entries
}

// ValidateSuppression checks a future consumer's request against the frozen policy
// and an independently resolved active source/SBOM/run snapshot.
func (r ReachabilityAuthorityRegistry) ValidateSuppression(cohort, mode string, active ReachabilitySnapshotIdentity, request SuppressionAuthorityRequest) error {
	policy, err := r.Lookup(cohort, mode)
	if err != nil {
		return err
	}
	return policy.ValidateSuppression(active, request)
}

// Validate reports whether this registry retains complete, exact frozen coverage.
func (r ReachabilityAuthorityRegistry) Validate() error {
	if len(r.policies) != len(initialPolicyKeys()) || len(r.ordered) != len(initialPolicyKeys()) {
		return fmt.Errorf("%w: incomplete reachability authority registry", shared.ErrValidation)
	}
	for _, key := range initialPolicyKeys() {
		policy, exists := r.policies[key]
		if !exists {
			return fmt.Errorf("%w: missing reachability authority key %q", shared.ErrValidation, key)
		}
		if err := policy.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func initialPolicyKeys() []CohortModePolicyKey {
	return []CohortModePolicyKey{
		{cohort: CohortGo, mode: ModeSourceTier2},
		{cohort: CohortGo, mode: ModeBinary},
		{cohort: CohortPython, mode: ModeImport},
		{cohort: CohortPython, mode: ModeSemantic},
		{cohort: CohortDotNet, mode: ModeBuildAwareImport},
		{cohort: CohortRust, mode: ModeImport},
		{cohort: CohortRuby, mode: ModeImport},
		{cohort: CohortJavaScript, mode: ModeImport},
		{cohort: CohortJavaScript, mode: ModeLexical},
		{cohort: CohortJavaScript, mode: ModeInterprocedural},
		{cohort: CohortRust, mode: ModeSymbolsTier2},
		{cohort: CohortPHP, mode: ModeImport},
		{cohort: CohortPHP, mode: ModeSymbolsTier2},
		{cohort: CohortRuby, mode: ModeSymbolsTier2},
		{cohort: CohortDotNet, mode: ModeSymbolsTier2},
		{cohort: CohortCpp, mode: ModeSymbolsTier2},
		{cohort: CohortJVM, mode: ModeCoarse},
		{cohort: CohortJVM, mode: ModeTier2},
		{cohort: CohortRuntime, mode: ModeRuntimeLibraryUse},
	}
}

func frozenDisposition(key CohortModePolicyKey) SuppressionDisposition {
	switch key {
	case CohortModePolicyKey{cohort: CohortGo, mode: ModeSourceTier2},
		CohortModePolicyKey{cohort: CohortPython, mode: ModeImport},
		CohortModePolicyKey{cohort: CohortPython, mode: ModeSemantic},
		CohortModePolicyKey{cohort: CohortDotNet, mode: ModeBuildAwareImport}:
		return SuppressionEligible
	case CohortModePolicyKey{cohort: CohortRust, mode: ModeImport},
		CohortModePolicyKey{cohort: CohortRuby, mode: ModeImport}:
		return SuppressionProhibited
	default:
		return SuppressionRaiseOnly
	}
}

func approvedActorPair(key CohortModePolicyKey) (string, string, bool) {
	switch key {
	case CohortModePolicyKey{cohort: CohortGo, mode: ModeSourceTier2}:
		return ProofActorCallgraphScan, ProofActorCallgraphEngine, true
	case CohortModePolicyKey{cohort: CohortPython, mode: ModeImport}:
		return ProofActorPyImportScan, ProofActorPyImportEngine, true
	case CohortModePolicyKey{cohort: CohortPython, mode: ModeSemantic}:
		return ProofActorPySemanticScan, ProofActorPySemanticEngine, true
	case CohortModePolicyKey{cohort: CohortDotNet, mode: ModeBuildAwareImport}:
		return ProofActorDotNetReachScan, ProofActorDotNetReachEngine, true
	default:
		return "", "", false
	}
}

func requiredCompletenessObligations(key CohortModePolicyKey) []CompletenessObligation {
	if frozenDisposition(key) != SuppressionEligible {
		return nil
	}
	return []CompletenessObligation{
		ObligationEnumeration,
		ObligationEntrypoints,
		ObligationOpaqueSurface,
		ObligationRuntimeInputs,
		ObligationDeployInputs,
	}
}

func initialCompletenessContract(key CohortModePolicyKey) (CompletenessContract, error) {
	switch key {
	case CohortModePolicyKey{cohort: CohortGo, mode: ModeSourceTier2}:
		return NewCompletenessContract(CompletenessContractDefinition{
			ID:               "go-source-tier2-completeness-v1",
			ReviewerRole:     "go-callgraph-verifier",
			Enumeration:      []string{"go-module-and-package-enumeration"},
			Entrypoints:      []string{"go-main-and-test-entrypoint-enumeration"},
			OpaqueSurface:    []string{"go-reflection-and-plugin-surface-accounting"},
			RuntimeInputs:    []string{"go-runtime-input-unavailability-makes-proof-incomplete"},
			DeploymentInputs: []string{"go-deployment-input-unavailability-makes-proof-incomplete"},
		})
	case CohortModePolicyKey{cohort: CohortPython, mode: ModeImport}:
		return NewCompletenessContract(CompletenessContractDefinition{
			ID:               "python-import-completeness-v1",
			ReviewerRole:     "python-import-verifier",
			Enumeration:      []string{"python-distribution-and-import-root-enumeration"},
			Entrypoints:      []string{"python-application-entrypoint-enumeration"},
			OpaqueSurface:    []string{"python-dynamic-import-and-plugin-surface-accounting"},
			RuntimeInputs:    []string{"python-runtime-input-unavailability-makes-proof-incomplete"},
			DeploymentInputs: []string{"python-deployment-input-unavailability-makes-proof-incomplete"},
		})
	case CohortModePolicyKey{cohort: CohortPython, mode: ModeSemantic}:
		return NewCompletenessContract(CompletenessContractDefinition{
			ID:               "python-semantic-completeness-v1",
			ReviewerRole:     "python-semantic-verifier",
			Enumeration:      []string{"python-distribution-and-module-enumeration"},
			Entrypoints:      []string{"python-application-entrypoint-enumeration"},
			OpaqueSurface:    []string{"python-dynamic-dispatch-and-import-surface-accounting"},
			RuntimeInputs:    []string{"python-runtime-input-unavailability-makes-proof-incomplete"},
			DeploymentInputs: []string{"python-deployment-input-unavailability-makes-proof-incomplete"},
		})
	case CohortModePolicyKey{cohort: CohortDotNet, mode: ModeBuildAwareImport}:
		return NewCompletenessContract(CompletenessContractDefinition{
			ID:               "dotnet-build-aware-import-completeness-v1",
			ReviewerRole:     "dotnet-build-aware-verifier",
			Enumeration:      []string{"dotnet-restore-graph-and-assembly-enumeration"},
			Entrypoints:      []string{"dotnet-application-entrypoint-enumeration"},
			OpaqueSurface:    []string{"dotnet-reflection-and-dynamic-surface-accounting"},
			RuntimeInputs:    []string{"dotnet-runtime-input-unavailability-makes-proof-incomplete"},
			DeploymentInputs: []string{"dotnet-deployment-input-unavailability-makes-proof-incomplete"},
		})
	default:
		return CompletenessContract{}, fmt.Errorf("%w: %s has no suppression completeness contract", shared.ErrValidation, key)
	}
}

func cloneReachabilityAuthorityPolicy(policy ReachabilityAuthorityPolicy) ReachabilityAuthorityPolicy {
	cloned := ReachabilityAuthorityPolicy{key: policy.key, disposition: policy.disposition}
	if policy.approval != nil {
		approval := cloneSuppressionApproval(*policy.approval)
		cloned.approval = &approval
	}
	return cloned
}

func cloneSuppressionApproval(approval SuppressionApproval) SuppressionApproval {
	return SuppressionApproval{
		proposer:  approval.proposer,
		verifier:  approval.verifier,
		contract:  cloneCompletenessContract(approval.contract),
		authority: approval.authority,
	}
}

func validActorIdentity(actor string) bool {
	return actor != "" && actor == strings.TrimSpace(actor) && len(actor) <= 128
}
