package reachbench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

const (
	authorityBundleDirectory     = "trusted-bundle"
	authorityEnvelopeDirectory   = "envelopes"
	authoritySupportingDirectory = "authority"

	authorityAllowlistResultPath = authoritySupportingDirectory + "/baseline-allowlist-result.json"
	authorityBaselineReportPath  = authoritySupportingDirectory + "/baseline-report.json"
	authorityCheckpointPath      = authoritySupportingDirectory + "/baseline-checkpoint.json"
	authorityRatchetPath         = authoritySupportingDirectory + "/candidate-ratchet.json"
	authorityLifecyclePath       = authoritySupportingDirectory + "/baseline-lifecycle-manifest.json"
	authorityRepeatPath          = authoritySupportingDirectory + "/baseline-semantic-repeat.json"
	authorityReviewEvidencePath  = authoritySupportingDirectory + "/baseline-review-evidence.json"
	authorityDispositionPath     = authoritySupportingDirectory + "/baseline-disposition-evidence.json"
	authorityProvenancePath      = authoritySupportingDirectory + "/candidate-assets-provenance.json"

	baselineReviewEvidenceSchema = "synapse-reachability-baseline-review-evidence-v1"
	baselineDispositionSchema    = "synapse-reachability-baseline-disposition-evidence-v1"
	candidateProvenanceSchema    = "synapse-reachability-candidate-assets-provenance-v1"
	authorityControllerID        = "reachability-authority-curator"
)

// AuthorityCuratorDependencies provides the process boundary used to derive
// trusted checkout facts. Command receives one executable and its argv values;
// it must not invoke a shell.
type AuthorityCuratorDependencies struct {
	Command CommandRunner
}

// DefaultAuthorityCuratorDependencies provides the host-backed, argv-only Git
// command runner for the authority curator.
func DefaultAuthorityCuratorDependencies() AuthorityCuratorDependencies {
	return AuthorityCuratorDependencies{Command: runAuthorityGit}
}

// AuthorityCurator derives unsigned controller material from reviewed evidence
// and existing sanitized baseline publication artifacts. External provisioners
// add trust policy and detached signatures; this curator never approves or signs.
type AuthorityCurator struct {
	command          CommandRunner
	baselineRevision string
}

// authorityGitInvocation neutralizes configuration that could execute a program
// or alter the objects and worktree observed by the curator. The checkout's
// local and worktree configuration is then rejected before curation proceeds.
func authorityGitInvocation(root string, args ...string) []string {
	invocation := make([]string, 0, len(args)+31)
	invocation = append(invocation,
		"--no-pager",
		"--no-replace-objects",
		"-c", "core.fsmonitor=false",
		"-c", "core.hooksPath="+os.DevNull,
		"-c", "core.worktree=",
		"-c", "extensions.worktreeConfig=false",
		"-c", "diff.external=",
		"-c", "diff.trustExitCode=false",
		"-c", "merge.tool=",
		"-c", "merge.guitool=",
		"-c", "core.pager=cat",
		"-c", "credential.helper=",
		"-c", "core.alternateRefsCommand=",
		"-c", "core.alternateRefsPrefixes=",
	)
	if root != "" {
		invocation = append(invocation, "-C", root)
	}
	return append(invocation, args...)
}

// NewAuthorityCurator validates the process dependency used for local Git
// inspection.
func NewAuthorityCurator(dependencies AuthorityCuratorDependencies) (*AuthorityCurator, error) {
	return newAuthorityCurator(dependencies, measurement.TrustedBaselineRevision)
}

func newAuthorityCurator(dependencies AuthorityCuratorDependencies, baselineRevision string) (*AuthorityCurator, error) {
	if dependencies.Command == nil {
		return nil, errors.New("reachability authority curator requires a command runner")
	}
	if !benchcycle.FullSHA(baselineRevision) {
		return nil, errors.New("reachability authority curator requires a fixed baseline revision")
	}
	return &AuthorityCurator{command: dependencies.Command, baselineRevision: baselineRevision}, nil
}

// PrepareBaselineAuthority is the host-backed protected-baseline authority
// operation used by the curator command.
func PrepareBaselineAuthority(ctx context.Context, reviewEvidencePath, outputDirectory string) error {
	curator, err := NewAuthorityCurator(DefaultAuthorityCuratorDependencies())
	if err != nil {
		return err
	}
	return curator.PrepareBaseline(ctx, reviewEvidencePath, outputDirectory)
}

// DeriveCandidateAuthority derives commit-ready candidate authority assets from
// a validated protected-baseline publication. It deliberately creates no
// candidate envelope because that envelope must bind the later final checkout.
func DeriveCandidateAuthority(ctx context.Context, baselinePublicationDirectory, baselineAuthorityDirectory, reviewEvidencePath, dispositionEvidencePath, outputDirectory string) error {
	curator, err := NewAuthorityCurator(DefaultAuthorityCuratorDependencies())
	if err != nil {
		return err
	}
	return curator.DeriveCandidate(ctx, baselinePublicationDirectory, baselineAuthorityDirectory, reviewEvidencePath, dispositionEvidencePath, outputDirectory)
}

// PrepareCandidateAuthority stages a final-HEAD-bound controller from the fixed
// candidate authority path committed in the inspected pristine checkout.
func PrepareCandidateAuthority(ctx context.Context, outputDirectory string) error {
	curator, err := NewAuthorityCurator(DefaultAuthorityCuratorDependencies())
	if err != nil {
		return err
	}
	return curator.PrepareCandidate(ctx, outputDirectory)
}

// PrepareBaseline derives unsigned protected-baseline controller material from
// the current full, pristine checkout and one reviewed evidence artifact. It
// only validates, canonicalizes, references, and stages evidence; external
// detached signatures are required before the route is authoritative.
func (curator *AuthorityCurator) PrepareBaseline(ctx context.Context, reviewEvidencePath, outputDirectory string) error {
	checkout, err := curator.inspectCheckout(ctx)
	if err != nil {
		return err
	}
	reviewEvidence, err := readBaselineReviewEvidence(ctx, reviewEvidencePath)
	if err != nil {
		return fmt.Errorf("read reviewed baseline evidence: %w", err)
	}
	diff, err := curator.git(ctx, checkout.root, "diff", "--no-ext-diff", "--no-textconv", "--name-status", "--no-renames", "-z", curator.baselineRevision+"..."+checkout.harness.Commit)
	if err != nil {
		return fmt.Errorf("derive baseline harness delta with git argv: %w", err)
	}
	allowlist, err := BuildBaselineAllowlist("reviewed-harness-delta", diff)
	if err != nil {
		return err
	}
	if err := validateBaselineReviewBinding(reviewEvidence.Document, checkout, diff, allowlist); err != nil {
		return err
	}
	assets, err := BuildProtectedBaselineControllerAssets(allowlist, checkout.harness, checkout.baselineAnalyzer, authorityControllerID, reviewEvidence.Reference)
	if err != nil {
		return fmt.Errorf("build protected baseline authority assets: %w", err)
	}
	return curator.publishAuthority(ctx, outputDirectory, []string{checkout.root}, []authorityAsset{
		{path: authorityBundleDirectory + "/baseline-input.json", body: assets.BaselineInputJSON},
		{path: authorityBundleDirectory + "/baseline-allowlist.json", body: assets.BaselineAllowlistJSON},
		{path: authorityBundleDirectory + "/trusted-bundle.json", body: assets.TrustedBundleJSON},
		{path: authorityReviewEvidencePath, body: reviewEvidence.File},
		{path: authorityEnvelopeDirectory + "/" + assets.EnvelopeFileName, body: assets.EnvelopeJSON},
	}, func(cleanupCtx context.Context) error {
		return curator.revalidateCheckout(cleanupCtx, checkout)
	}, func(verifyCtx context.Context, stage string) error {
		return validateStagedBaselineAuthority(verifyCtx, stage, assets, reviewEvidence)
	})
}

// DeriveCandidate builds unsigned, commit-ready candidate authority assets from
// a fully validated baseline publication, its generated baseline authority root,
// and canonical evidence. It intentionally has no final-checkout dependency and
// therefore cannot emit a candidate envelope or approval.
func (curator *AuthorityCurator) DeriveCandidate(ctx context.Context, baselinePublicationDirectory, baselineAuthorityDirectory, reviewEvidencePath, dispositionEvidencePath, outputDirectory string) error {
	publication, err := loadPublishedBaseline(ctx, baselinePublicationDirectory)
	if err != nil {
		return err
	}
	allowlist, err := loadOriginalBaselineAllowlist(ctx, baselineAuthorityDirectory, publication.manifest)
	if err != nil {
		return err
	}
	reviewEvidence, err := readBaselineReviewEvidence(ctx, reviewEvidencePath)
	if err != nil {
		return fmt.Errorf("read reviewed candidate evidence: %w", err)
	}
	if publication.manifest.Authority.ReviewEvidence != reviewEvidence.Reference {
		return errors.New("candidate review evidence does not match the published baseline manifest")
	}
	dispositionEvidence, err := readBaselineDispositionEvidence(ctx, dispositionEvidencePath)
	if err != nil {
		return fmt.Errorf("read reviewed candidate disposition evidence: %w", err)
	}
	if err := validateBaselineDispositionBinding(dispositionEvidence.Document, publication); err != nil {
		return err
	}
	if reviewEvidence.Reference == dispositionEvidence.Reference || reviewEvidence.Reference.Digest == dispositionEvidence.Reference.Digest {
		return errors.New("candidate review and disposition evidence must be independent")
	}
	assets, err := BuildCandidateControllerAssets(
		publication.report,
		publication.manifest,
		publication.allowlistResult,
		allowlist,
		reviewEvidence.Reference,
		dispositionEvidence.Reference,
		CheckpointActors{
			Producer:   dispositionEvidence.Document.Producer,
			Reviewer:   dispositionEvidence.Document.Reviewer,
			Maintainer: dispositionEvidence.Document.Maintainer,
		},
	)
	if err != nil {
		return fmt.Errorf("build candidate authority assets: %w", err)
	}
	provenance, provenanceJSON, err := buildCandidateAssetsProvenance(publication.manifest, publication.repeat, assets, reviewEvidence.Reference, dispositionEvidence.Reference)
	if err != nil {
		return err
	}
	return curator.publishAuthority(ctx, outputDirectory, []string{publication.root, baselineAuthorityDirectory}, []authorityAsset{
		{path: "baseline-input.json", body: assets.BaselineInputJSON},
		{path: "candidate-input.json", body: assets.CandidateInputJSON},
		{path: "baseline-allowlist.json", body: assets.BaselineAllowlistJSON},
		{path: "trusted-bundle.json", body: assets.TrustedBundleJSON},
		{path: authorityAllowlistResultPath, body: assets.BaselineAllowlistResultJSON},
		{path: authorityBaselineReportPath, body: assets.BaselineReportJSON},
		{path: authorityCheckpointPath, body: assets.CheckpointJSON},
		{path: authorityRatchetPath, body: assets.RatchetJSON},
		{path: authorityLifecyclePath, body: publication.manifestJSON},
		{path: authorityRepeatPath, body: publication.repeatJSON},
		{path: authorityReviewEvidencePath, body: reviewEvidence.File},
		{path: authorityDispositionPath, body: dispositionEvidence.File},
		{path: authorityProvenancePath, body: provenanceJSON},
	}, func(context.Context) error {
		return nil
	}, func(verifyCtx context.Context, stage string) error {
		return validateStagedCandidateAuthority(verifyCtx, stage, assets, publication, provenance, reviewEvidence, dispositionEvidence)
	})
}

// PrepareCandidate validates the fixed, committed candidate authority source,
// reproduces its controller bundle, stages unsigned review subjects and baseline
// evidence, and binds its envelope to the exact pristine final HEAD. It cannot
// create authority until an external provisioner adds detached signatures.
func (curator *AuthorityCurator) PrepareCandidate(ctx context.Context, outputDirectory string) error {
	checkout, err := curator.inspectCheckout(ctx)
	if err != nil {
		return err
	}
	authority, err := curator.loadCommittedCandidateAuthority(ctx, checkout)
	if err != nil {
		return err
	}
	candidateReview, candidateReviewJSON, candidateReviewRef, err := buildCandidateReviewSubject(authority, checkout.harness)
	if err != nil {
		return fmt.Errorf("build final candidate review subject: %w", err)
	}
	envelope, envelopeFileName, envelopeJSON, _, err := BuildCandidateControllerEnvelope(authority.assets, checkout.harness, authorityControllerID, candidateReviewRef)
	if err != nil {
		return fmt.Errorf("build final candidate controller envelope: %w", err)
	}
	return curator.publishAuthority(ctx, outputDirectory, []string{checkout.root}, []authorityAsset{
		{path: authorityBundleDirectory + "/baseline-input.json", body: authority.baselineInputFile},
		{path: authorityBundleDirectory + "/candidate-input.json", body: authority.candidateInputFile},
		{path: authorityBundleDirectory + "/baseline-allowlist.json", body: authority.baselineAllowlistFile},
		{path: authorityBundleDirectory + "/trusted-bundle.json", body: authority.bundleFile},
		{path: authorityReviewEvidencePath, body: authority.reviewEvidence.File},
		{path: authorityDispositionPath, body: authority.dispositionEvidence.File},
		{path: controllerCandidateReviewSubjectPath, body: candidateReviewJSON},
		{path: authorityEnvelopeDirectory + "/" + envelopeFileName, body: envelopeJSON},
	}, func(cleanupCtx context.Context) error {
		if err := curator.revalidateCheckout(cleanupCtx, checkout); err != nil {
			return err
		}
		currentAuthority, err := curator.loadCommittedCandidateAuthority(cleanupCtx, checkout)
		if err != nil {
			return err
		}
		if !sameCandidateAuthority(authority, currentAuthority) {
			return errors.New("committed candidate authority changed before publication")
		}
		return nil
	}, func(verifyCtx context.Context, stage string) error {
		return validatePreparedCandidateController(verifyCtx, stage, authority, candidateReview, envelope, envelopeFileName)
	})
}

type authorityCheckout struct {
	root             string
	harness          HarnessIdentity
	baselineAnalyzer RevisionIdentity
}

func (curator *AuthorityCurator) inspectCheckout(ctx context.Context) (authorityCheckout, error) {
	gitDirectoryOutput, err := curator.command(ctx, "git", authorityGitInvocation("", "rev-parse", "--absolute-git-dir")...)
	if err != nil {
		return authorityCheckout{}, fmt.Errorf("derive repository Git directory with git argv: %w", err)
	}
	gitDirectory, err := benchcycle.RealDirectory(strings.TrimSpace(string(gitDirectoryOutput)))
	if err != nil {
		return authorityCheckout{}, fmt.Errorf("validate repository Git directory: %w", err)
	}
	if err := curator.assertSafeGitConfiguration(ctx, gitDirectory); err != nil {
		return authorityCheckout{}, err
	}
	rootOutput, err := curator.command(ctx, "git", authorityGitInvocation("", "rev-parse", "--show-toplevel")...)
	if err != nil {
		return authorityCheckout{}, fmt.Errorf("derive repository root with git argv: %w", err)
	}
	root, err := benchcycle.RealDirectory(strings.TrimSpace(string(rootOutput)))
	if err != nil {
		return authorityCheckout{}, fmt.Errorf("validate repository root: %w", err)
	}
	if err := curator.assertCapturedGitDirectory(ctx, root, gitDirectory); err != nil {
		return authorityCheckout{}, err
	}
	if err := curator.assertNoReplacementRefs(ctx, root); err != nil {
		return authorityCheckout{}, err
	}
	status, err := curator.git(ctx, root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching")
	if err != nil {
		return authorityCheckout{}, fmt.Errorf("check authoritative checkout with git argv: %w", err)
	}
	if len(status) != 0 {
		return authorityCheckout{}, errors.New("authority curator requires a pristine checkout without tracked, untracked, or ignored residue")
	}
	shallow, err := curator.git(ctx, root, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return authorityCheckout{}, fmt.Errorf("inspect checkout shallow state with git argv: %w", err)
	}
	if strings.TrimSpace(string(shallow)) != "false" {
		return authorityCheckout{}, errors.New("authority curator requires complete non-shallow Git history")
	}
	harnessCommit, err := curator.gitSHA(ctx, root, "HEAD^{commit}")
	if err != nil {
		return authorityCheckout{}, fmt.Errorf("derive harness commit: %w", err)
	}
	harnessTree, err := curator.gitSHA(ctx, root, harnessCommit+"^{tree}")
	if err != nil {
		return authorityCheckout{}, fmt.Errorf("derive harness tree: %w", err)
	}
	baselineCommit, err := curator.gitSHA(ctx, root, curator.baselineRevision+"^{commit}")
	if err != nil {
		return authorityCheckout{}, fmt.Errorf("derive fixed baseline analyzer commit: %w", err)
	}
	if baselineCommit != curator.baselineRevision {
		return authorityCheckout{}, errors.New("derived baseline analyzer commit does not match the fixed trusted revision")
	}
	baselineTree, err := curator.gitSHA(ctx, root, curator.baselineRevision+"^{tree}")
	if err != nil {
		return authorityCheckout{}, fmt.Errorf("derive fixed baseline analyzer tree: %w", err)
	}
	if _, err := curator.git(ctx, root, "merge-base", "--is-ancestor", curator.baselineRevision, harnessCommit); err != nil {
		return authorityCheckout{}, fmt.Errorf("verify fixed baseline ancestry with git argv: %w", err)
	}
	harness := HarnessIdentity{ID: ReviewedHarnessID, Commit: harnessCommit, Tree: harnessTree}
	if err := validateHarness(harness); err != nil {
		return authorityCheckout{}, err
	}
	baselineAnalyzer := RevisionIdentity{ID: AnalyzerSubjectID, Commit: baselineCommit, Tree: baselineTree}
	if err := validateRevision(baselineAnalyzer); err != nil {
		return authorityCheckout{}, err
	}
	return authorityCheckout{root: root, harness: harness, baselineAnalyzer: baselineAnalyzer}, nil
}

func (curator *AuthorityCurator) git(ctx context.Context, root string, args ...string) ([]byte, error) {
	return curator.command(ctx, "git", authorityGitInvocation(root, args...)...)
}

func (curator *AuthorityCurator) assertSafeGitConfiguration(ctx context.Context, gitDirectory string) error {
	configPaths, err := authorityGitConfigurationPaths(gitDirectory)
	if err != nil {
		return err
	}
	for _, configPath := range configPaths {
		info, err := os.Lstat(configPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect Git configuration file: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("authority curator rejects non-regular Git configuration files")
		}
		configured, err := curator.command(ctx, "git", authorityGitInvocation("", "config", "--file", configPath, "--null", "--name-only", "--no-includes", "--list")...)
		if err != nil {
			return fmt.Errorf("inspect repository Git configuration: %w", err)
		}
		for _, entry := range bytes.Split(configured, []byte{0}) {
			key := strings.ToLower(string(entry))
			if key == "" {
				continue
			}
			if unsafeAuthorityGitConfig(key) {
				return fmt.Errorf("authority curator rejects unsafe Git configuration %q", key)
			}
		}
	}
	return nil
}

func authorityGitConfigurationPaths(gitDirectory string) ([]string, error) {
	commonDirectory := gitDirectory
	commonPointer := filepath.Join(gitDirectory, "commondir")
	info, err := os.Lstat(commonPointer)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 4096 {
			return nil, errors.New("authority curator rejects an invalid Git common-directory pointer")
		}
		body, readErr := os.ReadFile(commonPointer)
		if readErr != nil {
			return nil, fmt.Errorf("read Git common-directory pointer: %w", readErr)
		}
		candidate := strings.TrimSpace(string(body))
		if candidate == "" {
			return nil, errors.New("git common-directory pointer is empty")
		}
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(gitDirectory, candidate)
		}
		commonDirectory, err = benchcycle.RealDirectory(candidate)
		if err != nil {
			return nil, fmt.Errorf("validate Git common directory: %w", err)
		}
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("inspect Git common-directory pointer: %w", err)
	}
	paths := []string{filepath.Join(commonDirectory, "config")}
	worktreeConfig := filepath.Join(gitDirectory, "config.worktree")
	if filepath.Clean(worktreeConfig) != filepath.Clean(paths[0]) {
		paths = append(paths, worktreeConfig)
	}
	return paths, nil
}

func (curator *AuthorityCurator) assertCapturedGitDirectory(ctx context.Context, root, captured string) error {
	output, err := curator.git(ctx, root, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return fmt.Errorf("rederive repository Git directory: %w", err)
	}
	current, err := benchcycle.RealDirectory(strings.TrimSpace(string(output)))
	if err != nil {
		return fmt.Errorf("validate rederived repository Git directory: %w", err)
	}
	capturedInfo, err := os.Stat(captured)
	if err != nil {
		return fmt.Errorf("inspect captured repository Git directory: %w", err)
	}
	currentInfo, err := os.Stat(current)
	if err != nil {
		return fmt.Errorf("inspect rederived repository Git directory: %w", err)
	}
	if !os.SameFile(capturedInfo, currentInfo) {
		return errors.New("repository Git directory changed during authority inspection")
	}
	return nil
}

func unsafeAuthorityGitConfig(key string) bool {
	switch key {
	case "include.path", "core.fsmonitor", "core.hookspath", "core.worktree", "extensions.worktreeconfig",
		"core.alternaterefscommand", "core.alternaterefsprefixes", "core.pager", "credential.helper", "core.sshcommand":
		return true
	}
	return strings.HasPrefix(key, "includeif.") ||
		strings.HasPrefix(key, "alias.") ||
		strings.HasPrefix(key, "extensions.") ||
		strings.HasPrefix(key, "objects.") ||
		strings.HasPrefix(key, "pager.") ||
		(strings.HasPrefix(key, "diff.") && (key == "diff.external" || strings.HasSuffix(key, ".command") || strings.HasSuffix(key, ".textconv"))) ||
		(strings.HasPrefix(key, "merge.") && (key == "merge.tool" || key == "merge.guitool" || strings.HasSuffix(key, ".driver"))) ||
		(strings.HasPrefix(key, "mergetool.") && (strings.HasSuffix(key, ".cmd") || strings.HasSuffix(key, ".path"))) ||
		(strings.HasPrefix(key, "filter.") && (strings.HasSuffix(key, ".clean") || strings.HasSuffix(key, ".smudge") || strings.HasSuffix(key, ".process")))
}

func (curator *AuthorityCurator) gitSHA(ctx context.Context, root, revision string) (string, error) {
	output, err := curator.git(ctx, root, "rev-parse", "--verify", revision)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(output))
	if !benchcycle.FullSHA(value) {
		return "", errors.New("git did not return a lowercase full SHA")
	}
	return value, nil
}

type publishedBaseline struct {
	root            string
	report          measurement.MeasurementReport
	manifest        LifecycleManifest
	repeat          SemanticRepeatResult
	allowlistResult BaselineAllowlistResult
	manifestJSON    []byte
	repeatJSON      []byte
}

func loadPublishedBaseline(ctx context.Context, directory string) (publishedBaseline, error) {
	root, err := safeArtifactDirectory(ctx, directory, "sanitized baseline publication")
	if err != nil {
		return publishedBaseline{}, err
	}
	var artifacts ArtifactManifest
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(root, artifactManifestPath), &artifacts); err != nil {
		return publishedBaseline{}, fmt.Errorf("read baseline artifact manifest: %w", err)
	}
	if err := artifacts.Validate(); err != nil {
		return publishedBaseline{}, fmt.Errorf("validate baseline artifact manifest: %w", err)
	}
	var manifest LifecycleManifest
	manifestCanonical, err := readCanonicalJSONContext(ctx, filepath.Join(root, "lifecycle-manifest.json"), &manifest)
	if err != nil {
		return publishedBaseline{}, fmt.Errorf("read baseline lifecycle manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return publishedBaseline{}, fmt.Errorf("validate baseline lifecycle manifest: %w", err)
	}
	if manifest.Route != RouteProtectedBaseline || manifest.BaselineAllowlist == nil {
		return publishedBaseline{}, errors.New("sanitized publication is not a protected baseline")
	}
	var repeat SemanticRepeatResult
	repeatCanonical, err := readCanonicalJSONContext(ctx, filepath.Join(root, "semantic-repeat.json"), &repeat)
	if err != nil {
		return publishedBaseline{}, fmt.Errorf("read baseline semantic repeat: %w", err)
	}
	if err := repeat.Validate(); err != nil {
		return publishedBaseline{}, fmt.Errorf("validate baseline semantic repeat: %w", err)
	}
	if !equalStrings(repeat.ReportIDs, manifest.ReportIDs) {
		return publishedBaseline{}, errors.New("baseline semantic repeat does not bind lifecycle report identifiers")
	}
	var allowlistResult BaselineAllowlistResult
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(root, baselineAllowlistResultPath()), &allowlistResult); err != nil {
		return publishedBaseline{}, fmt.Errorf("read baseline allowlist result: %w", err)
	}
	if err := allowlistResult.Validate(); err != nil {
		return publishedBaseline{}, fmt.Errorf("validate baseline allowlist result: %w", err)
	}
	if !sameCanonical(allowlistResult, *manifest.BaselineAllowlist) {
		return publishedBaseline{}, errors.New("baseline allowlist result does not match lifecycle manifest")
	}
	firstReport, firstBytes, err := readCanonicalMeasurementReport(ctx, filepath.Join(root, "repetition-1", "report.json"))
	if err != nil {
		return publishedBaseline{}, fmt.Errorf("read first baseline report: %w", err)
	}
	secondReport, secondBytes, err := readCanonicalMeasurementReport(ctx, filepath.Join(root, "repetition-2", "report.json"))
	if err != nil {
		return publishedBaseline{}, fmt.Errorf("read second baseline report: %w", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) || !sameCanonical(firstReport, secondReport) {
		return publishedBaseline{}, errors.New("baseline repetition reports are not byte-identical")
	}
	if !reportIDsBindBaseline(manifest.ReportIDs, firstReport.ID) || !reportIDsBindBaseline(repeat.ReportIDs, firstReport.ID) {
		return publishedBaseline{}, errors.New("baseline reports do not bind lifecycle and semantic repeat identifiers")
	}
	if err := replaySanitizedBundle(ctx, root, manifest, repeat, runtimeFacts{}); err != nil {
		return publishedBaseline{}, fmt.Errorf("replay sanitized baseline publication: %w", err)
	}
	return publishedBaseline{
		root: root, report: firstReport, manifest: manifest, repeat: repeat, allowlistResult: allowlistResult,
		manifestJSON: canonicalDocument(manifestCanonical), repeatJSON: canonicalDocument(repeatCanonical),
	}, nil
}

func loadOriginalBaselineAllowlist(ctx context.Context, directory string, manifest LifecycleManifest) (BaselineAllowlist, error) {
	root, err := safeArtifactDirectory(ctx, directory, "baseline authority")
	if err != nil {
		return BaselineAllowlist{}, err
	}
	bundleRoot, err := benchcycle.RealDirectory(filepath.Join(root, authorityBundleDirectory))
	if err != nil {
		return BaselineAllowlist{}, fmt.Errorf("validate baseline authority bundle directory: %w", err)
	}
	runner := &Runner{}
	bundle, bundleRef, err := runner.loadBundle(bundleRoot, RouteProtectedBaseline)
	if err != nil {
		return BaselineAllowlist{}, fmt.Errorf("read baseline authority trusted bundle: %w", err)
	}
	if manifest.Bundle != bundleRef {
		return BaselineAllowlist{}, errors.New("baseline authority trusted bundle does not match the published lifecycle manifest")
	}
	if _, err := runner.loadInputTemplate(bundleRoot, bundle.BaselineInput, measurement.BaselineMeasurement); err != nil {
		return BaselineAllowlist{}, fmt.Errorf("read baseline authority input: %w", err)
	}
	allowlistPath, err := benchcycle.BelowRoot(bundleRoot, bundle.BaselineAllowlist.Path)
	if err != nil {
		return BaselineAllowlist{}, fmt.Errorf("resolve original baseline allowlist: %w", err)
	}
	var allowlist BaselineAllowlist
	encoded, err := readCanonicalJSONContext(ctx, allowlistPath, &allowlist)
	if err != nil {
		return BaselineAllowlist{}, fmt.Errorf("read original baseline allowlist: %w", err)
	}
	if err := allowlist.Validate(); err != nil {
		return BaselineAllowlist{}, fmt.Errorf("validate original baseline allowlist: %w", err)
	}
	if benchmark.SHA256Digest(encoded) != bundle.BaselineAllowlist.Digest {
		return BaselineAllowlist{}, errors.New("original baseline allowlist does not match the authority bundle")
	}
	return allowlist, nil
}

func readCanonicalMeasurementReport(ctx context.Context, file string) (measurement.MeasurementReport, []byte, error) {
	raw, err := readRegularFileContext(ctx, file)
	if err != nil {
		return measurement.MeasurementReport{}, nil, err
	}
	report, err := measurement.DecodeMeasurementReport(bytes.NewReader(raw))
	if err != nil {
		return measurement.MeasurementReport{}, nil, err
	}
	canonical, _, err := canonicalMeasurementReportFile(report)
	if err != nil {
		return measurement.MeasurementReport{}, nil, err
	}
	if !bytes.Equal(raw, canonical) {
		return measurement.MeasurementReport{}, nil, errors.New("measurement report is not canonical")
	}
	return report, canonical, nil
}

// baselineReviewEvidenceDocument retains the fixed reviewed-document shape.
// The curator validates objective identities, source-delta facts, and pass/fail
// fields without creating or rewriting review prose.
type baselineReviewEvidenceDocument struct {
	SchemaVersion string                     `json:"schema_version"`
	ID            string                     `json:"id"`
	Harness       HarnessIdentity            `json:"harness"`
	Analyzer      RevisionIdentity           `json:"analyzer"`
	SourceDelta   baselineReviewSourceDelta  `json:"source_delta"`
	Checkpoints   []baselineReviewCheckpoint `json:"checkpoints"`
	CurrentChecks []baselineReviewCheck      `json:"current_checks"`
	Findings      []string                   `json:"findings"`
}

type baselineReviewSourceDelta struct {
	Range                 string `json:"range"`
	RawDiffByteCount      int    `json:"raw_diff_byte_count"`
	RawDiffDigest         string `json:"raw_diff_digest"`
	NormalizedEntryCount  int    `json:"normalized_entry_count"`
	AddedEntryCount       int    `json:"added_entry_count"`
	ModifiedEntryCount    int    `json:"modified_entry_count"`
	NormalizedEntryDigest string `json:"normalized_entry_digest"`
}

type baselineReviewCheckpoint struct {
	Name         string `json:"name"`
	ReviewedHead string `json:"reviewed_head"`
	Verdict      string `json:"verdict"`
	Confidence   string `json:"confidence"`
	Findings     int    `json:"findings"`
}

type baselineReviewCheck struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
}

// baselineDispositionEvidenceDocument retains the fixed reviewed-disposition
// shape. The curator validates its artifact bindings and procedural actors but
// never creates or rewrites its decision prose.
type baselineDispositionEvidenceDocument struct {
	SchemaVersion     string                        `json:"schema_version"`
	ID                string                        `json:"id"`
	BaselineResult    measurement.ArtifactReference `json:"baseline_result"`
	LifecycleManifest measurement.ArtifactReference `json:"lifecycle_manifest"`
	SemanticRepeat    measurement.ArtifactReference `json:"semantic_repeat"`
	AllowlistResult   measurement.ArtifactReference `json:"allowlist_result"`
	Decision          string                        `json:"decision"`
	Producer          string                        `json:"producer"`
	Reviewer          string                        `json:"reviewer"`
	Maintainer        string                        `json:"maintainer"`
	Checks            []baselineReviewCheck         `json:"checks"`
}

type canonicalEvidence struct {
	Reference measurement.ArtifactReference
	File      []byte
}

type baselineReviewEvidence struct {
	canonicalEvidence
	Document baselineReviewEvidenceDocument
}

type baselineDispositionEvidence struct {
	canonicalEvidence
	Document baselineDispositionEvidenceDocument
}

func readBaselineReviewEvidence(ctx context.Context, file string) (baselineReviewEvidence, error) {
	var evidence baselineReviewEvidenceDocument
	canonical, err := readCanonicalJSONContext(ctx, file, &evidence)
	if err != nil {
		return baselineReviewEvidence{}, err
	}
	if err := validateBaselineReviewEvidence(evidence); err != nil {
		return baselineReviewEvidence{}, err
	}
	return baselineReviewEvidence{
		canonicalEvidence: canonicalEvidence{
			Reference: canonicalReference(evidence.ID, canonical),
			File:      canonicalDocument(canonical),
		},
		Document: evidence,
	}, nil
}

func readBaselineDispositionEvidence(ctx context.Context, file string) (baselineDispositionEvidence, error) {
	var evidence baselineDispositionEvidenceDocument
	canonical, err := readCanonicalJSONContext(ctx, file, &evidence)
	if err != nil {
		return baselineDispositionEvidence{}, err
	}
	if err := validateBaselineDispositionEvidence(evidence); err != nil {
		return baselineDispositionEvidence{}, err
	}
	return baselineDispositionEvidence{
		canonicalEvidence: canonicalEvidence{
			Reference: canonicalReference(evidence.ID, canonical),
			File:      canonicalDocument(canonical),
		},
		Document: evidence,
	}, nil
}

func validateBaselineReviewEvidence(evidence baselineReviewEvidenceDocument) error {
	if evidence.SchemaVersion != baselineReviewEvidenceSchema {
		return fmt.Errorf("baseline review evidence schema must be %q", baselineReviewEvidenceSchema)
	}
	if !bounded(evidence.ID) {
		return errors.New("baseline review evidence requires a bounded id")
	}
	if err := validateHarness(evidence.Harness); err != nil {
		return fmt.Errorf("validate baseline review harness: %w", err)
	}
	if err := validateRevision(evidence.Analyzer); err != nil {
		return fmt.Errorf("validate baseline review analyzer: %w", err)
	}
	if evidence.Harness.ID == evidence.Analyzer.ID {
		return errors.New("baseline review evidence conflates harness and analyzer identities")
	}
	if evidence.SourceDelta.RawDiffByteCount < 1 || !validDigest(evidence.SourceDelta.RawDiffDigest) ||
		evidence.SourceDelta.NormalizedEntryCount < 1 || evidence.SourceDelta.NormalizedEntryCount > maxCells ||
		evidence.SourceDelta.AddedEntryCount < 0 || evidence.SourceDelta.ModifiedEntryCount < 0 ||
		evidence.SourceDelta.AddedEntryCount+evidence.SourceDelta.ModifiedEntryCount != evidence.SourceDelta.NormalizedEntryCount ||
		!validDigest(evidence.SourceDelta.NormalizedEntryDigest) {
		return errors.New("baseline review evidence contains invalid source-delta facts")
	}
	if len(evidence.Checkpoints) == 0 || len(evidence.Checkpoints) > maxCells ||
		len(evidence.CurrentChecks) == 0 || len(evidence.CurrentChecks) > maxCells ||
		evidence.Findings == nil || len(evidence.Findings) != 0 {
		return errors.New("baseline review evidence must contain passing checkpoints and checks with no findings")
	}
	seen := make(map[string]struct{}, len(evidence.Checkpoints)+len(evidence.CurrentChecks))
	for _, checkpoint := range evidence.Checkpoints {
		if !bounded(checkpoint.Name) || !benchcycle.FullSHA(checkpoint.ReviewedHead) || checkpoint.Verdict != "PASS" || checkpoint.Confidence != "high" || checkpoint.Findings != 0 {
			return errors.New("baseline review evidence contains an invalid or non-passing checkpoint")
		}
		if _, duplicate := seen[checkpoint.Name]; duplicate {
			return errors.New("baseline review evidence contains duplicate checkpoint or check names")
		}
		seen[checkpoint.Name] = struct{}{}
	}
	for _, check := range evidence.CurrentChecks {
		if !bounded(check.Name) || check.Status != "PASS" || !bounded(check.Evidence) {
			return errors.New("baseline review evidence contains an invalid or non-passing current check")
		}
		if _, duplicate := seen[check.Name]; duplicate {
			return errors.New("baseline review evidence contains duplicate checkpoint or check names")
		}
		seen[check.Name] = struct{}{}
	}
	return nil
}

func validateBaselineReviewBinding(evidence baselineReviewEvidenceDocument, checkout authorityCheckout, diff []byte, allowlist BaselineAllowlist) error {
	if evidence.Harness != checkout.harness || evidence.Analyzer != checkout.baselineAnalyzer {
		return errors.New("baseline review evidence does not bind the inspected harness and fixed analyzer")
	}
	expectedRange := measurement.TrustedBaselineRevision + "..." + checkout.harness.Commit
	if evidence.SourceDelta.Range != expectedRange || evidence.SourceDelta.RawDiffByteCount != len(diff) || evidence.SourceDelta.RawDiffDigest != benchmark.SHA256Digest(diff) {
		return errors.New("baseline review evidence does not bind the exact Git source delta")
	}
	encodedEntries, err := benchmark.CanonicalJSON(allowlist.Entries)
	if err != nil {
		return fmt.Errorf("encode baseline review normalized entries: %w", err)
	}
	added := 0
	modified := 0
	for _, entry := range allowlist.Entries {
		switch entry.Status {
		case "A":
			added++
		case "M":
			modified++
		}
	}
	if evidence.SourceDelta.NormalizedEntryCount != len(allowlist.Entries) || evidence.SourceDelta.AddedEntryCount != added ||
		evidence.SourceDelta.ModifiedEntryCount != modified || evidence.SourceDelta.NormalizedEntryDigest != benchmark.SHA256Digest(encodedEntries) {
		return errors.New("baseline review evidence does not bind the normalized source delta")
	}
	for _, checkpoint := range evidence.Checkpoints {
		if checkpoint.ReviewedHead == checkout.harness.Commit {
			return nil
		}
	}
	return errors.New("baseline review evidence has no passing checkpoint for the inspected harness head")
}

func validateBaselineDispositionEvidence(evidence baselineDispositionEvidenceDocument) error {
	if evidence.SchemaVersion != baselineDispositionSchema {
		return fmt.Errorf("baseline disposition evidence schema must be %q", baselineDispositionSchema)
	}
	if !bounded(evidence.ID) {
		return errors.New("baseline disposition evidence requires a bounded id")
	}
	for _, reference := range []measurement.ArtifactReference{
		evidence.BaselineResult,
		evidence.LifecycleManifest,
		evidence.SemanticRepeat,
		evidence.AllowlistResult,
	} {
		if err := validateArtifact(reference); err != nil {
			return errors.New("baseline disposition evidence contains an invalid artifact reference")
		}
	}
	if evidence.Decision != "accepted_as_procedural_baseline" || !bounded(evidence.Producer) || !bounded(evidence.Reviewer) || !bounded(evidence.Maintainer) {
		return errors.New("baseline disposition evidence is not an accepted disposition with descriptive actors")
	}
	if len(evidence.Checks) == 0 || len(evidence.Checks) > maxCells {
		return errors.New("baseline disposition evidence requires passing checks")
	}
	seen := make(map[string]struct{}, len(evidence.Checks))
	for _, check := range evidence.Checks {
		if !bounded(check.Name) || check.Status != "PASS" || !bounded(check.Evidence) {
			return errors.New("baseline disposition evidence contains an invalid or non-passing check")
		}
		if _, duplicate := seen[check.Name]; duplicate {
			return errors.New("baseline disposition evidence contains duplicate check names")
		}
		seen[check.Name] = struct{}{}
	}
	return nil
}

func validateBaselineDispositionBinding(evidence baselineDispositionEvidenceDocument, publication publishedBaseline) error {
	_, reportCanonical, err := canonicalMeasurementReportFile(publication.report)
	if err != nil {
		return fmt.Errorf("encode disposition baseline report binding: %w", err)
	}
	manifestCanonical, err := benchmark.CanonicalJSON(publication.manifest)
	if err != nil {
		return fmt.Errorf("encode disposition lifecycle binding: %w", err)
	}
	repeatCanonical, err := benchmark.CanonicalJSON(publication.repeat)
	if err != nil {
		return fmt.Errorf("encode disposition semantic-repeat binding: %w", err)
	}
	allowlistCanonical, err := benchmark.CanonicalJSON(publication.allowlistResult)
	if err != nil {
		return fmt.Errorf("encode disposition allowlist binding: %w", err)
	}
	if evidence.BaselineResult != canonicalReference(publication.report.ID, reportCanonical) ||
		evidence.LifecycleManifest != canonicalReference("baseline-lifecycle-manifest.json", manifestCanonical) ||
		evidence.SemanticRepeat != canonicalReference("baseline-semantic-repeat.json", repeatCanonical) ||
		evidence.AllowlistResult != canonicalReference("baseline-allowlist-result.json", allowlistCanonical) {
		return errors.New("baseline disposition evidence does not bind the published baseline artifacts")
	}
	return nil
}

// candidateAssetsProvenance is the checked-in trusted-assets provenance shape.
// It intentionally has no candidate envelope reference: an envelope belongs to
// a subsequent final-HEAD preparation step.
type candidateAssetsProvenance struct {
	SchemaVersion       string                        `json:"schema_version"`
	BaselineHarness     HarnessIdentity               `json:"baseline_harness"`
	BaselineAnalyzer    RevisionIdentity              `json:"baseline_analyzer"`
	ReviewEvidence      measurement.ArtifactReference `json:"review_evidence"`
	DispositionEvidence measurement.ArtifactReference `json:"disposition_evidence"`
	LifecycleManifest   measurement.ArtifactReference `json:"lifecycle_manifest"`
	SemanticRepeat      measurement.ArtifactReference `json:"semantic_repeat"`
	BaselineInput       measurement.ArtifactReference `json:"baseline_input"`
	CandidateInput      measurement.ArtifactReference `json:"candidate_input"`
	BaselineAllowlist   measurement.ArtifactReference `json:"baseline_allowlist"`
	AllowlistResult     measurement.ArtifactReference `json:"allowlist_result"`
	BaselineReport      measurement.ArtifactReference `json:"baseline_report"`
	Checkpoint          measurement.ArtifactReference `json:"checkpoint"`
	Ratchet             measurement.ArtifactReference `json:"ratchet"`
	Bundle              measurement.ArtifactReference `json:"bundle"`
}

func (provenance candidateAssetsProvenance) Validate() error {
	if provenance.SchemaVersion != candidateProvenanceSchema {
		return fmt.Errorf("candidate assets provenance schema must be %q", candidateProvenanceSchema)
	}
	if err := validateHarness(provenance.BaselineHarness); err != nil {
		return fmt.Errorf("validate candidate provenance baseline harness: %w", err)
	}
	if err := validateRevision(provenance.BaselineAnalyzer); err != nil {
		return fmt.Errorf("validate candidate provenance baseline analyzer: %w", err)
	}
	for _, named := range []struct {
		name string
		ref  measurement.ArtifactReference
	}{
		{"review evidence", provenance.ReviewEvidence},
		{"disposition evidence", provenance.DispositionEvidence},
		{"lifecycle manifest", provenance.LifecycleManifest},
		{"semantic repeat", provenance.SemanticRepeat},
		{"baseline input", provenance.BaselineInput},
		{"candidate input", provenance.CandidateInput},
		{"baseline allowlist", provenance.BaselineAllowlist},
		{"allowlist result", provenance.AllowlistResult},
		{"baseline report", provenance.BaselineReport},
		{"checkpoint", provenance.Checkpoint},
		{"ratchet", provenance.Ratchet},
		{"bundle", provenance.Bundle},
	} {
		if err := validateArtifact(named.ref); err != nil {
			return fmt.Errorf("validate candidate provenance %s: %w", named.name, err)
		}
	}
	return nil
}

func buildCandidateAssetsProvenance(manifest LifecycleManifest, repeat SemanticRepeatResult, assets CandidateControllerAssets, reviewEvidence, dispositionEvidence measurement.ArtifactReference) (candidateAssetsProvenance, []byte, error) {
	_, manifestCanonical, err := canonicalJSONFile(manifest)
	if err != nil {
		return candidateAssetsProvenance{}, nil, fmt.Errorf("encode baseline lifecycle manifest provenance: %w", err)
	}
	_, repeatCanonical, err := canonicalJSONFile(repeat)
	if err != nil {
		return candidateAssetsProvenance{}, nil, fmt.Errorf("encode baseline semantic repeat provenance: %w", err)
	}
	provenance := candidateAssetsProvenance{
		SchemaVersion:       candidateProvenanceSchema,
		BaselineHarness:     manifest.Harness,
		BaselineAnalyzer:    manifest.Analyzer,
		ReviewEvidence:      reviewEvidence,
		DispositionEvidence: dispositionEvidence,
		LifecycleManifest:   canonicalReference("baseline-lifecycle-manifest.json", manifestCanonical),
		SemanticRepeat:      canonicalReference("baseline-semantic-repeat.json", repeatCanonical),
		BaselineInput:       assets.BaselineInputRef,
		CandidateInput:      assets.CandidateInputRef,
		BaselineAllowlist:   assets.BaselineAllowlistRef,
		AllowlistResult:     assets.BaselineAllowlistResultRef,
		BaselineReport:      assets.BaselineReportRef,
		Checkpoint:          assets.CheckpointRef,
		Ratchet:             assets.RatchetRef,
		Bundle:              assets.BundleRef,
	}
	if err := provenance.Validate(); err != nil {
		return candidateAssetsProvenance{}, nil, fmt.Errorf("validate candidate assets provenance: %w", err)
	}
	encoded, _, err := canonicalJSONFile(provenance)
	if err != nil {
		return candidateAssetsProvenance{}, nil, fmt.Errorf("encode candidate assets provenance: %w", err)
	}
	return provenance, encoded, nil
}

type candidateAuthority struct {
	root                  string
	inventoryDigest       string
	assets                CandidateControllerAssets
	manifest              LifecycleManifest
	repeat                SemanticRepeatResult
	provenance            candidateAssetsProvenance
	reviewEvidence        baselineReviewEvidence
	dispositionEvidence   baselineDispositionEvidence
	baselineInputFile     []byte
	candidateInputFile    []byte
	baselineAllowlistFile []byte
	bundleFile            []byte
}

func expectedCandidateAuthorityFiles() []string {
	return []string{
		"authority/baseline-allowlist-result.json",
		"authority/baseline-checkpoint.json",
		"authority/baseline-disposition-evidence.json",
		"authority/baseline-lifecycle-manifest.json",
		"authority/baseline-report.json",
		"authority/baseline-review-evidence.json",
		"authority/baseline-semantic-repeat.json",
		"authority/candidate-assets-provenance.json",
		"authority/candidate-ratchet.json",
		"baseline-allowlist.json",
		"baseline-input.json",
		"candidate-input.json",
		"trusted-bundle.json",
	}
}

func loadCandidateAuthority(ctx context.Context, directory string) (candidateAuthority, error) {
	root, err := safeArtifactDirectory(ctx, directory, "candidate authority")
	if err != nil {
		return candidateAuthority{}, err
	}
	files, err := regularRelativeFiles(ctx, root)
	if err != nil {
		return candidateAuthority{}, err
	}
	if !equalStrings(files, expectedCandidateAuthorityFiles()) {
		return candidateAuthority{}, errors.New("candidate authority asset inventory is not exact")
	}
	runner := &Runner{}
	bundle, bundleRef, err := runner.loadBundle(root, RouteCandidate)
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority trusted bundle: %w", err)
	}
	baselineInput, err := runner.loadInputTemplate(root, bundle.BaselineInput, measurement.BaselineMeasurement)
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority baseline input: %w", err)
	}
	if bundle.CandidateInput == nil {
		return candidateAuthority{}, errors.New("candidate authority trusted bundle has no candidate input")
	}
	candidateInput, err := runner.loadInputTemplate(root, *bundle.CandidateInput, measurement.CandidateAcceptance)
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority candidate input: %w", err)
	}

	baselineInputCanonical, err := readCanonicalJSONContext(ctx, filepath.Join(root, "baseline-input.json"), &measurement.MeasurementInput{})
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority baseline input bytes: %w", err)
	}
	candidateInputCanonical, err := readCanonicalJSONContext(ctx, filepath.Join(root, "candidate-input.json"), &measurement.MeasurementInput{})
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority candidate input bytes: %w", err)
	}
	var allowlist BaselineAllowlist
	allowlistCanonical, err := readCanonicalJSONContext(ctx, filepath.Join(root, "baseline-allowlist.json"), &allowlist)
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority baseline allowlist: %w", err)
	}
	if err := allowlist.Validate(); err != nil {
		return candidateAuthority{}, fmt.Errorf("validate candidate authority baseline allowlist: %w", err)
	}
	var storedBundle TrustedBundle
	bundleCanonical, err := readCanonicalJSONContext(ctx, filepath.Join(root, "trusted-bundle.json"), &storedBundle)
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority bundle bytes: %w", err)
	}
	if !sameCanonical(storedBundle, bundle) {
		return candidateAuthority{}, errors.New("candidate authority trusted bundle changed while reading")
	}

	supportingRoot, err := benchcycle.RealDirectory(filepath.Join(root, authoritySupportingDirectory))
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("validate candidate authority support directory: %w", err)
	}
	var allowlistResult BaselineAllowlistResult
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(supportingRoot, filepath.Base(authorityAllowlistResultPath)), &allowlistResult); err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority allowlist result: %w", err)
	}
	if err := allowlistResult.Validate(); err != nil {
		return candidateAuthority{}, fmt.Errorf("validate candidate authority allowlist result: %w", err)
	}
	report, reportFile, err := readCanonicalMeasurementReport(ctx, filepath.Join(supportingRoot, filepath.Base(authorityBaselineReportPath)))
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority baseline report: %w", err)
	}
	var checkpoint measurement.ProceduralBaselineCheckpoint
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(supportingRoot, filepath.Base(authorityCheckpointPath)), &checkpoint); err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority checkpoint: %w", err)
	}
	if err := checkpoint.Validate(baselineInput.Policy, report); err != nil {
		return candidateAuthority{}, fmt.Errorf("validate candidate authority checkpoint: %w", err)
	}
	var ratchet measurement.CandidateRatchet
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(supportingRoot, filepath.Base(authorityRatchetPath)), &ratchet); err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority ratchet: %w", err)
	}
	if err := ratchet.Validate(); err != nil {
		return candidateAuthority{}, fmt.Errorf("validate candidate authority ratchet: %w", err)
	}
	var manifest LifecycleManifest
	manifestCanonical, err := readCanonicalJSONContext(ctx, filepath.Join(supportingRoot, filepath.Base(authorityLifecyclePath)), &manifest)
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority lifecycle manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return candidateAuthority{}, fmt.Errorf("validate candidate authority lifecycle manifest: %w", err)
	}
	var repeat SemanticRepeatResult
	repeatCanonical, err := readCanonicalJSONContext(ctx, filepath.Join(supportingRoot, filepath.Base(authorityRepeatPath)), &repeat)
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority semantic repeat: %w", err)
	}
	if err := repeat.Validate(); err != nil {
		return candidateAuthority{}, fmt.Errorf("validate candidate authority semantic repeat: %w", err)
	}
	if !equalStrings(repeat.ReportIDs, manifest.ReportIDs) {
		return candidateAuthority{}, errors.New("candidate authority semantic repeat does not bind lifecycle report identifiers")
	}
	reviewEvidence, err := readBaselineReviewEvidence(ctx, filepath.Join(supportingRoot, filepath.Base(authorityReviewEvidencePath)))
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority review evidence: %w", err)
	}
	if manifest.Authority.ReviewEvidence != reviewEvidence.Reference {
		return candidateAuthority{}, errors.New("candidate authority review evidence does not match lifecycle manifest")
	}
	if reviewEvidence.Document.Harness != manifest.Harness || reviewEvidence.Document.Analyzer != manifest.Analyzer {
		return candidateAuthority{}, errors.New("candidate authority review evidence does not bind lifecycle identities")
	}
	dispositionEvidence, err := readBaselineDispositionEvidence(ctx, filepath.Join(supportingRoot, filepath.Base(authorityDispositionPath)))
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority disposition evidence: %w", err)
	}
	if err := validateBaselineDispositionBinding(dispositionEvidence.Document, publishedBaseline{
		report: report, manifest: manifest, repeat: repeat, allowlistResult: allowlistResult,
	}); err != nil {
		return candidateAuthority{}, err
	}
	if checkpoint.Producer != dispositionEvidence.Document.Producer || checkpoint.Reviewer != dispositionEvidence.Document.Reviewer || checkpoint.Maintainer != dispositionEvidence.Document.Maintainer {
		return candidateAuthority{}, errors.New("candidate authority checkpoint does not preserve descriptive disposition actors")
	}
	if reviewEvidence.Reference == dispositionEvidence.Reference || reviewEvidence.Reference.Digest == dispositionEvidence.Reference.Digest {
		return candidateAuthority{}, errors.New("candidate authority review and disposition evidence must be independent")
	}
	var provenance candidateAssetsProvenance
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(supportingRoot, filepath.Base(authorityProvenancePath)), &provenance); err != nil {
		return candidateAuthority{}, fmt.Errorf("read candidate authority provenance: %w", err)
	}
	if err := provenance.Validate(); err != nil {
		return candidateAuthority{}, fmt.Errorf("validate candidate authority provenance: %w", err)
	}

	assets, err := BuildCandidateControllerAssets(report, manifest, allowlistResult, allowlist, reviewEvidence.Reference, dispositionEvidence.Reference, CheckpointActors{
		Producer: checkpoint.Producer, Reviewer: checkpoint.Reviewer, Maintainer: checkpoint.Maintainer,
	})
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("rebuild candidate authority assets: %w", err)
	}
	if !sameCanonical(baselineInput, assets.BaselineInput) || !sameCanonical(candidateInput, assets.CandidateInput) || !sameCanonical(bundle, assets.TrustedBundle) ||
		!bytes.Equal(canonicalDocument(baselineInputCanonical), assets.BaselineInputJSON) || !bytes.Equal(canonicalDocument(candidateInputCanonical), assets.CandidateInputJSON) ||
		!bytes.Equal(canonicalDocument(allowlistCanonical), assets.BaselineAllowlistJSON) || !bytes.Equal(canonicalDocument(bundleCanonical), assets.TrustedBundleJSON) ||
		!bytes.Equal(reportFile, assets.BaselineReportJSON) {
		return candidateAuthority{}, errors.New("candidate authority trusted assets differ from deterministic reconstruction")
	}
	if candidateInput.Baseline == nil || candidateInput.Checkpoint == nil || candidateInput.Ratchet == nil ||
		!sameCanonical(*candidateInput.Baseline, report) || !sameCanonical(*candidateInput.Checkpoint, checkpoint) || !sameCanonical(*candidateInput.Ratchet, ratchet) {
		return candidateAuthority{}, errors.New("candidate authority input does not bind baseline, checkpoint, and ratchet")
	}
	if !sameCanonical(checkpoint, assets.Checkpoint) || !sameCanonical(ratchet, assets.Ratchet) || !sameCanonical(allowlistResult, assets.BaselineAllowlistResult) {
		return candidateAuthority{}, errors.New("candidate authority evidence differs from deterministic reconstruction")
	}
	expectedProvenance, _, err := buildCandidateAssetsProvenance(manifest, repeat, assets, reviewEvidence.Reference, dispositionEvidence.Reference)
	if err != nil {
		return candidateAuthority{}, err
	}
	if !sameCanonical(provenance, expectedProvenance) {
		return candidateAuthority{}, errors.New("candidate authority provenance differs from deterministic reconstruction")
	}
	if provenance.LifecycleManifest != canonicalReference("baseline-lifecycle-manifest.json", manifestCanonical) || provenance.SemanticRepeat != canonicalReference("baseline-semantic-repeat.json", repeatCanonical) || provenance.Bundle != bundleRef {
		return candidateAuthority{}, errors.New("candidate authority provenance does not bind staged bytes")
	}
	return candidateAuthority{
		root: root, assets: assets, manifest: manifest, repeat: repeat, provenance: provenance,
		reviewEvidence: reviewEvidence, dispositionEvidence: dispositionEvidence,
		baselineInputFile: canonicalDocument(baselineInputCanonical), candidateInputFile: canonicalDocument(candidateInputCanonical),
		baselineAllowlistFile: canonicalDocument(allowlistCanonical), bundleFile: canonicalDocument(bundleCanonical),
	}, nil
}

func canonicalDocument(canonical []byte) []byte {
	file := make([]byte, len(canonical)+1)
	copy(file, canonical)
	file[len(file)-1] = '\n'
	return file
}

type authorityAsset struct {
	path string
	body []byte
}

func pathsOverlap(left, right string) bool {
	leftAbsolute, leftErr := filepath.Abs(left)
	rightAbsolute, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return true
	}
	return pathContains(leftAbsolute, rightAbsolute) || pathContains(rightAbsolute, leftAbsolute)
}

func pathContains(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func stageAuthorityAssets(output string, directories []string, assets []authorityAsset) error {
	knownDirectories := make(map[string]struct{}, len(directories))
	for _, directory := range directories {
		if !isSingleAuthorityDirectory(directory) {
			return fmt.Errorf("invalid authority output directory %q", directory)
		}
		if _, exists := knownDirectories[directory]; exists {
			return fmt.Errorf("duplicate authority output directory %q", directory)
		}
		if err := createAuthorityDirectory(output, directory); err != nil {
			return err
		}
		knownDirectories[directory] = struct{}{}
	}
	seen := make(map[string]struct{}, len(assets))
	for _, asset := range assets {
		if !isAuthorityAssetPath(asset.path) {
			return fmt.Errorf("invalid authority asset path %q", asset.path)
		}
		parent := path.Dir(asset.path)
		if parent != "." {
			if _, exists := knownDirectories[parent]; !exists {
				return fmt.Errorf("authority asset %q has an unprepared parent directory", asset.path)
			}
		}
		if _, exists := seen[asset.path]; exists {
			return fmt.Errorf("duplicate authority asset %q", asset.path)
		}
		seen[asset.path] = struct{}{}
		parentPath := output
		if parent != "." {
			var err error
			parentPath, err = benchcycle.RealDirectory(filepath.Join(output, filepath.FromSlash(parent)))
			if err != nil {
				return fmt.Errorf("revalidate authority asset parent: %w", err)
			}
		}
		if err := benchcycle.WriteFile(filepath.Join(parentPath, filepath.Base(filepath.FromSlash(asset.path))), asset.body, 0o600); err != nil {
			return fmt.Errorf("write authority asset %q without overwrite: %w", asset.path, err)
		}
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := benchcycle.SyncDirectory(filepath.Join(output, directories[index])); err != nil {
			return err
		}
	}
	return benchcycle.SyncDirectory(output)
}

func isSingleAuthorityDirectory(value string) bool {
	return value != "" && value == path.Base(value) && value != "." && value != ".."
}

func isAuthorityAssetPath(value string) bool {
	if value == "" || path.IsAbs(value) || path.Clean(value) != value || path.Base(value) == "." || path.Base(value) == ".." {
		return false
	}
	parent := path.Dir(value)
	return parent == "." || isSingleAuthorityDirectory(parent)
}

func createAuthorityDirectory(root, relative string) error {
	assetPath, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return err
	}
	if !pathContains(root, assetPath) {
		return errors.New("authority output directory escapes output root")
	}
	if _, err := os.Lstat(assetPath); err == nil {
		return fmt.Errorf("authority output directory %q already exists", relative)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Mkdir(assetPath, 0o700); err != nil {
		return err
	}
	if _, err := benchcycle.RealDirectory(assetPath); err != nil {
		return fmt.Errorf("authority output directory %q is not real: %w", relative, err)
	}
	return nil
}

func safeArtifactDirectory(ctx context.Context, directory, label string) (string, error) {
	root, err := benchcycle.RealDirectory(directory)
	if err != nil {
		return "", fmt.Errorf("validate %s directory: %w", label, err)
	}
	if _, err := regularRelativeFiles(ctx, root); err != nil {
		return "", fmt.Errorf("validate %s file tree: %w", label, err)
	}
	return root, nil
}

func validateStagedBaselineAuthority(ctx context.Context, output string, assets ProtectedBaselineControllerAssets, review baselineReviewEvidence) error {
	if _, err := safeArtifactDirectory(ctx, output, "staged baseline authority"); err != nil {
		return err
	}
	files, err := regularRelativeFiles(ctx, output)
	if err != nil {
		return err
	}
	expectedFiles := []string{
		authorityReviewEvidencePath,
		authorityEnvelopeDirectory + "/" + assets.EnvelopeFileName,
		authorityBundleDirectory + "/baseline-allowlist.json",
		authorityBundleDirectory + "/baseline-input.json",
		authorityBundleDirectory + "/trusted-bundle.json",
	}
	if !equalStrings(files, expectedFiles) {
		return errors.New("staged baseline authority asset inventory is not exact")
	}
	stagedReview, err := readBaselineReviewEvidence(ctx, filepath.Join(output, filepath.FromSlash(authorityReviewEvidencePath)))
	if err != nil || stagedReview.Reference != review.Reference || !bytes.Equal(stagedReview.File, review.File) {
		return errors.New("staged baseline review evidence differs from generated authority")
	}
	bundleRoot, err := benchcycle.RealDirectory(filepath.Join(output, authorityBundleDirectory))
	if err != nil {
		return err
	}
	runner := &Runner{}
	bundle, bundleRef, err := runner.loadBundle(bundleRoot, RouteProtectedBaseline)
	if err != nil {
		return err
	}
	if bundleRef != assets.BundleRef || !sameCanonical(bundle, assets.TrustedBundle) {
		return errors.New("staged baseline trusted bundle differs from generated assets")
	}
	input, err := runner.loadInputTemplate(bundleRoot, bundle.BaselineInput, measurement.BaselineMeasurement)
	if err != nil || !sameCanonical(input, assets.BaselineInput) {
		return errors.New("staged baseline input is invalid or differs from generated assets")
	}
	allowlistPath, err := benchcycle.BelowRoot(bundleRoot, bundle.BaselineAllowlist.Path)
	if err != nil {
		return err
	}
	var allowlist BaselineAllowlist
	encoded, err := readCanonicalJSONContext(ctx, allowlistPath, &allowlist)
	if err != nil || !sameCanonical(allowlist, assets.BaselineAllowlist) || benchmark.SHA256Digest(encoded) != bundle.BaselineAllowlist.Digest {
		return errors.New("staged baseline allowlist is invalid or differs from generated assets")
	}
	envelopeRoot, err := benchcycle.RealDirectory(filepath.Join(output, authorityEnvelopeDirectory))
	if err != nil {
		return err
	}
	envelopePath, err := benchcycle.BelowRoot(envelopeRoot, assets.EnvelopeFileName)
	if err != nil {
		return err
	}
	var envelope RunEnvelope
	if _, err := readCanonicalJSONContext(ctx, envelopePath, &envelope); err != nil || !sameCanonical(envelope, assets.Envelope) {
		return errors.New("staged baseline envelope is invalid or differs from generated assets")
	}
	return validateEnvelopeMeasurement(envelope, input, bundleRef)
}

func validateStagedCandidateAuthority(ctx context.Context, output string, assets CandidateControllerAssets, publication publishedBaseline, provenance candidateAssetsProvenance, reviewEvidence baselineReviewEvidence, dispositionEvidence baselineDispositionEvidence) error {
	authority, err := loadCandidateAuthority(ctx, output)
	if err != nil {
		return err
	}
	if !sameCanonical(authority.assets, assets) || !sameCanonical(authority.manifest, publication.manifest) || !sameCanonical(authority.repeat, publication.repeat) ||
		!sameCanonical(authority.provenance, provenance) || authority.reviewEvidence.Reference != reviewEvidence.Reference || authority.dispositionEvidence.Reference != dispositionEvidence.Reference ||
		!bytes.Equal(authority.reviewEvidence.File, reviewEvidence.File) || !bytes.Equal(authority.dispositionEvidence.File, dispositionEvidence.File) {
		return errors.New("staged candidate authority differs from generated assets")
	}
	return nil
}

func validatePreparedCandidateController(ctx context.Context, output string, authority candidateAuthority, expectedReview candidateReviewSubject, expectedEnvelope RunEnvelope, envelopeFileName string) error {
	if _, err := safeArtifactDirectory(ctx, output, "prepared candidate controller"); err != nil {
		return err
	}
	files, err := regularRelativeFiles(ctx, output)
	if err != nil {
		return err
	}
	expectedFiles := []string{
		authorityDispositionPath,
		authorityReviewEvidencePath,
		controllerCandidateReviewSubjectPath,
		authorityEnvelopeDirectory + "/" + envelopeFileName,
		authorityBundleDirectory + "/baseline-allowlist.json",
		authorityBundleDirectory + "/baseline-input.json",
		authorityBundleDirectory + "/candidate-input.json",
		authorityBundleDirectory + "/trusted-bundle.json",
	}
	if !equalStrings(files, expectedFiles) {
		return errors.New("prepared candidate controller asset inventory is not exact")
	}
	stagedReview, _, stagedReviewRef, err := readControllerCandidateReviewSubject(ctx, output)
	if err != nil || !sameCanonical(stagedReview, expectedReview) || expectedEnvelope.Authority.ReviewEvidence != stagedReviewRef {
		return errors.New("prepared candidate review subject differs from the final-head envelope")
	}
	stagedBaselineReview, _, err := readControllerBaselineReviewEvidence(ctx, output)
	if err != nil || stagedBaselineReview.Reference != authority.reviewEvidence.Reference || !bytes.Equal(stagedBaselineReview.File, authority.reviewEvidence.File) {
		return errors.New("prepared baseline review evidence differs from committed authority")
	}
	stagedDisposition, _, err := readControllerBaselineDispositionEvidence(ctx, output)
	if err != nil || stagedDisposition.Reference != authority.dispositionEvidence.Reference || !bytes.Equal(stagedDisposition.File, authority.dispositionEvidence.File) {
		return errors.New("prepared baseline disposition evidence differs from committed authority")
	}
	bundleRoot, err := benchcycle.RealDirectory(filepath.Join(output, authorityBundleDirectory))
	if err != nil {
		return err
	}
	runner := &Runner{}
	bundle, bundleRef, err := runner.loadBundle(bundleRoot, RouteCandidate)
	if err != nil {
		return err
	}
	if bundleRef != authority.assets.BundleRef || !sameCanonical(bundle, authority.assets.TrustedBundle) {
		return errors.New("prepared candidate bundle differs from committed authority")
	}
	baselineInput, err := runner.loadInputTemplate(bundleRoot, bundle.BaselineInput, measurement.BaselineMeasurement)
	if err != nil || !sameCanonical(baselineInput, authority.assets.BaselineInput) {
		return errors.New("prepared candidate baseline input differs from committed authority")
	}
	if bundle.CandidateInput == nil {
		return errors.New("prepared candidate bundle is missing candidate input")
	}
	candidateInput, err := runner.loadInputTemplate(bundleRoot, *bundle.CandidateInput, measurement.CandidateAcceptance)
	if err != nil || !sameCanonical(candidateInput, authority.assets.CandidateInput) {
		return errors.New("prepared candidate input differs from committed authority")
	}
	envelopeRoot, err := benchcycle.RealDirectory(filepath.Join(output, authorityEnvelopeDirectory))
	if err != nil {
		return err
	}
	envelopePath, err := benchcycle.BelowRoot(envelopeRoot, envelopeFileName)
	if err != nil {
		return err
	}
	var envelope RunEnvelope
	if _, err := readCanonicalJSONContext(ctx, envelopePath, &envelope); err != nil || !sameCanonical(envelope, expectedEnvelope) {
		return errors.New("prepared candidate envelope differs from final-head envelope")
	}
	return validateEnvelopeMeasurement(envelope, candidateInput, bundleRef)
}
