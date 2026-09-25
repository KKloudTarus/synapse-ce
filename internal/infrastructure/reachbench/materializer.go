package reachbench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	reachcontract "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

const (
	MaterializationManifestSchemaVersion = "synapse-reachability-materialization-v1"

	materializationDirectory         = "fixture-materializations"
	maxMaterializedFileBytes   int64 = 1 << 20
	maxMaterializedOutputBytes int64 = 4 << 20
	maxMaterializedTotalBytes  int64 = 8 << 20
	maxMaterializedFiles             = 256
	materializerProbeTimeout         = 15 * time.Second
	materializerBuildTimeout         = 2 * time.Minute
	materializerMaxOutputBytes       = 64 << 10
	copyBufferSize                   = 32 << 10
)

// ToolLocator resolves only the fixed tool names that a frozen fixture recipe declares.
type ToolLocator func(string) (string, error)

// FixtureMaterializerDependencies supplies the process and platform boundaries used by
// FixtureMaterializer. Platform and LocateTool make the materialization policy
// deterministic in focused tests.
type FixtureMaterializerDependencies struct {
	ToolRunner ports.ToolRunner
	Platform   func() string
	LocateTool ToolLocator
}

// DefaultFixtureMaterializerDependencies returns host-backed dependencies for the
// package-local materializer. Production wiring is intentionally deferred to the
// reachability capture adapters.
func DefaultFixtureMaterializerDependencies(runner ports.ToolRunner) FixtureMaterializerDependencies {
	return FixtureMaterializerDependencies{
		ToolRunner: runner,
		Platform: func() string {
			return runtime.GOOS + "/" + runtime.GOARCH
		},
		LocateTool: exec.LookPath,
	}
}

// FixtureMaterializer creates one private deterministic workspace for a frozen
// fixture specification. It does not execute or capture any analyzer.
type FixtureMaterializer struct {
	runner     ports.ToolRunner
	platform   func() string
	locateTool ToolLocator
}

// NewFixtureMaterializer validates the external dependencies required to copy and
// optionally build a fixture.
func NewFixtureMaterializer(dependencies FixtureMaterializerDependencies) (*FixtureMaterializer, error) {
	if dependencies.ToolRunner == nil {
		return nil, errors.New("reachability fixture tool runner is required")
	}
	if dependencies.Platform == nil {
		return nil, errors.New("reachability fixture platform is required")
	}
	if dependencies.LocateTool == nil {
		return nil, errors.New("reachability fixture tool locator is required")
	}
	return &FixtureMaterializer{
		runner:     dependencies.ToolRunner,
		platform:   dependencies.Platform,
		locateTool: dependencies.LocateTool,
	}, nil
}

// FixtureMaterializationRequest contains the frozen specification, the private
// lifecycle workspace root, and the stable opaque key for one benchmark cell.
type FixtureMaterializationRequest struct {
	Specification reachcontract.FixtureSpecification
	WorkRoot      string
	CellKey       string
}

// MaterializedArtifact identifies a declared analyzer-consumed file without
// exposing its temporary absolute location.
type MaterializedArtifact struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

// MaterializedFixture is the private materialization result. Root is intentionally
// excluded from canonical identities; callers use the safe resolvers for declared files.
type MaterializedFixture struct {
	Root          string                             `json:"-"`
	Specification reachcontract.FixtureSpecification `json:"specification"`
	Inputs        []MaterializedArtifact             `json:"inputs"`
	Outputs       []MaterializedArtifact             `json:"outputs"`

	inputPaths  map[string]string
	outputPaths map[string]struct{}
}

// MaterializationManifest is the stable repeat-comparison and evidence identity for a
// private fixture materialization. It intentionally contains no absolute path.
type MaterializationManifest struct {
	SchemaVersion string                 `json:"schema_version"`
	FixtureID     string                 `json:"fixture_id"`
	FixtureDigest string                 `json:"fixture_digest"`
	Inputs        []MaterializedArtifact `json:"inputs"`
	Outputs       []MaterializedArtifact `json:"outputs"`
}

// Materialize removes and recreates the deterministic per-cell workspace, copies all
// declared inputs, executes an optional frozen recipe, and verifies declared outputs.
func (materializer *FixtureMaterializer) Materialize(ctx context.Context, request FixtureMaterializationRequest) (MaterializedFixture, error) {
	if err := ctx.Err(); err != nil {
		return MaterializedFixture{}, err
	}
	if strings.TrimSpace(request.CellKey) == "" || request.CellKey != strings.TrimSpace(request.CellKey) || len(request.CellKey) > maxIdentifierBytes {
		return MaterializedFixture{}, errors.New("invalid opaque reachability fixture cell key")
	}
	specification, _, err := frozenFixtureSpecification(request.Specification)
	if err != nil {
		return MaterializedFixture{}, err
	}
	root, err := prepareMaterializationRoot(request.WorkRoot, request.CellKey)
	if err != nil {
		return MaterializedFixture{}, err
	}
	if err := ctx.Err(); err != nil {
		return MaterializedFixture{}, err
	}

	inputs, err := materializeFixtureInputs(ctx, root, specification)
	if err != nil {
		return MaterializedFixture{}, err
	}
	outputs := make([]MaterializedArtifact, 0)
	if specification.Build != nil {
		if err := materializer.build(ctx, root, specification); err != nil {
			return MaterializedFixture{}, err
		}
		inputs, err = verifyMaterializedInputs(ctx, root, specification, inputs)
		if err != nil {
			return MaterializedFixture{}, err
		}
		outputs, err = verifyMaterializedOutputs(ctx, root, *specification.Build)
		if err != nil {
			return MaterializedFixture{}, err
		}
	}
	return MaterializedFixture{
		Root:          root,
		Specification: cloneMaterializedSpecification(specification),
		Inputs:        append([]MaterializedArtifact(nil), inputs...),
		Outputs:       append([]MaterializedArtifact(nil), outputs...),
		inputPaths:    materializedInputPaths(specification),
		outputPaths:   materializedOutputPaths(specification),
	}, nil
}

// ResolveInput returns the private absolute path for one declared input path. For a
// file with MaterializedPath, it resolves that materialized location instead.
func (fixture MaterializedFixture) ResolveInput(path string) (string, error) {
	materializedPath, declared := fixture.inputPaths[path]
	if !declared {
		return "", fmt.Errorf("undeclared reachability fixture input %q", path)
	}
	return resolveDeclaredRegularFile(fixture.Root, materializedPath)
}

// AnalysisRoot derives the analyzer target from the frozen fixture's material
// entries. Materialization preserves the contract's nested layout, while each
// analyzer expects its project or source directory rather than the enclosing
// private cell workspace. Only declared, verified entries participate; output
// paths and arbitrary files cannot widen the analysis target.
func (fixture MaterializedFixture) AnalysisRoot() (string, error) {
	root, err := benchcycle.RealDirectory(fixture.Root)
	if err != nil {
		return "", fmt.Errorf("validate materialized fixture root: %w", err)
	}
	// Low-level adapter tests may exercise a manually constructed fixture without
	// a contract specification. Production materialization always has entries, so
	// the normal path below remains metadata-derived and fail-closed.
	if len(fixture.Specification.Entries) == 0 {
		return root, nil
	}

	analysisRoot := ""
	for _, entry := range fixture.Specification.Entries {
		entryPath, err := fixture.ResolveInput(entry.Path)
		if err != nil {
			return "", fmt.Errorf("resolve materialized fixture entry %q: %w", entry.Path, err)
		}
		entryRoot := filepath.Dir(entryPath)
		if analysisRoot == "" {
			analysisRoot = entryRoot
			continue
		}
		analysisRoot, err = commonMaterializedParent(root, analysisRoot, entryRoot)
		if err != nil {
			return "", err
		}
	}
	if analysisRoot == "" {
		return "", errors.New("materialized fixture has no analysis entries")
	}
	analysisRoot, err = benchcycle.RealDirectory(analysisRoot)
	if err != nil {
		return "", fmt.Errorf("validate materialized fixture analysis root: %w", err)
	}
	if !materializedPathWithin(root, analysisRoot) {
		return "", errors.New("materialized fixture analysis root escapes fixture root")
	}
	return analysisRoot, nil
}

// AnalysisRelativeInput resolves a declared contract input relative to AnalysisRoot. It is the safe bridge
// from immutable fixture locator metadata to analyzers that identify first-party source symbols by their
// root-relative module path; an undeclared path or one outside the derived root is rejected.
func (fixture MaterializedFixture) AnalysisRelativeInput(path string) (string, error) {
	analysisRoot, err := fixture.AnalysisRoot()
	if err != nil {
		return "", err
	}
	input, err := fixture.ResolveInput(path)
	if err != nil {
		return "", err
	}
	if !materializedPathWithin(analysisRoot, input) {
		return "", fmt.Errorf("materialized fixture input %q is outside analysis root", path)
	}
	relative, err := filepath.Rel(analysisRoot, input)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return "", fmt.Errorf("derive analysis-relative fixture input %q", path)
	}
	return filepath.ToSlash(relative), nil
}

func commonMaterializedParent(root, first, second string) (string, error) {
	for candidate := first; ; candidate = filepath.Dir(candidate) {
		if materializedPathWithin(candidate, second) {
			if !materializedPathWithin(root, candidate) {
				return "", errors.New("materialized fixture entry parent escapes fixture root")
			}
			return candidate, nil
		}
		if candidate == root {
			break
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			break
		}
	}
	return "", errors.New("materialized fixture entries have no common parent")
}

func materializedPathWithin(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// ResolveOutput returns the private absolute path for one declared analyzer-consumed
// build output.
func (fixture MaterializedFixture) ResolveOutput(path string) (string, error) {
	if _, declared := fixture.outputPaths[path]; !declared {
		return "", fmt.Errorf("undeclared reachability fixture output %q", path)
	}
	return resolveDeclaredRegularFile(fixture.Root, path)
}

// Manifest returns the path-independent materialization identity suitable for repeat
// comparison or later evidence capture.
func (fixture MaterializedFixture) Manifest() (MaterializationManifest, error) {
	fixtureDigest, err := reachcontract.DigestFixtureSpecification(fixture.Specification)
	if err != nil {
		return MaterializationManifest{}, fmt.Errorf("validate materialized fixture specification: %w", err)
	}
	inputs, err := canonicalMaterializedArtifacts(fixture.Inputs, maxMaterializedFileBytes)
	if err != nil {
		return MaterializationManifest{}, fmt.Errorf("validate materialized fixture inputs: %w", err)
	}
	outputs, err := canonicalMaterializedArtifacts(fixture.Outputs, maxMaterializedOutputBytes)
	if err != nil {
		return MaterializationManifest{}, fmt.Errorf("validate materialized fixture outputs: %w", err)
	}
	return MaterializationManifest{
		SchemaVersion: MaterializationManifestSchemaVersion,
		FixtureID:     fixture.Specification.ID,
		FixtureDigest: fixtureDigest,
		Inputs:        inputs,
		Outputs:       outputs,
	}, nil
}

// CanonicalManifest encodes the path-independent materialization manifest using the
// repository's canonical JSON helper.
func (fixture MaterializedFixture) CanonicalManifest() ([]byte, error) {
	manifest, err := fixture.Manifest()
	if err != nil {
		return nil, err
	}
	encoded, err := benchmark.CanonicalJSON(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode materialization manifest: %w", err)
	}
	return encoded, nil
}

// ManifestDigest returns the SHA-256 identity of CanonicalManifest.
func (fixture MaterializedFixture) ManifestDigest() (string, error) {
	encoded, err := fixture.CanonicalManifest()
	if err != nil {
		return "", err
	}
	return benchmark.SHA256Digest(encoded), nil
}

func frozenFixtureSpecification(supplied reachcontract.FixtureSpecification) (reachcontract.FixtureSpecification, string, error) {
	suppliedDigest, err := reachcontract.DigestFixtureSpecification(supplied)
	if err != nil {
		return reachcontract.FixtureSpecification{}, "", fmt.Errorf("validate reachability fixture specification: %w", err)
	}
	contract, err := reachcontract.LoadReachabilityBenchmark()
	if err != nil {
		return reachcontract.FixtureSpecification{}, "", fmt.Errorf("load frozen reachability fixture specification: %w", err)
	}
	for _, fixture := range contract.Fixtures.Fixtures {
		if fixture.ID != supplied.ID {
			continue
		}
		frozenDigest, err := reachcontract.DigestFixtureSpecification(fixture)
		if err != nil {
			return reachcontract.FixtureSpecification{}, "", fmt.Errorf("digest frozen reachability fixture specification: %w", err)
		}
		if frozenDigest != suppliedDigest {
			return reachcontract.FixtureSpecification{}, "", fmt.Errorf("reachability fixture specification digest mismatch for %q", supplied.ID)
		}
		return cloneMaterializedSpecification(fixture), frozenDigest, nil
	}
	return reachcontract.FixtureSpecification{}, "", fmt.Errorf("unknown frozen reachability fixture %q", supplied.ID)
}

func prepareMaterializationRoot(workRoot, cellKey string) (string, error) {
	trustedRoot, err := benchcycle.RealDirectory(workRoot)
	if err != nil {
		return "", fmt.Errorf("validate reachability fixture work root: %w", err)
	}
	parent, err := ensurePrivateDirectory(trustedRoot, materializationDirectory)
	if err != nil {
		return "", fmt.Errorf("create reachability fixture materialization parent: %w", err)
	}
	sum := sha256.Sum256([]byte(cellKey))
	cellDirectory := hex.EncodeToString(sum[:])
	root := filepath.Join(parent, cellDirectory)
	if err := removeMaterializationTree(root); err != nil {
		return "", fmt.Errorf("remove prior reachability fixture materialization: %w", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		return "", fmt.Errorf("create reachability fixture materialization: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("inspect reachability fixture materialization: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("reachability fixture materialization is not a real directory")
	}
	return root, nil
}

func removeMaterializationTree(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return os.Remove(path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		child := filepath.Join(path, entry.Name())
		childInfo, err := os.Lstat(child)
		if err != nil {
			return err
		}
		if childInfo.Mode()&os.ModeSymlink == 0 && childInfo.IsDir() {
			if err := removeMaterializationTree(child); err != nil {
				return err
			}
			continue
		}
		if err := os.Remove(child); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

func materializeFixtureInputs(ctx context.Context, root string, specification reachcontract.FixtureSpecification) ([]MaterializedArtifact, error) {
	if len(specification.Files) == 0 || len(specification.Files) > maxMaterializedFiles {
		return nil, errors.New("reachability fixture input count exceeds materializer bound")
	}
	inputs := make([]MaterializedArtifact, 0, len(specification.Files))
	var total int64
	for _, file := range specification.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		contents, err := reachcontract.ReadFixtureFile(file)
		if err != nil {
			return nil, fmt.Errorf("read reachability fixture input %q: %w", file.Path, err)
		}
		if int64(len(contents)) != file.Size || benchmark.SHA256Digest(contents) != file.Digest {
			return nil, fmt.Errorf("verified reachability fixture input %q changed during read", file.Path)
		}
		total += int64(len(contents))
		if total > maxMaterializedTotalBytes {
			return nil, fmt.Errorf("reachability fixture inputs exceed %d bytes", maxMaterializedTotalBytes)
		}
		materializedPath := file.Path
		if file.MaterializedPath != "" {
			materializedPath = file.MaterializedPath
		}
		if err := writePrivateFixtureFile(ctx, root, materializedPath, contents); err != nil {
			return nil, fmt.Errorf("materialize reachability fixture input %q: %w", file.Path, err)
		}
		identity, err := digestDeclaredRegularFile(ctx, root, materializedPath, maxMaterializedFileBytes)
		if err != nil {
			return nil, fmt.Errorf("verify materialized reachability fixture input %q: %w", file.Path, err)
		}
		if identity.Size != file.Size || identity.Digest != file.Digest {
			return nil, fmt.Errorf("materialized reachability fixture input %q digest mismatch", file.Path)
		}
		inputs = append(inputs, identity)
	}
	return canonicalMaterializedArtifacts(inputs, maxMaterializedFileBytes)
}

func verifyMaterializedInputs(ctx context.Context, root string, specification reachcontract.FixtureSpecification, expected []MaterializedArtifact) ([]MaterializedArtifact, error) {
	if len(expected) != len(specification.Files) {
		return nil, errors.New("incomplete materialized reachability fixture inputs")
	}
	byPath := make(map[string]MaterializedArtifact, len(expected))
	for _, identity := range expected {
		byPath[identity.Path] = identity
	}
	verified := make([]MaterializedArtifact, 0, len(specification.Files))
	for _, file := range specification.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := file.Path
		if file.MaterializedPath != "" {
			path = file.MaterializedPath
		}
		identity, err := digestDeclaredRegularFile(ctx, root, path, maxMaterializedFileBytes)
		if err != nil {
			return nil, fmt.Errorf("verify retained reachability fixture input %q: %w", file.Path, err)
		}
		if identity.Size != file.Size || identity.Digest != file.Digest || identity != byPath[path] {
			return nil, fmt.Errorf("reachability build modified declared input %q", file.Path)
		}
		verified = append(verified, identity)
	}
	return canonicalMaterializedArtifacts(verified, maxMaterializedFileBytes)
}

func writePrivateFixtureFile(ctx context.Context, root, relative string, contents []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := declaredPath(root, relative, true)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	writeErr := copyFixtureBytes(ctx, file, contents)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(path, 0o600)
}

func copyFixtureBytes(ctx context.Context, destination io.Writer, contents []byte) error {
	for len(contents) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		count := copyBufferSize
		if len(contents) < count {
			count = len(contents)
		}
		written, err := destination.Write(contents[:count])
		if err != nil {
			return err
		}
		if written != count {
			return io.ErrShortWrite
		}
		contents = contents[count:]
	}
	return ctx.Err()
}

func (materializer *FixtureMaterializer) build(ctx context.Context, root string, specification reachcontract.FixtureSpecification) error {
	build := specification.Build
	if build == nil {
		return nil
	}
	if materializer.platform() != "linux/amd64" || build.TargetPlatform != "linux/amd64" || build.Toolchain.TargetPlatform != "linux/amd64" || build.Toolchain.Resolution != reachcontract.FixtureToolchainMaterializerRequired {
		return errors.New("reachability fixture build requires the linux/amd64 materializer platform")
	}
	if err := prepareBuildOutputDirectories(root, *build); err != nil {
		return fmt.Errorf("prepare reachability fixture build outputs: %w", err)
	}
	environment, err := materializer.buildEnvironment(root, *build)
	if err != nil {
		return err
	}
	if err := materializer.probeToolchain(ctx, root, *build, environment); err != nil {
		return err
	}
	for index, step := range build.Steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, args, err := buildToolInvocation(root, specification, step)
		if err != nil {
			return fmt.Errorf("prepare reachability fixture build step %d: %w", index+1, err)
		}
		result, err := materializer.runner.Run(ctx, ports.ToolSpec{
			Name:           name,
			Args:           args,
			Timeout:        materializerBuildTimeout,
			MaxOutputBytes: materializerMaxOutputBytes,
			Env:            append([]string(nil), environment...),
		})
		if err := requireSuccessfulToolRun(ctx, result, err); err != nil {
			return fmt.Errorf("run reachability fixture build step %d: %w", index+1, err)
		}
	}
	return nil
}

// buildToolInvocation keeps fixture-local paths out of the shared process runner.
// The fixture specification was checked against the embedded frozen contract before
// materialization. Go accepts an argv-native directory switch; the other closed
// tool forms receive only verified absolute paths below the real materialization root.
func buildToolInvocation(root string, specification reachcontract.FixtureSpecification, step reachcontract.FixtureBuildStep) (string, []string, error) {
	frozen, _, err := frozenFixtureSpecification(specification)
	if err != nil {
		return "", nil, err
	}
	if frozen.Build == nil || !frozenBuildStep(*frozen.Build, step) {
		return "", nil, errors.New("reachability fixture build step is not frozen")
	}
	build := *frozen.Build
	name := step.Argv[0]
	args := append([]string(nil), step.Argv[1:]...)
	switch build.Kind {
	case reachcontract.FixtureBuildGoBinary:
		if name != "go" {
			return "", nil, errors.New("frozen Go fixture build has an unexpected tool")
		}
		invocation, err := goInvocationArgs(root, build.WorkingDirectory, args)
		if err != nil {
			return "", nil, err
		}
		return name, invocation, nil
	case reachcontract.FixtureBuildDotNetPublish:
		if name != "dotnet" {
			return "", nil, errors.New("frozen .NET fixture build has an unexpected tool")
		}
	case reachcontract.FixtureBuildJVMPackage:
		if name != "javac" && name != "jar" {
			return "", nil, errors.New("frozen JVM fixture build has an unexpected tool")
		}
	default:
		return "", nil, errors.New("unsupported frozen reachability fixture build kind")
	}
	rewritten, err := rewriteFrozenRootRelativeArgs(root, args)
	if err != nil {
		return "", nil, err
	}
	return name, rewritten, nil
}

func frozenBuildStep(build reachcontract.FixtureBuild, candidate reachcontract.FixtureBuildStep) bool {
	for _, step := range build.Steps {
		if len(step.Argv) != len(candidate.Argv) {
			continue
		}
		matches := true
		for index := range step.Argv {
			if step.Argv[index] != candidate.Argv[index] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func goInvocationArgs(root, workingDirectory string, args []string) ([]string, error) {
	workingRoot := root
	if workingDirectory != "." {
		var err error
		workingRoot, err = declaredPath(root, workingDirectory, false)
		if err != nil {
			return nil, fmt.Errorf("resolve reachability fixture Go working directory: %w", err)
		}
	}
	trustedRoot, err := benchcycle.RealDirectory(workingRoot)
	if err != nil {
		return nil, fmt.Errorf("validate reachability fixture Go root: %w", err)
	}
	rewritten, err := rewriteFrozenRootRelativeArgs(root, args)
	if err != nil {
		return nil, err
	}
	invocation := make([]string, 0, len(rewritten)+2)
	invocation = append(invocation, "-C", trustedRoot)
	invocation = append(invocation, rewritten...)
	return invocation, nil
}

func rewriteFrozenRootRelativeArgs(root string, args []string) ([]string, error) {
	rewritten := make([]string, len(args))
	for index, arg := range args {
		value, err := rewriteFrozenRootRelativeArg(root, arg)
		if err != nil {
			return nil, err
		}
		rewritten[index] = value
	}
	return rewritten, nil
}

func rewriteFrozenRootRelativeArg(root, arg string) (string, error) {
	if !strings.HasPrefix(arg, "./") {
		return arg, nil
	}
	if strings.Contains(arg, ":") {
		parts := strings.Split(arg, ":")
		for index, part := range parts {
			if !strings.HasPrefix(part, "./") {
				return "", errors.New("frozen JVM classpath contains a non-root-relative entry")
			}
			path, err := resolveFrozenRootRelativePath(root, part)
			if err != nil {
				return "", err
			}
			parts[index] = path
		}
		return strings.Join(parts, ":"), nil
	}
	return resolveFrozenRootRelativePath(root, arg)
}

func resolveFrozenRootRelativePath(root, arg string) (string, error) {
	if !strings.HasPrefix(arg, "./") {
		return "", errors.New("fixture build path is not root-relative")
	}
	relative := strings.TrimPrefix(arg, "./")
	if !fs.ValidPath(relative) || relative == "." {
		return "", fmt.Errorf("unsafe frozen fixture build path %q", arg)
	}
	path, err := declaredPath(root, relative, false)
	if err != nil {
		return "", fmt.Errorf("resolve frozen fixture build path %q: %w", arg, err)
	}
	return path, nil
}

func prepareBuildOutputDirectories(root string, build reachcontract.FixtureBuild) error {
	if len(build.Outputs) == 0 || len(build.Outputs) > maxMaterializedFiles {
		return errors.New("reachability fixture output count exceeds materializer bound")
	}
	for _, output := range build.Outputs {
		if _, err := declaredPath(root, output.Path, true); err != nil {
			return fmt.Errorf("prepare output %q: %w", output.Path, err)
		}
	}
	return nil
}

func (materializer *FixtureMaterializer) buildEnvironment(root string, build reachcontract.FixtureBuild) ([]string, error) {
	toolDirectories := map[string]struct{}{}
	for _, step := range build.Steps {
		if len(step.Argv) == 0 {
			return nil, errors.New("empty validated reachability fixture build step")
		}
		location, err := materializer.locateTool(step.Argv[0])
		if err != nil {
			return nil, fmt.Errorf("locate trusted reachability fixture tool %q: %w", step.Argv[0], err)
		}
		if !filepath.IsAbs(location) {
			return nil, fmt.Errorf("trusted reachability fixture tool %q has non-absolute location", step.Argv[0])
		}
		toolDirectories[filepath.Dir(location)] = struct{}{}
	}
	if len(toolDirectories) == 0 {
		return nil, errors.New("reachability fixture build has no trusted tools")
	}
	privateDirectories := []string{
		".materializer/home",
		".materializer/tmp",
		".materializer/cache",
		".materializer/cache/go-build",
		".materializer/cache/go-mod",
		".materializer/cache/go-path",
		".materializer/cache/nuget-packages",
		".materializer/cache/nuget-http",
		".materializer/config",
	}
	resolvedDirectories := make(map[string]string, len(privateDirectories))
	for _, relative := range privateDirectories {
		directory, err := ensurePrivateDirectory(root, relative)
		if err != nil {
			return nil, fmt.Errorf("create private reachability fixture directory: %w", err)
		}
		resolvedDirectories[relative] = directory
	}
	paths := make([]string, 0, len(toolDirectories))
	for directory := range toolDirectories {
		paths = append(paths, directory)
	}
	sort.Strings(paths)
	fixed := map[string]string{
		"PATH":                              strings.Join(paths, string(os.PathListSeparator)),
		"HOME":                              resolvedDirectories[".materializer/home"],
		"TMPDIR":                            resolvedDirectories[".materializer/tmp"],
		"TMP":                               resolvedDirectories[".materializer/tmp"],
		"TEMP":                              resolvedDirectories[".materializer/tmp"],
		"XDG_CACHE_HOME":                    resolvedDirectories[".materializer/cache"],
		"XDG_CONFIG_HOME":                   resolvedDirectories[".materializer/config"],
		"TZ":                                "UTC",
		"LC_ALL":                            "C",
		"LANG":                              "C",
		"SOURCE_DATE_EPOCH":                 "0",
		"GOENV":                             "off",
		"GOWORK":                            "off",
		"GOTOOLCHAIN":                       "local",
		"GOPROXY":                           "off",
		"GOSUMDB":                           "off",
		"GONOPROXY":                         "*",
		"GONOSUMDB":                         "*",
		"GOCACHE":                           resolvedDirectories[".materializer/cache/go-build"],
		"GOMODCACHE":                        resolvedDirectories[".materializer/cache/go-mod"],
		"GOPATH":                            resolvedDirectories[".materializer/cache/go-path"],
		"DOTNET_CLI_TELEMETRY_OPTOUT":       "1",
		"DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
		"DOTNET_NOLOGO":                     "1",
		"DOTNET_MULTILEVEL_LOOKUP":          "0",
		"DOTNET_CLI_HOME":                   resolvedDirectories[".materializer/home"],
		"NUGET_PACKAGES":                    resolvedDirectories[".materializer/cache/nuget-packages"],
		"NUGET_HTTP_CACHE_PATH":             resolvedDirectories[".materializer/cache/nuget-http"],
		"NUGET_XMLDOC_MODE":                 "skip",
	}
	for _, declared := range build.Env {
		if _, exists := fixed[declared.Key]; exists {
			return nil, fmt.Errorf("reachability fixture build environment duplicates protected key %q", declared.Key)
		}
		if declared.Value != strings.TrimSpace(declared.Value) || len(declared.Value) > 512 || strings.Contains(declared.Value, "\x00") {
			return nil, fmt.Errorf("reachability fixture build environment has invalid value for %q", declared.Key)
		}
		fixed[declared.Key] = declared.Value
	}
	keys := make([]string, 0, len(fixed))
	for key := range fixed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+fixed[key])
	}
	return environment, nil
}

func (materializer *FixtureMaterializer) probeToolchain(ctx context.Context, root string, build reachcontract.FixtureBuild, environment []string) error {
	name, args := toolchainProbe(build.Toolchain.Family)
	if name == "" {
		return fmt.Errorf("unsupported reachability fixture toolchain family %q", build.Toolchain.Family)
	}
	if name == "go" {
		var err error
		args, err = goInvocationArgs(root, build.WorkingDirectory, args)
		if err != nil {
			return err
		}
	}
	result, err := materializer.runner.Run(ctx, ports.ToolSpec{
		Name:           name,
		Args:           args,
		Timeout:        materializerProbeTimeout,
		MaxOutputBytes: materializerMaxOutputBytes,
		Env:            append([]string(nil), environment...),
	})
	if err := requireSuccessfulToolRun(ctx, result, err); err != nil {
		return fmt.Errorf("probe reachability fixture toolchain %q: %w", build.Toolchain.Family, err)
	}
	if !matchingToolchainVersion(build.Toolchain.Family, build.Toolchain.Version, result) {
		return fmt.Errorf("reachability fixture toolchain %q version does not match required %q", build.Toolchain.Family, build.Toolchain.Version)
	}
	return nil
}

func toolchainProbe(family string) (string, []string) {
	switch family {
	case "go":
		return "go", []string{"version"}
	case "dotnet-sdk":
		return "dotnet", []string{"--version"}
	case "openjdk":
		return "javac", []string{"-version"}
	default:
		return "", nil
	}
}

func matchingToolchainVersion(family, version string, result ports.ToolResult) bool {
	stdout := strings.TrimSpace(string(result.Stdout))
	stderr := strings.TrimSpace(string(result.Stderr))
	switch family {
	case "go":
		return stderr == "" && stdout == "go version go"+version+" linux/amd64"
	case "dotnet-sdk":
		return stderr == "" && stdout == version
	case "openjdk":
		return (stdout == "javac "+version && stderr == "") || (stderr == "javac "+version && stdout == "")
	default:
		return false
	}
}

func requireSuccessfulToolRun(ctx context.Context, result ports.ToolResult, runErr error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if runErr != nil {
		return runErr
	}
	if result.TimedOut {
		return errors.New("tool execution timed out")
	}
	if result.Truncated {
		return errors.New("tool execution output was truncated")
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("tool execution exited with status %d", result.ExitCode)
	}
	return nil
}

func verifyMaterializedOutputs(ctx context.Context, root string, build reachcontract.FixtureBuild) ([]MaterializedArtifact, error) {
	if len(build.Outputs) == 0 || len(build.Outputs) > maxMaterializedFiles {
		return nil, errors.New("reachability fixture output count exceeds materializer bound")
	}
	outputs := make([]MaterializedArtifact, 0, len(build.Outputs))
	seen := make(map[string]struct{}, len(build.Outputs))
	var total int64
	for _, output := range build.Outputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, exists := seen[output.Path]; exists {
			return nil, fmt.Errorf("duplicate reachability fixture output %q", output.Path)
		}
		seen[output.Path] = struct{}{}
		identity, err := digestDeclaredRegularFile(ctx, root, output.Path, maxMaterializedOutputBytes)
		if err != nil {
			return nil, fmt.Errorf("verify reachability fixture output %q: %w", output.Path, err)
		}
		total += identity.Size
		if total > maxMaterializedTotalBytes {
			return nil, fmt.Errorf("reachability fixture outputs exceed %d bytes", maxMaterializedTotalBytes)
		}
		outputPath, err := resolveDeclaredRegularFile(root, output.Path)
		if err != nil {
			return nil, fmt.Errorf("revalidate reachability fixture output %q before restricting permissions: %w", output.Path, err)
		}
		if err := os.Chmod(outputPath, 0o600); err != nil {
			return nil, fmt.Errorf("restrict reachability fixture output %q: %w", output.Path, err)
		}
		outputs = append(outputs, identity)
	}
	return canonicalMaterializedArtifacts(outputs, maxMaterializedOutputBytes)
}

func digestDeclaredRegularFile(ctx context.Context, root, relative string, maxBytes int64) (MaterializedArtifact, error) {
	path, err := resolveDeclaredRegularFile(root, relative)
	if err != nil {
		return MaterializedArtifact{}, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return MaterializedArtifact{}, err
	}
	if before.Size() > maxBytes {
		return MaterializedArtifact{}, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return MaterializedArtifact{}, err
	}
	hash := sha256.New()
	buffer := make([]byte, copyBufferSize)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return MaterializedArtifact{}, err
		}
		count, readErr := file.Read(buffer)
		if count > 0 {
			size += int64(count)
			if size > maxBytes {
				_ = file.Close()
				return MaterializedArtifact{}, fmt.Errorf("file exceeds %d bytes", maxBytes)
			}
			if _, err := hash.Write(buffer[:count]); err != nil {
				_ = file.Close()
				return MaterializedArtifact{}, err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = file.Close()
			return MaterializedArtifact{}, readErr
		}
	}
	if err := file.Close(); err != nil {
		return MaterializedArtifact{}, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return MaterializedArtifact{}, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return MaterializedArtifact{}, errors.New("file changed during read")
	}
	if size != before.Size() {
		return MaterializedArtifact{}, errors.New("file size changed during read")
	}
	return MaterializedArtifact{Path: relative, Size: size, Digest: "sha256:" + hex.EncodeToString(hash.Sum(nil))}, nil
}

func resolveDeclaredRegularFile(root, relative string) (string, error) {
	path, err := declaredPath(root, relative, false)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("declared fixture path is not a regular non-symlink file")
	}
	return path, nil
}

func declaredPath(root, relative string, createParents bool) (string, error) {
	if !fs.ValidPath(relative) {
		return "", fmt.Errorf("unsafe declared fixture path %q", relative)
	}
	trustedRoot, err := benchcycle.RealDirectory(root)
	if err != nil {
		return "", err
	}
	parts := strings.Split(relative, "/")
	current := trustedRoot
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		if createParents {
			info, err := os.Lstat(current)
			if os.IsNotExist(err) {
				if err := os.Mkdir(current, 0o700); err != nil {
					return "", err
				}
				info, err = os.Lstat(current)
			}
			if err != nil {
				return "", err
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return "", errors.New("declared fixture parent is not a real directory")
			}
			if err := os.Chmod(current, 0o700); err != nil {
				return "", err
			}
			continue
		}
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("declared fixture parent is not a real directory")
		}
	}
	path := filepath.Join(current, parts[len(parts)-1])
	relativePath, err := filepath.Rel(trustedRoot, path)
	if err != nil || relativePath == "." || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return "", errors.New("declared fixture path escapes work root")
	}
	return path, nil
}

func ensurePrivateDirectory(root, relative string) (string, error) {
	if !fs.ValidPath(relative) {
		return "", fmt.Errorf("unsafe private directory path %q", relative)
	}
	trustedRoot, err := benchcycle.RealDirectory(root)
	if err != nil {
		return "", err
	}
	current := trustedRoot
	for _, part := range strings.Split(relative, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return "", err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("private fixture path is not a real directory")
		}
		if err := os.Chmod(current, 0o700); err != nil {
			return "", err
		}
	}
	return current, nil
}

func canonicalMaterializedArtifacts(artifacts []MaterializedArtifact, maxBytes int64) ([]MaterializedArtifact, error) {
	if len(artifacts) > maxMaterializedFiles {
		return nil, fmt.Errorf("artifact count exceeds %d", maxMaterializedFiles)
	}
	canonical := append([]MaterializedArtifact(nil), artifacts...)
	sort.Slice(canonical, func(left, right int) bool { return canonical[left].Path < canonical[right].Path })
	var total int64
	for index, artifact := range canonical {
		if !fs.ValidPath(artifact.Path) || artifact.Size < 0 || artifact.Size > maxBytes || !validDigest(artifact.Digest) {
			return nil, fmt.Errorf("invalid materialized artifact %q", artifact.Path)
		}
		if index > 0 && artifact.Path == canonical[index-1].Path {
			return nil, fmt.Errorf("duplicate materialized artifact %q", artifact.Path)
		}
		total += artifact.Size
		if total > maxMaterializedTotalBytes {
			return nil, fmt.Errorf("materialized artifacts exceed %d bytes", maxMaterializedTotalBytes)
		}
	}
	return canonical, nil
}

func cloneMaterializedSpecification(specification reachcontract.FixtureSpecification) reachcontract.FixtureSpecification {
	clone := specification
	clone.Files = append([]reachcontract.FixtureFile(nil), specification.Files...)
	clone.Entries = append([]reachcontract.FixtureEntry(nil), specification.Entries...)
	clone.Subjects = append([]reachcontract.FixtureSubject(nil), specification.Subjects...)
	if specification.Build != nil {
		build := *specification.Build
		build.Steps = append([]reachcontract.FixtureBuildStep(nil), specification.Build.Steps...)
		for index := range build.Steps {
			build.Steps[index].Argv = append([]string(nil), build.Steps[index].Argv...)
		}
		build.Env = append([]reachcontract.FixtureBuildEnv(nil), specification.Build.Env...)
		build.Outputs = append([]reachcontract.FixtureOutput(nil), specification.Build.Outputs...)
		clone.Build = &build
	}
	return clone
}

func materializedInputPaths(specification reachcontract.FixtureSpecification) map[string]string {
	paths := make(map[string]string, len(specification.Files))
	for _, file := range specification.Files {
		path := file.Path
		if file.MaterializedPath != "" {
			path = file.MaterializedPath
		}
		paths[file.Path] = path
	}
	return paths
}

func materializedOutputPaths(specification reachcontract.FixtureSpecification) map[string]struct{} {
	if specification.Build == nil {
		return map[string]struct{}{}
	}
	paths := make(map[string]struct{}, len(specification.Build.Outputs))
	for _, output := range specification.Build.Outputs {
		paths[output.Path] = struct{}{}
	}
	return paths
}
