//go:build linux

package scabench

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/google/go-containerregistry/pkg/name"
)

const (
	ociTargetPlatform  = "linux/amd64"
	ociTargetPidsLimit = "32"
	ociTargetMemory    = "256m"
)

// DigestPinnedOCITargetRunner executes only target-native package utilities in
// a locally resolved, digest-pinned OCI image. It is deliberately separate
// from the Bubblewrap scanner runner, whose /usr is the host filesystem.
type DigestPinnedOCITargetRunner struct {
	docker       ports.ToolRunner
	imageRef     string
	repository   string
	targetDigest string
}

type inspectedOCIImage struct {
	RepoDigests  []string `json:"RepoDigests"`
	OS           string   `json:"Os"`
	Architecture string   `json:"Architecture"`
}

var _ ports.ToolRunner = (*DigestPinnedOCITargetRunner)(nil)

func NewDigestPinnedOCITargetRunner(docker ports.ToolRunner, imageRef, targetDigest string) (*DigestPinnedOCITargetRunner, error) {
	if docker == nil {
		return nil, fmt.Errorf("target OCI runner requires a Docker runner")
	}
	repository, digest, ok := normalizedPinnedOCIRepository(imageRef)
	if !validNativeDigest(targetDigest) || !ok || digest != targetDigest {
		return nil, fmt.Errorf("target OCI runner requires an exact digest-pinned image reference")
	}
	return &DigestPinnedOCITargetRunner{docker: docker, imageRef: imageRef, repository: repository, targetDigest: targetDigest}, nil
}

func (runner *DigestPinnedOCITargetRunner) Run(ctx context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	if runner == nil || runner.docker == nil {
		return ports.ToolResult{}, fmt.Errorf("target OCI runner is unavailable")
	}
	if err := validateTargetNativeSpec(spec); err != nil {
		return ports.ToolResult{}, err
	}
	if err := runner.verifyLocalImage(ctx); err != nil {
		return ports.ToolResult{}, err
	}
	args := []string{
		"run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--pids-limit=" + ociTargetPidsLimit, "--memory=" + ociTargetMemory, "--platform=" + ociTargetPlatform,
	}
	for _, value := range spec.Env {
		args = append(args, "--env", value)
	}
	args = append(args, "--entrypoint", spec.Name, runner.imageRef)
	args = append(args, spec.Args...)
	result, err := runner.docker.Run(ctx, ports.ToolSpec{Name: "docker", Args: args, Timeout: spec.Timeout, MaxOutputBytes: spec.MaxOutputBytes})
	if err != nil {
		return result, fmt.Errorf("run target-native OCI command: %w", err)
	}
	if result.TimedOut || result.Truncated {
		return result, fmt.Errorf("target-native OCI command did not complete")
	}
	return result, nil
}

func (runner *DigestPinnedOCITargetRunner) verifyLocalImage(ctx context.Context) error {
	result, err := runner.docker.Run(ctx, ports.ToolSpec{Name: "docker", Args: []string{"image", "inspect", "--format", "{{json .}}", runner.imageRef}, MaxOutputBytes: 64 << 10})
	if err != nil {
		return fmt.Errorf("inspect target OCI image: %w", err)
	}
	if result.ExitCode != 0 || result.TimedOut || result.Truncated {
		return fmt.Errorf("inspect target OCI image did not complete")
	}
	var image inspectedOCIImage
	if err := json.Unmarshal(result.Stdout, &image); err != nil {
		return fmt.Errorf("decode target OCI image identity: %w", err)
	}
	if image.OS != "linux" || image.Architecture != "amd64" {
		return fmt.Errorf("local target OCI image platform is %q/%q, want linux/amd64", image.OS, image.Architecture)
	}
	for _, reference := range image.RepoDigests {
		repository, digest, ok := normalizedPinnedOCIRepository(reference)
		if ok && repository == runner.repository && digest == runner.targetDigest {
			return nil
		}
	}
	return fmt.Errorf("local target OCI image does not attest the requested exact repo digest")
}

func normalizedPinnedOCIRepository(reference string) (string, string, bool) {
	if reference == "" || strings.TrimSpace(reference) != reference {
		return "", "", false
	}
	at := strings.LastIndexByte(reference, '@')
	if at <= 0 || at == len(reference)-1 || strings.Contains(reference[:at], "@") {
		return "", "", false
	}
	parsed, err := name.ParseReference(reference)
	if err != nil {
		return "", "", false
	}
	digest, ok := parsed.(name.Digest)
	if !ok || !validNativeDigest(digest.DigestStr()) {
		return "", "", false
	}
	return digest.Context().Name(), digest.DigestStr(), true
}

func validateTargetNativeSpec(spec ports.ToolSpec) error {
	if spec.Name != "/usr/bin/dpkg" && spec.Name != "/usr/bin/rpm" || len(spec.Args) == 0 || len(spec.Stdin) != 0 || spec.Workdir != "" || len(spec.ReadOnlyPaths) != 0 || len(spec.ExtraFiles) != 0 || spec.Started != nil || len(spec.CapAdd) != 0 || spec.MemMaxBytes != 0 || spec.PidsMax != 0 || spec.EgressPolicy != nil || spec.EgressExecutionKind != "" || spec.EgressExecutionID != "" || spec.HostNetwork {
		return fmt.Errorf("target OCI runner rejected an unsafe native comparison specification")
	}
	for _, value := range spec.Env {
		key, raw, ok := strings.Cut(value, "=")
		if !ok || !validTargetEnvironmentKey(key) || containsNativeControl(raw) {
			return fmt.Errorf("target OCI runner rejected an invalid native comparison environment value")
		}
	}
	return nil
}

func validTargetEnvironmentKey(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if character == '_' || unicode.IsLetter(character) || index > 0 && unicode.IsDigit(character) {
			continue
		}
		return false
	}
	return true
}
