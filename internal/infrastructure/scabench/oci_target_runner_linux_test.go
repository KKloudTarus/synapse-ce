//go:build linux

package scabench

import (
	"context"
	"fmt"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ociTargetRunnerFake struct {
	specs   []ports.ToolSpec
	results []ports.ToolResult
}

func (runner *ociTargetRunnerFake) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	runner.specs = append(runner.specs, spec)
	if len(runner.results) == 0 {
		return ports.ToolResult{}, fmt.Errorf("unexpected Docker invocation")
	}
	result := runner.results[0]
	runner.results = runner.results[1:]
	return result, nil
}

func TestDigestPinnedOCITargetRunnerVerifiesImageAndUsesHardenedArgv(t *testing.T) {
	digest := digestByte('a')
	image := "registry.example.test/target@" + digest
	fake := &ociTargetRunnerFake{results: []ports.ToolResult{{Stdout: []byte(`{"RepoDigests":["` + image + `"],"Os":"linux","Architecture":"amd64"}`)}, {ExitCode: 0}}}
	runner, err := NewDigestPinnedOCITargetRunner(fake, image, digest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runner.Run(context.Background(), ports.ToolSpec{Name: "/usr/bin/rpm", Args: []string{"--eval", "constant"}, Env: []string{"SYNAPSE_SCA_RPM_LEFT_EVR=1:1-1", "SYNAPSE_SCA_RPM_RIGHT_EVR=1:2-1"}, MaxOutputBytes: 16 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.specs) != 2 {
		t.Fatalf("Docker invocation count = %d", len(fake.specs))
	}
	if got := fmt.Sprint(fake.specs[0].Args); got != fmt.Sprint([]string{"image", "inspect", "--format", "{{json .}}", image}) {
		t.Fatalf("image inspect argv = %s", got)
	}
	want := []string{"run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=32", "--memory=256m", "--platform=linux/amd64", "--env", "SYNAPSE_SCA_RPM_LEFT_EVR=1:1-1", "--env", "SYNAPSE_SCA_RPM_RIGHT_EVR=1:2-1", "--entrypoint", "/usr/bin/rpm", image, "--eval", "constant"}
	if got := fmt.Sprint(fake.specs[1].Args); got != fmt.Sprint(want) {
		t.Fatalf("target OCI argv = %s, want %s", got, fmt.Sprint(want))
	}
}

func TestDigestPinnedOCITargetRunnerRejectsMismatchedLocalImage(t *testing.T) {
	digest := digestByte('b')
	image := "registry.example.test/target@" + digest
	fake := &ociTargetRunnerFake{results: []ports.ToolResult{{Stdout: []byte(`{"RepoDigests":["registry.example.test/target@` + digestByte('c') + `"],"Os":"linux","Architecture":"amd64"}`)}}}
	runner, err := NewDigestPinnedOCITargetRunner(fake, image, digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), ports.ToolSpec{Name: "/usr/bin/dpkg", Args: []string{"--compare-versions", "1", "lt", "2"}, MaxOutputBytes: 16 << 10}); err == nil {
		t.Fatal("target OCI runner accepted an image at another digest")
	}
	if len(fake.specs) != 1 {
		t.Fatalf("target OCI runner executed after failed image inspection: %+v", fake.specs)
	}
}

func TestDigestPinnedOCITargetRunnerRejectsImageWithUnexpectedPlatform(t *testing.T) {
	digest := digestByte('d')
	image := "registry.example.test/target@" + digest
	fake := &ociTargetRunnerFake{results: []ports.ToolResult{{Stdout: []byte(`{"RepoDigests":["` + image + `"],"Os":"linux","Architecture":"arm64"}`)}}}
	runner, err := NewDigestPinnedOCITargetRunner(fake, image, digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), ports.ToolSpec{Name: "/usr/bin/dpkg", Args: []string{"--compare-versions", "1", "lt", "2"}, MaxOutputBytes: 16 << 10}); err == nil {
		t.Fatal("target OCI runner accepted an image with an unexpected platform")
	}
	if len(fake.specs) != 1 {
		t.Fatalf("target OCI runner executed after failed platform attestation: %+v", fake.specs)
	}
}
