//go:build linux

package scabench

import (
	"context"
	"fmt"
	"strings"
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

func TestDigestPinnedOCITargetRunnerAcceptsNormalizedRepoDigestAttestation(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		inspected string
	}{
		{
			name:      "Docker Hub official image omits registry, library namespace, and tag",
			requested: "docker.io/library/debian:12.13-slim@" + digestByte('e'),
			inspected: "debian@" + digestByte('e'),
		},
		{
			name:      "Docker Hub library alias matches index registry alias",
			requested: "library/debian:12.13-slim@" + digestByte('f'),
			inspected: "index.docker.io/library/debian@" + digestByte('f'),
		},
		{
			name:      "Docker Hub index registry alias matches Docker registry alias",
			requested: "index.docker.io/library/debian:12.13-slim@" + digestByte('0'),
			inspected: "docker.io/library/debian@" + digestByte('0'),
		},
		{
			name:      "non Docker Hub image omits only tag",
			requested: "registry.suse.com/bci/bci-base:15.6@" + digestByte('f'),
			inspected: "registry.suse.com/bci/bci-base@" + digestByte('f'),
		},
		{
			name:      "registry port remains repository identity",
			requested: "registry.example.test:5000/benchmark/target:1.0@" + digestByte('1'),
			inspected: "registry.example.test:5000/benchmark/target@" + digestByte('1'),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			digest := test.requested[strings.LastIndexByte(test.requested, '@')+1:]
			fake := &ociTargetRunnerFake{results: []ports.ToolResult{
				{Stdout: []byte(`{"RepoDigests":["` + test.inspected + `"],"Os":"linux","Architecture":"amd64"}`)},
				{ExitCode: 0},
			}}
			runner, err := NewDigestPinnedOCITargetRunner(fake, test.requested, digest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runner.Run(context.Background(), ports.ToolSpec{Name: "/usr/bin/dpkg", Args: []string{"--compare-versions", "1", "lt", "2"}, MaxOutputBytes: 16 << 10}); err != nil {
				t.Fatalf("target OCI runner rejected normalized repo digest attestation: %v", err)
			}
		})
	}
}

func TestDigestPinnedOCITargetRunnerRejectsIncorrectOrMalformedRepoDigestAttestation(t *testing.T) {
	digest := digestByte('2')
	tests := []struct {
		name      string
		requested string
		inspected string
	}{
		{
			name:      "Docker Hub wrong repository at exact digest",
			requested: "docker.io/library/debian:12.13-slim@" + digest,
			inspected: "ubuntu@" + digest,
		},
		{
			name:      "non Docker Hub wrong repository at exact digest",
			requested: "registry.suse.com/bci/bci-base:15.6@" + digest,
			inspected: "registry.suse.com/bci/bci-micro@" + digest,
		},
		{
			name:      "registry port omitted at exact digest",
			requested: "registry.example.test:5000/benchmark/target:1.0@" + digest,
			inspected: "registry.example.test/benchmark/target@" + digest,
		},
		{
			name:      "wrong digest at exact repository",
			requested: "registry.suse.com/bci/bci-base:15.6@" + digest,
			inspected: "registry.suse.com/bci/bci-base@" + digestByte('3'),
		},
		{
			name:      "malformed inspected reference",
			requested: "registry.suse.com/bci/bci-base:15.6@" + digest,
			inspected: "registry.suse.com/bci/bci-base@" + digest + "@unexpected",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &ociTargetRunnerFake{results: []ports.ToolResult{{Stdout: []byte(`{"RepoDigests":["` + test.inspected + `"],"Os":"linux","Architecture":"amd64"}`)}}}
			runner, err := NewDigestPinnedOCITargetRunner(fake, test.requested, digest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runner.Run(context.Background(), ports.ToolSpec{Name: "/usr/bin/dpkg", Args: []string{"--compare-versions", "1", "lt", "2"}, MaxOutputBytes: 16 << 10}); err == nil {
				t.Fatal("target OCI runner accepted an incorrect repo digest attestation")
			}
			if len(fake.specs) != 1 {
				t.Fatalf("target OCI runner executed after failed image inspection: %+v", fake.specs)
			}
		})
	}
}

func TestNewDigestPinnedOCITargetRunnerRejectsMalformedImageReference(t *testing.T) {
	digest := digestByte('4')
	if _, err := NewDigestPinnedOCITargetRunner(&ociTargetRunnerFake{}, "docker.io/library/debian@unexpected@"+digest, digest); err == nil {
		t.Fatal("target OCI runner accepted a malformed digest-pinned image reference")
	}
}

func TestDigestPinnedOCITargetRunnerRejectsIncompleteImageInspection(t *testing.T) {
	digest := digestByte('5')
	image := "registry.suse.com/bci/bci-base:15.6@" + digest
	tests := []struct {
		name   string
		result ports.ToolResult
	}{
		{name: "nonzero exit", result: ports.ToolResult{ExitCode: 1}},
		{name: "timeout", result: ports.ToolResult{TimedOut: true}},
		{name: "truncated output", result: ports.ToolResult{Truncated: true}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &ociTargetRunnerFake{results: []ports.ToolResult{test.result}}
			runner, err := NewDigestPinnedOCITargetRunner(fake, image, digest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runner.Run(context.Background(), ports.ToolSpec{Name: "/usr/bin/dpkg", Args: []string{"--compare-versions", "1", "lt", "2"}, MaxOutputBytes: 16 << 10}); err == nil {
				t.Fatal("target OCI runner accepted an incomplete image inspection")
			}
			if len(fake.specs) != 1 {
				t.Fatalf("target OCI runner executed after incomplete image inspection: %+v", fake.specs)
			}
		})
	}
}
