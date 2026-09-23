// Command synapse-sca-cycle runs fixed SCA benchmark cycles.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func main() {
	os.Exit(executeCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func executeCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: synapse-sca-cycle {run|candidate} [flags]")
		return 1
	}
	switch args[0] {
	case "run":
		return executeTrustedCLI(args[1:], stdout, stderr)
	case "candidate":
		return executeCandidateCLI(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintln(stderr, "usage: synapse-sca-cycle {run|candidate} [flags]")
		return 1
	}
}

func executeTrustedCLI(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("synapse-sca-cycle run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	corpusRoot := flags.String("corpus-root", "", "absolute frozen corpus root")
	trustedInputRoot := flags.String("trusted-input-root", "", "absolute trusted input root")
	outputRoot := flags.String("output-root", "", "absolute sanitized output root")
	rawRetentionRoot := flags.String("raw-retention-root", "", "absolute protected raw retention root")
	implementationCommit := flags.String("implementation-commit", "", "exact 40-character implementation SHA")
	runKey := flags.String("run-key", "", "run and attempt identifier")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: positional arguments are not supported")
		return 1
	}
	_, err := capture.Run(context.Background(), capture.RunInput{
		CorpusRoot: *corpusRoot, TrustedInputRoot: *trustedInputRoot, OutputRoot: *outputRoot,
		RawRetentionRoot: *rawRetentionRoot, ImplementationCommit: *implementationCommit, RunKey: *runKey,
	}, capture.RunnerFactory(productionRunner))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "SCA benchmark cycle completed")
	return 0
}

func executeCandidateCLI(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("synapse-sca-cycle candidate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	offlineInputRoot := flags.String("offline-input-root", "", "absolute prepared offline input root")
	evidenceRoot := flags.String("evidence-root", "", "absolute protected evidence root")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if flags.NArg() != 0 || *offlineInputRoot == "" || *evidenceRoot == "" {
		_, _ = fmt.Fprintln(stderr, "usage: synapse-sca-cycle candidate --offline-input-root PATH --evidence-root PATH")
		return 1
	}
	workingDir, err := os.Getwd()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle candidate:", err)
		return 1
	}
	corpusRoot, implementationCommit, err := candidateCheckout(workingDir)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle candidate:", err)
		return 1
	}
	runKey, err := candidateRunKey()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle candidate:", err)
		return 1
	}
	result, err := capture.RunCandidate(context.Background(), capture.CandidateInput{
		SourceRoot: workingDir, CorpusRoot: corpusRoot, OfflineInputRoot: *offlineInputRoot,
		EvidenceRoot: *evidenceRoot, ImplementationCommit: implementationCommit, RunKey: runKey,
	}, capture.RunnerFactory(productionRunner))
	if result.EvidencePath != "" {
		_, _ = fmt.Fprintln(stdout, "Candidate evidence:", result.EvidencePath)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle candidate:", err)
		if result.Candidate != nil && !result.Gate.CandidatePassed {
			return 2
		}
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "Unsigned candidate cycle completed; results are diagnostic, not accepted")
	return 0
}

func candidateCheckout(workingDir string) (string, string, error) {
	rootOutput, err := exec.Command("git", "-C", workingDir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", "", fmt.Errorf("locate source checkout: %w", err)
	}
	root := strings.TrimSpace(string(rootOutput))
	if !filepath.IsAbs(root) {
		return "", "", errors.New("source checkout path is not absolute")
	}
	if filepath.Clean(workingDir) != filepath.Clean(root) {
		return "", "", errors.New("run candidate from the source checkout root")
	}
	status, err := exec.Command("git", "-C", root, "status", "--porcelain", "--untracked-files=all").Output()
	if err != nil {
		return "", "", fmt.Errorf("check source checkout cleanliness: %w", err)
	}
	if len(status) != 0 {
		return "", "", errors.New("candidate requires a clean source checkout")
	}
	commitOutput, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", "", fmt.Errorf("identify source commit: %w", err)
	}
	commit := strings.TrimSpace(string(commitOutput))
	if len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" {
		return "", "", errors.New("candidate requires a full lowercase SHA-1 source commit")
	}
	return filepath.Join(root, "internal", "usecase", "scabench", "corpus"), commit, nil
}

func candidateRunKey() (string, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate candidate run key: %w", err)
	}
	return "candidate/" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(nonce[:]), nil
}

func productionRunner(limits capture.RuntimeLimits) (ports.ToolRunner, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("hardened sandbox requires Linux")
	}
	delegatedRoot := os.Getenv("SCA_ACCURACY_DELEGATED_CGROUP_ROOT")
	if strings.TrimSpace(delegatedRoot) == "" {
		return nil, errors.New("hardened sandbox requires SCA_ACCURACY_DELEGATED_CGROUP_ROOT captured from the delegated service")
	}
	ready, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runner, err := sandbox.NewDirectCgroupRunnerReadyAt(ready, time.Duration(limits.TimeoutSeconds)*time.Second, limits.MaxOutputBytes, limits.MemoryBytes, limits.PIDsMax, 250*time.Millisecond, delegatedRoot)
	if err != nil {
		return nil, err
	}
	if runner.ControlSetIdentity() != capture.SandboxIdentityBubblewrapSeccompCgroupV2 {
		return nil, errors.New("required sandbox control set is unavailable")
	}
	return runner, nil
}
