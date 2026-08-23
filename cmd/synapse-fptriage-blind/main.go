// Command synapse-fptriage-blind manages offline blinded human review packets for an existing shadow
// evaluation report. It never invokes an LLM or changes a quality-gate decision.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func main() {
	mode := flag.String("mode", "", "export, import, or join")
	datasetPath := flag.String("dataset", "", "locked evaluation dataset JSON (export and join)")
	reportPath := flag.String("report", "", "locked shadow evaluation report JSON")
	packetPath := flag.String("packet", "", "blind packet JSON (import and join)")
	submissionPath := flag.String("submission", "", "reviewer decision submission JSON (import) or authenticated receipt JSON (join)")
	reviewer := flag.String("reviewer", "", "trusted-boundary human reviewer identity (import only; never read from submission JSON)")
	humanReviewersPath := flag.String("human-reviewers", "", "private operator-owned allowlist file, one human reviewer identity per line")
	authKeyPath := flag.String("auth-key-file", "", "private operator HMAC key file, at least 32 bytes")
	seed := flag.String("seed", "", "private reproducibility seed (export only)")
	outputPath := flag.String("output", "", "new output artifact path")
	flag.Parse()

	if err := run(*mode, *datasetPath, *reportPath, *packetPath, *submissionPath, *seed, *reviewer, *humanReviewersPath, *authKeyPath, *outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "synapse-fptriage-blind: %v\n", err)
		os.Exit(1)
	}
}

func run(mode, datasetPath, reportPath, packetPath, submissionPath, seed, reviewer, humanReviewersPath, authKeyPath, outputPath string) error {
	mode = strings.TrimSpace(mode)
	if mode != "export" && mode != "import" && mode != "join" {
		return fmt.Errorf("--mode must be export, import, or join")
	}
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" || outputPath == "-" {
		return fmt.Errorf("--output must be a new private file path")
	}
	if _, err := os.Lstat(outputPath); err == nil || !os.IsNotExist(err) {
		return fmt.Errorf("--output must be a new private file path")
	}
	authenticator, err := loadAuthenticator(authKeyPath)
	if err != nil {
		return err
	}
	allowedHumanReviewers, err := loadHumanReviewers(humanReviewersPath)
	if err != nil {
		return err
	}
	var value any
	switch mode {
	case "export":
		dataset, report, err := loadDatasetAndReport(datasetPath, reportPath)
		if err != nil {
			return err
		}
		packet, err := sca.ExportBlindFPTriagePacket(dataset, report, seed, authenticator)
		if err != nil {
			return err
		}
		value = packet
	case "import":
		packet, err := loadPacket(packetPath)
		if err != nil {
			return err
		}
		report, err := loadReport(reportPath)
		if err != nil {
			return err
		}
		submission, err := loadSubmission(submissionPath)
		if err != nil {
			return err
		}
		imported, err := sca.ImportBlindFPTriageSubmission(packet, submission, reviewer, allowedHumanReviewers, report.Run.ProposerModel, report.Run.VerifierModel, authenticator)
		if err != nil {
			return err
		}
		value = imported
	case "join":
		dataset, report, err := loadDatasetAndReport(datasetPath, reportPath)
		if err != nil {
			return err
		}
		packet, err := loadPacket(packetPath)
		if err != nil {
			return err
		}
		submission, err := loadImportedSubmission(submissionPath)
		if err != nil {
			return err
		}
		joined, err := sca.JoinBlindFPTriageSubmission(dataset, report, packet, submission, allowedHumanReviewers, authenticator)
		if err != nil {
			return err
		}
		value = joined
	default:
		return fmt.Errorf("--mode must be export, import, or join")
	}
	return writePrivateJSON(outputPath, value)
}

func loadDatasetAndReport(datasetPath, reportPath string) (sca.AIEvaluationDataset, sca.AIEvaluationReport, error) {
	if strings.TrimSpace(datasetPath) == "" || strings.TrimSpace(reportPath) == "" {
		return sca.AIEvaluationDataset{}, sca.AIEvaluationReport{}, fmt.Errorf("--dataset and --report are required")
	}
	datasetBytes, err := os.ReadFile(datasetPath)
	if err != nil {
		return sca.AIEvaluationDataset{}, sca.AIEvaluationReport{}, fmt.Errorf("read dataset: %w", err)
	}
	dataset, err := sca.LoadAIEvaluationDataset(datasetBytes)
	if err != nil {
		return sca.AIEvaluationDataset{}, sca.AIEvaluationReport{}, err
	}
	report, err := loadReport(reportPath)
	if err != nil {
		return sca.AIEvaluationDataset{}, sca.AIEvaluationReport{}, err
	}
	return dataset, report, nil
}

func loadReport(path string) (sca.AIEvaluationReport, error) {
	if strings.TrimSpace(path) == "" {
		return sca.AIEvaluationReport{}, fmt.Errorf("--report is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return sca.AIEvaluationReport{}, fmt.Errorf("read evaluation report: %w", err)
	}
	report, err := sca.LoadAIEvaluationReport(b)
	if err != nil {
		return sca.AIEvaluationReport{}, fmt.Errorf("load evaluation report: %w", err)
	}
	return report, nil
}

func loadPacket(path string) (sca.BlindFPTriagePacket, error) {
	if strings.TrimSpace(path) == "" {
		return sca.BlindFPTriagePacket{}, fmt.Errorf("--packet is required")
	}
	var packet sca.BlindFPTriagePacket
	if err := readStrictJSON(path, &packet); err != nil {
		return packet, fmt.Errorf("read blind packet: %w", err)
	}
	return packet, nil
}

func loadSubmission(path string) (sca.BlindFPTriageSubmission, error) {
	if strings.TrimSpace(path) == "" {
		return sca.BlindFPTriageSubmission{}, fmt.Errorf("--submission is required")
	}
	var submission sca.BlindFPTriageSubmission
	if err := readStrictJSON(path, &submission); err != nil {
		return submission, fmt.Errorf("read blind submission: %w", err)
	}
	return submission, nil
}

func loadImportedSubmission(path string) (sca.BlindFPTriageImportedSubmission, error) {
	if strings.TrimSpace(path) == "" {
		return sca.BlindFPTriageImportedSubmission{}, fmt.Errorf("--submission is required")
	}
	var submission sca.BlindFPTriageImportedSubmission
	if err := readStrictJSON(path, &submission); err != nil {
		return submission, fmt.Errorf("read authenticated blind submission: %w", err)
	}
	return submission, nil
}

func loadAuthenticator(path string) (sca.BlindFPTriageAuthenticator, error) {
	if strings.TrimSpace(path) == "" {
		return sca.BlindFPTriageAuthenticator{}, fmt.Errorf("--auth-key-file is required")
	}
	if err := requirePrivateFile(path); err != nil {
		return sca.BlindFPTriageAuthenticator{}, fmt.Errorf("blind authentication key: %w", err)
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return sca.BlindFPTriageAuthenticator{}, fmt.Errorf("read blind authentication key: %w", err)
	}
	return sca.NewBlindFPTriageAuthenticator(bytes.TrimSpace(key))
}

func loadHumanReviewers(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("--human-reviewers is required")
	}
	if err := requirePrivateFile(path); err != nil {
		return nil, fmt.Errorf("human reviewer allowlist: %w", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read human reviewer allowlist: %w", err)
	}
	var reviewers []string
	for _, line := range bytes.Split(b, []byte{10}) {
		if identity := strings.TrimSpace(string(line)); identity != "" && !strings.HasPrefix(identity, "#") {
			reviewers = append(reviewers, identity)
		}
	}
	if len(reviewers) == 0 {
		return nil, fmt.Errorf("human reviewer allowlist is empty")
	}
	return reviewers, nil
}

func readStrictJSON(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON content")
	}
	return nil
}

// requirePrivateFile rejects operator secrets and allowlists that another local account could
// read or substitute: symlinks, non-regular files, and group- or world-accessible modes. Windows
// is refused because this command cannot verify a current-user-only ACL.
func requirePrivateFile(path string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("private input files are not supported on Windows: current-user-only ACL verification is unavailable in this command")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat private input: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("private input must be a regular file, not a symlink or special file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private input must not grant group or other access")
	}
	return nil
}

func writePrivateJSON(path string, value any) error {
	if filepath.Base(path) == "." {
		return fmt.Errorf("invalid output path")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("private output parent must be a pre-existing directory: %w", err)
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("private output parent must be a pre-existing directory")
	}
	if runtime.GOOS == "windows" {
		return fmt.Errorf("private output is disabled on Windows: current-user-only ACL establishment and verification are unavailable in this command; use a platform with verifiable private permissions")
	}
	if info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("private output parent must not grant group or other access")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create blind workflow output: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write blind workflow output: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync blind workflow output: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close blind workflow output: %w", err)
	}
	return nil
}
