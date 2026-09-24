package ast

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/sastbench"
)

// exportSecuribenchBlindedProposals writes a verifier packet from fresh scanner detections. It tokenizes source
// filenames and removes comments before export, so Securibench good/bad names and marker annotations cannot
// reach the verifier. The trusted scorer retains the original locations in memory for replay after a verdict.
func securibenchBlindedProposalBatch(t *testing.T, srcRoot, corpusDigest string, detected []sastbench.Finding) sastbench.ProposalBatch {
	t.Helper()
	salt := strings.TrimSpace(os.Getenv("SYNAPSE_POST_TRIAGE_PACKET_SALT"))
	if err := validatePacketSalt(salt); err != nil {
		t.Fatalf("invalid SYNAPSE_POST_TRIAGE_PACKET_SALT: %v", err)
	}
	inputs := make([]sastbench.ProposalInput, 0, len(detected))
	for _, finding := range detected {
		path, err := findSecuribenchSource(srcRoot, finding.File)
		if err != nil {
			t.Fatalf("find source for blinded proposal %s: %v", finding.File, err)
		}
		inputs = append(inputs, sastbench.ProposalInput{Finding: finding, PacketFile: blindedSourceName(finding.File, salt), SourceContext: blindedSourceContext(t, path, finding.Line)})
	}
	batch, err := sastbench.NewProposalBatchWithContext(corpusDigest, "synapse-owned", inputs)
	if err != nil {
		t.Fatalf("build blinded proposal packet: %v", err)
	}
	return batch
}

func exportSecuribenchBlindedProposals(t *testing.T, exportPath, srcRoot, corpusDigest string, detected []sastbench.Finding) {
	t.Helper()
	batch := securibenchBlindedProposalBatch(t, srcRoot, corpusDigest, detected)
	f, err := os.Create(exportPath)
	if err != nil {
		t.Fatalf("create SYNAPSE_POST_TRIAGE_PROPOSALS: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := sastbench.EncodeProposalBatch(f, batch); err != nil {
		t.Fatalf("write blinded proposal packet: %v", err)
	}
	t.Logf("wrote %d blinded post-triage proposals to %s", len(batch.Proposals), exportPath)
}

// postTriageSecuribenchReport replays a recorded independent verdict over fresh scanner output. It is shared
// by accepted comparison and diagnostic measurement so both paths reject stale packets and false suppression.
func postTriageSecuribenchReport(t *testing.T, verdictPath, srcRoot, corpusDigest string, detected []sastbench.Finding, cases []sastbench.LabeledCase) sastbench.Report {
	t.Helper()
	responsePath := strings.TrimSpace(os.Getenv("SYNAPSE_POST_TRIAGE_RESPONSE"))
	if responsePath == "" {
		t.Fatal("SYNAPSE_POST_TRIAGE_VERDICTS requires SYNAPSE_POST_TRIAGE_RESPONSE")
	}
	verdictFile, err := os.Open(verdictPath)
	if err != nil {
		t.Fatalf("open post-triage verdict artifact: %v", err)
	}
	defer func() { _ = verdictFile.Close() }()
	artifact, err := sastbench.LoadVerdictArtifact(verdictFile)
	if err != nil {
		t.Fatalf("load post-triage verdict artifact: %v", err)
	}
	if artifact.ResponseRef != responsePath {
		t.Fatal("post-triage verdict response reference does not match SYNAPSE_POST_TRIAGE_RESPONSE")
	}
	responseBytes, err := os.ReadFile(responsePath)
	if err != nil {
		t.Fatalf("read recorded verifier response: %v", err)
	}
	batch := securibenchBlindedProposalBatch(t, srcRoot, corpusDigest, detected)
	confirmed, err := sastbench.ReplayVerdicts(batch, artifact, strings.NewReader(string(responseBytes)), corpusDigest)
	if err != nil {
		t.Fatalf("replay post-triage verdicts for truth coverage: %v", err)
	}
	if lost := sastbench.NewlyLostTrueCases(detected, confirmed, cases, securibenchScoredCWEs, securibenchLineWindow); len(lost) > 0 {
		t.Fatalf("post-triage suppressed scanner-proposed true cases: %s", strings.Join(lost, ", "))
	}
	report, err := sastbench.ScorePostTriage(batch, artifact, strings.NewReader(string(responseBytes)), cases, securibenchScoredCWEs, securibenchLineWindow)
	if err != nil {
		t.Fatalf("replay post-triage verdicts: %v", err)
	}
	report.Corpus = "securibench-micro"
	return report
}

func writeSecuribenchDiagnosticReport(t *testing.T, path string, report sastbench.Report) {
	t.Helper()
	report.Engine += " [diagnostic-unaccepted]"
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create diagnostic post-triage report: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := sastbench.EncodeReport(f, report); err != nil {
		t.Fatalf("write diagnostic post-triage report: %v", err)
	}
	t.Logf("wrote diagnostic, unaccepted post-triage report to %s; it is not a baseline and cannot promote itself", path)
}

// verifySecuribenchPostTriage is enabled only when a verdict path is supplied. It deliberately fails closed
// without the retained parsed response or a committed historical baseline; ordinary proposal export remains a
// diagnostic operation until independent verdict evidence exists.
func verifySecuribenchPostTriage(t *testing.T, verdictPath, srcRoot, corpusDigest string, detected []sastbench.Finding, cases []sastbench.LabeledCase) {
	t.Helper()
	responsePath := strings.TrimSpace(os.Getenv("SYNAPSE_POST_TRIAGE_RESPONSE"))
	baselinePath := strings.TrimSpace(os.Getenv("SYNAPSE_POST_TRIAGE_BASELINE"))
	baselineEngine := strings.TrimSpace(os.Getenv("SYNAPSE_POST_TRIAGE_BASELINE_ENGINE"))
	if responsePath == "" || baselinePath == "" || baselineEngine == "" {
		t.Fatal("SYNAPSE_POST_TRIAGE_VERDICTS requires SYNAPSE_POST_TRIAGE_RESPONSE, SYNAPSE_POST_TRIAGE_BASELINE, and externally configured SYNAPSE_POST_TRIAGE_BASELINE_ENGINE")
	}
	candidate := postTriageSecuribenchReport(t, verdictPath, srcRoot, corpusDigest, detected, cases)
	baselineFile, err := os.Open(baselinePath)
	if err != nil {
		t.Fatalf("open post-triage baseline: %v", err)
	}
	defer func() { _ = baselineFile.Close() }()
	baseline, err := sastbench.LoadReport(baselineFile)
	if err != nil {
		t.Fatalf("load post-triage baseline: %v", err)
	}
	counts := make(map[string]int, len(securibenchScoredCWEs))
	for _, c := range cases {
		for _, cwe := range securibenchScoredCWEs {
			if c.CWE == cwe {
				counts[cwe]++
			}
		}
	}
	contract := sastbench.PostTriageAcceptance{Corpus: candidate.Corpus, CorpusDigest: corpusDigest, CandidateEngine: candidate.Engine, BaselineEngine: baselineEngine, LineWindow: securibenchLineWindow, ScoredCWEs: securibenchScoredCWEs, ExpectedCounts: counts, Floors: sastbench.DefaultSecuribenchFloors()}
	detail, err := sastbench.AcceptPostTriage(contract, candidate, baseline)
	if err != nil {
		t.Fatalf("post-triage acceptance: %v\n%s", err, strings.Join(detail, "\n"))
	}
	for _, line := range detail {
		t.Log(line)
	}
}

func findSecuribenchSource(root, name string) (string, error) {
	var found string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Base(path) == name {
			found = path
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", os.ErrNotExist
	}
	return found, nil
}

func blindedSourceName(name, salt string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	_, _ = mac.Write([]byte(name))
	digest := mac.Sum(nil)
	return "source-" + hex.EncodeToString(digest[:16]) + ".java"
}

func validatePacketSalt(salt string) error {
	if len(salt) != sha256.Size*2 {
		return fmt.Errorf("must be exactly %d hex characters", sha256.Size*2)
	}
	if _, err := hex.DecodeString(salt); err != nil {
		return fmt.Errorf("must be hexadecimal: %w", err)
	}
	return nil
}

func blindedSourceContext(t *testing.T, path string, line int) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read source context: %v", err)
	}
	return blindedJavaMethod(string(data), line)
}

var corpusOutcomeToken = regexp.MustCompile(`(?i)\b(good|bad)\b`)

// blindedJavaMethod retains the enclosing method, which gives a verifier the source-to-sink flow, while
// removing Java comments (including Securibench annotations) without damaging comment-like string literals.
func blindedJavaMethod(source string, targetLine int) string {
	lines := strings.Split(stripJavaComments(source), "\n")
	target := targetLine - 1
	if target < 0 || target >= len(lines) {
		return ""
	}
	depth := make([]int, len(lines)+1)
	for i, line := range lines {
		depth[i+1] = depth[i] + strings.Count(line, "{") - strings.Count(line, "}")
	}
	start := target
	end := len(lines)
	for i := target; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if isJavaMethodStart(trimmed) && depth[i] < depth[target] {
			candidateEnd := len(lines)
			for j := i; j < len(lines); j++ {
				if depth[j+1] == depth[i] {
					candidateEnd = j + 1
					break
				}
			}
			if candidateEnd <= target {
				continue
			}
			start = i
			end = candidateEnd
			break
		}
	}
	context := strings.Join(lines[start:end], "\n")
	return corpusOutcomeToken.ReplaceAllString(context, "variant")
}

func isJavaMethodStart(line string) bool {
	if !strings.Contains(line, "(") || !strings.Contains(line, ")") || !strings.Contains(line, "{") {
		return false
	}
	for _, control := range []string{"if", "for", "while", "switch", "catch", "try", "do", "else", "synchronized"} {
		if strings.HasPrefix(line, control+"(") || strings.HasPrefix(line, control+" (") {
			return false
		}
	}
	return true
}

func stripJavaComments(source string) string {
	var out strings.Builder
	inBlock, inString, inChar, escaped := false, false, false, false
	for i := 0; i < len(source); i++ {
		ch := source[i]
		if inBlock {
			if ch == '*' && i+1 < len(source) && source[i+1] == '/' {
				inBlock = false
				i++
			}
			if ch == '\n' {
				out.WriteByte(ch)
			}
			continue
		}
		if !inString && !inChar && ch == '/' && i+1 < len(source) {
			if source[i+1] == '/' {
				for i < len(source) && source[i] != '\n' {
					i++
				}
				if i < len(source) {
					out.WriteByte('\n')
				}
				continue
			}
			if source[i+1] == '*' {
				inBlock = true
				i++
				continue
			}
		}
		out.WriteByte(ch)
		if inString {
			if ch == '"' && !escaped {
				inString = false
			}
			escaped = ch == '\\' && !escaped
			continue
		}
		if inChar {
			if ch == '\'' && !escaped {
				inChar = false
			}
			escaped = ch == '\\' && !escaped
			continue
		}
		if ch == '"' {
			inString = true
			escaped = false
		}
		if ch == '\'' {
			inChar = true
			escaped = false
		}
	}
	return out.String()
}
