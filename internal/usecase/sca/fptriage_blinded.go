package sca

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	BlindFPTriagePacketSchema     = "synapse-fp-triage-blind-packet-v1"
	BlindFPTriageSubmissionSchema = "synapse-fp-triage-blind-submission-v1"
	BlindFPTriageJoinedSchema     = "synapse-fp-triage-blind-joined-v1"
	blindFPTriageHMACAlgorithm    = "hmac-sha256"
)

var blindFPTriageForbiddenText = regexp.MustCompile(`(?i)\b(?:model verdict|model confidence|model rationale|proposer verdict|proposer confidence|proposer rationale|verifier verdict|verifier confidence|verifier rationale|experiment arm|would_gate_exempt|gate_exempt)\b`)

// BlindFPTriageAuthenticator holds an operator-supplied private HMAC key.
type BlindFPTriageAuthenticator struct{ key []byte }

// NewBlindFPTriageAuthenticator rejects short keys rather than offering misleading authentication.
func NewBlindFPTriageAuthenticator(key []byte) (BlindFPTriageAuthenticator, error) {
	if len(key) < sha256.Size {
		return BlindFPTriageAuthenticator{}, fmt.Errorf("blind triage authentication key must be at least %d bytes", sha256.Size)
	}
	return BlindFPTriageAuthenticator{key: append([]byte(nil), key...)}, nil
}

type BlindFPTriageAuthentication struct {
	Algorithm string `json:"algorithm"`
	MAC       string `json:"mac"`
}

// BlindFPTriagePacket is the reviewer-facing subset of an evaluation dataset and run. It deliberately
// excludes labels and every model output, identity, confidence, rationale, and experiment-arm field.
type BlindFPTriagePacket struct {
	SchemaVersion  string                      `json:"schema_version"`
	PacketID       string                      `json:"packet_id"`
	DatasetVersion string                      `json:"dataset_version"`
	DatasetSHA256  string                      `json:"dataset_sha256"`
	RunSHA256      string                      `json:"run_sha256"`
	Shadow         bool                        `json:"shadow"`
	GateExempt     bool                        `json:"gate_exempt"`
	Cases          []BlindFPTriagePacketCase   `json:"cases"`
	Authentication BlindFPTriageAuthentication `json:"authentication"`
}

type BlindFPTriagePacketCase struct {
	BlindID     string          `json:"blind_id"`
	Language    string          `json:"language"`
	Framework   string          `json:"framework"`
	Kind        finding.Kind    `json:"kind"`
	Severity    shared.Severity `json:"severity"`
	CWE         string          `json:"cwe"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	File        string          `json:"file"`
	Line        int             `json:"line"`
	Source      string          `json:"source"`
}

type BlindFPTriageDecision string

const (
	BlindFPTriageFalsePositive BlindFPTriageDecision = "false_positive"
	BlindFPTriageTruePositive  BlindFPTriageDecision = "true_positive"
	BlindFPTriageAbstain       BlindFPTriageDecision = "abstain"
)

type BlindFPTriageReviewDecision struct {
	BlindID   string                `json:"blind_id"`
	Decision  BlindFPTriageDecision `json:"decision"`
	Rationale string                `json:"rationale,omitempty"`
}

// BlindFPTriageSubmission is untrusted reviewer input. The trusted command boundary supplies reviewer identity separately.
type BlindFPTriageSubmission struct {
	SchemaVersion string                        `json:"schema_version"`
	PacketID      string                        `json:"packet_id"`
	DatasetSHA256 string                        `json:"dataset_sha256"`
	RunSHA256     string                        `json:"run_sha256"`
	Shadow        bool                          `json:"shadow"`
	GateExempt    bool                          `json:"gate_exempt"`
	Decisions     []BlindFPTriageReviewDecision `json:"decisions"`
}

// BlindFPTriageImportedSubmission is an authenticated receipt binding reviewer identity, decisions, dataset, run, and packet.
type BlindFPTriageImportedSubmission struct {
	BlindFPTriageSubmission
	Reviewer       string                      `json:"reviewer"`
	Authentication BlindFPTriageAuthentication `json:"authentication"`
}

// BlindFPTriageMetrics measure a submitted human review against the locked ground truth only after join.
type BlindFPTriageMetrics struct {
	Total                   int     `json:"total"`
	Reviewed                int     `json:"reviewed"`
	HumanFalsePositives     int     `json:"human_false_positives"`
	DecidedFalsePositives   int     `json:"decided_false_positives"`
	CorrectFalsePositives   int     `json:"correct_false_positives"`
	Abstentions             int     `json:"abstentions"`
	Disagreements           int     `json:"disagreements"`
	DisagreementComparisons int     `json:"disagreement_comparisons"`
	PolicyExemptible        int     `json:"policy_exemptible"`
	Precision               float64 `json:"precision"`
	Recall                  float64 `json:"recall"`
	AbstentionRate          float64 `json:"abstention_rate"`
	DisagreementRate        float64 `json:"disagreement_rate"`
	PolicyExemptibleRate    float64 `json:"policy_exemptible_rate"`
}

// BlindFPTriageJoinedReport contains aggregate results only; it never republishes individual model output.
type BlindFPTriageJoinedReport struct {
	SchemaVersion string               `json:"schema_version"`
	PacketID      string               `json:"packet_id"`
	DatasetSHA256 string               `json:"dataset_sha256"`
	RunSHA256     string               `json:"run_sha256"`
	Reviewer      string               `json:"reviewer"`
	Shadow        bool                 `json:"shadow"`
	GateExempt    bool                 `json:"gate_exempt"`
	Metrics       BlindFPTriageMetrics `json:"metrics"`
}

// ExportBlindFPTriagePacket makes a shuffled, seed-reproducible reviewer packet from a locked dataset/run.
func ExportBlindFPTriagePacket(dataset AIEvaluationDataset, report AIEvaluationReport, seed string, authenticator BlindFPTriageAuthenticator) (BlindFPTriagePacket, error) {
	if strings.TrimSpace(seed) == "" {
		return BlindFPTriagePacket{}, fmt.Errorf("blind packet seed is required")
	}
	if !authenticator.valid() {
		return BlindFPTriagePacket{}, fmt.Errorf("blind packet authentication is required")
	}
	if err := dataset.Validate(); err != nil {
		return BlindFPTriagePacket{}, fmt.Errorf("validate blind packet dataset: %w", err)
	}
	if err := report.Validate(); err != nil {
		return BlindFPTriagePacket{}, fmt.Errorf("validate blind packet run: %w", err)
	}
	if report.DatasetVersion != dataset.Version || report.DatasetSHA256 != evaluationDatasetDigest(dataset) {
		return BlindFPTriagePacket{}, fmt.Errorf("blind packet dataset does not match evaluation run")
	}

	cases := append([]AIEvaluationCase(nil), dataset.Cases...)
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	packet := BlindFPTriagePacket{
		SchemaVersion:  BlindFPTriagePacketSchema,
		DatasetVersion: dataset.Version,
		DatasetSHA256:  report.DatasetSHA256,
		RunSHA256:      report.RunID,
		Shadow:         true,
		GateExempt:     false,
		Cases:          make([]BlindFPTriagePacketCase, 0, len(cases)),
	}
	for _, c := range cases {
		blindCase, err := blindSafeFPTriageProjection(c)
		if err != nil {
			return BlindFPTriagePacket{}, err
		}
		blindCase.BlindID = blindCaseID(seed, report.RunID, c.ID)
		packet.Cases = append(packet.Cases, blindCase)
	}
	seedDigest := sha256.Sum256([]byte(seed))
	// #nosec G404 -- the seeded PRNG provides reproducible blind ordering, not secrecy or authentication.
	r := rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(seedDigest[:8]))))
	r.Shuffle(len(packet.Cases), func(i, j int) { packet.Cases[i], packet.Cases[j] = packet.Cases[j], packet.Cases[i] })
	packetID, err := blindPacketDigest(packet)
	if err != nil {
		return BlindFPTriagePacket{}, fmt.Errorf("digest blind packet: %w", err)
	}
	packet.PacketID = packetID
	if err := authenticator.signPacket(&packet); err != nil {
		return BlindFPTriagePacket{}, err
	}
	return packet, nil
}

// ImportBlindFPTriageSubmission validates a reviewer response before it can be joined with the run.
func ImportBlindFPTriageSubmission(packet BlindFPTriagePacket, submission BlindFPTriageSubmission, reviewer string, allowedHumanReviewers []string, proposer, verifier string, authenticator BlindFPTriageAuthenticator) (BlindFPTriageImportedSubmission, error) {
	if err := validateBlindPacket(packet); err != nil {
		return BlindFPTriageImportedSubmission{}, err
	}
	if submission.SchemaVersion != BlindFPTriageSubmissionSchema || submission.PacketID != packet.PacketID ||
		submission.DatasetSHA256 != packet.DatasetSHA256 || submission.RunSHA256 != packet.RunSHA256 ||
		!submission.Shadow || submission.GateExempt {
		return BlindFPTriageImportedSubmission{}, fmt.Errorf("blind submission is not locked to the shadow, non-exempt packet")
	}
	if err := validateAuthenticatedBlindPacket(packet, authenticator); err != nil {
		return BlindFPTriageImportedSubmission{}, err
	}
	if err := validateBlindFPTriageReviewer(reviewer, allowedHumanReviewers, proposer, verifier); err != nil {
		return BlindFPTriageImportedSubmission{}, err
	}
	if len(submission.Decisions) != len(packet.Cases) {
		return BlindFPTriageImportedSubmission{}, fmt.Errorf("blind submission must decide every packet case exactly once")
	}
	caseIDs := make(map[string]struct{}, len(packet.Cases))
	for _, c := range packet.Cases {
		caseIDs[c.BlindID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(submission.Decisions))
	for _, d := range submission.Decisions {
		if _, ok := caseIDs[d.BlindID]; !ok {
			return BlindFPTriageImportedSubmission{}, fmt.Errorf("blind submission contains unknown case %q", d.BlindID)
		}
		if _, duplicate := seen[d.BlindID]; duplicate {
			return BlindFPTriageImportedSubmission{}, fmt.Errorf("blind submission contains duplicate case %q", d.BlindID)
		}
		seen[d.BlindID] = struct{}{}
		if d.Decision != BlindFPTriageFalsePositive && d.Decision != BlindFPTriageTruePositive && d.Decision != BlindFPTriageAbstain {
			return BlindFPTriageImportedSubmission{}, fmt.Errorf("blind submission case %q has invalid decision %q", d.BlindID, d.Decision)
		}
	}
	imported := BlindFPTriageImportedSubmission{BlindFPTriageSubmission: submission, Reviewer: reviewer}
	if err := authenticator.signSubmission(&imported); err != nil {
		return BlindFPTriageImportedSubmission{}, err
	}
	return imported, nil
}

// JoinBlindFPTriageSubmission joins an already imported submission with the locked data and run.
func JoinBlindFPTriageSubmission(dataset AIEvaluationDataset, report AIEvaluationReport, packet BlindFPTriagePacket, submission BlindFPTriageImportedSubmission, allowedHumanReviewers []string, authenticator BlindFPTriageAuthenticator) (BlindFPTriageJoinedReport, error) {
	if err := dataset.Validate(); err != nil {
		return BlindFPTriageJoinedReport{}, fmt.Errorf("validate join dataset: %w", err)
	}
	if err := report.Validate(); err != nil {
		return BlindFPTriageJoinedReport{}, fmt.Errorf("validate join run: %w", err)
	}
	if err := validateAuthenticatedBlindPacket(packet, authenticator); err != nil {
		return BlindFPTriageJoinedReport{}, err
	}
	if packet.DatasetSHA256 != evaluationDatasetDigest(dataset) || packet.RunSHA256 != report.RunID || report.DatasetSHA256 != packet.DatasetSHA256 {
		return BlindFPTriageJoinedReport{}, fmt.Errorf("blind packet does not match dataset and evaluation run")
	}
	if err := validateImportedBlindFPTriageSubmission(packet, submission, allowedHumanReviewers, report.Run.ProposerModel, report.Run.VerifierModel, authenticator); err != nil {
		return BlindFPTriageJoinedReport{}, fmt.Errorf("validate imported blind submission: %w", err)
	}

	byFile := make(map[string]AIEvaluationCase, len(dataset.Cases))
	for _, c := range dataset.Cases {
		byFile[c.File] = c
	}
	results := make(map[string]AIEvaluationResult, len(report.Results))
	for _, r := range report.Results {
		results[r.CaseID] = r
	}
	metrics := BlindFPTriageMetrics{Total: len(submission.Decisions)}
	packetCases := make(map[string]BlindFPTriagePacketCase, len(packet.Cases))
	for _, c := range packet.Cases {
		packetCases[c.BlindID] = c
	}
	for _, d := range submission.Decisions {
		blindCase := packetCases[d.BlindID]
		c, ok := byFile[blindCase.File]
		if !ok || c.Language != blindCase.Language || c.Framework != blindCase.Framework || c.Kind != blindCase.Kind || c.Severity != blindCase.Severity || c.CWE != blindCase.CWE || c.Title != blindCase.Title || c.Description != blindCase.Description || c.Line != blindCase.Line || c.Source != blindCase.Source {
			return BlindFPTriageJoinedReport{}, fmt.Errorf("blind packet case mapping is invalid")
		}
		result, ok := results[c.ID]
		if !ok {
			return BlindFPTriageJoinedReport{}, fmt.Errorf("evaluation run has no result for case %q", c.ID)
		}
		if c.Label == AIEvaluationFalsePositive {
			metrics.HumanFalsePositives++
		}
		if result.WouldGateExempt {
			metrics.PolicyExemptible++
		}
		if d.Decision == BlindFPTriageAbstain {
			metrics.Abstentions++
			continue
		}
		metrics.Reviewed++
		decisionFP := d.Decision == BlindFPTriageFalsePositive
		if decisionFP {
			metrics.DecidedFalsePositives++
		}
		if decisionFP && c.Label == AIEvaluationFalsePositive {
			metrics.CorrectFalsePositives++
		}
		if result.Covered {
			metrics.DisagreementComparisons++
			if decisionFP != result.ConsensusFalsePositive {
				metrics.Disagreements++
			}
		}
	}
	metrics.Precision = blindRatio(metrics.CorrectFalsePositives, metrics.DecidedFalsePositives)
	metrics.Recall = blindRatio(metrics.CorrectFalsePositives, metrics.HumanFalsePositives)
	metrics.AbstentionRate = blindRatio(metrics.Abstentions, metrics.Total)
	metrics.DisagreementRate = blindRatio(metrics.Disagreements, metrics.DisagreementComparisons)
	metrics.PolicyExemptibleRate = blindRatio(metrics.PolicyExemptible, metrics.Total)
	return BlindFPTriageJoinedReport{SchemaVersion: BlindFPTriageJoinedSchema, PacketID: packet.PacketID, DatasetSHA256: packet.DatasetSHA256, RunSHA256: packet.RunSHA256, Reviewer: submission.Reviewer, Shadow: true, GateExempt: false, Metrics: metrics}, nil
}

func blindSafeFPTriageProjection(c AIEvaluationCase) (BlindFPTriagePacketCase, error) {
	fields := []struct{ name, value string }{{"language", c.Language}, {"framework", c.Framework}, {"cwe", c.CWE}, {"title", c.Title}, {"description", c.Description}, {"file", c.File}, {"source", c.Source}}
	for _, field := range fields {
		if blindFPTriageForbiddenText.MatchString(field.value) {
			return BlindFPTriagePacketCase{}, fmt.Errorf("blind packet %s contains a forbidden model-decision marker", field.name)
		}
	}
	return BlindFPTriagePacketCase{Language: c.Language, Framework: c.Framework, Kind: c.Kind, Severity: c.Severity, CWE: c.CWE, Title: c.Title, Description: c.Description, File: c.File, Line: c.Line, Source: c.Source}, nil
}

func validateBlindFPTriageReviewer(reviewer string, allowedHumanReviewers []string, proposer, verifier string) error {
	if strings.TrimSpace(reviewer) == "" || reviewer != strings.TrimSpace(reviewer) || aitriagereview.IsMachineOrModelActor(reviewer, proposer, verifier) {
		return fmt.Errorf("blind submission reviewer must be an allowlisted human distinct from proposer and verifier")
	}
	for _, allowed := range allowedHumanReviewers {
		if reviewer == allowed && reviewer == strings.TrimSpace(allowed) && !aitriagereview.IsMachineOrModelActor(allowed, proposer, verifier) {
			return nil
		}
	}
	return fmt.Errorf("blind submission reviewer is not an allowlisted human")
}

func validateImportedBlindFPTriageSubmission(packet BlindFPTriagePacket, submission BlindFPTriageImportedSubmission, allowedHumanReviewers []string, proposer, verifier string, authenticator BlindFPTriageAuthenticator) error {
	if err := validateBlindFPTriageReviewer(submission.Reviewer, allowedHumanReviewers, proposer, verifier); err != nil {
		return err
	}
	if err := authenticator.verifySubmission(submission); err != nil {
		return err
	}
	return nil
}

func validateAuthenticatedBlindPacket(packet BlindFPTriagePacket, authenticator BlindFPTriageAuthenticator) error {
	if err := validateBlindPacket(packet); err != nil {
		return err
	}
	return authenticator.verifyPacket(packet)
}

func (a BlindFPTriageAuthenticator) valid() bool { return len(a.key) >= sha256.Size }
func (a BlindFPTriageAuthenticator) signPacket(packet *BlindFPTriagePacket) error {
	mac, err := a.mac("packet", canonicalBlindPacket(*packet))
	if err != nil {
		return err
	}
	packet.Authentication = BlindFPTriageAuthentication{Algorithm: blindFPTriageHMACAlgorithm, MAC: mac}
	return nil
}
func (a BlindFPTriageAuthenticator) verifyPacket(packet BlindFPTriagePacket) error {
	mac, err := a.mac("packet", canonicalBlindPacket(packet))
	if err != nil || packet.Authentication.Algorithm != blindFPTriageHMACAlgorithm || !constantTimeHexEqual(packet.Authentication.MAC, mac) {
		return fmt.Errorf("blind packet authentication failed")
	}
	return nil
}
func (a BlindFPTriageAuthenticator) signSubmission(submission *BlindFPTriageImportedSubmission) error {
	mac, err := a.mac("submission", canonicalBlindSubmission(*submission))
	if err != nil {
		return err
	}
	submission.Authentication = BlindFPTriageAuthentication{Algorithm: blindFPTriageHMACAlgorithm, MAC: mac}
	return nil
}
func (a BlindFPTriageAuthenticator) verifySubmission(submission BlindFPTriageImportedSubmission) error {
	mac, err := a.mac("submission", canonicalBlindSubmission(submission))
	if err != nil || submission.Authentication.Algorithm != blindFPTriageHMACAlgorithm || !constantTimeHexEqual(submission.Authentication.MAC, mac) {
		return fmt.Errorf("blind submission authentication failed")
	}
	return nil
}
func (a BlindFPTriageAuthenticator) mac(kind string, canonical []byte) (string, error) {
	if !a.valid() {
		return "", fmt.Errorf("blind triage authentication is required")
	}
	h := hmac.New(sha256.New, a.key)
	_, _ = h.Write([]byte("synapse-fp-triage-blind-v1\x00" + kind + "\x00"))
	_, _ = h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func canonicalBlindPacket(packet BlindFPTriagePacket) []byte {
	packet.Authentication = BlindFPTriageAuthentication{}
	b, _ := json.Marshal(packet)
	return b
}
func canonicalBlindSubmission(submission BlindFPTriageImportedSubmission) []byte {
	submission.Authentication = BlindFPTriageAuthentication{}
	b, _ := json.Marshal(submission)
	return b
}
func constantTimeHexEqual(actual, expected string) bool {
	actualBytes, err := hex.DecodeString(actual)
	if err != nil {
		return false
	}
	expectedBytes, err := hex.DecodeString(expected)
	return err == nil && len(actualBytes) == len(expectedBytes) && subtle.ConstantTimeCompare(actualBytes, expectedBytes) == 1
}

func validateBlindPacket(packet BlindFPTriagePacket) error {
	digest, err := blindPacketDigest(packet)
	if err != nil {
		return fmt.Errorf("digest blind packet: %w", err)
	}
	if packet.SchemaVersion != BlindFPTriagePacketSchema || strings.TrimSpace(packet.PacketID) == "" ||
		!validEvaluationSHA256(packet.DatasetSHA256) || !validEvaluationSHA256(packet.RunSHA256) || !packet.Shadow || packet.GateExempt || len(packet.Cases) == 0 || packet.PacketID != digest {
		return fmt.Errorf("invalid blind packet")
	}
	seen := make(map[string]struct{}, len(packet.Cases))
	for _, c := range packet.Cases {
		if !validEvaluationSHA256(c.BlindID) || strings.TrimSpace(c.Language) == "" || strings.TrimSpace(c.Framework) == "" ||
			(c.Kind != finding.KindSAST && c.Kind != finding.KindMisconfig) || !c.Severity.Valid() || strings.TrimSpace(c.Title) == "" || strings.TrimSpace(c.File) == "" || c.Line <= 0 {
			return fmt.Errorf("invalid blind packet case")
		}
		if _, err := blindSafeFPTriageProjection(AIEvaluationCase{Language: c.Language, Framework: c.Framework, Kind: c.Kind, Severity: c.Severity, CWE: c.CWE, Title: c.Title, Description: c.Description, File: c.File, Line: c.Line, Source: c.Source}); err != nil {
			return err
		}
		if _, duplicate := seen[c.BlindID]; duplicate {
			return fmt.Errorf("duplicate blind packet case")
		}
		seen[c.BlindID] = struct{}{}
	}
	return nil
}

func blindCaseID(seed, runID, caseID string) string {
	sum := sha256.Sum256([]byte("synapse-fp-triage-blind-v1\x00" + seed + "\x00" + runID + "\x00" + caseID))
	return hex.EncodeToString(sum[:])
}

func blindPacketDigest(packet BlindFPTriagePacket) (string, error) {
	copyPacket := packet
	copyPacket.PacketID = ""
	copyPacket.Authentication = BlindFPTriageAuthentication{}
	b, err := json.Marshal(copyPacket)
	if err != nil {
		return "", fmt.Errorf("marshal canonical blind packet: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func blindRatio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}
