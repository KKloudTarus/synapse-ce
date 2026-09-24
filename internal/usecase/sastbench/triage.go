package sastbench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// ProposalSchemaVersion and VerdictSchemaVersion version the two artifacts exchanged during a blind
// post-triage benchmark. The verdict artifact deliberately contains proposal IDs and decisions only: corpus
// truth labels remain in the scorer and are never supplied to a verifier.
const (
	ProposalSchemaVersion = "synapse-sast-proposals-v1"
	VerdictSchemaVersion  = "synapse-sast-verdicts-v1"
)

// Proposal is one canonical finding put before an independent verifier.
type Proposal struct {
	ID            string  `json:"id"`
	PacketFinding Finding `json:"finding"`
	SourceContext string  `json:"source_context"`
	Finding       Finding `json:"-"`
}

// ProposalInput is fresh scanner output prepared for a blinded verifier packet. SourceContext is scanner-side
// source context only; it must never contain corpus truth labels.
type ProposalInput struct {
	Finding       Finding
	PacketFile    string
	SourceContext string
}

// ProposalBatch is the complete propose-stage output for one corpus run. CorpusDigest binds it to the answer
// key used for scoring; Proposer identifies the proposing system or person for independence checks.
type ProposalBatch struct {
	Schema       string     `json:"schema"`
	CorpusDigest string     `json:"corpus_digest"`
	Proposer     string     `json:"proposer"`
	Proposals    []Proposal `json:"proposals"`
}

// Verdict is an independent verifier decision. Confirmed findings flow into the post-triage scorer; rejected
// findings are omitted, which means rejecting a real finding is scored as a false negative.
type Verdict struct {
	ProposalID string `json:"proposal_id"`
	Decision   string `json:"decision"` // "confirmed" or "rejected"
}

// VerdictArtifact is a complete independent verifier result for exactly one proposal batch. The verifier
// identity and configuration are content-pinned; ResponseDigest binds the recorded provider response without
// placing provider text (which can contain source snippets) in the benchmark artifact.
type VerdictArtifact struct {
	Schema         string    `json:"schema"`
	CorpusDigest   string    `json:"corpus_digest"`
	ProposalDigest string    `json:"proposal_digest"`
	Verifier       string    `json:"verifier"`
	Model          string    `json:"model"`
	Role           string    `json:"role"`
	ConfigDigest   string    `json:"config_digest"`
	PromptDigest   string    `json:"prompt_digest"`
	PacketDigest   string    `json:"packet_digest"`
	ResponseDigest string    `json:"response_digest"`
	ResponseRef    string    `json:"response_ref"`
	Verdicts       []Verdict `json:"verdicts"`
}

// RecordedVerdictResponse is the normalized, retained verifier response. An adapter must parse provider output
// into this exact shape before sealing a VerdictArtifact; a digest alone is not evidence that its decisions
// match the artifact consumed by the scorer.
type RecordedVerdictResponse struct {
	Schema         string    `json:"schema"`
	ProposalDigest string    `json:"proposal_digest"`
	Verdicts       []Verdict `json:"verdicts"`
}

const RecordedVerdictResponseSchemaVersion = "synapse-sast-verdict-response-v1"

// VerdictProducer is the use-case port for an automated independent verifier such as CapSAST. Its adapter
// must record the provider response and return its SHA-256 in VerdictArtifact.ResponseDigest. The scorer does
// not implement this port and never supplies corpus truth labels to it.
type VerdictProducer interface {
	Verify(ctx context.Context, batch ProposalBatch) (VerdictArtifact, error)
}

// NewProposalBatch canonicalizes all detections from a fresh run. Duplicate finding identities are rejected so
// a verifier cannot satisfy coverage by deciding the same proposal twice under different IDs.
func NewProposalBatch(corpusDigest, proposer string, findings []Finding) (ProposalBatch, error) {
	inputs := make([]ProposalInput, len(findings))
	for i, finding := range findings {
		inputs[i].Finding = finding
		inputs[i].PacketFile = finding.File
	}
	return NewProposalBatchWithContext(corpusDigest, proposer, inputs)
}

// NewProposalBatchWithContext canonicalizes scanner findings and the source context shown to a verifier. The
// source context is bound into ProposalDigest, so a verdict cannot be replayed after a scanner output packet
// changes while retaining the same locations.
func NewProposalBatchWithContext(corpusDigest, proposer string, inputs []ProposalInput) (ProposalBatch, error) {
	if strings.TrimSpace(corpusDigest) == "" {
		return ProposalBatch{}, fmt.Errorf("proposal corpus digest is required")
	}
	if strings.TrimSpace(proposer) == "" {
		return ProposalBatch{}, fmt.Errorf("proposal proposer is required")
	}
	batch := ProposalBatch{Schema: ProposalSchemaVersion, CorpusDigest: corpusDigest, Proposer: proposer}
	seen := make(map[string]bool, len(inputs))
	for _, input := range inputs {
		finding := input.Finding
		if err := validateFinding(finding); err != nil {
			return ProposalBatch{}, err
		}
		packetFile := input.PacketFile
		if strings.TrimSpace(packetFile) == "" {
			packetFile = finding.File
		}
		packetFinding := Finding{File: packetFile, Line: finding.Line, CWE: finding.CWE}
		id := proposalID(packetFinding)
		if seen[id] {
			return ProposalBatch{}, fmt.Errorf("duplicate proposal finding %q", id)
		}
		seen[id] = true
		batch.Proposals = append(batch.Proposals, Proposal{ID: id, Finding: finding, PacketFinding: packetFinding, SourceContext: input.SourceContext})
	}
	sort.Slice(batch.Proposals, func(i, j int) bool { return batch.Proposals[i].ID < batch.Proposals[j].ID })
	return batch, nil
}

// ProposalDigest hashes the complete canonical proposal set. It is independent of order and binds a verdict
// artifact to the exact findings that were reviewed.
func ProposalDigest(batch ProposalBatch) (string, error) {
	if err := validateProposalBatch(batch); err != nil {
		return "", err
	}
	rows := make([]string, 0, len(batch.Proposals))
	for _, proposal := range batch.Proposals {
		rows = append(rows, strings.Join([]string{proposal.ID, proposal.PacketFinding.File, strconv.Itoa(proposal.PacketFinding.Line), proposal.PacketFinding.CWE, proposal.SourceContext}, "\x00"))
	}
	sort.Strings(rows)
	h := sha256.New()
	for _, row := range rows {
		_, _ = io.WriteString(h, row+"\n")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ReplayVerdicts validates the recorded verifier response before replaying a full independent verification.
// expectedCorpusDigest is supplied by the current corpus loader, preventing a verdict from a stale answer key
// being replayed.
func ReplayVerdicts(batch ProposalBatch, artifact VerdictArtifact, response io.Reader, expectedCorpusDigest string) ([]Finding, error) {
	if err := VerifyRecordedResponse(artifact, response); err != nil {
		return nil, err
	}
	return replayVerdicts(batch, artifact, expectedCorpusDigest)
}

func replayVerdicts(batch ProposalBatch, artifact VerdictArtifact, expectedCorpusDigest string) ([]Finding, error) {
	if err := validateProposalBatch(batch); err != nil {
		return nil, err
	}
	if strings.TrimSpace(expectedCorpusDigest) == "" || batch.CorpusDigest != expectedCorpusDigest {
		return nil, fmt.Errorf("proposal batch corpus digest does not match current corpus")
	}
	if artifact.Schema != VerdictSchemaVersion {
		return nil, fmt.Errorf("verdict schema %q is not %q", artifact.Schema, VerdictSchemaVersion)
	}
	if artifact.CorpusDigest != expectedCorpusDigest {
		return nil, fmt.Errorf("verdict corpus digest does not match current corpus")
	}
	if strings.TrimSpace(artifact.Verifier) == "" || strings.TrimSpace(artifact.Model) == "" || strings.TrimSpace(artifact.Role) == "" || strings.TrimSpace(artifact.ResponseRef) == "" {
		return nil, fmt.Errorf("verdict verifier, model, role, and response reference are required")
	}
	if artifact.Verifier == batch.Proposer {
		return nil, fmt.Errorf("verdict verifier must differ from proposer")
	}
	if !isSHA256(artifact.ConfigDigest) || !isSHA256(artifact.PromptDigest) || !isSHA256(artifact.PacketDigest) || !isSHA256(artifact.ResponseDigest) {
		return nil, fmt.Errorf("verdict config, prompt, packet, and response digests must be SHA-256 hex")
	}
	digest, err := ProposalDigest(batch)
	if err != nil {
		return nil, err
	}
	if artifact.ProposalDigest != digest {
		return nil, fmt.Errorf("verdict proposal digest does not match fresh proposal batch")
	}
	if artifact.PacketDigest != digest {
		return nil, fmt.Errorf("verdict packet digest does not match fresh proposal batch")
	}
	proposals := make(map[string]Finding, len(batch.Proposals))
	for _, proposal := range batch.Proposals {
		if err := validateFinding(proposal.Finding); err != nil {
			return nil, fmt.Errorf("replay requires fresh internal finding for proposal %q: %w", proposal.ID, err)
		}
		proposals[proposal.ID] = proposal.Finding
	}
	seen := make(map[string]bool, len(artifact.Verdicts))
	confirmed := make([]Finding, 0, len(artifact.Verdicts))
	for _, verdict := range artifact.Verdicts {
		finding, ok := proposals[verdict.ProposalID]
		if !ok {
			return nil, fmt.Errorf("verdict references foreign proposal %q", verdict.ProposalID)
		}
		if seen[verdict.ProposalID] {
			return nil, fmt.Errorf("duplicate verdict for proposal %q", verdict.ProposalID)
		}
		seen[verdict.ProposalID] = true
		switch verdict.Decision {
		case "confirmed":
			confirmed = append(confirmed, finding)
		case "rejected":
		default:
			return nil, fmt.Errorf("verdict for proposal %q has invalid decision %q", verdict.ProposalID, verdict.Decision)
		}
	}
	if len(seen) != len(proposals) {
		missing := make([]string, 0, len(proposals)-len(seen))
		for id := range proposals {
			if !seen[id] {
				missing = append(missing, id)
			}
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("verdict coverage incomplete: missing proposals %s", strings.Join(missing, ", "))
	}
	sort.Slice(confirmed, func(i, j int) bool {
		if confirmed[i].File != confirmed[j].File {
			return confirmed[i].File < confirmed[j].File
		}
		if confirmed[i].Line != confirmed[j].Line {
			return confirmed[i].Line < confirmed[j].Line
		}
		return confirmed[i].CWE < confirmed[j].CWE
	})
	return confirmed, nil
}

// ScorePostTriage replays a blinded verifier artifact against the freshly loaded answer key, then scores only
// confirmed proposals. The answer key stays in this scoring step and is never part of ProposalBatch or the
// verifier artifact.
func ScorePostTriage(batch ProposalBatch, artifact VerdictArtifact, response io.Reader, cases []LabeledCase, scoredCWEs []string, lineWindow int) (Report, error) {
	corpusDigest := CorpusDigest(cases)
	confirmed, err := ReplayVerdicts(batch, artifact, response, corpusDigest)
	if err != nil {
		return Report{}, err
	}
	return Report{
		Schema:       ReportSchemaVersion,
		Engine:       batch.Proposer + " + " + artifact.Verifier,
		CorpusDigest: corpusDigest,
		Stage:        "post-triage",
		LineWindow:   lineWindow,
		ScoredCWEs:   append([]string(nil), scoredCWEs...),
		CWEs:         ScoreByCWE(confirmed, cases, scoredCWEs, lineWindow),
	}, nil
}

// NewlyLostTrueCases identifies true corpus cases proposed by the scanner but absent after verifier triage.
// Aggregate recall can hide one rejected true finding behind a newly detected one elsewhere, so acceptance must
// reject every item returned here rather than relying on per-CWE totals alone.
func NewlyLostTrueCases(proposed, postTriage []Finding, cases []LabeledCase, scoredCWEs []string, lineWindow int) []string {
	if lineWindow < 0 {
		lineWindow = DefaultLineWindow
	}
	scored := make(map[string]bool, len(scoredCWEs))
	for _, cwe := range scoredCWEs {
		scored[cwe] = true
	}
	proposedByLocation := findingsByFileCWE(proposed, scored)
	postByLocation := findingsByFileCWE(postTriage, scored)
	var lost []string
	for _, candidate := range cases {
		if !candidate.Real || !scored[candidate.CWE] {
			continue
		}
		key := candidate.File + "\x00" + candidate.CWE
		if caseMatched(candidate, proposedByLocation[key], lineWindow) && !caseMatched(candidate, postByLocation[key], lineWindow) {
			lost = append(lost, candidate.Name)
		}
	}
	sort.Strings(lost)
	return lost
}

func findingsByFileCWE(findings []Finding, scored map[string]bool) map[string][]int {
	byLocation := make(map[string][]int, len(findings))
	for _, finding := range findings {
		if scored[finding.CWE] {
			byLocation[finding.File+"\x00"+finding.CWE] = append(byLocation[finding.File+"\x00"+finding.CWE], finding.Line)
		}
	}
	return byLocation
}

// VerifyRecordedResponse confirms that the retained response bytes match the digest and that their parsed
// proposal digest and complete verdict set exactly match the artifact. The caller owns response storage; this
// pure check deliberately does not resolve ResponseRef as a filesystem path or URL.
func VerifyRecordedResponse(artifact VerdictArtifact, response io.Reader) error {
	if !isSHA256(artifact.ResponseDigest) {
		return fmt.Errorf("verdict response digest must be SHA-256 hex")
	}
	bytes, err := io.ReadAll(response)
	if err != nil {
		return fmt.Errorf("hash recorded verifier response: %w", err)
	}
	h := sha256.Sum256(bytes)
	if got := hex.EncodeToString(h[:]); got != artifact.ResponseDigest {
		return fmt.Errorf("recorded verifier response does not match verdict response digest")
	}
	var parsed RecordedVerdictResponse
	dec := json.NewDecoder(strings.NewReader(string(bytes)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&parsed); err != nil {
		return fmt.Errorf("parse recorded verifier response: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("parse recorded verifier response: trailing data")
	}
	if parsed.Schema != RecordedVerdictResponseSchemaVersion || parsed.ProposalDigest != artifact.ProposalDigest {
		return fmt.Errorf("recorded verifier response does not bind the verdict proposal batch")
	}
	if !sameVerdicts(parsed.Verdicts, artifact.Verdicts) {
		return fmt.Errorf("recorded verifier response verdicts do not match verdict artifact")
	}
	return nil
}

func sameVerdicts(left, right []Verdict) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]string, len(left))
	for _, verdict := range left {
		if verdict.ProposalID == "" || values[verdict.ProposalID] != "" {
			return false
		}
		values[verdict.ProposalID] = verdict.Decision
	}
	for _, verdict := range right {
		if values[verdict.ProposalID] != verdict.Decision {
			return false
		}
	}
	return true
}

func validateProposalBatch(batch ProposalBatch) error {
	if batch.Schema != ProposalSchemaVersion {
		return fmt.Errorf("proposal schema %q is not %q", batch.Schema, ProposalSchemaVersion)
	}
	if strings.TrimSpace(batch.CorpusDigest) == "" || strings.TrimSpace(batch.Proposer) == "" {
		return fmt.Errorf("proposal corpus digest and proposer are required")
	}
	seen := make(map[string]bool, len(batch.Proposals))
	for _, proposal := range batch.Proposals {
		if err := validateFinding(proposal.PacketFinding); err != nil {
			return err
		}
		if proposal.ID != proposalID(proposal.PacketFinding) {
			return fmt.Errorf("proposal ID does not match its blinded finding")
		}
		if seen[proposal.ID] {
			return fmt.Errorf("duplicate proposal %q", proposal.ID)
		}
		seen[proposal.ID] = true
	}
	return nil
}

func validateFinding(f Finding) error {
	if strings.TrimSpace(f.File) == "" || strings.TrimSpace(f.CWE) == "" || f.Line < 0 {
		return fmt.Errorf("proposal finding requires file, CWE, and non-negative line")
	}
	return nil
}

func proposalID(f Finding) string {
	h := sha256.Sum256([]byte(strings.Join([]string{f.File, strconv.Itoa(f.Line), f.CWE}, "\x00")))
	return hex.EncodeToString(h[:])
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// EncodeProposalBatch and EncodeVerdictArtifact produce stable, inspectable JSON artifacts.
func EncodeProposalBatch(w io.Writer, batch ProposalBatch) error {
	return encodeTriageArtifact(w, batch, "proposal batch")
}
func EncodeVerdictArtifact(w io.Writer, artifact VerdictArtifact) error {
	return encodeTriageArtifact(w, artifact, "verdict artifact")
}

func encodeTriageArtifact(w io.Writer, value any, name string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	return nil
}

// LoadProposalBatch and LoadVerdictArtifact reject unknown JSON fields. Loaded artifacts are subsequently
// validated against the freshly generated batch by ReplayVerdicts.
func LoadProposalBatch(r io.Reader) (ProposalBatch, error) {
	var batch ProposalBatch
	if err := decodeTriageArtifact(r, &batch, "proposal batch"); err != nil {
		return ProposalBatch{}, err
	}
	if err := validateProposalBatch(batch); err != nil {
		return ProposalBatch{}, err
	}
	return batch, nil
}

func LoadVerdictArtifact(r io.Reader) (VerdictArtifact, error) {
	var artifact VerdictArtifact
	if err := decodeTriageArtifact(r, &artifact, "verdict artifact"); err != nil {
		return VerdictArtifact{}, err
	}
	if artifact.Schema != VerdictSchemaVersion {
		return VerdictArtifact{}, fmt.Errorf("verdict schema %q is not %q", artifact.Schema, VerdictSchemaVersion)
	}
	return artifact, nil
}

func decodeTriageArtifact(r io.Reader, value any, name string) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("decode %s: trailing data", name)
	}
	return nil
}
