// Package secretscan is an owned, deterministic secret scanner over a prepared workspace. It looks for
// hardcoded credentials (cloud keys, VCS tokens, private-key blocks, high-entropy assignments) with a
// keyword pre-filter (only run a regex when its trigger word is present), per-rule and global allow-rules
// to cut false positives, and a Shannon-entropy gate for the generic rule. It is READ-ONLY and never
// touches the network.
//
// SECURITY: a detected secret is REDACTED before it leaves this package. ScanFiles returns only a masked
// preview, so a leaked credential never reaches logs, the transcript, the evidence seal, or the report.
package secretscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxFiles          = 50000     // bound the workspace walk
	maxFileBytes      = 5 << 20   // skip files larger than 5 MiB (secrets live in small config/source)
	maxTotalScanBytes = 100 << 20 // bound aggregate source reads
	maxFindings       = 2000      // bound aggregate redacted output
	sniffBytes        = 8 << 10   // read this much to decide binary-or-text
	// Decode-pass bounds: a secret hidden inside a base64/hex value is found by decoding, but the pass
	// must not become a DoS amplifier, so tokens, decoded volume, and per-token size are all capped.
	minBase64TokenLen      = 32        // < this decodes to < 24 bytes, below any modeled secret
	minHexTokenLen         = 40        // even length; < this decodes to < 20 bytes
	maxEncodedTokenLen     = 20000     // a credential is small; do not decode a giant blob
	maxDecodeTokensPerFile = 500       // bound tokens decoded per file
	maxDecodedBytesPerFile = 512 << 10 // bound aggregate decoded volume per file
)

// rule is one detector. keywords pre-filter the file (cheap Contains) before the regex runs; group selects
// which submatch is the secret (0 = whole match); minEnt > 0 rejects low-entropy matches (FP guard).
type rule struct {
	id       string
	category string
	title    string
	severity shared.Severity
	keywords []string
	re       *regexp.Regexp
	group    int
	minEnt   float64
	allow    []*regexp.Regexp // per-rule allow-list (matched against the secret text)
	// lineSkip, when set, drops a match based on the whole line it sits on. It is how a rule tells a
	// delimiter quoted inside other code from the thing it delimits.
	lineSkip func(line string) bool
	// maskNotebookOutput makes this rule read a notebook with its cell OUTPUTS blanked.
	maskNotebookOutput bool
	// maskPEMBodies makes this rule read the file with the BODY of every PEM block blanked. A key block is
	// ONE credential, and the private-key rule already reports it at its header; without this, each of the
	// 49 base64 body lines of an SSH key in an ArgoCD manifest became its own finding, so one key was
	// reported 50 times where gitleaks reports it once.
	maskPEMBodies bool
	// skipValue drops a match on the matched VALUE rather than on its line, for a shape a regex cannot
	// express. It exists for the keyword-free entropy rule, whose character class includes "/" and so
	// reads a URL or asset path as base64.
	skipValue func(secret string) bool
	// scanComments makes this rule read the file WITH its comments intact. Comments are blanked for
	// every other rule, because a generic or keyword-anchored pattern fires constantly on documentation
	// and example values. A provider rule whose unique prefix IS the signal has the opposite problem: a
	// real AKIA or ghp_ token committed inside a comment is a leaked credential that is still live, and
	// masking it reports a clean file. A prefix cannot be produced by prose, so admitting comments for
	// these rules costs no precision.
	scanComments bool
	// configFilesOnly narrows scanComments to CONFIGURATION files. A commented-out setting in a values.yaml
	// or a .env is the value that was applied until someone commented it out; a commented-out assignment in
	// source code is dead code or a documented example, which is why comments stay masked there.
	configFilesOnly bool
}

// Scanner implements ports.SecretScanner with an owned ruleset.
type Scanner struct {
	rules       []rule
	allow       []*regexp.Regexp // global allow-list (placeholders, docs examples)
	skipDirs    map[string]bool
	skipExt     map[string]bool
	openAndRead func(*os.Root, string, fs.FileInfo, int64) ([]byte, error)
}

var _ ports.SecretScanner = (*Scanner)(nil)

// New returns a scanner with the default ruleset.
func New() *Scanner {
	return &Scanner{
		rules: defaultRules(),
		allow: compileAll([]string{
			`(?i)example`, `(?i)placeholder`, `(?i)changeme`, `(?i)redacted`, `(?i)dummy`,
			`(?i)your[_-]?(secret|token|key|password)`, `(?i)^x{6,}$`, `(?i)^0+$`,
			`(?i)sample`, `^\$\{`, `(?i)^<[a-z_]+>$`,
			// A value that tells the reader to replace it is a template, not a credential. Found on live
			// code as REPLACE_ME_… and as …-change-in-production-<year>; "changeme" above does not cover
			// either spelling.
			`(?i)replace[_-]?(me|this|with)`, `(?i)change[_-]?(this|in[_-]?produc)`,
			`(?i)^(insert|todo|fixme)`,
		}),
		skipDirs: set(".git", "node_modules", "vendor", "dist", "build", "target", ".idea",
			".gradle", ".venv", "venv", "__pycache__", ".terraform", "bin"),
		// .zip/.gz/.tar/.jar/.war are NOT skipped: they are routed to the bounded archive scanner (archive.go).
		skipExt: set(".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf",
			".class", ".exe", ".so", ".dll", ".dylib", ".woff", ".woff2",
			".ttf", ".eot", ".mp4", ".mp3", ".mov", ".bin", ".wasm", ".lock", ".sum"),
		openAndRead: openAndReadRegular,
	}
}

// Name identifies the source on findings.
func (s *Scanner) Name() string { return "synapse-secret-scan" }

// ScanFiles walks root and returns redacted secret hits. It confines every open to root and stops
// when an aggregate byte, file, or finding limit is reached. Child-file failures mark the report truncated
// and are otherwise skipped. It is deterministic and READ-ONLY: it makes NO network calls (a nil verify
// state), so the SecretScanner contract holds.
func (s *Scanner) ScanFiles(ctx context.Context, root string) (ports.SecretScanReport, error) {
	return s.scanFiles(ctx, root, scanLimits{files: maxFiles, bytes: maxTotalScanBytes, findings: maxFindings}, nil)
}

// ScanFilesVerified is the opt-in active-verification path (D6.3, ports.VerifyingSecretScanner): it scans
// like ScanFiles but additionally asks verifier whether each detected credential is live and stamps the
// finding's Verified verdict. The raw secret is confined to this scan (used only for the single provider
// call, keyed by hash for per-scan dedup, then discarded) and never returned, logged, or sealed. A nil
// verifier falls back to the deterministic path. Verification never removes a finding: an unknown or
// unverified verdict leaves the hit exactly as ScanFiles would report it.
func (s *Scanner) ScanFilesVerified(ctx context.Context, root string, verifier ports.SecretVerifier) (ports.SecretScanReport, error) {
	if verifier == nil {
		return s.ScanFiles(ctx, root)
	}
	vf := &verifyState{ctx: ctx, verifier: verifier, cache: map[string]ports.SecretVerdict{}}
	return s.scanFiles(ctx, root, scanLimits{files: maxFiles, bytes: maxTotalScanBytes, findings: maxFindings}, vf)
}

var _ ports.VerifyingSecretScanner = (*Scanner)(nil)

// maxSecretVerifications caps the number of DISTINCT provider calls one verified scan may make. A repo with
// more than this many distinct credential-shaped strings is adversarial or misconfigured; the rest are left
// SecretUnknown rather than amplified into outbound requests (a hostile-repo egress/rate-limit guard). It
// bounds calls, not findings: every hit is still reported.
const maxSecretVerifications = 100

// verifyState carries the per-scan active-verification context. It is nil on the deterministic ScanFiles
// path. cache dedups provider calls within a scan by rule + secret hash, so a credential repeated across
// files is verified once and the plaintext is never held in a map (only its sha256). calls counts the
// DISTINCT provider calls made this scan, capped at maxSecretVerifications.
type verifyState struct {
	ctx      context.Context
	verifier ports.SecretVerifier
	cache    map[string]ports.SecretVerdict
	calls    int
}

// verdict returns the verification verdict for one detected secret, calling the provider at most once per
// distinct (rule, secret) per scan and at most maxSecretVerifications times per scan. It returns
// SecretUnknown when verification is off, the per-scan cap is reached, or the verifier fails; the verifier
// is responsible for keeping the secret out of any returned error. The plaintext is used only for the call
// and the sha256 cache key, never stored or logged here.
func verdict(vf *verifyState, ruleID, secret string) ports.SecretVerdict {
	if vf == nil || vf.verifier == nil {
		return ports.SecretUnknown
	}
	// AWS credentials are never verified component-by-component: STS authentication requires a matched
	// access-key/secret-key pair (and a session token for ASIA credentials). scanContent collects and pairs
	// direct findings before using the optional grouped-verifier extension below.
	if isAWSGroupedRule(ruleID) {
		return ports.SecretUnknown
	}
	sum := sha256.Sum256([]byte(secret))
	key := ruleID + ":" + hex.EncodeToString(sum[:])
	if v, ok := vf.cache[key]; ok {
		return v
	}
	if vf.calls >= maxSecretVerifications {
		return ports.SecretUnknown // over the per-scan cap: do not call (and do not cache, to keep the cap on calls)
	}
	vf.calls++
	v, _ := vf.verifier.Verify(vf.ctx, ruleID, []byte(secret)) // error is pre-redacted; unknown on failure
	vf.cache[key] = v
	return v
}

const awsPairLineWindow = 24

type awsCandidate struct {
	ruleID string
	secret string
	line   int
	index  int
}

func isAWSGroupedRule(ruleID string) bool {
	switch ruleID {
	case "aws-access-key-id", "aws-secret-access-key", "aws-session-token":
		return true
	default:
		return false
	}
}

// verifyAWSPairs correlates only unambiguous nearby components from the same scanned content. It never
// guesses: a component that has zero or multiple plausible partners stays SecretUnknown. One matched set
// consumes one call from the existing per-scan budget and receives one shared STS verdict.
func verifyAWSPairs(vf *verifyState, findings *[]ports.SecretRawFinding, candidates []awsCandidate) {
	if vf == nil || vf.verifier == nil || len(candidates) == 0 {
		return
	}
	grouped, ok := vf.verifier.(ports.GroupedSecretVerifier)
	if !ok {
		return
	}
	for _, access := range candidates {
		if access.ruleID != "aws-access-key-id" {
			continue
		}
		secret, ok := uniqueAWSCandidate(candidates, access.line, "aws-secret-access-key")
		if !ok || !mutuallyUniqueAWSPartner(candidates, access, secret) {
			continue
		}

		matched := []awsCandidate{access, secret}
		session, hasSession := uniqueAWSCandidate(candidates, access.line, "aws-session-token")
		hasSession = hasSession && mutuallyUniqueAWSPartner(candidates, access, session)
		if hasSession {
			matched = append(matched, session)
		} else if strings.HasPrefix(access.secret, "ASIA") {
			continue // temporary credentials cannot be checked without an unambiguous session token
		}
		materials := []ports.SecretMaterial{
			{RuleID: access.ruleID, Secret: []byte(access.secret)},
			{RuleID: secret.ruleID, Secret: []byte(secret.secret)},
		}
		if hasSession {
			materials = append(materials, ports.SecretMaterial{RuleID: session.ruleID, Secret: []byte(session.secret)})
		}

		cacheKey := groupedVerificationKey(materials)
		v, cached := vf.cache[cacheKey]
		if !cached {
			if vf.calls >= maxSecretVerifications {
				for i := range materials {
					clear(materials[i].Secret)
				}
				continue
			}
			vf.calls++
			v, _ = grouped.VerifyGroup(vf.ctx, materials) // errors are pre-redacted; unknown on failure
			vf.cache[cacheKey] = v
		}
		for _, candidate := range matched {
			if candidate.index >= 0 && candidate.index < len(*findings) {
				(*findings)[candidate.index].Verified = v
			}
		}
		for i := range materials {
			clear(materials[i].Secret)
		}
	}
}

func uniqueAWSCandidate(candidates []awsCandidate, line int, ruleID string) (awsCandidate, bool) {
	var match awsCandidate
	count := 0
	for _, candidate := range candidates {
		if candidate.ruleID != ruleID || lineDistance(candidate.line, line) > awsPairLineWindow {
			continue
		}
		match = candidate
		count++
	}
	return match, count == 1
}

func mutuallyUniqueAWSPartner(candidates []awsCandidate, access, partner awsCandidate) bool {
	other, ok := uniqueAWSCandidate(candidates, partner.line, "aws-access-key-id")
	return ok && other.index == access.index
}

func lineDistance(a, b int) int {
	if a < b {
		return b - a
	}
	return a - b
}

func groupedVerificationKey(materials []ports.SecretMaterial) string {
	h := sha256.New()
	_, _ = h.Write([]byte("group:"))
	for _, material := range materials {
		_, _ = h.Write([]byte(material.RuleID))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(material.Secret)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type scanLimits struct {
	files    int
	bytes    int64
	findings int
}

func (s *Scanner) scanFiles(ctx context.Context, root string, limits scanLimits, vf *verifyState) (report ports.SecretScanReport, err error) {
	if err := ctx.Err(); err != nil {
		return report, fmt.Errorf("secret scan: %w", err)
	}
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return report, fmt.Errorf("secret scan root %q: %w", root, err)
	}
	rootDir, err := os.OpenRoot(rootAbs)
	if err != nil {
		return report, fmt.Errorf("open secret scan root %q: %w", root, err)
	}
	defer func() {
		if closeErr := rootDir.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close secret scan root %q: %w", root, closeErr))
		}
	}()

	seen := map[string]bool{}
	visited := 0
	var bytesRead int64
	walkErr := fs.WalkDir(rootDir.FS(), ".", func(path string, d fs.DirEntry, walkEntryErr error) error {
		if walkEntryErr != nil {
			if path == "." {
				return fmt.Errorf("walk root: %w", walkEntryErr)
			}
			report.Truncated = true
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && s.skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if archiveExts[ext] {
			// Bounded archive scan: look inside a .jar/.war/.zip/.tar/.gz for secrets in its members.
			info, infoErr := d.Info()
			if infoErr != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				return nil
			}
			visited++
			if visited > limits.files {
				report.Truncated = true
				return fs.SkipAll
			}
			if len(report.Findings) >= limits.findings || limits.bytes-bytesRead <= 0 {
				report.Truncated = true
				return fs.SkipAll
			}
			archData, aerr := openAndReadArchive(rootDir, path, info, limits.bytes-bytesRead)
			if aerr != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return ctxErr
				}
				report.Truncated = true // an archive too large or unreadable is a lower bound, never silent
				return nil
			}
			bytesRead += int64(len(archData))
			// Clamp this archive's decompressed budget to the remaining scan-wide byte budget, then charge the
			// decompressed bytes it consumes back, so a directory of many small bombs cannot collectively
			// decompress more than limits.bytes.
			budget := &archiveBudget{maxEntries: maxArchiveEntries, maxBytes: maxArchiveTotalBytes}
			if remaining := limits.bytes - bytesRead; remaining < budget.maxBytes {
				budget.maxBytes = remaining
			}
			if budget.maxBytes < 0 {
				budget.maxBytes = 0
			}
			if s.scanArchiveData(ctx, filepath.ToSlash(path), archData, ext, seen, &report.Findings, limits.findings, budget, 0, vf) {
				report.Truncated = true
			}
			bytesRead += budget.bytes // charge decompressed bytes against the scan-wide budget
			return nil
		}
		if s.skipExt[ext] {
			return nil
		}
		visited++
		if visited > limits.files {
			report.Truncated = true
			return fs.SkipAll
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			report.Truncated = true
			return nil
		}
		if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxFileBytes {
			return nil
		}
		if len(report.Findings) >= limits.findings || info.Size() > limits.bytes-bytesRead {
			report.Truncated = true
			return fs.SkipAll
		}
		data, readErr := s.openAndRead(rootDir, path, info, limits.bytes-bytesRead)
		if readErr != nil {
			if errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
				return readErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			report.Truncated = true
			return nil
		}
		bytesRead += int64(len(data))
		if isBinary(data) {
			return nil
		}
		if s.scanContent(filepath.ToSlash(path), data, seen, &report.Findings, limits.findings, vf) {
			report.Truncated = true
			return fs.SkipAll
		}
		return nil
	})
	if walkErr != nil {
		return report, fmt.Errorf("secret scan: %w", walkErr)
	}
	if err := ctx.Err(); err != nil {
		return report, fmt.Errorf("secret scan: %w", err)
	}
	return report, nil
}

func openAndReadRegular(root *os.Root, rel string, walkInfo fs.FileInfo, limit int64) ([]byte, error) {
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	openedInfo, err := f.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(walkInfo, openedInfo) ||
		openedInfo.Size() == 0 || openedInfo.Size() > maxFileBytes || openedInfo.Size() > limit {
		return nil, fmt.Errorf("opened file %q changed", rel)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("read file %q", rel)
	}
	after, err := f.Stat()
	if err != nil || !stableFileSnapshot(openedInfo, after, int64(len(data))) {
		return nil, fmt.Errorf("file %q changed during scan", rel)
	}
	return data, nil
}

func stableFileSnapshot(before, after fs.FileInfo, bytesRead int64) bool {
	return before.Mode().IsRegular() && after.Mode().IsRegular() && os.SameFile(before, after) &&
		before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) && after.Size() == bytesRead
}

func (s *Scanner) scanContent(rel string, data []byte, seen map[string]bool, out *[]ports.SecretRawFinding, limit int, vf *verifyState) bool {
	// Blank comment regions (VB, #-family, //-and-/* */-family) before the rules run, so a secret that
	// lives only in a comment is not reported as a live finding. Offsets/newlines are preserved.
	// Keep the pre-mask text: an inline "synapse:allow" annotation lives in the trailing comment that
	// maskComments blanks, and maskComments preserves byte offsets, so a match offset indexes both.
	original := string(data)
	data = maskComments(rel, data)
	text := string(data)
	var masked []byte // notebook-output-masked view, built once on first demand
	awsCandidates := make([]awsCandidate, 0, 3)
	for i := range s.rules {
		r := &s.rules[i]
		// maskComments preserves byte offsets, so a match offset and a line count index either string.
		subject := text
		if r.scanComments && (!r.configFilesOnly || isConfigFileName(rel)) {
			subject = original
		}
		if r.maskNotebookOutput {
			if masked == nil {
				masked = maskNotebookOutputs(rel, []byte(subject))
			}
			subject = string(masked)
		}
		if r.maskPEMBodies {
			subject = string(maskPEMBlockBodies([]byte(subject)))
		}
		if !hasAnyKeyword(subject, r.keywords) {
			continue
		}
		for _, m := range r.re.FindAllStringSubmatchIndex(subject, -1) {
			if len(*out) >= limit {
				return true
			}
			start, end := m[0], m[1]
			if r.group > 0 && len(m) > 2*r.group+1 && m[2*r.group] >= 0 {
				start, end = m[2*r.group], m[2*r.group+1]
			}
			secret := subject[start:end]
			if s.allowed(secret, r.allow) {
				continue
			}
			if r.skipValue != nil && r.skipValue(secret) {
				continue
			}
			if r.lineSkip != nil && r.lineSkip(lineOf(subject, start)) {
				continue
			}
			if inlineAllow(lineOf(original, start)) {
				continue // an inline "synapse:allow" / "gitleaks:allow" annotation suppresses this line
			}
			if r.minEnt > 0 && shannon(secret) < r.minEnt {
				continue
			}
			line := 1 + strings.Count(subject[:start], "\n")
			key := r.id + ":" + rel + ":" + strconv.Itoa(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			// Active verification (opt-in) runs here, where the plaintext is still in scope, and only the
			// verdict is kept; the value is redacted into Match immediately after. verdict is a no-op
			// (SecretUnknown) on the deterministic path.
			verified := ports.SecretUnknown
			findingIndex := len(*out)
			if isAWSGroupedRule(r.id) {
				awsCandidates = append(awsCandidates, awsCandidate{ruleID: r.id, secret: secret, line: line, index: findingIndex})
			} else {
				verified = verdict(vf, r.id, secret)
			}
			*out = append(*out, ports.SecretRawFinding{
				File:        rel,
				Line:        line,
				RuleID:      r.id,
				Category:    r.category,
				Title:       r.title,
				Severity:    r.severity,
				Match:       redactMatch(secret),
				Verified:    verified,
				Fingerprint: secretFingerprint(secret),
			})
		}
	}
	verifyAWSPairs(vf, out, awsCandidates)
	// A secret hidden inside a base64/hex value (a Kubernetes Secret, a base64-wrapped credential) is
	// invisible to the rules above; the decode pass finds it. It runs on the same comment-masked text so a
	// secret encoded inside a comment stays masked.
	if s.scanDecoded(rel, text, original, seen, out, limit, vf) {
		return true
	}
	return false
}

var (
	// A base64 run of at least minBase64TokenLen characters, optionally padded. The class spans the std
	// (+/) and url (-_) alphabets; a token that mixes them decodes as neither and is skipped.
	base64TokenRe = regexp.MustCompile(`[A-Za-z0-9+/_-]{` + strconv.Itoa(minBase64TokenLen) + `,}={0,2}`)
	hexTokenRe    = regexp.MustCompile(`\b[0-9a-fA-F]{` + strconv.Itoa(minHexTokenLen) + `,}\b`)
)

// scanDecoded finds base64/hex tokens in text, decodes each one level (bounded), and re-runs the detectors
// over the decoded bytes, so a secret carried inside an encoded value is found. The finding is reported at
// the ENCODED token's line, where a reader edits it. The pass is purely ADDITIVE: a hit requires a real
// detector (with its distinctive keyword) to fire on the decoded bytes, so a random encoded blob (a hash,
// an id, minified data) produces nothing. Returns true if the finding limit was reached.
func (s *Scanner) scanDecoded(rel, text, original string, seen map[string]bool, out *[]ports.SecretRawFinding, limit int, vf *verifyState) bool {
	tokens := 0
	decodedBudget := maxDecodedBytesPerFile
	consider := func(start int, token string, decode func(string) ([]byte, bool), enc string) bool {
		if tokens >= maxDecodeTokensPerFile || decodedBudget <= 0 || len(token) > maxEncodedTokenLen {
			return false
		}
		// Count every decode ATTEMPT (a rejected decode still did the work), so the cap bounds total decode
		// cost even against a file of tokens that all decode to binary. A token is <= maxEncodedTokenLen, so
		// each decode allocates a bounded amount, and at most maxDecodeTokensPerFile decodes run.
		tokens++
		decoded, ok := decode(token)
		if !ok || len(decoded) == 0 || isBinary(decoded) {
			return false
		}
		decodedBudget -= len(decoded)
		// The inline-allow annotation lives in the trailing comment, which maskComments blanks in text;
		// check it against the pre-mask original (offsets are preserved by masking).
		if inlineAllow(lineOf(original, start)) {
			return false // an inline allow on the encoded token's line suppresses it
		}
		// A PEM block's body is masked before the detectors run, so one key carried inside an encoded
		// value stays one credential rather than one finding per base64 body line. The armour lines stay,
		// so the private-key rule still sees its header.
		decodedText := string(maskPEMBlockBodies(decoded))
		line := 1 + strings.Count(text[:start], "\n")
		for i := range s.rules {
			r := &s.rules[i]
			// A KEYWORD-FREE rule must not run here. Decoded bytes are high-entropy by construction, so the
			// entropy rule fired on anything base64 carried: an EKS cluster's base64 CA certificate decodes
			// to a PEM whose DER body is a perfect high-entropy token, and that was 19 findings on one
			// Terraform module repository, one per rendered fixture, for a value that is public by
			// definition. It also contradicted this pass's own contract, which is that a hit requires a real
			// detector with its distinctive keyword to fire on the decoded bytes.
			if len(r.keywords) == 0 {
				continue
			}
			if !hasAnyKeyword(decodedText, r.keywords) {
				continue
			}
			for _, m := range r.re.FindAllStringSubmatchIndex(decodedText, -1) {
				if len(*out) >= limit {
					return true
				}
				ds, de := m[0], m[1]
				if r.group > 0 && len(m) > 2*r.group+1 && m[2*r.group] >= 0 {
					ds, de = m[2*r.group], m[2*r.group+1]
				}
				secret := decodedText[ds:de]
				if s.allowed(secret, r.allow) || (r.minEnt > 0 && shannon(secret) < r.minEnt) {
					continue
				}
				key := r.id + ":" + enc + ":" + rel + ":" + strconv.Itoa(line)
				if seen[key] {
					continue
				}
				seen[key] = true
				*out = append(*out, ports.SecretRawFinding{
					File: rel, Line: line, RuleID: r.id, Category: r.category,
					Title: r.title + " (" + enc + "-encoded)", Severity: r.severity,
					Match:    redactMatch(secret),
					Verified: verdict(vf, r.id, secret),
				})
			}
		}
		return false
	}
	// Cap the candidate enumeration at the token budget so a file packed with encoded-looking runs cannot
	// force materializing millions of match locations before the per-token cap in consider applies.
	for _, loc := range base64TokenRe.FindAllStringIndex(text, maxDecodeTokensPerFile) {
		if consider(loc[0], text[loc[0]:loc[1]], decodeBase64Token, "base64") {
			return true
		}
	}
	for _, loc := range hexTokenRe.FindAllStringIndex(text, maxDecodeTokensPerFile) {
		if consider(loc[0], text[loc[0]:loc[1]], decodeHexToken, "hex") {
			return true
		}
	}
	return false
}

// decodeBase64Token tries the standard and URL alphabets, padded and unpadded, returning the first that
// decodes cleanly. A token that fits no alphabet is not base64 and is skipped.
func decodeBase64Token(token string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(token); err == nil && len(b) > 0 {
			return b, true
		}
	}
	return nil, false
}

// decodeHexToken decodes an even-length hex run.
func decodeHexToken(token string) ([]byte, bool) {
	if len(token)%2 != 0 {
		return nil, false
	}
	b, err := hex.DecodeString(token)
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return b, true
}

// inlineAllow reports whether a line carries an inline suppression annotation ("synapse:allow", or
// "gitleaks:allow" for drop-in compatibility), so an intentional test or example secret on that line is
// not reported. Matched case-insensitively anywhere on the line, since it lives in a trailing comment.
func inlineAllow(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "synapse:allow") || strings.Contains(lower, "gitleaks:allow")
}

// lineOf returns the full line containing byte offset at.
func lineOf(text string, at int) string {
	start := strings.LastIndexByte(text[:at], '\n') + 1
	end := strings.IndexByte(text[at:], '\n')
	if end < 0 {
		return text[start:]
	}
	return text[start : at+end]
}

// maskPEMBlockBodies blanks the base64 BODY of every PEM block while preserving byte offsets and newlines,
// so a match offset and a line count still index the same positions. The BEGIN and END armour lines are kept:
// the private-key rule matches the header and must still see it.
//
// A key block is ONE credential. Without this every base64 line of it also satisfied the keyword-free entropy
// rule, so a 49-line SSH key inside an ArgoCD repository manifest produced 49 entropy findings beside the one
// private-key finding, and the same block in git history doubled that to 100. The remediation is one rotation.
func maskPEMBlockBodies(data []byte) []byte {
	out := append([]byte(nil), data...)
	inBody := false
	for start := 0; start < len(out); {
		end := start
		for end < len(out) && out[end] != '\n' {
			end++
		}
		line := string(out[start:end])
		switch {
		case strings.Contains(line, "-----BEGIN"):
			inBody = true // the header line itself is preserved
		case strings.Contains(line, "-----END"):
			inBody = false
		case inBody:
			for i := start; i < end; i++ {
				if out[i] != '\r' {
					out[i] = ' '
				}
			}
		}
		start = end + 1
	}
	return out
}

// pemBodyRunMin is the shortest base64 run counted as key body. It sits above every word in the PEM armour
// ("BEGIN", "PRIVATE", "OPENSSH") so a bare header contributes nothing.
const pemBodyRunMin = 20

// pemBodyMinBytes is how much base64 body must sit on a PEM header's line before the header is read as an
// embedded key block rather than a quoted constant. The smallest real key body, an EC P-256 key in PKCS#8,
// is about 240 base64 characters, and a rule example or a delimiter constant carries none.
const pemBodyMinBytes = 128

// pemHeaderQuotedInline reports whether the PEM header on this line is a quoted one-line constant rather
// than the first line of a key block. Three marks say one-line string: the header does not start the line,
// the END marker sits beside it, or the line carries an escaped newline. Each of those is a rule example, a
// delimiter to strip, or a test name.
//
// A key EMBEDDED in a source-code string literal carries all three marks and is still a real key. A GCP
// service-account JSON pasted into a Java constant reads as
// `"  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEv…\\n-----END PRIVATE KEY-----\\n"`, and standing
// it down lost a critical finding on live code. So the stand-down now requires the line to carry no key
// body. Base64 is counted across the whole line rather than as one run, because the escaped newlines break
// a single key into many short runs.
func pemHeaderQuotedInline(line string) bool {
	if pemBodyBase64Bytes(line) >= pemBodyMinBytes {
		return false
	}
	trimmed := strings.TrimLeft(line, " \t\"'`")
	if !strings.HasPrefix(trimmed, "-----BEGIN") {
		return true
	}
	return strings.Contains(line, "-----END") || strings.Contains(line, `\n`)
}

// pemBodyBase64Bytes sums the base64 runs on the line that are long enough to be key body.
func pemBodyBase64Bytes(line string) int {
	total, run := 0, 0
	flush := func() {
		if run >= pemBodyRunMin {
			total += run
		}
		run = 0
	}
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '=':
			run++
		default:
			flush()
		}
	}
	flush()
	return total
}

// maskVBComments preserves byte offsets and newlines while blanking apostrophe and statement Rem comments.
// Doubled quotes remain inside string literals, so an apostrophe or Rem in a VB string is not misread.
func maskVBComments(data []byte) []byte {
	out := append([]byte(nil), data...)
	for start := 0; start < len(out); {
		end := start
		for end < len(out) && out[end] != '\n' {
			end++
		}
		inString, statementStart := false, true
		for i := start; i < end; i++ {
			if inString {
				if out[i] == '"' {
					if i+1 < end && out[i+1] == '"' {
						i++
						continue
					}
					inString = false
				}
				continue
			}
			if out[i] == '"' {
				inString = true
				statementStart = false
				continue
			}
			if out[i] == '\'' {
				for j := i; j < end; j++ {
					out[j] = ' '
				}
				break
			}
			if out[i] == ':' {
				statementStart = true
				continue
			}
			if out[i] == ' ' || out[i] == '\t' || out[i] == '\r' {
				continue
			}
			if statementStart && i+3 <= end && strings.EqualFold(string(out[i:i+3]), "rem") &&
				(i+3 == end || out[i+3] == ' ' || out[i+3] == '\t') {
				for j := i; j < end; j++ {
					out[j] = ' '
				}
				break
			}
			statementStart = false
		}
		start = end + 1
	}
	return out
}

func (s *Scanner) allowed(secret string, ruleAllow []*regexp.Regexp) bool {
	t := strings.TrimSpace(secret)
	for _, re := range s.allow {
		if re.MatchString(t) {
			return true
		}
	}
	for _, re := range ruleAllow {
		if re.MatchString(t) {
			return true
		}
	}
	return false
}

// secretFingerprint is a stable, non-reversible identity for a matched credential. It exists so the same
// credential seen in many git blobs is recognised as ONE leak: the remediation is one rotation, however many
// commits carry it. SHA-256 is used because the value must never be recoverable from the finding, and the
// digest is domain-separated so a fingerprint cannot be confused with any other digest in the system.
func secretFingerprint(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("synapse-secret-fingerprint:" + s))
	return hex.EncodeToString(sum[:])
}

// redactMatch masks a secret to a short, non-usable preview. A private-key block is replaced wholesale.
func redactMatch(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "PRIVATE KEY") {
		return "<private key redacted>"
	}
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:3] + strings.Repeat("*", 6) + s[len(s)-2:]
}

func hasAnyKeyword(text string, kws []string) bool {
	if len(kws) == 0 {
		return true
	}
	text = strings.ToLower(text)
	for _, k := range kws {
		if strings.Contains(text, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

// shannon returns the Shannon entropy (bits per char) of s.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, f := range freq {
		p := f / n
		h -= p * math.Log2(p)
	}
	return h
}

func isBinary(data []byte) bool {
	n := len(data)
	if n > sniffBytes {
		n = sniffBytes
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func compileAll(pats []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

// highEntropyDeferKeywords are lowercase substrings that, when present on a line, make the keyword-FREE
// generic-high-entropy rule stand down (matched case-insensitively by hasAnyKeyword). The first group are
// credential keywords the PROMOTED/gating generic-secret rule owns, so a keyword-context secret is gated
// there rather than quarantined here; the second group are benign high-entropy contexts (SRI/integrity,
// digests, checksums, ETags) that are public hashes, not credentials.
var highEntropyDeferKeywords = []string{
	"secret", "token", "passwd", "password", "api_key", "apikey", "access_key",
	"integrity", "digest", "checksum", "sha256", "sha384", "sha512", "sha1", "md5", "fingerprint", "etag",
}

// wordlikePathToken reports whether a slash-bearing candidate is a PATH rather than base64. The
// keyword-free entropy rule's character class includes "/", so a URL or asset path of the right length
// clears the 4.5 bits/char floor and is reported as a credential. Found across a real estate: one notebook
// cell's output held 2.2 MB of a printed catalogue dump, and 1,999 of the 2,844 keyword-free entropy
// findings in the whole estate came from that single file, all of them CDN asset paths, one repeated 853
// times.
//
// The discriminator is base64's own signature: encoding random bytes produces mixed case throughout, so
// any run of 8 or more characters holds both an upper and a lower case letter. A path's segments are words
// and numbers, which do not. A candidate whose every slash-delimited segment lacks that mixed-case run is
// a path. Segments shorter than 8 are ignored, since a short one carries no evidence either way.
//
// This suppresses on the VALUE, so it cannot hide a credential that merely sits on a line near a path, and
// it leaves the keyword-anchored generic-secret rule untouched: a real token assigned to an api_key is
// still gated there whatever its shape.
// clientPublicBundlePrefixes are the environment-variable prefixes a frontend build tool INLINES into the
// browser bundle. A value behind one of them is published to every visitor by construction, so it is a
// public configuration value and not a leaked credential. Datadog's RUM client token, which is prefixed
// "pub" precisely because it ships in page source, arrives on live code as REACT_APP_DATADOG_CLIENT_TOKEN.
var clientPublicBundlePrefixes = []string{
	"REACT_APP_", "NEXT_PUBLIC_", "NUXT_PUBLIC_", "VITE_", "VUE_APP_",
	"EXPO_PUBLIC_", "GATSBY_", "PUBLIC_", "STORYBOOK_",
}

// clientPublicVariableLine reports whether the line assigns to one of those variables. It gates only the
// GENERIC keyword rule: for a generic high-entropy value there is no way to tell a public token from a
// private one, and the variable name settles it. A distinctive-prefix provider rule (an AWS key, a GitHub
// token) is deliberately NOT gated, because a real provider credential behind a public prefix is a leak
// that has already shipped.
func clientPublicVariableLine(line string) bool {
	for _, prefix := range clientPublicBundlePrefixes {
		at := strings.Index(line, prefix)
		if at < 0 {
			continue
		}
		// The prefix must start a token, so a substring inside some other identifier does not count.
		if at > 0 {
			c := line[at-1]
			if c == '_' || c == '-' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
				continue
			}
		}
		return true
	}
	return false
}

// secretNamingKeys are keys whose value NAMES a credential store rather than holding a credential. In a Helm
// values file `existingSecret: app-db-credentials` points at a Kubernetes Secret, so the value is a resource
// name that is meant to be in the repository.
var secretNamingKeys = []string{
	"existingsecret", "existingsecretname", "secretname", "secret_name", "secret-name",
	"secretref", "secret_ref", "secretkeyref", "existingclaim", "secretprovider", "secretproviderclass",
}

// namesACredentialStore reports whether the line's key points at a credential store instead of holding a
// credential, which is the one shape a commented-out configuration line shares with a real leak.
func namesACredentialStore(line string) bool {
	key, _, found := strings.Cut(line, ":")
	if !found {
		key, _, found = strings.Cut(line, "=")
		if !found {
			return false
		}
	}
	normalised := strings.ToLower(strings.Trim(strings.TrimSpace(key), "#/-[] \t\"'"))
	for _, name := range secretNamingKeys {
		if strings.HasSuffix(normalised, name) {
			return true
		}
	}
	return false
}

// commentedCredentialLineSkip drops the two line shapes a commented-out setting shares with something that is
// not a credential: a value inlined into a browser bundle by construction, and a key that names a credential
// store rather than holding a credential.
func commentedCredentialLineSkip(line string) bool {
	return clientPublicVariableLine(line) || namesACredentialStore(line)
}

// assignedValueNotCredential reports whether the value assigned to a credential-named key is something
// other than the credential. Two shapes account for it in practice, and both became reachable when the
// value's quotes stopped being required:
//
//   - A PATH saying where the credential lives (`password_file: /run/secrets/db_password`). wordlikePathToken
//     already recognises that shape, and it is used here for exactly the same reason.
//   - An IDENTIFIER or constant reference standing in for the credential (`password = DB_PASSWORD_DEFAULT`,
//     `secret: defaultClientSecret`). A real credential of 16 characters or more essentially always carries
//     a digit; a name written for a human does not, and in source code an unquoted assignment holds a name
//     far more often than a literal. A value with any character no identifier can carry, so anything with
//     /, +, = or -, is exempt from the identifier test and judged on entropy alone.
func assignedValueNotCredential(secret string) bool {
	if wordlikePathToken(secret) {
		return true
	}
	if identifierAssignment(secret) {
		return true
	}
	hasDigit := false
	for i := 0; i < len(secret); i++ {
		c := secret[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		default:
			return false // not an identifier at all: judge it on entropy
		}
	}
	return !hasDigit
}

// nextAssignmentRe matches an identifier immediately followed by "=": the shape of another assignment, not
// of a value.
var nextAssignmentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}=`)

// identifierAssignment reports whether the captured value is itself an assignment. The whitespace between a
// key and its value may cross a newline, which is how a JSON formatter breaks a long line, so a key with an
// EMPTY value reaches past its own line and takes the next one:
//
//	CAPTCHA_H_SECRET=
//	CAPTCHA_H_TIMEOUT=5
//
// captured CAPTCHA_H_TIMEOUT=5 as the secret and reported it a line below the key. Three of those sat in one
// env template on a real repository. A base64 value carries "=" only as trailing padding, never after an
// identifier, so this cannot reject a real credential.
func identifierAssignment(secret string) bool {
	return nextAssignmentRe.MatchString(secret)
}

// connectionStringPlaceholder reports whether a connection string's password component is a substitution
// placeholder rather than a credential.
func connectionStringPlaceholder(value string) bool {
	at := strings.LastIndex(value, "@")
	if at < 0 {
		return false
	}
	colon := strings.LastIndex(value[:at], ":")
	if colon < 0 {
		return false
	}
	password := value[colon+1 : at]
	if templatePlaceholder(password) {
		return true
	}
	// The other documented shape names the parts with the words themselves: `postgres://user:password@host/db`
	// in a docstring is the URI grammar, not a credential. 65 of one repository's findings were that line in
	// driver docs and translation catalogues. BOTH components must be generic, so `admin:password` stays
	// reported: a real account name beside a weak password is a credential, and a weak one at that.
	scheme := strings.Index(value, "://")
	if scheme < 0 {
		return false
	}
	user := value[scheme+3 : colon]
	return placeholderWords[strings.ToLower(user)] && placeholderWords[strings.ToLower(password)]
}

// placeholderWords are the self-describing names documentation uses in place of a value.
var placeholderWords = map[string]bool{
	"user": true, "username": true, "user_name": true, "youruser": true, "your_user": true,
	"myuser": true, "dbuser": true, "db_user": true, "login": true, "account": true,
	"password": true, "passwd": true, "pwd": true, "pass": true, "secret": true,
	"yourpassword": true, "your_password": true, "mypassword": true, "my_password": true,
	"dbpassword": true, "db_password": true, "changeme": true, "changethis": true,
}

// templatePlaceholder recognises the substitution shapes documentation and configuration use to stand in for
// a value: <NAME>, {name}, {{name}}, ${NAME}, %(name)s and $NAME.
func templatePlaceholder(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return true
	}
	switch {
	case strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">"):
		return true
	case strings.HasPrefix(v, "{") && strings.HasSuffix(v, "}"):
		return true
	case strings.HasPrefix(v, "${"), strings.HasPrefix(v, "%("), strings.HasPrefix(v, "%{"):
		return true
	case strings.HasPrefix(v, "$"):
		return true
	}
	return false
}

// codecAlphabets are the ordered character tables every base64/base32/base36 implementation carries. They
// have maximal character variety, so they clear any entropy floor by construction, and one of them appears
// in a vendored polyfill in most JavaScript repositories.
var codecAlphabets = []string{
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=",
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=",
	"0123456789abcdefghijklmnopqrstuvwxyz",
}

// codecAlphabetToken reports whether the candidate is a run of one of those tables. A credential that is a
// contiguous slice of an ordered alphabet is not a credential anyone generated.
func codecAlphabetToken(value string) bool {
	if len(value) < 24 {
		return false // too short to be a table; leave it to the entropy floor
	}
	for _, alphabet := range codecAlphabets {
		if strings.Contains(alphabet, value) {
			return true
		}
	}
	return false
}

func wordlikePathToken(secret string) bool {
	if !strings.Contains(secret, "/") {
		return false
	}
	for _, seg := range strings.Split(secret, "/") {
		if len(seg) < 8 {
			continue
		}
		var hasUpper, hasLower bool
		for _, c := range seg {
			switch {
			case c >= 'A' && c <= 'Z':
				hasUpper = true
			case c >= 'a' && c <= 'z':
				hasLower = true
			}
		}
		if hasUpper && hasLower {
			return false
		}
	}
	return true
}

// resourcePathExtensions are the file extensions whose presence marks a quoted value as a RESOURCE PATH
// rather than a credential. Kept to source, config and migration artefacts: a credential is never stored as
// the name of a .java or .xml file, while a long generated migration name is exactly that shape.
var resourcePathExtensions = []string{
	".xml", ".sql", ".yaml", ".yml", ".json", ".properties", ".java", ".kt", ".ts", ".js", ".go", ".py",
	".html", ".csv", ".md", ".txt", ".png", ".jpg", ".svg",
	// Media and font assets. A CDN asset URL carries a high-entropy path segment by design: an avatar at
	// pbs.twimg.com/profile_images/<18 digits>/<8 mixed-case chars>_400x400.jpeg cleared the entropy floor
	// six times in one repository, where gitleaks reported nothing.
	".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp", ".mp4", ".webm", ".woff", ".woff2", ".ttf", ".eot",
}

// resourcePathIndicators mark the line as declaring where something lives.
// A URL is a location by definition, so "://" is the indicator for the asset case. Both halves are still
// required: the line must name a location AND carry a known non-credential extension, so a credential in a
// query string is untouched.
var resourcePathIndicators = []string{
	"classpath:", "file=", "file:", "path=", "resource=", "src=", "href=", "include", "://",
	// CSS and SCSS name a location with `src:` and `url(` rather than an attribute. A webfont is served
	// under a content hash, so `src: url(/fonts/UcC73FwrK3iLTeHuS_fvQtMwCp50KnMa25L7W0Q5n-wU.woff2)` is a
	// 44-character high-entropy token by design: two font stylesheets produced 20 of one repository's 26
	// secret findings, where gitleaks reported one.
	"src:", "url(", "srcset=",
}

// lineDeclaresResourcePath reports whether the line is a resource declaration whose high-entropy token is a
// FILE NAME, not a credential. Liquibase and Flyway generate migration names long and varied enough to clear
// a 4.5 bits/char entropy floor on the base64 alphabet, so a JHipster changelog produces one keyword-free
// entropy hit per include line and nothing in the old skip list stood them down.
//
// Both halves are required, which is what keeps this from swallowing a real secret: the line must name a
// location AND carry a known non-credential extension. A credential assigned on a line that merely contains
// the word "file" still fires, and a credential keyword on the line defers to the gating generic-secret rule
// before this is consulted.
func lineDeclaresResourcePath(line string) bool {
	lower := strings.ToLower(line)
	hasIndicator := false
	for _, indicator := range resourcePathIndicators {
		if strings.Contains(lower, indicator) {
			hasIndicator = true
			break
		}
	}
	if !hasIndicator {
		return false
	}
	for _, ext := range resourcePathExtensions {
		if strings.Contains(lower, ext) {
			return true
		}
	}
	return false
}

// defaultRules is the owned starter ruleset. Prefix-anchored rules (AWS/GitHub/GitLab/Slack/Google/private
// key) need no entropy gate; the generic assignment rule is entropy-gated and only MEDIUM to bound FPs.
func baseDefaultRules() []rule {
	return []rule{
		{
			id: "aws-access-key-id", category: "AWS", title: "AWS access key ID", severity: shared.SeverityHigh,
			keywords: []string{"AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ASIA", "A3T"},
			re:       regexp.MustCompile(`\b((?:A3T[A-Z0-9])|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`),
		},
		{
			id: "github-token", category: "GitHub", title: "GitHub token", severity: shared.SeverityHigh,
			keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
			re:       regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b`),
		},
		{
			id: "gitlab-pat", category: "GitLab", title: "GitLab personal access token", severity: shared.SeverityHigh,
			keywords: []string{"glpat-"},
			re:       regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`),
		},
		{
			id: "slack-token", category: "Slack", title: "Slack token", severity: shared.SeverityHigh,
			keywords: []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"},
			re:       regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
		},
		{
			id: "google-api-key", category: "Google", title: "Google API key", severity: shared.SeverityHigh,
			keywords: []string{"AIza"},
			re:       regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		},
		{
			id: "private-key", category: "PrivateKey", title: "Private key block", severity: shared.SeverityCritical,
			keywords: []string{"PRIVATE KEY"},
			re:       regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
			// A key block starts its line with the header (a PEM file, a raw string). A header that sits
			// after other code on its line, with the END marker or an escaped newline beside it, is a
			// one-line string constant: a rule example, a delimiter to strip, a test name.
			lineSkip: pemHeaderQuotedInline,
		},
		{
			id: "jwt", category: "JWT", title: "JSON Web Token", severity: shared.SeverityMedium,
			keywords: []string{"eyJ"},
			re:       regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
		},
		// ── cloud provider keys ─────────────────────────────────────────────────
		{
			id: "aws-secret-access-key", category: "AWS", title: "AWS secret access key", severity: shared.SeverityHigh,
			keywords: []string{"aws_secret", "AWS_SECRET", "secret_access_key", "SecretAccessKey"},
			re:       regexp.MustCompile(`(?i)aws_?secret_?access_?key["']?\s*[:=]\s*["']([A-Za-z0-9/+]{40})["']`),
			group:    1, minEnt: 4.0,
		},
		{
			id: "gcp-service-account-key", category: "GCP", title: "GCP service account key", severity: shared.SeverityHigh,
			keywords: []string{"service_account"},
			re:       regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		},
		{
			id: "azure-storage-key", category: "Azure", title: "Azure storage account key", severity: shared.SeverityHigh,
			keywords: []string{"AccountKey="},
			re:       regexp.MustCompile(`AccountKey=[A-Za-z0-9+/]{86,88}==`),
		},
		// ── VCS / package registry tokens ───────────────────────────────────────
		{
			id: "github-fine-grained-pat", category: "GitHub", title: "GitHub fine-grained token", severity: shared.SeverityHigh,
			keywords: []string{"github_pat_"},
			re:       regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`),
		},
		{
			id: "npm-token", category: "npm", title: "npm access token", severity: shared.SeverityHigh,
			keywords: []string{"npm_"},
			re:       regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
		},
		{
			id: "pypi-token", category: "PyPI", title: "PyPI upload token", severity: shared.SeverityHigh,
			keywords: []string{"pypi-"},
			re:       regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{50,}\b`),
		},
		{
			id: "rubygems-token", category: "RubyGems", title: "RubyGems API key", severity: shared.SeverityHigh,
			keywords: []string{"rubygems_"},
			re:       regexp.MustCompile(`\brubygems_[a-f0-9]{48}\b`),
		},
		// ── SaaS provider tokens ─────────────────────────────────────────────────
		{
			id: "stripe-secret-key", category: "Stripe", title: "Stripe secret key", severity: shared.SeverityHigh,
			keywords: []string{"sk_live_", "rk_live_"},
			re:       regexp.MustCompile(`\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b`),
		},
		{
			id: "twilio-api-key", category: "Twilio", title: "Twilio API key SID", severity: shared.SeverityHigh,
			keywords: []string{"SK"},
			re:       regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),
		},
		{
			id: "sendgrid-api-key", category: "SendGrid", title: "SendGrid API key", severity: shared.SeverityHigh,
			keywords: []string{"SG."},
			re:       regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`),
		},
		{
			id: "slack-webhook-url", category: "Slack", title: "Slack webhook URL", severity: shared.SeverityMedium,
			keywords: []string{"hooks.slack.com"},
			re:       regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]{40,}`),
		},
		{
			id: "mailgun-api-key", category: "Mailgun", title: "Mailgun API key", severity: shared.SeverityHigh,
			keywords: []string{"key-"},
			re:       regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`),
		},
		{
			id: "mailchimp-api-key", category: "Mailchimp", title: "Mailchimp API key", severity: shared.SeverityHigh,
			keywords: []string{"-us"},
			re:       regexp.MustCompile(`\b[0-9a-f]{32}-us[0-9]{1,2}\b`),
		},
		{
			id: "openai-api-key", category: "OpenAI", title: "OpenAI API key", severity: shared.SeverityHigh,
			keywords: []string{"sk-"},
			re:       regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b`),
		},
		{
			id: "anthropic-api-key", category: "Anthropic", title: "Anthropic API key", severity: shared.SeverityHigh,
			keywords: []string{"sk-ant-"},
			re:       regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`),
		},
		{
			id: "digitalocean-token", category: "DigitalOcean", title: "DigitalOcean personal access token", severity: shared.SeverityHigh,
			keywords: []string{"dop_v1_"},
			re:       regexp.MustCompile(`\bdop_v1_[a-f0-9]{64}\b`),
		},
		{
			id: "shopify-token", category: "Shopify", title: "Shopify access token", severity: shared.SeverityHigh,
			keywords: []string{"shpat_", "shpss_", "shpca_", "shppa_"},
			re:       regexp.MustCompile(`\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b`),
		},
		{
			id: "square-token", category: "Square", title: "Square access token", severity: shared.SeverityHigh,
			keywords: []string{"sq0atp-", "sq0csp-", "EAAA"},
			re:       regexp.MustCompile(`\b(?:sq0atp-[A-Za-z0-9_-]{22}|sq0csp-[A-Za-z0-9_-]{43}|EAAA[A-Za-z0-9_-]{60,})\b`),
		},
		{
			id: "telegram-bot-token", category: "Telegram", title: "Telegram bot token", severity: shared.SeverityMedium,
			keywords: []string{":AA"},
			re:       regexp.MustCompile(`\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b`),
		},
		{
			id: "new-relic-key", category: "NewRelic", title: "New Relic API key", severity: shared.SeverityHigh,
			keywords: []string{"NRAK-", "NRAA-", "NRJS-", "NRII-", "NRRA-"},
			re:       regexp.MustCompile(`\bNR(?:AK|AA|JS|II|RA)-[A-Za-z0-9]{27}\b`),
		},
		{
			id: "dynatrace-token", category: "Dynatrace", title: "Dynatrace token", severity: shared.SeverityHigh,
			keywords: []string{"dt0c01."},
			re:       regexp.MustCompile(`\bdt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b`),
		},
		{
			id: "grafana-token", category: "Grafana", title: "Grafana service account token", severity: shared.SeverityHigh,
			keywords: []string{"glc_", "glsa_"},
			re:       regexp.MustCompile(`\bgl(?:c|sa)_[A-Za-z0-9_]{32,}\b`),
		},
		{
			id: "planetscale-token", category: "PlanetScale", title: "PlanetScale token", severity: shared.SeverityHigh,
			keywords: []string{"pscale_pw_", "pscale_tkn_"},
			re:       regexp.MustCompile(`\bpscale_(?:pw|tkn)_[A-Za-z0-9_-]{32,}\b`),
		},
		{
			id: "doppler-token", category: "Doppler", title: "Doppler token", severity: shared.SeverityHigh,
			keywords: []string{"dp.pt.", "dp.st.", "dp.ct.", "dp.sa."},
			re:       regexp.MustCompile(`\bdp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,}\b`),
		},
		{
			id: "postman-api-key", category: "Postman", title: "Postman API key", severity: shared.SeverityHigh,
			keywords: []string{"PMAK-"},
			re:       regexp.MustCompile(`\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b`),
		},
		{
			id: "huggingface-token", category: "HuggingFace", title: "Hugging Face token", severity: shared.SeverityHigh,
			keywords: []string{"hf_"},
			re:       regexp.MustCompile(`\bhf_[A-Za-z0-9]{34}\b`),
		},
		{
			id: "sentry-dsn", category: "Sentry", title: "Sentry DSN with secret", severity: shared.SeverityMedium,
			keywords: []string{"sentry.io"},
			re:       regexp.MustCompile(`https://[a-f0-9]{32}(?::[a-f0-9]{32})?@[a-z0-9.-]*sentry\.io/[0-9]+`),
		},
		// ── infra / CI tokens ────────────────────────────────────────────────────
		{
			id: "vault-token", category: "Vault", title: "HashiCorp Vault token", severity: shared.SeverityHigh,
			keywords: []string{"hvs.", "hvb."},
			re:       regexp.MustCompile(`\bhv[sb]\.[A-Za-z0-9_-]{20,}\b`),
		},
		{
			id: "terraform-cloud-token", category: "Terraform", title: "Terraform Cloud API token", severity: shared.SeverityHigh,
			keywords: []string{".atlasv1."},
			re:       regexp.MustCompile(`\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}\b`),
		},
		{
			id: "datadog-api-key", category: "Datadog", title: "Datadog API key", severity: shared.SeverityMedium,
			keywords: []string{"datadog", "Datadog", "DATADOG", "dd_api", "DD_API"},
			re:       regexp.MustCompile(`(?i)(?:datadog|dd)[_-]?api[_-]?key["']?\s*[:=]\s*["']([a-f0-9]{32})["']`),
			group:    1, minEnt: 3.0,
		},
		// ── connection strings / other private-key formats ──────────────────────
		{
			id: "db-connection-string", category: "Database", title: "Database connection string with credentials", severity: shared.SeverityHigh,
			keywords: []string{"://"},
			re:       regexp.MustCompile(`\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:@\s/"']+:[^@\s/"']{3,}@[^\s"']+`),
			// A database's own documentation gives the URI shape with the parts named, so every such line
			// matched: `postgresql://<UserName>:<DBPassword>@<Database Host>/<Database Name>` was 234 of one
			// repository's 267 secret findings, almost all of them in docs. A password component that is a
			// substitution placeholder is a documented shape, not a credential.
			skipValue: connectionStringPlaceholder,
		},
		{
			id: "putty-private-key", category: "PrivateKey", title: "PuTTY private key", severity: shared.SeverityCritical,
			keywords: []string{"PuTTY-User-Key-File"},
			re:       regexp.MustCompile(`PuTTY-User-Key-File-\d`),
		},
		{
			id: "age-secret-key", category: "Age", title: "age secret key", severity: shared.SeverityHigh,
			keywords: []string{"AGE-SECRET-KEY-1"},
			re:       regexp.MustCompile(`AGE-SECRET-KEY-1[0-9A-Z]{58}`),
		},
		{
			id: "databricks-token", category: "Databricks", title: "Databricks personal access token", severity: shared.SeverityHigh,
			keywords: []string{"dapi"},
			re:       regexp.MustCompile(`\bdapi[0-9a-f]{32}\b`),
		},
		{
			id: "linear-api-key", category: "Linear", title: "Linear API key", severity: shared.SeverityHigh,
			keywords: []string{"lin_api_"},
			re:       regexp.MustCompile(`\blin_api_[A-Za-z0-9]{40}\b`),
		},
		{
			id: "jfrog-token", category: "JFrog", title: "JFrog Artifactory token", severity: shared.SeverityHigh,
			keywords: []string{"AKCp8"},
			re:       regexp.MustCompile(`\bAKCp8[A-Za-z0-9]{50,}\b`),
		},
		{
			// Keyword-INDEPENDENT high-entropy detector (D6.7): fires on a standalone base64-alphabet token
			// of 32-64 chars with Shannon entropy >= 4.5 bits/char, with NO adjacent keyword. The 4.5 floor
			// sits ABOVE the 4.0 maximum of any hex string, so git SHAs, md5/sha hashes, and hex UUIDs are
			// excluded by construction; only a base64-alphabet blob (a real token/key shape) can clear it.
			// The delimiter anchors capture a COMPLETE token, so a fragment of a long minified/base64 blob
			// (which is neither 32-64 chars nor delimited) does not match. Its hits are QUARANTINED into the
			// needs-verify queue (quarantineUnkeyedEntropySecrets), never promoted to a gating finding, so
			// the residual noise of a keyword-free rule cannot fail a build.
			id: "generic-high-entropy", category: "Generic", title: "High-entropy string", severity: shared.SeverityMedium,
			keywords: nil,
			re:       regexp.MustCompile(`(?:^|[^A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{32,64}={0,2})(?:[^A-Za-z0-9+/=_-]|$)`),
			group:    1, minEnt: 4.5,
			// This is the KEYWORD-FREE detector. If a secret keyword is on the same line, defer to the
			// keyword-anchored generic-secret rule (which is PROMOTED/gating) rather than quarantining here,
			// so a keyword-context secret is never demoted to gate-exempt. Also skip benign high-entropy
			// contexts (SRI/integrity, digests, checksums) that are public hashes, not credentials.
			lineSkip: func(line string) bool {
				return hasAnyKeyword(line, highEntropyDeferKeywords) || lineDeclaresResourcePath(line)
			},
			skipValue:          func(v string) bool { return wordlikePathToken(v) || codecAlphabetToken(v) },
			maskNotebookOutput: true,
			maskPEMBodies:      true,
		},
		{
			id: "generic-secret", category: "Generic", title: "Hardcoded secret", severity: shared.SeverityMedium,
			keywords: []string{"secret", "token", "passwd", "password", "api_key", "apikey", "apiKey", "access_key", "SECRET", "TOKEN", "API_KEY"},
			// The key had to be the bare word or a VB [bracketed] keyword, which missed the two
			// shapes real config files use: camelCase (`cookieSecret: "\u2026"`) and a bracketed
			// config key (`app.config['SECRET_KEY_HMAC_2'] = "\u2026"`). The keyword may now carry
			// an identifier suffix and be wrapped in brackets and quotes. The value guards
			// (16 characters, entropy 3.5, allow-list) are untouched, so precision is unchanged.
			// The value's quote may be BACKSLASH-ESCAPED. A Jupyter notebook stores each cell's source as
			// JSON-encoded strings, so a credential written in a code cell reads as api_key = \"…\" on
			// disk, and requiring a bare quote missed every one of them. Notebooks are exactly where a
			// data team leaves a key, so this was a hole in the GATING rule, not a cosmetic one. The
			// optional backslash admits one more character in a position that previously allowed only a
			// quote, so it costs no precision.
			//
			// The value's QUOTES ARE OPTIONAL. Requiring them meant the rule never fired on the one place
			// credentials actually sit in a Spring, Rails or Helm deployment: an unquoted YAML scalar, and
			// the same in .env and .properties. On one live repository gitleaks found 25 distinct
			// credentials this way that this rule could not see, under keys as plain as `password:`,
			// `client-secret:` and `secret-key:`. In exchange the match must now end at a real value
			// boundary (a quote, whitespace, end of input, or a delimiter), so a value the character class
			// truncates mid-token no longer counts; a quoted value behaves exactly as before.
			//
			// The keyword suffix also admits a HYPHEN, so `secret-key:` and `access-token:` reach the
			// rule. The value guards are unchanged: 16 characters, entropy 3.5, the allow-list, and the
			// identifier/path skip below.
			//
			// The separator admits a SECOND character, which makes `password := "…"` match. Go's short
			// variable declaration is how a Go program assigns a literal, and the single-character
			// separator had never matched it. `==` matches too, and a comparison against a literal
			// credential is a hardcoded credential just the same.
			re:        regexp.MustCompile(`(?i)(?:(?:(?:public|private|protected|friend|shared|static|readonly|writable|shadows|overrides|overridable|notinheritable|mustinherit)\s+)*(?:dim|const)\s+)?(?:\[\s*["']?)?(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)[A-Za-z0-9_-]{0,32}["']?[ \t]*\]?\$?[ \t]*(?:as[ \t]+[A-Za-z_][A-Za-z0-9_.]*)?[ \t]*["']?[ \t]*\]?[ \t]*[:=]=?\s*\\?["']?([A-Za-z0-9/+=_\-]{16,})(?:\\?["']|\s|$|[,;)\]}])`),
			group:     1,
			minEnt:    3.5,
			allow:     compileAll([]string{`(?i)^(true|false|null|none|localhost)$`}),
			skipValue: assignedValueNotCredential,
			lineSkip:  clientPublicVariableLine,
		},
		{
			// A credential in a COMMENT is still a credential in the repository: it is in the history, it is
			// readable by everyone with access, and a commented-out config line is usually the value that was
			// live yesterday. Comments are blanked before the rules run so that prose and examples do not
			// surface as live findings, which left this class unreported: gitleaks found seven of them on one
			// live estate where this scanner found none.
			//
			// The distinction the rule keeps is structural rather than textual. It matches only a credential
			// ASSIGNMENT whose line BEGINS with a comment marker, which is what a commented-out setting looks
			// like, and it leaves prose that merely mentions a credential alone. The value guards are the ones
			// generic-secret uses, so the bar for what counts as a credential is the same in a comment as it is
			// in live code, and the two never see the same text: generic-secret reads the masked file.
			id: "commented-credential", category: "Generic", title: "Credential left in a comment", severity: shared.SeverityMedium,
			keywords:        []string{"secret", "token", "passwd", "password", "api_key", "apikey", "apiKey", "access_key", "SECRET", "TOKEN", "API_KEY"},
			re:              regexp.MustCompile(`(?im)^[ \t]*(?:#|//|--|;)+[ \t]*["']?[A-Za-z0-9_.\-]{0,32}(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)[A-Za-z0-9_-]{0,32}["']?[ \t]*[:=]=?\s*\\?["']?([A-Za-z0-9/+=_\-]{16,})(?:\\?["']|\s|$|[,;)\]}])`),
			group:           1,
			minEnt:          3.5,
			allow:           compileAll([]string{`(?i)^(true|false|null|none|localhost)$`}),
			skipValue:       assignedValueNotCredential,
			lineSkip:        commentedCredentialLineSkip,
			scanComments:    true,
			configFilesOnly: true,
		},
		// ── additional distinctive-prefix provider tokens (near-zero false positive: the unique prefix is the signal) ──
		{
			id: "dockerhub-pat", category: "Docker", title: "Docker Hub personal access token", severity: shared.SeverityHigh,
			keywords: []string{"dckr_pat_"},
			// No trailing \b: the token body is base64url and may end in '-' or '_', where \b would not
			// match. The character class is its own right boundary (it stops at a quote/space).
			re: regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_-]{20,}`),
		},
		{
			id: "stripe-restricted-key", category: "Stripe", title: "Stripe restricted key", severity: shared.SeverityHigh,
			keywords: []string{"rk_live_", "rk_test_"},
			re:       regexp.MustCompile(`\brk_(?:live|test)_[A-Za-z0-9]{24,}\b`),
		},
		{
			id: "gitlab-pipeline-trigger-token", category: "GitLab", title: "GitLab pipeline trigger token", severity: shared.SeverityHigh,
			keywords: []string{"glptt-"},
			re:       regexp.MustCompile(`\bglptt-[0-9a-f]{40}\b`),
		},
		{
			id: "pulumi-access-token", category: "Pulumi", title: "Pulumi access token", severity: shared.SeverityHigh,
			keywords: []string{"pul-"},
			re:       regexp.MustCompile(`\bpul-[0-9a-f]{40}\b`),
		},
		{
			id: "clojars-deploy-token", category: "Clojars", title: "Clojars deploy token", severity: shared.SeverityHigh,
			keywords: []string{"CLOJARS_"},
			re:       regexp.MustCompile(`\bCLOJARS_[A-Za-z0-9]{60}\b`),
		},
		// ── AI/dev SaaS provider tokens (distinctive prefixes; lower-bound lengths since exact bodies vary) ──
		{
			id: "sentry-auth-token", category: "Sentry", title: "Sentry auth token", severity: shared.SeverityHigh,
			keywords: []string{"sntrys_"},
			re:       regexp.MustCompile(`\bsntrys_[A-Za-z0-9_=-]{40,}`),
		},
		{
			id: "readme-api-key", category: "ReadMe", title: "ReadMe API key", severity: shared.SeverityHigh,
			keywords: []string{"rdme_"},
			re:       regexp.MustCompile(`\brdme_[A-Za-z0-9]{40,}\b`),
		},
		{
			id: "figma-token", category: "Figma", title: "Figma personal access token", severity: shared.SeverityHigh,
			keywords: []string{"figd_"},
			re:       regexp.MustCompile(`\bfigd_[A-Za-z0-9_-]{40,}`),
		},
		{
			id: "atlassian-api-token", category: "Atlassian", title: "Atlassian API token", severity: shared.SeverityHigh,
			keywords: []string{"ATATT3xFfGF0"},
			re:       regexp.MustCompile(`\bATATT3xFfGF0[A-Za-z0-9_=-]{40,}`),
		},
		{
			id: "openshift-token", category: "OpenShift", title: "OpenShift ServiceAccount token", severity: shared.SeverityHigh,
			keywords: []string{"sha256~"},
			re:       regexp.MustCompile(`\bsha256~[A-Za-z0-9_-]{43}`),
		},
		{
			id: "duffel-api-token", category: "Duffel", title: "Duffel API token", severity: shared.SeverityHigh,
			keywords: []string{"duffel_test_", "duffel_live_"},
			re:       regexp.MustCompile(`\bduffel_(?:test|live)_[A-Za-z0-9_-]{43}`),
		},
		{
			id: "frameio-token", category: "Frame.io", title: "Frame.io developer token", severity: shared.SeverityHigh,
			keywords: []string{"fio-u-"},
			re:       regexp.MustCompile(`\bfio-u-[A-Za-z0-9_=-]{64}`),
		},
		{
			id: "definednetworking-token", category: "DefinedNetworking", title: "Defined Networking nebula API key", severity: shared.SeverityHigh,
			keywords: []string{"dnkey-"},
			re:       regexp.MustCompile(`\bdnkey-[A-Za-z0-9=_-]{26}-[A-Za-z0-9=_-]{52}`),
		},
		{
			id: "typeform-token", category: "Typeform", title: "Typeform personal access token", severity: shared.SeverityHigh,
			keywords: []string{"tfp_"},
			re:       regexp.MustCompile(`\btfp_[A-Za-z0-9_-]{40,}`),
		},
		{
			id: "prefect-api-key", category: "Prefect", title: "Prefect Cloud API key", severity: shared.SeverityHigh,
			keywords: []string{"pnu_", "pnb_"},
			re:       regexp.MustCompile(`\bpn[ub]_[A-Za-z0-9]{36}`),
		},
		{
			id: "contentful-token", category: "Contentful", title: "Contentful personal access token", severity: shared.SeverityHigh,
			keywords: []string{"CFPAT-"},
			re:       regexp.MustCompile(`\bCFPAT-[A-Za-z0-9_-]{43}`),
		},
		{
			id: "shippo-token", category: "Shippo", title: "Shippo API token", severity: shared.SeverityHigh,
			keywords: []string{"shippo_live_", "shippo_test_"},
			re:       regexp.MustCompile(`\bshippo_(?:live|test)_[A-Fa-f0-9]{40}`),
		},
		{
			id: "onepassword-service-account", category: "1Password", title: "1Password service account token", severity: shared.SeverityCritical,
			keywords: []string{"ops_eyJ"},
			re:       regexp.MustCompile(`\bops_eyJ[A-Za-z0-9+/]{250,}={0,3}`),
		},
		{
			id: "gitlab-runner-token", category: "GitLab", title: "GitLab runner registration token", severity: shared.SeverityHigh,
			keywords: []string{"GR1348941"},
			re:       regexp.MustCompile(`\bGR1348941[0-9A-Za-z_-]{20}`),
		},
		{
			id: "easypost-token", category: "EasyPost", title: "EasyPost API token", severity: shared.SeverityHigh,
			keywords: []string{"EZAK", "EZTK"},
			re:       regexp.MustCompile(`\bEZ(?:AK|TK)[A-Za-z0-9]{54}`),
		},
		{
			id: "slack-app-token", category: "Slack", title: "Slack app-level token", severity: shared.SeverityHigh,
			keywords: []string{"xapp-"},
			re:       regexp.MustCompile(`\bxapp-\d-[A-Z0-9]{11}-\d{13}-[a-f0-9]{64}`),
		},
		{
			id: "intra42-client-secret", category: "Intra42", title: "42 (Intra) client secret", severity: shared.SeverityHigh,
			keywords: []string{"s-s4t2ud-", "s-s4t2af-"},
			re:       regexp.MustCompile(`\bs-s4t2(?:ud|af)-[a-f0-9]{64}`),
		},
		{
			id: "yandex-api-key", category: "Yandex", title: "Yandex API key", severity: shared.SeverityHigh,
			keywords: []string{"AQVN"},
			re:       regexp.MustCompile(`\bAQVN[A-Za-z0-9_-]{35,38}`),
		},
		{
			id: "notion-token", category: "Notion", title: "Notion integration token", severity: shared.SeverityHigh,
			keywords: []string{"ntn_"},
			re:       regexp.MustCompile(`\bntn_[0-9]{11}[A-Za-z0-9]{35}`),
		},
		{
			id: "flutterwave-secret-key", category: "Flutterwave", title: "Flutterwave secret key", severity: shared.SeverityHigh,
			keywords: []string{"FLWSECK"},
			re:       regexp.MustCompile(`\bFLWSECK(?:_TEST|_LIVE)?-[0-9a-fA-F]{32}-X\b`),
		},
		{
			id: "alibaba-access-key-id", category: "Alibaba", title: "Alibaba Cloud AccessKey ID", severity: shared.SeverityHigh,
			keywords: []string{"LTAI"},
			re:       regexp.MustCompile(`\bLTAI[A-Za-z0-9]{20}\b`),
		},
		{
			id: "adafruit-io-key", category: "Adafruit", title: "Adafruit IO key", severity: shared.SeverityHigh,
			keywords: []string{"aio_"},
			re:       regexp.MustCompile(`\baio_[A-Za-z0-9]{28}\b`),
		},
		{
			id: "sourcegraph-access-token", category: "Sourcegraph", title: "Sourcegraph access token", severity: shared.SeverityHigh,
			keywords: []string{"sgp_"},
			// v2 (sgp_<40hex>) plus v3 (sgp_<16hex>_<40hex> instance-scoped, and sgp_local_<40hex>).
			re: regexp.MustCompile(`\bsgp_(?:[0-9a-fA-F]{40}|(?:[0-9a-fA-F]{16}|local)_[0-9a-fA-F]{40})\b`),
		},
		{
			id: "replicate-api-token", category: "Replicate", title: "Replicate API token", severity: shared.SeverityHigh,
			keywords: []string{"r8_"},
			// The whole token is 40 characters: the "r8_" prefix plus 37 alphanumerics.
			re: regexp.MustCompile(`\br8_[A-Za-z0-9]{37}\b`),
		},
		{
			id: "airtable-pat", category: "Airtable", title: "Airtable personal access token", severity: shared.SeverityHigh,
			keywords: []string{"pat"},
			// pat + 14 alphanumerics + '.' + 64 lowercase hex.
			re: regexp.MustCompile(`\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b`),
		},
		{
			id: "sonarqube-token", category: "SonarQube", title: "SonarQube token", severity: shared.SeverityHigh,
			keywords: []string{"sqp_", "squ_", "sqa_"},
			// user (squ_), project (sqp_), and global-analysis (sqa_) tokens: prefix plus 40 lowercase hex.
			re: regexp.MustCompile(`\bsq[apu]_[0-9a-f]{40}\b`),
		},
		{
			id: "dropbox-token", category: "Dropbox", title: "Dropbox access token", severity: shared.SeverityHigh,
			keywords: []string{"sl."},
			// Short-lived token: "sl." + a 135-char base64url body (may end in '='), bounded by a
			// non-token character or end-of-line (a trailing \b is unreliable when the body ends in '=' or '-').
			// The reported secret is capture group 1 (the token without the trailing boundary character).
			re:    regexp.MustCompile(`\b(sl\.[A-Za-z0-9=_-]{135})(?:[^A-Za-z0-9=_-]|$)`),
			group: 1,
		},
		{
			id: "cloudinary-url", category: "Cloudinary", title: "Cloudinary URL credential", severity: shared.SeverityHigh,
			keywords: []string{"cloudinary://"},
			// cloudinary://<15-digit api key>:<27-char api secret>@<cloud name: letter then 1-127 [A-Za-z0-9-]>.
			re: regexp.MustCompile(`cloudinary://[0-9]{15}:[A-Za-z0-9_-]{27}@[A-Za-z][A-Za-z0-9-]{1,127}`),
		},
		{
			id: "discord-webhook-url", category: "Discord", title: "Discord webhook URL", severity: shared.SeverityMedium,
			keywords: []string{"discord.com/api/webhooks/", "discordapp.com/api/webhooks/"},
			// The webhook id (17-20 digits) plus its token (60-110 url-safe base64 chars); ptb./canary. hosts too.
			re: regexp.MustCompile(`https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,110}`),
		},
	}
}

// maskNotebookOutputs blanks the OUTPUT spans of a Jupyter notebook while preserving byte offsets and
// newlines, the same contract maskComments keeps, so a match offset and a line count still index the file.
//
// Why outputs are different from source: a cell's output is what running the code printed, not what anyone
// wrote. Profiling a real estate, one notebook's cell output held 2.2 MB of a printed catalogue dump and
// produced 1,999 of the 2,844 keyword-free entropy findings across all 72 repositories, every one of them
// an asset path or a crawler key. Chasing those token shapes is the wrong cut; the right one is that
// program output is not authored content.
//
// It is applied ONLY to the keyword-free entropy rule. A provider token printed into an output is still a
// leaked credential, and the prefix-anchored rules keep reading the whole file, so an AKIA or a ghp_ in a
// cell output is still reported. What stands down is the rule that cannot tell a catalogue dump from a key.
func maskNotebookOutputs(rel string, data []byte) []byte {
	if !strings.HasSuffix(strings.ToLower(rel), ".ipynb") {
		return data
	}
	out := append([]byte(nil), data...)
	dec := json.NewDecoder(bytes.NewReader(data))
	depth := 0
	pendingOutputs := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return out // a malformed notebook keeps whatever was masked so far, never fails the scan
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		case string:
			if depth > 0 && t == "outputs" && !pendingOutputs {
				start := dec.InputOffset()
				var skip json.RawMessage
				if err := dec.Decode(&skip); err != nil {
					return out
				}
				end := dec.InputOffset()
				if start >= 0 && end <= int64(len(out)) && start < end {
					for i := start; i < end; i++ {
						if out[i] != '\n' && out[i] != '\r' {
							out[i] = ' '
						}
					}
				}
			}
		}
	}
}
