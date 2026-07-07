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
	"context"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxFiles     = 50000   // bound the workspace walk
	maxFileBytes = 5 << 20 // skip files larger than 5 MiB (secrets live in small config/source)
	sniffBytes   = 8 << 10 // read this much to decide binary-or-text
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
}

// Scanner implements ports.SecretScanner with an owned ruleset.
type Scanner struct {
	rules    []rule
	allow    []*regexp.Regexp // global allow-list (placeholders, docs examples)
	skipDirs map[string]bool
	skipExt  map[string]bool
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
		}),
		skipDirs: set(".git", "node_modules", "vendor", "dist", "build", "target", ".idea",
			".gradle", ".venv", "venv", "__pycache__", ".terraform", "bin"),
		skipExt: set(".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz",
			".tar", ".jar", ".war", ".class", ".exe", ".so", ".dll", ".dylib", ".woff", ".woff2",
			".ttf", ".eot", ".mp4", ".mp3", ".mov", ".bin", ".wasm", ".lock", ".sum"),
	}
}

// Name identifies the source on findings.
func (s *Scanner) Name() string { return "synapse-secret-scan" }

// ScanFiles walks root and returns redacted secret hits. Best-effort: an unreadable file is skipped.
func (s *Scanner) ScanFiles(ctx context.Context, root string) ([]ports.SecretRawFinding, error) {
	var out []ports.SecretRawFinding
	seen := map[string]bool{} // dedup rule+file+line
	count := 0
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if s.skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// Only read regular files: never follow a symlink out of the (untrusted) workspace, so a planted
		// link cannot exfiltrate an out-of-root file's path or a redacted preview into a finding.
		if !d.Type().IsRegular() {
			return nil
		}
		if s.skipExt[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		if count >= maxFiles {
			return filepath.SkipAll
		}
		count++
		info, e := d.Info()
		if e != nil || info.Size() == 0 || info.Size() > maxFileBytes {
			return nil
		}
		data, e := os.ReadFile(path)
		if e != nil || isBinary(data) {
			return nil
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(path, root), string(os.PathSeparator))
		s.scanContent(rel, data, seen, &out)
		return nil
	})
	if walkErr != nil {
		return out, fmt.Errorf("secret scan: %w", walkErr) // e.g. context cancellation
	}
	return out, nil
}

func (s *Scanner) scanContent(rel string, data []byte, seen map[string]bool, out *[]ports.SecretRawFinding) {
	text := string(data)
	for i := range s.rules {
		r := &s.rules[i]
		if !hasAnyKeyword(text, r.keywords) {
			continue
		}
		for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := m[0], m[1]
			if r.group > 0 && len(m) > 2*r.group+1 && m[2*r.group] >= 0 {
				start, end = m[2*r.group], m[2*r.group+1]
			}
			secret := text[start:end]
			if s.allowed(secret, r.allow) {
				continue
			}
			if r.minEnt > 0 && shannon(secret) < r.minEnt {
				continue
			}
			line := 1 + strings.Count(text[:start], "\n")
			key := r.id + ":" + rel + ":" + strconv.Itoa(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			*out = append(*out, ports.SecretRawFinding{
				File:     rel,
				Line:     line,
				RuleID:   r.id,
				Category: r.category,
				Title:    r.title,
				Severity: r.severity,
				Match:    redactMatch(secret),
			})
		}
	}
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
	for _, k := range kws {
		if strings.Contains(text, k) {
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

// defaultRules is the owned starter ruleset. Prefix-anchored rules (AWS/GitHub/GitLab/Slack/Google/private
// key) need no entropy gate; the generic assignment rule is entropy-gated and only MEDIUM to bound FPs.
func defaultRules() []rule {
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
		},
		{
			id: "jwt", category: "JWT", title: "JSON Web Token", severity: shared.SeverityMedium,
			keywords: []string{"eyJ"},
			re:       regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
		},
		{
			id: "generic-secret", category: "Generic", title: "Hardcoded secret", severity: shared.SeverityMedium,
			keywords: []string{"secret", "token", "passwd", "password", "api_key", "apikey", "access_key", "SECRET", "TOKEN", "API_KEY"},
			re:       regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)["']?\s*[:=]\s*["']([A-Za-z0-9/+=_\-]{16,})["']`),
			group:    1,
			minEnt:   3.5,
			allow:    compileAll([]string{`(?i)^(true|false|null|none|localhost)$`}),
		},
	}
}
