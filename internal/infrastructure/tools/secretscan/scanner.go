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
			id: "generic-secret", category: "Generic", title: "Hardcoded secret", severity: shared.SeverityMedium,
			keywords: []string{"secret", "token", "passwd", "password", "api_key", "apikey", "access_key", "SECRET", "TOKEN", "API_KEY"},
			re:       regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)["']?\s*[:=]\s*["']([A-Za-z0-9/+=_\-]{16,})["']`),
			group:    1,
			minEnt:   3.5,
			allow:    compileAll([]string{`(?i)^(true|false|null|none|localhost)$`}),
		},
	}
}
