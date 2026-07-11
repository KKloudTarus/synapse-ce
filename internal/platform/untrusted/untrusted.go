// Package untrusted is the shared guard for any UNTRUSTED text a source-reading AI ingests
// – dependency source excerpts, files a SAST/threat brain reads, or a
// tool's stdout. It composes the controls that keep secrets out of logs and the LLM
// boundary intact: REDACT secrets → CAP size (rune-safe) → CLASSIFY likely prompt-injection → FENCE
// the content so the model treats it as data, not instructions.
//
// The REAL security boundary is the typed Go tool-call state machine + the
// execution gate; this guard is defense-in-depth that removes a prompt-injection foothold and
// surfaces an advisory suspicion signal the caller can seal as evidence / lower confidence on. It
// generalizes the orchestrator's existing fence+cap for the new source-reading consumers.
package untrusted

import (
	"bytes"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
)

// fenceClose is the closing delimiter; a forged copy in the body is defanged so untrusted content
// cannot "break out" of the fence and smuggle instructions.
const fenceClose = "</untrusted>"

// fenceTagRE matches ANY literal fence tag in a body – open or close, any case, any attributes – so
// a forged copy can be neutralized. Catches the case/spacing/opening-tag variants a single literal
// ReplaceAll would miss (defense-in-depth for the data/instruction boundary).
var fenceTagRE = regexp.MustCompile(`(?i)</?untrusted\b[^>]*>`)

// truncMarker is appended when Cap truncates (visible to the model so it knows content was cut).
const truncMarker = "\n…[truncated]"

// Verdict is the injection-classifier result. Suspicious is ADVISORY (the caller decides – the guard
// never silently drops content); Markers name the heuristics that fired, for audit/evidence.
type Verdict struct {
	Suspicious bool     `json:"suspicious"`
	Markers    []string `json:"markers,omitempty"`
}

// Guarded is the output of Guard: the fenced/redacted/capped text plus the signals a caller seals.
type Guarded struct {
	Fenced    string  `json:"fenced"`
	Truncated bool    `json:"truncated"`
	Injection Verdict `json:"injection"`
}

// Guard is the one-call composite for feeding untrusted content to an LLM: redact secrets → cap to
// maxBytes (rune-safe) → classify injection (on the redacted+capped bytes) → fence. secrets may be
// nil; maxBytes<=0 means no cap. label names the source (e.g. "dep-source:lodash@4.17.21").
func Guard(label string, content []byte, maxBytes int, secrets [][]byte) Guarded {
	red := redact.Bytes(content, secrets)
	capped, truncated := Cap(red, maxBytes)
	return Guarded{
		Fenced:    Fence(label, capped),
		Truncated: truncated,
		Injection: ClassifyInjection(capped),
	}
}

// Fence wraps content so the model treats it as DATA, not instructions. Any forged
// fence tag in the body – open OR close, any case/attributes – is defanged, removing the
// prompt-injection breakout foothold. NOTE: Fence does NOT redact secrets; call Guard for the full
// redact→cap→classify→fence pipeline and use Fence alone only on already-redacted content.
func Fence(label string, content []byte) string {
	// Defang any forged fence tag by breaking its leading "<": "</untrusted>" → "<\/untrusted>",
	// "<untrusted x>" → "<\untrusted x>" – so untrusted content can't fabricate or escape the boundary.
	safe := fenceTagRE.ReplaceAllFunc(content, func(m []byte) []byte {
		out := make([]byte, 0, len(m)+1)
		out = append(out, '<', '\\')
		return append(out, m[1:]...)
	})
	var sb strings.Builder
	sb.WriteString(`<untrusted source="`)
	sb.WriteString(escapeAttr(label))
	sb.WriteString("\">\n")
	sb.Write(safe)
	sb.WriteString("\n")
	sb.WriteString(fenceClose)
	return sb.String()
}

// Cap truncates b to at most maxBytes on a UTF-8 RUNE boundary (so a sealed/hash-chained payload
// never carries a half-rune that json.Marshal would rewrite to U+FFFD), appending a marker.
// maxBytes<=0 ⇒ no cap. Returns a FRESH slice (never aliases the caller's buffer) + the truncated flag.
func Cap(b []byte, maxBytes int) ([]byte, bool) {
	if maxBytes <= 0 || len(b) <= maxBytes {
		out := make([]byte, len(b))
		copy(out, b)
		return out, false
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	out := make([]byte, 0, cut+len(truncMarker))
	out = append(out, b[:cut]...)
	out = append(out, truncMarker...)
	return out, true
}

// injectionMarkers are conservative-RECALL heuristics for prompt-injection in untrusted text. They
// favor catching an attack over avoiding a false positive (a benign code comment that literally says
// "ignore all previous instructions" IS flagged – the safe direction, since the result is advisory).
var injectionMarkers = []struct {
	name string
	re   *regexp.Regexp
}{
	{"override", regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\b[^.]{0,40}\b(previous|prior|above|earlier|all)\b[^.]{0,24}\b(instruction|prompt|rule|context|direction|message)`)},
	{"role-spoof", regexp.MustCompile(`(?im)^\s*(system|assistant|developer)\s*:\s`)},
	{"new-instructions", regexp.MustCompile(`(?i)\b(new|updated|revised|real)\s+(instruction|task|objective|system\s+prompt)s?\b`)},
	{"identity-reset", regexp.MustCompile(`(?i)\byou are (now|no longer)\b|\bact as\b|\bpretend to be\b|\bjailbreak\b`)},
	{"tool-mimicry", regexp.MustCompile(`(?i)"(tool_call|function_call|tool_name|tool_calls)"\s*:`)},
	{"exfil", regexp.MustCompile(`(?i)\b(send|post|exfiltrate|upload|leak|email)\b[^.]{0,40}\b(http|https|curl|webhook|secret|token|credential|api[_-]?key)\b`)},
	{"fence-escape", regexp.MustCompile(`(?i)</?untrusted\b`)},
}

// ClassifyInjection scans content for known prompt-injection heuristics. It is ADVISORY – it never
// drops content; a Suspicious result means the caller should treat the text with extra suspicion
// (seal the markers as evidence, lower confidence, or require human review). It is BEST-EFFORT, not
// exhaustive: it strips zero-width/format runes first (a common token-splitting evasion), but a
// sufficiently clever transform (unicode confusables, arbitrary encodings) can still evade it – the
// same caveat redact states. Markers are returned in a stable order for deterministic sealing.
func ClassifyInjection(content []byte) Verdict {
	scan := stripInvisible(content)
	var markers []string
	for _, m := range injectionMarkers {
		if m.re.Match(scan) {
			markers = append(markers, m.name)
		}
	}
	return Verdict{Suspicious: len(markers) > 0, Markers: markers}
}

// stripInvisible removes zero-width / format (Cf) runes + the BOM so an attacker can't break up a
// trigger token (e.g. a zero-width space inside "ignore") to slip past the classifier.
func stripInvisible(b []byte) []byte {
	return bytes.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) { // zero-width space/joiner, BOM (U+FEFF), other format runes
			return -1
		}
		return r
	}, b)
}

// escapeAttr neutralizes characters that would break out of the fence's source="" attribute.
func escapeAttr(s string) string {
	return strings.NewReplacer(`"`, "'", "<", "", ">", "", "\n", " ", "\r", " ").Replace(s)
}
