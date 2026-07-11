// Package redact is the shared belt-and-suspenders scrubber for secret material on its
// way to any sink – logs, the audit writer, the evidence seal, tool output. It is
// defense-in-depth behind the vault: the vault keeps secrets out of argv and
// the worker env, and redact ensures that if a tool echoes its own token (or a URL
// carries embedded creds) the value is removed before it is published or sealed.
package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
)

// Placeholder is what a redacted secret is replaced with.
const Placeholder = "[REDACTED]"

// urlCredsRE matches the userinfo of a URL (scheme://user:pass@host or scheme://token@host).
var urlCredsRE = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@`)

// URLCreds strips credentials embedded in any URL, keeping the scheme + host:
// https://user:pass@h → https://***@h. (Generalizes acquire.credsRE / sca.credInErr.)
func URLCreds(s string) string { return urlCredsRE.ReplaceAllString(s, "$1***@") }

// Bytes removes every non-empty secret value from data (exact substring match) and
// strips URL-embedded creds. Used to scrub a tool's stdout/stderr before it is logged
// or sealed, so a tool that prints its own injected token is caught.
//
// Each secret is scrubbed both verbatim AND in its common ENCODED forms – base64 (std +
// URL-safe, padded + unpadded) and lower/upper hex – because a tool that echoes
// base64(token) or hex(token) would otherwise defeat a verbatim-only scrub (demonstrated
// in the red-team audit). DEFENSE-IN-DEPTH ONLY, not the primary control: the vault keeps
// plaintext out of argv/`/proc` and injects via the child env, so a secret reaches here
// only if a misbehaving tool echoes it. An ARBITRARY transform (gzip, XOR, char-by-char)
// can still defeat any substring scrub – treat a tool that can emit attacker-chosen output
// AND holds a secret as able to exfiltrate it; the vault scoping is what bounds blast radius.
func Bytes(data []byte, secrets [][]byte) []byte {
	if len(data) == 0 {
		return data
	}
	out := data
	for _, sec := range secrets {
		if len(sec) == 0 {
			continue
		}
		for _, form := range encodedForms(sec) {
			out = bytes.ReplaceAll(out, form, []byte(Placeholder))
		}
	}
	return []byte(URLCreds(string(out)))
}

// encodedForms returns the secret plus the encodings a tool is most likely to emit, so the
// scrubber catches base64/hex leakage, not just the verbatim value.
func encodedForms(sec []byte) [][]byte {
	forms := [][]byte{
		sec,
		[]byte(base64.StdEncoding.EncodeToString(sec)),
		[]byte(base64.RawStdEncoding.EncodeToString(sec)),
		[]byte(base64.URLEncoding.EncodeToString(sec)),
		[]byte(base64.RawURLEncoding.EncodeToString(sec)),
		[]byte(hex.EncodeToString(sec)),
		[]byte(strings.ToUpper(hex.EncodeToString(sec))),
	}
	// Drop any short/empty encodings that could over-redact (none expected for real secrets).
	out := forms[:0]
	for _, f := range forms {
		if len(f) >= 4 {
			out = append(out, f)
		}
	}
	return out
}

// String is the string form of Bytes for log/error messages.
func String(s string, secrets []string) string {
	bs := make([][]byte, 0, len(secrets))
	for _, sec := range secrets {
		bs = append(bs, []byte(sec))
	}
	return string(Bytes([]byte(s), bs))
}
