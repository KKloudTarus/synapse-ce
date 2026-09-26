package msgtemplate

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// errOutputLimit is returned by limitWriter once the rune budget is spent. text/template stops
// executing on a write error, so the budget also stops the work; Render treats it as truncation,
// never as a failure.
var errOutputLimit = errors.New("msgtemplate: output limit reached")

// truncationMarker ends output cut by the limit writer or by the truncate function.
const truncationMarker = "…"

// limitWriter keeps at most max runes. text/template writes whole strings (literal text or one
// printed value) per call, so a call never splits a rune.
type limitWriter struct {
	b         strings.Builder
	n, max    int
	truncated bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	count := utf8.RuneCount(p)
	if w.n+count <= w.max {
		w.b.Write(p)
		w.n += count
		return len(p), nil
	}
	keep := runePrefixBytes(p, w.max-w.n)
	w.b.Write(p[:keep])
	w.n = w.max
	w.truncated = true
	return keep, errOutputLimit
}

// output returns the text written so far, ending with the truncation marker when the budget ran
// out. The result never exceeds max runes.
func (w *limitWriter) output() Output {
	if !w.truncated {
		return Output{Text: w.b.String()}
	}
	return Output{Text: truncateRunes(w.b.String()+truncationMarker, w.max), Truncated: true}
}

// runePrefixBytes returns the byte length of the first n runes of p.
func runePrefixBytes(p []byte, n int) int {
	i := 0
	for ; n > 0 && i < len(p); n-- {
		_, size := utf8.DecodeRune(p[i:])
		i += size
	}
	return i
}

// truncateRunes cuts value to at most max runes, ending a cut value with the truncation marker.
func truncateRunes(value string, max int) string {
	if max <= 0 {
		return ""
	}
	if utf8.RuneCountInString(value) <= max {
		return value
	}
	runes := []rune(value)
	return string(runes[:max-1]) + truncationMarker
}
