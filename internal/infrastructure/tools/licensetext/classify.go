// Package licensetext classifies license FILE TEXT into an SPDX id with a confidence
// score, using github.com/google/licensecheck (the classifier deps.dev/pkgsite use).
// It is the shared, deterministic, offline primitive behind both the JAR license reader
// (jarlicense) and the workspace license-file scanner (licensefile) – so they agree on
// the match threshold and the SPDX id, and both can surface the confidence.
package licensetext

import "github.com/google/licensecheck"

// DefaultMinConfidence is the licensecheck coverage threshold (percent) below which a
// text match is too weak to attribute. Trivy's analogous default is 90; we use 75 to
// still recognize lightly-edited LICENSE files while staying high-confidence.
const DefaultMinConfidence = 75.0

// Classify scans license file text and returns the best SPDX id and its coverage
// confidence (0..100). The confidence is the FILE-LEVEL coverage (how much of the text
// matched any license), not the per-match span; for a normal single-license file they
// coincide. ok is false when nothing clears minConfidence. Pass minConfidence <= 0 to use
// DefaultMinConfidence. Pure: no I/O, deterministic.
func Classify(data []byte, minConfidence float64) (spdx string, confidence float64, ok bool) {
	if len(data) == 0 {
		return "", 0, false
	}
	if minConfidence <= 0 {
		minConfidence = DefaultMinConfidence
	}
	cov := licensecheck.Scan(data)
	if cov.Percent < minConfidence || len(cov.Match) == 0 {
		return "", 0, false
	}
	// Pick the match covering the most text (a clean LICENSE file is usually one match).
	best := cov.Match[0]
	for _, m := range cov.Match[1:] {
		if (m.End - m.Start) > (best.End - best.Start) {
			best = m
		}
	}
	if best.IsURL || best.ID == "" {
		return "", 0, false
	}
	return best.ID, cov.Percent, true
}
