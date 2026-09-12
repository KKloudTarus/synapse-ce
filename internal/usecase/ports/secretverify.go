package ports

import "context"

// SecretVerdict is the result of an opt-in active check of a detected secret against its issuing provider.
// It NEVER carries the secret value. Absent verification (feature off, provider unknown, network error) is
// SecretUnknown, and an unknown or unverified verdict must NEVER suppress a finding: a committed credential
// is a leak even if it has since been rotated or revoked. Only SecretVerified is allowed to raise a
// finding's confidence.
type SecretVerdict string

const (
	// SecretUnknown means no verdict was reached: verification is off, no provider matches the rule, or the
	// provider call failed or was inconclusive. It is the default and changes nothing about the finding.
	SecretUnknown SecretVerdict = ""
	// SecretVerified means the provider confirmed the credential is currently live (an authenticated
	// read-only call succeeded). This is a confirmed active credential and raises the finding above
	// needs-verify.
	SecretVerified SecretVerdict = "verified"
	// SecretUnverified means the provider actively rejected the credential (e.g. HTTP 401): it is not live
	// right now. The finding is KEPT (a committed-then-revoked secret is still a leak to rotate); the
	// verdict only records that the credential is not currently active.
	SecretUnverified SecretVerdict = "unverified"
)

// SecretVerifier performs one minimal, read-only API call against the issuing provider of a detected secret
// to determine whether the credential is live (D6.3). It is OPT-IN and default-off; a nil SecretVerifier
// means no verification. Implementations MUST:
//   - make at most one outbound call per Verify and never send the secret anywhere but that single call;
//   - never log, seal, wrap into a returned error, or otherwise emit the raw secret (redact it out of any
//     error) — the secret bytes it receives must not escape the call (safety invariant #3);
//   - return SecretUnknown (never an error that leaks context) when no provider matches ruleID, and map a
//     network/transport failure to SecretUnknown with a redacted error, never to SecretUnverified;
//   - be safe for concurrent use and internally rate-limit their outbound calls.
//
// ruleID is the detecting rule (e.g. "aws-access-key-id") used to select the per-provider verifier. secret
// is the raw credential bytes; the caller passes them only because the plaintext is already in scope at the
// detection site and is discarded immediately after.
type SecretVerifier interface {
	Verify(ctx context.Context, ruleID string, secret []byte) (SecretVerdict, error)
}

// SecretMaterial is one raw credential component passed only across the optional grouped-verification
// boundary. It exists for providers such as AWS whose read-only authentication check requires a credential
// set (access key id + secret access key, and a session token for temporary credentials). Callers MUST keep
// values ephemeral: never log, persist, seal, or include them in a returned error.
type SecretMaterial struct {
	RuleID string
	Secret []byte
}

// GroupedSecretVerifier is an optional extension implemented by verifiers that can authenticate a bounded
// group of related credential components with one provider request. The scanner, which still owns the raw
// detection context, is responsible for pairing only unambiguous nearby components. Implementations MUST
// make at most one outbound call and follow the same redaction, rate-limit, and failure semantics as
// SecretVerifier.Verify.
type GroupedSecretVerifier interface {
	VerifyGroup(ctx context.Context, materials []SecretMaterial) (SecretVerdict, error)
}

// VerifyingSecretScanner is the OPTIONAL active-verification extension of a SecretScanner. ScanFiles (the
// SecretScanner contract) stays deterministic and read-only; ScanFilesVerified additionally makes the
// opt-in outbound provider calls through the verifier and stamps each finding's Verified verdict, with the
// raw secret confined to the scanner and never returned. The SCA pipeline type-asserts this interface and
// calls it only when active verification is enabled for the scan; a scanner that also implements it must
// keep plaintext inside the adapter and redact it from every error and log.
type VerifyingSecretScanner interface {
	ScanFilesVerified(ctx context.Context, root string, verifier SecretVerifier) (SecretScanReport, error)
}
