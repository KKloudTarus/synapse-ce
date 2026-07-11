// Package timestamp implements ports.TimestampAuthority with an RFC-3161 client: it
// anchors a custody chain head to an EXTERNAL trusted timestamp, so a head can be
// proven to have existed before a given instant independent of the server's own
// ed25519 key – i.e. tamper-PROOF, not just tamper-evident (append-only, tamper-evident
// custody). ASN.1/CMS is handled by github.com/digitorus/timestamp (never hand-rolled).
//
// Token verification (VerifyToken) lives here, not in the domain, because RFC-3161 +
// CMS are not stdlib (unlike the ed25519 attestation in domain/evidence). It proves
// the token binds the digest and that the token's own CMS signature is intact; it does
// NOT decide whether the issuing TSA is trusted – that is the verifier's policy.
package timestamp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	rfc3161 "github.com/digitorus/timestamp"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultTimeout  = 15 * time.Second
	maxResponseSize = 1 << 20 // 1 MiB – an RFC-3161 reply is small
	contentTypeReq  = "application/timestamp-query"
)

// Client is an RFC-3161 timestamp client bound to one TSA URL.
type Client struct {
	url        string
	httpClient *http.Client
}

var _ ports.TimestampAuthority = (*Client)(nil)

// NewClient validates the TSA URL and returns a client. A non-positive timeout uses a
// default; the timeout bounds the seal-path call so a slow TSA cannot hang it (the
// vault treats timestamping as best-effort).
func NewClient(url string, timeout time.Duration) (*Client, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return nil, fmt.Errorf("%w: timestamp authority url is required", shared.ErrValidation)
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{url: url, httpClient: &http.Client{Timeout: timeout}}, nil
}

// Timestamp requests an RFC-3161 token over digest (a chain head's bytes). The TSA's
// messageImprint is SHA-256(digest); the response is verified to bind exactly that
// digest before it is accepted, and the opaque DER token is base64'd into the result.
func (c *Client) Timestamp(ctx context.Context, digest []byte) (ports.TimestampToken, error) {
	if len(digest) == 0 {
		return ports.TimestampToken{}, fmt.Errorf("%w: cannot timestamp an empty digest", shared.ErrValidation)
	}
	reqDER, err := rfc3161.CreateRequest(bytes.NewReader(digest), &rfc3161.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true, // ask the TSA to embed its cert chain (needed for later verification / LTV)
	})
	if err != nil {
		return ports.TimestampToken{}, fmt.Errorf("build timestamp request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(reqDER))
	if err != nil {
		return ports.TimestampToken{}, fmt.Errorf("timestamp http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", contentTypeReq)
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return ports.TimestampToken{}, fmt.Errorf("contact timestamp authority: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return ports.TimestampToken{}, fmt.Errorf("read timestamp response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return ports.TimestampToken{}, fmt.Errorf("timestamp authority returned %s: %s", resp.Status, snippet)
	}
	ts, err := rfc3161.ParseResponse(body) // parses + checks the token's CMS signature
	if err != nil {
		return ports.TimestampToken{}, fmt.Errorf("parse timestamp response: %w", err)
	}
	if err := bindsDigest(ts, digest); err != nil {
		return ports.TimestampToken{}, err
	}
	return ports.TimestampToken{
		Authority: c.url,
		Token:     base64.StdEncoding.EncodeToString(ts.RawToken),
	}, nil
}

// VerifyToken re-parses an opaque RFC-3161 token, confirms it binds digest (its
// messageImprint == SHA-256(digest)) and that the token's CMS signature is intact, and
// returns the asserted time. Whether the issuing TSA is trusted is the caller's policy
// (pin the TSA cert / require an eIDAS-qualified authority).
func VerifyToken(token ports.TimestampToken, digest []byte) (time.Time, error) {
	raw, err := base64.StdEncoding.DecodeString(token.Token)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: malformed timestamp token", shared.ErrValidation)
	}
	ts, err := rfc3161.Parse(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: timestamp token failed verification: %v", shared.ErrValidation, err)
	}
	if err := bindsDigest(ts, digest); err != nil {
		return time.Time{}, err
	}
	return ts.Time, nil
}

// bindsDigest checks the token's messageImprint is SHA-256(digest).
func bindsDigest(ts *rfc3161.Timestamp, digest []byte) error {
	sum := sha256.Sum256(digest)
	if ts.HashAlgorithm != crypto.SHA256 || !bytes.Equal(ts.HashedMessage, sum[:]) {
		return fmt.Errorf("%w: timestamp token does not bind this digest", shared.ErrValidation)
	}
	return nil
}
