package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Pushing an engagement scan to the console closes the gap between the two halves of the product: a
// pipeline could record a code-quality analysis with --server/--project and had no way to put the
// security findings of the same run anywhere, so an engagement stayed empty while CI was green.
// POST /api/v1/engagements/{id}/sarif is the server's own ingest path, the same one an external
// tool's report goes through, so the findings arrive deduplicated against first-party findings and
// with the refusals and coverage gaps the server decided, rather than trusted wholesale.

// engagementIngest is the server's answer to a SARIF ingest.
type engagementIngest struct {
	Accepted     int      `json:"accepted"`
	Deduplicated int      `json:"deduplicated"`
	Matched      int      `json:"matched_first_party"`
	Coverage     []string `json:"coverage"`
	Refused      []struct {
		Rule   string `json:"rule"`
		Reason string `json:"reason"`
	} `json:"refused"`
}

// engagementIngestURL builds the ingest endpoint for one engagement. The id goes through path
// escaping: an id with a slash would otherwise change which route the request reaches.
func engagementIngestURL(server, engagementID, assetID string) (string, error) {
	base, err := pushBaseURL(server)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(engagementID)
	if id == "" {
		return "", fmt.Errorf("engagement id is required")
	}
	// Path holds the decoded form and RawPath the encoded one. Setting both keeps a slash inside the
	// id encoded in the request line, so an id such as "eng/../../users" cannot reach another route,
	// while url.URL still sees one path segment for it.
	prefix := strings.TrimRight(base.EscapedPath(), "/")
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/engagements/" + id + "/sarif"
	base.RawPath = prefix + "/api/v1/engagements/" + url.PathEscape(id) + "/sarif"
	if asset := strings.TrimSpace(assetID); asset != "" {
		base.RawQuery = url.Values{"asset_id": {asset}}.Encode()
	}
	return base.String(), nil
}

// pushEngagementSARIF sends one SARIF document to an engagement and returns what the server did with
// it. The caller decides whether a refusal is fatal; this reports, it does not judge.
func pushEngagementSARIF(ctx context.Context, client *http.Client, target pushTarget, document []byte) (engagementIngest, error) {
	if client == nil {
		return engagementIngest{}, fmt.Errorf("http client is required")
	}
	endpoint, err := engagementIngestURL(target.server, target.engagement, target.asset)
	if err != nil {
		return engagementIngest{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(document))
	if err != nil {
		return engagementIngest{}, fmt.Errorf("build engagement ingest request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+target.token)
	resp, err := client.Do(req)
	if err != nil {
		return engagementIngest{}, fmt.Errorf("post engagement findings: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return engagementIngest{}, fmt.Errorf("read engagement ingest response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The server's message is the useful part (an unknown engagement, a closed authorization
		// window, a refused document), so pass it through rather than restating the status.
		return engagementIngest{}, fmt.Errorf("engagement ingest refused with %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out engagementIngest
	if err := json.Unmarshal(body, &out); err != nil {
		return engagementIngest{}, fmt.Errorf("decode engagement ingest response: %w", err)
	}
	return out, nil
}

// reportEngagementIngest prints what the server accepted. A coverage note or a refusal is the part an
// operator needs to see, so neither is folded into the count.
func reportEngagementIngest(w io.Writer, engagementID string, result engagementIngest) {
	summary := fmt.Sprintf("Engagement %s: %d finding(s) accepted", engagementID, result.Accepted)
	if result.Deduplicated > 0 {
		summary += fmt.Sprintf(", %d deduplicated", result.Deduplicated)
	}
	if result.Matched > 0 {
		summary += fmt.Sprintf(", %d matched an existing first-party finding", result.Matched)
	}
	_, _ = fmt.Fprintln(w, summary)
	for _, refusal := range result.Refused {
		_, _ = fmt.Fprintf(w, "  refused %s: %s\n", refusal.Rule, refusal.Reason)
	}
	for _, note := range result.Coverage {
		_, _ = fmt.Fprintf(w, "  coverage: %s\n", note)
	}
}

// engagementSBOMURL is the import endpoint for an engagement's active SBOM.
func engagementSBOMURL(server, engagementID string) (string, error) {
	base, err := pushBaseURL(server)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(engagementID)
	if id == "" {
		return "", fmt.Errorf("engagement id is required")
	}
	prefix := strings.TrimRight(base.EscapedPath(), "/")
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/engagements/" + id + "/sbom"
	base.RawPath = prefix + "/api/v1/engagements/" + url.PathEscape(id) + "/sbom"
	return base.String(), nil
}

// pushEngagementSBOM uploads the CycloneDX document the scan generated. The server keeps one active
// imported SBOM per engagement, so this replaces rather than accumulates, which is why the caller
// only reaches it when the operator asked for it.
func pushEngagementSBOM(ctx context.Context, client *http.Client, target pushTarget, document []byte) error {
	if client == nil {
		return fmt.Errorf("http client is required")
	}
	endpoint, err := engagementSBOMURL(target.server, target.engagement)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(document))
	if err != nil {
		return fmt.Errorf("build engagement sbom request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+target.token)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post engagement sbom: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read engagement sbom response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("engagement sbom import refused with %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
