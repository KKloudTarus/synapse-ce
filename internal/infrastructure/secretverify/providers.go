package secretverify

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// maxDrainBytes bounds how much of a provider response body is read then discarded. The body is never
// logged or inspected beyond the status code; draining a little keeps the connection reusable.
const maxDrainBytes = 4 << 10

// doGet issues a single GET to baseURL+path with the given headers and returns the verdict for its status.
// It reads no meaningful part of the body (status only) and never logs the request or the headers (which
// carry the secret). rejectOn401 is passed through to the status mapping. The caller has already
// rate-limited.
func doGet(ctx context.Context, client *http.Client, url string, headers map[string]string, rejectOn401 bool) (ports.SecretVerdict, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ports.SecretUnknown, fmt.Errorf("build request: %w", err)
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := client.Do(req)
	if err != nil {
		return ports.SecretUnknown, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))
	return verdictForStatus(resp.StatusCode, rejectOn401), nil
}

// checkGitHub confirms a GitHub token via GET /user (read-only). A GitHub PAT authenticates as
// "Authorization: token <pat>"; 200 = live. A 401/403 is NOT treated as dead (rejectOn401 is false): the
// token could be a live GitHub Enterprise credential rejected only by public github.com.
func checkGitHub(ctx context.Context, client *http.Client, baseURL, secret string, rejectOn401 bool) (ports.SecretVerdict, error) {
	return doGet(ctx, client, baseURL+"/user", map[string]string{
		"Authorization": "token " + secret,
		"Accept":        "application/vnd.github+json",
	}, rejectOn401)
}

// checkGitLab confirms a GitLab personal access token via GET /api/v4/user (read-only) with the
// PRIVATE-TOKEN header; 200 = live. A rejection is inconclusive (rejectOn401 false): the token may belong to
// a self-managed GitLab instance, not public gitlab.com.
func checkGitLab(ctx context.Context, client *http.Client, baseURL, secret string, rejectOn401 bool) (ports.SecretVerdict, error) {
	return doGet(ctx, client, baseURL+"/api/v4/user", map[string]string{
		"PRIVATE-TOKEN": secret,
	}, rejectOn401)
}

// checkOpenAI confirms an OpenAI API key via GET /v1/models (read-only bearer auth); 200 = live, 401 =
// rejected (rejectOn401 true: OpenAI has a single global host, so a rejected sk- key is genuinely inactive).
func checkOpenAI(ctx context.Context, client *http.Client, baseURL, secret string, rejectOn401 bool) (ports.SecretVerdict, error) {
	return doGet(ctx, client, baseURL+"/v1/models", map[string]string{
		"Authorization": "Bearer " + secret,
	}, rejectOn401)
}

// checkVault confirms a Vault service token via the configured read-only lookup-self endpoint. Vault uses
// 403 for an invalid/expired token; rate limiting and all other statuses remain inconclusive.
func checkVault(ctx context.Context, client *http.Client, endpoint, secret string, _ bool) (ports.SecretVerdict, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ports.SecretUnknown, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", secret)
	resp, err := client.Do(req)
	if err != nil {
		return ports.SecretUnknown, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return ports.SecretVerified, nil
	case resp.StatusCode == http.StatusForbidden:
		return ports.SecretUnverified, nil
	default:
		return ports.SecretUnknown, nil
	}
}
