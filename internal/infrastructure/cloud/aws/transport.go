package aws

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

// requestTransport enforces live authority and an aggregate request limit for
// every SDK attempt, including paginator requests and automatic retries.
type requestTransport struct {
	next      http.RoundTripper
	connector *Connector
	scope     ports.CloudScope
}

func (t requestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := ports.AuthorizeCloudOperation(request.Context(), t.scope, "provider-request", awsOperation(request)); err != nil {
		return nil, err
	}
	if err := t.connector.limiter.Wait(request.Context()); err != nil {
		return nil, fmt.Errorf("limit AWS provider request: %w", err)
	}
	return t.next.RoundTrip(request)
}

func awsOperation(request *http.Request) string {
	if operation := request.URL.Query().Get("x-id"); operation != "" {
		return operation
	}
	if target := request.Header.Get("X-Amz-Target"); target != "" {
		if i := strings.LastIndexByte(target, '.'); i >= 0 {
			return target[i+1:]
		}
		return target
	}
	if request.Body != nil {
		body, err := io.ReadAll(request.Body)
		if err == nil {
			request.Body = io.NopCloser(bytes.NewReader(body))
			if values, err := url.ParseQuery(string(body)); err == nil && values.Get("Action") != "" {
				return values.Get("Action")
			}
		}
	}
	switch {
	case request.URL.Query().Has("policyStatus"):
		return "GetBucketPolicyStatus"
	case request.URL.Query().Has("encryption"):
		return "GetBucketEncryption"
	case request.Method == http.MethodGet && request.URL.Path == "/":
		return "ListBuckets"
	default:
		return "unknown-read-operation"
	}
}

func (c *Connector) scopedConfig(config awssdk.Config, scope ports.CloudScope) awssdk.Config {
	client := c.opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	copyClient := *client
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	copyClient.Transport = requestTransport{next: next, connector: c, scope: scope}
	copyConfig := config.Copy()
	copyConfig.HTTPClient = &copyClient
	return copyConfig
}

var _ http.RoundTripper = requestTransport{}
