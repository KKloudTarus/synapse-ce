package secretverify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const awsSTSEndpoint = "https://sts.amazonaws.com/"

var _ ports.GroupedSecretVerifier = (*Verifier)(nil)

// VerifyGroup performs one pair-aware provider check. The grouped extension currently accepts only one
// complete AWS credential set; unsupported or incomplete groups stay unknown and make no request.
func (v *Verifier) VerifyGroup(ctx context.Context, materials []ports.SecretMaterial) (ports.SecretVerdict, error) {
	var accessKey, secretKey, sessionToken string
	for _, material := range materials {
		switch material.RuleID {
		case "aws-access-key-id":
			if accessKey != "" {
				return ports.SecretUnknown, nil
			}
			accessKey = string(material.Secret)
		case "aws-secret-access-key":
			if secretKey != "" {
				return ports.SecretUnknown, nil
			}
			secretKey = string(material.Secret)
		case "aws-session-token":
			if sessionToken != "" {
				return ports.SecretUnknown, nil
			}
			sessionToken = string(material.Secret)
		default:
			return ports.SecretUnknown, nil
		}
	}
	if accessKey == "" || secretKey == "" || (strings.HasPrefix(accessKey, "ASIA") && sessionToken == "") {
		return ports.SecretUnknown, nil
	}
	if err := v.limiter.Wait(ctx); err != nil {
		return ports.SecretUnknown, fmt.Errorf("secret verify rate-limit wait: %w", err)
	}
	verdict, err := v.verifyAWS(ctx, accessKey, secretKey, sessionToken)
	if err != nil {
		return ports.SecretUnknown, fmt.Errorf("secret verify aws-sts: %s", redact.String(err.Error(), []string{accessKey, secretKey, sessionToken}))
	}
	return verdict, nil
}

func (v *Verifier) verifyAWS(ctx context.Context, accessKey, secretKey, sessionToken string) (ports.SecretVerdict, error) {
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.stsURL, strings.NewReader(body))
	if err != nil {
		return ports.SecretUnknown, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	now := v.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}
	signedHeaders, canonicalHeaders := awsCanonicalHeaders(req, sessionToken != "")
	payloadHash := sha256Hex([]byte(body))
	uri := req.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		uri,
		canonicalQuery(req.URL),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
	scope := date + "/us-east-1/sts/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
	signingKey := awsSigningKey(secretKey, date, "us-east-1", "sts")
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)

	resp, err := v.client.Do(req)
	if err != nil {
		return ports.SecretUnknown, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxDrainBytes))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return ports.SecretVerified, nil
	}
	lower := strings.ToLower(string(data))
	for _, code := range []string{"invalidclienttokenid", "signaturedoesnotmatch", "expiredtoken", "tokenrefreshrequired", "unrecognizedclientexception"} {
		if strings.Contains(lower, code) {
			return ports.SecretUnverified, nil
		}
	}
	// Throttling, provider outages, and unfamiliar responses are inconclusive, never proof that a key is dead.
	return ports.SecretUnknown, nil
}

func awsCanonicalHeaders(req *http.Request, withToken bool) (signed, canonical string) {
	headers := []string{"content-type", "host", "x-amz-date"}
	if withToken {
		headers = append(headers, "x-amz-security-token")
	}
	signed = strings.Join(headers, ";")
	var b strings.Builder
	b.WriteString("content-type:")
	b.WriteString(strings.TrimSpace(req.Header.Get("Content-Type")))
	b.WriteByte('\n')
	b.WriteString("host:")
	b.WriteString(strings.ToLower(req.URL.Host))
	b.WriteByte('\n')
	b.WriteString("x-amz-date:")
	b.WriteString(req.Header.Get("X-Amz-Date"))
	b.WriteByte('\n')
	if withToken {
		b.WriteString("x-amz-security-token:")
		b.WriteString(strings.TrimSpace(req.Header.Get("X-Amz-Security-Token")))
		b.WriteByte('\n')
	}
	return signed, b.String()
}

func canonicalQuery(u *url.URL) string {
	if u == nil || u.RawQuery == "" {
		return ""
	}
	return u.Query().Encode()
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func awsSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}
