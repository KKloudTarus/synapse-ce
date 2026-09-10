package secretscan

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func syntheticToken(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, n)
	state := uint32(0x9e3779b9)
	for i := range out {
		state = state*1664525 + 1013904223
		out[i] = alphabet[int((state>>16)%uint32(len(alphabet)))]
	}
	return string(out)
}

func syntheticHex(n int) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, n)
	state := uint32(0x85ebca6b)
	for i := range out {
		state = state*1103515245 + 12345
		out[i] = alphabet[int((state>>16)%uint32(len(alphabet)))]
	}
	return string(out)
}

func TestParityExpansionRules(t *testing.T) {
	assign := func(key string, parts ...string) string { return key + `="` + strings.Join(parts, "") + `"` }
	join := func(parts ...string) string { return strings.Join(parts, "") }
	tests := []struct {
		id       string
		positive string
		negative string
	}{
		{"okta-api-token", assign("OKTA_API_TOKEN", syntheticToken(32)), assign("OKTA_API_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"auth0-client-secret", assign("AUTH0_CLIENT_SECRET", syntheticToken(40)), assign("AUTH0_CLIENT_SECRET", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"cloudflare-api-token", assign("CLOUDFLARE_API_TOKEN", syntheticToken(32)), assign("CLOUDFLARE_API_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"cloudflare-global-api-key", assign("CF_GLOBAL_API_KEY", syntheticToken(32)), assign("CF_GLOBAL_API_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"firebase-server-key", assign("FIREBASE_SERVER_KEY", syntheticToken(40)), assign("FIREBASE_SERVER_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLEEXAMPLE")},
		{"discord-bot-token", assign("DISCORD_BOT_TOKEN", syntheticToken(24), ".", syntheticToken(6), ".", syntheticToken(30)), assign("DISCORD_BOT_TOKEN", "EXAMPLEEXAMPLEEXAMPLEEXAM", ".Yz1234.", "EXAMPLEEXAMPLEEXAMPLEEXAMPLE12")},
		{"heroku-api-key", assign("HEROKU_API_KEY", syntheticToken(32)), assign("HEROKU_API_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"mapbox-secret-token", assign("MAPBOX_SECRET_TOKEN", "sk.", syntheticToken(36)), assign("MAPBOX_SECRET_TOKEN", "sk.", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLEEXAMPLE")},
		{"netlify-access-token", assign("NETLIFY_ACCESS_TOKEN", syntheticToken(36)), assign("NETLIFY_ACCESS_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"pagerduty-api-token", assign("PAGERDUTY_API_TOKEN", syntheticToken(32)), assign("PAGERDUTY_API_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"snyk-api-token", assign("SNYK_API_TOKEN", syntheticToken(36)), assign("SNYK_API_TOKEN", "EXAMPLE-EXAMPLE-", "EXAMPLE-EXAMPLE123456")},
		{"twitter-bearer-token", assign("TWITTER_BEARER_TOKEN", syntheticToken(64)), assign("TWITTER_BEARER_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE")},
		{"azure-ad-client-secret", assign("ENTRA_CLIENT_SECRET", syntheticToken(40)), assign("ENTRA_CLIENT_SECRET", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"aws-session-token", assign("AWS_SESSION_TOKEN", syntheticToken(96)), assign("AWS_SESSION_TOKEN", strings.Repeat("EXAMPLE", 14))},
		{"gcp-oauth-client-secret", join("client_secret=\"", "GOCSPX-", syntheticToken(32), "\""), join("client_secret=\"", "GOCSPX-", "EXAMPLEEXAMPLEEXAMPLEEXAMPLE", "\"")},
		{"kubeconfig-token", join("token: ", syntheticToken(48)), "token: EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"},
		{"authorization-bearer", join("Authorization: Bearer ", syntheticToken(36)), "Authorization: Bearer EXAMPLEEXAMPLEEXAMPLEEXAMPLE1234"},
		{"authorization-basic", join("Authorization: Basic ", syntheticToken(32)), "Authorization: Basic EXAMPLEEXAMPLEEXAMPLEEXAMPLE"},
		{"npmrc-auth-token", join("//registry.npmjs.org/:_authToken=", syntheticToken(32)), "//registry.npmjs.org/:_authToken=EXAMPLEEXAMPLEEXAMPLEEXAMPLE"},
		{"pypirc-password", join("[pypi]\nusername = __token__\npass", "word = ", syntheticToken(32)), "[pypi]\nusername = __token__\npassword = EXAMPLEEXAMPLEEXAMPLEEXAMPLE"},
		{"netrc-password", join("machine api.example.net login buildbot pass", "word ", syntheticToken(24)), "machine api.example.net login buildbot password EXAMPLEEXAMPLEEXAMPLE"},
		{"htpasswd-hash", join("alice:", "$apr1$", syntheticToken(8), "$", syntheticToken(22)), join("alice:", "$apr1$", "example1$", "abcdefghijklmnopqrstuv")},
		{"circleci-token", assign("CIRCLECI_TOKEN", syntheticToken(32)), assign("CIRCLECI_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"bitbucket-app-password", assign("BITBUCKET_APP_PASSWORD", syntheticToken(32)), assign("BITBUCKET_APP_PASSWORD", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"azure-devops-pat", assign("AZDO_PAT", syntheticToken(52)), assign("AZDO_PAT", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"fastly-api-token", assign("FASTLY_API_TOKEN", syntheticToken(32)), assign("FASTLY_API_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"vercel-token", assign("VERCEL_ACCESS_TOKEN", syntheticToken(32)), assign("VERCEL_ACCESS_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"supabase-service-role-key", assign("SUPABASE_SERVICE_ROLE_KEY", syntheticToken(24), ".", syntheticToken(24), ".", syntheticToken(24)), assign("SUPABASE_SERVICE_ROLE_KEY", "EXAMPLEEXAMPLEEXAMPLEEX.", "EXAMPLEEXAMPLEEXAMPLE.", "EXAMPLEEXAMPLEEXAMPLE")},
		{"algolia-admin-api-key", assign("ALGOLIA_ADMIN_API_KEY", syntheticHex(32)), assign("ALGOLIA_ADMIN_API_KEY", strings.Repeat("0", 32))},
		{"launchdarkly-sdk-key", assign("LD_SDK_KEY", syntheticToken(32)), assign("LD_SDK_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"launchdarkly-api-token", assign("LD_API_TOKEN", syntheticToken(32)), assign("LD_API_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"segment-write-key", assign("SEGMENT_WRITE_KEY", syntheticToken(32)), assign("SEGMENT_WRITE_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"posthog-api-key", assign("POSTHOG_API_KEY", "phx_", syntheticToken(32)), assign("POSTHOG_API_KEY", "phx_", "EXAMPLEEXAMPLEEXAMPLE")},
		{"datadog-application-key", assign("DD_APPLICATION_KEY", syntheticHex(40)), assign("DD_APPLICATION_KEY", strings.Repeat("0", 40))},
		{"honeycomb-api-key", assign("HONEYCOMB_API_KEY", syntheticToken(32)), assign("HONEYCOMB_API_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"splunk-hec-token", assign("SPLUNK_HEC_TOKEN", syntheticHex(36)), assign("SPLUNK_HEC_TOKEN", "EXAMPLE-EXAMPLE-", "EXAMPLE-EXAMPLE123456")},
		{"elastic-api-key", join("Authorization: ApiKey ", syntheticToken(32)), "Authorization: ApiKey EXAMPLEEXAMPLEEXAMPLEEXAMPLE"},
		{"jenkins-api-token", assign("JENKINS_API_TOKEN", syntheticHex(32)), assign("JENKINS_API_TOKEN", strings.Repeat("0", 32))},
		{"travis-ci-token", assign("TRAVIS_CI_TOKEN", syntheticToken(32)), assign("TRAVIS_CI_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"github-client-secret", assign("GITHUB_CLIENT_SECRET", syntheticHex(40)), assign("GITHUB_CLIENT_SECRET", strings.Repeat("0", 40))},
		{"gitlab-deploy-token", join("token=\"", "gldt-", syntheticToken(28), "\""), join("token=\"", "gldt-", "EXAMPLEEXAMPLEEXAMPLEEXAMPLE", "\"")},
		{"shopify-shared-secret", assign("SHOPIFY_SHARED_SECRET", syntheticHex(32)), assign("SHOPIFY_SHARED_SECRET", strings.Repeat("0", 32))},
		{"azure-sas-token", assign("AZURE_SAS_TOKEN", "?sv=2024-11-04&ss=b&srt=sco&sp=rwdlacupiytfx&sig=", syntheticToken(32)), assign("AZURE_SAS_TOKEN", "?sv=2024-11-04&sig=", "EXAMPLEEXAMPLEEXAMPLEEXAMPLE")},
		{"gcp-oauth-refresh-token", join("refresh_token=\"", "1//", syntheticToken(40), "\""), join("refresh_token=\"", "1//", "EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE", "\"")},
		{"mongodb-atlas-api-private-key", assign("MONGODB_ATLAS_PRIVATE_KEY", syntheticToken(32)), assign("MONGODB_ATLAS_PRIVATE_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
	}

	if got := len(defaultRules()); got < 120 {
		t.Fatalf("default secret detector count = %d, want at least 120", got)
	}
	if got := len(parityExpansionRules()); got != len(tests) {
		t.Fatalf("expansion rule count = %d, fixture count = %d", got, len(tests))
	}

	s := New()
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if !scanHasRule(s, tt.positive, tt.id) {
				t.Fatalf("positive fixture did not trigger %s", tt.id)
			}
			if scanHasRule(s, tt.negative, tt.id) {
				t.Fatalf("placeholder negative triggered %s", tt.id)
			}
		})
	}
}

func scanHasRule(s *Scanner, text, want string) bool {
	var findings []ports.SecretRawFinding
	s.scanContent("fixture.env", []byte(text), map[string]bool{}, &findings, 1000)
	for _, finding := range findings {
		if finding.RuleID == want {
			return true
		}
	}
	return false
}

func TestParityExpansionRuleIDsUnique(t *testing.T) {
	ids := parityExpansionRuleIDs()
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			t.Fatalf("duplicate parity expansion rule id %q", ids[i])
		}
	}
	if len(ids) != 45 {
		t.Fatalf("parity expansion rule count = %d, want 45", len(ids))
	}
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			t.Fatal("empty parity expansion rule id")
		}
	}
}
