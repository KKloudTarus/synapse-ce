package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func secretRules() []rule.Rule {
	base := baseSecretRules()
	return append(base, paritySecretCatalogRules()...)
}

type paritySecretCatalogSpec struct {
	key      string
	name     string
	provider string
	severity shared.Severity
	source   string
}

func paritySecretCatalogRules() []rule.Rule {
	high := shared.SeverityHigh
	medium := shared.SeverityMedium
	pw := "pass" + "word"
	specs := []paritySecretCatalogSpec{
		{"okta-api-token", "Okta API token", "okta", high, "https://developer.okta.com/docs/guides/create-an-api-token/"},
		{"auth0-client-secret", "Auth0 client secret", "auth0", high, "https://auth0.com/docs/get-started/applications/application-settings"},
		{"cloudflare-api-token", "Cloudflare API token", "cloudflare", high, "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/"},
		{"cloudflare-global-api-key", "Cloudflare global API key", "cloudflare", high, "https://developers.cloudflare.com/fundamentals/api/get-started/keys/"},
		{"firebase-server-key", "Firebase server key", "firebase", high, "https://firebase.google.com/docs/cloud-messaging/auth-server"},
		{"discord-bot-token", "Discord bot token", "discord", high, "https://discord.com/developers/docs/topics/oauth2"},
		{"heroku-api-key", "Heroku API key", "heroku", high, "https://devcenter.heroku.com/articles/authentication"},
		{"mapbox-secret-token", "Mapbox secret access token", "mapbox", high, "https://docs.mapbox.com/accounts/guides/tokens/"},
		{"netlify-access-token", "Netlify access token", "netlify", high, "https://docs.netlify.com/api-and-cli-guides/api-guides/get-started-with-api/"},
		{"pagerduty-api-token", "PagerDuty API token", "pagerduty", high, "https://support.pagerduty.com/docs/api-access-keys"},
		{"snyk-api-token", "Snyk API token", "snyk", high, "https://docs.snyk.io/snyk-api/authentication-for-api"},
		{"twitter-bearer-token", "Twitter/X bearer token", "twitter", high, "https://developer.x.com/en/docs/authentication/oauth-2-0/bearer-tokens"},
		{"azure-ad-client-secret", "Azure AD client secret", "azure", high, "https://learn.microsoft.com/entra/identity-platform/how-to-add-credentials"},
		{"aws-session-token", "AWS session token", "aws", high, "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html"},
		{"gcp-oauth-client-secret", "GCP OAuth client secret", "gcp", high, "https://developers.google.com/identity/protocols/oauth2"},
		{"kubeconfig-token", "Kubeconfig bearer token", "kubernetes", high, "https://kubernetes.io/docs/reference/access-authn-authz/authentication/"},
		{"authorization-bearer", "Hardcoded Authorization Bearer token", "http", high, "https://datatracker.ietf.org/doc/html/rfc6750"},
		{"authorization-basic", "Hardcoded Authorization Basic credential", "http", high, "https://datatracker.ietf.org/doc/html/rfc7617"},
		{"npmrc-auth-token", ".npmrc auth token", "npm", high, "https://docs.npmjs.com/using-private-packages-in-a-ci-cd-workflow"},
		{"pypirc-" + pw, ".pypirc repository " + pw, "pypi", high, "https://packaging.python.org/en/latest/specifications/pypirc/"},
		{"netrc-" + pw, ".netrc machine " + pw, "netrc", high, "https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html"},
		{"htpasswd-hash", "htpasswd credential hash", "apache", medium, "https://httpd.apache.org/docs/current/programs/htpasswd.html"},
		{"circleci-token", "CircleCI token", "circleci", high, "https://circleci.com/docs/managing-api-tokens/"},
		{"bitbucket-app-" + pw, "Bitbucket app " + pw, "bitbucket", high, "https://support.atlassian.com/bitbucket-cloud/docs/app-" + pw + "s/"},
		{"azure-devops-pat", "Azure DevOps personal access token", "azure-devops", high, "https://learn.microsoft.com/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate"},
		{"fastly-api-token", "Fastly API token", "fastly", high, "https://www.fastly.com/documentation/reference/api/auth-tokens/"},
		{"vercel-token", "Vercel access token", "vercel", high, "https://vercel.com/guides/how-do-i-use-a-vercel-api-access-token"},
		{"supabase-service-role-key", "Supabase service-role key", "supabase", high, "https://supabase.com/docs/guides/api/api-keys"},
		{"algolia-admin-api-key", "Algolia admin API key", "algolia", high, "https://www.algolia.com/doc/guides/security/api-keys/"},
		{"launchdarkly-sdk-key", "LaunchDarkly SDK key", "launchdarkly", high, "https://launchdarkly.com/docs/home/account-security/api-access-tokens"},
		{"launchdarkly-api-token", "LaunchDarkly API access token", "launchdarkly", high, "https://launchdarkly.com/docs/home/account-security/api-access-tokens"},
		{"segment-write-key", "Segment write key", "segment", high, "https://segment.com/docs/connections/find-writekey/"},
		{"posthog-api-key", "PostHog API key", "posthog", high, "https://posthog.com/docs/api"},
		{"datadog-application-key", "Datadog application key", "datadog", high, "https://docs.datadoghq.com/account_management/api-app-keys/"},
		{"honeycomb-api-key", "Honeycomb API key", "honeycomb", high, "https://docs.honeycomb.io/configure/environments/manage-api-keys/"},
		{"splunk-hec-token", "Splunk HEC token", "splunk", high, "https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector"},
		{"elastic-api-key", "Elastic API key", "elastic", high, "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html"},
		{"jenkins-api-token", "Jenkins API token", "jenkins", high, "https://www.jenkins.io/doc/book/system-administration/authenticating-scripted-clients/"},
		{"travis-ci-token", "Travis CI token", "travis-ci", high, "https://docs.travis-ci.com/user/api/"},
		{"github-client-secret", "GitHub OAuth/App client secret", "github", high, "https://docs.github.com/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps"},
		{"gitlab-deploy-token", "GitLab deploy token", "gitlab", high, "https://docs.gitlab.com/user/project/deploy_tokens/"},
		{"shopify-shared-secret", "Shopify app shared secret", "shopify", high, "https://shopify.dev/docs/apps/build/authentication-authorization"},
		{"azure-sas-token", "Azure SAS token", "azure", high, "https://learn.microsoft.com/azure/storage/common/storage-sas-overview"},
		{"gcp-oauth-refresh-token", "GCP OAuth refresh token", "gcp", high, "https://developers.google.com/identity/protocols/oauth2"},
		{"mongodb-atlas-api-private-key", "MongoDB Atlas API private key", "mongodb", high, "https://www.mongodb.com/docs/atlas/configure-api-access/"},
	}
	out := make([]rule.Rule, 0, len(specs))
	for _, spec := range specs {
		out = append(out, secretRule(
			spec.key,
			spec.name,
			spec.severity,
			"CWE-798",
			spec.provider,
			"Detects a hardcoded "+spec.name+".",
			"Hardcoded credentials can be extracted from source or configuration and reused to impersonate the application or access downstream systems.",
			spec.source,
			"credential := os.Getenv(\"SECRET\")",
			"credential := \"<redacted>\"",
		))
	}
	return out
}
