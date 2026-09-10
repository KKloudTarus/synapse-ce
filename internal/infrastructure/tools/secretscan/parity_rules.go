package secretscan

import (
	"regexp"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// defaultRules keeps the mature detector set in scanner.go stable and appends the D6.2 breadth expansion.
// Keeping the expansion isolated makes provider additions reviewable while preserving the scanner's shared
// redaction, keyword-prefilter, entropy, allow-list, and decode-pass behavior.
func defaultRules() []rule {
	base := baseDefaultRules()
	return append(base, parityExpansionRules()...)
}

func parityExpansionRuleIDs() []string {
	rules := parityExpansionRules()
	ids := make([]string, 0, len(rules))
	for _, r := range rules {
		ids = append(ids, r.id)
	}
	sort.Strings(ids)
	return ids
}

func assignedParityRule(id, category, title string, severity shared.Severity, keywords []string, keyPattern, valuePattern string, minEnt float64) rule {
	return rule{
		id: id, category: category, title: title, severity: severity, keywords: keywords,
		re:    regexp.MustCompile(`(?i)(?:` + keyPattern + `)["']?\s*[:=]\s*["']?(` + valuePattern + `)`),
		group: 1, minEnt: minEnt,
	}
}

func parityExpansionRules() []rule {
	high := shared.SeverityHigh
	medium := shared.SeverityMedium
	return []rule{
		assignedParityRule("okta-api-token", "Okta", "Okta API token", high, []string{"okta", "ssws"}, `okta[_-]?(?:api[_-]?)?token`, `[A-Za-z0-9._-]{20,64}`, 3.0),
		assignedParityRule("auth0-client-secret", "Auth0", "Auth0 client secret", high, []string{"auth0", "client_secret"}, `auth0[_-]?client[_-]?secret`, `[A-Za-z0-9._~+-]{24,128}`, 3.0),
		assignedParityRule("cloudflare-api-token", "Cloudflare", "Cloudflare API token", high, []string{"cloudflare", "cf_api_token"}, `(?:cloudflare|cf)[_-]?(?:api[_-]?)?token`, `[A-Za-z0-9_-]{20,64}`, 3.0),
		assignedParityRule("cloudflare-global-api-key", "Cloudflare", "Cloudflare global API key", high, []string{"cloudflare", "cf_api_key", "cf_global"}, `(?:cloudflare|cf)[_-]?(?:global[_-]?)?(?:api[_-]?)?key`, `[A-Za-z0-9_-]{24,64}`, 3.0),
		assignedParityRule("firebase-server-key", "Firebase", "Firebase server key", high, []string{"firebase", "fcm"}, `(?:firebase|fcm)[_-]?(?:server[_-]?)?(?:api[_-]?)?key`, `[A-Za-z0-9:_-]{30,200}`, 3.0),
		assignedParityRule("discord-bot-token", "Discord", "Discord bot token", high, []string{"discord", "bot_token"}, `discord[_-]?(?:bot[_-]?)?token`, `[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`, 3.5),
		assignedParityRule("heroku-api-key", "Heroku", "Heroku API key", high, []string{"heroku"}, `heroku[_-]?(?:api[_-]?)?(?:key|token)`, `[A-Za-z0-9_-]{24,64}`, 3.0),
		assignedParityRule("mapbox-secret-token", "Mapbox", "Mapbox secret access token", high, []string{"mapbox", "sk."}, `mapbox[_-]?(?:secret[_-]?)?(?:access[_-]?)?(?:token|key)`, `sk\.[A-Za-z0-9._-]{30,}`, 3.0),
		assignedParityRule("netlify-access-token", "Netlify", "Netlify access token", high, []string{"netlify"}, `netlify[_-]?(?:access[_-]?)?token`, `[A-Za-z0-9_-]{30,80}`, 3.0),
		assignedParityRule("pagerduty-api-token", "PagerDuty", "PagerDuty API token", high, []string{"pagerduty", "pd_api"}, `(?:pagerduty|pd)[_-]?(?:api[_-]?)?token`, `[A-Za-z0-9._-]{20,64}`, 3.0),
		assignedParityRule("snyk-api-token", "Snyk", "Snyk API token", high, []string{"snyk"}, `snyk[_-]?(?:api[_-]?)?token`, `[A-Za-z0-9-]{32,64}`, 3.0),
		assignedParityRule("twitter-bearer-token", "Twitter", "Twitter/X bearer token", high, []string{"twitter", "bearer_token"}, `(?:twitter|x)[_-]?(?:api[_-]?)?bearer[_-]?token`, `[A-Za-z0-9%._~-]{40,200}`, 3.0),
		assignedParityRule("azure-ad-client-secret", "Azure", "Azure AD client secret", high, []string{"azure", "aad", "entra", "client_secret"}, `(?:azure|aad|entra)[_-]?(?:ad[_-]?)?client[_-]?secret`, `[A-Za-z0-9._~+-]{24,128}`, 3.0),
		assignedParityRule("aws-session-token", "AWS", "AWS session token", high, []string{"aws_session_token", "sessiontoken"}, `(?:aws[_-]?session[_-]?token|sessiontoken)`, `[A-Za-z0-9/+=]{80,}`, 4.0),
		{
			id: "gcp-oauth-client-secret", category: "GCP", title: "GCP OAuth client secret", severity: high,
			keywords: []string{"GOCSPX-"}, re: regexp.MustCompile(`\b(GOCSPX-[A-Za-z0-9_-]{20,80})\b`), group: 1,
		},
		{
			id: "kubeconfig-token", category: "Kubernetes", title: "Kubeconfig bearer token", severity: high,
			keywords: []string{"token:"}, re: regexp.MustCompile(`(?m)^\s*token:\s*["']?([A-Za-z0-9._~+/-]{20,})`), group: 1, minEnt: 3.5,
		},
		{
			id: "authorization-bearer", category: "HTTP", title: "Hardcoded Authorization Bearer token", severity: high,
			keywords: []string{"authorization", "bearer"}, re: regexp.MustCompile(`(?i)\bauthorization["']?\s*[:=]\s*["']?bearer\s+([A-Za-z0-9._~+/-]{20,})`), group: 1, minEnt: 3.0,
		},
		{
			id: "authorization-basic", category: "HTTP", title: "Hardcoded Authorization Basic credential", severity: high,
			keywords: []string{"authorization", "basic"}, re: regexp.MustCompile(`(?i)\bauthorization["']?\s*[:=]\s*["']?basic\s+([A-Za-z0-9+/]{16,}={0,2})`), group: 1, minEnt: 3.0,
		},
		{
			id: "npmrc-auth-token", category: "npm", title: ".npmrc auth token", severity: high,
			keywords: []string{"_authToken", "_authtoken"}, re: regexp.MustCompile(`(?im)(?://[^\s=]+/?:)?_authToken\s*=\s*([^\s#"']{16,})`), group: 1, minEnt: 3.0,
		},
		{
			id: "pypirc-password", category: "PyPI", title: ".pypirc repository password", severity: high,
			keywords: []string{"[pypi]", "[testpypi]", "password"}, re: regexp.MustCompile(`(?is)\[(?:pypi|testpypi)\][^\[]*?\bpassword\s*=\s*([^\s#"']{12,})`), group: 1, minEnt: 3.0,
		},
		{
			id: "netrc-password", category: "Netrc", title: ".netrc machine password", severity: high,
			keywords: []string{"machine", "password"}, re: regexp.MustCompile(`(?i)\bmachine\s+[^\s]+\s+login\s+[^\s]+\s+password\s+([^\s]{8,})`), group: 1, minEnt: 2.5,
		},
		{
			id: "htpasswd-hash", category: "Apache", title: "htpasswd credential hash", severity: medium,
			keywords: []string{"$2", "$apr1$"}, re: regexp.MustCompile(`(?m)^[^:#\s]+:(\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}|\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22})`), group: 1,
		},
		assignedParityRule("circleci-token", "CircleCI", "CircleCI token", high, []string{"circleci"}, `circleci[_-]?(?:api[_-]?)?(?:token|key)`, `[A-Za-z0-9_-]{24,64}`, 3.0),
		assignedParityRule("bitbucket-app-password", "Bitbucket", "Bitbucket app password", high, []string{"bitbucket", "app_password"}, `bitbucket[_-]?(?:app[_-]?)?password`, `[A-Za-z0-9_-]{20,80}`, 3.0),
		assignedParityRule("azure-devops-pat", "AzureDevOps", "Azure DevOps personal access token", high, []string{"azure_devops", "azdo", "pat"}, `(?:azure[_-]?devops|azdo)[_-]?(?:pat|token)`, `(?:[A-Za-z0-9]{52}|[A-Za-z0-9]{84})`, 3.5),
		assignedParityRule("fastly-api-token", "Fastly", "Fastly API token", high, []string{"fastly"}, `fastly[_-]?(?:api[_-]?)?(?:token|key)`, `[A-Za-z0-9_-]{20,64}`, 3.0),
		assignedParityRule("vercel-token", "Vercel", "Vercel access token", high, []string{"vercel"}, `vercel[_-]?(?:access[_-]?)?token`, `[A-Za-z0-9_-]{20,80}`, 3.0),
		assignedParityRule("supabase-service-role-key", "Supabase", "Supabase service-role key", high, []string{"supabase", "service_role"}, `supabase[_-]?service[_-]?role[_-]?(?:key|token)`, `[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`, 3.0),
		assignedParityRule("algolia-admin-api-key", "Algolia", "Algolia admin API key", high, []string{"algolia", "admin_api_key"}, `algolia[_-]?(?:admin[_-]?)?(?:api[_-]?)?key`, `[A-Fa-f0-9]{32}`, 3.0),
		assignedParityRule("launchdarkly-sdk-key", "LaunchDarkly", "LaunchDarkly SDK key", high, []string{"launchdarkly", "ld_sdk"}, `(?:launchdarkly|ld)[_-]?(?:sdk[_-]?)?key`, `[A-Za-z0-9._-]{20,100}`, 3.0),
		assignedParityRule("launchdarkly-api-token", "LaunchDarkly", "LaunchDarkly API access token", high, []string{"launchdarkly", "ld_api"}, `(?:launchdarkly|ld)[_-]?(?:api[_-]?)?(?:token|access[_-]?token)`, `[A-Za-z0-9._-]{20,100}`, 3.0),
		assignedParityRule("segment-write-key", "Segment", "Segment write key", high, []string{"segment", "write_key"}, `segment[_-]?(?:write[_-]?)?key`, `[A-Za-z0-9_-]{20,64}`, 3.0),
		assignedParityRule("posthog-api-key", "PostHog", "PostHog API key", high, []string{"posthog", "phx_"}, `posthog[_-]?(?:api[_-]?)?key`, `(?:phx_)?[A-Za-z0-9_-]{20,80}`, 3.0),
		assignedParityRule("datadog-application-key", "Datadog", "Datadog application key", high, []string{"datadog", "dd_app"}, `(?:datadog|dd)[_-]?(?:application|app)[_-]?key`, `[A-Fa-f0-9]{40}`, 3.0),
		assignedParityRule("honeycomb-api-key", "Honeycomb", "Honeycomb API key", high, []string{"honeycomb"}, `honeycomb[_-]?(?:api[_-]?)?key`, `[A-Za-z0-9_-]{20,80}`, 3.0),
		assignedParityRule("splunk-hec-token", "Splunk", "Splunk HEC token", high, []string{"splunk", "hec"}, `splunk[_-]?(?:hec[_-]?)?token`, `[0-9A-Fa-f-]{36}`, 3.0),
		{
			id: "elastic-api-key", category: "Elastic", title: "Elastic API key", severity: high,
			keywords: []string{"authorization", "apikey"}, re: regexp.MustCompile(`(?i)\bauthorization["']?\s*[:=]\s*["']?apikey\s+([A-Za-z0-9+/=_-]{20,})`), group: 1, minEnt: 3.0,
		},
		assignedParityRule("jenkins-api-token", "Jenkins", "Jenkins API token", high, []string{"jenkins"}, `jenkins[_-]?(?:api[_-]?)?token`, `[A-Fa-f0-9]{32,34}`, 3.0),
		assignedParityRule("travis-ci-token", "TravisCI", "Travis CI token", high, []string{"travis"}, `travis(?:[_-]?ci)?[_-]?(?:api[_-]?)?(?:token|key)`, `[A-Za-z0-9_-]{20,80}`, 3.0),
		assignedParityRule("github-client-secret", "GitHub", "GitHub OAuth/App client secret", high, []string{"github", "client_secret"}, `github[_-]?client[_-]?secret`, `[A-Fa-f0-9]{40}`, 3.0),
		{
			id: "gitlab-deploy-token", category: "GitLab", title: "GitLab deploy token", severity: high,
			keywords: []string{"gldt-"}, re: regexp.MustCompile(`\b(gldt-[A-Za-z0-9_-]{20,})\b`), group: 1,
		},
		assignedParityRule("shopify-shared-secret", "Shopify", "Shopify app shared secret", high, []string{"shopify", "shared_secret"}, `shopify[_-]?(?:app[_-]?)?(?:shared[_-]?)?secret`, `[A-Fa-f0-9]{32}`, 3.0),
		assignedParityRule("azure-sas-token", "Azure", "Azure SAS token", high, []string{"azure", "sas", "sig="}, `azure[_-]?(?:storage[_-]?)?sas[_-]?(?:token|query)?`, `\??[A-Za-z0-9%&=+/_-]{40,}`, 3.0),
		{
			id: "gcp-oauth-refresh-token", category: "GCP", title: "GCP OAuth refresh token", severity: high,
			keywords: []string{"1//"}, re: regexp.MustCompile(`\b(1//[A-Za-z0-9_-]{30,200})\b`), group: 1, minEnt: 3.0,
		},
		assignedParityRule("mongodb-atlas-api-private-key", "MongoDB", "MongoDB Atlas API private key", high, []string{"mongodb", "atlas", "private_key"}, `(?:mongodb|atlas)[_-]?(?:api[_-]?)?private[_-]?key`, `[A-Za-z0-9_-]{24,64}`, 3.0),
	}
}
