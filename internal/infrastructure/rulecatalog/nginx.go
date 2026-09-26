package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// nginxRules are the nginx configuration checks. The file decides what reaches the application and what the
// application's answers look like on the wire, so it holds a class of defect no other surface does: a redirect
// target or an upstream the caller chooses, a TLS version broken a decade ago, and a location block that
// silently discards the headers the server block set.
func nginxRules() []rule.Rule {
	const compliantServer = "server {\n    listen 443 ssl;\n    server_name app.example.com;\n" +
		"    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:!aNULL;\n" +
		"    add_header Strict-Transport-Security \"max-age=63072000\" always;\n" +
		"    client_max_body_size 20m;\n" +
		"    location / {\n        proxy_pass http://app_upstream;\n    }\n}\n"

	return []rule.Rule{
		{
			Key: "nginx-weak-tls-version", Name: "Server accepts a deprecated TLS version", Language: "Nginx",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityMedium, Tags: []string{"nginx", "transport"},
			CWE: []string{"CWE-327"}, OWASP: []string{"A02:2021"}, Detection: rule.DetectionAST,
			Description: "`ssl_protocols` admits SSLv2, SSLv3, TLSv1 or TLSv1.1.",
			Rationale: "A client that offers only a deprecated version still gets a connection that looks encrypted and is readable by anything " +
				"on the path. TLS 1.0 and 1.1 are deprecated by RFC 8996 and SSLv2 and SSLv3 are broken outright, and a server that still accepts " +
				"one is the reason a downgrade works.\n\nSource: https://datatracker.ietf.org/doc/html/rfc8996",
			Remediation:         "List TLSv1.2 and TLSv1.3 only.",
			CompliantExample:    compliantServer,
			NoncompliantExample: "server {\n    listen 443 ssl;\n    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n}\n",
			RemediationEffort:   15,
		},
		{
			Key: "nginx-weak-cipher-suite", Name: "Cipher list admits a broken primitive", Language: "Nginx",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityMedium, Tags: []string{"nginx", "transport"},
			CWE: []string{"CWE-327"}, OWASP: []string{"A02:2021"}, Detection: rule.DetectionAST,
			Description: "`ssl_ciphers` admits RC4, DES, 3DES, MD5, a NULL suite or an anonymous key exchange.",
			Rationale: "A cipher list is a negotiation, so the weakest suite in it is the one an attacker steers the handshake toward. NULL and " +
				"EXPORT suites offer no confidentiality at all, and an anonymous key exchange authenticates nobody, which makes the certificate " +
				"beside it decorative.\n\nSource: https://cwe.mitre.org/data/definitions/327.html",
			Remediation:         "Offer an ECDHE suite list with AES-GCM or CHACHA20, and exclude the rest with a leading exclamation mark.",
			CompliantExample:    compliantServer,
			NoncompliantExample: "server {\n    listen 443 ssl;\n    ssl_protocols TLSv1.2;\n    ssl_ciphers HIGH:RC4-SHA:!aNULL;\n}\n",
			RemediationEffort:   15,
		},
		{
			Key: "nginx-proxy-pass-host-header", Name: "Upstream is chosen by the Host header", Language: "Nginx",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityHigh, Tags: []string{"nginx", "ssrf"},
			CWE: []string{"CWE-918"}, OWASP: []string{"A10:2021"}, Detection: rule.DetectionAST,
			Description: "`proxy_pass` builds the upstream address from `$host` or `$http_host`.",
			Rationale: "The Host header is set by the caller, so the upstream is too: a request carrying any host reaches whatever that name " +
				"resolves to, with this server's network position and its access to everything inside the perimeter. That is server-side request " +
				"forgery expressed in a configuration file. Passing the header ON to a named upstream (`proxy_set_header Host $host`) is the " +
				"ordinary reverse-proxy pattern and is a different thing, so it is not reported.\n\nSource: https://cwe.mitre.org/data/definitions/918.html",
			Remediation:         "Name the upstream, or resolve it through an `upstream` block.",
			CompliantExample:    compliantServer,
			NoncompliantExample: "server {\n    listen 80;\n    location / {\n        proxy_pass http://$http_host;\n    }\n}\n",
			RemediationEffort:   60,
		},
		{
			Key: "nginx-redirect-host-header", Name: "Redirect target is chosen by the Host header", Language: "Nginx",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityMedium, Tags: []string{"nginx", "redirect"},
			CWE: []string{"CWE-601"}, OWASP: []string{"A01:2021"}, Detection: rule.DetectionAST,
			Description: "A `return 30x` or a redirecting `rewrite` builds its target from `$host` or `$http_host`.",
			Rationale: "The caller sets the Host header, so the caller sets the redirect. A request carrying an attacker's host is answered with " +
				"a redirect to it, which is an open redirect on a domain users trust, and it poisons any cache that keys on the path alone." +
				"\n\nSource: https://cwe.mitre.org/data/definitions/601.html",
			Remediation:         "Redirect to a literal host, or to `$server_name`.",
			CompliantExample:    "server {\n    listen 80;\n    server_name app.example.com;\n    return 301 https://app.example.com$request_uri;\n}\n",
			NoncompliantExample: "server {\n    listen 80;\n    return 301 https://$http_host$request_uri;\n}\n",
			RemediationEffort:   15,
		},
		{
			Key: "nginx-redirect-without-scheme", Name: "Redirect keeps the request's scheme", Language: "Nginx",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityLow, Tags: []string{"nginx", "transport"},
			CWE: []string{"CWE-319"}, OWASP: []string{"A02:2021"}, Detection: rule.DetectionAST,
			Description: "A redirect target names a host but carries `$scheme` or no scheme at all.",
			Rationale: "nginx answers with the scheme the request arrived on, so a plaintext request is redirected to another plaintext URL and a " +
				"redirect meant to move clients onto TLS never does. A target that is only a path capture is a canonical-URL rewrite on the same " +
				"scheme and host, which is not this.\n\nSource: https://cwe.mitre.org/data/definitions/319.html",
			Remediation:         "Write the scheme into the target.",
			CompliantExample:    "server {\n    listen 80;\n    server_name app.example.com;\n    return 301 https://app.example.com$request_uri;\n}\n",
			NoncompliantExample: "server {\n    listen 80;\n    return 301 $scheme://10.11.12.1:8069;\n}\n",
			RemediationEffort:   15,
		},
		{
			Key: "nginx-header-redefinition", Name: "Location block discards the server's headers", Language: "Nginx",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityMedium, Tags: []string{"nginx", "headers"},
			CWE: []string{"CWE-693"}, OWASP: []string{"A05:2021"}, Detection: rule.DetectionAST,
			Description: "A `location` block calls `add_header` while its `server` block also does.",
			Rationale: "`add_header` in a nested block REPLACES the inherited set rather than adding to it, so every header the server block set " +
				"is dropped for that route and nothing in the file says so. It is how Strict-Transport-Security or Content-Security-Policy stops " +
				"being sent on exactly the paths a caching or override rule singled out." +
				"\n\nSource: https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header",
			Remediation:         "Repeat the inherited headers in the location, or move them into a snippet every block includes.",
			CompliantExample:    compliantServer,
			NoncompliantExample: "server {\n    listen 443 ssl;\n    ssl_protocols TLSv1.2;\n    add_header Strict-Transport-Security \"max-age=63072000\" always;\n    location /assets/ {\n        add_header Cache-Control \"public, immutable\";\n    }\n}\n",
			RemediationEffort:   30,
		},
		{
			Key: "nginx-h2c-smuggling", Name: "Client chooses the protocol to upgrade to", Language: "Nginx",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityHigh, Tags: []string{"nginx", "smuggling"},
			CWE: []string{"CWE-444"}, OWASP: []string{"A05:2021"}, Detection: rule.DetectionAST,
			Description: "`proxy_set_header Upgrade $http_upgrade` is set beside a Connection upgrade header.",
			Rationale: "Forwarding the Upgrade value verbatim lets the caller pick the protocol, so a request asking for h2c is answered with an " +
				"HTTP/2 cleartext connection straight to the upstream, and everything this configuration enforces per request stops applying. A " +
				"literal `Connection \"upgrade\"` beside it does not help, because the protocol being upgraded to is still the caller's choice." +
				"\n\nSource: https://cwe.mitre.org/data/definitions/444.html",
			Remediation:         "Pin the value the route needs (`proxy_set_header Upgrade \"websocket\"`), or accept an upgrade only where the upstream is a websocket endpoint.",
			CompliantExample:    "server {\n    listen 80;\n    location /socket.io {\n        proxy_pass http://app_upstream;\n        proxy_set_header Upgrade \"websocket\";\n        proxy_set_header Connection \"upgrade\";\n    }\n}\n",
			NoncompliantExample: "server {\n    listen 80;\n    location /socket.io {\n        proxy_pass http://app_upstream;\n        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection \"upgrade\";\n    }\n}\n",
			RemediationEffort:   30,
		},
		{
			Key: "nginx-alias-path-traversal", Name: "Alias allows a path above its directory", Language: "Nginx",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityHigh, Tags: []string{"nginx", "traversal"},
			CWE: []string{"CWE-22"}, OWASP: []string{"A01:2021"}, Detection: rule.DetectionAST,
			Description: "A `location` prefix without a trailing slash is served by an `alias` target that has one.",
			Rationale: "nginx appends whatever follows the prefix to the alias target, so with the slash on only one side a request for " +
				"`/prefix../` resolves above the directory the alias points at and serves files from the parent. This is nginx's own documented " +
				"trap and it reads as a working static-file block.\n\nSource: https://nginx.org/en/docs/http/ngx_http_core_module.html#alias",
			Remediation:         "Add the trailing slash to the location, or use `root` instead of `alias`.",
			CompliantExample:    "server {\n    listen 80;\n    location /static/ {\n        alias /var/www/static/;\n    }\n}\n",
			NoncompliantExample: "server {\n    listen 80;\n    location /static {\n        alias /var/www/static/;\n    }\n}\n",
			RemediationEffort:   15,
		},
		{
			Key: "nginx-proxy-ssl-verify-off", Name: "Upstream TLS certificate is not verified", Language: "Nginx",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityMedium, Tags: []string{"nginx", "transport"},
			CWE: []string{"CWE-295"}, OWASP: []string{"A02:2021"}, Detection: rule.DetectionAST,
			Description: "`proxy_ssl_verify` is off.",
			Rationale: "nginx then accepts any certificate the upstream presents, including one an attacker on that path substitutes, so the " +
				"connection is encrypted and unauthenticated. Encryption without authentication protects against a passive reader and against " +
				"nobody who can answer.\n\nSource: https://cwe.mitre.org/data/definitions/295.html",
			Remediation:         "Turn verification on and point `proxy_ssl_trusted_certificate` at the issuing CA.",
			CompliantExample:    "server {\n    listen 80;\n    location / {\n        proxy_pass https://app_upstream;\n        proxy_ssl_verify on;\n        proxy_ssl_trusted_certificate /etc/ssl/certs/ca.pem;\n    }\n}\n",
			NoncompliantExample: "server {\n    listen 80;\n    location / {\n        proxy_pass https://app_upstream;\n        proxy_ssl_verify off;\n    }\n}\n",
			RemediationEffort:   30,
		},
		{
			Key: "nginx-autoindex-enabled", Name: "Directory listing is served", Language: "Nginx",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityMedium, Tags: []string{"nginx", "exposure"},
			CWE: []string{"CWE-548"}, OWASP: []string{"A01:2021"}, Detection: rule.DetectionAST,
			Description: "`autoindex` is on.",
			Rationale: "A request for a directory with no index file is answered with a listing of everything in it, so a backup, a database dump " +
				"or a key that was safe only because nobody knew its name becomes reachable by browsing." +
				"\n\nSource: https://cwe.mitre.org/data/definitions/548.html",
			Remediation:         "Turn it off and serve an explicit index.",
			CompliantExample:    "server {\n    listen 80;\n    location /files/ {\n        autoindex off;\n        alias /var/www/files/;\n    }\n}\n",
			NoncompliantExample: "server {\n    listen 80;\n    location /files/ {\n        autoindex on;\n        alias /var/www/files/;\n    }\n}\n",
			RemediationEffort:   5,
		},
		{
			Key: "nginx-unbounded-request-body", Name: "Request body size is unbounded", Language: "Nginx",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityLow, Tags: []string{"nginx", "availability"},
			CWE: []string{"CWE-770"}, OWASP: []string{"A04:2021"}, Detection: rule.DetectionAST,
			Description: "`client_max_body_size` is 0, which removes the limit.",
			Rationale: "One caller then decides how much disk and memory a request consumes, and it is consumed before any application code runs, " +
				"so no application-level control can refuse it.\n\nSource: https://cwe.mitre.org/data/definitions/770.html",
			Remediation:         "Set the size the largest legitimate upload needs.",
			CompliantExample:    compliantServer,
			NoncompliantExample: "server {\n    listen 80;\n    client_max_body_size 0;\n}\n",
			RemediationEffort:   5,
		},
	}
}
