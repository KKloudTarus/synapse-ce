package misconfig

import "testing"

// A cipher list mixes offers with exclusions, and a version token ends at a dot. Both are places a naive
// pattern reports a correct configuration: TLSv1.2 contains TLSv1, and !aNULL contains aNULL.
func TestNginxTLSTokensAreBounded(t *testing.T) {
	hardened := `server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:!aNULL:!MD5:!RC4;
}
`
	got := ruleIDs(scan(t, map[string]string{"nginx.conf": hardened}))
	for _, unwanted := range []string{"nginx-weak-tls-version", "nginx-weak-cipher-suite"} {
		if _, ok := got[unwanted]; ok {
			t.Errorf("%s fired on a hardened server", unwanted)
		}
	}

	weak := `server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ALL:!EXPORT:RC4-SHA;
}
`
	got = ruleIDs(scan(t, map[string]string{"nginx.conf": weak}))
	f, ok := got["nginx-weak-tls-version"]
	if !ok {
		t.Fatalf("a deprecated version must be reported, got %v", keys(got))
	}
	if !contains(f.Description, "TLSv1") {
		t.Errorf("the finding must name the version, got %q", f.Description)
	}
	// The exclusion comes before the offer, which is exactly where stopping at the first match reports nothing.
	c, ok := got["nginx-weak-cipher-suite"]
	if !ok {
		t.Fatalf("a broken cipher offered after an exclusion must be reported, got %v", keys(got))
	}
	if !contains(c.Description, "RC4") {
		t.Errorf("the finding must name the offered primitive, got %q", c.Description)
	}
}

// Passing the Host header ON to a named upstream is the ordinary reverse-proxy pattern. Building the upstream
// ADDRESS out of it is server-side request forgery. Reporting the first is the false positive that makes this
// class useless, and it is what another scanner does on 9 occurrences of this estate.
func TestNginxHostHeaderOnlyWhenItPicksTheTarget(t *testing.T) {
	ordinary := `server {
    listen 80;
    location / {
        proxy_pass http://app_upstream;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
`
	got := ruleIDs(scan(t, map[string]string{"nginx.conf": ordinary}))
	for _, unwanted := range []string{"nginx-proxy-pass-host-header", "nginx-redirect-host-header"} {
		if _, ok := got[unwanted]; ok {
			t.Errorf("%s fired on the standard reverse-proxy pattern", unwanted)
		}
	}

	forged := `server {
    listen 80;
    location / {
        proxy_pass http://$http_host;
    }
}
`
	if _, ok := ruleIDs(scan(t, map[string]string{"nginx.conf": forged}))["nginx-proxy-pass-host-header"]; !ok {
		t.Error("an upstream built from the Host header must be reported")
	}

	open := `server {
    listen 80;
    return 301 https://$http_host$request_uri;
}
`
	if _, ok := ruleIDs(scan(t, map[string]string{"nginx.conf": open}))["nginx-redirect-host-header"]; !ok {
		t.Error("a redirect built from the Host header must be reported")
	}
}

// A redirect that names a host with $scheme keeps a plaintext request plaintext. A redirect to a path capture
// is a canonical-URL rewrite on the same scheme and host, which is not the same thing.
func TestNginxRedirectScheme(t *testing.T) {
	kept := `server {
    listen 80;
    return 301 $scheme://10.11.12.1:8069;
}
`
	if _, ok := ruleIDs(scan(t, map[string]string{"nginx.conf": kept}))["nginx-redirect-without-scheme"]; !ok {
		t.Error("a redirect that carries the request's scheme must be reported")
	}

	canonical := `server {
    listen 80;
    rewrite ^(.+)/$ $1 permanent;
    return 301 https://app.example.com$request_uri;
}
`
	if _, ok := ruleIDs(scan(t, map[string]string{"nginx.conf": canonical}))["nginx-redirect-without-scheme"]; ok {
		t.Error("a path-capture rewrite and an absolute https redirect must stay silent")
	}
}

// add_header in a nested block REPLACES the inherited set. It is only a defect when the server block set one,
// so a location that is the only place headers are set is correct and stays silent.
func TestNginxHeaderRedefinition(t *testing.T) {
	discarding := `server {
    listen 443 ssl;
    ssl_protocols TLSv1.2;
    add_header Strict-Transport-Security "max-age=63072000" always;
    location /assets/ {
        add_header Cache-Control "public, immutable";
    }
}
`
	got := ruleIDs(scan(t, map[string]string{"nginx.conf": discarding}))
	f, ok := got["nginx-header-redefinition"]
	if !ok {
		t.Fatalf("a location that replaces the server's headers must be reported, got %v", keys(got))
	}
	if f.Resource != "location /assets/" {
		t.Errorf("the finding must name the route, got %q", f.Resource)
	}

	onlyInLocation := `server {
    listen 80;
    location = /config.js {
        add_header Cache-Control "no-store";
    }
    location = /index.html {
        add_header Cache-Control "no-store";
    }
}
`
	if _, ok := ruleIDs(scan(t, map[string]string{"nginx.conf": onlyInLocation}))["nginx-header-redefinition"]; ok {
		t.Error("a location is not discarding headers the server never set")
	}
}

// The CLIENT chooses the Upgrade value, so a literal Connection "upgrade" beside a forwarded $http_upgrade does
// not protect anything. Pinning the Upgrade value does.
func TestNginxH2CSmuggling(t *testing.T) {
	vulnerable := `server {
    listen 80;
    location /socket.io {
        proxy_pass http://app_upstream;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
`
	if _, ok := ruleIDs(scan(t, map[string]string{"nginx.conf": vulnerable}))["nginx-h2c-smuggling"]; !ok {
		t.Error("a forwarded Upgrade value beside a Connection upgrade must be reported")
	}

	pinned := `server {
    listen 80;
    location /socket.io {
        proxy_pass http://app_upstream;
        proxy_set_header Upgrade "websocket";
        proxy_set_header Connection "upgrade";
    }
}
`
	if _, ok := ruleIDs(scan(t, map[string]string{"nginx.conf": pinned}))["nginx-h2c-smuggling"]; ok {
		t.Error("a pinned Upgrade value must stay silent")
	}

	// Forwarding Upgrade with no Connection upgrade header does not complete the upgrade.
	lone := `server {
    listen 80;
    location /ws {
        proxy_pass http://app_upstream;
        proxy_set_header Upgrade $http_upgrade;
    }
}
`
	if _, ok := ruleIDs(scan(t, map[string]string{"nginx.conf": lone}))["nginx-h2c-smuggling"]; ok {
		t.Error("one header without the other does not upgrade the connection")
	}
}

// The slash is the whole defect: with it on both sides or neither, nginx resolves inside the target.
func TestNginxAliasTraversal(t *testing.T) {
	traversal := `server {
    listen 80;
    location /static {
        alias /var/www/static/;
    }
}
`
	if _, ok := ruleIDs(scan(t, map[string]string{"nginx.conf": traversal}))["nginx-alias-path-traversal"]; !ok {
		t.Error("a prefix without a trailing slash aliased to one with must be reported")
	}

	for name, cfg := range map[string]string{
		"both slashes":    "server {\n    location /static/ {\n        alias /var/www/static/;\n    }\n    listen 80;\n}\n",
		"neither slash":   "server {\n    location /static {\n        alias /var/www/static;\n    }\n    listen 80;\n}\n",
		"regex location":  "server {\n    location ~ ^/static/(.*)$ {\n        alias /var/www/static/;\n    }\n    listen 80;\n}\n",
		"root not alias":  "server {\n    location /static {\n        root /var/www/;\n    }\n    listen 80;\n}\n",
		"exact match loc": "server {\n    location = /static {\n        alias /var/www/static/index.html;\n    }\n    listen 80;\n}\n",
	} {
		if _, ok := ruleIDs(scan(t, map[string]string{"nginx.conf": cfg}))["nginx-alias-path-traversal"]; ok {
			t.Errorf("%s must stay silent", name)
		}
	}
}

// The remaining three are single-directive facts, checked together with their negatives.
func TestNginxDirectiveFacts(t *testing.T) {
	bad := `server {
    listen 80;
    client_max_body_size 0;
    location /files/ {
        autoindex on;
        alias /var/www/files/;
    }
    location /api/ {
        proxy_pass https://app_upstream;
        proxy_ssl_verify off;
    }
}
`
	got := ruleIDs(scan(t, map[string]string{"nginx.conf": bad}))
	for _, want := range []string{"nginx-unbounded-request-body", "nginx-autoindex-enabled", "nginx-proxy-ssl-verify-off"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected %s, got %v", want, keys(got))
		}
	}

	good := `server {
    listen 80;
    client_max_body_size 20m;
    location /files/ {
        autoindex off;
        alias /var/www/files/;
    }
    location /api/ {
        proxy_pass https://app_upstream;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca.pem;
    }
}
`
	got = ruleIDs(scan(t, map[string]string{"nginx.conf": good}))
	for _, unwanted := range []string{"nginx-unbounded-request-body", "nginx-autoindex-enabled", "nginx-proxy-ssl-verify-off"} {
		if _, ok := got[unwanted]; ok {
			t.Errorf("%s fired on a correct directive", unwanted)
		}
	}
}

// A .conf file that is not nginx configuration contributes nothing, and a commented-out directive is not a
// directive. Both are how a generic .conf extension turns into false positives.
func TestNginxPreFilter(t *testing.T) {
	ini := "[database]\nhost = db.internal\nssl_protocols = TLSv1\n"
	for _, f := range scan(t, map[string]string{"app.conf": ini}) {
		if f.RuleID == "nginx-weak-tls-version" {
			t.Error("an ini file must not be read as nginx configuration")
		}
	}

	commented := `server {
    listen 80;
    # ssl_protocols TLSv1 TLSv1.1;
    # autoindex on;
}
`
	got := ruleIDs(scan(t, map[string]string{"nginx.conf": commented}))
	for _, unwanted := range []string{"nginx-weak-tls-version", "nginx-autoindex-enabled"} {
		if _, ok := got[unwanted]; ok {
			t.Errorf("%s fired on a commented-out directive", unwanted)
		}
	}
}
