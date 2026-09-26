package misconfig

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// An nginx configuration decides what reaches the application and what the application's answers look like on
// the wire, so it holds its own class of defect: a redirect target the caller chooses, an upstream the caller
// chooses, a TLS version that was broken a decade ago, and a location block that silently discards the security
// headers the server block set.
//
// The file is read as DIRECTIVES inside a block stack rather than as lines, because several of these checks are
// about where a directive sits: `add_header` means something different in a location than in a server, and
// `alias` is only a traversal when its location prefix does not end in a slash.

const (
	maxNginxLines      = 200000 // bound a generated configuration
	maxNginxBlockDepth = 64     // a real configuration nests under ten; this is a guard, not a limit
)

// nginxDirective is one directive and the block stack it sits in.
type nginxDirective struct {
	name  string
	args  []string
	raw   string
	line  int
	stack []nginxBlock
}

type nginxBlock struct {
	kind string // server, location, http, if, upstream, map, ...
	arg  string // a location's match expression
	line int
}

// enclosing reports the innermost block of the given kind, and whether there is one.
func (d nginxDirective) enclosing(kind string) (nginxBlock, bool) {
	for i := len(d.stack) - 1; i >= 0; i-- {
		if d.stack[i].kind == kind {
			return d.stack[i], true
		}
	}
	return nginxBlock{}, false
}

var (
	reNginxBlockOpen = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*(.*?)\s*\{$`)
	// A weak TLS version. TLSv1 and TLSv1.1 are deprecated by RFC 8996; SSLv2 and SSLv3 are broken.
	// RE2 has no lookahead, so the token is bounded by explicit classes: without them the \b after TLSv1 is
	// satisfied by the dot in TLSv1.2 and a correct configuration reads as a broken one.
	reNginxWeakTLS = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9.])(SSLv2|SSLv3|TLSv1\.1|TLSv1)([^A-Za-z0-9.]|$)`)
	// A cipher string that admits a broken primitive. NULL and EXPORT mean no or token encryption.
	reNginxWeakCipher = regexp.MustCompile(`(?i)(^|[!+:\-])(RC4|3DES|DES|MD5|NULL|EXPORT|aNULL|eNULL|ADH|IDEA|SEED|PSK)(\b|:|$)`)
	// The Host header, which the CALLER sets. nginx offers it as $host (normalised) and $http_host (verbatim).
	reNginxHostVar = regexp.MustCompile(`\$(host|http_host)\b`)
	// A redirect whose target carries no scheme, so nginx answers with the scheme the request arrived on.
	reNginxSchemeless = regexp.MustCompile(`^(//|\$host|\$http_host|\$scheme)`)
)

// isNginxConfName recognises the conventional places an nginx configuration lives. The content sniff below is
// what actually decides, so this only has to let the candidates through.
func isNginxConfName(rel string) bool {
	base := strings.ToLower(filepath.Base(rel))
	dir := strings.ToLower(filepath.ToSlash(filepath.Dir(rel)))
	if strings.HasPrefix(base, "nginx") {
		return true
	}
	if strings.Contains(dir, "nginx") || strings.Contains(dir, "sites-enabled") ||
		strings.Contains(dir, "sites-available") || strings.Contains(dir, "conf.d") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(base))
	return ext == ".conf" || ext == ".nginx" || ext == ".vhost"
}

// looksNginx is the content pre-filter: a block nginx owns, plus a semicolon-terminated directive. A plain
// .conf file that is an ini or a properties file contributes nothing.
func looksNginx(data []byte) bool {
	t := string(data)
	if !strings.Contains(t, ";") {
		return false
	}
	for _, marker := range []string{"server {", "server{", "http {", "http{", "location ", "upstream ", "listen ", "server_name "} {
		if strings.Contains(t, marker) {
			return true
		}
	}
	return false
}

// scanNginx runs the owned nginx checks.
func scanNginx(rel string, data []byte) []ports.MisconfigRawFinding {
	directives := parseNginxDirectives(data)
	if len(directives) == 0 {
		return nil
	}
	var out []ports.MisconfigRawFinding
	add := func(d nginxDirective, rule, title, desc string, sev shared.Severity) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: d.line, RuleID: rule, Title: title, Severity: sev,
			Resource: clip(nginxResource(d)), Description: desc,
		})
	}

	// serverHeaders records the server blocks that set a response header, so a location block that sets one
	// too can be recognised as replacing the inherited set rather than adding to it.
	serverHeaders := map[int]bool{}
	for _, d := range directives {
		if d.name != "add_header" {
			continue
		}
		if block, ok := d.enclosing("server"); ok {
			if _, inLocation := d.enclosing("location"); !inLocation {
				serverHeaders[block.line] = true
			}
		}
	}

	for _, d := range directives {
		switch d.name {
		case "ssl_protocols":
			if m := reNginxWeakTLS.FindStringSubmatch(strings.Join(d.args, " ")); m != nil {
				add(d, "nginx-weak-tls-version", "Server accepts a deprecated TLS version",
					"ssl_protocols admits "+clip(m[2])+". TLS 1.0 and 1.1 are deprecated by RFC 8996 and SSLv2 and SSLv3 are broken, so a client that offers only one of them still gets an encrypted-looking connection an attacker on the path can read. List TLSv1.2 and TLSv1.3 only.",
					shared.SeverityMedium)
			}
		case "ssl_ciphers":
			// A cipher list mixes offers with exclusions, so every match has to be read: stopping at the first
			// one reports nothing for `ALL:!EXPORT:RC4`, where the exclusion comes before the offer.
			if name := nginxWeakCipherOffered(strings.Join(d.args, " ")); name != "" {
				add(d, "nginx-weak-cipher-suite", "Cipher list admits a broken primitive",
					"ssl_ciphers admits "+clip(name)+", which is broken or offers no confidentiality at all. Prefer an ECDHE suite list with AES-GCM or CHACHA20, and exclude the rest with a leading exclamation mark.",
					shared.SeverityMedium)
			}
		case "proxy_pass":
			if reNginxHostVar.MatchString(strings.Join(d.args, " ")) {
				add(d, "nginx-proxy-pass-host-header", "Upstream is chosen by the Host header",
					"proxy_pass builds the upstream address from the Host header, which the caller sets, so a request carrying any Host reaches whatever that name resolves to with this server's network position. That is server-side request forgery through a configuration file. Name the upstream explicitly, or resolve it through an upstream block.",
					shared.SeverityHigh)
			}
		case "proxy_ssl_verify":
			if len(d.args) > 0 && strings.EqualFold(d.args[0], "off") {
				add(d, "nginx-proxy-ssl-verify-off", "Upstream TLS certificate is not verified",
					"proxy_ssl_verify is off, so nginx accepts any certificate the upstream presents, including one an attacker on that path substitutes. The connection is encrypted and unauthenticated, which is the part that matters. Turn verification on and point proxy_ssl_trusted_certificate at the issuing CA.",
					shared.SeverityMedium)
			}
		case "autoindex":
			if len(d.args) > 0 && strings.EqualFold(d.args[0], "on") {
				add(d, "nginx-autoindex-enabled", "Directory listing is served",
					"autoindex is on, so a request for a directory with no index file is answered with a listing of everything in it: backups, dumps and keys that were never meant to be reachable by name. Turn it off and serve an explicit index.",
					shared.SeverityMedium)
			}
		case "client_max_body_size":
			if len(d.args) > 0 && strings.TrimSpace(d.args[0]) == "0" {
				add(d, "nginx-unbounded-request-body", "Request body size is unbounded",
					"client_max_body_size 0 removes the limit, so one caller decides how much disk and memory a request consumes before any application code runs. Set a size the largest legitimate upload needs.",
					shared.SeverityLow)
			}
		case "add_header":
			if block, ok := d.enclosing("server"); ok {
				if _, inLocation := d.enclosing("location"); inLocation && serverHeaders[block.line] {
					add(d, "nginx-header-redefinition", "Location block discards the server's headers",
						"add_header in a location REPLACES the inherited set rather than adding to it, so every header the enclosing server block set is dropped for this route. That is how a Strict-Transport-Security or Content-Security-Policy header silently stops being sent on exactly the paths that matter. Repeat the inherited headers here, or move them to a snippet this location includes.",
						shared.SeverityMedium)
				}
			}
		case "proxy_set_header":
			// The CLIENT chooses the Upgrade value, so forwarding it verbatim is what lets a caller ask for
			// h2c. A literal Connection "upgrade" beside it does not help: the protocol being upgraded to is
			// still the caller's choice.
			if len(d.args) >= 2 && strings.EqualFold(d.args[0], "Upgrade") &&
				strings.Contains(strings.Join(d.args[1:], " "), "$http_upgrade") && nginxForwardsConnectionUpgrade(d, directives) {
				add(d, "nginx-h2c-smuggling", "Client chooses the protocol to upgrade to",
					"The Upgrade header is forwarded from the request while a Connection upgrade header is set, so a caller asking for h2c gets an HTTP/2 cleartext connection to the upstream and then speaks to it directly, past every rule this configuration applies per request. Pin the value the route actually needs (proxy_set_header Upgrade \"websocket\"), or accept the upgrade only where the upstream is a websocket endpoint.",
					shared.SeverityHigh)
			}
		case "alias":
			// A location prefix that does not end in a slash, aliased to a path that does, lets `/prefix../`
			// resolve above the alias root. This is nginx's own documented trap.
			if block, ok := d.enclosing("location"); ok && len(d.args) > 0 {
				prefix := nginxLocationPrefix(block.arg)
				if prefix != "" && !strings.HasSuffix(prefix, "/") && strings.HasSuffix(d.args[0], "/") {
					add(d, "nginx-alias-path-traversal", "Alias allows a path above its directory",
						"The location prefix "+clip(prefix)+" does not end in a slash while the alias target does, so nginx appends whatever follows the prefix to the target and a request for "+clip(prefix)+"../ resolves above it. Add the trailing slash to the location, or use root instead of alias.",
						shared.SeverityHigh)
				}
			}
		case "return", "rewrite":
			target := nginxRedirectTarget(d)
			if target == "" {
				continue
			}
			if reNginxHostVar.MatchString(target) {
				add(d, "nginx-redirect-host-header", "Redirect target is chosen by the Host header",
					"The redirect is built from the Host header, which the caller sets, so a request carrying an attacker's host is answered with a redirect to it. That turns this server into an open redirect and poisons any cache that keys on the path alone. Redirect to a literal host, or to $server_name.",
					shared.SeverityMedium)
				continue
			}
			if reNginxSchemeless.MatchString(target) {
				add(d, "nginx-redirect-without-scheme", "Redirect keeps the request's scheme",
					"The redirect target carries no scheme, so nginx answers with the scheme the request arrived on and a plaintext request is redirected to another plaintext URL. A redirect meant to move clients onto TLS then never does. Write the scheme into the target.",
					shared.SeverityLow)
			}
		}
	}
	return out
}

// nginxForwardsConnectionUpgrade reports whether the same block also sets a Connection header that asks for an
// upgrade. Both headers have to reach the upstream for the upgrade to happen, so one without the other is not
// the defect.
func nginxForwardsConnectionUpgrade(d nginxDirective, all []nginxDirective) bool {
	block := 0
	if len(d.stack) > 0 {
		block = d.stack[len(d.stack)-1].line
	}
	for _, other := range all {
		if other.name != "proxy_set_header" || len(other.args) < 2 || !strings.EqualFold(other.args[0], "Connection") {
			continue
		}
		at := 0
		if len(other.stack) > 0 {
			at = other.stack[len(other.stack)-1].line
		}
		if at != block {
			continue
		}
		value := strings.ToLower(strings.Trim(strings.Join(other.args[1:], " "), `"'`))
		if strings.Contains(value, "upgrade") || strings.Contains(value, "$http_connection") {
			return true
		}
	}
	return false
}

// nginxWeakCipherOffered returns the first broken primitive a cipher list OFFERS. A name behind an exclamation
// mark is being excluded, which is the fix rather than the defect.
func nginxWeakCipherOffered(list string) string {
	for _, m := range reNginxWeakCipher.FindAllStringSubmatch(list, -1) {
		if !strings.Contains(m[1], "!") {
			return m[2]
		}
	}
	return ""
}

// nginxResource names the block a finding sits in, so a reader knows which route it is about.
func nginxResource(d nginxDirective) string {
	if block, ok := d.enclosing("location"); ok {
		return "location " + block.arg
	}
	if block, ok := d.enclosing("server"); ok && block.arg != "" {
		return "server " + block.arg
	}
	return d.name
}

// nginxLocationPrefix returns the path a location matches, dropping a modifier. A regex location has no plain
// prefix, so it returns the empty string and the alias check does not apply.
func nginxLocationPrefix(arg string) string {
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		return ""
	}
	switch fields[0] {
	case "~", "~*", "^~", "=":
		if len(fields) < 2 {
			return ""
		}
		if fields[0] == "~" || fields[0] == "~*" {
			return "" // a regex location: what it matches is not a prefix
		}
		return fields[1]
	}
	if strings.ContainsAny(fields[0], "()[]|*+?") {
		return "" // an unprefixed regex
	}
	return fields[0]
}

// nginxRedirectTarget returns the URL a return or rewrite directive redirects to, or "" when the directive is
// not a redirect. A `return 200` or a `rewrite ... last` rewrites internally and answers no redirect.
func nginxRedirectTarget(d nginxDirective) string {
	if d.name == "return" {
		if len(d.args) < 2 || !strings.HasPrefix(d.args[0], "3") || len(d.args[0]) != 3 {
			return ""
		}
		return strings.Trim(d.args[1], `"'`)
	}
	// rewrite <pattern> <replacement> [flag]
	if len(d.args) < 3 {
		return ""
	}
	flag := strings.ToLower(strings.Trim(d.args[len(d.args)-1], `"'`))
	if flag != "redirect" && flag != "permanent" {
		return ""
	}
	return strings.Trim(d.args[1], `"'`)
}

// parseNginxDirectives reads the file into directives with their block stack. It is deliberately tolerant: an
// unbalanced brace costs the rest of the stack, never the scan.
func parseNginxDirectives(data []byte) []nginxDirective {
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxNginxLines {
		lines = lines[:maxNginxLines]
	}
	var out []nginxDirective
	var stack []nginxBlock
	for i, raw := range lines {
		line := strings.TrimSpace(stripNginxComment(strings.TrimRight(raw, "\r")))
		if line == "" {
			continue
		}
		// A line can close blocks and then open or state something else.
		for strings.HasPrefix(line, "}") {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			line = strings.TrimSpace(line[1:])
		}
		if line == "" {
			continue
		}
		if m := reNginxBlockOpen.FindStringSubmatch(line); m != nil {
			if len(stack) < maxNginxBlockDepth {
				stack = append(stack, nginxBlock{kind: strings.ToLower(m[1]), arg: m[2], line: i + 1})
			}
			continue
		}
		statement := strings.TrimSuffix(line, ";")
		fields := strings.Fields(statement)
		if len(fields) == 0 {
			continue
		}
		stackCopy := make([]nginxBlock, len(stack))
		copy(stackCopy, stack)
		out = append(out, nginxDirective{
			name: strings.ToLower(fields[0]), args: fields[1:], raw: line, line: i + 1, stack: stackCopy,
		})
	}
	return out
}

// stripNginxComment removes a `#` comment. A `#` inside a quoted string is part of the value.
func stripNginxComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case c == '#' && !inS && !inD:
			return s[:i]
		}
	}
	return s
}
