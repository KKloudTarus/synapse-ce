package jsresolution

import "strings"

// SpecifierKind is the source-only identity class of a module specifier before
// workspace or SBOM correlation.
type SpecifierKind string

const (
	SpecifierBuiltin       SpecifierKind = "builtin"
	SpecifierPackage       SpecifierKind = "package"
	SpecifierPackageImport SpecifierKind = "package-import"
	SpecifierRelative      SpecifierKind = "relative"
	SpecifierUnsupported   SpecifierKind = "unsupported"
)

// Valid reports whether k is a supported specifier kind.
func (k SpecifierKind) Valid() bool {
	switch k {
	case SpecifierBuiltin, SpecifierPackage, SpecifierPackageImport, SpecifierRelative, SpecifierUnsupported:
		return true
	default:
		return false
	}
}

// ClassifiedSpecifier is the deterministic lexical classification of a module
// specifier. PackageName is set only for npm package specifiers. BuiltinName is
// canonicalized to the node: form.
type ClassifiedSpecifier struct {
	Raw         string
	Kind        SpecifierKind
	PackageName string
	BuiltinName string
}

// ClassifySpecifier classifies one observed module specifier without consulting
// the filesystem, package-manager state, or network.
func ClassifySpecifier(raw string) ClassifiedSpecifier {
	out := ClassifiedSpecifier{Raw: raw, Kind: SpecifierUnsupported}
	if raw == "" || strings.IndexByte(raw, 0) >= 0 || strings.ContainsAny(raw, "\r\n\t ") {
		return out
	}
	if raw == "." || raw == ".." || strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
		out.Kind = SpecifierRelative
		return out
	}
	if strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "\\") {
		return out
	}
	if strings.HasPrefix(raw, "node:") {
		name := strings.TrimPrefix(raw, "node:")
		if name == "" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || !isNodeBuiltin(name) {
			return out
		}
		out.Kind = SpecifierBuiltin
		out.BuiltinName = raw
		return out
	}
	if isBareNodeBuiltin(raw) {
		out.Kind = SpecifierBuiltin
		out.BuiltinName = "node:" + raw
		return out
	}
	if strings.HasPrefix(raw, "#") {
		if raw == "#" || strings.HasPrefix(raw, "#/") {
			return out
		}
		out.Kind = SpecifierPackageImport
		return out
	}
	if strings.Contains(raw, ":") {
		return out
	}

	root := raw
	if strings.HasPrefix(raw, "@") {
		parts := strings.Split(raw, "/")
		if len(parts) < 2 {
			return out
		}
		root = parts[0] + "/" + parts[1]
	} else if slash := strings.IndexByte(raw, '/'); slash >= 0 {
		root = raw[:slash]
	}
	name, err := NormalizePackageName(root)
	if err != nil {
		return out
	}
	out.Kind = SpecifierPackage
	out.PackageName = name
	return out
}

// Bare built-ins intentionally excludes prefix-only modules. Those modules are
// recognized only in node: form so an npm package with the same bare name is
// never silently reclassified as a runtime built-in.
var bareNodeBuiltins = map[string]struct{}{
	"_http_agent": {}, "_http_client": {}, "_http_common": {}, "_http_incoming": {}, "_http_outgoing": {}, "_http_server": {},
	"_stream_duplex": {}, "_stream_passthrough": {}, "_stream_readable": {}, "_stream_transform": {}, "_stream_wrap": {}, "_stream_writable": {},
	"_tls_common": {}, "_tls_wrap": {},
	"assert": {}, "assert/strict": {}, "async_hooks": {}, "buffer": {}, "child_process": {}, "cluster": {}, "console": {}, "constants": {},
	"crypto": {}, "dgram": {}, "diagnostics_channel": {}, "dns": {}, "dns/promises": {}, "domain": {}, "events": {}, "fs": {}, "fs/promises": {},
	"http": {}, "http2": {}, "https": {}, "inspector": {}, "inspector/promises": {}, "module": {}, "net": {}, "os": {}, "path": {},
	"path/posix": {}, "path/win32": {}, "perf_hooks": {}, "process": {}, "punycode": {}, "querystring": {}, "readline": {}, "readline/promises": {},
	"repl": {}, "stream": {}, "stream/consumers": {}, "stream/promises": {}, "stream/web": {}, "string_decoder": {}, "sys": {}, "timers": {},
	"timers/promises": {}, "tls": {}, "trace_events": {}, "tty": {}, "url": {}, "util": {}, "util/types": {}, "v8": {}, "vm": {}, "wasi": {},
	"worker_threads": {}, "zlib": {},
}

// Node reserves these modules for node:-prefixed loading. Keep this explicit
// rather than trusting an arbitrary node:* string as a built-in identity.
var prefixOnlyNodeBuiltins = map[string]struct{}{
	"ffi":            {},
	"sea":            {},
	"sqlite":         {},
	"test":           {},
	"test/reporters": {},
}

func isNodeBuiltin(name string) bool {
	if isBareNodeBuiltin(name) {
		return true
	}
	_, ok := prefixOnlyNodeBuiltins[name]
	return ok
}

func isBareNodeBuiltin(name string) bool {
	_, ok := bareNodeBuiltins[name]
	return ok
}
