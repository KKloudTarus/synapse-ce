package rulemeta

// SemanticAlias records a legacy rule key whose detector is intentionally
// retired in favour of a canonical detector. The key remains catalogued for
// compatibility, but production scanning runs only the canonical detector so a
// single source construct cannot emit duplicate findings under two rule IDs.
type SemanticAlias struct {
	Alias     string
	Canonical string
}

var semanticAliases = []SemanticAlias{
	{Alias: "js-node-sys-module", Canonical: "node-sys-module"},
	{Alias: "js-node-domain-module", Canonical: "node-domain-module"},
	{Alias: "js-node-punycode-module", Canonical: "node-punycode-deprecated"},
	{Alias: "js-no-process-exit", Canonical: "node-process-exit-lib"},
}

var canonicalByAlias = func() map[string]string {
	out := make(map[string]string, len(semanticAliases))
	for _, pair := range semanticAliases {
		out[pair.Alias] = pair.Canonical
	}
	return out
}()

// displayNameOverrides disambiguates independently catalogued rules that share
// a historical display name. The semantic-duplicate guard remains strict: no
// pair is exempted merely because its keys are related.
var displayNameOverrides = map[string]string{
	"cpp:empty-catch-clause":               "Structurally empty catch clause",
	"csharp-ast-empty-catch":               "Structurally empty catch clause",
	"js-ast-ternary-boolean":               "Redundant boolean-literal ternary expression",
	"js-node-domain-module":                "Deprecated domain module import",
	"js-node-punycode-module":              "Deprecated built-in punycode module import",
	"js-node-sys-module":                   "Removed sys module import",
	"js-no-process-exit":                   "Abrupt process.exit() termination",
	"php:get-magic-quotes":                 "Removed get_magic_quotes_gpc API",
	"php:set-magic-quotes":                 "Removed set_magic_quotes_runtime API",
	"rust:swallowed-error-let-underscore":  "Result discarded by wildcard assignment",
	"vb:process-start-variable":            "Process.Start first argument is a variable",
}

// CanonicalKey maps a compatibility alias to the detector key that owns the
// production finding. Unknown keys are returned unchanged.
func CanonicalKey(key string) string {
	if canonical, ok := canonicalByAlias[key]; ok {
		return canonical
	}
	return key
}

// DisplayName returns the reviewed public name for keys whose historical name
// was ambiguous. All other rules keep their source-provided display name.
func DisplayName(key, current string) string {
	if name, ok := displayNameOverrides[key]; ok {
		return name
	}
	return current
}

// SemanticAliases returns a defensive copy for production detector
// reconciliation tests.
func SemanticAliases() []SemanticAlias {
	out := make([]SemanticAlias, len(semanticAliases))
	copy(out, semanticAliases)
	return out
}
