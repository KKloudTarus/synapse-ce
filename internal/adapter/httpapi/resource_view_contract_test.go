package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// wireContract is the exact set of JSON keys each view type serializes, written out by hand.
//
// Engagements and projects became a breaking wire-format change in this release, and the web client
// reads these names. A handler test that enumerates SOME keys does not stop a rename: renaming
// authorized_from left the whole package green, which is the same defect the snake_case work was
// undertaken to fix. This pins the complete set in both directions, so adding a field, removing one
// or renaming one all fail here and force the web client and the OpenAPI document to move with it.
var wireContract = map[string][]string{
	"engagementView": {
		"id", "tenant_id", "project_id", "business_asset_id", "name", "client", "status",
		"scope", "roe", "authorized_from", "authorized_to", "timezone", "live_recon_enabled",
		"created_at", "updated_at",
		// list enrichment, present only on listEngagements rows with the stores wired
		"findings_count", "last_scan_date", "last_scan_status",
	},
	"projectView": {
		"id", "tenant_id", "name", "key", "source_binding", "default_profile_by_lang",
		"gate_id", "created_at", "updated_at",
	},
	"engagementFindingsView": {"total", "critical", "high", "medium", "low", "info"},
	"scopeView":              {"in_scope", "out_of_scope"},
	"roeView":                {"allowed_tool_classes", "blackouts"},
	"blackoutView":           {"from", "to"},
}

// TestResourceViewWireContract compares the declared contract with the struct tags in
// resource_view.go, so neither side can drift without the other.
func TestResourceViewWireContract(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "resource_view.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse resource_view.go: %v", err)
	}

	found := map[string][]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structType, ok := spec.Type.(*ast.StructType)
		if !ok {
			return true
		}
		var keys []string
		for _, field := range structType.Fields.List {
			if field.Tag == nil {
				continue
			}
			tag, unquoteErr := strconv.Unquote(field.Tag.Value)
			if unquoteErr != nil {
				t.Fatalf("%s: unreadable struct tag %s", spec.Name.Name, field.Tag.Value)
			}
			name, _, _ := strings.Cut(jsonTagValue(tag), ",")
			if name == "" || name == "-" {
				continue
			}
			keys = append(keys, name)
		}
		if len(keys) > 0 {
			sort.Strings(keys)
			found[spec.Name.Name] = keys
		}
		return true
	})

	for name, want := range wireContract {
		got, ok := found[name]
		if !ok {
			t.Errorf("view type %q is gone from resource_view.go; the contract above still names it", name)
			continue
		}
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s wire keys = %v, want %v.\nA rename here breaks the web client and the OpenAPI document; change them in the same commit and update this contract.", name, got, want)
		}
	}
	for name := range found {
		if _, ok := wireContract[name]; !ok {
			t.Errorf("resource_view.go declares view type %q with no entry in the wire contract; add one so its keys are pinned", name)
		}
	}
}

// jsonTagValue extracts the json tag from a raw struct tag without reflect, which cannot read a tag
// off an ast node.
func jsonTagValue(tag string) string {
	for _, part := range strings.Fields(tag) {
		if after, ok := strings.CutPrefix(part, `json:"`); ok {
			return strings.TrimSuffix(after, `"`)
		}
	}
	return ""
}
