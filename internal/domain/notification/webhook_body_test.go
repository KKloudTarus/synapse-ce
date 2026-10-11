package notification

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func webhookSchema(t *testing.T) *msgtemplate.Schema {
	t.Helper()
	schema, err := msgtemplate.NewSchema(msgtemplate.SchemaSpec{Vars: []string{"title", "severity", "count"}})
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func renderBody(t *testing.T, source string, vars map[string]string) []byte {
	t.Helper()
	out, err := RenderCustomWebhookBody(source, webhookSchema(t), msgtemplate.Data{Vars: vars})
	if err != nil {
		t.Fatalf("render %s: %v", source, err)
	}
	if !json.Valid(out) {
		t.Fatalf("rendered body is not JSON: %s", out)
	}
	return out
}

// A variable's value always lands as one JSON string, whatever it looks like: a number, a boolean,
// an object, a closing bracket or quote.
func TestWebhookBodyTypeConfusion(t *testing.T) {
	for _, value := range []string{`123`, `true`, `null`, `{"a":1}`, `]`, `[1,2]`, `"`, `\`, `\"`, `}`, "line\nbreak", `{{.title}}`} {
		out := renderBody(t, `{"title":"{{.title}}","n":"{{.count}}"}`, map[string]string{"title": value, "count": value})
		var decoded map[string]any
		if err := json.Unmarshal(out, &decoded); err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		if len(decoded) != 2 {
			t.Fatalf("%q: keys = %v", value, decoded)
		}
		for _, key := range []string{"title", "n"} {
			if _, ok := decoded[key].(string); !ok {
				t.Fatalf("%q: %s is %T, want a string: %s", value, key, decoded[key], out)
			}
		}
	}
	// The value round-trips as text once the engine's Markdown escapes are removed.
	out := renderBody(t, `{"title":"{{.title}}"}`, map[string]string{"title": `{"a":1} ] "q"`})
	var decoded map[string]string
	if err := json.Unmarshal(out, &decoded); err != nil || decoded["title"] != `{"a":1} ] "q"` {
		t.Fatalf("title = %q err=%v (%s)", decoded["title"], err, out)
	}
}

// Quotes and braces inside values cannot add keys or close the object.
func TestWebhookBodyKeyInjection(t *testing.T) {
	for _, value := range []string{`"}`, `","admin":true`, `", "admin": true, "x": "`, `"},{"admin":true`, `\",\"admin\":true`} {
		out := renderBody(t, `{"event":"scan","title":"{{.title}}","nested":{"sev":"{{.severity}}"}}`, map[string]string{"title": value, "severity": value})
		var decoded map[string]any
		if err := json.Unmarshal(out, &decoded); err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		if _, injected := decoded["admin"]; injected || len(decoded) != 3 {
			t.Fatalf("%q injected a key: %s", value, out)
		}
		nested, _ := decoded["nested"].(map[string]any)
		if len(nested) != 1 {
			t.Fatalf("%q changed the nested object: %s", value, out)
		}
		if decoded["title"] != value {
			t.Fatalf("%q rendered as %q", value, decoded["title"])
		}
	}
}

// Literals keep their type and text: numbers are not rounded, key order is the author's.
func TestWebhookBodyKeepsLiterals(t *testing.T) {
	out := renderBody(t, `{"z":1,"big":12345678901234567890,"f":1.50,"ok":true,"none":null,"list":[1,"a",{"k":"v"}],"empty":{},"arr":[],"literal":"a\\*b"}`, nil)
	want := `{"z":1,"big":12345678901234567890,"f":1.50,"ok":true,"none":null,"list":[1,"a",{"k":"v"}],"empty":{},"arr":[],"literal":"a\\*b"}`
	if string(out) != want {
		t.Fatalf("body = %s\nwant   %s", out, want)
	}
	// A rendered value mixes literal text and escaped variables.
	out = renderBody(t, `{"text":"Scan {{.title}}: {{.severity}}!"}`, map[string]string{"title": "*done*", "severity": "high"})
	if string(out) != `{"text":"Scan *done*: high!"}` {
		t.Fatalf("body = %s", out)
	}
}

func TestWebhookBodyRefusals(t *testing.T) {
	deep := `{"a":` + strings.Repeat(`[`, MaxWebhookBodyDepth) + strings.Repeat(`]`, MaxWebhookBodyDepth) + `}`
	okDeep := `{"a":` + strings.Repeat(`[`, MaxWebhookBodyDepth-1) + strings.Repeat(`]`, MaxWebhookBodyDepth-1) + `}`
	manyLeaves := `{"a":[` + strings.TrimSuffix(strings.Repeat(`1,`, MaxWebhookBodyLeaves+1), ",") + `]}`
	okLeaves := `{"a":[` + strings.TrimSuffix(strings.Repeat(`1,`, MaxWebhookBodyLeaves), ",") + `]}`
	large := `{"a":"` + strings.Repeat("x", MaxWebhookBodyBytes) + `"}`
	for _, ok := range []string{okDeep, okLeaves, `{}`, `{"a":"{{.title}}"}`} {
		if _, err := ParseWebhookBody(ok); err != nil {
			t.Fatalf("%.40s: %v", ok, err)
		}
	}
	for name, tc := range map[string]struct {
		source string
		code   WebhookBodyCode
		path   string
	}{
		"duplicate key":          {`{"a":1,"b":2,"a":3}`, WebhookBodyDuplicateKey, "$.a"},
		"nested duplicate":       {`{"a":{"x":1,"x":"{{.title}}"}}`, WebhookBodyDuplicateKey, "$.a.x"},
		"too deep":               {deep, WebhookBodyTooDeep, "$.a[0][0][0][0][0][0][0]"},
		"too many leaves":        {manyLeaves, WebhookBodyTooManyLeaves, "$.a[256]"},
		"too large":              {large, WebhookBodyTooLarge, ""},
		"expression key":         {`{"{{.title}}":1}`, WebhookBodyExpressionInKey, `$["{{.title}}"]`},
		"expression bare value":  {`{"a":{{.count}}}`, WebhookBodyExpressionOutside, ""},
		"expression bare item":   {"{\n  \"a\": [1, {{.count}}]\n}", WebhookBodyExpressionOutside, ""},
		"expression top level":   {`{{.title}}`, WebhookBodyExpressionOutside, ""},
		"array top level":        {`["{{.title}}"]`, WebhookBodyNotObject, "$"},
		"string top level":       {`"{{.title}}"`, WebhookBodyNotObject, "$"},
		"trailing object":        {`{"a":1}{"b":2}`, WebhookBodyTrailingData, ""},
		"trailing garbage":       {`{"a":1} x`, WebhookBodyTrailingData, ""},
		"syntax":                 {`{"a":1,}`, WebhookBodyInvalidJSON, ""},
		"unterminated":           {`{"a":"x`, WebhookBodyInvalidJSON, ""},
		"invalid utf8":           {"{\"a\":\"\xff\"}", WebhookBodyInvalidEncoding, ""},
		"single quotes":          {`{'a':1}`, WebhookBodyInvalidJSON, ""},
		"escaped quote in value": {`{"a":"\"{{.title}}\"","a":1}`, WebhookBodyDuplicateKey, "$.a"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseWebhookBody(tc.source)
			var bodyErr *WebhookBodyError
			if !errors.As(err, &bodyErr) || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v", err)
			}
			if bodyErr.Code != tc.code || (tc.path != "" && bodyErr.Path != tc.path) {
				t.Fatalf("err = %+v, want code %s path %s", bodyErr, tc.code, tc.path)
			}
		})
	}
	// The position of a bare expression is reported.
	_, err := ParseWebhookBody("{\n  \"a\": [1, {{.count}}]\n}")
	var bodyErr *WebhookBodyError
	if !errors.As(err, &bodyErr) || bodyErr.Line != 2 || bodyErr.Column != 12 {
		t.Fatalf("position = %+v", bodyErr)
	}
	// Errors never quote a value.
	_, err = ParseWebhookBody(`{"a":"secret-value","a":1}`)
	if err == nil || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("err = %v", err)
	}
}

func TestWebhookBodyCompileRejectsUnknownVariables(t *testing.T) {
	body, err := ParseWebhookBody(`{"ok":"{{.title}}","list":["x","{{.password}}"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := body.Expressions(); !reflect.DeepEqual(got, []WebhookBodyExpression{{"$.ok", "{{.title}}"}, {"$.list[1]", "{{.password}}"}}) {
		t.Fatalf("expressions = %+v", got)
	}
	_, err = CompileWebhookBody(body, webhookSchema(t))
	var compileErr *WebhookBodyCompileError
	var engineErr *msgtemplate.Error
	if !errors.As(err, &compileErr) || compileErr.Path != "$.list[1]" || !errors.As(err, &engineErr) || engineErr.Code != msgtemplate.CodeUnknownVariable {
		t.Fatalf("err = %v", err)
	}
}

func TestWebhookBodyPaths(t *testing.T) {
	for key, want := range map[string]string{"a": "$.a", "a_1": "$.a_1", "1a": `$["1a"]`, "a b": `$["a b"]`, "": `$[""]`, `x"y`: `$["x\"y"]`} {
		if got := childPath("$", key); got != want {
			t.Errorf("childPath(%q) = %s, want %s", key, got, want)
		}
	}
	if got := childPath("$", strings.Repeat("é", 100)); !strings.HasSuffix(got, `…"]`) || len(got) > 80 {
		t.Errorf("long key path = %s", got)
	}
}

func TestUnescapeMarkdown(t *testing.T) {
	for in, want := range map[string]string{`a\*b`: `a*b`, `\\`: `\`, `a\b`: `a\b`, `end\`: `end\`, `\{\}`: `{}`, "plain": "plain"} {
		if got := unescapeMarkdown(in); got != want {
			t.Errorf("unescapeMarkdown(%q) = %q, want %q", in, got, want)
		}
	}
}
