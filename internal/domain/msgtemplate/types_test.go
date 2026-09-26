package msgtemplate

import (
	"errors"
	"testing"
)

func TestCompileChecksArgumentTypes(t *testing.T) {
	for source, code := range map[string]Code{
		`{{upper (count .items)}}`:                CodeArgumentType,
		`{{.title | truncate "x"}}`:               CodeArgumentType,
		`{{.title | truncate 1.5}}`:               CodeArgumentType,
		`{{default "x" (count .items)}}`:          CodeArgumentType,
		`{{eq .title 1}}`:                         CodeArgumentType,
		`{{ne (count .items) "1"}}`:               CodeArgumentType,
		`{{eq (or .title 1) "x"}}`:                CodeArgumentType,
		`{{upper (and .title 1)}}`:                CodeArgumentType,
		`{{plural true "a" "b"}}`:                 CodeArgumentType,
		`{{with count .items}}{{upper .}}{{end}}`: CodeArgumentType,
		`{{not .items}}`:                          CodeListMisuse,
		`{{and .items .title}}`:                   CodeListMisuse,
	} {
		_, err := Compile("test", source, testSchema())
		var tmplErr *Error
		if !errors.As(err, &tmplErr) || tmplErr.Code != code {
			t.Fatalf("Compile(%s) error = %v, want %s", source, err, code)
		}
	}
	data := Data{Vars: map[string]string{"title": "t", "summary": "s"}, Lists: map[string][]map[string]string{"items": {{"title": "a"}}}}
	for source, want := range map[string]string{
		`{{upper (or .owner .title)}}`:          "T",
		`{{with count .items}}{{.}} new{{end}}`: "1 new",
		`{{if eq (count .items) 1}}one{{end}}`:  "one",
		`{{plural 2 "a" "b"}}`:                  "b",
		`{{and .title .summary}}`:               "s",
	} {
		if got := render(t, source, data); got != want {
			t.Fatalf("%s rendered %q, want %q", source, got, want)
		}
	}
}

func TestFuncSpecCheck(t *testing.T) {
	list := value{kind: kList, list: "items"}
	cases := []struct {
		name   string
		fn     string
		args   []value
		result kind
		code   Code
	}{
		{"exact arity", "upper", []value{stringValue}, kString, ""},
		{"too few", "truncate", []value{stringValue}, 0, CodeWrongArgumentCount},
		{"too many", "upper", []value{stringValue, stringValue}, 0, CodeWrongArgumentCount},
		{"variadic", "eq", []value{stringValue, stringValue, stringValue}, kBool, ""},
		{"wrong scalar", "truncate", []value{stringValue, stringValue}, 0, CodeArgumentType},
		{"list where scalar", "upper", []value{list}, 0, CodeListMisuse},
		{"scalar where list", "count", []value{stringValue}, 0, CodeListMisuse},
		{"list parameter", "count", []value{list}, kInt, ""},
		{"accepted union", "plural", []value{stringValue, stringValue, stringValue}, kString, ""},
		{"mixed comparison", "eq", []value{stringValue, intValue}, 0, CodeArgumentType},
		{"union comparison", "ne", []value{{kind: kString | kInt}, stringValue}, 0, CodeArgumentType},
		{"and returns union", "and", []value{stringValue, intValue}, kString | kInt, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, code, ok := funcSpecs[tc.fn].check(tc.args)
			if ok != (tc.code == "") || code != tc.code || (ok && result.kind != tc.result) {
				t.Fatalf("check = %v, %q, %v; want kind %v, code %q", result, code, ok, tc.result, tc.code)
			}
		})
	}
}

func TestEveryAllowlistedFunctionIsImplemented(t *testing.T) {
	builtins := map[string]bool{"eq": true, "ne": true, "and": true, "or": true, "not": true}
	funcs := funcMap()
	for name := range funcSpecs {
		if _, ok := funcs[name]; !ok && !builtins[name] {
			t.Errorf("%s is allowlisted but not implemented", name)
		}
	}
	for name := range funcs {
		if _, ok := funcSpecs[name]; !ok && name != escapeFunc {
			t.Errorf("%s is implemented but not allowlisted", name)
		}
	}
}
