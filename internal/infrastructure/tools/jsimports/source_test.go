package jsimports

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestObserveSourceImports(t *testing.T) {
	for _, tc := range []struct {
		name     string
		source   string
		jsx      bool
		want     []SourceImport
		complete bool
	}{
		{"static", "import http from 'node:http';", false, []SourceImport{{Specifier: "node:http"}}, true},
		{"dynamic", "const http = await import(\n/* client */ 'http');", false, []SourceImport{{Specifier: "http"}}, true},
		{"commonjs", "const http = require('http');", false, []SourceImport{{Specifier: "http"}}, true},
		{"erased type import", "import type { RequestOptions } from 'node:http';", false, []SourceImport{{Specifier: "node:http", TypeOnly: true}}, true},
		{"inline type still loads module", "import { type RequestOptions } from 'node:http';", false, []SourceImport{{Specifier: "node:http"}}, true},
		{"quoted import prose", `const docs = "import('node:http')";`, false, nil, true},
		{"commented import", "/* import http from 'node:http'; */", false, nil, true},
		{"computed loader", "const http = require(moduleName);", false, nil, false},
		{"jsx prose", "export const Help = () => <p>Data imported from the archive.</p>;", true, nil, true},
		{"jsx loader signature stays conservative", "export const Help = () => <p>import('node:http')</p>;", true, nil, false},
		{"invalid UTF8", string([]byte{0xff}), false, nil, false},
		{"oversized source", strings.Repeat(" ", int(defaultMaxFileBytes)+1), false, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, complete, err := ObserveSourceImports(context.Background(), []byte(tc.source), tc.jsx)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) == 0 {
				got = nil
			}
			if complete != tc.complete || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got imports=%+v complete=%v; want %+v, %v", got, complete, tc.want, tc.complete)
			}
		})
	}
}

func TestObserveSourceImportsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, complete, err := ObserveSourceImports(ctx, []byte("import 'http';"), false)
	if !errors.Is(err, context.Canceled) || complete {
		t.Fatalf("got complete=%v err=%v", complete, err)
	}
}

func TestObserveSourceImportsRequiresContext(t *testing.T) {
	if _, _, err := ObserveSourceImports(nil, nil, false); err == nil { //nolint:staticcheck // Verify invalid-context rejection.
		t.Fatal("nil context was accepted")
	}
}
