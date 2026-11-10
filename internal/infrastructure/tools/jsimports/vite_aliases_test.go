package jsimports

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestObserveViteAliases(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		want         []ViteAlias
		complete     bool
	}{
		{"direct", `export default { resolve: { alias: { '@': '/app/src', lib: '/app/lib' } } };`, []ViteAlias{{"@", "/app/src"}, {"lib", "/app/lib"}}, true},
		{"defineConfig", `import { defineConfig } from 'vite'; export default defineConfig({ resolve: { alias: { '@': '/app/src' } } });`, []ViteAlias{{"@", "/app/src"}}, true},
		{"renamed binding", "import { defineConfig as config } from 'vite'\nexport default config({resolve:{alias:{'@':'/app/src',},},});", []ViteAlias{{"@", "/app/src"}}, true},
		{"empty config", `export default {};`, nil, true},
		{"fake binding", `import { defineConfig } from 'other'; export default defineConfig({resolve:{alias:{'@':'/app/src'}}});`, nil, false},
		{"unbound call", `export default defineConfig({resolve:{alias:{'@':'/app/src'}}});`, nil, false},
		{"dynamic value", `export default {resolve:{alias:{'@':resolve('src')}}};`, nil, false},
		{"spread", `export default {...other, resolve:{alias:{'@':'/app/src'}}};`, nil, false},
		{"duplicate alias", `export default {resolve:{alias:{'@':'/app/src','@':'/app/server'}}};`, nil, false},
		{"duplicate resolve", `export default {resolve:{alias:{}},resolve:{alias:{}}};`, nil, false},
		{"computed key", `export default {resolve:{alias:{[name]:'/app/src'}}};`, nil, false},
		{"numeric ordering", `export default {resolve:{alias:{'1':'/app/src'}}};`, nil, false},
		{"prototype setter", `export default {resolve:{alias:{'__proto__':'/app/src'}}};`, nil, false},
		{"unsupported plugin", `export default {plugins:[plugin()],resolve:{alias:{}}};`, nil, false},
		{"trailing mutation", `export default {resolve:{alias:{'@':'/app/src'}}}; doSomething();`, nil, false},
		{"quoted example", `const example = "export default {resolve:{alias:{'@':'/app/src'}}}";`, nil, false},
		{"unterminated config", `export default {resolve:{alias:{'@':'/app/src'`, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, complete, err := ObserveViteAliases(context.Background(), []byte(tc.source))
			if err != nil || complete != tc.complete || complete && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("aliases=%+v complete=%v err=%v; want %+v complete=%v", got, complete, err, tc.want, tc.complete)
			}
		})
	}
}

func TestObserveViteAliasesBoundaries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := ObserveViteAliases(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
	if _, _, err := ObserveViteAliases(nil, nil); err == nil { //nolint:staticcheck // Verify invalid-context rejection.
		t.Fatal("nil context accepted")
	}
	for _, source := range [][]byte{[]byte(strings.Repeat(" ", int(defaultMaxFileBytes)+1)), {0xff}} {
		if _, complete, err := ObserveViteAliases(context.Background(), source); err != nil || complete {
			t.Fatalf("invalid source: complete=%v err=%v", complete, err)
		}
	}
}
