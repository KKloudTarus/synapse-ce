package confluence

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestLegacyXMLRPCRequestUsesSameOriginContextPathAndEscapesValues(t *testing.T) {
	adapter := testAdapter(t, false, transport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Path != "/confluence/rpc/xmlrpc" {
			t.Fatalf("request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/xml") {
			t.Fatalf("content type %q", got)
		}
		body := readBody(t, r)
		if strings.Contains(body, "<unsafe>") || !strings.Contains(body, "&lt;unsafe&gt;") {
			t.Fatalf("XML value was not escaped: %q", body)
		}
		return response(http.StatusOK, `<?xml version="1.0"?><methodResponse><params><param><value><boolean>1</boolean></value></param></params></methodResponse>`), nil
	}), nil)
	if _, err := adapter.legacyXMLRPCRequest(context.Background(), "confluence2.getUserGroups", []xmlRPCValue{xmlRPCString(""), xmlRPCString("<unsafe>")}, false); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyXMLRPCConfigurationIsExplicitAndDataCenterOnly(t *testing.T) {
	if err := dcDescriptor.ValidateConfig(map[string]any{"space": "SIL", "read_group": "synapse-readers", "data_class": "detail", "legacy_xmlrpc_restrictions": true}); err != nil {
		t.Fatal(err)
	}
	if err := dcDescriptor.ValidateConfig(map[string]any{"space": "SIL", "read_group": "synapse-readers", "data_class": "detail", "legacy_xmlrpc_restrictions": "true"}); err == nil {
		t.Fatal("accepted non-boolean legacy XML-RPC option")
	}
	if err := cloudDescriptor.ValidateConfig(map[string]any{"space": "SIL", "read_group": "synapse-readers", "data_class": "detail", "legacy_xmlrpc_restrictions": true}); err == nil {
		t.Fatal("accepted Cloud legacy XML-RPC option")
	}
}

func TestLegacyXMLRPCPreflightRequiresConfluence102AndMembership(t *testing.T) {
	for name, test := range map[string]struct {
		server string
		groups string
		want   string
	}{
		"accepted":           {server: xmlRPCServerInfo("10", "2"), groups: xmlRPCGroups("other", "synapse-readers")},
		"wrong-version":      {server: xmlRPCServerInfo("11", "2"), groups: xmlRPCGroups("synapse-readers"), want: "legacy_xmlrpc_unsupported"},
		"missing-membership": {server: xmlRPCServerInfo("10", "2"), groups: xmlRPCGroups("other"), want: "legacy_xmlrpc_unverified"},
	} {
		t.Run(name, func(t *testing.T) {
			adapter := newLegacyXMLRPCAdapter(t, transport(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/user/current"):
					return response(http.StatusOK, `{"username":"publisher"}`), nil
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rpc/xmlrpc"):
					switch xmlRPCMethod(t, r) {
					case "confluence2.getServerInfo":
						return response(http.StatusOK, test.server), nil
					case "confluence2.getUserGroups":
						return response(http.StatusOK, test.groups), nil
					}
				}
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
				return nil, nil
			}))
			err := adapter.legacyXMLRPCPreflight(context.Background(), "")
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if got := providerCode(t, err); got.Code != test.want {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestLegacyXMLRPCTestConnectionPerformsReadOnlyPreflight(t *testing.T) {
	calls := make([]string, 0, 4)
	adapter := newLegacyXMLRPCAdapter(t, transport(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/user/current"):
			calls = append(calls, "current")
			return response(http.StatusOK, `{"username":"publisher"}`), nil
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/space/SIL"):
			calls = append(calls, "space")
			return response(http.StatusOK, `{"key":"SIL"}`), nil
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rpc/xmlrpc"):
			method := xmlRPCMethod(t, r)
			calls = append(calls, method)
			switch method {
			case "confluence2.getServerInfo":
				return response(http.StatusOK, xmlRPCServerInfo("10", "2")), nil
			case "confluence2.getUserGroups":
				return response(http.StatusOK, xmlRPCGroups("synapse-readers")), nil
			}
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		return nil, nil
	}))
	if err := adapter.TestConnection(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != "current,space,confluence2.getServerInfo,confluence2.getUserGroups" {
		t.Fatalf("calls=%q", got)
	}
}

func TestParseXMLRPCResponseAcceptsUntypedServerVersions(t *testing.T) {
	value, err := parseXMLRPCResponse([]byte(xmlRPCServerInfo("10", "2")))
	if err != nil {
		t.Fatal(err)
	}
	if value.kind != xmlRPCStructKind || value.members["majorVersion"].text != "10" || value.members["minorVersion"].text != "2" {
		t.Fatalf("value=%+v", value)
	}
}

func TestLegacyXMLRPCRestrictionWritesViewThenEditAndIsIdempotent(t *testing.T) {
	storage := neutralShellStorage("synapse-intent-a")
	setOperations := make([]string, 0, 2)
	preflights := 0
	restricted := false
	adapter := newLegacyXMLRPCAdapter(t, transport(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/user/current"):
			return response(http.StatusOK, `{"username":"publisher"}`), nil
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/content/1"):
			return response(http.StatusOK, content("1", neutralShellTitle("synapse-intent-a"), storage, 1)), nil
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/restriction/byOperation/read"):
			if restricted {
				return response(http.StatusOK, exactRestriction("read", "synapse-readers", false)), nil
			}
			return response(http.StatusOK, emptyRestriction("read")), nil
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/restriction/byOperation/update"):
			return response(http.StatusOK, exactRestriction("update", "synapse-readers", false)), nil
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rpc/xmlrpc"):
			body := readBody(t, r)
			switch xmlRPCMethodFromBody(t, body) {
			case "confluence2.getServerInfo":
				preflights++
				return response(http.StatusOK, xmlRPCServerInfo("10", "2")), nil
			case "confluence2.getUserGroups":
				return response(http.StatusOK, xmlRPCGroups("synapse-readers")), nil
			case "confluence2.setContentPermissions":
				if !strings.Contains(body, "<i8>1</i8>") || strings.Contains(body, "<string>1</string>") {
					t.Fatalf("page ID was not encoded as i8: %s", body)
				}
				operation := xmlRPCSetOperation(t, body)
				setOperations = append(setOperations, operation)
				if operation == "Edit" {
					restricted = true
				}
				return response(http.StatusOK, xmlRPCBoolean(true)), nil
			}
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		return nil, nil
	}))
	if err := adapter.RestrictDocument(context.Background(), "1", "synapse-readers"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(setOperations, ","); got != "View,Edit" || preflights != 3 {
		t.Fatalf("operations=%q preflights=%d", got, preflights)
	}
	if err := adapter.RestrictDocument(context.Background(), "1", "synapse-readers"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(setOperations, ","); got != "View,Edit" {
		t.Fatalf("idempotent operations=%q", got)
	}
}

func TestLegacyXMLRPCSecondWriteFailureIsAmbiguousAndDoesNotFallback(t *testing.T) {
	storage := neutralShellStorage("synapse-intent-a")
	setCalls := 0
	adapter := newLegacyXMLRPCAdapter(t, transport(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/user/current"):
			return response(http.StatusOK, `{"username":"publisher"}`), nil
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/content/1"):
			return response(http.StatusOK, content("1", neutralShellTitle("synapse-intent-a"), storage, 1)), nil
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/restriction/byOperation/"):
			return response(http.StatusOK, emptyRestriction("read")), nil
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rpc/xmlrpc"):
			switch xmlRPCMethod(t, r) {
			case "confluence2.getServerInfo":
				return response(http.StatusOK, xmlRPCServerInfo("10", "2")), nil
			case "confluence2.getUserGroups":
				return response(http.StatusOK, xmlRPCGroups("synapse-readers")), nil
			case "confluence2.setContentPermissions":
				setCalls++
				if setCalls == 1 {
					return response(http.StatusOK, xmlRPCBoolean(true)), nil
				}
				return response(http.StatusOK, xmlRPCBoolean(false)), nil
			}
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		return nil, nil
	}))
	got := providerCode(t, adapter.RestrictDocument(context.Background(), "1", "synapse-readers"))
	if got.Code != "legacy_xmlrpc_invalid_response" || !got.Ambiguous || setCalls != 2 {
		t.Fatalf("error=%+v setCalls=%d", got, setCalls)
	}
}

func TestParseXMLRPCResponseRejectsFaultsAndUnsafeShapes(t *testing.T) {
	for _, body := range []string{
		`<methodResponse><fault><value><string>secret</string></value></fault></methodResponse>`,
		`<methodResponse><params><param><value><boolean>1</boolean></value></param><param><value><boolean>1</boolean></value></param></params></methodResponse>`,
		`<!DOCTYPE methodResponse><methodResponse><params><param><value><boolean>1</boolean></value></param></params></methodResponse>`,
		`<methodResponse><params><param><value><struct><member><name>x</name><value>1</value></member><member><name>x</name><value>2</value></member></struct></value></param></params></methodResponse>`,
	} {
		t.Run(body[:16], func(t *testing.T) {
			if _, err := parseXMLRPCResponse([]byte(body)); err == nil {
				t.Fatal("accepted unsafe XML-RPC response")
			}
		})
	}
}

func TestLegacyXMLRPCRequestClassifiesFaultsAndRefusalsWithoutLeakingBody(t *testing.T) {
	for name, test := range map[string]struct {
		status    int
		body      string
		code      string
		ambiguous bool
	}{
		"fault":   {status: http.StatusOK, body: `<methodResponse><fault><value><string>provider-secret</string></value></fault></methodResponse>`, code: "legacy_xmlrpc_invalid_response", ambiguous: true},
		"refusal": {status: http.StatusForbidden, body: "provider-secret", code: "unauthorized"},
	} {
		t.Run(name, func(t *testing.T) {
			adapter := newLegacyXMLRPCAdapter(t, transport(func(*http.Request) (*http.Response, error) {
				return response(test.status, test.body), nil
			}))
			_, err := adapter.legacyXMLRPCRequest(context.Background(), "confluence2.setContentPermissions", []xmlRPCValue{xmlRPCString(""), xmlRPCInteger(1), xmlRPCString("View"), xmlRPCValue{kind: xmlRPCArrayKind}}, true)
			got := providerCode(t, err)
			if got.Code != test.code || got.Ambiguous != test.ambiguous || strings.Contains(got.Error(), "provider-secret") {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestLegacyXMLRPCRejectsUnsupportedMethodArityAndPageOverflowBeforeHTTP(t *testing.T) {
	adapter := newLegacyXMLRPCAdapter(t, transport(func(*http.Request) (*http.Response, error) {
		t.Fatal("unexpected XML-RPC request")
		return nil, nil
	}))
	if _, err := adapter.legacyXMLRPCRequest(context.Background(), "confluence2.getUserGroups", []xmlRPCValue{xmlRPCString("")}, false); providerCode(t, err).Code != "invalid_request" {
		t.Fatalf("error=%v", err)
	}
	if got := providerCode(t, adapter.setLegacyXMLRPCPermissions(context.Background(), "99999999999999999999", "synapse-readers")); got.Code != "invalid_restriction" || got.Ambiguous {
		t.Fatalf("%+v", got)
	}
}

func TestParseXMLRPCResponseRejectsOversizedArraysAndHonorsContext(t *testing.T) {
	values := strings.Repeat("<value><string>group</string></value>", maxXMLRPCArrayValues+1)
	body := `<methodResponse><params><param><value><array><data>` + values + `</data></array></value></param></params></methodResponse>`
	if _, err := parseXMLRPCResponse([]byte(body)); err == nil {
		t.Fatal("accepted oversized XML-RPC array")
	}
	oversizedScalar := `<methodResponse><params><param><value><string>` + strings.Repeat("x", maxXMLRPCScalarBytes+1) + `</string></value></param></params></methodResponse>`
	if _, err := parseXMLRPCResponse([]byte(oversizedScalar)); err == nil {
		t.Fatal("accepted oversized XML-RPC scalar")
	}
	nested := `<value><string>leaf</string></value>`
	for range maxXMLRPCDepth + 1 {
		nested = `<value><array><data>` + nested + `</data></array></value>`
	}
	tooDeep := `<methodResponse><params><param>` + nested + `</param></params></methodResponse>`
	if _, err := parseXMLRPCResponse([]byte(tooDeep)); err == nil {
		t.Fatal("accepted overly nested XML-RPC response")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	adapter := newLegacyXMLRPCAdapter(t, transport(func(r *http.Request) (*http.Response, error) {
		return nil, r.Context().Err()
	}))
	if _, err := adapter.legacyXMLRPCRequest(ctx, "confluence2.getServerInfo", []xmlRPCValue{xmlRPCString("")}, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func newLegacyXMLRPCAdapter(t *testing.T, main transport) *Adapter {
	t.Helper()
	adapter := testAdapter(t, false, main, nil)
	adapter.legacyXMLRPC = true
	return adapter
}

func xmlRPCMethod(t *testing.T, request *http.Request) string {
	t.Helper()
	return xmlRPCMethodFromBody(t, readBody(t, request))
}

func xmlRPCMethodFromBody(t *testing.T, body string) string {
	t.Helper()
	const open, close = "<methodName>", "</methodName>"
	start := strings.Index(body, open)
	end := strings.Index(body, close)
	if start < 0 || end < start {
		t.Fatalf("missing method name: %s", body)
	}
	return body[start+len(open) : end]
}

func xmlRPCSetOperation(t *testing.T, body string) string {
	t.Helper()
	for _, operation := range []string{"View", "Edit"} {
		if strings.Contains(body, "<string>"+operation+"</string>") {
			return operation
		}
	}
	t.Fatalf("missing set operation: %s", body)
	return ""
}

func xmlRPCServerInfo(major, minor string) string {
	return `<?xml version="1.0"?><methodResponse><params><param><value><struct><member><name>majorVersion</name><value>` + major + `</value></member><member><name>minorVersion</name><value>` + minor + `</value></member></struct></value></param></params></methodResponse>`
}

func xmlRPCGroups(groups ...string) string {
	var values strings.Builder
	for _, group := range groups {
		values.WriteString("<value><string>")
		values.WriteString(group)
		values.WriteString("</string></value>")
	}
	return `<?xml version="1.0"?><methodResponse><params><param><value><array><data>` + values.String() + `</data></array></value></param></params></methodResponse>`
}

func xmlRPCBoolean(value bool) string {
	encoded := "0"
	if value {
		encoded = "1"
	}
	return `<?xml version="1.0"?><methodResponse><params><param><value><boolean>` + encoded + `</boolean></value></param></params></methodResponse>`
}

func readBody(t *testing.T, request *http.Request) string {
	t.Helper()
	value, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}
