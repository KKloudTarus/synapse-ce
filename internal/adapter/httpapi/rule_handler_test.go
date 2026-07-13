package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/rules"
)

type fakeRulesService struct {
	listRes    []rule.Rule
	listErr    error
	getRes     rule.Rule
	getErr     error
	lastFilter rules.Filter
	lastKey    rule.Key
	listCalls  int
	getCalls   int
}

func (f *fakeRulesService) List(ctx context.Context, filter rules.Filter) ([]rule.Rule, error) {
	f.listCalls++
	f.lastFilter = filter
	return f.listRes, f.listErr
}

func (f *fakeRulesService) Get(ctx context.Context, key rule.Key) (rule.Rule, error) {
	f.getCalls++
	f.lastKey = key
	return f.getRes, f.getErr
}

func TestRouter_listRules(t *testing.T) {
	svc := &fakeRulesService{
		listRes: []rule.Rule{
			{Key: "r1", Language: "go", Tags: []string{"tag1"}},
		},
	}
	rt := &Router{rules: svc, log: discardLog()}

	callList := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		rt.listRules(w, req)
		return w
	}

	t.Run("success", func(t *testing.T) {
		w := callList("/api/v1/rules?language=go&language=python&type=bug")
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		if len(svc.lastFilter.Languages) != 2 {
			t.Errorf("expected parsed filter languages, got %v", svc.lastFilter.Languages)
		}

		var res []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0]["key"] != "r1" {
			t.Errorf("expected summary payload, got %v", res)
		}

		if res[0]["tags"] == nil {
			t.Errorf("expected non-null array")
		}
		if _, ok := res[0]["compliant_example"]; ok {
			t.Errorf("summary should not contain compliant_example")
		}
	})

	t.Run("unsupported query param", func(t *testing.T) {
		svc.listCalls = 0
		w := callList("/api/v1/rules?severty=high")
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for bad query param, got %d", w.Code)
		}
		if svc.listCalls != 0 {
			t.Errorf("expected 0 list calls, got %d", svc.listCalls)
		}
	})

	t.Run("service validation error", func(t *testing.T) {
		svc.listCalls = 0
		w := callList("/api/v1/rules?type=unknown")
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for bad type, got %d", w.Code)
		}
		if svc.listCalls != 0 {
			t.Errorf("expected 0 list calls, got %d", svc.listCalls)
		}
	})

	t.Run("combined params", func(t *testing.T) {
		svc.listCalls = 0
		w := callList("/api/v1/rules?severity=high&severity=critical&tag=security")
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		if len(svc.lastFilter.Severities) != 2 || len(svc.lastFilter.Tags) != 1 {
			t.Errorf("expected 2 severities and 1 tag, got %v and %v", svc.lastFilter.Severities, svc.lastFilter.Tags)
		}
	})

	t.Run("service internal error", func(t *testing.T) {
		svc.listErr = errors.New("boom")
		w := callList("/api/v1/rules")
		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", w.Code)
		}
		svc.listErr = nil
	})

	t.Run("empty list", func(t *testing.T) {
		svc.listRes = nil
		w := callList("/api/v1/rules")
		if w.Code != http.StatusOK || w.Body.String() != "[]\n" {
			t.Errorf("expected empty array, got %q", w.Body.String())
		}
	})
}

func TestRouter_getRule(t *testing.T) {
	svc := &fakeRulesService{
		getRes: rule.Rule{Key: "r1", CompliantExample: "example"},
	}
	rt := &Router{rules: svc, log: discardLog()}

	callGet := func(key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/"+key, nil)
		req.SetPathValue("key", key)
		w := httptest.NewRecorder()
		rt.getRule(w, req)
		return w
	}

	t.Run("success", func(t *testing.T) {
		w := callGet("go:sql")
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		if svc.lastKey != "go:sql" {
			t.Errorf("expected preserved key, got %s", svc.lastKey)
		}
		var res map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if res["compliant_example"] != "example" {
			t.Errorf("expected detail payload")
		}
		if res["tags"] == nil {
			t.Errorf("expected non-null array")
		}
		if _, ok := res["CompliantExample"]; ok {
			t.Errorf("should not contain PascalCase keys")
		}
	})

	t.Run("empty key", func(t *testing.T) {
		w := callGet("")
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("not found", func(t *testing.T) {
		svc.getErr = shared.ErrNotFound
		w := callGet("unknown")
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
		svc.getErr = nil
	})

	t.Run("service internal error", func(t *testing.T) {
		svc.getErr = errors.New("boom")
		w := callGet("go:sql")
		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", w.Code)
		}
		svc.getErr = nil
	})
}

func TestRealCatalogIntegration(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatal(err)
	}

	svc, err := rules.NewService(cat)
	if err != nil {
		t.Fatal(err)
	}

	rt := &Router{rules: svc, log: discardLog()}

	callList := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		rt.listRules(w, req)
		return w
	}

	callGet := func(key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/"+key, nil)
		req.SetPathValue("key", key)
		w := httptest.NewRecorder()
		rt.getRule(w, req)
		return w
	}

	t.Run("list all matches catalog count", func(t *testing.T) {
		w := callList("/api/v1/rules")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var res []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}

		all, err := cat.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != len(all) {
			t.Fatalf("expected %d rules, got %d", len(all), len(res))
		}

		// Check exact ordered key sets
		for i := 0; i < len(all); i++ {
			expectedKey := string(all[i].Key)
			actualKey := res[i]["key"].(string)
			if expectedKey != actualKey {
				t.Errorf("index %d: expected key %s, got %s", i, expectedKey, actualKey)
			}
		}

		// check sorting
		for i := 1; i < len(res); i++ {
			k1 := res[i-1]["key"].(string)
			k2 := res[i]["key"].(string)
			if k1 > k2 {
				t.Errorf("expected sorted keys, found %s > %s", k1, k2)
			}
		}
	})

	t.Run("filter returns subset", func(t *testing.T) {
		w := callList("/api/v1/rules?language=go")
		var res []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}

		if len(res) == 0 {
			t.Errorf("expected some go rules")
		}
		for _, r := range res {
			if strings.ToLower(r["language"].(string)) != "go" {
				t.Errorf("expected go rule, got %v", r["language"])
			}
		}
	})

	t.Run("get known key", func(t *testing.T) {
		all, err := cat.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		firstKey := string(all[0].Key)

		w := callGet(firstKey)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var res map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if res["key"] != firstKey {
			t.Errorf("expected key %s, got %v", firstKey, res["key"])
		}
		if res["description"] == "" {
			t.Errorf("expected description")
		}
	})

	t.Run("get unknown key", func(t *testing.T) {
		w := callGet("some-non-existent-rule-key-123")
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})
}
