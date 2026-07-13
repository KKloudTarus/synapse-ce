package rules_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/rules"
)

type fakeCatalog struct {
	rules     []rule.Rule
	err       error
	getCalls  int
	listCalls int
}

func (f *fakeCatalog) List(ctx context.Context) ([]rule.Rule, error) {
	f.listCalls++
	if f.err != nil {
		return nil, f.err
	}
	return f.rules, nil
}

func (f *fakeCatalog) Get(ctx context.Context, key rule.Key) (rule.Rule, error) {
	f.getCalls++
	if f.err != nil {
		return rule.Rule{}, f.err
	}
	for _, r := range f.rules {
		if r.Key == key {
			return r, nil
		}
	}
	return rule.Rule{}, shared.ErrNotFound
}

func TestNewFilter(t *testing.T) {
	cases := []struct {
		name       string
		query      string
		languages  []string
		types      []string
		severities []string
		tags       []string
		cwe        []string
		wantErr    bool
		check      func(t *testing.T, f rules.Filter)
	}{
		{
			name: "empty everything",
			check: func(t *testing.T, f rules.Filter) {
				if f.Query != "" || len(f.Languages) > 0 || len(f.Types) > 0 || len(f.Severities) > 0 || len(f.Tags) > 0 || len(f.CWE) > 0 {
					t.Errorf("expected empty filter, got %+v", f)
				}
			},
		},
		{
			name:  "whitespace query",
			query: "   \t\n",
			check: func(t *testing.T, f rules.Filter) {
				if f.Query != "" {
					t.Errorf("expected empty query, got %q", f.Query)
				}
			},
		},
		{
			name:      "language deduplication and lowercase internal preservation",
			languages: []string{"go", "GO", " Go "},
			check: func(t *testing.T, f rules.Filter) {
				if len(f.Languages) != 1 || strings.ToLower(f.Languages[0]) != "go" {
					t.Errorf("expected deduplicated 'go', got %v", f.Languages)
				}
			},
		},
		{
			name:  "valid types case-insensitive",
			types: []string{"BUG", "vulnerability ", "CoDe_SmeLL", "security_hotspot"},
			check: func(t *testing.T, f rules.Filter) {
				if len(f.Types) != 4 {
					t.Errorf("expected 4 types, got %v", f.Types)
				}
			},
		},
		{
			name:    "invalid type",
			types:   []string{"unknown"},
			wantErr: true,
		},
		{
			name:       "valid severities case-insensitive",
			severities: []string{"LOW", "medium ", "High", "Critical"},
			check: func(t *testing.T, f rules.Filter) {
				if len(f.Severities) != 4 {
					t.Errorf("expected 4 severities, got %v", f.Severities)
				}
			},
		},
		{
			name:       "invalid severity",
			severities: []string{"warning"},
			wantErr:    true,
		},
		{
			name: "cwe parsing and deduplication",
			cwe:  []string{"CWE-89", "cwe-89", "89", " 89 "},
			check: func(t *testing.T, f rules.Filter) {
				if len(f.CWE) != 1 || f.CWE[0] != "CWE-89" {
					t.Errorf("expected [CWE-89], got %v", f.CWE)
				}
			},
		},
		{name: "cwe missing number", cwe: []string{"CWE-"}, wantErr: true},
		{name: "cwe negative", cwe: []string{"-89"}, wantErr: true},
		{name: "cwe zero", cwe: []string{"0"}, wantErr: true},
		{name: "cwe decimal", cwe: []string{"89.0"}, wantErr: true},
		{name: "cwe letter", cwe: []string{"CWE-abc"}, wantErr: true},
		{
			name:  "boundary 256 query",
			query: strings.Repeat("a", 256),
		},
		{
			name:    "boundary 257 query",
			query:   strings.Repeat("a", 257),
			wantErr: true,
		},
		{
			name: "64 values exact",
			tags: make([]string, 32),
			cwe:  make([]string, 32),
			check: func(t *testing.T, f rules.Filter) {
			},
		},
	}

	// 64 values exact logic setup
	for i := 0; i < 32; i++ {
		cases[15].tags[i] = "tag"
		cases[15].cwe[i] = "89"
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := rules.NewFilter(tc.query, tc.languages, tc.types, tc.severities, tc.tags, tc.cwe)
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr %v, got %v", tc.wantErr, err)
			}
			if !tc.wantErr && tc.check != nil {
				tc.check(t, f)
			}
		})
	}
}

func TestNewFilter_Bounds(t *testing.T) {
	tags32 := make([]string, 32)
	for i := range tags32 {
		tags32[i] = "tag"
	}
	cwe32 := make([]string, 32)
	for i := range cwe32 {
		cwe32[i] = "89"
	}
	_, err := rules.NewFilter("", nil, nil, nil, tags32, cwe32)
	if err != nil {
		t.Errorf("64 total values should be allowed, got %v", err)
	}
}

// Test dimension bounds (max 32):
func TestNewFilter_DimensionBound(t *testing.T) {
	tags32 := make([]string, 32)
	for i := range tags32 {
		tags32[i] = "tag"
	}
	if _, err := rules.NewFilter("", nil, nil, nil, tags32, nil); err != nil {
		t.Errorf("32 tags should be permitted, got %v", err)
	}

	tags33 := make([]string, 33)
	for i := range tags33 {
		tags33[i] = "tag"
	}
	if _, err := rules.NewFilter("", nil, nil, nil, tags33, nil); err == nil {
		t.Error("33 tags should be rejected")
	}

	// Total filter values limit is 64.
	// 32 tags and 32 CWEs
	cwes32 := make([]string, 32)
	for i := range cwes32 {
		cwes32[i] = "1"
	}
	if _, err := rules.NewFilter("", nil, nil, nil, tags32, cwes32); err != nil {
		t.Errorf("64 total values should be permitted, got %v", err)
	}

	// 32 tags, 32 cwe, 1 language
	if _, err := rules.NewFilter("", []string{"go"}, nil, nil, tags32, cwes32); err == nil {
		t.Error("65 total values should be rejected")
	}
}

func TestService_List(t *testing.T) {
	ctx := context.Background()

	cat := &fakeCatalog{
		rules: []rule.Rule{
			{Key: "z-rule", Language: "python", Type: rule.TypeBug, DefaultSeverity: shared.SeverityLow, Tags: []string{"tag2"}, CWE: []string{"CWE-1"}},
			{Key: "a-rule", Language: "go", Type: rule.TypeVulnerability, DefaultSeverity: shared.SeverityHigh, Tags: []string{"tag1"}, CWE: []string{"CWE-89"}, Description: "has SQL"},
			{Key: "m-rule", Language: "go", Type: rule.TypeCodeSmell, DefaultSeverity: shared.SeverityMedium, Tags: []string{"tag1", "tag2"}, CWE: []string{"CWE-79"}},
		},
	}

	svc, err := rules.NewService(cat)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Unsorted input returns sorted output by key
	f, _ := rules.NewFilter("", nil, nil, nil, nil, nil)
	out, err := svc.List(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || string(out[0].Key) != "a-rule" || string(out[1].Key) != "m-rule" || string(out[2].Key) != "z-rule" {
		t.Errorf("expected ascending key sort, got %+v", out)
	}

	// 2. Filter OR semantics in dimension, AND semantics across
	f, _ = rules.NewFilter("", []string{"go"}, []string{"vulnerability", "code_smell"}, nil, []string{"tag1"}, nil)
	out, _ = svc.List(ctx, f)
	if len(out) != 2 || string(out[0].Key) != "a-rule" || string(out[1].Key) != "m-rule" {
		t.Errorf("expected a-rule and m-rule, got %+v", out)
	}

	// 3. CWE matching
	f, _ = rules.NewFilter("", nil, nil, nil, nil, []string{"89"})
	out, _ = svc.List(ctx, f)
	if len(out) != 1 || string(out[0].Key) != "a-rule" {
		t.Errorf("expected a-rule, got %+v", out)
	}

	// 4. Query text matching case-insensitive
	f, _ = rules.NewFilter("SQl", nil, nil, nil, nil, nil)
	out, _ = svc.List(ctx, f)
	if len(out) != 1 || string(out[0].Key) != "a-rule" {
		t.Errorf("expected a-rule, got %+v", out)
	}

	// 5. No match returns non-nil empty slice
	f, _ = rules.NewFilter("nomatch", nil, nil, nil, nil, nil)
	out, _ = svc.List(ctx, f)
	if out == nil || len(out) != 0 {
		t.Errorf("expected non-nil empty slice, got %v", out)
	}

	// 6. Source rules are cloned (slices)
	cat.rules[0].Tags[0] = "mutated" // change the original, should not affect previously returned
	// Verify we returned clones. Let's mutate the clone and see if source is affected
	f, _ = rules.NewFilter("", nil, nil, nil, nil, nil)
	out, _ = svc.List(ctx, f)
	out[0].Tags[0] = "mutated-clone"
	if cat.rules[1].Tags[0] == "mutated-clone" { // index 1 in source is index 0 in sorted
		t.Errorf("source catalog was mutated!")
	}
}

func TestService_Get(t *testing.T) {
	ctx := context.Background()

	cat := &fakeCatalog{
		rules: []rule.Rule{
			{Key: "go:sql-injection"},
			{Key: "a-rule", Tags: []string{"tag1"}},
		},
	}

	svc, err := rules.NewService(cat)
	if err != nil {
		t.Fatal(err)
	}

	// Exact match including colon
	r, err := svc.Get(ctx, rule.Key("go:sql-injection"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Key != "go:sql-injection" {
		t.Errorf("expected go:sql-injection, got %q", r.Key)
	}

	// Case-sensitive miss
	_, err = svc.Get(ctx, rule.Key("GO:SQL-INJECTION"))
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Empty key
	_, err = svc.Get(ctx, rule.Key(""))
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}

	// Slice cloning
	r2, _ := svc.Get(ctx, rule.Key("a-rule"))
	r2.Tags[0] = "mutated"
	if cat.rules[1].Tags[0] == "mutated" {
		t.Errorf("source catalog was mutated!")
	}
}

func TestNewService_NilDependency(t *testing.T) {
	_, err := rules.NewService(nil)
	if err == nil {
		t.Error("expected error for nil catalog")
	}
}

func TestServiceListCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cat := &fakeCatalog{}
	svc, _ := rules.NewService(cat)
	_, err := svc.List(ctx, rules.Filter{})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("expected context canceled, got %v", err)
	}

	if cat.listCalls != 0 {
		t.Fatalf("catalog.List called %d times", cat.listCalls)
	}
}

func TestServiceGetCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cat := &fakeCatalog{}
	svc, err := rules.NewService(cat)
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.Get(ctx, rule.Key("a-rule"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	if cat.getCalls != 0 {
		t.Fatalf("catalog.Get called %d times", cat.getCalls)
	}
}

func TestNewFilter_Advanced(t *testing.T) {
	cases := []struct {
		name       string
		languages  []string
		types      []string
		severities []string
		tags       []string
		cwe        []string
		wantErr    bool
	}{
		{name: "empty language value", languages: []string{""}, wantErr: true},
		{name: "empty type value", types: []string{""}, wantErr: true},
		{name: "empty severity value", severities: []string{""}, wantErr: true},
		{name: "empty tag value", tags: []string{""}, wantErr: true},
		{name: "boundary 128 language", languages: []string{strings.Repeat("a", 128)}, wantErr: false},
		{name: "boundary 129 language", languages: []string{strings.Repeat("a", 129)}, wantErr: true},
		{name: "CWE--89", cwe: []string{"CWE--89"}, wantErr: true},
		{name: "CWE-+89", cwe: []string{"CWE-+89"}, wantErr: true},
		{name: "  CWE-89", cwe: []string{"  CWE-89"}, wantErr: false}, // gets trimmed
		{name: "CWE-00089", cwe: []string{"CWE-00089"}, wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rules.NewFilter("", tc.languages, tc.types, tc.severities, tc.tags, tc.cwe)
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestService_List_Advanced(t *testing.T) {
	ctx := context.Background()
	cat := &fakeCatalog{
		rules: []rule.Rule{
			{
				Key: "a", Name: "name_match", Language: "go", Type: rule.TypeBug, DefaultSeverity: shared.SeverityLow,
				Description: "desc", Rationale: "rat", Remediation: "rem", Detection: rule.DetectionAST,
				Tags: []string{"tag1"}, CWE: []string{"CWE-1"}, OWASP: []string{"A1"}, Qualities: []rule.Quality{rule.QualitySecurity},
			},
			{Key: "b", CompliantExample: "match_but_ignored", NoncompliantExample: "match_but_ignored"},
		},
	}
	svc, _ := rules.NewService(cat)

	// Test search matches and non-matches
	f, _ := rules.NewFilter("name_match", nil, nil, nil, nil, nil)
	out, _ := svc.List(ctx, f)
	if len(out) != 1 {
		t.Errorf("expected match")
	}

	f, _ = rules.NewFilter("match_but_ignored", nil, nil, nil, nil, nil)
	out, _ = svc.List(ctx, f)
	if len(out) != 0 {
		t.Errorf("should not match examples")
	}

	// Test empty catalog
	catEmpty := &fakeCatalog{rules: []rule.Rule{}}
	svcEmpty, _ := rules.NewService(catEmpty)
	out, _ = svcEmpty.List(ctx, rules.Filter{})
	if out == nil {
		t.Errorf("expected non-nil empty slice")
	}

	// Test error propagation
	catErr := &fakeCatalog{err: errors.New("boom")}
	svcErr, _ := rules.NewService(catErr)
	_, err := svcErr.List(ctx, rules.Filter{})
	if err == nil || err.Error() != "boom" {
		t.Errorf("expected error propagation")
	}
}

func TestService_Get_Advanced(t *testing.T) {
	ctx := context.Background()
	cat := &fakeCatalog{
		rules: []rule.Rule{
			{Key: " go:rule "}, // whitespace
		},
	}
	svc, _ := rules.NewService(cat)

	// Exact case lookup with whitespace
	r, err := svc.Get(ctx, rule.Key(" go:rule "))
	if err != nil || r.Key != " go:rule " {
		t.Errorf("expected match")
	}

	// Error propagation
	catErr := &fakeCatalog{err: errors.New("boom")}
	svcErr, _ := rules.NewService(catErr)
	_, err = svcErr.Get(ctx, rule.Key("k"))
	if err == nil || err.Error() != "boom" {
		t.Errorf("expected error propagation")
	}
}
