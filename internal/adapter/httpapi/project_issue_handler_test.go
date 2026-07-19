package httpapi

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestProjectIssueListParams(t *testing.T) {
	t.Run("valid facets", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/?lens=new-code&status=accepted&type=bug&severity=high&rule=r1&language=Go&path=cmd&new_code=true&search=x&limit=10", nil)
		f, err := projectIssueListParams(r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f.Status == nil || *f.Status != "accepted" {
			t.Errorf("status not parsed: %+v", f.Status)
		}
		if f.Type == nil || *f.Type != rule.TypeBug {
			t.Errorf("type not parsed: %+v", f.Type)
		}
		if f.RuleKey != "r1" || f.Language != "Go" || f.PathPrefix != "cmd" || !f.NewCodeOnly || f.Limit != 10 {
			t.Errorf("facets not parsed: %+v", f)
		}
	})

	cases := []struct{ name, query string }{
		{"unknown param", "/?bogus=1"},
		{"invalid status", "/?status=weird"},
		{"invalid type", "/?type=weird"},
		{"invalid severity", "/?severity=weird"},
		{"invalid lens", "/?lens=weird"},
		{"limit too high", "/?limit=500"},
		{"limit non-numeric", "/?limit=abc"},
		{"cursor unpaired", "/?before_id=x"},
		{"cursor bad time", "/?before_last_seen_at=nope&before_id=x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := projectIssueListParams(httptest.NewRequest("GET", c.query, nil))
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}
