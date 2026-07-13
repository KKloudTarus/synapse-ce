package httpapi

import (
	"context"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/rules"
)

type rulesService interface {
	List(context.Context, rules.Filter) ([]rule.Rule, error)
	Get(context.Context, rule.Key) (rule.Rule, error)
}

type ruleSummaryView struct {
	Key               string   `json:"key"`
	Name              string   `json:"name"`
	Language          string   `json:"language"`
	Type              string   `json:"type"`
	Qualities         []string `json:"qualities"`
	DefaultSeverity   string   `json:"default_severity"`
	Tags              []string `json:"tags"`
	CWE               []string `json:"cwe"`
	OWASP             []string `json:"owasp"`
	Description       string   `json:"description"`
	RemediationEffort int      `json:"remediation_effort"`
	Detection         string   `json:"detection"`
}

type ruleDetailView struct {
	Key                 string   `json:"key"`
	Name                string   `json:"name"`
	Language            string   `json:"language"`
	Type                string   `json:"type"`
	Qualities           []string `json:"qualities"`
	DefaultSeverity     string   `json:"default_severity"`
	Tags                []string `json:"tags"`
	CWE                 []string `json:"cwe"`
	OWASP               []string `json:"owasp"`
	Description         string   `json:"description"`
	Rationale           string   `json:"rationale"`
	Remediation         string   `json:"remediation"`
	CompliantExample    string   `json:"compliant_example"`
	NoncompliantExample string   `json:"noncompliant_example"`
	RemediationEffort   int      `json:"remediation_effort"`
	Detection           string   `json:"detection"`
}

func toRuleSummary(r rule.Rule) ruleSummaryView {
	return ruleSummaryView{
		Key:               string(r.Key),
		Name:              r.Name,
		Language:          r.Language,
		Type:              string(r.Type),
		Qualities:         qualitiesToStrings(r.Qualities),
		DefaultSeverity:   string(r.DefaultSeverity),
		Tags:              stringsOrDefault(r.Tags),
		CWE:               stringsOrDefault(r.CWE),
		OWASP:             stringsOrDefault(r.OWASP),
		Description:       r.Description,
		RemediationEffort: r.RemediationEffort,
		Detection:         string(r.Detection),
	}
}

func toRuleDetail(r rule.Rule) ruleDetailView {
	return ruleDetailView{
		Key:                 string(r.Key),
		Name:                r.Name,
		Language:            r.Language,
		Type:                string(r.Type),
		Qualities:           qualitiesToStrings(r.Qualities),
		DefaultSeverity:     string(r.DefaultSeverity),
		Tags:                stringsOrDefault(r.Tags),
		CWE:                 stringsOrDefault(r.CWE),
		OWASP:               stringsOrDefault(r.OWASP),
		Description:         r.Description,
		Rationale:           r.Rationale,
		Remediation:         r.Remediation,
		CompliantExample:    r.CompliantExample,
		NoncompliantExample: r.NoncompliantExample,
		RemediationEffort:   r.RemediationEffort,
		Detection:           string(r.Detection),
	}
}

func qualitiesToStrings(q []rule.Quality) []string {
	if len(q) == 0 {
		return []string{}
	}
	s := make([]string, len(q))
	for i, v := range q {
		s[i] = string(v)
	}
	return s
}

func stringsOrDefault(s []string) []string {
	if len(s) == 0 {
		return []string{}
	}
	return append([]string(nil), s...)
}

func (rt *Router) listRules(w http.ResponseWriter, r *http.Request) {
	allowed := map[string]bool{
		"q":        true,
		"language": true,
		"type":     true,
		"severity": true,
		"tag":      true,
		"cwe":      true,
	}
	for k := range r.URL.Query() {
		if !allowed[k] {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "unsupported query parameter: " + k})
			return
		}
	}

	qParams := r.URL.Query()
	f, err := rules.NewFilter(
		qParams.Get("q"),
		qParams["language"],
		qParams["type"],
		qParams["severity"],
		qParams["tag"],
		qParams["cwe"],
	)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: err.Error()})
		return
	}

	res, err := rt.rules.List(r.Context(), f)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}

	views := make([]ruleSummaryView, len(res))
	for i, rl := range res {
		views[i] = toRuleSummary(rl)
	}
	if views == nil {
		views = []ruleSummaryView{}
	}

	writeJSON(w, http.StatusOK, views)
}

func (rt *Router) getRule(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "empty rule key"})
		return
	}

	res, err := rt.rules.Get(r.Context(), rule.Key(key))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}

	writeJSON(w, http.StatusOK, toRuleDetail(res))
}
