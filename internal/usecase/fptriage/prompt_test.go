package fptriage

import (
	"encoding/json"
	"testing"
)

// unsupportedStrictKeywords are JSON Schema keywords that OpenAI structured outputs reject in
// strict mode. Sending any of them makes the provider answer 400 invalid_json_schema, which the
// triage telemetry records as a provider error - so a schema regression looks like a flaky
// gateway rather than a malformed request. "uniqueItems" caused exactly that: every
// evidence-backed critique failed with
// "Invalid schema for response_format 'evidence_critique': ... 'uniqueItems' is not permitted".
var unsupportedStrictKeywords = []string{"uniqueItems", "patternProperties", "not", "if", "then", "else"}

// TestCritiqueSchemasAvoidUnsupportedStrictKeywords pins both response schemas against the strict
// structured-output subset. Constraints that cannot be expressed on the wire are enforced in code
// (duplicate citations by validateEvidenceCitations), never by a keyword the provider rejects.
func TestCritiqueSchemasAvoidUnsupportedStrictKeywords(t *testing.T) {
	for _, tc := range []struct {
		name   string
		schema json.RawMessage
	}{
		{"critique", critiqueSchema},
		{"evidence_critique", evidenceCritiqueSchema},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(tc.schema, &doc); err != nil {
				t.Fatalf("schema is not valid JSON: %v", err)
			}
			if strict, ok := doc["strict"].(bool); !ok || !strict {
				t.Errorf(`strict = %v, want true (structured outputs must be schema-constrained)`, doc["strict"])
			}
			for _, keyword := range unsupportedStrictKeywords {
				if found := findKey(doc, keyword); found {
					t.Errorf("schema uses %q, which strict structured outputs reject with 400 invalid_json_schema", keyword)
				}
			}
		})
	}
}

// TestEvidenceCritiqueSchemaKeepsCitationConstraints guards the other half of the contract: dropping
// uniqueItems must not quietly drop the bounds and token shape that keep citations parseable.
func TestEvidenceCritiqueSchemaKeepsCitationConstraints(t *testing.T) {
	var doc struct {
		Schema struct {
			Properties struct {
				EvidenceTokens struct {
					Type     string `json:"type"`
					MinItems *int   `json:"minItems"`
					MaxItems *int   `json:"maxItems"`
					Items    struct {
						Pattern string `json:"pattern"`
					} `json:"items"`
				} `json:"evidence_tokens"`
			} `json:"properties"`
		} `json:"schema"`
	}
	if err := json.Unmarshal(evidenceCritiqueSchema, &doc); err != nil {
		t.Fatalf("unmarshal evidence schema: %v", err)
	}
	tokens := doc.Schema.Properties.EvidenceTokens
	if tokens.Type != "array" {
		t.Errorf("evidence_tokens type = %q, want array", tokens.Type)
	}
	if tokens.MinItems == nil || *tokens.MinItems < 1 {
		t.Error("evidence_tokens must require at least one citation")
	}
	if tokens.MaxItems == nil || *tokens.MaxItems < 1 {
		t.Error("evidence_tokens must stay bounded by maxItems")
	}
	if tokens.Items.Pattern == "" {
		t.Error("evidence_tokens items must pin the ev: token pattern")
	}
}

// findKey reports whether key appears anywhere in the decoded schema tree.
func findKey(node any, key string) bool {
	switch typed := node.(type) {
	case map[string]any:
		for k, v := range typed {
			if k == key || findKey(v, key) {
				return true
			}
		}
	case []any:
		for _, v := range typed {
			if findKey(v, key) {
				return true
			}
		}
	}
	return false
}
