package confluence

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestObservedRestrictionLossIsTypedAndTransportIsNot(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       int
		moved, extra bool
		want         string
		lost         bool
	}{
		{"moved", 200, true, false, "wrong_container", true},
		{"identity_changed", 200, false, false, "remote_identity_changed", true},
		{"extra_reader", 200, false, true, "restriction_unverified", true},
		{"credential_refusal", 403, false, false, "unauthorized", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			main := transport(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/content/1") {
					if tc.status != 200 {
						return response(tc.status, `{}`), nil
					}
					body := content("1", "Stored report", "<p>body</p>", 1)
					if tc.name == "identity_changed" {
						body = content("2", "Stored report", "<p>body</p>", 1)
					}
					if tc.moved {
						body = strings.ReplaceAll(body, `"key":"SIL"`, `"key":"FOREIGN"`)
					}
					return response(200, body), nil
				}
				if strings.Contains(r.URL.Path, "/restriction/") {
					op := "read"
					if strings.HasSuffix(r.URL.Path, "/update") {
						op = "update"
					}
					group := "synapse-readers"
					if tc.extra {
						group = "other-readers"
					}
					return response(200, exactRestriction(op, group, false)), nil
				}
				t.Fatalf("unexpected request %s", r.URL.Path)
				return nil, nil
			})
			a := testAdapter(t, false, main, nil)
			got := providerCode(t, a.VerifyDocumentRestriction(context.Background(), "1", "SIL", "synapse-readers"))
			if got.Code != tc.want || got.RestrictionLost != tc.lost || got.Ambiguous {
				t.Fatalf("refusal=%+v wantcode=%s loss=%t", got, tc.want, tc.lost)
			}
		})
	}
}

func TestIncompleteRestrictionProofDoesNotClaimObservedLoss(t *testing.T) {
	for _, proof := range []string{`{}`, `{"operation":"read","restrictions":{"user":{"size":0,"results":[]},"group":{"size":1,"results":[{}]}}}`, `{"operation":"read","restrictions":{"user":{"size":0,"results":[]},"group":{"size":1,"results":[{"name":"other-readers"}],"_links":{"next":"more"}}}}`} {
		a := testAdapter(t, false, transport(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/content/1") {
				return response(200, content("1", "Stored report", "<p>body</p>", 1)), nil
			}
			if strings.Contains(r.URL.Path, "/restriction/") {
				return response(200, proof), nil
			}
			t.Fatalf("unexpected request %s", r.URL.Path)
			return nil, nil
		}), nil)
		got := providerCode(t, a.VerifyDocumentRestriction(context.Background(), "1", "SIL", "synapse-readers"))
		if got.RestrictionLost || got.Ambiguous {
			t.Fatalf("incomplete proof claimed loss: %+v", got)
		}
	}
}

func TestCloudRestrictionLossRequiresCompleteCurrentObservation(t *testing.T) {
	for _, tc := range []struct {
		name, state, permissions string
		lost                     bool
	}{
		{"read_not_restricted", `{"state":"EDIT_RESTRICTED"}`, `{}`, true},
		{"state_missing", `{}`, `{}`, false},
		{"extra_reader", `{"state":"VIEW_RESTRICTED"}`, `{"results":[{"operation":"read","principal":{"principalType":"user","principalId":"extra-reader"}}],"_links":{}}`, true},
		{"missing_identity", `{"state":"VIEW_RESTRICTED"}`, `{"results":[{"operation":"read","principal":{"principalType":"group"}}],"_links":{}}`, false},
		{"incomplete_list", `{"state":"VIEW_RESTRICTED"}`, `{"results":[],"_links":{"next":"more"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := testAdapterWithCloudV2(t, true, nil, nil, transport(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/restriction-state") {
					return response(200, tc.state), nil
				}
				return response(200, tc.permissions), nil
			}))
			got := providerCode(t, a.verifyCloudV2Restriction(context.Background(), "1", "synapse-readers"))
			if got.RestrictionLost != tc.lost || got.Ambiguous {
				t.Fatalf("classification=%+v wantloss=%t", got, tc.lost)
			}
		})
	}
}
