package jira

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTransitionTicketIncludesLiteralCommentForCloudAndDC(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		t.Run(map[bool]string{true: "cloud", false: "dc"}[cloud], func(t *testing.T) {
			calls := 0
			a := testAdapter(t, cloud, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/issue/SEC-9/transitions") {
					t.Fatalf("unexpected transition: %s %s", r.Method, r.URL.Path)
				}
				body, _ := io.ReadAll(r.Body)
				var envelope struct {
					Transition map[string]string `json:"transition"`
					Update     struct {
						Comment []struct {
							Add struct {
								Body json.RawMessage `json:"body"`
							} `json:"add"`
						} `json:"comment"`
					} `json:"update"`
				}
				if json.Unmarshal(body, &envelope) != nil || envelope.Transition["id"] != "31" || len(envelope.Update.Comment) != 1 {
					t.Fatalf("invalid transition body: %s", body)
				}
				comment := envelope.Update.Comment[0].Add.Body
				if !strings.Contains(string(comment), "Đã khắc phục") || strings.Contains(string(comment), `"type":"mention"`) {
					t.Fatalf("unsafe/missing comment: %s", comment)
				}
				if cloud != strings.HasPrefix(string(comment), "{") {
					t.Fatalf("wrong comment representation: %s", comment)
				}
				return response(204, "", nil), nil
			})
			if err := a.TransitionTicket(context.Background(), "SEC-9", "31", "Đã khắc phục [~admin] {panel}"); err != nil || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestTransitionTicketWithoutCommentUsesTransitionOnlyPayload(t *testing.T) {
	a := testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/issue/SEC-9/transitions") {
			t.Fatalf("unexpected transition: %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"update"`) || !strings.Contains(string(body), `"transition"`) {
			t.Fatalf("transition-only payload=%s", body)
		}
		return response(204, "", nil), nil
	})
	if err := a.TransitionTicket(context.Background(), "SEC-9", "31", ""); err != nil {
		t.Fatal(err)
	}
}

func TestCommentTicketUsesDedicatedEndpointAndVerifiesReceipt(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		t.Run(map[bool]string{true: "cloud", false: "dc"}[cloud], func(t *testing.T) {
			var formatted json.RawMessage
			a := testAdapter(t, cloud, func(r *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(r.Body)
				switch {
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issue/SEC-9/comment"):
					var request struct {
						Body json.RawMessage `json:"body"`
					}
					if json.Unmarshal(body, &request) != nil || len(request.Body) == 0 || !strings.Contains(string(request.Body), "synapse") {
						t.Fatalf("comment request=%s", body)
					}
					formatted = request.Body
					return response(201, `{"id":"10001"}`, nil), nil
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issue/SEC-9/comment/10001"):
					author := json.RawMessage(`{"name":"integration-dc"}`)
					if cloud {
						author = json.RawMessage(`{"accountId":"integration-cloud"}`)
					}
					out, err := json.Marshal(struct {
						ID     string          `json:"id"`
						Author json.RawMessage `json:"author"`
						Body   json.RawMessage `json:"body"`
					}{ID: "10001", Author: author, Body: formatted})
					if err != nil {
						t.Fatal(err)
					}
					return response(200, string(out), nil), nil
				default:
					t.Fatalf("unexpected comment request: %s %s", r.Method, r.URL.Path)
					return nil, nil
				}
			})
			author := "integration-dc"
			if cloud {
				author = "integration-cloud"
			}
			receipt, err := a.CommentTicket(context.Background(), "SEC-9", "Resolved [synapse-intent-item-1] [~admin]", author)
			if err != nil || receipt.ID != "10001" {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
		})
	}
}

func TestCommentTicketKeepsUnreadableReceiptUncertain(t *testing.T) {
	a := testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			return response(201, `{"id":"10001"}`, nil), nil
		}
		return response(404, `{}`, nil), nil
	})
	_, err := a.CommentTicket(context.Background(), "SEC-9", "Resolved [synapse-intent-item-1]", "integration-cloud")
	var classified *ports.TicketProviderError
	if !errors.As(err, &classified) || !classified.Ambiguous || classified.Status != http.StatusNotFound {
		t.Fatalf("receipt error=%v", err)
	}
}

func TestFindTicketCommentCloudUsesBoundedOffsetPagesAndExactProof(t *testing.T) {
	const expected = "Resolved [synapse-intent-item-1]"
	var a *Adapter
	a = testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/issue/SEC-9/comment") || r.URL.Query().Get("maxResults") != "50" {
			t.Fatalf("unexpected comment read: %s %s", r.Method, r.URL.String())
		}
		body, err := a.FormatTicketDescription(expected, nil)
		if err != nil {
			t.Fatal(err)
		}
		start := r.URL.Query().Get("startAt")
		result := map[string]any{"maxResults": 50, "total": 51}
		switch start {
		case "0":
			result["startAt"] = 0
			comments := make([]any, 0, 50)
			for n := range 50 {
				comments = append(comments, map[string]any{"id": fmt.Sprintf("%d", 10000+n), "author": map[string]any{"accountId": "other"}, "body": body})
			}
			result["comments"] = comments
		case "50":
			result["startAt"] = 50
			result["comments"] = []any{map[string]any{"id": "10050", "author": map[string]any{"accountId": "integration-cloud"}, "body": body}}
		default:
			t.Fatalf("unexpected offset %q", start)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		return response(200, string(raw), nil), nil
	})
	found, err := a.FindTicketComment(context.Background(), "SEC-9", expected, "synapse-intent-item-1", "integration-cloud")
	if err != nil || !found {
		t.Fatalf("found=%t err=%v", found, err)
	}
}

func TestFindTicketCommentRefusesCopiedMarkerDuplicateOrTruncatedHistory(t *testing.T) {
	for _, tc := range []struct {
		name      string
		kind      string
		wantErr   bool
		wantFound bool
	}{
		{"copied-marker", "copied", false, false},
		{"duplicate", "duplicate", true, false},
		{"truncated", "truncated", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const expected = "Resolved [synapse-intent-item-1]"
			var a *Adapter
			a = testAdapter(t, false, func(r *http.Request) (*http.Response, error) {
				if r.URL.Query().Get("startAt") != "0" {
					t.Fatalf("unexpected offset %s", r.URL.Query().Get("startAt"))
				}
				body := expected
				if tc.kind == "copied" {
					body = "different [synapse-intent-item-1]"
				}
				formatted, err := a.FormatTicketDescription(body, nil)
				if err != nil {
					t.Fatal(err)
				}
				comments, total := []any{}, 2
				if tc.kind != "truncated" {
					comments = append(comments, map[string]any{"id": "10001", "author": map[string]any{"name": "integration-dc"}, "body": formatted})
				}
				if tc.kind == "duplicate" {
					comments = append(comments, map[string]any{"id": "10002", "author": map[string]any{"name": "integration-dc"}, "body": formatted})
				}
				if tc.kind == "copied" {
					total = 1
				}
				raw, err := json.Marshal(map[string]any{"comments": comments, "maxResults": 50, "startAt": 0, "total": total})
				if err != nil {
					t.Fatal(err)
				}
				return response(200, string(raw), nil), nil
			})
			found, err := a.FindTicketComment(context.Background(), "SEC-9", expected, "synapse-intent-item-1", "integration-dc")
			if (err != nil) != tc.wantErr || found != tc.wantFound {
				t.Fatalf("found=%t err=%v", found, err)
			}
		})
	}
}

func TestFindTicketCommentRejectsInconsistentOffsetTotalsForCloudAndDC(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		for _, mode := range []string{"overrun", "offset-past-total"} {
			t.Run(fmt.Sprintf("cloud=%t/%s", cloud, mode), func(t *testing.T) {
				const expected = "Resolved [synapse-intent-item-1]"
				principal := "integration-dc"
				if cloud {
					principal = "integration-cloud"
				}
				var a *Adapter
				a = testAdapter(t, cloud, func(r *http.Request) (*http.Response, error) {
					body, err := a.FormatTicketDescription(expected, nil)
					if err != nil {
						t.Fatal(err)
					}
					author := map[string]any{"name": principal}
					if cloud {
						author = map[string]any{"accountId": principal}
					}
					start := r.URL.Query().Get("startAt")
					result := map[string]any{"maxResults": 50, "startAt": 0, "total": 0, "comments": []any{map[string]any{"id": "10001", "author": author, "body": body}}}
					if mode == "offset-past-total" {
						if start == "0" {
							result = map[string]any{"maxResults": 50, "startAt": 0, "total": 2, "comments": []any{map[string]any{"id": "10001", "author": author, "body": body}}}
						} else if start == "1" {
							result = map[string]any{"maxResults": 50, "startAt": 1, "total": 0, "comments": []any{}}
						} else {
							t.Fatalf("unexpected offset %s", start)
						}
					}
					raw, err := json.Marshal(result)
					if err != nil {
						t.Fatal(err)
					}
					return response(200, string(raw), nil), nil
				})
				found, err := a.FindTicketComment(context.Background(), "SEC-9", expected, "synapse-intent-item-1", principal)
				if err == nil || found {
					t.Fatalf("found=%t err=%v", found, err)
				}
			})
		}
	}
}

func TestTransitionRefusesSecretsAndRetainsUncertainWrites(t *testing.T) {
	a := testAdapter(t, false, func(*http.Request) (*http.Response, error) {
		t.Fatal("secret reached provider")
		return nil, nil
	})
	if err := a.TransitionTicket(context.Background(), "SEC-1", "31", "secret-token"); err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("secret result: %v", err)
	}
	a = testAdapter(t, true, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("secret-token lost acknowledgement")
	})
	err := a.TransitionTicket(context.Background(), "SEC-1", "31", "Resolved")
	var classified *ports.TicketProviderError
	if !errors.As(err, &classified) || !classified.Ambiguous || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("lost acknowledgement: %v", err)
	}
}

func TestGetTicketUsesStatusCategoryAndNeverResolutionAsState(t *testing.T) {
	for _, tc := range []struct{ category, resolution string }{
		{"new", `{"name":"Fixed"}`},
		{"indeterminate", `{"name":"Unresolved"}`},
		{"done", "null"},
	} {
		t.Run(tc.category, func(t *testing.T) {
			a := testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Query().Get("fields") != "status,updated,resolution,created,creator" || r.URL.Query().Get("expand") != "changelog" {
					t.Fatal("unexpected read")
				}
				return response(200, `{"key":"SEC-1","fields":{"updated":"2026-10-17T11:11:11.123+0700","status":{"statusCategory":{"key":"`+tc.category+`"}},"resolution":`+tc.resolution+`}}`, nil), nil
			})
			observation, err := a.GetTicket(context.Background(), "SEC-1")
			if err != nil || observation.StatusCategory != tc.category || observation.UpdatedAt.IsZero() || observation.Deleted {
				t.Fatalf("observation=%+v err=%v", observation, err)
			}
		})
	}
}

func TestGetTicketMarks404AndRejectsMalformedOrUnsafeFacts(t *testing.T) {
	for _, tc := range []struct {
		status  int
		body    string
		deleted bool
		wantErr bool
	}{
		{404, `{}`, true, false},
		{403, `{}`, false, true},
		{200, `{"key":"OTHER-1"}`, false, true},
		{200, `{"key":"SEC-1","fields":{"updated":"2026-10-17T00:00:00Z","status":{"statusCategory":{"key":"resolved"}}}}`, false, true},
		{200, `{"key":"SEC-1","fields":{"updated":"bad","status":{"statusCategory":{"key":"done"}}}}`, false, true},
		{200, `{"key":"SEC-1","fields":{"updated":"2026-10-17T00:00:00Z","status":{"statusCategory":{"key":"done"}},"resolution":{"name":"secret-token"}}}`, false, true},
	} {
		a := testAdapter(t, false, func(*http.Request) (*http.Response, error) { return response(tc.status, tc.body, nil), nil })
		got, err := a.GetTicket(context.Background(), "SEC-1")
		if (err != nil) != tc.wantErr || got.Deleted != tc.deleted || err != nil && strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("observation=%+v err=%v", got, err)
		}
	}
}

func TestGetTicketAttributesStatusChangeInsteadOfLatestComment(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		a := testAdapter(t, cloud, func(r *http.Request) (*http.Response, error) {
			return response(200, `{"key":"SEC-1","fields":{"updated":"2026-10-17T10:00:00Z","status":{"id":"100","statusCategory":{"key":"done"}}},"changelog":{"total":300,"histories":[{"created":"2026-10-17T10:00:00Z","author":{"accountId":"human-commenter","name":"human-commenter"},"items":[{"field":"comment"}]},{"created":"2026-10-17T09:00:00Z","author":{"accountId":"integration-cloud","name":"integration-dc"},"items":[{"fieldId":"status","to":"100"}]}]}}`, nil), nil
		})
		out, err := a.GetTicket(context.Background(), "SEC-1")
		want := "integration-dc"
		if cloud {
			want = "integration-cloud"
		}
		if err != nil || out.AuthorID != want || out.StatusChangedAt.Format("15:04") != "09:00" {
			t.Fatalf("observation=%+v err=%v", out, err)
		}
	}
}

func TestGetTicketDefersUnknownOrAmbiguousStatusAuthor(t *testing.T) {
	for _, history := range []string{
		`{"total":300,"histories":[{"created":"2026-10-17T10:00:00Z","author":{"accountId":"commenter"},"items":[{"field":"comment"}]}]}`,
		`{"total":1,"histories":[{"created":"2026-10-17T09:00:00Z","author":{"accountId":"user"},"items":[{"field":"status","to":"different-status"}]}]}`,
		`{"total":2,"histories":[{"created":"bad","author":{"accountId":"user"},"items":[{"field":"status","to":"100"}]},{"created":"2026-10-17T09:00:00Z","author":{"accountId":"older"},"items":[{"field":"status","to":"100"}]}]}`,
	} {
		a := testAdapter(t, true, func(*http.Request) (*http.Response, error) {
			return response(200, `{"key":"SEC-1","fields":{"updated":"2026-10-17T10:00:00Z","status":{"id":"100","statusCategory":{"key":"done"}}},"changelog":`+history+`}`, nil), nil
		})
		out, err := a.GetTicket(context.Background(), "SEC-1")
		if err != nil || out.AuthorID != "" || out.StatusCategory != "done" {
			t.Fatalf("observation=%+v err=%v", out, err)
		}
	}
}

func TestGetTicketUsesCreatorOnlyWhenNoHistoryExists(t *testing.T) {
	a := testAdapter(t, true, func(*http.Request) (*http.Response, error) {
		return response(200, `{"key":"SEC-1","fields":{"created":"2026-10-17T09:00:00Z","updated":"2026-10-17T09:00:00Z","creator":{"accountId":"integration"},"status":{"id":"100","statusCategory":{"key":"done"}}},"changelog":{"total":0,"histories":[]}}`, nil), nil
	})
	out, err := a.GetTicket(context.Background(), "SEC-1")
	if err != nil || out.AuthorID != "integration" || out.StatusChangedAt.IsZero() {
		t.Fatalf("observation=%+v err=%v", out, err)
	}
}
