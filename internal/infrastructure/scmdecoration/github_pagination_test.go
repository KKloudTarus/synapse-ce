package scmdecoration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestGitHubFindCheckRunPaginatesByExternalID(t *testing.T) {
	decoration := testDecoration("summary")
	externalID := githubExternalID(decoration.Target)
	var pages []int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/repos/acme/widget/commits/head/check-runs" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("check_name") != githubCheckName || r.URL.Query().Get("filter") != "all" || r.URL.Query().Get("per_page") != "100" {
			http.Error(w, "unexpected query", http.StatusBadRequest)
			return
		}
		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil {
			http.Error(w, "missing page", http.StatusBadRequest)
			return
		}
		pages = append(pages, page)
		w.Header().Set("Content-Type", "application/json")

		response := githubCheckRuns{}
		switch page {
		case 1:
			response.CheckRuns = make([]githubCheckRun, 100)
			for i := range response.CheckRuns {
				response.CheckRuns[i] = githubCheckRun{
					ID:         int64(i + 1),
					Name:       githubCheckName,
					HeadSHA:    "head",
					ExternalID: "foreign-" + strconv.Itoa(i),
				}
			}
		case 2:
			response.CheckRuns = []githubCheckRun{{ID: 141, Name: githubCheckName, HeadSHA: "head", ExternalID: externalID}}
		default:
			http.Error(w, "unexpected page", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	decorator, err := newGitHubDecorator(server.Client(), server.URL, githubCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	run, err := decorator.findCheckRun(context.Background(), "acme/widget", "head", externalID, githubHeaders([]byte("token")))
	if err != nil {
		t.Fatal(err)
	}
	if run.ID != 141 {
		t.Fatalf("check run id = %d, want 141", run.ID)
	}
	if len(pages) != 2 || pages[0] != 1 || pages[1] != 2 {
		t.Fatalf("pages = %v, want [1 2]", pages)
	}
}

func TestGitHubPublishStatusPaginatesToOwnedContext(t *testing.T) {
	var pages []int
	posts := 0
	state, description := githubGateState(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/widget/statuses/head" && r.Method == http.MethodPost {
			posts++
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/repos/acme/widget/commits/head/statuses" || r.URL.Query().Get("per_page") != "100" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil {
			http.Error(w, "missing page", http.StatusBadRequest)
			return
		}
		pages = append(pages, page)
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case 1:
			statuses := make([]githubCommitStatus, 100)
			for i := range statuses {
				statuses[i] = githubCommitStatus{Context: "foreign-" + strconv.Itoa(i), State: "success"}
			}
			_ = json.NewEncoder(w).Encode(statuses)
		case 2:
			_ = json.NewEncoder(w).Encode([]githubCommitStatus{{Context: githubStatusContext, State: state, Description: description}})
		default:
			http.Error(w, "unexpected page", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	decorator, err := newGitHubDecorator(server.Client(), server.URL, githubCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := decorator.publishStatus(context.Background(), "acme/widget", testDecoration("summary"), githubHeaders([]byte("token"))); err != nil {
		t.Fatal(err)
	}
	if posts != 0 {
		t.Fatalf("status POSTs = %d, want 0 when the owned status is on page two", posts)
	}
	if len(pages) != 2 || pages[0] != 1 || pages[1] != 2 {
		t.Fatalf("pages = %v, want [1 2]", pages)
	}
}

func TestGitHubFindCommentPaginatesToOwnedMarker(t *testing.T) {
	var pages []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/repos/acme/widget/issues/7/comments" || r.URL.Query().Get("per_page") != "100" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil {
			http.Error(w, "missing page", http.StatusBadRequest)
			return
		}
		pages = append(pages, page)
		w.Header().Set("Content-Type", "application/json")

		var comments []githubIssueComment
		switch page {
		case 1:
			comments = make([]githubIssueComment, 100)
			for i := range comments {
				comments[i] = githubIssueComment{ID: int64(i + 1), Body: "unrelated comment"}
			}
		case 2:
			comments = []githubIssueComment{{ID: 151, Body: githubCommentMarker + "\n\nexisting summary"}}
		default:
			http.Error(w, "unexpected page", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(comments)
	}))
	defer server.Close()

	decorator, err := newGitHubDecorator(server.Client(), server.URL, githubCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	comment, err := decorator.findComment(context.Background(), "acme/widget", 7, githubHeaders([]byte("token")))
	if err != nil {
		t.Fatal(err)
	}
	if comment.ID != 151 {
		t.Fatalf("comment id = %d, want 151", comment.ID)
	}
	if len(pages) != 2 || pages[0] != 1 || pages[1] != 2 {
		t.Fatalf("pages = %v, want [1 2]", pages)
	}
}
