package documentproviders

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int, value any) *http.Response {
	var data []byte
	if raw, ok := value.([]byte); ok {
		data = raw
	} else {
		data, _ = json.Marshal(value)
	}
	return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(data))}
}
func TestRestrictedDocumentProfilesAdvertiseRelease(t *testing.T) {
	registry := integration.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []integration.Provider{SharePoint, OneDrive, Drive} {
		descriptor, err := registry.Descriptor(provider)
		if err != nil || !descriptor.Supports(integration.CapabilityDocuments) {
			t.Fatalf("working restricted document profile unavailable: %s %v", provider, err)
		}
	}
}
func TestDocumentOriginsAndErrorsDoNotExposeCredentials(t *testing.T) {
	for _, endpoint := range []string{"https://evil.example", "https://www.googleapis.com/drive", "https://www.googleapis.com?token=private-fixture-token"} {
		if _, err := newDrive(integration.Integration{Provider: Drive, Endpoint: endpoint}, integration.CredentialBundle{"access_token": "private-fixture-token"}, selfhosted.Rules{}); err == nil {
			t.Fatalf("accepted origin %s", endpoint)
		}
	}
	request, _ := http.NewRequest("POST", "https://www.googleapis.com/drive/v2/files", nil)
	client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("https://user:private-fixture-token@invalid")
	})}
	_, _, err := readResponse(client, request, 100, 200)
	if err == nil || strings.Contains(err.Error(), "private-fixture-token") {
		t.Fatal("unsafe network error")
	}
	var p *ports.DocumentProviderError
	if !errors.As(err, &p) || !p.Ambiguous {
		t.Fatal("lost write must be ambiguous")
	}
}

func TestDocumentRateLimitPreservesBoundedRetryAfter(t *testing.T) {
	now := time.Date(2026, time.October, 20, 8, 0, 0, 0, time.UTC)
	for name, input := range map[string]struct {
		value string
		want  time.Duration
	}{
		"delta":     {value: "7", want: 7 * time.Second},
		"http date": {value: now.Add(2 * time.Minute).Format(http.TimeFormat), want: 2 * time.Minute},
		"past date": {value: now.Add(-time.Second).Format(http.TimeFormat), want: 0},
		"malformed": {value: "later", want: time.Minute},
		"overflow":  {value: "18446744073709551615", want: maxDocumentRetryAfter},
	} {
		t.Run(name, func(t *testing.T) {
			if got := documentRetryAfterAt(input.value, now); got != input.want {
				t.Fatalf("retry after %q = %s, want %s", input.value, got, input.want)
			}
		})
	}
	request, err := http.NewRequest(http.MethodPost, "https://www.googleapis.com/drive/v2/files", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		out := response(http.StatusTooManyRequests, nil)
		out.Header.Set("Retry-After", "7")
		return out, nil
	})}
	_, _, err = readResponse(client, request, 1024, http.StatusOK)
	var providerErr *ports.DocumentProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != "rate_limited" || providerErr.RetryAfter != 7*time.Second || providerErr.Ambiguous {
		t.Fatalf("rate limit classification = %#v, err=%v", providerErr, err)
	}
}

func TestDriveObservedRestrictionLossHasTypedMarker(t *testing.T) {
	t.Run("extra reader", func(t *testing.T) {
		a, f := newDriveFixture(t)
		f.extra = true
		err := a.CheckDocumentRelease(context.Background(), "parent", "group")
		var providerErr *ports.DocumentProviderError
		if !errors.As(err, &providerErr) || !providerErr.RestrictionLost || providerErr.Code != "restricted_sharing_unverified" {
			t.Fatalf("observed extra reader = %#v, err=%v", providerErr, err)
		}
	})
	t.Run("incomplete permissions", func(t *testing.T) {
		a, f := newDriveFixture(t)
		f.incomplete = true
		err := a.CheckDocumentRelease(context.Background(), "parent", "group")
		var providerErr *ports.DocumentProviderError
		if !errors.As(err, &providerErr) || providerErr.RestrictionLost || providerErr.Code != "incomplete_permissions" {
			t.Fatalf("incomplete proof = %#v, err=%v", providerErr, err)
		}
	})
	t.Run("moved publication", func(t *testing.T) {
		a, f := newDriveFixture(t)
		shell, err := a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
		if err != nil {
			t.Fatal(err)
		}
		f.files["folder"]["parents"] = []map[string]string{{"id": "other-parent"}}
		err = a.VerifyDocumentRestriction(context.Background(), shell.ID, "parent", "group")
		var providerErr *ports.DocumentProviderError
		if !errors.As(err, &providerErr) || !providerErr.RestrictionLost || providerErr.Code != "remote_identity_changed" {
			t.Fatalf("moved publication = %#v, err=%v", providerErr, err)
		}
	})
}

func TestDriveMalformedRestrictionProofDoesNotSignalLoss(t *testing.T) {
	for name, permission := range map[string]map[string]any{
		"missing type": {"id": "group", "role": "reader"},
		"invalid type": {"id": "group", "type": "robot", "role": "reader"},
		"missing role": {"id": "group", "type": "group"},
		"invalid role": {"id": "group", "type": "group", "role": "operator"},
	} {
		t.Run(name, func(t *testing.T) {
			a, f := newDriveFixture(t)
			f.permissionPages = map[string]map[string]any{"": {
				"items": []map[string]any{
					{"id": "owner", "type": "user", "role": "owner"},
					permission,
				},
			}}
			err := a.CheckDocumentRelease(context.Background(), "parent", "group")
			var providerErr *ports.DocumentProviderError
			if !errors.As(err, &providerErr) || providerErr.RestrictionLost || providerErr.Code != "complete_acl_unverifiable" {
				t.Fatalf("malformed permission = %#v, err=%v", providerErr, err)
			}
		})
	}
}

func TestDriveMissingACLAndShellIdentityProofDoesNotSignalLoss(t *testing.T) {
	for name, page := range map[string]map[string]any{
		"missing permission items": {},
		"null permission items":    {"items": nil},
	} {
		t.Run(name, func(t *testing.T) {
			a, f := newDriveFixture(t)
			f.permissionPages = map[string]map[string]any{"": page}
			err := a.CheckDocumentRelease(context.Background(), "parent", "group")
			assertDriveUnverifiable(t, err)
		})
	}
	for _, operation := range []struct {
		name string
		call func(*driveAdapter, string) error
	}{
		{"verify", func(a *driveAdapter, page string) error {
			return a.VerifyDocumentRestriction(context.Background(), page, "parent", "group")
		}},
		{"restricted read", func(a *driveAdapter, page string) error {
			_, err := a.ReadRestrictedDocument(context.Background(), page, "parent", "group")
			return err
		}},
	} {
		for name, mutate := range map[string]func(map[string]any){
			"missing MIME":         func(file map[string]any) { delete(file, "mimeType") },
			"null MIME":            func(file map[string]any) { file["mimeType"] = nil },
			"MIME without subtype": func(file map[string]any) { file["mimeType"] = "application" },
			"empty MIME":           func(file map[string]any) { file["mimeType"] = "" },
			"malformed MIME":       func(file map[string]any) { file["mimeType"] = "not a media type" },
			"missing parents":      func(file map[string]any) { delete(file, "parents") },
			"null parents":         func(file map[string]any) { file["parents"] = nil },
			"missing parent ID":    func(file map[string]any) { file["parents"] = []map[string]string{{}} },
			"invalid parent ID":    func(file map[string]any) { file["parents"] = []map[string]string{{"id": "not an ID"}} },
			"missing properties":   func(file map[string]any) { delete(file, "properties") },
			"null properties":      func(file map[string]any) { file["properties"] = nil },
		} {
			t.Run(operation.name+" "+name, func(t *testing.T) {
				a, f := newDriveFixture(t)
				shell, err := a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
				if err != nil {
					t.Fatal(err)
				}
				mutate(f.files["folder"])
				assertDriveUnverifiable(t, operation.call(a, shell.ID))
			})
		}
	}
}

func TestDriveCompleteShellIdentityMismatchSignalsLoss(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"empty parents": func(file map[string]any) { file["parents"] = []map[string]string{} },
		"missing body property": func(file map[string]any) {
			file["properties"] = []map[string]string{{"key": "synapse-marker", "value": "synapse-intent-fixture", "visibility": "PRIVATE"}}
		},
		"missing marker property": func(file map[string]any) {
			file["properties"] = []map[string]string{{"key": "synapse-body", "value": "body", "visibility": "PRIVATE"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, f := newDriveFixture(t)
			shell, err := a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
			if err != nil {
				t.Fatal(err)
			}
			mutate(f.files["folder"])
			err = a.VerifyDocumentRestriction(context.Background(), shell.ID, "parent", "group")
			var providerErr *ports.DocumentProviderError
			if !errors.As(err, &providerErr) || !providerErr.RestrictionLost || providerErr.Code != "remote_identity_changed" {
				t.Fatalf("complete shell mismatch = %#v, err=%v", providerErr, err)
			}
		})
	}
}

func assertDriveUnverifiable(t *testing.T, err error) {
	t.Helper()
	var providerErr *ports.DocumentProviderError
	if !errors.As(err, &providerErr) || providerErr.RestrictionLost || (providerErr.Code != "complete_acl_unverifiable" && providerErr.Code != "complete_identity_unverifiable") {
		t.Fatalf("malformed proof = %#v, err=%v", providerErr, err)
	}
}

type driveFixture struct {
	files                      map[string]map[string]any
	content                    map[string][]byte
	extra                      bool
	incomplete                 bool
	permissionPages            map[string]map[string]any
	permissionPageTokens       []string
	permissionPageTokenPresent []bool
	childPages                 map[string]map[string]any
	childPageTokens            []string
	childPageTokenPresent      []bool
	mediaRevisionIDs           []string
	mediaIfMatches             []string
	metadataIfMatches          []string
	rejectMediaIfMatch         bool
	mediaETag                  string
	mediaStatus                int
	metadataStatus             int
	afterMediaETag             string
	afterMediaHeadRevision     string
	afterMediaMD5              string
	corruptMedia               bool
	writes, deletes            int
	deleteAttempts             int
	deleteFailAfter            int
	deleteFailStatus           int
	next                       int
	revision                   int
}

func newDriveFixture(t *testing.T) (*driveAdapter, *driveFixture) {
	t.Helper()
	adapter, err := newDrive(integration.Integration{Provider: Drive, Endpoint: "https://www.googleapis.com", Config: json.RawMessage(`{"space":"parent","read_group":"group","data_class":"detail"}`)}, integration.CredentialBundle{"access_token": "private-fixture-token"}, selfhosted.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	a := adapter.(*driveAdapter)
	f := &driveFixture{files: map[string]map[string]any{}, content: map[string][]byte{}}
	f.files["parent"] = map[string]any{"id": "parent", "title": "Restricted", "mimeType": folderMIME, "etag": "parent-v1", "owners": []map[string]string{{"permissionId": "owner"}}, "labels": map[string]bool{"trashed": false}}
	a.client = &http.Client{Transport: transportFunc(f.serve)}
	return a, f
}
func (f *driveFixture) serve(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != "www.googleapis.com" || r.Header.Get("Authorization") != "Bearer private-fixture-token" {
		return response(403, map[string]string{"error": "credential rejected"}), nil
	}
	p := r.URL.Path
	if p == "/drive/v2/about" {
		return response(200, map[string]any{"user": map[string]string{"permissionId": "owner"}}), nil
	}
	if p == "/drive/v2/files/generateIds" {
		return response(200, map[string]any{"ids": []string{"folder", "body"}}), nil
	}
	if strings.HasSuffix(p, "/permissions") {
		_, present := r.URL.Query()["pageToken"]
		token := r.URL.Query().Get("pageToken")
		f.permissionPageTokenPresent = append(f.permissionPageTokenPresent, present)
		f.permissionPageTokens = append(f.permissionPageTokens, token)
		if f.permissionPages != nil {
			out, ok := f.permissionPages[token]
			if !ok {
				return response(400, map[string]string{"error": "unexpected page token"}), nil
			}
			return response(200, out), nil
		}
		permissions := []map[string]any{{"id": "owner", "type": "user", "role": "owner"}, {"id": "group", "type": "group", "role": "reader"}}
		if f.extra {
			permissions = append(permissions, map[string]any{"id": "everyone", "type": "anyone", "role": "reader"})
		}
		out := map[string]any{"items": permissions}
		if f.incomplete {
			out["nextPageToken"] = "repeat"
		}
		return response(200, out), nil
	}
	if p == "/drive/v2/files" && r.Method == "POST" {
		f.writes++
		var file map[string]any
		_ = json.NewDecoder(r.Body).Decode(&file)
		file["etag"] = "shell-v1"
		file["owners"] = []map[string]string{{"permissionId": "owner"}}
		f.files[file["id"].(string)] = file
		return response(201, file), nil
	}
	if strings.HasPrefix(p, "/upload/drive/v2/files") {
		f.writes++
		kind, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if kind != "multipart/related" {
			return response(400, nil), nil
		}
		reader := multipart.NewReader(r.Body, params["boundary"])
		part, _ := reader.NextPart()
		var file map[string]any
		_ = json.NewDecoder(part).Decode(&file)
		part, _ = reader.NextPart()
		data, _ := io.ReadAll(part)
		id, _ := file["id"].(string)
		if r.Method == "PUT" {
			id = strings.TrimPrefix(p, "/upload/drive/v2/files/")
			old := f.files[id]
			if old == nil || r.Header.Get("If-Match") != old["etag"] {
				return response(412, nil), nil
			}
			file["parents"] = old["parents"]
		} else if id == "" {
			f.next++
			id = fmt.Sprintf("attachment-%d", f.next)
		}
		if r.Method == "POST" && f.files[id] != nil {
			return response(409, nil), nil
		}
		file["id"] = id
		f.revision++
		file["etag"] = fmt.Sprintf("body-v%d", f.revision+1)
		file["headRevisionId"] = fmt.Sprintf("head-%d", f.revision+1)
		file["owners"] = []map[string]string{{"permissionId": "owner"}}
		sum := md5.Sum(data)
		file["md5Checksum"] = hex.EncodeToString(sum[:])
		f.files[id] = file
		f.content[id] = data
		return response(200, file), nil
	}
	if p == "/drive/v2/files" {
		_, present := r.URL.Query()["pageToken"]
		token := r.URL.Query().Get("pageToken")
		f.childPageTokenPresent = append(f.childPageTokenPresent, present)
		f.childPageTokens = append(f.childPageTokens, token)
		if f.childPages != nil {
			out, ok := f.childPages[token]
			if !ok {
				return response(400, map[string]string{"error": "unexpected page token"}), nil
			}
			return response(200, out), nil
		}
		q := r.URL.Query().Get("q")
		items := []map[string]any{}
		for _, file := range f.files {
			parents, _ := file["parents"].([]any)
			if len(parents) > 0 {
				parent, _ := parents[0].(map[string]any)
				if strings.Contains(q, "'"+parent["id"].(string)+"'") {
					items = append(items, file)
				}
			} else if parents, ok := file["parents"].([]map[string]string); ok && len(parents) > 0 && strings.Contains(q, "'"+parents[0]["id"]+"'") {
				items = append(items, file)
			}
		}
		return response(200, map[string]any{"items": items}), nil
	}
	id := strings.TrimPrefix(p, "/drive/v2/files/")
	file, ok := f.files[id]
	if !ok {
		return response(404, nil), nil
	}
	if r.Method == "DELETE" {
		f.deleteAttempts++
		if f.deleteFailAfter > 0 && f.deleteAttempts > f.deleteFailAfter {
			return response(f.deleteFailStatus, nil), nil
		}
		f.deletes++
		delete(f.files, id)
		delete(f.content, id)
		return response(204, []byte{}), nil
	}
	if r.URL.Query().Get("alt") == "media" {
		f.mediaRevisionIDs = append(f.mediaRevisionIDs, r.URL.Query().Get("revisionId"))
		f.mediaIfMatches = append(f.mediaIfMatches, r.Header.Get("If-Match"))
		if f.mediaStatus != 0 {
			return response(f.mediaStatus, nil), nil
		}
		if f.rejectMediaIfMatch && r.Header.Get("If-Match") != "" {
			return response(http.StatusPreconditionFailed, nil), nil
		}
		if revision, _ := file["headRevisionId"].(string); r.URL.Query().Get("revisionId") != revision {
			return response(412, nil), nil
		}
		if f.afterMediaETag != "" {
			file["etag"] = f.afterMediaETag
		}
		if f.afterMediaHeadRevision != "" {
			file["headRevisionId"] = f.afterMediaHeadRevision
		}
		if f.afterMediaMD5 != "" {
			file["md5Checksum"] = f.afterMediaMD5
		}
		if f.corruptMedia {
			return response(200, []byte("corrupted media")), nil
		}
		out := response(200, f.content[id])
		if f.mediaETag != "" {
			out.Header.Set("ETag", f.mediaETag)
		}
		return out, nil
	}
	if expected := r.Header.Get("If-Match"); expected != "" {
		f.metadataIfMatches = append(f.metadataIfMatches, expected)
		if f.metadataStatus != 0 {
			return response(f.metadataStatus, nil), nil
		}
		if expected != file["etag"] {
			return response(http.StatusPreconditionFailed, nil), nil
		}
	}
	return response(200, file), nil
}

func TestDriveACLPaginationOmitsEmptyPageTokenAndPropagatesContinuation(t *testing.T) {
	a, f := newDriveFixture(t)
	f.permissionPages = map[string]map[string]any{
		"":                 {"items": []map[string]any{{"id": "owner", "type": "user", "role": "owner"}}, "nextPageToken": "permissions-next"},
		"permissions-next": {"items": []map[string]any{{"id": "group", "type": "group", "role": "reader"}}},
	}
	if err := a.CheckDocumentRelease(context.Background(), "parent", "group"); err != nil {
		t.Fatal(err)
	}
	if len(f.permissionPageTokens) != 2 || f.permissionPageTokenPresent[0] || f.permissionPageTokens[0] != "" || !f.permissionPageTokenPresent[1] || f.permissionPageTokens[1] != "permissions-next" {
		t.Fatalf("permission page tokens = present:%v values:%q", f.permissionPageTokenPresent, f.permissionPageTokens)
	}
}

func TestDriveChildrenPaginationOmitsEmptyPageTokenAndPropagatesContinuation(t *testing.T) {
	a, f := newDriveFixture(t)
	f.childPages = map[string]map[string]any{
		"":              {"items": []map[string]any{{"id": "child-one", "title": "one", "mimeType": "text/html", "etag": "one-v1", "parents": []map[string]string{{"id": "parent"}}, "owners": []map[string]string{{"permissionId": "owner"}}, "labels": map[string]bool{"trashed": false}}}, "nextPageToken": "children-next"},
		"children-next": {"items": []map[string]any{{"id": "child-two", "title": "two", "mimeType": "text/html", "etag": "two-v1", "parents": []map[string]string{{"id": "parent"}}, "owners": []map[string]string{{"permissionId": "owner"}}, "labels": map[string]bool{"trashed": false}}}},
	}
	children, err := a.children(context.Background(), "parent")
	if err != nil || len(children) != 2 {
		t.Fatalf("children = %+v, err = %v", children, err)
	}
	if len(f.childPageTokens) != 2 || f.childPageTokenPresent[0] || f.childPageTokens[0] != "" || !f.childPageTokenPresent[1] || f.childPageTokens[1] != "children-next" {
		t.Fatalf("child page tokens = present:%v values:%q", f.childPageTokenPresent, f.childPageTokens)
	}
}

func TestDriveChildrenRejectsRepeatedPageToken(t *testing.T) {
	a, f := newDriveFixture(t)
	f.childPages = map[string]map[string]any{
		"":       {"items": []map[string]any{}, "nextPageToken": "repeat"},
		"repeat": {"items": []map[string]any{}, "nextPageToken": "repeat"},
	}
	if _, err := a.children(context.Background(), "parent"); err == nil {
		t.Fatal("repeated child page token accepted")
	}
}
func TestDriveRefusesPublicOrIncompleteACLBeforeCreatingShell(t *testing.T) {
	for _, mode := range []string{"public", "incomplete"} {
		t.Run(mode, func(t *testing.T) {
			a, f := newDriveFixture(t)
			f.extra = mode == "public"
			f.incomplete = mode == "incomplete"
			if _, err := a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture"); err == nil {
				t.Fatal("unproven ACL accepted")
			}
			if f.writes != 0 {
				t.Fatal("remote write before ACL proof")
			}
		})
	}
}
func TestDrivePublishesWithPreallocatedIdentityAndOpaqueETag(t *testing.T) {
	a, f := newDriveFixture(t)
	ctx := context.Background()
	shell, err := a.CreateDocumentShell(ctx, "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	body, err := a.WriteDocumentRevision(ctx, shell, "Synthetic Tiếng Việt", "<h1>Synthetic Tiếng Việt</h1><p>Escaped &lt;script&gt;</p>", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if body.ID != shell.ID || body.Revision == shell.Revision {
		t.Fatal("identity/revision not retained")
	}
	remote, err := a.GetDocument(ctx, body.ID)
	if err != nil || remote.Title != "Synthetic Tiếng Việt" || remote.Neutral {
		t.Fatalf("readback=%+v err=%v", remote, err)
	}
	before := f.writes
	if _, err = a.WriteDocumentRevision(ctx, shell, "Stale", "<p>must not overwrite</p>", "synapse-intent-stale"); err == nil {
		t.Fatal("stale revision accepted")
	}
	if f.writes != before {
		t.Fatal("stale writer issued upload")
	}
}
func TestDrivePurgeChecksAuthorityBeforeEachPermanentDelete(t *testing.T) {
	a, f := newDriveFixture(t)
	ctx := context.Background()
	shell, err := a.CreateDocumentShell(ctx, "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.WriteDocumentRevision(ctx, shell, "Report", "<p>report</p>", "synapse-intent-fixture"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err = a.PurgeDocument(ctx, shell.ID, func(context.Context) error {
		calls++
		if calls == 2 {
			return errors.New("legal hold")
		}
		return nil
	})
	if err == nil || f.deletes != 1 || f.files["folder"] == nil {
		t.Fatalf("purge ignored authority: calls=%d deletes=%d err=%v", calls, f.deletes, err)
	}
}

func TestDrivePurgeKeepsRecoveryFenceAfterPartialPermanentDelete(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusPreconditionFailed, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			a, f := newDriveFixture(t)
			shell, err := a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = a.WriteDocumentRevision(context.Background(), shell, "Report", "<p>report</p>", "synapse-intent-fixture"); err != nil {
				t.Fatal(err)
			}
			f.deleteFailAfter, f.deleteFailStatus = 1, status
			err = a.PurgeDocument(context.Background(), shell.ID, func(context.Context) error { return nil })
			var providerErr *ports.DocumentProviderError
			if !errors.As(err, &providerErr) || !providerErr.Ambiguous || providerErr.Code != "purge_incomplete" {
				t.Fatalf("partial purge lost its recovery fence: err=%v", err)
			}
			if f.deletes != 1 || f.deleteAttempts != 2 || f.files["folder"] == nil {
				t.Fatalf("purge continued after rejected delete: deletes=%d attempts=%d folder=%v", f.deletes, f.deleteAttempts, f.files["folder"])
			}
		})
	}
}

func TestDrivePurgeKeepsRecoveryFenceWhenGuardChangesAfterDelete(t *testing.T) {
	a, f := newDriveFixture(t)
	shell, err := a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.WriteDocumentRevision(context.Background(), shell, "Report", "<p>report</p>", "synapse-intent-fixture"); err != nil {
		t.Fatal(err)
	}
	guardCalls := 0
	err = a.PurgeDocument(context.Background(), shell.ID, func(context.Context) error {
		guardCalls++
		if guardCalls == 2 {
			return errors.New("legal hold changed")
		}
		return nil
	})
	var providerErr *ports.DocumentProviderError
	if !errors.As(err, &providerErr) || !providerErr.Ambiguous || providerErr.Code != "purge_incomplete" {
		t.Fatalf("guard change lost partial purge fence: err=%v", err)
	}
	if f.deletes != 1 || f.deleteAttempts != 1 || f.files["folder"] == nil {
		t.Fatalf("purge issued a write after guard change: deletes=%d attempts=%d", f.deletes, f.deleteAttempts)
	}
}

func TestDrivePurgeValidatesAllChildrenBeforeDeletingAny(t *testing.T) {
	a, f := newDriveFixture(t)
	shell, err := a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.WriteDocumentRevision(context.Background(), shell, "Report", "<p>report</p>", "synapse-intent-fixture"); err != nil {
		t.Fatal(err)
	}
	f.files["manual"] = map[string]any{
		"id":       "manual",
		"title":    "manual.txt",
		"mimeType": "text/plain",
		"etag":     "manual-v1",
		"parents":  []map[string]string{{"id": "folder"}},
		"owners":   []map[string]string{{"permissionId": "owner"}},
		"labels":   map[string]bool{"trashed": false},
	}
	if err = a.PurgeDocument(context.Background(), shell.ID, func(context.Context) error { return nil }); err == nil {
		t.Fatal("unmanaged child accepted")
	}
	if f.deletes != 0 || f.deleteAttempts != 0 {
		t.Fatalf("purge deleted owned content before rejecting unmanaged child: deletes=%d attempts=%d", f.deletes, f.deleteAttempts)
	}
}
func TestDriveHTMLAllowsOnlyInertSourceAndLiteralReportText(t *testing.T) {
	for _, source := range []string{"<script>alert(1)</script>", "<p><iframe /></p>", "<?evil x?><p>text</p>"} {
		if _, err := encodeDriveHTML("Report", source, "synapse-intent-fixture"); err == nil {
			t.Fatal("active markup accepted")
		}
	}
	data, err := encodeDriveHTML("Report", "<p>Tiếng Việt &lt;script&gt;</p>", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("Tiếng Việt &lt;script&gt;")) {
		t.Fatal("literal text lost")
	}
	data = bytes.Replace(data, []byte("</body>"), []byte("<script>bad()</script></body>"), 1)
	if _, _, _, err = decodeDriveHTML(data); err == nil {
		t.Fatal("remote HTML tampering accepted")
	}
}

func TestDocumentHTMLCanonicalizersRejectUnsafeAndIncompleteAttachmentStructure(t *testing.T) {
	encoders := map[string]func(string, string, string, map[string]string) ([]byte, error){
		"drive": encodeDocumentHTML,
		"graph": encodeGraphHTML,
	}
	for name, encode := range encoders {
		t.Run(name, func(t *testing.T) {
			for _, storage := range []string{
				`<p><link href="https://attacker.invalid"><attachment filename="evidence.pdf"/></link></p>`,
				`<p><image src="https://attacker.invalid"><attachment filename="evidence.pdf"/></image></p>`,
				`<p><link></link></p>`,
				`<p><image></image></p>`,
				`<p><link><attachment filename="evidence.pdf"/></image></p>`,
				`<p><image><attachment filename="report.html"/></image></p>`,
			} {
				if _, err := encode("Report", storage, "synapse-intent-fixture", map[string]string{"evidence.pdf": "attachment", "report.html": "body"}); err == nil {
					t.Fatalf("accepted unsafe or incomplete storage %q", storage)
				}
			}
		})
	}
}

func TestDriveReadbackUsesHeadRevisionThenFencesOriginalMetadata(t *testing.T) {
	a, f := newDriveFixture(t)
	ctx := context.Background()
	shell, err := a.CreateDocumentShell(ctx, "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.WriteDocumentRevision(ctx, shell, "Report", "<p>Approved</p>", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	f.rejectMediaIfMatch = true
	f.mediaETag = "media-body-v2"
	remote, err := a.GetDocument(ctx, shell.ID)
	if err != nil || remote.Revision != "body-v2" {
		t.Fatalf("readback = %+v, err = %v", remote, err)
	}
	if len(f.mediaRevisionIDs) == 0 || f.mediaRevisionIDs[len(f.mediaRevisionIDs)-1] != "head-2" || f.mediaIfMatches[len(f.mediaIfMatches)-1] != "" || f.metadataIfMatches[len(f.metadataIfMatches)-1] != "body-v2" {
		t.Fatalf("media revisions=%q media conditions=%q metadata conditions=%q", f.mediaRevisionIDs, f.mediaIfMatches, f.metadataIfMatches)
	}
}

func TestDriveRestrictedReadReturnsCurrentStateWithoutRepeatingTheProof(t *testing.T) {
	a, f := newDriveFixture(t)
	ctx := context.Background()
	shell, err := a.CreateDocumentShell(ctx, "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	published, err := a.WriteDocumentRevision(ctx, shell, "Report", "<p>Approved</p>", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return f.serve(r)
	})
	state, err := a.ReadRestrictedDocument(ctx, published.ID, "parent", "group")
	if err != nil || state.ID != published.ID || state.Revision != published.Revision || state.Container != "parent" || state.Neutral {
		t.Fatalf("restricted state = %+v, err=%v", state, err)
	}
	if calls > 9 {
		t.Fatalf("restricted read repeated the same ACL proof: requests=%d", calls)
	}
	t.Logf("combined restricted read requests=%d", calls)
}

func TestDriveRejectsAttachmentNamesTheCanonicalDocumentCannotReference(t *testing.T) {
	a, f := newDriveFixture(t)
	shell, err := a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	before := f.writes
	for _, name := range []string{"report.html", graphManifestName, "chart?one.png", "chart#one.png"} {
		if err := a.UploadDocumentAttachment(context.Background(), shell.ID, ports.DocumentImage{Name: name, MediaType: "image/png", Data: []byte("png")}); err == nil {
			t.Fatalf("accepted an unreferenceable attachment name %q", name)
		}
	}
	if f.writes != before {
		t.Fatalf("invalid attachment name issued an outward write: before=%d after=%d", before, f.writes)
	}
}

func TestDriveReadbackRejectsChangedMetadataAfterPinnedMedia(t *testing.T) {
	for name, mutate := range map[string]func(*driveFixture){
		"etag":          func(f *driveFixture) { f.afterMediaETag = "body-v3" },
		"head revision": func(f *driveFixture) { f.afterMediaHeadRevision = "head-3" },
		"checksum":      func(f *driveFixture) { f.afterMediaMD5 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
		"bytes":         func(f *driveFixture) { f.corruptMedia = true },
	} {
		t.Run(name, func(t *testing.T) {
			a, f := newDriveFixture(t)
			shell, err := a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = a.WriteDocumentRevision(context.Background(), shell, "Report", "<p>Approved</p>", "synapse-intent-fixture"); err != nil {
				t.Fatal(err)
			}
			mutate(f)
			if _, err = a.GetDocument(context.Background(), shell.ID); err == nil {
				t.Fatal("changed blob proof accepted")
			}
			if name == "head revision" || name == "checksum" {
				if len(f.metadataIfMatches) == 0 || f.metadataIfMatches[len(f.metadataIfMatches)-1] != "body-v2" {
					t.Fatalf("changed metadata was not conditionally reread: %q", f.metadataIfMatches)
				}
			}
		})
	}
}

func TestDriveAttachmentProofUsesHeadRevisionAndDoesNotDuplicateOnFailure(t *testing.T) {
	a, f := newDriveFixture(t)
	ctx := context.Background()
	shell, err := a.CreateDocumentShell(ctx, "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	attachment := ports.DocumentImage{Name: "evidence.pdf", MediaType: "application/pdf", Data: []byte("%PDF-1.7 existing")}
	if err = a.UploadDocumentAttachment(ctx, shell.ID, attachment); err != nil {
		t.Fatal(err)
	}
	f.rejectMediaIfMatch = true
	f.mediaETag = "media-attachment-v1"
	before := f.writes
	if err = a.UploadDocumentAttachment(ctx, shell.ID, attachment); err != nil {
		t.Fatal(err)
	}
	if f.writes != before || len(f.mediaRevisionIDs) == 0 || f.mediaRevisionIDs[len(f.mediaRevisionIDs)-1] == "" || f.mediaIfMatches[len(f.mediaIfMatches)-1] != "" {
		t.Fatalf("attachment proof duplicated or was not revision-pinned: writes=%d before=%d revisions=%q conditions=%q", f.writes, before, f.mediaRevisionIDs, f.mediaIfMatches)
	}
	conflicting := attachment
	conflicting.Data = []byte("%PDF-1.7 different")
	if err = a.UploadDocumentAttachment(ctx, shell.ID, conflicting); err == nil || f.writes != before {
		t.Fatalf("attachment byte conflict accepted or uploaded duplicate: writes=%d before=%d err=%v", f.writes, before, err)
	}
	f.afterMediaETag = "attachment-drift"
	if err = a.UploadDocumentAttachment(ctx, shell.ID, attachment); err == nil || f.writes != before {
		t.Fatalf("drifted attachment proof accepted or uploaded duplicate: writes=%d before=%d err=%v", f.writes, before, err)
	}
}

func TestDrivePurgeDoesNotRequireBlobReadMetadata(t *testing.T) {
	a, f := newDriveFixture(t)
	ctx := context.Background()
	shell, err := a.CreateDocumentShell(ctx, "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.WriteDocumentRevision(ctx, shell, "Report", "<p>Approved</p>", "synapse-intent-fixture"); err != nil {
		t.Fatal(err)
	}
	delete(f.files["body"], "headRevisionId")
	delete(f.files["body"], "md5Checksum")
	if err = a.PurgeDocument(ctx, shell.ID, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if f.deletes != 2 {
		t.Fatalf("purge did not remove the report and shell: deletes=%d", f.deletes)
	}
}

func TestDriveBlobReadRejectsInvalidProofMetadataBeforeMediaRead(t *testing.T) {
	data := []byte("managed blob")
	sum := md5.Sum(data)
	for name, file := range map[string]driveFile{
		"missing head revision":   {ID: "body", ETag: "metadata-v1", MD5: hex.EncodeToString(sum[:])},
		"malformed head revision": {ID: "body", ETag: "metadata-v1", HeadRevision: "head/revision", MD5: hex.EncodeToString(sum[:])},
		"missing checksum":        {ID: "body", ETag: "metadata-v1", HeadRevision: "head-1"},
		"malformed checksum":      {ID: "body", ETag: "metadata-v1", HeadRevision: "head-1", MD5: "not-a-checksum"},
	} {
		t.Run(name, func(t *testing.T) {
			a, f := newDriveFixture(t)
			if _, err := a.readFileBytes(context.Background(), file); err == nil {
				t.Fatal("invalid blob proof metadata accepted")
			}
			if len(f.mediaRevisionIDs) != 0 {
				t.Fatalf("media read issued for invalid metadata: %q", f.mediaRevisionIDs)
			}
		})
	}
}

func TestDriveReadbackFailsClosedWhenProviderRejectsMediaOrMetadata(t *testing.T) {
	for _, test := range []struct {
		name   string
		phase  string
		status int
	}{
		{name: "media forbidden", phase: "media", status: http.StatusForbidden},
		{name: "media missing", phase: "media", status: http.StatusNotFound},
		{name: "media changed", phase: "media", status: http.StatusPreconditionFailed},
		{name: "metadata forbidden", phase: "metadata", status: http.StatusForbidden},
		{name: "metadata missing", phase: "metadata", status: http.StatusNotFound},
		{name: "metadata changed", phase: "metadata", status: http.StatusPreconditionFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, f := newDriveFixture(t)
			shell, err := a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = a.WriteDocumentRevision(context.Background(), shell, "Report", "<p>Approved</p>", "synapse-intent-fixture"); err != nil {
				t.Fatal(err)
			}
			if test.phase == "media" {
				f.mediaStatus = test.status
			} else {
				f.metadataStatus = test.status
			}
			if _, err = a.GetDocument(context.Background(), shell.ID); err == nil {
				t.Fatal("rejected provider read accepted")
			}
		})
	}
}

func TestDriveBlobReadFailsClosedOnCancellationAndOversizedMedia(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		a, _ := newDriveFixture(t)
		a.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			return nil, r.Context().Err()
		})}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := a.readFileBytes(ctx, driveFile{ID: "body", ETag: "metadata-v1", HeadRevision: "head-1", MD5: "00000000000000000000000000000000"}); err == nil {
			t.Fatal("cancelled media read accepted")
		}
	})
	t.Run("oversized media", func(t *testing.T) {
		a, _ := newDriveFixture(t)
		a.client = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusOK, bytes.Repeat([]byte{'x'}, 24<<20+1)), nil
		})}
		if _, err := a.readFileBytes(context.Background(), driveFile{ID: "body", ETag: "metadata-v1", HeadRevision: "head-1", MD5: "00000000000000000000000000000000"}); err == nil {
			t.Fatal("oversized media accepted")
		}
	})
}

// This opt-in capture renders the same safe HTML bytes sent by the adapters.
// It is local visual evidence, never a provider acceptance receipt.
func TestDocumentRenderingEvidence(t *testing.T) {
	output := os.Getenv("SYNAPSE_DOCUMENT_PREVIEW_DIR")
	if output == "" {
		t.Skip("local visual capture not requested")
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	registry := integration.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatal(err)
	}
	descriptors := []integration.ProviderDescriptor{}
	for _, provider := range []integration.Provider{SharePoint, OneDrive, Drive} {
		descriptor, err := registry.Descriptor(provider)
		if err != nil {
			t.Fatal(err)
		}
		descriptors = append(descriptors, descriptor)
	}
	descriptorJSON, err := json.MarshalIndent(descriptors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(output, "provider-descriptors.json"), descriptorJSON, 0600); err != nil {
		t.Fatal(err)
	}
	for _, locale := range []string{"en", "vi"} {
		title, text := "Security assessment report", "SQL injection — approved stored evidence."
		if locale == "vi" {
			title, text = "Báo cáo đánh giá bảo mật", "SQL injection — bằng chứng đã được phê duyệt."
		}
		storage := "<h1>" + title + "</h1><p>" + text + "</p><p>Literal &lt;script&gt; stays inert. Tiếng Việt: ă â ê ô ơ ư đ.</p><p><ac:link><ri:attachment ri:filename=\"report.pdf\"/><ac:plain-text-link-body>Download PDF</ac:plain-text-link-body></ac:link></p><p><ac:image><ri:attachment ri:filename=\"evidence.png\"/></ac:image></p>"
		for _, provider := range []string{"drive", "sharepoint"} {
			render := encodeDocumentHTML
			if provider == "sharepoint" {
				render = encodeGraphHTML
			}
			raw, err := render(title, storage, "synapse-intent-preview", map[string]string{"report.pdf": "managedpdf", "evidence.png": "managedimage"})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(output, provider+"-"+locale+".html"), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestDocumentConfiguredSecretsRefuseCommonEncodings(t *testing.T) {
	tokens := []string{"private-fixture-token", "graph-token", "sp-token"}
	a, _ := newDriveFixture(t)
	graph := &graphAdapter{token: tokens[1], sharePointToken: tokens[2]}
	for _, token := range tokens {
		for _, encoded := range []string{token, base64.StdEncoding.EncodeToString([]byte(token)), base64.RawStdEncoding.EncodeToString([]byte(token)), base64.URLEncoding.EncodeToString([]byte(token)), base64.RawURLEncoding.EncodeToString([]byte(token)), hex.EncodeToString([]byte(token)), strings.ToUpper(hex.EncodeToString([]byte(token)))} {
			validate := graph.ValidateDocumentText
			if token == tokens[0] {
				validate = a.ValidateDocumentText
			}
			if err := validate("Evidence: " + encoded); err == nil || strings.Contains(err.Error(), encoded) {
				t.Fatal("configured credential encoding accepted or leaked")
			}
		}
	}
}

func TestDriveRepublishOwnsBothRevisionsAndPurgesAfterSharingDrift(t *testing.T) {
	a, f := newDriveFixture(t)
	ctx := context.Background()
	shell, err := a.CreateDocumentShell(ctx, "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.UploadDocumentAttachment(ctx, shell.ID, ports.DocumentImage{Name: "first.pdf", MediaType: "application/pdf", Data: []byte("%PDF-1.7 first")}); err != nil {
		t.Fatal(err)
	}
	first, err := a.WriteDocumentRevision(ctx, shell, "First", "<p>Approved first</p>", "synapse-intent-first")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.UploadDocumentAttachment(ctx, shell.ID, ports.DocumentImage{Name: "second.pdf", MediaType: "application/pdf", Data: []byte("%PDF-1.7 second")}); err != nil {
		t.Fatal(err)
	}
	second, err := a.WriteDocumentRevision(ctx, first, "Second", "<p>Approved second</p>", "synapse-intent-second")
	if err != nil || second.Revision == first.Revision {
		t.Fatalf("republish revision did not advance: %v", err)
	}
	f.extra = true
	writes := f.writes
	if err = a.UploadDocumentAttachment(ctx, shell.ID, ports.DocumentImage{Name: "blocked.pdf", MediaType: "application/pdf", Data: []byte("%PDF-1.7 blocked")}); err == nil || f.writes != writes {
		t.Fatal("sharing drift allowed an outward write")
	}
	if err = a.PurgeDocument(ctx, shell.ID, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if f.deletes != 4 || f.files["folder"] != nil {
		t.Fatalf("managed retained artifacts not purged: deletes=%d", f.deletes)
	}
}

func TestDriveMaximumAttachmentProofReadsEachACLOnce(t *testing.T) {
	a, f := newDriveFixture(t)
	ctx := context.Background()
	shell, err := a.CreateDocumentShell(ctx, "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 11; i++ {
		if err = a.UploadDocumentAttachment(ctx, shell.ID, ports.DocumentImage{Name: fmt.Sprintf("evidence-%d.png", i), MediaType: "image/png", Data: []byte{byte(i + 1)}}); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	a.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) { calls++; return f.serve(r) })
	if err = a.VerifyDocumentRestriction(ctx, shell.ID, "parent", "group"); err != nil {
		t.Fatal(err)
	}
	if calls > 18 {
		t.Fatalf("maximum-size proof repeated metadata/identity reads: requests=%d", calls)
	}
}

func TestDriveOwnerProofDistinguishesMissingIdentityFromObservedTransfer(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		lost     bool
	}{
		{"missing owner ID", "", false},
		{"invalid owner ID", "not an ID", false},
		{"observed transfer", "other-owner", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, f := newDriveFixture(t)
			f.files["parent"]["owners"] = []map[string]string{{"permissionId": tc.id}}
			err := a.CheckDocumentRelease(context.Background(), "parent", "group")
			var refusal *ports.DocumentProviderError
			if !errors.As(err, &refusal) || refusal.RestrictionLost != tc.lost {
				t.Fatalf("ownerproof=%+v err=%v wantloss=%t", refusal, err, tc.lost)
			}
		})
	}
}
