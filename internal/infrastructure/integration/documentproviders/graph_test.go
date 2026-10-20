package documentproviders

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	graphSiteID = "site-guid"
	graphListID = "list-guid"
	parentGUID  = "parent-guid"
)

type graphFixture struct {
	a                      *graphAdapter
	items                  map[string]graphItem
	contents               map[string][]byte
	etags                  map[string]string
	links                  map[string]json.RawMessage
	nextRoles              string
	roleExtra              bool
	badGroup               bool
	unique                 bool
	currentType            int
	pendingDelete          bool
	deleteAttempts         int
	deleteFailAfter        int
	deleteFailStatus       int
	shellPublic            bool
	denyChildACL           bool
	denyShellReadback      bool
	denyFolderPermissions  bool
	denyProofAfterBody     bool
	denyProofAfterManifest bool
	failManifestCAS        bool
	nextFileID             int
	writes                 int
	deletes                int
	failUpdate             bool
	dropFolder             bool
	dropBody               bool
	dropManifest           bool
}

func graphRoles(extra bool) any {
	role := func(id, principalType, kind int, high, low string) any {
		return map[string]any{"Member": map[string]any{"Id": id, "PrincipalType": principalType}, "RoleDefinitionBindings": map[string]any{"results": []any{map[string]any{"RoleTypeKind": kind, "BasePermissions": map[string]string{"High": high, "Low": low}}}}}
	}
	out := []any{role(7, 4, sharePointReadRoleType, sharePointReadHigh, sharePointReadLow), role(9, 1, sharePointFullRoleType, sharePointFullHigh, sharePointFullLow)}
	if extra {
		out = append(out, role(10, 1, sharePointReadRoleType, sharePointReadHigh, sharePointReadLow))
	}
	return map[string]any{"d": map[string]any{"results": out}}
}

func newGraphFixture(t *testing.T) *graphFixture {
	t.Helper()
	site, _ := url.Parse("https://tenant.sharepoint.com/sites/security")
	a := &graphAdapter{provider: SharePoint, drive: "drive", container: "parent", group: "7", custodian: "9", folderPath: "/sites/security/restricted", token: "graph-token", sharePointToken: "sp-token", site: site}
	f := &graphFixture{a: a, items: map[string]graphItem{}, contents: map[string][]byte{}, etags: map[string]string{}, links: map[string]json.RawMessage{}, unique: true, currentType: 1}
	f.items["parent"] = f.item("parent", "Restricted", "", true, parentGUID)
	a.client = &http.Client{Transport: transportFunc(f.serve)}
	return f
}

func (f *graphFixture) item(id, name, parent string, folder bool, unique string) graphItem {
	item := graphItem{ID: id, Name: name, ETag: "graph-" + id, SharePointIDs: graphSharePointIDs{SiteID: graphSiteID, ListID: graphListID, ListItemUniqueID: unique, SiteURL: "https://tenant.sharepoint.com/sites/security"}}
	item.Parent.ID, item.Parent.DriveID = parent, "drive"
	if folder {
		item.Folder = json.RawMessage(`{}`)
	} else {
		item.File = json.RawMessage(`{"mimeType":"text/plain"}`)
	}
	return item
}

func (f *graphFixture) graphChildren(parent string) []graphItem {
	out := []graphItem{}
	for _, item := range f.items {
		if item.Parent.ID == parent {
			out = append(out, item)
		}
	}
	return out
}
func (f *graphFixture) byName(parent, name string) (graphItem, bool) {
	for _, item := range f.items {
		if item.Parent.ID == parent && item.Name == name {
			return item, true
		}
	}
	return graphItem{}, false
}
func (f *graphFixture) refForItem(item graphItem) string {
	if item.ID == "parent" {
		return f.a.folderPath
	}
	parent := f.items[item.Parent.ID]
	return graphChildPath(f.refForItem(parent), item.Name)
}
func (f *graphFixture) itemForRef(ref string) (graphItem, bool) {
	for _, item := range f.items {
		if f.refForItem(item) == ref {
			return item, true
		}
	}
	return graphItem{}, false
}

func (f *graphFixture) serve(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" {
		return response(http.StatusBadRequest, nil), nil
	}
	switch r.URL.Host {
	case "graph.microsoft.com":
		if r.Header.Get("Authorization") != "Bearer graph-token" {
			return response(http.StatusForbidden, nil), nil
		}
		return f.graph(r)
	case "tenant.sharepoint.com":
		if r.Header.Get("Authorization") != "Bearer sp-token" {
			return response(http.StatusForbidden, nil), nil
		}
		return f.sharePoint(r)
	default:
		return response(http.StatusForbidden, nil), nil
	}
}

func (f *graphFixture) graph(r *http.Request) (*http.Response, error) {
	p := strings.TrimPrefix(r.URL.Path, "/v1.0")
	if p == "/drives/drive" && r.Method == http.MethodGet {
		return response(200, map[string]any{"id": "drive", "driveType": "documentLibrary", "sharepointIds": map[string]string{"siteId": graphSiteID, "listId": graphListID, "siteUrl": "https://tenant.sharepoint.com/sites/security"}}), nil
	}
	if r.Method == http.MethodPost && p == "/drives/drive/items/parent/children" {
		if _, ok := f.byName("parent", "synapse-intent-fixture"); ok {
			return response(409, nil), nil
		} else {
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			name, _ := in["name"].(string)
			if name != "synapse-intent-fixture" {
				return response(400, nil), nil
			}
			created := f.item("shell", name, "parent", true, "shell-guid")
			f.items[created.ID] = created
			if f.shellPublic {
				f.links[created.ID] = json.RawMessage(`{"scope":"organization"}`)
			}
			f.writes++
			if f.dropFolder {
				return nil, errors.New("folder create completed before connection dropped")
			}
			return response(201, created), nil
		}
	}
	if strings.HasPrefix(p, "/drives/drive/items/") {
		rest := strings.TrimPrefix(p, "/drives/drive/items/")
		if strings.HasSuffix(rest, "/children") && r.Method == http.MethodGet {
			parent := strings.TrimSuffix(rest, "/children")
			return response(200, map[string]any{"value": f.graphChildren(parent)}), nil
		}
		if strings.HasSuffix(rest, "/permissions") && r.Method == http.MethodGet {
			id := strings.TrimSuffix(rest, "/permissions")
			if f.denyFolderPermissions && id == "shell" {
				return response(http.StatusForbidden, nil), nil
			}
			if f.denyChildACL && strings.HasPrefix(id, "attachment-") {
				return response(http.StatusForbidden, nil), nil
			}
			link := f.links[id]
			value := []any{}
			if len(link) > 0 {
				value = append(value, map[string]any{"id": "link", "link": json.RawMessage(link)})
			}
			return response(200, map[string]any{"value": value}), nil
		}
		if strings.HasSuffix(rest, "/permanentDelete") && r.Method == http.MethodPost {
			id := strings.TrimSuffix(rest, "/permanentDelete")
			if _, ok := f.items[id]; !ok {
				return response(404, nil), nil
			}
			f.deleteAttempts++
			if f.deleteFailAfter > 0 && f.deleteAttempts > f.deleteFailAfter {
				return response(f.deleteFailStatus, nil), nil
			}
			if f.pendingDelete {
				return response(202, []byte{}), nil
			}
			delete(f.items, id)
			delete(f.contents, id)
			f.deletes++
			return response(204, []byte{}), nil
		}
		if r.Method == http.MethodGet && strings.Contains(rest, ":/") {
			parts := strings.SplitN(rest, ":/", 2)
			if item, ok := f.byName(parts[0], strings.TrimSuffix(parts[1], ":")); ok {
				return response(200, item), nil
			}
			return response(404, nil), nil
		}
		if r.Method == http.MethodGet && !strings.Contains(rest, "/") {
			if rest == "shell" && f.denyShellReadback {
				return response(http.StatusForbidden, nil), nil
			}
			if item, ok := f.items[rest]; ok {
				return response(200, item), nil
			}
		}
	}
	return response(404, nil), nil
}

func (f *graphFixture) sharePoint(r *http.Request) (*http.Response, error) {
	p := r.URL.Path
	if strings.HasSuffix(p, "/_api/web/currentuser") {
		return response(200, map[string]any{"d": map[string]int{"Id": 9, "PrincipalType": f.currentType}}), nil
	}
	ref := ""
	for _, item := range f.items {
		candidate := f.refForItem(item)
		escaped := (&url.URL{Path: candidate}).EscapedPath()
		if (strings.Contains(r.URL.String(), escaped) || strings.Contains(r.URL.String(), candidate)) && len(candidate) > len(ref) {
			ref = candidate
		}
	}
	if strings.Contains(p, "RoleAssignments") {
		out := graphRoles(f.roleExtra).(map[string]any)
		d := out["d"].(map[string]any)
		if f.badGroup {
			d["results"].([]any)[0].(map[string]any)["Member"].(map[string]any)["PrincipalType"] = 1
		}
		if f.nextRoles != "" {
			d["__next"] = f.nextRoles
		}
		return response(200, out), nil
	}
	if strings.Contains(p, "ListItemAllFields") {
		item, ok := f.itemForRef(ref)
		if !ok {
			return response(404, nil), nil
		}
		return response(200, map[string]any{"d": map[string]any{"Id": 31, "UniqueId": item.SharePointIDs.ListItemUniqueID, "FileRef": ref, "HasUniqueRoleAssignments": item.ID == "parent" && f.unique, "ParentList": map[string]string{"Id": graphListID}}}), nil
	}
	if strings.Contains(p, "Files/add") && r.Method == http.MethodPost {
		folderRef := ref
		start := strings.Index(p, "url='")
		if start < 0 {
			return response(400, nil), nil
		}
		name := p[start+5:]
		name = strings.TrimSuffix(strings.SplitN(name, "'", 2)[0], "")
		folder, ok := f.itemForRef(folderRef)
		if !ok {
			return response(404, nil), nil
		}
		if _, ok = f.byName(folder.ID, name); ok {
			return response(409, nil), nil
		}
		data, _ := io.ReadAll(r.Body)
		id := "body"
		switch name {
		case graphManifestName:
			id = "manifest"
		case "report.html":
		default:
			f.nextFileID++
			id = "attachment-" + strconv.Itoa(f.nextFileID)
		}
		created := f.item(id, name, folder.ID, false, id+"-guid")
		f.items[id], f.contents[id], f.etags[id] = created, data, `"1"`
		f.writes++
		if name == "report.html" && f.denyProofAfterBody {
			f.denyFolderPermissions = true
		}
		if name == graphManifestName && f.denyProofAfterManifest {
			f.denyFolderPermissions = true
		}
		if (f.dropBody && name == "report.html") || (f.dropManifest && name == graphManifestName) {
			return nil, errors.New("write completed before connection dropped")
		}
		return response(201, map[string]any{"d": map[string]string{"Name": name}}), nil
	}
	if strings.Contains(p, "/$value") {
		item, ok := f.itemForRef(ref)
		if !ok {
			return response(404, nil), nil
		}
		if r.Method == http.MethodGet {
			out := response(200, f.contents[item.ID])
			out.Header.Set("ETag", f.etags[item.ID])
			return out, nil
		}
		if r.Method == http.MethodPost && r.Header.Get("X-HTTP-Method") == "PUT" {
			if f.failUpdate || (f.failManifestCAS && item.Name == graphManifestName) || r.Header.Get("If-Match") != f.etags[item.ID] {
				return response(412, nil), nil
			}
			f.contents[item.ID], _ = io.ReadAll(r.Body)
			if f.etags[item.ID] == `"1"` {
				f.etags[item.ID] = `"2"`
			} else {
				f.etags[item.ID] = `"3"`
			}
			f.writes++
			return response(200, []byte{}), nil
		}
	}
	if strings.Contains(p, "GetFileByServerRelativeUrl") && r.URL.Query().Get("$select") == "ETag" {
		item, ok := f.itemForRef(ref)
		if !ok {
			return response(404, nil), nil
		}
		return response(200, map[string]any{"d": map[string]string{"ETag": f.etags[item.ID]}}), nil
	}
	return response(404, nil), nil
}

func TestGraphReleaseRequiresCompleteBoundACL(t *testing.T) {
	for name, change := range map[string]func(*graphFixture){
		"extra_principal":        func(f *graphFixture) { f.roleExtra = true },
		"inherited_parent":       func(f *graphFixture) { f.unique = false },
		"incomplete_roles":       func(f *graphFixture) { f.nextRoles = "next" },
		"organization_link":      func(f *graphFixture) { f.links["parent"] = json.RawMessage(`{"scope":"organization"}`) },
		"read_principal_is_user": func(f *graphFixture) { f.badGroup = true },
		"custodian_is_not_user":  func(f *graphFixture) { f.currentType = 4 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newGraphFixture(t)
			change(f)
			if err := f.a.CheckDocumentRelease(context.Background(), "parent", "7"); err == nil {
				t.Fatal("unproven restricted authority accepted")
			}
			if f.writes != 0 {
				t.Fatal("release check wrote remotely")
			}
		})
	}
}

func TestGraphReleaseBindsGraphDriveToSharePointFolder(t *testing.T) {
	for name, change := range map[string]func(*graphFixture){
		"wrong_list": func(f *graphFixture) {
			item := f.items["parent"]
			item.SharePointIDs.ListID = "other-list"
			f.items["parent"] = item
		},
		"wrong_site": func(f *graphFixture) {
			item := f.items["parent"]
			item.SharePointIDs.SiteID = "other-site"
			f.items["parent"] = item
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGraphFixture(t)
			change(f)
			if err := f.a.CheckDocumentRelease(context.Background(), "parent", "7"); err == nil {
				t.Fatal("unbound Graph item accepted as configured SharePoint folder")
			}
		})
	}
}

func TestGraphConfigFailsClosedWithoutSharePointAuthority(t *testing.T) {
	item := integration.Integration{Provider: SharePoint, Endpoint: "https://tenant.sharepoint.com/sites/security", Config: json.RawMessage(`{"drive_id":"drive","space":"parent","folder_path":"/sites/security/restricted","read_group":"7","custodian_principal_id":"9","data_class":"detail"}`)}
	if _, err := newGraph(item, integration.CredentialBundle{"access_token": "graph-token"}, selfhosted.Rules{}); err == nil {
		t.Fatal("missing SharePoint audience token accepted")
	}
	if _, err := newGraph(item, integration.CredentialBundle{"access_token": "graph-token", "sharepoint_token": "sp-token"}, selfhosted.Rules{}); err != nil {
		t.Fatalf("complete restricted profile rejected: %v", err)
	}
	item.Config = json.RawMessage(`{"drive_id":"b!drive","space":"parent","folder_path":"/sites/security/restricted","read_group":"7","custodian_principal_id":"9","data_class":"detail"}`)
	if _, err := newGraph(item, integration.CredentialBundle{"access_token": "graph-token", "sharepoint_token": "sp-token"}, selfhosted.Rules{}); err != nil {
		t.Fatalf("valid Microsoft Graph b! drive ID rejected: %v", err)
	}
}

func TestGraphDocumentLifecycleUsesSameOriginCASAndPermanentPurge(t *testing.T) {
	f := newGraphFixture(t)
	ctx := context.Background()
	shell, err := f.a.CreateDocumentShell(ctx, "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if shell.URL != "https://tenant.sharepoint.com/sites/security/restricted/synapse-intent-fixture" {
		t.Fatalf("shell URL must be the bound publication folder, got %q", shell.URL)
	}
	found, err := f.a.FindDocumentMarker(ctx, "parent", "synapse-intent-fixture")
	if err != nil || len(found) != 1 || !found[0].Neutral || found[0].Marker != "synapse-intent-fixture" {
		t.Fatalf("neutral recovery=%+v err=%v", found, err)
	}
	if err = f.a.UploadDocumentAttachment(ctx, shell.ID, ports.DocumentImage{Name: "chart one.png", MediaType: "image/png", Data: []byte("png")}); err != nil {
		t.Fatal(err)
	}
	storage := `<p>Report</p><image><attachment filename="chart one.png"/></image>`
	published, err := f.a.WriteDocumentRevision(ctx, shell, "Report", storage, "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	remote, err := f.a.GetDocument(ctx, published.ID)
	if err != nil || remote.Neutral || remote.Marker != "synapse-intent-fixture" || remote.Title != "Report" || remote.Storage != storage {
		t.Fatalf("readback=%+v err=%v", remote, err)
	}
	before := f.writes
	if _, err = f.a.WriteDocumentRevision(ctx, shell, "stale", "<p>stale</p>", "synapse-intent-stale"); err == nil {
		t.Fatal("stale opaque revision was accepted")
	}
	if f.writes != before {
		t.Fatal("stale revision issued a content write")
	}
	// A reconstructed adapter has no local ownership cache. The durable
	// manifest must authorize a new staged attachment for a republish.
	reconstructed := *f.a
	// The executor enters the restrictions step on every republish. A stable
	// logical ID must not be mistaken for a still-incomplete neutral shell.
	if err = reconstructed.RestrictDocument(ctx, published.ID, "7"); err != nil {
		t.Fatalf("published report restriction recheck altered the shell: %v", err)
	}
	if err = reconstructed.UploadDocumentAttachment(ctx, published.ID, ports.DocumentImage{Name: "closure.pdf", MediaType: "application/pdf", Data: []byte("pdf")}); err != nil {
		t.Fatal(err)
	}
	updatedStorage := `<p>Updated</p><link><attachment filename="closure.pdf"/></link>`
	republished, err := reconstructed.WriteDocumentRevision(ctx, published, "Updated report", updatedStorage, "synapse-intent-republish")
	if err != nil {
		t.Fatal(err)
	}
	remote, err = reconstructed.GetDocument(ctx, republished.ID)
	if err != nil || remote.Marker != "synapse-intent-republish" || remote.Title != "Updated report" || remote.Storage != updatedStorage {
		t.Fatalf("republish readback=%+v err=%v", remote, err)
	}
	guards := 0
	err = reconstructed.PurgeDocument(ctx, republished.ID, func(context.Context) error {
		guards++
		return nil
	})
	if err != nil || f.deletes != 5 || f.items["shell"].ID != "" {
		t.Fatalf("purge err=%v deletes=%d items=%v", err, f.deletes, f.items)
	}
}

func TestGraphRecoversEveryInterruptedNeutralShellStage(t *testing.T) {
	for name, interrupt := range map[string]func(*graphFixture){
		"folder":   func(f *graphFixture) { f.dropFolder = true },
		"body":     func(f *graphFixture) { f.dropBody = true },
		"manifest": func(f *graphFixture) { f.dropManifest = true },
	} {
		t.Run(name, func(t *testing.T) {
			f := newGraphFixture(t)
			interrupt(f)
			_, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
			var providerErr *ports.DocumentProviderError
			if !errors.As(err, &providerErr) || !providerErr.Ambiguous {
				t.Fatalf("lost create must be ambiguous, got %v", err)
			}

			// A new adapter instance has only the remote folder name and marker.
			// Find remains read-only; guarded RestrictDocument resumes exactly the
			// missing neutral files and never creates a second reservation.
			reconstructed := *f.a
			writesBeforeFind := f.writes
			matches, err := reconstructed.FindDocumentMarker(context.Background(), "parent", "synapse-intent-fixture")
			if err != nil || len(matches) != 1 || !matches[0].Neutral || matches[0].Marker != "synapse-intent-fixture" {
				t.Fatalf("exact neutral shell was not recoverable: matches=%+v err=%v", matches, err)
			}
			if f.writes != writesBeforeFind {
				t.Fatalf("marker search wrote while reconciling partial shell: before=%d after=%d", writesBeforeFind, f.writes)
			}
			beforeRestrict, err := reconstructed.GetDocument(context.Background(), matches[0].ID)
			if err != nil || !beforeRestrict.Neutral || beforeRestrict.ID != matches[0].ID || beforeRestrict.Revision != matches[0].Revision {
				t.Fatalf("partial shell was not readable for fenced restriction: state=%+v err=%v", beforeRestrict, err)
			}
			if err = reconstructed.RestrictDocument(context.Background(), matches[0].ID, "7"); err != nil {
				t.Fatalf("neutral shell resume failed: %v", err)
			}
			remote, err := reconstructed.GetDocument(context.Background(), matches[0].ID)
			if err != nil || !remote.Neutral || remote.Marker != "synapse-intent-fixture" {
				t.Fatalf("completed neutral shell=%+v err=%v", remote, err)
			}
			if f.writes != 3 || f.items["shell"].ID == "" || f.items["body"].ID == "" || f.items["manifest"].ID == "" {
				t.Fatalf("resume duplicated or missed neutral artifacts: writes=%d items=%+v", f.writes, f.items)
			}
		})
	}
}

func TestGraphShellFollowupFailureIsAmbiguousAfterFolderCreate(t *testing.T) {
	f := newGraphFixture(t)
	f.shellPublic = true
	_, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	var providerErr *ports.DocumentProviderError
	if !errors.As(err, &providerErr) || !providerErr.Ambiguous || providerErr.Code != "shell_incomplete" || f.items["shell"].ID == "" {
		t.Fatalf("shell follow-up failure lost its ambiguity fence: err=%v shell=%+v", err, f.items["shell"])
	}
}

func TestGraphShellFolderReadbackFailureIsAmbiguousAfterCreate(t *testing.T) {
	f := newGraphFixture(t)
	f.denyShellReadback = true
	_, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	var providerErr *ports.DocumentProviderError
	if !errors.As(err, &providerErr) || !providerErr.Ambiguous || providerErr.Code != "shell_incomplete" {
		t.Fatalf("folder readback failure lost create recovery fence: err=%v", err)
	}
	if f.items["shell"].ID == "" || f.writes != 1 {
		t.Fatalf("fixture did not retain the created folder: shell=%+v writes=%d", f.items["shell"], f.writes)
	}
}

func TestGraphRestrictFinalProofFailureIsAmbiguousAfterMaterializingShell(t *testing.T) {
	f := newGraphFixture(t)
	f.dropBody = true
	_, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	var providerErr *ports.DocumentProviderError
	if !errors.As(err, &providerErr) || !providerErr.Ambiguous {
		t.Fatalf("fixture did not create an interrupted neutral shell: err=%v", err)
	}
	f.denyProofAfterManifest = true
	err = f.a.RestrictDocument(context.Background(), "shell~synapse-intent-fixture", "7")
	if !errors.As(err, &providerErr) || !providerErr.Ambiguous || providerErr.Code != "shell_incomplete" {
		t.Fatalf("post-materialization proof failure lost recovery fence: err=%v", err)
	}
	if f.items["manifest"].ID == "" || f.writes != 3 {
		t.Fatalf("fixture did not materialize then fence the shell: manifest=%+v writes=%d", f.items["manifest"], f.writes)
	}
}

func TestGraphRestrictManifestPreflightFailureIsAmbiguousAfterBodyMaterializes(t *testing.T) {
	f := newGraphFixture(t)
	f.dropFolder = true
	_, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	var providerErr *ports.DocumentProviderError
	if !errors.As(err, &providerErr) || !providerErr.Ambiguous || f.items["shell"].ID == "" {
		t.Fatalf("fixture did not create a folder-only neutral shell: err=%v shell=%+v", err, f.items["shell"])
	}
	f.dropFolder = false
	f.denyProofAfterBody = true
	err = f.a.RestrictDocument(context.Background(), "shell~synapse-intent-fixture", "7")
	if !errors.As(err, &providerErr) || !providerErr.Ambiguous || providerErr.Code != "shell_incomplete" {
		t.Fatalf("post-body manifest preflight failure lost recovery fence: err=%v", err)
	}
	if f.items["body"].ID == "" || f.items["manifest"].ID != "" || f.writes != 2 {
		t.Fatalf("fixture did not stop at the fenced body materialization: body=%+v manifest=%+v writes=%d", f.items["body"], f.items["manifest"], f.writes)
	}
}

func TestGraphPendingPermanentDeleteStaysAmbiguous(t *testing.T) {
	f := newGraphFixture(t)
	f.pendingDelete = true
	err := f.a.permanentDelete(context.Background(), "parent")
	var providerErr *ports.DocumentProviderError
	if !errors.As(err, &providerErr) || !providerErr.Ambiguous || providerErr.Code != "permanent_delete_pending" || f.items["parent"].ID == "" {
		t.Fatalf("accepted queued permanent delete: err=%v item=%+v", err, f.items["parent"])
	}
}

func TestGraphPurgeUsesBoundOwnershipAfterSharingDrift(t *testing.T) {
	f := newGraphFixture(t)
	shell, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	published, err := f.a.WriteDocumentRevision(context.Background(), shell, "Report", "<p>report</p>", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	// The public link and additional role make a new publication fail closed,
	// but must not prevent permanent removal of the already-bound artifacts.
	f.links["parent"] = json.RawMessage(`{"scope":"organization"}`)
	f.roleExtra = true
	if _, err = f.a.GetDocument(context.Background(), published.ID); err != nil {
		t.Fatalf("identity read for unpublish failed after sharing drift: %v", err)
	}
	if err = f.a.PurgeDocument(context.Background(), published.ID, func(context.Context) error { return nil }); err != nil || f.deletes != 3 {
		t.Fatalf("purge did not remove exposed owned document: err=%v deletes=%d", err, f.deletes)
	}
}

func TestGraphPurgeKeepsRecoveryFenceAfterPartialPermanentDelete(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusPreconditionFailed, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newGraphFixture(t)
			shell, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
			if err != nil {
				t.Fatal(err)
			}
			f.deleteFailAfter, f.deleteFailStatus = 1, status
			err = f.a.PurgeDocument(context.Background(), shell.ID, func(context.Context) error { return nil })
			var providerErr *ports.DocumentProviderError
			if !errors.As(err, &providerErr) || !providerErr.Ambiguous || providerErr.Code != "purge_incomplete" {
				t.Fatalf("partial purge lost its recovery fence: err=%v", err)
			}
			if f.deletes != 1 || f.deleteAttempts != 2 {
				t.Fatalf("purge continued after rejected delete: deletes=%d attempts=%d", f.deletes, f.deleteAttempts)
			}
		})
	}
}

func TestGraphPurgeKeepsRecoveryFenceWhenGuardChangesAfterDelete(t *testing.T) {
	f := newGraphFixture(t)
	shell, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	guardCalls := 0
	err = f.a.PurgeDocument(context.Background(), shell.ID, func(context.Context) error {
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
	if f.deletes != 1 || f.deleteAttempts != 1 {
		t.Fatalf("purge issued a write after guard change: deletes=%d attempts=%d", f.deletes, f.deleteAttempts)
	}
}

func TestGraphPurgeValidatesAllChildrenBeforeDeletingAny(t *testing.T) {
	f := newGraphFixture(t)
	shell, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	manual := f.item("manual", "manual.txt", "shell", false, "manual-guid")
	f.items[manual.ID], f.contents[manual.ID], f.etags[manual.ID] = manual, []byte("manual"), `"1"`
	if err = f.a.PurgeDocument(context.Background(), shell.ID, func(context.Context) error { return nil }); err == nil {
		t.Fatal("unmanaged child accepted")
	}
	if f.deletes != 0 || f.deleteAttempts != 0 {
		t.Fatalf("purge deleted owned content before rejecting unmanaged child: deletes=%d attempts=%d", f.deletes, f.deleteAttempts)
	}
}

func TestGraphAttachmentPostCreateFailuresStayAmbiguous(t *testing.T) {
	for name, configure := range map[string]func(*graphFixture){
		"child_acl_forbidden":   func(f *graphFixture) { f.denyChildACL = true },
		"manifest_cas_conflict": func(f *graphFixture) { f.failManifestCAS = true },
	} {
		t.Run(name, func(t *testing.T) {
			f := newGraphFixture(t)
			shell, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
			if err != nil {
				t.Fatal(err)
			}
			configure(f)
			err = f.a.UploadDocumentAttachment(context.Background(), shell.ID, ports.DocumentImage{Name: "chart.png", MediaType: "image/png", Data: []byte("png")})
			var providerErr *ports.DocumentProviderError
			if !errors.As(err, &providerErr) || !providerErr.Ambiguous || providerErr.Code != "attachment_ownership_incomplete" {
				t.Fatalf("post-create attachment failure lost recovery fence: err=%v", err)
			}
			if f.items["attachment-1"].ID == "" {
				t.Fatal("fixture did not create the attachment before the follow-up failure")
			}
		})
	}
}

func TestGraphReadAndPreflightRequestBounds(t *testing.T) {
	f := newGraphFixture(t)
	ctx := context.Background()
	shell, err := f.a.CreateDocumentShell(ctx, "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	published, err := f.a.WriteDocumentRevision(ctx, shell, "Report", "<p>report</p>", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	requests := atomic.Int64{}
	f.a.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		return f.serve(r)
	})
	if _, err = f.a.GetDocument(ctx, published.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.a.VerifyDocumentRestriction(ctx, published.ID, "parent", "7"); err != nil {
		t.Fatal(err)
	}
	if requests.Load() > 26 {
		t.Fatalf("complete read plus restriction proof used %d requests; duplicate snapshot reads regressed", requests.Load())
	}
	t.Logf("complete read plus restriction proof requests=%d", requests.Load())

	requests.Store(0)
	if err = f.a.UploadDocumentAttachment(ctx, published.ID, ports.DocumentImage{Name: "chart.png", MediaType: "image/png", Data: []byte("png")}); err != nil {
		t.Fatal(err)
	}
	if requests.Load() > 32 {
		t.Fatalf("single attachment operation used %d requests; duplicate preflight regressed", requests.Load())
	}
	t.Logf("single attachment operation requests=%d", requests.Load())
}

func TestGraphUploadPreflightFailurePreventsWrite(t *testing.T) {
	f := newGraphFixture(t)
	shell, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	before := f.writes
	f.roleExtra = true
	err = f.a.UploadDocumentAttachment(context.Background(), shell.ID, ports.DocumentImage{Name: "chart.png", MediaType: "image/png", Data: []byte("png")})
	if err == nil || f.writes != before {
		t.Fatalf("failed fresh ACL proof wrote attachment: err=%v writes=%d before=%d", err, f.writes, before)
	}
}

func TestGraphElevenAttachmentMonitorCompletesWithinObservationBudget(t *testing.T) {
	f := newGraphFixture(t)
	ctx := context.Background()
	shell, err := f.a.CreateDocumentShell(ctx, "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	published, err := f.a.WriteDocumentRevision(ctx, shell, "Report", "<p>report</p>", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 11; i++ {
		name := "chart-" + strconv.Itoa(i) + ".png"
		if err = f.a.UploadDocumentAttachment(ctx, published.ID, ports.DocumentImage{Name: name, MediaType: "image/png", Data: []byte("png")}); err != nil {
			t.Fatalf("seed attachment %d: %v", i, err)
		}
	}
	requests := atomic.Int64{}
	f.a.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		select {
		case <-time.After(100 * time.Millisecond):
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return f.serve(r)
	})
	check, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	started := time.Now()
	if _, err = f.a.GetDocument(check, published.ID); err == nil {
		err = f.a.VerifyDocumentRestriction(check, published.ID, "parent", "7")
	}
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("eleven-attachment monitor exceeded observation budget after %s (%d requests): %v", elapsed, requests.Load(), err)
	}
	if elapsed >= 9*time.Second {
		t.Fatalf("eleven-attachment monitor used %s (%d requests); bounded child checks did not meet the budget", elapsed, requests.Load())
	}
	t.Logf("eleven-attachment monitor requests=%d synthetic-rtt elapsed=%s", requests.Load(), elapsed)
}

func TestGraphRefusesUnsafeAttachmentCollisionAndChildLink(t *testing.T) {
	f := newGraphFixture(t)
	shell, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.a.UploadDocumentAttachment(context.Background(), shell.ID, ports.DocumentImage{Name: "chart.png", MediaType: "image/png", Data: []byte("one")}); err != nil {
		t.Fatal(err)
	}
	if err = f.a.UploadDocumentAttachment(context.Background(), shell.ID, ports.DocumentImage{Name: "chart.png", MediaType: "image/png", Data: []byte("two")}); err == nil {
		t.Fatal("attachment overwrite accepted")
	}
	f.links["attachment-1"] = json.RawMessage(`{"scope":"anonymous"}`)
	if err = f.a.VerifyDocumentRestriction(context.Background(), shell.ID, "parent", "7"); err == nil {
		t.Fatal("anonymous child sharing accepted")
	}
}

func TestGraphRefusesManualChildOutsideDurableManifest(t *testing.T) {
	f := newGraphFixture(t)
	shell, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	f.items["manual"] = f.item("manual", "manual.pdf", "shell", false, "manual-guid")
	f.contents["manual"] = []byte("manual")
	f.etags["manual"] = `"1"`
	if err = f.a.VerifyDocumentRestriction(context.Background(), shell.ID, "parent", "7"); err == nil {
		t.Fatal("manual child not listed in ownership manifest accepted")
	}
}

func TestGraphErrorsRedactTokens(t *testing.T) {
	f := newGraphFixture(t)
	f.a.client = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("https://user:graph-token@invalid/sp-token")
	})}
	_, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	if err == nil || strings.Contains(err.Error(), "graph-token") || strings.Contains(err.Error(), "sp-token") {
		t.Fatalf("unsafe provider error: %v", err)
	}
}

func TestGraphHTMLUsesOnlyRelativeAttachmentReferences(t *testing.T) {
	raw, err := encodeGraphHTML("Report", `<image><attachment filename="chart.png"/></image>`, "synapse-intent-fixture", map[string]string{"chart.png": "attachment"})
	if err != nil || strings.Contains(string(raw), "drive.google.com") || !strings.Contains(string(raw), `src="./chart.png"`) {
		t.Fatalf("unsafe graph HTML: %q err=%v", raw, err)
	}
}

func TestGraphChildProofRefusesCanceledContextBeforeRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &graphAdapter{client: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		t.Error("canceled child proof initiated a request")
		return nil, errors.New("unexpected request")
	})}}
	for _, children := range [][]graphItem{nil, {{ID: "child", Name: "report.html"}}} {
		if err := a.verifyDocumentChildren(ctx, children, "/sites/security/restricted", true); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled child proof succeeded: %v", err)
		}
	}
}

func TestGraphPurge404DoesNotProveRemoval(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			f := newGraphFixture(t)
			shell, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			f.a.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/permanentDelete") {
					calls++
					if calls == failAt {
						return response(http.StatusNotFound, nil), nil
					}
				}
				return f.serve(r)
			})
			err = f.a.PurgeDocument(context.Background(), shell.ID, func(context.Context) error { return nil })
			var p *ports.DocumentProviderError
			if !errors.As(err, &p) || !p.Ambiguous || p.Code != "purge_incomplete" || calls != failAt || f.items["shell"].ID == "" {
				t.Fatalf("404 cleared purge fence: err=%v calls=%d items=%+v", err, calls, f.items)
			}
		})
	}
}
func TestGraphNeutralBodyReadbackMismatchPreservesUncertainty(t *testing.T) {
	f := newGraphFixture(t)
	f.dropFolder = true
	_, err := f.a.CreateDocumentShell(context.Background(), "parent", "synapse-intent-fixture")
	if err == nil {
		t.Fatal("missing interruption")
	}
	f.dropFolder = false
	f.a.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := f.serve(r)
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "Files/add") && f.items["body"].ID != "" {
			f.contents["body"] = []byte("unexpected body")
		}
		return resp, err
	})
	err = f.a.RestrictDocument(context.Background(), "shell~synapse-intent-fixture", "7")
	var p *ports.DocumentProviderError
	if !errors.As(err, &p) || !p.Ambiguous || p.Code != "shell_incomplete" || f.writes != 2 || f.items["manifest"].ID != "" {
		t.Fatalf("post-create mismatch cleared fence: err=%v writes=%d items=%+v", err, f.writes, f.items)
	}
}
