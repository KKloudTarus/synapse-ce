package documentproviders

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	graphNeutralShell = "<!-- synapse neutral shell -->"
	graphManifestName = "synapse-ownership.json"
)

func graphContentHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func splitGraphPage(v string) (string, string, error) {
	p := strings.Split(v, "~")
	if len(p) != 2 || !safeID(p[0]) || !safeID(p[1]) {
		return "", "", shared.ErrValidation
	}
	return p[0], p[1], nil
}
func (a *graphAdapter) graphRemote(pageID, etag string) docpublish.RemotePage {
	folderPath := a.folderPath
	// Logical page IDs are anchored by the server-issued folder ID and the
	// validated reservation marker. Build the user-visible location from that
	// local contract rather than an arbitrary provider webUrl response.
	if _, marker, err := splitGraphPage(pageID); err == nil && validMarker(marker) {
		folderPath = graphChildPath(folderPath, marker)
	}
	u := url.URL{Scheme: a.site.Scheme, Host: a.site.Host, Path: folderPath}
	return docpublish.RemotePage{ID: pageID, Version: 1, Revision: etag, URL: u.String()}
}
func (a *graphAdapter) ValidateDocumentText(v string) error {
	if containsCredential(v, a.token) || containsCredential(v, a.sharePointToken) {
		return docError(0, "credential_in_payload", false)
	}
	return nil
}
func (a *graphAdapter) graph(ctx context.Context, method, p string, q url.Values, body []byte, headers http.Header, out any, want ...int) (http.Header, error) {
	u := url.URL{Scheme: "https", Host: "graph.microsoft.com", Path: "/v1.0" + p, RawQuery: q.Encode()}
	req, e := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if e != nil {
		return nil, docError(0, "invalid_request", false)
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header[k] = append([]string(nil), v...)
	}
	data, h, e := readResponse(a.client, req, 24<<20, want...)
	if e != nil {
		return nil, e
	}
	if out != nil && (strings.Contains(string(data), a.token) || strings.Contains(string(data), a.sharePointToken) || json.Unmarshal(data, out) != nil) {
		return nil, docError(http.StatusOK, "unsafe_provider_response", method != http.MethodGet)
	}
	return h, nil
}

type graphItem struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	ETag          string             `json:"eTag"`
	Folder        json.RawMessage    `json:"folder"`
	File          json.RawMessage    `json:"file"`
	Deleted       json.RawMessage    `json:"deleted"`
	SharePointIDs graphSharePointIDs `json:"sharepointIds"`
	Parent        struct {
		ID      string `json:"id"`
		DriveID string `json:"driveId"`
	} `json:"parentReference"`
}

func (a *graphAdapter) graphItem(ctx context.Context, id string) (graphItem, error) {
	var it graphItem
	if !safeID(id) {
		return it, shared.ErrValidation
	}
	_, e := a.graph(ctx, http.MethodGet, "/drives/"+a.drive+"/items/"+id, url.Values{"$select": {"id,name,eTag,folder,file,deleted,parentReference,sharepointIds"}}, nil, nil, &it, http.StatusOK)
	if e != nil {
		return it, e
	}
	if it.ID != id || it.Name == "" || len(it.Name) > 255 || !safeID(it.ID) || (len(it.Deleted) > 0 && string(it.Deleted) != "null") || normalizedGUID(it.SharePointIDs.ListID) == "" || normalizedGUID(it.SharePointIDs.ListItemUniqueID) == "" || normalizedGUID(it.SharePointIDs.SiteID) == "" {
		return it, docError(http.StatusOK, "invalid_remote_identity", false)
	}
	return it, nil
}

func (a *graphAdapter) graphChild(ctx context.Context, folder, name string) (graphItem, error) {
	if !safeID(folder) || (name != "report.html" && name != graphManifestName && !validAttachmentName(name)) {
		return graphItem{}, shared.ErrValidation
	}
	var out graphItem
	// graph builds the URL from Path, so pass the validated filename exactly;
	// pre-escaping here would turn a space into %2520 on the wire.
	_, err := a.graph(ctx, http.MethodGet, "/drives/"+a.drive+"/items/"+folder+":/"+name, nil, nil, nil, &out, http.StatusOK)
	if err != nil {
		return graphItem{}, err
	}
	if out.ID == "" || out.Name != name || out.Parent.ID != folder {
		return graphItem{}, docError(http.StatusOK, "invalid_remote_identity", false)
	}
	return a.graphItem(ctx, out.ID)
}

func (a *graphAdapter) children(ctx context.Context, parent string) ([]graphItem, error) {
	if !safeID(parent) {
		return nil, shared.ErrValidation
	}
	var out struct {
		Value []graphItem `json:"value"`
		Next  string      `json:"@odata.nextLink"`
	}
	_, err := a.graph(ctx, http.MethodGet, "/drives/"+a.drive+"/items/"+parent+"/children", url.Values{"$select": {"id,name,eTag,folder,file,deleted,parentReference,sharepointIds"}, "$top": {"200"}}, nil, nil, &out, http.StatusOK)
	if err != nil {
		return nil, err
	}
	if out.Next != "" || len(out.Value) > 200 {
		return nil, docError(http.StatusOK, "incomplete_children", false)
	}
	seen := make(map[string]bool, len(out.Value))
	for i := range out.Value {
		item := out.Value[i]
		if !safeID(item.ID) || seen[item.ID] || item.Parent.ID != parent || item.Parent.DriveID != a.drive || item.Name == "" || len(item.Name) > 255 || (len(item.Deleted) > 0 && string(item.Deleted) != "null") || (!presentFacet(item.File) && !presentFacet(item.Folder)) || (presentFacet(item.File) && presentFacet(item.Folder)) {
			return nil, docError(http.StatusOK, "invalid_child", false)
		}
		seen[item.ID] = true
	}
	return out.Value, nil
}

func graphChildPath(folderPath, name string) string { return path.Join(folderPath, name) }

func (a *graphAdapter) createShellFolder(ctx context.Context, marker string) (graphItem, error) {
	raw, _ := json.Marshal(map[string]any{"name": marker, "folder": map[string]any{}, "@microsoft.graph.conflictBehavior": "fail"})
	var created graphItem
	_, err := a.graph(ctx, http.MethodPost, "/drives/"+a.drive+"/items/"+a.container+"/children", nil, raw, http.Header{"Content-Type": {"application/json"}}, &created, http.StatusCreated)
	if err == nil {
		if !safeID(created.ID) || created.Name != marker || !presentFacet(created.Folder) || created.Parent.ID != a.container {
			return graphItem{}, docError(http.StatusCreated, "invalid_shell_response", true)
		}
		item, readErr := a.graphItem(ctx, created.ID)
		if readErr != nil {
			return graphItem{}, shellAmbiguity(readErr)
		}
		return item, nil
	}
	// A collision can be the exact existing shell after an interrupted create.
	// Resolve only that marker under the configured container; no broad search or
	// arbitrary remote URL is used.
	var providerErr *ports.DocumentProviderError
	if !isConflict(err, &providerErr) {
		return graphItem{}, err
	}
	items, listErr := a.children(ctx, a.container)
	if listErr != nil {
		return graphItem{}, err
	}
	for _, item := range items {
		if item.Name == marker && presentFacet(item.Folder) {
			return a.graphItem(ctx, item.ID)
		}
	}
	return graphItem{}, err
}

func isConflict(err error, target **ports.DocumentProviderError) bool {
	return errors.As(err, target) && (*target).Status == http.StatusConflict
}

func shellAmbiguity(err error) error {
	if err == nil {
		return nil
	}
	var providerErr *ports.DocumentProviderError
	if errors.As(err, &providerErr) {
		return docError(providerErr.Status, "shell_incomplete", true)
	}
	return docError(0, "shell_incomplete", true)
}

// partialEffectAmbiguity preserves the reconciliation fence after a remote
// mutation has succeeded. The operation can no longer be retried as a clean
// failure: a later local guard, readback, or provider rejection may leave an
// owned remote artifact outside the durable ownership record.
func partialEffectAmbiguity(err error, code string) error {
	if err == nil {
		return nil
	}
	var providerErr *ports.DocumentProviderError
	if errors.As(err, &providerErr) {
		return docError(providerErr.Status, code, true)
	}
	return docError(0, code, true)
}

func (a *graphAdapter) CreateDocumentShell(ctx context.Context, container, marker string) (docpublish.RemotePage, error) {
	if !validMarker(marker) {
		return docpublish.RemotePage{}, shared.ErrValidation
	}
	if err := a.CheckDocumentRelease(ctx, container, a.group); err != nil {
		return docpublish.RemotePage{}, err
	}
	folder, err := a.createShellFolder(ctx, marker)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	folderRef := graphChildPath(a.folderPath, marker)
	if err = a.verifyChildACL(ctx, folder, folderRef, true); err != nil {
		return docpublish.RemotePage{}, shellAmbiguity(err)
	}
	if err = a.CheckDocumentRelease(ctx, container, a.group); err != nil {
		return docpublish.RemotePage{}, shellAmbiguity(err)
	}
	// Files/add with overwrite=false is the SharePoint REST create precondition;
	// it avoids a redirecting Graph /content endpoint and never overwrites a
	// recovered shell body.
	create := "/_api/web/GetFolderByServerRelativeUrl(" + spQuote(folderRef) + ")/Files/add(url='report.html',overwrite=false)"
	if _, _, err = a.spBytes(ctx, http.MethodPost, create, http.Header{"Content-Type": {"text/html"}}, []byte(graphNeutralShell), http.StatusOK, http.StatusCreated); err != nil {
		return docpublish.RemotePage{}, shellAmbiguity(err)
	}
	body, err := a.graphChild(ctx, folder.ID, "report.html")
	if err != nil {
		return docpublish.RemotePage{}, shellAmbiguity(err)
	}
	bodyRef := graphChildPath(folderRef, "report.html")
	if !presentFacet(body.File) || (body.Parent.ID != folder.ID) {
		return docpublish.RemotePage{}, docError(http.StatusOK, "invalid_shell_response", true)
	}
	if err = a.verifyChildACL(ctx, body, bodyRef, false); err != nil {
		return docpublish.RemotePage{}, shellAmbiguity(err)
	}
	manifestRaw, _ := encodeGraphManifest(graphOwnershipManifest{Marker: marker, Files: map[string]string{}})
	manifestCreate := "/_api/web/GetFolderByServerRelativeUrl(" + spQuote(folderRef) + ")/Files/add(url='" + graphManifestName + "',overwrite=false)"
	if _, _, err = a.spBytes(ctx, http.MethodPost, manifestCreate, http.Header{"Content-Type": {"application/json"}}, manifestRaw, http.StatusOK, http.StatusCreated); err != nil {
		return docpublish.RemotePage{}, shellAmbiguity(err)
	}
	manifest, err := a.graphChild(ctx, folder.ID, graphManifestName)
	if err != nil {
		return docpublish.RemotePage{}, shellAmbiguity(err)
	}
	manifestRef := graphChildPath(folderRef, graphManifestName)
	if err = a.verifyChildACL(ctx, manifest, manifestRef, false); err != nil {
		return docpublish.RemotePage{}, shellAmbiguity(err)
	}
	if checked, _, _, checkErr := a.manifestSnapshot(ctx, folderRef, []graphItem{body, manifest}); checkErr != nil {
		return docpublish.RemotePage{}, shellAmbiguity(checkErr)
	} else if checked.Marker != marker || len(checked.Files) != 0 {
		return docpublish.RemotePage{}, docError(http.StatusOK, "invalid_ownership_manifest", true)
	}
	etag, err := a.spFileETag(ctx, bodyRef)
	if err != nil {
		return docpublish.RemotePage{}, shellAmbiguity(err)
	}
	return a.graphRemote(folder.ID+"~"+marker, etag), nil
}

// RestrictDocument is the only write-resume operation for a recovered neutral
// reservation. It never creates another folder or replaces an existing file:
// every partially-created object is read back, bound, and proved neutral before
// the next missing object is created with overwrite=false.
func (a *graphAdapter) RestrictDocument(ctx context.Context, page, group string) error {
	if group != a.group {
		return shared.ErrConflict
	}
	folderID, marker, err := splitGraphPage(page)
	if err != nil {
		return err
	}
	// A logical ID always includes the reservation marker. Complete a shell
	// only when the identity/content read proves it is still neutral; a normal
	// published page must retain its body and durable attachment manifest.
	current, err := a.GetDocument(ctx, page)
	if err != nil {
		return err
	}
	if current.Neutral && validMarker(marker) {
		return a.completeNeutralShell(ctx, folderID, marker)
	}
	return a.VerifyDocumentRestriction(ctx, page, a.container, group)
}

func (a *graphAdapter) neutralShellItems(ctx context.Context, folder graphItem, marker string, enforceACL bool) (map[string]graphItem, string, error) {
	if !presentFacet(folder.Folder) || folder.Parent.ID != a.container || folder.Parent.DriveID != a.drive || folder.Name != marker {
		return nil, "", docError(http.StatusOK, "remote_identity_changed", false)
	}
	folderRef := graphChildPath(a.folderPath, marker)
	if enforceACL {
		if err := a.verifyChildACL(ctx, folder, folderRef, true); err != nil {
			return nil, "", err
		}
	} else if err := a.verifyChildBinding(ctx, folder, folderRef, true); err != nil {
		return nil, "", err
	}
	children, err := a.children(ctx, folder.ID)
	if err != nil {
		return nil, "", err
	}
	items := make(map[string]graphItem, len(children))
	for _, child := range children {
		if !presentFacet(child.File) || presentFacet(child.Folder) || (child.Name != "report.html" && child.Name != graphManifestName) || items[child.Name].ID != "" {
			return nil, "", docError(http.StatusOK, "invalid_neutral_shell", false)
		}
		if enforceACL {
			if err := a.verifyChildACL(ctx, child, graphChildPath(folderRef, child.Name), false); err != nil {
				return nil, "", err
			}
		} else if err := a.verifyChildBinding(ctx, child, graphChildPath(folderRef, child.Name), false); err != nil {
			return nil, "", err
		}
		items[child.Name] = child
	}
	return items, folderRef, nil
}

func (a *graphAdapter) ensureNeutralFile(ctx context.Context, folder graphItem, folderRef, name string, raw []byte) (graphItem, bool, error) {
	items, _, err := a.neutralShellItems(ctx, folder, folder.Name, true)
	if err != nil {
		return graphItem{}, false, err
	}
	if existing := items[name]; existing.ID != "" {
		confirmed, _, readErr := a.bodySnapshot(ctx, graphChildPath(folderRef, name))
		if readErr != nil {
			return graphItem{}, false, readErr
		}
		if !bytes.Equal(confirmed, raw) {
			return graphItem{}, false, docError(http.StatusOK, "invalid_neutral_shell", false)
		}
		return existing, false, nil
	}
	// Authentication, binding, and the full effective ACL are rechecked directly
	// before every outward content write.
	if err = a.CheckDocumentRelease(ctx, a.container, a.group); err != nil {
		return graphItem{}, false, err
	}
	resource := "/_api/web/GetFolderByServerRelativeUrl(" + spQuote(folderRef) + ")/Files/add(url='" + name + "',overwrite=false)"
	contentType := "text/html"
	if name == graphManifestName {
		contentType = "application/json"
	}
	_, _, err = a.spBytes(ctx, http.MethodPost, resource, http.Header{"Content-Type": {contentType}}, raw, http.StatusOK, http.StatusCreated)
	created := err == nil
	if err != nil {
		var providerErr *ports.DocumentProviderError
		if !isConflict(err, &providerErr) {
			return graphItem{}, false, shellAmbiguity(err)
		}
	}
	item, readErr := a.graphChild(ctx, folder.ID, name)
	if readErr != nil {
		return graphItem{}, false, shellAmbiguity(readErr)
	}
	if readErr = a.verifyChildACL(ctx, item, graphChildPath(folderRef, name), false); readErr != nil {
		return graphItem{}, false, shellAmbiguity(readErr)
	}
	confirmed, _, readErr := a.bodySnapshot(ctx, graphChildPath(folderRef, name))
	if readErr != nil {
		return graphItem{}, false, shellAmbiguity(readErr)
	}
	if !bytes.Equal(confirmed, raw) {
		conflict := docError(http.StatusConflict, "neutral_shell_name_conflict", false)
		if created {
			return graphItem{}, false, shellAmbiguity(conflict)
		}
		return graphItem{}, false, conflict
	}
	return item, created, nil
}

func (a *graphAdapter) completeNeutralShell(ctx context.Context, folderID, marker string) error {
	if err := a.CheckDocumentRelease(ctx, a.container, a.group); err != nil {
		return err
	}
	folder, err := a.graphItem(ctx, folderID)
	if err != nil {
		return err
	}
	if !presentFacet(folder.Folder) || folder.Parent.ID != a.container || folder.Parent.DriveID != a.drive || folder.Name != marker {
		return docError(http.StatusOK, "remote_identity_changed", false)
	}
	folderRef := graphChildPath(a.folderPath, marker)
	_, bodyCreated, err := a.ensureNeutralFile(ctx, folder, folderRef, "report.html", []byte(graphNeutralShell))
	if err != nil {
		return err
	}
	manifestRaw, _ := encodeGraphManifest(graphOwnershipManifest{Marker: marker, Files: map[string]string{}})
	_, manifestCreated, err := a.ensureNeutralFile(ctx, folder, folderRef, graphManifestName, manifestRaw)
	if err != nil {
		if bodyCreated {
			return shellAmbiguity(err)
		}
		return err
	}
	// Read the finished reservation through the ordinary restricted verifier.
	if err = a.VerifyDocumentRestriction(ctx, folder.ID+"~"+marker, a.container, a.group); err != nil && (bodyCreated || manifestCreated) {
		return shellAmbiguity(err)
	}
	return err
}

func (a *graphAdapter) verifyDocumentChildren(ctx context.Context, children []graphItem, folderRef string, enforceACL bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Child permission and binding requests are independent read-only proofs.
	// Keep bounded parallelism so an attachment-heavy report stays within the
	// monitor budget without creating an unbounded provider request fan-out.
	checkCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var firstErr error
	var lock sync.Mutex
	for _, child := range children {
		child := child
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-checkCtx.Done():
				return
			}
			defer func() { <-sem }()
			ref := graphChildPath(folderRef, child.Name)
			var err error
			if enforceACL {
				err = a.verifyChildACL(checkCtx, child, ref, false)
			} else {
				err = a.verifyChildBinding(checkCtx, child, ref, false)
			}
			if err != nil {
				lock.Lock()
				if firstErr == nil {
					firstErr = err
					cancel()
				}
				lock.Unlock()
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

func (a *graphAdapter) documentItems(ctx context.Context, page, container, group string, enforceACL bool) (graphItem, graphItem, []graphItem, string, error) {
	folderID, bodyID, err := splitGraphPage(page)
	if err != nil {
		return graphItem{}, graphItem{}, nil, "", err
	}
	if container != a.container || (enforceACL && group != a.group) {
		return graphItem{}, graphItem{}, nil, "", shared.ErrConflict
	}
	if enforceACL {
		err = a.CheckDocumentRelease(ctx, container, group)
	} else {
		err = a.checkDestinationIdentity(ctx)
	}
	if err != nil {
		return graphItem{}, graphItem{}, nil, "", err
	}
	folder, err := a.graphItem(ctx, folderID)
	if err != nil {
		return graphItem{}, graphItem{}, nil, "", err
	}
	logicalPage := validMarker(bodyID)
	if !presentFacet(folder.Folder) || folder.Parent.ID != container || folder.Parent.DriveID != a.drive || !validMarker(folder.Name) || (logicalPage && folder.Name != bodyID) {
		return graphItem{}, graphItem{}, nil, "", docError(http.StatusOK, "remote_identity_changed", false)
	}
	folderRef := graphChildPath(a.folderPath, folder.Name)
	if enforceACL {
		err = a.verifyChildACL(ctx, folder, folderRef, true)
	} else {
		err = a.verifyChildBinding(ctx, folder, folderRef, true)
	}
	if err != nil {
		return graphItem{}, graphItem{}, nil, "", err
	}
	children, err := a.children(ctx, folderID)
	if err != nil {
		return graphItem{}, graphItem{}, nil, "", err
	}
	var body graphItem
	foundBody := false
	for _, child := range children {
		if !presentFacet(child.File) || presentFacet(child.Folder) || (child.Name != "report.html" && child.Name != graphManifestName && !validAttachmentName(child.Name)) {
			return graphItem{}, graphItem{}, nil, "", docError(http.StatusOK, "unmanaged_child", false)
		}
		if (logicalPage && child.Name == "report.html") || (!logicalPage && child.ID == bodyID) {
			if foundBody || child.Name != "report.html" {
				return graphItem{}, graphItem{}, nil, "", docError(http.StatusOK, "remote_identity_changed", false)
			}
			body, foundBody = child, true
		}
	}
	if !foundBody {
		return graphItem{}, graphItem{}, nil, "", docError(http.StatusOK, "remote_identity_changed", false)
	}
	if err = a.verifyDocumentChildren(ctx, children, folderRef, enforceACL); err != nil {
		return graphItem{}, graphItem{}, nil, "", err
	}
	return folder, body, children, folderRef, nil
}

func (a *graphAdapter) bodySnapshot(ctx context.Context, bodyRef string) ([]byte, string, error) {
	returnData, headers, err := a.spBytes(ctx, http.MethodGet, "/_api/web/GetFileByServerRelativeUrl("+spQuote(bodyRef)+")/$value", nil, nil, http.StatusOK)
	if err != nil {
		return nil, "", err
	}
	if err = a.ValidateDocumentText(string(returnData)); err != nil {
		return nil, "", err
	}
	etag := headers.Get("ETag")
	if etag == "" || len(etag) > 512 || strings.ContainsAny(etag, "\r\n") || containsCredential(etag, a.token) || containsCredential(etag, a.sharePointToken) {
		return nil, "", docError(http.StatusOK, "snapshot_revision_unavailable", false)
	}
	return returnData, etag, nil
}

func (a *graphAdapter) bodySource(ctx context.Context, bodyRef string) ([]byte, error) {
	raw, _, err := a.bodySnapshot(ctx, bodyRef)
	return raw, err
}

type graphOwnershipManifest struct {
	Marker string            `json:"marker"`
	Files  map[string]string `json:"files"`
}

func encodeGraphManifest(manifest graphOwnershipManifest) ([]byte, error) {
	if !validMarker(manifest.Marker) || len(manifest.Files) > 256 {
		return nil, shared.ErrValidation
	}
	for name, id := range manifest.Files {
		if !validAttachmentName(name) || !safeID(id) {
			return nil, shared.ErrValidation
		}
	}
	return json.Marshal(manifest)
}

func decodeGraphManifest(raw []byte) (graphOwnershipManifest, error) {
	var manifest graphOwnershipManifest
	if json.Unmarshal(raw, &manifest) != nil {
		return graphOwnershipManifest{}, docError(http.StatusOK, "invalid_ownership_manifest", false)
	}
	canonical, err := encodeGraphManifest(manifest)
	if err != nil || !bytes.Equal(canonical, raw) {
		return graphOwnershipManifest{}, docError(http.StatusOK, "invalid_ownership_manifest", false)
	}
	return manifest, nil
}

func graphManifestItem(children []graphItem) (graphItem, error) {
	var manifest graphItem
	for _, child := range children {
		if child.Name != graphManifestName {
			continue
		}
		if manifest.ID != "" || !presentFacet(child.File) {
			return graphItem{}, docError(http.StatusOK, "invalid_ownership_manifest", false)
		}
		manifest = child
	}
	if manifest.ID == "" {
		return graphItem{}, docError(http.StatusOK, "ownership_manifest_missing", false)
	}
	return manifest, nil
}

func (a *graphAdapter) manifestSnapshot(ctx context.Context, folderRef string, children []graphItem) (graphOwnershipManifest, graphItem, string, error) {
	item, err := graphManifestItem(children)
	if err != nil {
		return graphOwnershipManifest{}, graphItem{}, "", err
	}
	raw, etag, err := a.bodySnapshot(ctx, graphChildPath(folderRef, graphManifestName))
	if err != nil {
		return graphOwnershipManifest{}, graphItem{}, "", err
	}
	manifest, err := decodeGraphManifest(raw)
	if err != nil {
		return graphOwnershipManifest{}, graphItem{}, "", err
	}
	return manifest, item, etag, nil
}

func (a *graphAdapter) writeManifest(ctx context.Context, folderRef string, item graphItem, expectedETag string, manifest graphOwnershipManifest) error {
	raw, err := encodeGraphManifest(manifest)
	if err != nil {
		return err
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("If-Match", expectedETag)
	headers.Set("X-HTTP-Method", "PUT")
	fileRef := graphChildPath(folderRef, graphManifestName)
	if _, _, err = a.spBytes(ctx, http.MethodPost, "/_api/web/GetFileByServerRelativeUrl("+spQuote(fileRef)+")/$value", headers, raw, http.StatusOK, http.StatusNoContent); err != nil {
		return err
	}
	confirmed, _, err := a.bodySnapshot(ctx, fileRef)
	if err != nil {
		return docError(http.StatusOK, "manifest_readback_unavailable", true)
	}
	if !bytes.Equal(confirmed, raw) || item.Name != graphManifestName {
		return docError(http.StatusOK, "manifest_readback_invalid", true)
	}
	return nil
}

func (a *graphAdapter) validateDocumentOwnership(ctx context.Context, folder, body graphItem, children []graphItem, folderRef string, raw []byte) (graphOwnershipManifest, *htmlSource, error) {
	manifest, manifestItem, _, err := a.manifestSnapshot(ctx, folderRef, children)
	if err != nil {
		return graphOwnershipManifest{}, nil, err
	}
	if manifest.Marker != folder.Name {
		return graphOwnershipManifest{}, nil, docError(http.StatusOK, "invalid_ownership_manifest", false)
	}
	known := map[string]string{"report.html": body.ID, graphManifestName: manifestItem.ID}
	for name, id := range manifest.Files {
		if !validAttachmentName(name) || !safeID(id) || known[name] != "" {
			return graphOwnershipManifest{}, nil, docError(http.StatusOK, "invalid_ownership_manifest", false)
		}
		known[name] = id
	}
	if len(known) != len(children) {
		return graphOwnershipManifest{}, nil, docError(http.StatusOK, "unmanaged_child", false)
	}
	for _, child := range children {
		if known[child.Name] != child.ID {
			return graphOwnershipManifest{}, nil, docError(http.StatusOK, "unmanaged_child", false)
		}
	}
	if string(raw) == graphNeutralShell {
		return manifest, nil, nil
	}
	source, err := decodeGraphHTML(raw)
	if err != nil || !validMarker(source.Marker) || source.Title == "" {
		return graphOwnershipManifest{}, nil, docError(http.StatusOK, "invalid_source", false)
	}
	for name, id := range source.Files {
		if manifest.Files[name] != id {
			return graphOwnershipManifest{}, nil, docError(http.StatusOK, "invalid_source", false)
		}
	}
	return manifest, &source, nil
}

type graphDocumentSnapshot struct {
	folder, body graphItem
	children     []graphItem
	folderRef    string
	raw          []byte
	etag         string
	manifest     graphOwnershipManifest
	source       *htmlSource
}

func (a *graphAdapter) readCompleteDocument(ctx context.Context, page, container, group string, enforceACL bool) (graphDocumentSnapshot, error) {
	folder, body, children, folderRef, err := a.documentItems(ctx, page, container, group, enforceACL)
	if err != nil {
		return graphDocumentSnapshot{}, err
	}
	raw, etag, err := a.bodySnapshot(ctx, graphChildPath(folderRef, "report.html"))
	if err != nil {
		return graphDocumentSnapshot{}, err
	}
	manifest, source, err := a.validateDocumentOwnership(ctx, folder, body, children, folderRef, raw)
	if err != nil {
		return graphDocumentSnapshot{}, err
	}
	return graphDocumentSnapshot{folder: folder, body: body, children: children, folderRef: folderRef, raw: raw, etag: etag, manifest: manifest, source: source}, nil
}

func (a *graphAdapter) remoteState(page string, snapshot graphDocumentSnapshot) ports.DocumentRemoteState {
	out := ports.DocumentRemoteState{RemotePage: a.graphRemote(page, snapshot.etag), Container: a.container, Marker: snapshot.folder.Name, ContentHash: graphContentHash(snapshot.raw), Neutral: snapshot.source == nil}
	if snapshot.source != nil {
		out.Title, out.Storage, out.Marker = snapshot.source.Title, snapshot.source.Storage, snapshot.source.Marker
	}
	return out
}

func (a *graphAdapter) VerifyDocumentRestriction(ctx context.Context, page, container, group string) error {
	_, err := a.readCompleteDocument(ctx, page, container, group, true)
	return err
}

func (a *graphAdapter) GetDocument(ctx context.Context, page string) (ports.DocumentRemoteState, error) {
	// Complete documents are the steady state. Read them first so normal
	// monitor, attachment, and revision paths do not probe the partial-shell
	// representation and repeat every Graph/SharePoint identity read.
	snapshot, completeErr := a.readCompleteDocument(ctx, page, a.container, a.group, false)
	if completeErr == nil {
		return a.remoteState(page, snapshot), nil
	}
	folderID, marker, splitErr := splitGraphPage(page)
	if splitErr != nil {
		return ports.DocumentRemoteState{}, splitErr
	}
	// A reconciler may know that a create reached the folder but not which
	// neutral file acknowledgement was lost. This identity-only fallback
	// preserves the uncertainty fence; it performs no ACL proof and cannot
	// publish data. It is only reached when a complete snapshot was unavailable.
	if validMarker(marker) {
		if err := a.checkDestinationIdentity(ctx); err != nil {
			return ports.DocumentRemoteState{}, err
		}
		folder, err := a.graphItem(ctx, folderID)
		if err != nil {
			return ports.DocumentRemoteState{}, err
		}
		partial, recoverable, err := a.partialNeutralState(ctx, folder, marker, false)
		if err != nil {
			return ports.DocumentRemoteState{}, err
		}
		if recoverable {
			return partial, nil
		}
	}
	return ports.DocumentRemoteState{}, completeErr
}

func (a *graphAdapter) partialNeutralState(ctx context.Context, folder graphItem, marker string, enforceACL bool) (ports.DocumentRemoteState, bool, error) {
	if !presentFacet(folder.Folder) || folder.Parent.ID != a.container || folder.Parent.DriveID != a.drive || folder.Name != marker {
		return ports.DocumentRemoteState{}, false, docError(http.StatusOK, "remote_identity_changed", false)
	}
	items, folderRef, err := a.neutralShellItems(ctx, folder, marker, enforceACL)
	if err != nil {
		var providerErr *ports.DocumentProviderError
		// A published reservation can legitimately contain its owned
		// attachments. It is not a neutral recovery candidate, while binding
		// and provider failures remain observable to the caller.
		if errors.As(err, &providerErr) && providerErr.Code == "invalid_neutral_shell" {
			return ports.DocumentRemoteState{}, false, nil
		}
		return ports.DocumentRemoteState{}, false, err
	}
	body := items["report.html"]
	manifest := items[graphManifestName]
	if body.ID == "" && manifest.ID != "" {
		return ports.DocumentRemoteState{}, false, docError(http.StatusOK, "invalid_neutral_shell", false)
	}
	etag := ""
	contentHash := ""
	if body.ID != "" {
		raw, snapshotETag, readErr := a.bodySnapshot(ctx, graphChildPath(folderRef, "report.html"))
		if readErr != nil {
			return ports.DocumentRemoteState{}, false, readErr
		}
		if !bytes.Equal(raw, []byte(graphNeutralShell)) {
			return ports.DocumentRemoteState{}, false, nil
		}
		etag, contentHash = snapshotETag, graphContentHash(raw)
	}
	if manifest.ID != "" {
		raw, _, readErr := a.bodySnapshot(ctx, graphChildPath(folderRef, graphManifestName))
		if readErr != nil {
			return ports.DocumentRemoteState{}, false, readErr
		}
		expected, _ := encodeGraphManifest(graphOwnershipManifest{Marker: marker, Files: map[string]string{}})
		if !bytes.Equal(raw, expected) {
			return ports.DocumentRemoteState{}, false, docError(http.StatusOK, "invalid_neutral_shell", false)
		}
	}
	logical := folder.ID + "~" + marker
	return ports.DocumentRemoteState{RemotePage: a.graphRemote(logical, etag), Container: a.container, Marker: marker, ContentHash: contentHash, Neutral: true}, true, nil
}

// FindDocumentMarker is deliberately read-only. It reports only an exact,
// proven neutral reservation, including folder-only and body-only interrupted
// creation states. RestrictDocument performs the guarded completion later.
func (a *graphAdapter) FindDocumentMarker(ctx context.Context, container, marker string) ([]ports.DocumentRemoteState, error) {
	if container != a.container || !validMarker(marker) {
		return nil, shared.ErrValidation
	}
	if err := a.CheckDocumentRelease(ctx, container, a.group); err != nil {
		return nil, err
	}
	items, err := a.children(ctx, container)
	if err != nil {
		return nil, err
	}
	var matched graphItem
	for _, item := range items {
		if item.Name != marker || !presentFacet(item.Folder) {
			continue
		}
		if matched.ID != "" {
			return nil, docError(http.StatusOK, "duplicate_neutral_shell", false)
		}
		matched = item
	}
	if matched.ID == "" {
		return nil, nil
	}
	state, recoverable, err := a.partialNeutralState(ctx, matched, marker, true)
	if err != nil || !recoverable {
		return nil, err
	}
	return []ports.DocumentRemoteState{state}, nil
}

func (a *graphAdapter) UploadDocumentAttachment(ctx context.Context, page string, file ports.DocumentImage) error {
	folder, _, err := splitGraphPage(page)
	if err != nil {
		return err
	}
	if len(file.Data) == 0 || len(file.Data) > 20<<20 || !validAttachmentName(file.Name) || (!strings.HasPrefix(file.MediaType, "image/") && file.MediaType != "application/pdf") {
		return shared.ErrValidation
	}
	if err = a.ValidateDocumentText(file.Name); err != nil {
		return err
	}
	folderItem, err := a.graphItem(ctx, folder)
	if err != nil {
		return err
	}
	folderRef := graphChildPath(a.folderPath, folderItem.Name)
	fileRef := graphChildPath(folderRef, file.Name)
	create := "/_api/web/GetFolderByServerRelativeUrl(" + spQuote(folderRef) + ")/Files/add(url=" + spQuote(file.Name) + ",overwrite=false)"
	if err = a.VerifyDocumentRestriction(ctx, page, a.container, a.group); err != nil {
		return err
	}
	if _, _, err = a.spBytes(ctx, http.MethodPost, create, http.Header{"Content-Type": {file.MediaType}}, file.Data, http.StatusOK, http.StatusCreated); err == nil {
		child, readErr := a.graphChild(ctx, folder, file.Name)
		if readErr != nil {
			return docError(http.StatusOK, "attachment_readback_unavailable", true)
		}
		if readErr = a.verifyChildACL(ctx, child, fileRef, false); readErr != nil {
			return partialEffectAmbiguity(readErr, "attachment_ownership_incomplete")
		}
		children, readErr := a.children(ctx, folder)
		if readErr != nil {
			return docError(http.StatusOK, "ownership_readback_unavailable", true)
		}
		manifest, manifestItem, manifestETag, readErr := a.manifestSnapshot(ctx, folderRef, children)
		if readErr != nil || manifest.Marker != folderItem.Name || manifest.Files[file.Name] != "" {
			return docError(http.StatusOK, "ownership_manifest_unavailable", true)
		}
		manifest.Files[file.Name] = child.ID
		if readErr = a.CheckDocumentRelease(ctx, a.container, a.group); readErr != nil {
			return docError(http.StatusOK, "attachment_ownership_incomplete", true)
		}
		if readErr = a.writeManifest(ctx, folderRef, manifestItem, manifestETag, manifest); readErr != nil {
			return partialEffectAmbiguity(readErr, "attachment_ownership_incomplete")
		}
		return nil
	}
	// A deterministic collision is safe only after byte-for-byte same-origin
	// readback. All other provider failures retain their original classification.
	var pErr *ports.DocumentProviderError
	if !isConflict(err, &pErr) {
		return err
	}
	existing, readErr := a.bodySource(ctx, fileRef)
	if readErr != nil {
		return readErr
	}
	if !bytes.Equal(existing, file.Data) {
		return docError(http.StatusConflict, "attachment_name_conflict", false)
	}
	child, readErr := a.graphChild(ctx, folder, file.Name)
	if readErr != nil {
		return readErr
	}
	if readErr = a.verifyChildACL(ctx, child, fileRef, false); readErr != nil {
		return readErr
	}
	children, readErr := a.children(ctx, folder)
	if readErr != nil {
		return readErr
	}
	manifest, _, _, readErr := a.manifestSnapshot(ctx, folderRef, children)
	if readErr != nil || manifest.Files[file.Name] != child.ID {
		return docError(http.StatusOK, "attachment_ownership_unverified", false)
	}
	return nil
}

func (*graphAdapter) WriteDocument(context.Context, string, int, string, string, string) (docpublish.RemotePage, error) {
	return docpublish.RemotePage{}, docError(0, "opaque_revision_required", false)
}

func (a *graphAdapter) WriteDocumentRevision(ctx context.Context, expected docpublish.RemotePage, title, storage, marker string) (docpublish.RemotePage, error) {
	if _, _, err := splitGraphPage(expected.ID); err != nil {
		return docpublish.RemotePage{}, err
	}
	snapshot, err := a.readCompleteDocument(ctx, expected.ID, a.container, a.group, false)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	current := a.remoteState(expected.ID, snapshot)
	if current.Revision != expected.Revision {
		return docpublish.RemotePage{}, shared.ErrConflict
	}
	folderRef := snapshot.folderRef
	files := make(map[string]string, len(snapshot.manifest.Files))
	for name, id := range snapshot.manifest.Files {
		files[name] = id
	}
	raw, err := encodeGraphHTML(title, storage, marker, files)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	if err = a.ValidateDocumentText(title + storage); err != nil {
		return docpublish.RemotePage{}, err
	}
	// SharePoint REST honours If-Match on an existing file update. The Graph
	// content endpoint redirects to an upload host, so it is intentionally not
	// used by this restricted profile.
	bodyRef := graphChildPath(folderRef, "report.html")
	headers := make(http.Header)
	headers.Set("Content-Type", "text/html")
	headers.Set("If-Match", expected.Revision)
	headers.Set("X-HTTP-Method", "PUT")
	if err = a.VerifyDocumentRestriction(ctx, expected.ID, a.container, a.group); err != nil {
		return docpublish.RemotePage{}, err
	}
	if _, _, err = a.spBytes(ctx, http.MethodPost, "/_api/web/GetFileByServerRelativeUrl("+spQuote(bodyRef)+")/$value", headers, raw, http.StatusOK, http.StatusNoContent); err != nil {
		return docpublish.RemotePage{}, err
	}
	updated, err := a.GetDocument(ctx, expected.ID)
	if err != nil {
		return docpublish.RemotePage{}, docError(http.StatusOK, "write_readback_unavailable", true)
	}
	if updated.Title != title || updated.Storage != storage || updated.Marker != marker || updated.Revision == expected.Revision {
		return docpublish.RemotePage{}, docError(http.StatusOK, "write_readback_invalid", true)
	}
	return updated.RemotePage, nil
}

func (a *graphAdapter) permanentDelete(ctx context.Context, id string) error {
	_, err := a.graph(ctx, http.MethodPost, "/drives/"+a.drive+"/items/"+id+"/permanentDelete", nil, nil, nil, nil, http.StatusNoContent)
	var providerErr *ports.DocumentProviderError
	if errors.As(err, &providerErr) && providerErr.Status == http.StatusAccepted {
		// A queued delete does not prove the item and its version history are
		// gone. The command stays uncertain and reconciliation must not retire
		// the local publication.
		return docError(http.StatusAccepted, "permanent_delete_pending", true)
	}
	return err
}

func (a *graphAdapter) PurgeDocument(ctx context.Context, page string, guard func(context.Context) error) error {
	if guard == nil {
		return shared.ErrValidation
	}
	folder, body, children, folderRef, err := a.documentItems(ctx, page, a.container, a.group, false)
	if err != nil {
		return err
	}
	manifest, manifestItem, _, err := a.manifestSnapshot(ctx, folderRef, children)
	if err != nil || manifest.Marker != folder.Name {
		return docError(http.StatusOK, "invalid_ownership_manifest", false)
	}
	owned := map[string]bool{body.ID: true, manifestItem.ID: true}
	for _, id := range manifest.Files {
		if !safeID(id) || owned[id] {
			return docError(http.StatusOK, "unmanaged_child", false)
		}
		owned[id] = true
	}
	if len(owned) != len(children) {
		return docError(http.StatusOK, "unmanaged_child", false)
	}
	for _, child := range children {
		if !owned[child.ID] {
			return docError(http.StatusOK, "unmanaged_child", false)
		}
	}
	deleteDispatched := false
	for _, child := range children {
		if err = guard(ctx); err != nil {
			if deleteDispatched {
				return partialEffectAmbiguity(err, "purge_incomplete")
			}
			return err
		}
		deleteDispatched = true
		if err = a.permanentDelete(ctx, child.ID); err != nil {
			return partialEffectAmbiguity(err, "purge_incomplete")
		}
	}
	if err = guard(ctx); err != nil {
		if deleteDispatched {
			return partialEffectAmbiguity(err, "purge_incomplete")
		}
		return err
	}
	if err = a.permanentDelete(ctx, folder.ID); err != nil {
		return partialEffectAmbiguity(err, "purge_incomplete")
	}
	return nil
}
