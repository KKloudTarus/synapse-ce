package documentproviders

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	s3TestBucket = "synapse-reports"
	s3TestPrefix = "publications"
	s3TestReader = "arn:aws:iam::123456789012:role/report-readers"
	s3TestMarker = "synapse-intent-0001"
)

var s3GoodPolicy = `{"Version":"2012-10-17","Statement":[{"Sid":"readers","Effect":"Allow","Principal":{"AWS":["` +
	s3TestReader + `"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::` + s3TestBucket + `/` + s3TestPrefix + `/*"]}]}`

// s3Version is one stored version in the fake bucket, newest last.
type s3Version struct {
	versionID, etag, marker, contentType string
	body                                 []byte
	deleteMarker                         bool
}

// fakeS3 answers the subset of the S3 API the provider uses. It keeps every
// version so the fence and the purge can be observed, and it reports user
// metadata only on HEAD, the way AWS S3 does.
type fakeS3 struct {
	mu         sync.Mutex
	versioning string
	policy     string
	objectLock bool
	legalHold  map[string]bool
	objects    map[string][]s3Version
	deletes    []string
	puts       []string
	nextID     int
	listMeta   bool
	failPut    int
}

func newFakeS3() *fakeS3 {
	return &fakeS3{versioning: "Enabled", policy: s3GoodPolicy, legalHold: map[string]bool{}, objects: map[string][]s3Version{}}
}

func (f *fakeS3) put(key, marker, contentType string, body []byte) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.putLocked(key, marker, contentType, body)
}

func (f *fakeS3) putLocked(key, marker, contentType string, body []byte) string {
	f.nextID++
	version := s3Version{versionID: fmt.Sprintf("v%d", f.nextID), etag: fmt.Sprintf("%032x", f.nextID), marker: marker, contentType: contentType, body: body}
	f.objects[key] = append(f.objects[key], version)
	return version.versionID
}

func (f *fakeS3) head(key string) (s3Version, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	versions := f.objects[key]
	if len(versions) == 0 {
		return s3Version{}, false
	}
	latest := versions[len(versions)-1]
	return latest, !latest.deleteMarker
}

func (f *fakeS3) xmlError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "<Error><Code>"+code+"</Code><Message>"+code+"</Message></Error>")
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key := path, ""
	if index := strings.Index(path, "/"); index >= 0 {
		bucket, key = path[:index], path[index+1:]
	}
	if bucket != s3TestBucket {
		f.xmlError(w, http.StatusNotFound, "NoSuchBucket")
		return
	}
	query := r.URL.Query()
	switch {
	case key == "" && query.Has("versioning"):
		_, _ = io.WriteString(w, `<VersioningConfiguration><Status>`+f.versioning+`</Status></VersioningConfiguration>`)
	case key == "" && query.Has("policy"):
		if f.policy == "" {
			f.xmlError(w, http.StatusNotFound, "NoSuchBucketPolicy")
			return
		}
		_, _ = io.WriteString(w, f.policy)
	case key == "" && query.Has("object-lock"):
		if !f.objectLock {
			f.xmlError(w, http.StatusNotFound, "ObjectLockConfigurationNotFoundError")
			return
		}
		_, _ = io.WriteString(w, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`)
	case key == "" && query.Has("versions"):
		f.listVersions(w, query.Get("prefix"))
	case key != "" && query.Has("legal-hold"):
		status := "OFF"
		if f.legalHold[key] {
			status = "ON"
		}
		_, _ = io.WriteString(w, `<LegalHold><Status>`+status+`</Status></LegalHold>`)
	case key != "" && query.Has("retention"):
		f.xmlError(w, http.StatusNotFound, "NoSuchObjectLockConfiguration")
	case r.Method == http.MethodHead && key != "":
		f.serveHead(w, key)
	case r.Method == http.MethodGet && key != "":
		f.serveGet(w, key, query.Get("versionId"))
	case r.Method == http.MethodPut && key != "":
		f.servePut(w, r, key)
	case r.Method == http.MethodDelete && key != "":
		f.serveDelete(w, key, query.Get("versionId"))
	default:
		f.xmlError(w, http.StatusBadRequest, "NotImplemented")
	}
}

func (f *fakeS3) listVersions(w http.ResponseWriter, prefix string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body strings.Builder
	body.WriteString(`<ListVersionsResult><Name>` + s3TestBucket + `</Name><Prefix>` + prefix + `</Prefix><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>`)
	for key, versions := range f.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		for index, version := range versions {
			element := "Version"
			if version.deleteMarker {
				element = "DeleteMarker"
			}
			body.WriteString("<" + element + "><Key>" + key + "</Key><VersionId>" + version.versionID +
				"</VersionId><IsLatest>" + strconv.FormatBool(index == len(versions)-1) +
				"</IsLatest><LastModified>2026-10-23T00:00:00.000Z</LastModified><ETag>&#34;" + version.etag +
				"&#34;</ETag><Size>" + strconv.Itoa(len(version.body)) + "</Size><StorageClass>STANDARD</StorageClass>")
			if f.listMeta && version.marker != "" {
				body.WriteString("<UserMetadata><X-Amz-Meta-Synapse-Marker>" + version.marker + "</X-Amz-Meta-Synapse-Marker></UserMetadata>")
			}
			body.WriteString("</" + element + ">")
		}
	}
	body.WriteString(`</ListVersionsResult>`)
	w.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(w, body.String())
}

func (f *fakeS3) serveHead(w http.ResponseWriter, key string) {
	version, ok := f.head(key)
	if !ok {
		f.xmlError(w, http.StatusNotFound, "NoSuchKey")
		return
	}
	w.Header().Set("ETag", `"`+version.etag+`"`)
	w.Header().Set("Last-Modified", time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat))
	w.Header().Set("Content-Length", strconv.Itoa(len(version.body)))
	w.Header().Set("x-amz-version-id", version.versionID)
	if version.marker != "" {
		w.Header().Set("x-amz-meta-synapse-marker", version.marker)
	}
	w.WriteHeader(http.StatusOK)
}

func (f *fakeS3) serveGet(w http.ResponseWriter, key, versionID string) {
	f.mu.Lock()
	versions := f.objects[key]
	f.mu.Unlock()
	for index := len(versions) - 1; index >= 0; index-- {
		if versionID != "" && versions[index].versionID != versionID {
			continue
		}
		if versions[index].deleteMarker {
			break
		}
		w.Header().Set("ETag", `"`+versions[index].etag+`"`)
		w.Header().Set("Last-Modified", time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat))
		w.Header().Set("Content-Length", strconv.Itoa(len(versions[index].body)))
		_, _ = w.Write(versions[index].body)
		return
	}
	f.xmlError(w, http.StatusNotFound, "NoSuchKey")
}

func (f *fakeS3) servePut(w http.ResponseWriter, r *http.Request, key string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		f.xmlError(w, http.StatusBadRequest, "IncompleteBody")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failPut != 0 {
		status := f.failPut
		f.xmlError(w, status, "AccessDenied")
		return
	}
	f.puts = append(f.puts, key)
	versionID := f.putLocked(key, r.Header.Get("X-Amz-Meta-Synapse-Marker"), r.Header.Get("Content-Type"), body)
	w.Header().Set("ETag", `"`+f.objects[key][len(f.objects[key])-1].etag+`"`)
	w.Header().Set("x-amz-version-id", versionID)
	w.WriteHeader(http.StatusOK)
}

func (f *fakeS3) serveDelete(w http.ResponseWriter, key, versionID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, key+"@"+versionID)
	kept := []s3Version{}
	for _, version := range f.objects[key] {
		if version.versionID != versionID {
			kept = append(kept, version)
		}
	}
	if len(kept) == 0 {
		delete(f.objects, key)
	} else {
		f.objects[key] = kept
	}
	w.WriteHeader(http.StatusNoContent)
}

func newS3TestAdapter(t *testing.T, fake *fakeS3) (*s3Adapter, *httptest.Server) {
	t.Helper()
	// TLS keeps minio-go on the plain payload signature. Over plaintext it
	// switches to aws-chunked streaming, which the fake would have to unframe.
	server := httptest.NewTLSServer(fake)
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test endpoint: %v", err)
	}
	client, err := minio.New(endpoint.Host, &minio.Options{
		Creds:     credentials.NewStaticV4("AKIAEXAMPLE000000000", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", ""),
		Secure:    true,
		Region:    "us-east-1",
		Transport: server.Client().Transport,
	})
	if err != nil {
		t.Fatalf("minio client: %v", err)
	}
	return &s3Adapter{
		client: client, bucket: s3TestBucket, prefix: s3TestPrefix, principal: s3TestReader,
		endpoint: server.URL, accessKey: "AKIAEXAMPLE000000000", secretKey: "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
	}, server
}

func s3Refusal(t *testing.T, err error) *ports.DocumentProviderError {
	t.Helper()
	var refusal *ports.DocumentProviderError
	if !errors.As(err, &refusal) {
		t.Fatalf("expected a provider refusal, got %v", err)
	}
	return refusal
}

func seedS3Publication(fake *fakeS3, body []byte) {
	fake.put(s3TestPrefix+"/"+s3TestMarker+"/"+s3ShellName, s3TestMarker, "application/octet-stream", nil)
	if body != nil {
		fake.put(s3TestPrefix+"/"+s3TestMarker+"/"+s3BodyName, s3TestMarker, "text/html; charset=utf-8", body)
	}
}

func s3Document(t *testing.T, title, storage string) []byte {
	t.Helper()
	rendered, err := encodeS3HTML(title, storage, s3TestMarker, nil)
	if err != nil {
		t.Fatalf("encode document: %v", err)
	}
	return rendered
}

func TestS3NewValidatesDestination(t *testing.T) {
	secrets := integration.CredentialBundle{"access_key_id": "AKIAEXAMPLE000000000", "secret_access_key": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"}
	config := func(overrides map[string]string) []byte {
		values := map[string]string{"space": s3TestBucket, "prefix": s3TestPrefix, "read_group": s3TestReader, "region": "us-east-1", "data_class": "detail"}
		for key, value := range overrides {
			values[key] = value
		}
		raw, err := json.Marshal(values)
		if err != nil {
			t.Fatalf("marshal config: %v", err)
		}
		return raw
	}
	rules := selfhosted.Rules{}
	for _, tc := range []struct {
		name     string
		endpoint string
		config   []byte
		secrets  integration.CredentialBundle
		wantErr  bool
	}{
		{name: "aws endpoint", endpoint: "https://s3.eu-west-1.amazonaws.com", config: config(nil), secrets: secrets},
		{name: "plaintext endpoint", endpoint: "http://s3.eu-west-1.amazonaws.com", config: config(nil), secrets: secrets, wantErr: true},
		{name: "endpoint with path", endpoint: "https://s3.eu-west-1.amazonaws.com/bucket", config: config(nil), secrets: secrets, wantErr: true},
		{name: "endpoint with credentials", endpoint: "https://key:secret@s3.eu-west-1.amazonaws.com", config: config(nil), secrets: secrets, wantErr: true},
		{name: "endpoint with query", endpoint: "https://s3.eu-west-1.amazonaws.com?x=1", config: config(nil), secrets: secrets, wantErr: true},
		{name: "non aws host without allowlist", endpoint: "https://minio.internal", config: config(nil), secrets: secrets, wantErr: true},
		{name: "uppercase bucket", endpoint: "https://s3.eu-west-1.amazonaws.com", config: config(map[string]string{"space": "Synapse-Reports"}), secrets: secrets, wantErr: true},
		{name: "traversal prefix", endpoint: "https://s3.eu-west-1.amazonaws.com", config: config(map[string]string{"prefix": "reports/../etc"}), secrets: secrets, wantErr: true},
		{name: "wildcard reader", endpoint: "https://s3.eu-west-1.amazonaws.com", config: config(map[string]string{"read_group": "*"}), secrets: secrets, wantErr: true},
		{name: "summary data class", endpoint: "https://s3.eu-west-1.amazonaws.com", config: config(map[string]string{"data_class": "summary"}), secrets: secrets, wantErr: true},
		{name: "bad region", endpoint: "https://s3.eu-west-1.amazonaws.com", config: config(map[string]string{"region": "EU West 1"}), secrets: secrets, wantErr: true},
		{name: "missing secret", endpoint: "https://s3.eu-west-1.amazonaws.com", config: config(nil), secrets: integration.CredentialBundle{"access_key_id": "AKIAEXAMPLE000000000"}, wantErr: true},
		{name: "secret with whitespace", endpoint: "https://s3.eu-west-1.amazonaws.com", config: config(nil), secrets: integration.CredentialBundle{"access_key_id": "AKIAEXAMPLE000000000", "secret_access_key": "has space"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := integration.Integration{Provider: S3, Endpoint: tc.endpoint, Config: tc.config}
			adapter, err := newS3(item, tc.secrets, rules)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected a rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
			built, ok := adapter.(*s3Adapter)
			if !ok {
				t.Fatalf("factory returned %T", adapter)
			}
			built.Close()
			if built.secretKey != "" || built.accessKey != "" {
				t.Fatalf("Close must clear the held credential")
			}
		})
	}
}

func TestS3DestinationProof(t *testing.T) {
	foreign := strings.Replace(s3GoodPolicy, s3TestReader, "arn:aws:iam::123456789012:role/other", 1)
	for _, tc := range []struct {
		name           string
		versioning     string
		policy         string
		wantCode       string
		wantRestricted bool
		wantOK         bool
	}{
		{name: "exact reader", wantOK: true},
		{name: "versioning suspended", versioning: "Suspended", wantCode: "versioning_required"},
		{name: "no policy", policy: "none", wantCode: "reader_policy_unverifiable"},
		{name: "unparsable policy", policy: `{"Version":`, wantCode: "reader_policy_unverifiable"},
		{name: "public shorthand", policy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::` + s3TestBucket + `/` + s3TestPrefix + `/*"]}]}`, wantCode: "public_bucket_policy", wantRestricted: true},
		{name: "public aws map", policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:*"],"Resource":["arn:aws:s3:::` + s3TestBucket + `/*"]}]}`, wantCode: "public_bucket_policy", wantRestricted: true},
		{name: "foreign reader", policy: foreign, wantCode: "unexpected_reader_principal", wantRestricted: true},
		{name: "two readers", policy: `{"Statement":[` + strings.TrimSuffix(strings.TrimPrefix(s3GoodPolicy[strings.Index(s3GoodPolicy, "[")+1:], ""), "]}") + `,{"Sid":"second","Effect":"Allow","Principal":{"AWS":["` + s3TestReader + `"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::` + s3TestBucket + `/` + s3TestPrefix + `/*"]}]}`, wantCode: "reader_policy_unverifiable"},
		{name: "conditioned reader", policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["` + s3TestReader + `"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::` + s3TestBucket + `/` + s3TestPrefix + `/*"],"Condition":{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}}]}`, wantCode: "reader_policy_unverifiable"},
		{name: "reader on another prefix only", policy: strings.Replace(s3GoodPolicy, s3TestPrefix+"/*", "other/*", 1), wantCode: "reader_policy_unverifiable"},
		{name: "unknown principal shape", policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":{"nested":true}},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::` + s3TestBucket + `/` + s3TestPrefix + `/*"]}]}`, wantCode: "reader_policy_unverifiable"},
		{name: "public deny is not a breach", policy: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::` + s3TestBucket + `/*"]},` + s3GoodPolicy[strings.Index(s3GoodPolicy, "{\"Sid\""):], wantOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeS3()
			if tc.versioning != "" {
				fake.versioning = tc.versioning
			}
			switch tc.policy {
			case "":
			case "none":
				fake.policy = ""
			default:
				fake.policy = tc.policy
			}
			adapter, _ := newS3TestAdapter(t, fake)
			err := adapter.CheckDocumentRelease(context.Background(), s3TestBucket, s3TestReader)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("expected the destination to pass, got %v", err)
				}
				return
			}
			refusal := s3Refusal(t, err)
			if refusal.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", refusal.Code, tc.wantCode)
			}
			if refusal.RestrictionLost != tc.wantRestricted {
				t.Fatalf("RestrictionLost = %v, want %v", refusal.RestrictionLost, tc.wantRestricted)
			}
		})
	}
}

func TestS3PublicationIdentity(t *testing.T) {
	for _, tc := range []struct {
		name           string
		seed           func(*fakeS3)
		wantCode       string
		wantRestricted bool
	}{
		{name: "missing shell", seed: func(f *fakeS3) {
			f.put(s3TestPrefix+"/"+s3TestMarker+"/"+s3BodyName, s3TestMarker, "text/html", []byte("x"))
		}, wantCode: "remote_identity_changed", wantRestricted: true},
		{name: "shell carries content", seed: func(f *fakeS3) {
			f.put(s3TestPrefix+"/"+s3TestMarker+"/"+s3ShellName, s3TestMarker, "application/octet-stream", []byte("payload"))
		}, wantCode: "remote_identity_changed", wantRestricted: true},
		{name: "shell stamped for another publication", seed: func(f *fakeS3) {
			f.put(s3TestPrefix+"/"+s3TestMarker+"/"+s3ShellName, "synapse-intent-9999", "application/octet-stream", nil)
		}, wantCode: "remote_identity_changed", wantRestricted: true},
		{name: "unstamped shell", seed: func(f *fakeS3) {
			f.put(s3TestPrefix+"/"+s3TestMarker+"/"+s3ShellName, "", "application/octet-stream", nil)
		}, wantCode: "complete_identity_unverifiable"},
		{name: "foreign object in the publication", seed: func(f *fakeS3) {
			seedS3Publication(f, nil)
			f.put(s3TestPrefix+"/"+s3TestMarker+"/leak.png", "synapse-intent-9999", "image/png", []byte("x"))
		}, wantCode: "unmanaged_child"},
		{name: "unstamped object in the publication", seed: func(f *fakeS3) {
			seedS3Publication(f, nil)
			f.put(s3TestPrefix+"/"+s3TestMarker+"/leak.png", "", "image/png", []byte("x"))
		}, wantCode: "complete_identity_unverifiable"},
		{name: "nested key in the publication", seed: func(f *fakeS3) {
			seedS3Publication(f, nil)
			f.put(s3TestPrefix+"/"+s3TestMarker+"/nested/file.png", s3TestMarker, "image/png", []byte("x"))
		}, wantCode: "unmanaged_child"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeS3()
			tc.seed(fake)
			adapter, _ := newS3TestAdapter(t, fake)
			err := adapter.VerifyDocumentRestriction(context.Background(), s3TestMarker, s3TestBucket, s3TestReader)
			refusal := s3Refusal(t, err)
			if refusal.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", refusal.Code, tc.wantCode)
			}
			if refusal.RestrictionLost != tc.wantRestricted {
				t.Fatalf("RestrictionLost = %v, want %v", refusal.RestrictionLost, tc.wantRestricted)
			}
		})
	}
}

func TestS3ShellAndStateRoundTrip(t *testing.T) {
	fake := newFakeS3()
	adapter, _ := newS3TestAdapter(t, fake)
	ctx := context.Background()
	page, err := adapter.CreateDocumentShell(ctx, s3TestBucket, s3TestMarker)
	if err != nil {
		t.Fatalf("create shell: %v", err)
	}
	if page.ID != s3TestMarker || page.Revision != "new:"+s3TestMarker {
		t.Fatalf("shell page = %+v", page)
	}
	state, err := adapter.GetDocument(ctx, page.ID)
	if err != nil {
		t.Fatalf("read shell: %v", err)
	}
	if !state.Neutral || state.Title != "" || state.Storage != "" {
		t.Fatalf("a fresh shell must be neutral, got %+v", state)
	}
	written, err := adapter.WriteDocumentRevision(ctx, page, "Engagement report", "<p>finding</p>", s3TestMarker)
	if err != nil {
		t.Fatalf("write revision: %v", err)
	}
	if written.Revision == page.Revision || written.Revision == "" {
		t.Fatalf("revision did not advance: %+v", written)
	}
	state, err = adapter.GetDocument(ctx, page.ID)
	if err != nil {
		t.Fatalf("read document: %v", err)
	}
	if state.Neutral || state.Title != "Engagement report" || state.Storage != "<p>finding</p>" || state.Revision != written.Revision {
		t.Fatalf("state = %+v", state)
	}
	if _, err = adapter.CreateDocumentShell(ctx, s3TestBucket, s3TestMarker); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("a second shell for the same marker must conflict, got %v", err)
	}
}

func TestS3WriteRevisionFencesOnTheReadVersion(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "First", "<p>one</p>"))
	adapter, _ := newS3TestAdapter(t, fake)
	ctx := context.Background()
	state, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil {
		t.Fatalf("read document: %v", err)
	}
	// Another writer advances the body between the read and the write.
	fake.put(s3TestPrefix+"/"+s3TestMarker+"/"+s3BodyName, s3TestMarker, "text/html; charset=utf-8", s3Document(t, "Theirs", "<p>theirs</p>"))
	if _, err = adapter.WriteDocumentRevision(ctx, state.RemotePage, "Mine", "<p>mine</p>", s3TestMarker); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale revision must conflict, got %v", err)
	}
	fresh, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil {
		t.Fatalf("re-read document: %v", err)
	}
	if _, err = adapter.WriteDocumentRevision(ctx, fresh.RemotePage, "Mine", "<p>mine</p>", s3TestMarker); err != nil {
		t.Fatalf("fenced write on the current revision: %v", err)
	}
	if _, err = adapter.WriteDocument(ctx, s3TestMarker, 1, "Mine", "<p>mine</p>", s3TestMarker); err == nil {
		t.Fatalf("the version-numbered write must be refused")
	}
}

func TestS3WriteRefusesWhenTheDestinationTurnedPublic(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "First", "<p>one</p>"))
	adapter, _ := newS3TestAdapter(t, fake)
	ctx := context.Background()
	state, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil {
		t.Fatalf("read document: %v", err)
	}
	fake.policy = `{"Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::` + s3TestBucket + `/*"]}]}`
	_, err = adapter.WriteDocumentRevision(ctx, state.RemotePage, "Mine", "<p>mine</p>", s3TestMarker)
	refusal := s3Refusal(t, err)
	if refusal.Code != "public_bucket_policy" || !refusal.RestrictionLost {
		t.Fatalf("refusal = %+v", refusal)
	}
	if len(fake.puts) != 0 {
		t.Fatalf("a public destination must not receive a write, got %v", fake.puts)
	}
}

func TestS3AttachmentConflictAndIdempotence(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, nil)
	adapter, _ := newS3TestAdapter(t, fake)
	ctx := context.Background()
	image := ports.DocumentImage{Name: "chart.png", MediaType: "image/png", Data: []byte("first-bytes")}
	if err := adapter.UploadDocumentAttachment(ctx, s3TestMarker, image); err != nil {
		t.Fatalf("upload attachment: %v", err)
	}
	if err := adapter.UploadDocumentAttachment(ctx, s3TestMarker, image); err != nil {
		t.Fatalf("re-uploading identical bytes must be idempotent, got %v", err)
	}
	if uploads := len(fake.puts); uploads != 1 {
		t.Fatalf("attachment put count = %d, want 1", uploads)
	}
	changed := ports.DocumentImage{Name: "chart.png", MediaType: "image/png", Data: []byte("other-bytes")}
	refusal := s3Refusal(t, adapter.UploadDocumentAttachment(ctx, s3TestMarker, changed))
	if refusal.Code != "attachment_name_conflict" {
		t.Fatalf("refusal = %+v", refusal)
	}
	if err := adapter.UploadDocumentAttachment(ctx, s3TestMarker, ports.DocumentImage{Name: s3BodyName, MediaType: "image/png", Data: []byte("x")}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("the body name must be refused, got %v", err)
	}
	if err := adapter.UploadDocumentAttachment(ctx, s3TestMarker, ports.DocumentImage{Name: "../escape.png", MediaType: "image/png", Data: []byte("x")}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a traversing name must be refused, got %v", err)
	}
	state, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil {
		t.Fatalf("read document: %v", err)
	}
	written, err := adapter.WriteDocumentRevision(ctx, state.RemotePage, "With image", `<p><image><attachment filename="chart.png"></attachment></image></p>`, s3TestMarker)
	if err != nil {
		t.Fatalf("write with attachment: %v", err)
	}
	body, ok := fake.head(s3TestPrefix + "/" + s3TestMarker + "/" + s3BodyName)
	if !ok {
		t.Fatalf("body object missing after the write")
	}
	if !strings.Contains(string(body.body), `src="./chart.png"`) {
		t.Fatalf("attachment reference must stay relative to the publication: %s", body.body)
	}
	if written.Revision != body.versionID {
		t.Fatalf("returned revision %q does not name the stored version %q", written.Revision, body.versionID)
	}
}

func TestS3PurgeRemovesEveryVersion(t *testing.T) {
	ctx := context.Background()
	t.Run("all versions and delete markers", func(t *testing.T) {
		fake := newFakeS3()
		seedS3Publication(fake, s3Document(t, "First", "<p>one</p>"))
		fake.put(s3TestPrefix+"/"+s3TestMarker+"/"+s3BodyName, s3TestMarker, "text/html", s3Document(t, "Second", "<p>two</p>"))
		fake.put(s3TestPrefix+"/"+s3TestMarker+"/chart.png", s3TestMarker, "image/png", []byte("image"))
		adapter, _ := newS3TestAdapter(t, fake)
		if err := adapter.PurgeDocument(ctx, s3TestMarker, func(context.Context) error { return nil }); err != nil {
			t.Fatalf("purge: %v", err)
		}
		if len(fake.objects) != 0 {
			t.Fatalf("objects remain after the purge: %v", fake.objects)
		}
		if len(fake.deletes) != 4 {
			t.Fatalf("delete count = %d, want 4 (two body versions, the shell, the attachment)", len(fake.deletes))
		}
	})
	t.Run("guard refusal before the first delete", func(t *testing.T) {
		fake := newFakeS3()
		seedS3Publication(fake, s3Document(t, "First", "<p>one</p>"))
		adapter, _ := newS3TestAdapter(t, fake)
		err := adapter.PurgeDocument(ctx, s3TestMarker, func(context.Context) error { return shared.ErrConflict })
		if !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("a guard refusal before any delete must surface unchanged, got %v", err)
		}
		if len(fake.deletes) != 0 {
			t.Fatalf("no delete may be dispatched, got %v", fake.deletes)
		}
	})
	t.Run("guard refusal after a delete is ambiguous", func(t *testing.T) {
		fake := newFakeS3()
		seedS3Publication(fake, s3Document(t, "First", "<p>one</p>"))
		fake.put(s3TestPrefix+"/"+s3TestMarker+"/chart.png", s3TestMarker, "image/png", []byte("image"))
		adapter, _ := newS3TestAdapter(t, fake)
		calls := 0
		err := adapter.PurgeDocument(ctx, s3TestMarker, func(context.Context) error {
			calls++
			if calls > 1 {
				return shared.ErrConflict
			}
			return nil
		})
		refusal := s3Refusal(t, err)
		if !refusal.Ambiguous {
			t.Fatalf("a refusal after a dispatched delete must be ambiguous: %+v", refusal)
		}
	})
	t.Run("legal hold refuses", func(t *testing.T) {
		fake := newFakeS3()
		seedS3Publication(fake, s3Document(t, "First", "<p>one</p>"))
		fake.objectLock = true
		fake.legalHold[s3TestPrefix+"/"+s3TestMarker+"/"+s3BodyName] = true
		adapter, _ := newS3TestAdapter(t, fake)
		refusal := s3Refusal(t, adapter.PurgeDocument(ctx, s3TestMarker, func(context.Context) error { return nil }))
		if refusal.Code != "object_lock_retained" {
			t.Fatalf("refusal = %+v", refusal)
		}
		if len(fake.deletes) != 0 {
			t.Fatalf("a retained publication must not be partially deleted, got %v", fake.deletes)
		}
	})
}

func TestS3ListingMetadataAvoidsHeadRequests(t *testing.T) {
	fake := newFakeS3()
	fake.listMeta = true
	seedS3Publication(fake, s3Document(t, "First", "<p>one</p>"))
	adapter, server := newS3TestAdapter(t, fake)
	heads := 0
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			heads++
		}
		fake.ServeHTTP(w, r)
	})
	if _, err := adapter.GetDocument(context.Background(), s3TestMarker); err != nil {
		t.Fatalf("read document: %v", err)
	}
	if heads != 0 {
		t.Fatalf("a listing that carries the stamp must need no HEAD, got %d", heads)
	}
}

func TestS3CredentialNeverReachesThePayload(t *testing.T) {
	fake := newFakeS3()
	adapter, _ := newS3TestAdapter(t, fake)
	if err := adapter.ValidateDocumentText("report body"); err != nil {
		t.Fatalf("clean text: %v", err)
	}
	refusal := s3Refusal(t, adapter.ValidateDocumentText("leak "+adapter.secretKey))
	if refusal.Code != "credential_in_payload" {
		t.Fatalf("refusal = %+v", refusal)
	}
	adapter.sessionToken = "FwoGZXIvYXdzEBYaDEXAMPLESESSIONTOKEN"
	if refusal = s3Refusal(t, adapter.ValidateDocumentText("leak "+adapter.sessionToken)); refusal.Code != "credential_in_payload" {
		t.Fatalf("refusal = %+v", refusal)
	}
	adapter.sessionToken = ""
	// The access key ID is an identifier, and a destination may use a short word
	// for it; report text that happens to contain it is not a leak.
	if err := adapter.ValidateDocumentText("published from bucket " + adapter.accessKey); err != nil {
		t.Fatalf("the access key ID must not refuse report text: %v", err)
	}
	seedS3Publication(fake, []byte("<html><!--synapse-source:"+adapter.secretKey+"--></html>"))
	if _, err := adapter.GetDocument(context.Background(), s3TestMarker); err == nil {
		t.Fatalf("a stored body that carries the credential must be refused")
	}
}

func TestS3FindDocumentMarker(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "First", "<p>one</p>"))
	adapter, _ := newS3TestAdapter(t, fake)
	ctx := context.Background()
	matches, err := adapter.FindDocumentMarker(ctx, s3TestBucket, s3TestMarker)
	if err != nil {
		t.Fatalf("find marker: %v", err)
	}
	if len(matches) != 1 || matches[0].Marker != s3TestMarker || matches[0].Neutral {
		t.Fatalf("matches = %+v", matches)
	}
	empty, err := adapter.FindDocumentMarker(ctx, s3TestBucket, "synapse-intent-absent")
	if err != nil {
		t.Fatalf("find absent marker: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("absent marker must match nothing, got %+v", empty)
	}
	if _, err = adapter.FindDocumentMarker(ctx, "other-bucket", s3TestMarker); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("another container must be refused, got %v", err)
	}
	if _, err = adapter.FindDocumentMarker(ctx, s3TestBucket, "not-a-marker"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a foreign marker shape must be refused, got %v", err)
	}
}

func TestS3ProviderRegistered(t *testing.T) {
	registry := integration.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatalf("register: %v", err)
	}
	descriptor, err := registry.Descriptor(S3)
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if descriptor.Provider != S3 {
		t.Fatalf("descriptor = %+v", descriptor)
	}
	if len(descriptor.ConfigFields) != 5 || len(descriptor.SecretFields) != 3 {
		t.Fatalf("descriptor fields = %d config, %d secret", len(descriptor.ConfigFields), len(descriptor.SecretFields))
	}
	page := s3Remote(s3TestMarker, "https://example.invalid/b/p/", "v1")
	if page.ID != s3TestMarker || page.Version != 1 {
		t.Fatalf("remote page = %+v", docpublish.RemotePage(page))
	}
}
