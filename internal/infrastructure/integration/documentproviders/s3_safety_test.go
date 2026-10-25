package documentproviders

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
)

func TestS3ConcurrentBodyWriteConflicts(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "Initial", "<p>initial</p>"))
	adapter, server := newS3TestAdapter(t, fake)
	ctx := context.Background()
	state, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/"+s3BodyName) {
			once.Do(func() {
				fake.put(s3TestPrefix+"/"+s3TestMarker+"/"+s3BodyName, s3TestMarker, "text/html", s3Document(t, "Concurrent", "<p>concurrent</p>"))
			})
		}
		fake.ServeHTTP(w, r)
	})
	_, err = adapter.WriteDocumentRevision(ctx, state.RemotePage, "Mine", "<p>mine</p>", s3TestMarker)
	if refusal := s3Refusal(t, err); refusal.Code != "revision_conflict" || refusal.Ambiguous {
		t.Fatalf("expected a definite stale-content conflict, got %+v", refusal)
	}
	current, ok := fake.head(adapter.key(s3TestMarker, s3BodyName))
	if !ok || !bytes.Equal(current.body, s3Document(t, "Concurrent", "<p>concurrent</p>")) {
		t.Fatal("conditional write replaced the competing report")
	}
}

func TestS3VersionHistoryRemainsPurgeable(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, nil)
	for i := 0; i < 63; i++ {
		fake.put(s3TestPrefix+"/"+s3TestMarker+"/"+s3BodyName, s3TestMarker, "text/html", s3Document(t, "Initial", "<p>initial</p>"))
	}
	adapter, _ := newS3TestAdapter(t, fake)
	ctx := context.Background()
	state, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.WriteDocumentRevision(ctx, state.RemotePage, "Next", "<p>next</p>", s3TestMarker)
	if err != nil {
		t.Fatal(err)
	}
	if err = adapter.PurgeDocument(ctx, s3TestMarker, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("own successful write crossed version cap: purge refuses with %v; %d deletes", err, len(fake.deletes))
	}
}

func TestS3UnreadableHoldRefusesPurge(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "Initial", "<p>initial</p>"))
	fake.objectLock = true
	adapter, server := newS3TestAdapter(t, fake)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("legal-hold") || r.URL.Query().Has("retention") {
			fake.xmlError(w, http.StatusForbidden, "AccessDenied")
			return
		}
		fake.ServeHTTP(w, r)
	})
	err := adapter.PurgeDocument(context.Background(), s3TestMarker, func(context.Context) error { return nil })
	if err == nil || len(fake.deletes) > 0 {
		t.Fatalf("unverifiable Object Lock should refuse before deleting; got err=%v, deletes=%v", err, fake.deletes)
	}
}

func TestS3BrowserURLIdentifiesReport(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "Initial", "<p>initial</p>"))
	adapter, server := newS3TestAdapter(t, fake)
	state, err := adapter.GetDocument(context.Background(), s3TestMarker)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.Client().Get(state.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("saved document URL returns %d, URL=%s", resp.StatusCode, state.URL)
	}
}

func TestS3RepublishUsesNewReleaseMarker(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "Initial", "<p>initial</p>"))
	adapter, _ := newS3TestAdapter(t, fake)
	state, err := adapter.GetDocument(context.Background(), s3TestMarker)
	if err != nil {
		t.Fatal(err)
	}
	const updateMarker = "synapse-intent-0002"
	if !validMarker(updateMarker) {
		t.Fatal("invalid test marker")
	}
	_, err = adapter.WriteDocumentRevision(context.Background(), state.RemotePage, "Updated", "<p>updated</p>", updateMarker)
	if err != nil {
		t.Fatalf("first republish to unchanged remote ID with a new valid intent marker was rejected: %v", err)
	}
}

func TestS3RejectsOverlappingPublicWildcardPolicy(t *testing.T) {
	fake := newFakeS3()
	fake.policy = strings.TrimSuffix(s3GoodPolicy, "]}") + `,{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::synapse-reports/*/report.html"}]}`
	adapter, _ := newS3TestAdapter(t, fake)
	if err := adapter.CheckDocumentRelease(context.Background(), s3TestBucket, s3TestReader); err == nil {
		t.Fatal("public GetObject grant matching every publication report was accepted")
	}
}

func TestS3PurgeRefusesHiddenForeignVersion(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "Report", "<p>safe</p>"))
	key := s3TestPrefix + "/" + s3TestMarker + "/manual-backup.pdf"
	fake.put(key, "foreign-owner", "application/pdf", []byte("unmanaged historical data"))
	fake.mu.Lock()
	fake.objects[key] = append(fake.objects[key], s3Version{versionID: "foreign-delete-marker", deleteMarker: true})
	fake.mu.Unlock()
	adapter, _ := newS3TestAdapter(t, fake)
	err := adapter.PurgeDocument(context.Background(), s3TestMarker, func(context.Context) error { return nil })
	if err == nil || len(fake.deletes) != 0 {
		t.Fatalf("expected refusal without deletion; err=%v deleted=%v", err, fake.deletes)
	}
}

type s3CaptureTransport func(*http.Request) (*http.Response, error)

func (fn s3CaptureTransport) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestS3AWSRequestUsesPinnedHost(t *testing.T) {
	item := integration.Integration{Provider: S3, Endpoint: "https://s3.eu-west-1.amazonaws.com", Config: []byte(`{"space":"synapse-reports","prefix":"publications","read_group":"arn:aws:iam::123456789012:role/report-readers","region":"eu-west-1","data_class":"detail","read_endpoint":"https://reports.example.com/bucket"}`)}
	built, err := newS3(item, integration.CredentialBundle{"access_key_id": "AKIAEXAMPLE000000000", "secret_access_key": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"}, selfhosted.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	adapter := built.(*s3Adapter)
	defer adapter.Close()
	var actualHost string
	adapter.transport.RegisterProtocol("https", s3CaptureTransport(func(req *http.Request) (*http.Response, error) {
		actualHost = req.URL.Hostname()
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`)), Request: req}, nil
	}))
	if _, err = adapter.client.GetBucketVersioning(context.Background(), adapter.bucket); err != nil {
		t.Fatal(err)
	}
	endpoint, _ := url.Parse(item.Endpoint)
	policy, err := s3Policy(item, endpoint, selfhosted.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	if !policy.AllowHost(actualHost, "443") {
		t.Fatalf("SDK generated host %q rejected by production AllowHost", actualHost)
	}
}
