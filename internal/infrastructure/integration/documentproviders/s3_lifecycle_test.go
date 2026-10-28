package documentproviders

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestS3RepublishPreservesPublicationIdentity(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "Before", "<p>before</p>"))
	adapter, _ := newS3TestAdapter(t, fake)
	ctx := context.Background()
	before, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil {
		t.Fatal(err)
	}
	const nextMarker = "synapse-intent-next-release"
	written, err := adapter.WriteDocumentRevision(ctx, before.RemotePage, "After", "<p>after</p>", nextMarker)
	if err != nil {
		t.Fatal(err)
	}
	after, err := adapter.ReadRestrictedDocument(ctx, s3TestMarker, s3TestBucket, s3TestReader)
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != before.ID || after.Marker != nextMarker || after.Revision != written.Revision || after.Revision == before.Revision {
		t.Fatalf("republish did not preserve identity and advance its content revision: %+v", after)
	}
	body, _ := fake.head(adapter.key(s3TestMarker, s3BodyName))
	if body.marker != s3TestMarker || written.Revision != body.etag {
		t.Fatalf("body ownership must stay stable, with ETag concurrency: marker=%s revision=%s", body.marker, written.Revision)
	}
}

func TestS3ConditionalCreationPreservesCompetingObjects(t *testing.T) {
	for _, kind := range []string{"shell", "body", "attachment"} {
		t.Run(kind, func(t *testing.T) {
			fake := newFakeS3()
			if kind != "shell" {
				seedS3Publication(fake, nil)
			}
			adapter, server := newS3TestAdapter(t, fake)
			name := s3ShellName
			if kind == "body" {
				name = s3BodyName
			} else if kind == "attachment" {
				name = "chart.png"
			}
			key := adapter.key(s3TestMarker, name)
			competing := []byte("a concurrent object's bytes")
			var once sync.Once
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut && r.URL.Path == "/"+s3TestBucket+"/"+key {
					once.Do(func() { fake.put(key, "foreign-owner", "application/octet-stream", competing) })
				}
				fake.ServeHTTP(w, r)
			})
			ctx := context.Background()
			var err error
			switch kind {
			case "shell":
				_, err = adapter.CreateDocumentShell(ctx, s3TestBucket, s3TestMarker)
			case "body":
				state, readErr := adapter.GetDocument(ctx, s3TestMarker)
				if readErr != nil {
					t.Fatal(readErr)
				}
				_, err = adapter.WriteDocumentRevision(ctx, state.RemotePage, "Report", "<p>body</p>", s3TestMarker)
			case "attachment":
				err = adapter.UploadDocumentAttachment(ctx, s3TestMarker, ports.DocumentImage{Name: name, MediaType: "image/png", Data: []byte("ours")})
			}
			if refusal := s3Refusal(t, err); refusal.Code != "revision_conflict" || refusal.Ambiguous {
				t.Fatalf("expected definite creation conflict, got %+v", refusal)
			}
			current, ok := fake.head(key)
			if !ok || !bytes.Equal(current.body, competing) || current.marker != "foreign-owner" {
				t.Fatal("the conditional create replaced a competing object")
			}
		})
	}
}

func TestS3IdenticalBytesRetainContentRevision(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "Initial", "<p>initial</p>"))
	adapter, _ := newS3TestAdapter(t, fake)
	ctx := context.Background()
	before, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil {
		t.Fatal(err)
	}
	key := adapter.key(s3TestMarker, s3BodyName)
	original, _ := fake.head(key)
	// Restoring the exact representation creates history, not a new ETag. The
	// supported precondition fences current content, not every history event.
	fake.put(key, s3TestMarker, original.contentType, original.body)
	restored, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil || restored.Revision != before.Revision {
		t.Fatalf("identical restored content must retain its concurrency token: %+v, %v", restored, err)
	}
	if _, err = adapter.WriteDocumentRevision(ctx, before.RemotePage, "Next", "<p>next</p>", "synapse-intent-next-release"); err != nil {
		t.Fatalf("content precondition should still match identical restored bytes: %v", err)
	}
}

func TestS3HistoryAdmissionLeavesPurgeCapacity(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, nil)
	for i := 0; i < s3WriteHistoryLimit-2; i++ {
		fake.put(s3TestPrefix+"/"+s3TestMarker+"/"+s3BodyName, s3TestMarker, "text/html", s3Document(t, "Before", "<p>before</p>"))
	}
	adapter, _ := newS3TestAdapter(t, fake)
	ctx := context.Background()
	before, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = adapter.WriteDocumentRevision(ctx, before.RemotePage, "Last admitted", "<p>after</p>", "synapse-intent-last-admitted"); err != nil {
		t.Fatal(err)
	}
	current, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil {
		t.Fatal(err)
	}
	puts := len(fake.puts)
	_, err = adapter.WriteDocumentRevision(ctx, current.RemotePage, "Over budget", "<p>over</p>", "synapse-intent-over-budget")
	if refusal := s3Refusal(t, err); refusal.Code != "publication_history_full" || len(fake.puts) != puts {
		t.Fatalf("history budget must refuse before dispatch: %+v", refusal)
	}
	if err = adapter.PurgeDocument(ctx, s3TestMarker, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("admission boundary must remain purgeable across listing pages: %v", err)
	}
	if len(fake.objects) != 0 {
		t.Fatal("version history survived purge")
	}
}

func TestS3NewAttachmentReservesBodyCapacity(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, nil)
	for i := 0; i < s3MaxObjects-2; i++ {
		fake.put(fmt.Sprintf("%s/%s/chart-%d.png", s3TestPrefix, s3TestMarker, i), s3TestMarker, "image/png", []byte("image"))
	}
	adapter, _ := newS3TestAdapter(t, fake)
	ctx := context.Background()
	err := adapter.UploadDocumentAttachment(ctx, s3TestMarker, ports.DocumentImage{Name: "over.png", MediaType: "image/png", Data: []byte("image")})
	if refusal := s3Refusal(t, err); refusal.Code != "publication_too_large" || len(fake.puts) != 0 {
		t.Fatalf("new attachment consumed the reserved body slot: %+v", refusal)
	}
	state, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = adapter.WriteDocumentRevision(ctx, state.RemotePage, "At capacity", "<p>bounded</p>", s3TestMarker); err != nil {
		t.Fatalf("reserved body write failed: %v", err)
	}
	if _, err = adapter.GetDocument(ctx, s3TestMarker); err != nil {
		t.Fatalf("publication became unreadable at capacity: %v", err)
	}
	if err = adapter.PurgeDocument(ctx, s3TestMarker, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("publication became unpurgeable at capacity: %v", err)
	}
}

func TestS3LostBodyAcknowledgementIsAmbiguous(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, nil)
	adapter, server := newS3TestAdapter(t, fake)
	ctx := context.Background()
	state, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.ServeHTTP(w, r)
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/"+s3BodyName) {
			panic(http.ErrAbortHandler)
		}
	})
	_, err = adapter.WriteDocumentRevision(ctx, state.RemotePage, "Stored", "<p>stored</p>", "synapse-intent-lost-ack")
	var refusal *ports.DocumentProviderError
	if !errors.As(err, &refusal) || !refusal.Ambiguous {
		t.Fatalf("lost acknowledgement must preserve uncertainty, got %v", err)
	}
	if len(fake.puts) != 1 {
		t.Fatalf("the SDK retried a dispatched write: puts=%v", fake.puts)
	}
	stored, err := adapter.GetDocument(ctx, s3TestMarker)
	if err != nil || stored.Marker != "synapse-intent-lost-ack" {
		t.Fatalf("the stored current release must remain observable for reconciliation: %+v, %v", stored, err)
	}
}

func TestS3CancellationCannotConfirmAbsence(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "Report", "<p>content</p>"))
	adapter, server := newS3TestAdapter(t, fake)
	ctx, cancel := context.WithCancel(context.Background())
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Has("versions") {
			cancel()
			return
		}
		fake.ServeHTTP(w, r)
	})
	if err := adapter.PurgeDocument(ctx, s3TestMarker, func(context.Context) error { return nil }); err == nil {
		t.Fatal("cancelled enumeration confirmed publication absence")
	}
	if len(fake.deletes) != 0 {
		t.Fatal("cancelled enumeration dispatched a delete")
	}
}

func TestS3PurgePreservesConcurrentAddition(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "Report", "<p>content</p>"))
	adapter, server := newS3TestAdapter(t, fake)
	key := adapter.key(s3TestMarker, "foreign.png")
	var once sync.Once
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			once.Do(func() { fake.put(key, "foreign-owner", "image/png", []byte("foreign bytes")) })
		}
		fake.ServeHTTP(w, r)
	})
	err := adapter.PurgeDocument(context.Background(), s3TestMarker, func(context.Context) error { return nil })
	if refusal := s3Refusal(t, err); !refusal.Ambiguous {
		t.Fatalf("a concurrent addition must leave purge uncertain: %+v", refusal)
	}
	if current, ok := fake.head(key); !ok || current.marker != "foreign-owner" {
		t.Fatal("purge deleted an object outside its inspected snapshot")
	}
}

func TestS3PurgeRequiresReadableLockState(t *testing.T) {
	for _, failure := range []string{"object-lock", "legal-hold", "retention"} {
		t.Run(failure, func(t *testing.T) {
			fake := newFakeS3()
			seedS3Publication(fake, s3Document(t, "Report", "<p>content</p>"))
			fake.objectLock = true
			adapter, server := newS3TestAdapter(t, fake)
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Has(failure) {
					fake.xmlError(w, http.StatusForbidden, "AccessDenied")
					return
				}
				fake.ServeHTTP(w, r)
			})
			if err := adapter.PurgeDocument(context.Background(), s3TestMarker, func(context.Context) error { return nil }); err == nil || len(fake.deletes) != 0 {
				t.Fatalf("unreadable %s must refuse before any deletion: %v, deletes=%v", failure, err, fake.deletes)
			}
		})
	}
}

func TestS3BoundedListingsDoNotRetainProducerGoroutines(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, nil)
	for i := 0; i < s3MaxHistoryVersions+1; i++ {
		fake.put(fmt.Sprintf("%s/%s/asset-%d.png", s3TestPrefix, s3TestMarker, i), s3TestMarker, "image/png", nil)
	}
	adapter, _ := newS3TestAdapter(t, fake)
	producers := func() int {
		stacks := make([]byte, 4<<20)
		size := runtime.Stack(stacks, true)
		return strings.Count(string(stacks[:size]), "minio-go/v7.(*Client).ListObjects.func1(")
	}
	before := producers()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 10; i++ {
		if _, err := adapter.publicationObjects(ctx, s3TestMarker); err == nil {
			t.Fatal("expected current-object budget refusal")
		}
		if _, err := adapter.allVersions(ctx, s3TestMarker); err == nil {
			t.Fatal("expected historical-version budget refusal")
		}
	}
	if after := producers(); after != before {
		t.Fatalf("bounded listing retained SDK producer goroutines: before=%d after=%d", before, after)
	}
}

func TestS3LockedHistoryFitsWorkerBudget(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, nil)
	fake.objectLock = true
	for i := 0; i < s3WriteHistoryLimit-1; i++ {
		fake.put(s3TestPrefix+"/"+s3TestMarker+"/"+s3BodyName, s3TestMarker, "text/html", s3Document(t, "Report", "<p>content</p>"))
	}
	adapter, server := newS3TestAdapter(t, fake)
	var requests atomic.Int64
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		timer := time.NewTimer(60 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		fake.ServeHTTP(w, r)
	})
	// Leave ten seconds of the 45-second worker pass for its preliminary work.
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	started := time.Now()
	err := adapter.PurgeDocument(ctx, s3TestMarker, func(ctx context.Context) error {
		// Include a realistic nonzero authorization-query cost for each delete.
		timer := time.NewTimer(5 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	})
	fake.mu.Lock()
	remaining := len(fake.objects)
	deletes := len(fake.deletes)
	fake.mu.Unlock()
	t.Logf("versions=%d latency=60ms guard=5ms elapsed=%s requests=%d deletes=%d remaining=%d", s3WriteHistoryLimit, time.Since(started), requests.Load(), deletes, remaining)
	if err != nil || remaining != 0 || deletes != s3WriteHistoryLimit {
		t.Fatalf("admitted locked history did not finish inside the worker budget: %v", err)
	}
}

func TestS3PurgeWaitsForEveryConcurrentProof(t *testing.T) {
	fake := newFakeS3()
	seedS3Publication(fake, s3Document(t, "Report", "<p>content</p>"))
	fake.put(s3TestPrefix+"/"+s3TestMarker+"/foreign.pdf", "foreign-owner", "application/pdf", []byte("foreign"))
	adapter, server := newS3TestAdapter(t, fake)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "/foreign.pdf") {
			once.Do(func() { close(entered) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		fake.ServeHTTP(w, r)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- adapter.PurgeDocument(ctx, s3TestMarker, func(context.Context) error { return nil }) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("foreign version proof did not start")
	}
	fake.mu.Lock()
	deletes := len(fake.deletes)
	fake.mu.Unlock()
	close(release)
	if deletes != 0 {
		t.Fatalf("purge deleted %d versions before the last proof finished", deletes)
	}
	if err := <-result; err == nil {
		t.Fatal("foreign historical version passed concurrent proof")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.deletes) != 0 {
		t.Fatal("failed concurrent proof allowed a delete")
	}
}
