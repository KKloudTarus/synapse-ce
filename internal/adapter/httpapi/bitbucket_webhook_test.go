package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestBitbucketSignatureAndAuthenticatedTenant(t *testing.T) {
	for _, tc := range []struct {
		name, header, signature, id string
		status                      int
	}{
		{"correct", bitbucketSignatureHeader, "correct", "{11111111-1111-1111-1111-111111111111}", 202},
		{"wrong", bitbucketSignatureHeader, "wrong", "11111111-1111-1111-1111-111111111111", 401},
		{"generic header refused", inboundWebhookSignature, "correct", "11111111-1111-1111-1111-111111111111", 401},
		{"missing uuid", bitbucketSignatureHeader, "correct", "", 400},
		{"invalid uuid", bitbucketSignatureHeader, "correct", "not-a-uuid", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, store, receiver, _ := setupHook(t)
			e := store.records[hookIDA]
			e.Provider = "bitbucket"
			store.records[hookIDA] = e
			body := `{"push":{"changes":[]}}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/hooks/"+hookIDA+"", strings.NewReader(body))
			sig := webhookSig(hookSecret('a'), []byte(body))
			if tc.signature == "wrong" {
				sig = webhookSig(hookSecret('b'), []byte(body))
			}
			req.Header.Set(tc.header, sig)
			req.Header.Set(bitbucketEventHeader, "repo:push")
			req.Header.Set(bitbucketRequestHeader, tc.id)
			// Human auth and caller tenant never supply hook identity.
			req.Header.Set("Authorization", "Bearer attacker")
			req.Header.Set("X-Tenant-ID", "tenant-B")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			if tc.status == 202 {
				got := receiver.snapshot()
				if len(got) != 1 || got[0].tenant != "tenant-A" || got[0].provider != "bitbucket" || got[0].eventID != "11111111-1111-1111-1111-111111111111" {
					t.Fatalf("receiver=%+v", got)
				}
			} else if len(receiver.snapshot()) != 0 {
				t.Fatal("invalid request invoked receiver")
			}
			if len(store.events) != 0 {
				t.Fatal("Bitbucket receipt claimed outside the receiver transaction")
			}
		})
	}
}
func TestBitbucketDuplicateHeadersAndPreviousKey(t *testing.T) {
	h, store, receiver, cipher := setupHook(t)
	e := store.records[hookIDA]
	e.Provider = "bitbucket"
	sealed, err := cipher.Seal(hookSecret('p'), ports.InboundWebhookAAD(e.TenantID, hookIDA, e.OwnerKind, e.OwnerID, e.CurrentVersion-1))
	if err != nil {
		t.Fatal(err)
	}
	e.PreviousSealed, e.PreviousExpiresAt = sealed, time.Now().Add(time.Hour)
	store.records[hookIDA] = e
	for _, duplicate := range []string{"", bitbucketSignatureHeader, bitbucketRequestHeader, bitbucketEventHeader} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hooks/"+hookIDA, strings.NewReader(`{}`))
		req.Header.Set(bitbucketSignatureHeader, webhookSig(hookSecret('p'), []byte(`{}`)))
		req.Header.Set(bitbucketEventHeader, "repo:push")
		req.Header.Set(bitbucketRequestHeader, "11111111-1111-1111-1111-111111111111")
		if duplicate != "" {
			req.Header.Add(duplicate, req.Header.Get(duplicate))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		want := 202
		if duplicate == bitbucketSignatureHeader {
			want = 401
		} else if duplicate != "" {
			want = 400
		}
		if w.Code != want {
			t.Fatalf("duplicate=%q status=%d body=%s", duplicate, w.Code, w.Body)
		}
	}
	if len(receiver.snapshot()) != 1 {
		t.Fatalf("received=%d", len(receiver.snapshot()))
	}
}
