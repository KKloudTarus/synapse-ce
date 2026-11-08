package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDASTScanHandlerRejectsSecretsAndUnknownFields(t *testing.T) {
	for _, body := range []string{
		`{"target":"https://app.test","unknown":true}`,
		`{"target":"https://app.test","session":{"credentials":[{"name":"token","reference":"{{secret:token}}"}]}}`,
	} {
		rt := &Router{log: discardLog()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/e/dast/proposals", strings.NewReader(body))
		req.SetPathValue("id", "e")
		rec := httptest.NewRecorder()
		rt.proposeDASTScan(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
}
