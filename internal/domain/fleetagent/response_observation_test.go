package fleetagent

import (
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
)

func validResponseObservationRequest() ResponseObservationRequest {
	attemptedAt := time.Unix(2_000_000, 0).UTC()
	return ResponseObservationRequest{
		ProtocolVersion: ResponseObservationProtocolVersion, RequestID: "request-1", TenantID: "tenant-1",
		ObserverAgentID: "observer-1", AssetID: "asset-1", EngagementID: "eng-1", ActionID: "action-1",
		ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-1", ReceiptID: "receipt", ReceiptDigest: "0000000000000000000000000000000000000000000000000000000000000000", VerificationChallenge: strings.Repeat("b", 64),
		Target: responsesaga.TargetFingerprint{
			Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1",
		},
		AttemptedAt: attemptedAt, IssuedAt: attemptedAt.Add(time.Second), NotAfter: attemptedAt.Add(time.Minute),
	}
}

func TestResponseObservationRequestValidationAndDigest(t *testing.T) {
	request := validResponseObservationRequest()
	if err := request.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	digest := ResponseObservationRequestDigest(request)
	changed := request
	changed.ObserverAgentID = "observer-2"
	if ResponseObservationRequestDigest(changed) == digest {
		t.Fatal("digest did not bind observer identity")
	}
	changed = request
	changed.Target.ProcessAssetID = "asset-2"
	if err := changed.Validate(); err == nil {
		t.Fatal("request with mismatched target asset must fail")
	}
	changed = request
	changed.IssuedAt = changed.AttemptedAt.Add(-time.Second)
	if err := changed.Validate(); err == nil {
		t.Fatal("request issued before the attempt must fail")
	}
}
