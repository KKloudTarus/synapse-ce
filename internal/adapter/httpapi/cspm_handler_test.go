package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/cspm"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type cspmConnectorStub struct{ vault ports.CredentialVault }

func (c cspmConnectorStub) Enumerate(ctx context.Context, scope ports.CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	secret, err := c.vault.Resolve(ctx, scope.EngagementID, scope.CredentialRef)
	if err != nil {
		return cloudposture.Inventory{}, nil, err
	}
	for i := range secret {
		secret[i] = 0
	}
	return cloudposture.Inventory{Provider: cloudposture.ProviderAWS, Complete: false, Resources: []cloudposture.Resource{{Provider: cloudposture.ProviderAWS, ID: "bucket", Kind: asset.KindStorage, Public: cloudposture.StateEnabled}}}, []cloudposture.CoverageIssue{{Provider: cloudposture.ProviderAWS, Scope: "account", Category: "identity", Code: "permission_denied"}}, nil
}
func (c cspmConnectorStub) Evaluate(_ context.Context, inv cloudposture.Inventory) ([]cloudposture.PostureFinding, error) {
	return cloudposture.Evaluate(inv)
}

type cspmClock struct{ t time.Time }

func (c cspmClock) Now() time.Time { return c.t }

type cspmIDs struct{ n int }

func (i *cspmIDs) NewID() shared.ID { i.n++; return shared.ID("asset") }

type cspmAudit struct{ entries []ports.AuditEntry }

func (a *cspmAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type cspmEvidenceStub struct{}

func (cspmEvidenceStub) SealCloudSnapshot(context.Context, shared.ID, cloudposture.Inventory, []cloudposture.CoverageIssue, string) (shared.ID, string, error) {
	return "evidence", "hash", nil
}

type cspmExecutorStub struct{ connector ports.CloudConnector }

func (s cspmExecutorStub) EnumerateCloud(ctx context.Context, scope ports.CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	return s.connector.Enumerate(ctx, scope)
}

func TestCSPMFullRunDoesNotLeakCredential(t *testing.T) {
	secret := "CSPM-sentinel-secret-429"
	now := time.Unix(1, 0)
	cipher, err := vault.NewCipher(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	vaultStore := vault.NewMemoryVault(cipher, func() time.Time { return now })
	if err := vaultStore.Put(context.Background(), "eng", "aws-prod", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), principalKey, Principal{ID: "operator", TenantID: "tenant"})
	audit := &cspmAudit{}
	assetsStore := memory.NewAssetStore()
	assets, _ := assetuc.NewService(assetsStore, audit, cspmClock{now}, &cspmIDs{})
	findings := memory.NewFindingRepository()
	observations := memory.NewCloudObservationStore()
	findings.SetCloudObservationStore(observations)
	engagements := memory.NewEngagementRepository()
	eng, _ := engagement.New("eng", "tenant", "cloud", "client", now)
	eng.Status = engagement.StatusActive
	eng.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetCloudAccount, Value: "organization/o-1"}}}
	_ = engagements.Create(ctx, eng)
	service, _ := cspm.NewService(map[cloudposture.Provider]ports.CloudConnector{cloudposture.ProviderAWS: cspmConnectorStub{vault: vaultStore}}, assets, findings, engagements, audit, cspmClock{now})
	service.SetEvidenceSealer(cspmEvidenceStub{})
	service.SetObservationStore(observations)
	service.SetSandboxExecutor(cspmExecutorStub{connector: cspmConnectorStub{vault: vaultStore}})
	runs := memory.NewCloudRunStore()
	queue := memory.NewJobQueue(&cspmIDs{}, func() time.Time { return now })
	_ = service.SetDurableExecution(runs, queue, &cspmIDs{})
	service.SetRunLock(memory.NewRunLock())
	var logs bytes.Buffer
	router := &Router{log: slog.New(slog.NewTextHandler(&logs, nil))}
	router.SetCSPM(service)
	body := `{"targets":[{"provider":"aws","root":"organization/o-1","credential_ref":"aws-prod"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng/cspm/runs", strings.NewReader(body)).WithContext(ctx)
	req.SetPathValue("id", "eng")
	res := httptest.NewRecorder()
	router.runCSPM(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	job, err := queue.Claim(ctx, time.Minute, cspm.JobKind)
	if err != nil || job == nil {
		t.Fatalf("claim CSPM job: %v", err)
	}
	if err := service.RunJob(shared.WithTenant(ctx, "tenant"), job.Payload); err != nil {
		t.Fatal(err)
	}
	assetsOut, _ := assetsStore.ListAssets(ctx, "tenant")
	findingsOut, _ := findings.ListByEngagement(ctx, "eng")
	refs, _ := vaultStore.List(ctx, "eng")
	payload, _ := json.Marshal([]any{res.Body.String(), logs.String(), audit.entries, assetsOut, findingsOut, refs})
	for _, encoded := range []string{secret, base64.StdEncoding.EncodeToString([]byte(secret)), url.QueryEscape(secret), hex.EncodeToString([]byte(secret))} {
		if bytes.Contains(payload, []byte(encoded)) {
			t.Fatalf("credential leaked as %q", encoded)
		}
	}
}
