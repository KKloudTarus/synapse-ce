package documentproviders

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	policyTestBucket    = "synapse-reports"
	policyTestPrefix    = "publications"
	policyTestPrincipal = "arn:aws:iam::123456789012:role/report-readers"
)

func policyTestDocument(statements string) string {
	return `{"Version":"2012-10-17","Statement":[` + statements + `]}`
}

func policyTestStatement(principal, action, resource string) string {
	return `{"Effect":"Allow","Principal":` + principal + `,"Action":` + action + `,"Resource":` + resource + `}`
}

func policyRefusal(t *testing.T, err error) *ports.DocumentProviderError {
	t.Helper()
	var refusal *ports.DocumentProviderError
	if !errors.As(err, &refusal) {
		t.Fatalf("expected DocumentProviderError, got %T: %v", err, err)
	}
	return refusal
}

func TestVerifyS3ReaderPolicy(t *testing.T) {
	fullPrefix := `"arn:aws:s3:::` + policyTestBucket + `/` + policyTestPrefix + `/*"`
	exactObject := `"arn:aws:s3:::` + policyTestBucket + `/` + policyTestPrefix + `/report.html"`
	reader := `{"AWS":"` + policyTestPrincipal + `"}`
	foreign := `{"AWS":"arn:aws:iam::123456789012:role/other"}`

	for _, tc := range []struct {
		name           string
		policy         string
		wantCode       string
		wantRestricted bool
	}{
		{
			name:   "accepts one unconditional canonical reader",
			policy: policyTestDocument(policyTestStatement(reader, `"s3:GetObject"`, fullPrefix)),
		},
		{
			name:     "does not treat one descendant as the whole prefix",
			policy:   policyTestDocument(policyTestStatement(reader, `"s3:GetObject"`, exactObject)),
			wantCode: "reader_policy_unverifiable",
		},
		{
			name:           "refuses public descendant grant",
			policy:         policyTestDocument(policyTestStatement(`"*"`, `"s3:GetObject"`, exactObject) + `,` + policyTestStatement(reader, `"s3:GetObject"`, fullPrefix)),
			wantCode:       "public_bucket_policy",
			wantRestricted: true,
		},
		{
			name:           "refuses foreign overlapping wildcard grant",
			policy:         policyTestDocument(policyTestStatement(foreign, `"s3:Get*"`, `"arn:aws:s3:::`+policyTestBucket+`/`+policyTestPrefix+`/*"`) + `,` + policyTestStatement(reader, `"s3:GetObjectVersion"`, fullPrefix)),
			wantCode:       "unexpected_reader_principal",
			wantRestricted: true,
		},
		{
			name:     "rejects wildcard within a resource",
			policy:   policyTestDocument(policyTestStatement(reader, `"s3:GetObject"`, `"arn:aws:s3:::`+policyTestBucket+`/*/report.html"`)),
			wantCode: "reader_policy_unverifiable",
		},
		{
			name:     "rejects unsupported principal namespace",
			policy:   policyTestDocument(policyTestStatement(`{"Service":"lambda.amazonaws.com"}`, `"s3:GetObject"`, fullPrefix)),
			wantCode: "reader_policy_unverifiable",
		},
		{
			name:     "rejects duplicate statement keys",
			policy:   `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Effect":"Allow","Principal":` + reader + `,"Action":"s3:GetObject","Resource":` + fullPrefix + `}]}`,
			wantCode: "reader_policy_unverifiable",
		},
		{
			name:     "rejects unsupported action glob before skip",
			policy:   policyTestDocument(policyTestStatement(reader, `"s3:Put*"`, `"arn:aws:s3:::`+policyTestBucket+`/unrelated/*"`) + `,` + policyTestStatement(reader, `"s3:GetObject"`, fullPrefix)),
			wantCode: "reader_policy_unverifiable",
		},
		{
			name:   "allows public deny alongside canonical reader",
			policy: policyTestDocument(`{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::` + policyTestBucket + `/*"},` + policyTestStatement(reader, `"s3:GetObject"`, fullPrefix)),
		},
		{
			name:           "does not allow deny to cancel public grant",
			policy:         policyTestDocument(`{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":` + fullPrefix + `},` + policyTestStatement(`"*"`, `"s3:GetObject"`, fullPrefix) + `,` + policyTestStatement(reader, `"s3:GetObject"`, fullPrefix)),
			wantCode:       "public_bucket_policy",
			wantRestricted: true,
		},
		{
			name:     "requires an unconditional canonical reader",
			policy:   policyTestDocument(`{"Effect":"Allow","Principal":` + reader + `,"Action":"s3:GetObject","Resource":` + fullPrefix + `,"Condition":{"StringEquals":{"aws:PrincipalArn":"` + policyTestPrincipal + `"}}}`),
			wantCode: "reader_policy_unverifiable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyS3ReaderPolicy(tc.policy, policyTestBucket, policyTestPrefix, policyTestPrincipal)
			if tc.wantCode == "" {
				if err != nil {
					t.Fatalf("verifyS3ReaderPolicy() error = %v", err)
				}
				return
			}
			refusal := policyRefusal(t, err)
			if refusal.Code != tc.wantCode || refusal.RestrictionLost != tc.wantRestricted {
				t.Fatalf("refusal = (%q, restricted=%v), want (%q, restricted=%v)", refusal.Code, refusal.RestrictionLost, tc.wantCode, tc.wantRestricted)
			}
		})
	}
}
