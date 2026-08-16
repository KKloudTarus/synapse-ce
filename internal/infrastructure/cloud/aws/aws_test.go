package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/smithy-go"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestEnumeratePaginatesCategoriesWithoutCredentialLeakage(t *testing.T) {
	const secret = "TOP-SECRET-ACCESS-KEY"
	server, emulator := awsEmulator(t, false, false)
	connector := newTestConnector(t, server.URL, secret)
	inventory, gaps, err := connector.Enumerate(context.Background(), testScope())
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Complete || !hasGap(gaps, "regions", "unsupported") || !hasGap(gaps, "identity-policy", "unsupported") {
		t.Fatalf("coverage = %#v", gaps)
	}
	want := map[string]int{"cloud_account": 2, "host": 4, "storage": 4, "exposure": 4, "identity": 4}
	if got := resourceKinds(inventory); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("resource categories = %#v, want %#v", got, want)
	}
	for _, operation := range []string{"DescribeOrganization", "ListAccounts", "DescribeInstances", "ListBuckets", "GetBucketPolicyStatus", "GetBucketEncryption", "DescribeSecurityGroups", "ListUsers"} {
		minimum := 2
		if operation == "DescribeOrganization" || operation == "GetBucketPolicyStatus" || operation == "GetBucketEncryption" {
			minimum = 1
		}
		if emulator.calls(operation) < minimum {
			t.Fatalf("%s was not paginated: %#v", operation, emulator.counts)
		}
	}
	if strings.Contains(emulator.traffic.String(), secret) {
		t.Fatal("credential secret appeared in provider traffic")
	}
}

func TestProviderRequestAuthorizationRunsForEverySDKAttempt(t *testing.T) {
	server, emulator := awsEmulator(t, false, false)
	connector := newTestConnector(t, server.URL, "TOP-SECRET-ACCESS-KEY")
	var mu sync.Mutex
	var operations []string
	scope := testScope()
	scope.Authorize = func(_ context.Context, operation ports.CloudOperation) error {
		mu.Lock()
		operations = append(operations, operation.Name)
		mu.Unlock()
		return nil
	}
	if _, _, err := connector.Enumerate(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(operations) == 0 || len(operations) < emulator.calls("DescribeInstances") {
		t.Fatalf("authorizations=%#v requests=%#v", operations, emulator.counts)
	}
	for _, operation := range operations {
		if operation == "unknown-read-operation" {
			t.Fatalf("unknown provider operation: %#v", operations)
		}
	}
}

func TestEnumerateReconstructsCanonicalScopeKey(t *testing.T) {
	server, _ := awsEmulator(t, false, false)
	connector := newTestConnector(t, server.URL, "TOP-SECRET-ACCESS-KEY")
	scope := testScope()
	scope.ScopeKey = ""
	scope.Authorize = func(_ context.Context, operation ports.CloudOperation) error {
		if operation.ScopeKey != "aws:organizations/o-example" {
			t.Fatalf("scope key = %q", operation.ScopeKey)
		}
		return nil
	}
	if _, _, err := connector.Enumerate(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
}

func TestEnumerateReportsPermissionAndUnreachableAccounts(t *testing.T) {
	for _, test := range []struct {
		name, want        string
		deny, unreachable bool
	}{
		{name: "permission", deny: true, want: "permission_denied"},
		{name: "unreachable", unreachable: true, want: "unreachable_account"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _ := awsEmulator(t, test.deny, test.unreachable)
			connector := newTestConnector(t, server.URL, "TOP-SECRET-ACCESS-KEY")
			inventory, gaps, err := connector.Enumerate(context.Background(), testScope())
			if err != nil {
				t.Fatal(err)
			}
			if inventory.Complete || !hasGapCode(gaps, test.want) {
				t.Fatalf("inventory=%#v gaps=%#v", inventory, gaps)
			}
		})
	}
}

type memoryVault struct{ secret []byte }

var _ ports.CredentialVault = (*memoryVault)(nil)

func (m memoryVault) Put(context.Context, shared.ID, string, []byte) error { return nil }
func (m memoryVault) Resolve(context.Context, shared.ID, string) ([]byte, error) {
	return append([]byte(nil), m.secret...), nil
}
func (m memoryVault) List(context.Context, shared.ID) ([]ports.CredentialMeta, error) {
	return nil, nil
}
func (m memoryVault) Delete(context.Context, shared.ID, string) error { return nil }

func newTestConnector(t *testing.T, endpoint, secret string) *Connector {
	t.Helper()
	connector, err := New(memoryVault{[]byte(`{"access_key_id":"access-key","secret_access_key":"` + secret + `","role_arn_template":"arn:aws:iam::{account_id}:role/SynapseReadOnly"}`)}, Options{Endpoint: endpoint, RequestsPerSecond: 10000})
	if err != nil {
		t.Fatal(err)
	}
	return connector
}

func testScope() ports.CloudScope {
	return ports.CloudScope{EngagementID: shared.ID("engagement"), Provider: cloudposture.ProviderAWS, Root: "o-example", CredentialRef: "aws-read-only", ScopeKey: "aws:organizations/o-example", Authorize: func(context.Context, ports.CloudOperation) error { return nil }}
}

func hasGap(gaps []cloudposture.CoverageIssue, category, code string) bool {
	for _, gap := range gaps {
		if gap.Category == category && gap.Code == code {
			return true
		}
	}
	return false
}

func hasGapCode(gaps []cloudposture.CoverageIssue, code string) bool {
	for _, gap := range gaps {
		if gap.Code == code {
			return true
		}
	}
	return false
}

func resourceKinds(inventory cloudposture.Inventory) map[string]int {
	out := map[string]int{}
	for _, resource := range inventory.Resources {
		out[string(resource.Kind)]++
	}
	return out
}

type emulatorState struct {
	mu      sync.Mutex
	counts  map[string]int
	traffic strings.Builder
}

func (s *emulatorState) calls(operation string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[operation]
}

func awsEmulator(t *testing.T, deny, unreachable bool) (*httptest.Server, *emulatorState) {
	t.Helper()
	state := &emulatorState{counts: map[string]int{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		action := r.Form.Get("Action")
		if action == "" {
			var input struct {
				Action string `json:"Action"`
			}
			_ = json.Unmarshal(body, &input)
			action = input.Action
		}
		if action == "" {
			action = r.URL.Query().Get("x-id")
		}
		if action == "" && r.URL.Query().Has("policyStatus") {
			action = "GetBucketPolicyStatus"
		}
		if action == "" && r.URL.Query().Has("encryption") {
			action = "GetBucketEncryption"
		}
		if action == "" {
			action = r.Header.Get("X-Amz-Target")
			if i := strings.LastIndex(action, "."); i >= 0 {
				action = action[i+1:]
			}
		}
		state.mu.Lock()
		state.counts[action]++
		state.traffic.WriteString(r.URL.String())
		state.traffic.WriteByte('\n')
		for _, value := range r.Header.Values("Authorization") {
			state.traffic.WriteString(value)
		}
		state.mu.Unlock()
		if deny && action == "DescribeInstances" {
			writeQueryError(w, http.StatusForbidden, "AccessDenied", "missing permission")
			return
		}
		if unreachable && action == "AssumeRole" {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		switch action {
		case "DescribeOrganization":
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			fmt.Fprint(w, `{"Organization":{"Id":"o-example","Arn":"arn:aws:organizations::111111111111:organization/o-example","FeatureSet":"ALL","MasterAccountId":"111111111111","MasterAccountArn":"arn:aws:organizations::111111111111:account/o-example/a","MasterAccountEmail":"root@example.invalid"}}`)
		case "ListAccounts":
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			if hasPageToken(body, r) {
				fmt.Fprint(w, `{"Accounts":[{"Id":"222222222222","Arn":"arn:aws:organizations::222222222222:account/o-example/b","Name":"second"}]}`)
				return
			}
			if deny || unreachable {
				fmt.Fprint(w, `{"Accounts":[{"Id":"111111111111","Arn":"arn:aws:organizations::111111111111:account/o-example/a","Name":"first"}]}`)
				return
			}
			fmt.Fprint(w, `{"Accounts":[{"Id":"111111111111","Arn":"arn:aws:organizations::111111111111:account/o-example/a","Name":"first"}],"NextToken":"page-2"}`)
		case "AssumeRole":
			fmt.Fprint(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>temporary</AccessKeyId><SecretAccessKey>temporary-secret</SecretAccessKey><SessionToken>temporary-token</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
		case "DescribeInstances":
			if hasPageToken(body, r) {
				fmt.Fprint(w, `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><instancesSet><item><instanceId>i-second</instanceId></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`)
				return
			}
			fmt.Fprint(w, `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><instancesSet><item><instanceId>i-first</instanceId><ipAddress>203.0.113.7</ipAddress></item></instancesSet></item></reservationSet><nextToken>page-2</nextToken></DescribeInstancesResponse>`)
		case "ListBuckets":
			if hasPageToken(body, r) {
				fmt.Fprint(w, `<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets><Bucket><Name>second-bucket</Name></Bucket></Buckets></ListAllMyBucketsResult>`)
				return
			}
			fmt.Fprint(w, `<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets><Bucket><Name>first-bucket</Name></Bucket></Buckets><ContinuationToken>page-2</ContinuationToken></ListAllMyBucketsResult>`)
		case "GetBucketPolicyStatus":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<PolicyStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsPublic>true</IsPublic></PolicyStatus>`)
		case "GetBucketEncryption":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`)
		case "DescribeSecurityGroups":
			if hasPageToken(body, r) {
				fmt.Fprint(w, `<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><securityGroupInfo><item><groupId>sg-second</groupId><groupName>second</groupName></item></securityGroupInfo></DescribeSecurityGroupsResponse>`)
				return
			}
			fmt.Fprint(w, `<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><securityGroupInfo><item><groupId>sg-first</groupId><groupName>first</groupName><ipPermissions><item><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item></ipPermissions></item></securityGroupInfo><nextToken>page-2</nextToken></DescribeSecurityGroupsResponse>`)
		case "ListUsers":
			if hasPageToken(body, r) {
				fmt.Fprint(w, `<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListUsersResult><Users><member><Arn>arn:aws:iam::222222222222:user/second</Arn><UserName>second</UserName></member></Users></ListUsersResult></ListUsersResponse>`)
				return
			}
			fmt.Fprint(w, `<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListUsersResult><Users><member><Arn>arn:aws:iam::111111111111:user/first</Arn><UserName>first</UserName></member></Users><IsTruncated>true</IsTruncated><Marker>page-2</Marker></ListUsersResult></ListUsersResponse>`)
		default:
			t.Errorf("unexpected AWS operation %q (%s): %s", action, r.URL.String(), body)
		}
	}))
	return server, state
}

func hasPageToken(body []byte, r *http.Request) bool {
	return strings.Contains(string(body), "page-2") || r.URL.Query().Get("continuation-token") == "page-2"
}

func writeQueryError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Code>%s</Code><Message>%s</Message></Error></ErrorResponse>`, code, message)
}
func TestLeastPrivilegeActionsIsImmutable(t *testing.T) {
	actions := LeastPrivilegeActions()
	actions[0] = "mutated"
	if LeastPrivilegeActions()[0] == "mutated" {
		t.Fatal("permission manifest may be mutated by callers")
	}
}

// TestListAccountsRespectsProviderPageLimit pins the ListAccounts page size to what AWS
// Organizations actually accepts. MaxAccounts is our TOTAL bound (default 100), but the API
// rejects a MaxResults above 20 with InvalidInputException instead of clamping it, so sending the
// total bound failed account enumeration on every real organization and surfaced as an opaque
// "provider_error" coverage gap - with zero assets and zero findings - after DescribeOrganization
// had already succeeded.
func TestListAccountsRespectsProviderPageLimit(t *testing.T) {
	var mu sync.Mutex
	var requested []int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		action := r.Header.Get("X-Amz-Target")
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch {
		case strings.HasSuffix(action, "DescribeOrganization"):
			fmt.Fprint(w, `{"Organization":{"Id":"o-example","Arn":"arn:aws:organizations::111111111111:organization/o-example","FeatureSet":"ALL","MasterAccountId":"111111111111"}}`)
		case strings.HasSuffix(action, "ListAccounts"):
			var input struct {
				MaxResults *int64 `json:"MaxResults"`
			}
			_ = json.Unmarshal(body, &input)
			mu.Lock()
			if input.MaxResults != nil {
				requested = append(requested, *input.MaxResults)
			}
			mu.Unlock()
			// Mirror the real API: oversized page sizes are REJECTED, never clamped.
			if input.MaxResults != nil && *input.MaxResults > maxListAccountsPageSize {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"__type":"InvalidInputException","message":"You provided a value that exceeds the maximum allowed."}`)
				return
			}
			fmt.Fprint(w, `{"Accounts":[{"Id":"111111111111","Arn":"arn:aws:organizations::111111111111:account/o-example/a","Name":"first"}]}`)
		default:
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"__type":"AccessDeniedException","message":"denied"}`)
		}
	}))
	defer server.Close()

	connector := newTestConnector(t, server.URL, "TOP-SECRET-ACCESS-KEY")
	inventory, gaps, err := connector.Enumerate(context.Background(), testScope())
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]int64(nil), requested...)
	mu.Unlock()
	if len(got) == 0 {
		t.Fatal("ListAccounts was never called")
	}
	for _, size := range got {
		if size > maxListAccountsPageSize {
			t.Fatalf("ListAccounts MaxResults = %d, want <= %d (AWS rejects larger values)", size, maxListAccountsPageSize)
		}
	}
	if hasGapCode(gaps, "provider_error") {
		t.Fatalf("account enumeration reported a provider error: %#v", gaps)
	}
	if len(inventory.Resources) == 0 {
		t.Fatal("no accounts were enumerated")
	}
}

// TestAbsentBucketConfigIsAnObservedNegative pins the difference between "the provider told us the
// configuration does not exist" and "we could not observe it". NoSuchBucketPolicy and
// ServerSideEncryptionConfigurationNotFoundError are definitive negatives, but they were recorded as
// storage coverage gaps: that invented a provider_error on healthy accounts AND left Public/Encrypted
// unknown, so an unencrypted bucket produced no posture finding at all.
func TestAbsentBucketConfigIsAnObservedNegative(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-Amz-Target")
		switch {
		case strings.HasSuffix(action, "DescribeOrganization"):
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			fmt.Fprint(w, `{"Organization":{"Id":"o-example","Arn":"arn:aws:organizations::111111111111:organization/o-example","FeatureSet":"ALL","MasterAccountId":"111111111111"}}`)
		case strings.HasSuffix(action, "ListAccounts"):
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			fmt.Fprint(w, `{"Accounts":[{"Id":"111111111111","Arn":"arn:aws:organizations::111111111111:account/o-example/a","Name":"first"}]}`)
		case strings.Contains(r.URL.RawQuery, "policyStatus"):
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<Error><Code>NoSuchBucketPolicy</Code><Message>The bucket policy does not exist</Message></Error>`)
		case strings.Contains(r.URL.RawQuery, "encryption"):
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<Error><Code>ServerSideEncryptionConfigurationNotFoundError</Code><Message>absent</Message></Error>`)
		case strings.Contains(r.URL.Path, "AssumeRole") || strings.Contains(r.URL.RawQuery, "AssumeRole"):
			fmt.Fprint(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>temporary</AccessKeyId><SecretAccessKey>temporary-secret</SecretAccessKey><SessionToken>temporary-token</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
		default:
			body, _ := io.ReadAll(r.Body)
			if bytes.Contains(body, []byte("AssumeRole")) {
				fmt.Fprint(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>temporary</AccessKeyId><SecretAccessKey>temporary-secret</SecretAccessKey><SessionToken>temporary-token</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
				return
			}
			fmt.Fprint(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>plain</Name></Bucket></Buckets></ListAllMyBucketsResult>`)
		}
	}))
	defer server.Close()

	connector := newTestConnector(t, server.URL, "TOP-SECRET-ACCESS-KEY")
	inventory, gaps, err := connector.Enumerate(context.Background(), testScope())
	if err != nil {
		t.Fatal(err)
	}
	if hasGap(gaps, "storage", "provider_error") {
		t.Errorf("absent bucket configuration was reported as a provider error: %#v", gaps)
	}
	var bucket *cloudposture.Resource
	for i := range inventory.Resources {
		if inventory.Resources[i].Kind == asset.KindStorage {
			bucket = &inventory.Resources[i]
			break
		}
	}
	if bucket == nil {
		t.Fatal("bucket was not enumerated")
	}
	if bucket.Encrypted != cloudposture.StateDisabled {
		t.Errorf("Encrypted = %q, want %q (absent configuration means NOT encrypted)", bucket.Encrypted, cloudposture.StateDisabled)
	}
	if bucket.Public != cloudposture.StateDisabled {
		t.Errorf("Public = %q, want %q (no bucket policy means not public by policy)", bucket.Public, cloudposture.StateDisabled)
	}
}

// TestIsAbsentConfigOnlyMatchesTheNamedCode keeps the carve-out narrow: a real permission or
// transport failure must still become a coverage gap, never a silent negative.
func TestIsAbsentConfigOnlyMatchesTheNamedCode(t *testing.T) {
	absent := &smithy.GenericAPIError{Code: "NoSuchBucketPolicy", Message: "absent"}
	if !isAbsentConfig(absent, "NoSuchBucketPolicy") {
		t.Error("the named absence code was not recognized")
	}
	if isAbsentConfig(absent, "ServerSideEncryptionConfigurationNotFoundError") {
		t.Error("an absence code matched a DIFFERENT configuration's code")
	}
	if isAbsentConfig(&smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}, "NoSuchBucketPolicy") {
		t.Error("AccessDenied was treated as an observed negative")
	}
	if isAbsentConfig(errors.New("connection reset"), "NoSuchBucketPolicy") {
		t.Error("a transport error was treated as an observed negative")
	}
}

// TestSuccessfulCallWithNilConfigStaysUnknown is the review finding this file previously missed. Only
// the named ABSENCE ERROR CODES are evidence of absence. A 200 response carrying a nil config field
// is not: recording it as a definitive negative manufactures an evidence-backed posture claim out of
// a missing field, which is the same category error as treating a real absence as a failure.
func TestSuccessfulCallWithNilConfigStaysUnknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-Amz-Target")
		switch {
		case strings.HasSuffix(action, "DescribeOrganization"):
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			fmt.Fprint(w, `{"Organization":{"Id":"o-example","Arn":"arn:aws:organizations::111111111111:organization/o-example","FeatureSet":"ALL","MasterAccountId":"111111111111"}}`)
		case strings.HasSuffix(action, "ListAccounts"):
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			fmt.Fprint(w, `{"Accounts":[{"Id":"111111111111","Arn":"arn:aws:organizations::111111111111:account/o-example/a","Name":"first"}]}`)
		case strings.Contains(r.URL.RawQuery, "policyStatus"), strings.Contains(r.URL.RawQuery, "encryption"):
			// 200 OK carrying no configuration field at all - a successful call that establishes
			// nothing. This is NOT one of the named absence error codes.
			w.WriteHeader(http.StatusOK)
		default:
			body, _ := io.ReadAll(r.Body)
			if bytes.Contains(body, []byte("AssumeRole")) {
				fmt.Fprint(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>temporary</AccessKeyId><SecretAccessKey>temporary-secret</SecretAccessKey><SessionToken>temporary-token</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
				return
			}
			fmt.Fprint(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>plain</Name></Bucket></Buckets></ListAllMyBucketsResult>`)
		}
	}))
	defer server.Close()

	connector := newTestConnector(t, server.URL, "TOP-SECRET-ACCESS-KEY")
	inventory, _, err := connector.Enumerate(context.Background(), testScope())
	if err != nil {
		t.Fatal(err)
	}
	var bucket *cloudposture.Resource
	for i := range inventory.Resources {
		if inventory.Resources[i].Kind == asset.KindStorage {
			bucket = &inventory.Resources[i]
			break
		}
	}
	if bucket == nil {
		t.Fatal("bucket was not enumerated")
	}
	if bucket.Encrypted != cloudposture.StateUnknown {
		t.Errorf("Encrypted = %q, want %q (a nil config field on a 200 is not evidence of absence)", bucket.Encrypted, cloudposture.StateUnknown)
	}
	if bucket.Public != cloudposture.StateUnknown {
		t.Errorf("Public = %q, want %q (a nil policy-status field on a 200 is not evidence of absence)", bucket.Public, cloudposture.StateUnknown)
	}
}
