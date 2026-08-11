// Package aws implements the read-only AWS cloud posture connector.
package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"golang.org/x/time/rate"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultRegion       = "us-east-1"
	defaultMaxAccounts  = 100
	defaultMaxResources = 1000
	defaultRate         = 5
)

var _ ports.CloudConnector = (*Connector)(nil)

// Options bounds provider calls and permits an emulator endpoint in tests.
type Options struct {
	Region                  string
	Endpoint                string
	HTTPClient              *http.Client
	MaxAccounts             int
	MaxResourcesPerCategory int
	RequestsPerSecond       int
}

// Connector obtains credential material only from the credential vault.
type Connector struct {
	vault   ports.CredentialVault
	opts    Options
	limiter *rate.Limiter
}

// New creates a read-only AWS connector. Credentials are resolved when a scope runs.
func New(vault ports.CredentialVault, opts Options) (*Connector, error) {
	if vault == nil {
		return nil, fmt.Errorf("%w: AWS connector requires a credential vault", shared.ErrValidation)
	}
	if opts.Region == "" {
		opts.Region = defaultRegion
	}
	if opts.MaxAccounts == 0 {
		opts.MaxAccounts = defaultMaxAccounts
	}
	if opts.MaxResourcesPerCategory == 0 {
		opts.MaxResourcesPerCategory = defaultMaxResources
	}
	if opts.RequestsPerSecond == 0 {
		opts.RequestsPerSecond = defaultRate
	}
	if opts.MaxAccounts < 1 || opts.MaxResourcesPerCategory < 1 || opts.RequestsPerSecond < 1 {
		return nil, fmt.Errorf("%w: AWS connector bounds must be positive", shared.ErrValidation)
	}
	return &Connector{vault: vault, opts: opts, limiter: rate.NewLimiter(rate.Limit(opts.RequestsPerSecond), opts.RequestsPerSecond)}, nil
}

// Evaluate delegates all SDK-neutral posture evaluation to the domain.
func (c *Connector) Evaluate(_ context.Context, inventory cloudposture.Inventory) ([]cloudposture.PostureFinding, error) {
	return cloudposture.Evaluate(inventory)
}

// Enumerate records every observed resource and never treats incomplete account coverage as clean.
func (c *Connector) Enumerate(ctx context.Context, scope ports.CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	_, scopeKey, err := cloudposture.NormalizeRoot(scope.Provider, scope.Root)
	inventory := cloudposture.Inventory{Provider: cloudposture.ProviderAWS, ScopeKey: scopeKey, Complete: true}
	if err != nil {
		return inventory, nil, err
	}
	scope.ScopeKey = scopeKey
	if scope.Provider != cloudposture.ProviderAWS || scope.EngagementID.IsZero() || strings.TrimSpace(scope.Root) == "" || strings.TrimSpace(scope.CredentialRef) == "" {
		return inventory, nil, fmt.Errorf("%w: invalid AWS cloud scope", shared.ErrValidation)
	}
	secret, err := c.vault.Resolve(ctx, scope.EngagementID, scope.CredentialRef)
	if err != nil {
		return inventory, nil, fmt.Errorf("resolve AWS credential reference: %w", err)
	}
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()
	credential, err := parseCredential(secret)
	if err != nil {
		return inventory, nil, err
	}
	base, err := c.loadConfig(ctx, credential)
	if err != nil {
		return inventory, nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	base = c.scopedConfig(base, scope)
	limiter := newLimiter(c.opts.RequestsPerSecond)
	defer limiter.close()

	org := organizations.NewFromConfig(base)
	if !strings.HasPrefix(scope.Root, "o-") || strings.ContainsAny(scope.Root, "/ \t\r\n") {
		return inventory, nil, fmt.Errorf("%w: AWS root must be an organization id", shared.ErrValidation)
	}
	organization, err := org.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return inventory, []cloudposture.CoverageIssue{*coverageGap(scope.Root, "accounts", err)}, nil
	}
	if organization.Organization == nil || awssdk.ToString(organization.Organization.Id) != scope.Root {
		return inventory, nil, fmt.Errorf("%w: AWS credential organization does not match approved root", shared.ErrForbidden)
	}
	accounts, accountGap := c.accounts(ctx, org, scope.Root)
	if accountGap != nil {
		inventory.Complete = false
		return inventory, []cloudposture.CoverageIssue{*accountGap}, nil
	}
	for _, account := range accounts {
		inventory.Resources = append(inventory.Resources, cloudposture.Resource{Provider: cloudposture.ProviderAWS, AccountID: account.id, ID: account.arn, Name: account.name, Kind: asset.KindCloudAccount, ResourceType: "aws:account"})
	}
	if len(accounts) >= c.opts.MaxAccounts {
		inventory.Complete = false
	}

	var gaps []cloudposture.CoverageIssue
	if len(accounts) >= c.opts.MaxAccounts {
		gaps = append(gaps, cloudposture.CoverageIssue{Provider: cloudposture.ProviderAWS, Scope: scope.Root, Category: "accounts", Code: "limit_reached", Detail: "account enumeration reached the configured limit"})
	}
	for _, account := range accounts {
		accountConfig, gap := c.accountConfig(ctx, base, credential, account, scope.Root)
		if gap != nil {
			inventory.Complete = false
			gaps = append(gaps, *gap)
			continue
		}
		c.enumerateAccount(ctx, accountConfig, account, limiter, &inventory, &gaps)
	}
	appendUnsupportedCoverage(&inventory, &gaps, scope.Root)
	if len(gaps) != 0 {
		inventory.Complete = false
	}
	inventory.Sort()
	return inventory, gaps, nil
}

type vaultCredential struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	RoleARNTemplate string `json:"role_arn_template"`
}

func parseCredential(secret []byte) (vaultCredential, error) {
	var credential vaultCredential
	if err := json.Unmarshal(secret, &credential); err != nil || credential.AccessKeyID == "" || credential.SecretAccessKey == "" || credential.RoleARNTemplate == "" {
		return vaultCredential{}, fmt.Errorf("%w: invalid AWS credential material", shared.ErrValidation)
	}
	if !strings.Contains(credential.RoleARNTemplate, "{account_id}") {
		return vaultCredential{}, fmt.Errorf("%w: AWS role ARN template must contain {account_id}", shared.ErrValidation)
	}
	return credential, nil
}

func (c *Connector) loadConfig(ctx context.Context, credential vaultCredential) (awssdk.Config, error) {
	options := []func(*config.LoadOptions) error{
		config.WithRegion(c.opts.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken)),
		config.WithRetryMaxAttempts(2),
	}
	if c.opts.Endpoint != "" {
		options = append(options, config.WithBaseEndpoint(c.opts.Endpoint))
	}
	if c.opts.HTTPClient != nil {
		options = append(options, config.WithHTTPClient(c.opts.HTTPClient))
	}
	return config.LoadDefaultConfig(ctx, options...)
}

type account struct {
	id   string
	arn  string
	name string
}

func (c *Connector) accounts(ctx context.Context, client *organizations.Client, root string) ([]account, *cloudposture.CoverageIssue) {
	pager := organizations.NewListAccountsPaginator(client, &organizations.ListAccountsInput{MaxResults: awssdk.Int32(int32(c.opts.MaxAccounts))})
	var accounts []account
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, coverageGap(root, "accounts", err)
		}
		for _, item := range page.Accounts {
			if item.Id == nil || item.Arn == nil {
				continue
			}
			accounts = append(accounts, account{id: awssdk.ToString(item.Id), arn: awssdk.ToString(item.Arn), name: awssdk.ToString(item.Name)})
			if len(accounts) == c.opts.MaxAccounts {
				return accounts, nil
			}
		}
	}
	return accounts, nil
}

func (c *Connector) accountConfig(ctx context.Context, base awssdk.Config, credential vaultCredential, account account, root string) (awssdk.Config, *cloudposture.CoverageIssue) {
	roleARN := strings.ReplaceAll(credential.RoleARNTemplate, "{account_id}", account.id)
	result, err := sts.NewFromConfig(base).AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: awssdk.String(roleARN), RoleSessionName: awssdk.String("synapse-cspm")})
	if err != nil || result.Credentials == nil {
		if err == nil {
			err = errors.New("AssumeRole returned no credentials")
		}
		return awssdk.Config{}, coverageGap(account.id, "account", err)
	}
	config := base.Copy()
	config.Credentials = credentials.NewStaticCredentialsProvider(awssdk.ToString(result.Credentials.AccessKeyId), awssdk.ToString(result.Credentials.SecretAccessKey), awssdk.ToString(result.Credentials.SessionToken))
	return config, nil
}

func (c *Connector) enumerateAccount(ctx context.Context, cfg awssdk.Config, account account, limiter *limiter, inventory *cloudposture.Inventory, gaps *[]cloudposture.CoverageIssue) {
	c.instances(ctx, ec2.NewFromConfig(cfg), account, limiter, inventory, gaps)
	c.buckets(ctx, s3.NewFromConfig(cfg, func(o *s3.Options) { o.UsePathStyle = true }), account, limiter, inventory, gaps)
	c.securityGroups(ctx, ec2.NewFromConfig(cfg), account, limiter, inventory, gaps)
	c.users(ctx, iam.NewFromConfig(cfg), account, limiter, inventory, gaps)
}

func (c *Connector) instances(ctx context.Context, client *ec2.Client, account account, limiter *limiter, inventory *cloudposture.Inventory, gaps *[]cloudposture.CoverageIssue) {
	pager := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{MaxResults: awssdk.Int32(int32(c.opts.MaxResourcesPerCategory))})
	count := 0
	for pager.HasMorePages() && count < c.opts.MaxResourcesPerCategory {
		if err := limiter.wait(ctx); err != nil {
			*gaps = append(*gaps, *coverageGap(account.id, "compute", err))
			return
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			*gaps = append(*gaps, *coverageGap(account.id, "compute", err))
			return
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				id := awssdk.ToString(instance.InstanceId)
				if id == "" {
					continue
				}
				public := cloudposture.StateDisabled
				if instance.PublicIpAddress != nil {
					public = cloudposture.StateEnabled
				}
				inventory.Resources = append(inventory.Resources, cloudposture.Resource{Provider: cloudposture.ProviderAWS, AccountID: account.id, ID: "arn:aws:ec2:" + c.opts.Region + ":" + account.id + ":instance/" + id, Name: id, Kind: asset.KindHost, ResourceType: "aws:ec2:instance", Region: c.opts.Region, Public: public, PublicNetwork: cloudposture.StateUnknown})
				count++
				if count == c.opts.MaxResourcesPerCategory {
					*gaps = append(*gaps, cloudposture.CoverageIssue{Provider: cloudposture.ProviderAWS, Scope: account.id, Category: "inventory", Code: "limit_reached", Detail: "resource enumeration reached the configured limit"})
					return
				}
			}
		}
	}
}

func (c *Connector) buckets(ctx context.Context, client *s3.Client, account account, limiter *limiter, inventory *cloudposture.Inventory, gaps *[]cloudposture.CoverageIssue) {
	var token *string
	count := 0
	for count < c.opts.MaxResourcesPerCategory {
		if err := limiter.wait(ctx); err != nil {
			*gaps = append(*gaps, *coverageGap(account.id, "storage", err))
			return
		}
		result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{ContinuationToken: token, MaxBuckets: awssdk.Int32(int32(c.opts.MaxResourcesPerCategory))})
		if err != nil {
			*gaps = append(*gaps, *coverageGap(account.id, "storage", err))
			return
		}
		for _, bucket := range result.Buckets {
			name := awssdk.ToString(bucket.Name)
			if name == "" {
				continue
			}
			resource := cloudposture.Resource{Provider: cloudposture.ProviderAWS, AccountID: account.id, ID: "arn:aws:s3:::" + name, Name: name, Kind: asset.KindStorage, ResourceType: "aws:s3:bucket", Public: cloudposture.StateUnknown, Encrypted: cloudposture.StateUnknown}
			if err := limiter.wait(ctx); err != nil {
				*gaps = append(*gaps, *coverageGap(account.id, "storage", err))
			} else {
				status, statusErr := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: awssdk.String(name)})
				if statusErr != nil {
					*gaps = append(*gaps, *coverageGap(account.id, "storage", statusErr))
				} else if status.PolicyStatus != nil && awssdk.ToBool(status.PolicyStatus.IsPublic) {
					resource.Public = cloudposture.StateEnabled
				}
			}
			if err := limiter.wait(ctx); err != nil {
				*gaps = append(*gaps, *coverageGap(account.id, "storage", err))
			} else {
				encryption, encryptionErr := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: awssdk.String(name)})
				if encryptionErr != nil {
					*gaps = append(*gaps, *coverageGap(account.id, "storage", encryptionErr))
				} else if encryption.ServerSideEncryptionConfiguration != nil {
					resource.Encrypted = cloudposture.StateEnabled
				}
			}
			inventory.Resources = append(inventory.Resources, resource)
			count++
			if count == c.opts.MaxResourcesPerCategory {
				*gaps = append(*gaps, cloudposture.CoverageIssue{Provider: cloudposture.ProviderAWS, Scope: account.id, Category: "inventory", Code: "limit_reached", Detail: "resource enumeration reached the configured limit"})
				return
			}
		}
		if result.ContinuationToken == nil || *result.ContinuationToken == "" {
			return
		}
		token = result.ContinuationToken
	}
}

func (c *Connector) securityGroups(ctx context.Context, client *ec2.Client, account account, limiter *limiter, inventory *cloudposture.Inventory, gaps *[]cloudposture.CoverageIssue) {
	pager := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{MaxResults: awssdk.Int32(int32(c.opts.MaxResourcesPerCategory))})
	count := 0
	for pager.HasMorePages() && count < c.opts.MaxResourcesPerCategory {
		if err := limiter.wait(ctx); err != nil {
			*gaps = append(*gaps, *coverageGap(account.id, "network", err))
			return
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			*gaps = append(*gaps, *coverageGap(account.id, "network", err))
			return
		}
		for _, group := range page.SecurityGroups {
			id := awssdk.ToString(group.GroupId)
			if id == "" {
				continue
			}
			public := cloudposture.StateDisabled
			for _, permission := range group.IpPermissions {
				if publicIngress(permission) {
					public = cloudposture.StateEnabled
					break
				}
			}
			inventory.Resources = append(inventory.Resources, cloudposture.Resource{Provider: cloudposture.ProviderAWS, AccountID: account.id, ID: "arn:aws:ec2:" + c.opts.Region + ":" + account.id + ":security-group/" + id, Name: awssdk.ToString(group.GroupName), Kind: asset.KindExposure, ResourceType: "aws:ec2:security-group", Region: c.opts.Region, Public: public, PublicNetwork: cloudposture.StateUnknown})
			count++
			if count == c.opts.MaxResourcesPerCategory {
				*gaps = append(*gaps, cloudposture.CoverageIssue{Provider: cloudposture.ProviderAWS, Scope: account.id, Category: "inventory", Code: "limit_reached", Detail: "resource enumeration reached the configured limit"})
				return
			}
		}
	}
}

func (c *Connector) users(ctx context.Context, client *iam.Client, account account, limiter *limiter, inventory *cloudposture.Inventory, gaps *[]cloudposture.CoverageIssue) {
	pager := iam.NewListUsersPaginator(client, &iam.ListUsersInput{MaxItems: awssdk.Int32(int32(c.opts.MaxResourcesPerCategory))})
	count := 0
	for pager.HasMorePages() && count < c.opts.MaxResourcesPerCategory {
		if err := limiter.wait(ctx); err != nil {
			*gaps = append(*gaps, *coverageGap(account.id, "identity", err))
			return
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			*gaps = append(*gaps, *coverageGap(account.id, "identity", err))
			return
		}
		for _, user := range page.Users {
			id := awssdk.ToString(user.Arn)
			if id == "" {
				continue
			}
			inventory.Resources = append(inventory.Resources, cloudposture.Resource{Provider: cloudposture.ProviderAWS, AccountID: account.id, ID: id, Name: awssdk.ToString(user.UserName), Kind: asset.KindIdentity, ResourceType: "aws:iam:user"})
			count++
			if count == c.opts.MaxResourcesPerCategory {
				*gaps = append(*gaps, cloudposture.CoverageIssue{Provider: cloudposture.ProviderAWS, Scope: account.id, Category: "inventory", Code: "limit_reached", Detail: "resource enumeration reached the configured limit"})
				return
			}
		}
	}
}

func publicIngress(permission ec2types.IpPermission) bool {
	for _, range_ := range permission.IpRanges {
		if awssdk.ToString(range_.CidrIp) == "0.0.0.0/0" {
			return true
		}
	}
	for _, range_ := range permission.Ipv6Ranges {
		if awssdk.ToString(range_.CidrIpv6) == "::/0" {
			return true
		}
	}
	return false
}

func appendUnsupportedCoverage(inventory *cloudposture.Inventory, gaps *[]cloudposture.CoverageIssue, scope string) {
	for _, category := range []string{"regions", "network-reachability", "identity-policy", "identity-last-use"} {
		*gaps = append(*gaps, cloudposture.CoverageIssue{Provider: cloudposture.ProviderAWS, Scope: scope, Category: category, Code: "unsupported", Detail: "connector does not yet establish this posture category"})
	}
	inventory.Complete = false
}

func coverageGap(scope, category string, err error) *cloudposture.CoverageIssue {
	code := "unreachable_account"
	var apiErr smithy.APIError
	var responseErr *smithyhttp.ResponseError
	if errors.As(err, &responseErr) && responseErr.HTTPStatusCode() == http.StatusForbidden {
		code = "permission_denied"
	} else if errors.As(err, &apiErr) {
		if apiErr.ErrorCode() == "AccessDenied" || apiErr.ErrorCode() == "AccessDeniedException" || apiErr.ErrorCode() == "UnauthorizedOperation" {
			code = "permission_denied"
		} else if apiErr.ErrorCode() == "RequestTimeout" || apiErr.ErrorCode() == "ServiceUnavailable" || apiErr.ErrorCode() == "UnknownError" {
			code = "unreachable_account"
		} else {
			code = "provider_error"
		}
	} else {
		var networkErr net.Error
		if !errors.As(err, &networkErr) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			code = "provider_error"
		}
	}
	return &cloudposture.CoverageIssue{Provider: cloudposture.ProviderAWS, Scope: scope, Category: category, Code: code, Detail: "cloud provider request failed"}
}

type limiter struct{ ticker *time.Ticker }

func newLimiter(rate int) *limiter {
	return &limiter{ticker: time.NewTicker(time.Second / time.Duration(rate))}
}
func (l *limiter) wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.ticker.C:
		return nil
	}
}
func (l *limiter) close() { l.ticker.Stop() }
