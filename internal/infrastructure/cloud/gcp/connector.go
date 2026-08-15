// Package gcp provides the read-only Google Cloud posture connector.
package gcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/auth/credentials"
	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	cloudresourcemanagerv3 "google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"
	htransport "google.golang.org/api/transport/http"
)

var errResourceLimit = errors.New("GCP resource enumeration limit reached")

const (
	defaultMaxProjects  = 100
	defaultMaxFolders   = 1_000
	defaultMaxResources = 10_000
	defaultMinInterval  = 100 * time.Millisecond
)

// Options bounds remote enumeration. HTTPClient and Endpoint are intended for
// emulator and httptest use; production uses the credential resolved from Vault.
type Options struct {
	Endpoint       string
	HTTPClient     *http.Client
	MaxProjects    int
	MaxFolders     int
	MaxResources   int
	MinRequestWait time.Duration
}

// Connector observes GCP resources using only list operations.
type Connector struct {
	vault ports.CredentialVault
	opts  Options

	mu   sync.Mutex
	next time.Time
}

var _ ports.CloudConnector = (*Connector)(nil)

// New creates a bounded GCP connector.
func New(vault ports.CredentialVault, opts Options) (*Connector, error) {
	if vault == nil {
		return nil, fmt.Errorf("gcp connector: credential vault is required")
	}
	if opts.MaxProjects < 0 || opts.MaxFolders < 0 || opts.MaxResources < 0 || opts.MinRequestWait < 0 {
		return nil, fmt.Errorf("gcp connector: invalid enumeration limits")
	}
	if opts.MaxProjects == 0 {
		opts.MaxProjects = defaultMaxProjects
	}
	if opts.MaxFolders == 0 {
		opts.MaxFolders = defaultMaxFolders
	}
	if opts.MaxResources == 0 {
		opts.MaxResources = defaultMaxResources
	}
	if opts.MinRequestWait == 0 {
		opts.MinRequestWait = defaultMinInterval
	}
	return &Connector{vault: vault, opts: opts}, nil
}

// Evaluate uses the SDK-neutral posture policy.
func (c *Connector) Evaluate(_ context.Context, inventory cloudposture.Inventory) ([]cloudposture.PostureFinding, error) {
	return cloudposture.Evaluate(inventory)
}

// Enumerate lists visible GCP projects and their compute, storage, network,
// and identity resources. Per-category failures are coverage gaps, never clean results.
func (c *Connector) Enumerate(ctx context.Context, scope ports.CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	if err := validateScope(scope); err != nil {
		return cloudposture.Inventory{}, nil, err
	}
	if scope.Authorize == nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("%w: GCP cloud operation authorizer is required", shared.ErrForbidden)
	}
	credential, err := c.vault.Resolve(ctx, scope.EngagementID, scope.CredentialRef)
	if err != nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("resolve GCP credential: %w", err)
	}
	defer clear(credential)

	_, scopeKey, keyErr := cloudposture.NormalizeRoot(scope.Provider, scope.Root)
	if keyErr != nil {
		return cloudposture.Inventory{}, nil, keyErr
	}
	scope.ScopeKey = scopeKey
	clients, err := c.newClients(ctx, credential, scope)
	if err != nil {
		return cloudposture.Inventory{}, nil, err
	}

	inv := cloudposture.Inventory{Provider: cloudposture.ProviderGCP, ScopeKey: scopeKey, Complete: true}
	projects, gaps, err := c.projects(ctx, clients, scope.Root)
	if err != nil {
		return cloudposture.Inventory{}, nil, err
	}
	if len(gaps) > 0 {
		inv.Complete = false
	}

	if len(projects) > c.opts.MaxProjects {
		projects = projects[:c.opts.MaxProjects]
		gaps = append(gaps, coverage(scope.Root, "projects", "limit_reached", "project enumeration limit reached"))
		inv.Complete = false
	}
	for _, project := range projects {
		if len(inv.Resources) >= c.opts.MaxResources {
			gaps = append(gaps, coverage(project, "resources", "limit_reached", "resource enumeration limit reached"))
			inv.Complete = false
			break
		}
		inv.Resources = append(inv.Resources, cloudposture.Resource{
			Provider: cloudposture.ProviderGCP, AccountID: project, ID: "projects/" + project,
			Name: project, Kind: asset.KindCloudAccount, ResourceType: "gcp_project",
			Public: cloudposture.StateUnknown, Encrypted: cloudposture.StateUnknown,
		})
		projectGaps := c.enumerateProject(ctx, clients, project, &inv)
		if len(projectGaps) > 0 {
			inv.Complete = false
			gaps = append(gaps, projectGaps...)
		}
		if len(inv.Resources) >= c.opts.MaxResources {
			gaps = append(gaps, coverage(project, "resources", "limit_reached", "resource enumeration limit reached"))
			inv.Complete = false
			break
		}
	}
	inv.Sort()
	sortCoverage(gaps)
	if err := inv.Validate(); err != nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("validate GCP inventory: %w", err)
	}
	return inv, gaps, nil
}

type clients struct {
	resources *cloudresourcemanager.Service
	hierarchy *cloudresourcemanagerv3.Service
	compute   *compute.Service
	storage   *storage.Service
	identity  *iam.Service
}

func (c *Connector) newClients(ctx context.Context, credential []byte, scope ports.CloudScope) (clients, error) {
	opts := []option.ClientOption{}
	if c.opts.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(c.opts.Endpoint))
	}
	if c.opts.HTTPClient != nil {
		client := *c.opts.HTTPClient
		client.Transport = limitedTransport{base: client.Transport, wait: c.wait, authorize: c.authorize(scope)}
		opts = append(opts, option.WithHTTPClient(&client))
	} else {
		authorize := c.authorize(scope)
		authClient := &http.Client{Transport: limitedTransport{base: http.DefaultTransport, wait: c.wait, authorize: authorize}}
		creds, err := credentials.NewCredentialsFromJSON(credentials.ServiceAccount, credential, &credentials.DetectOptions{
			Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
			Client: authClient,
		})
		if err != nil {
			return clients{}, fmt.Errorf("parse GCP service-account credential: %w", err)
		}
		transport, err := htransport.NewTransport(ctx, http.DefaultTransport, option.WithAuthCredentials(creds), option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
		if err != nil {
			return clients{}, fmt.Errorf("create GCP authenticated transport: %w", err)
		}
		opts = append(opts, option.WithHTTPClient(&http.Client{Transport: limitedTransport{base: transport, wait: c.wait, authorize: authorize}}))
	}
	clear(credential)
	resources, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return clients{}, fmt.Errorf("create GCP resource manager client: %w", err)
	}
	hierarchyClient, err := cloudresourcemanagerv3.NewService(ctx, opts...)
	if err != nil {
		return clients{}, fmt.Errorf("create GCP hierarchy client: %w", err)
	}
	computeClient, err := compute.NewService(ctx, opts...)
	if err != nil {
		return clients{}, fmt.Errorf("create GCP compute client: %w", err)
	}
	storageClient, err := storage.NewService(ctx, opts...)
	if err != nil {
		return clients{}, fmt.Errorf("create GCP storage client: %w", err)
	}
	identityClient, err := iam.NewService(ctx, opts...)
	if err != nil {
		return clients{}, fmt.Errorf("create GCP IAM client: %w", err)
	}
	return clients{resources: resources, hierarchy: hierarchyClient, compute: computeClient, storage: storageClient, identity: identityClient}, nil
}

var (
	gcpProjectRoot = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	gcpParentRoot  = regexp.MustCompile(`^(organizations|folders)/[0-9]+$`)
)

func validateScope(scope ports.CloudScope) error {
	root := strings.Trim(strings.TrimSpace(scope.Root), "/")
	if scope.Provider != cloudposture.ProviderGCP || scope.EngagementID.IsZero() || strings.TrimSpace(scope.CredentialRef) == "" || (!gcpProjectRoot.MatchString(root) && !gcpParentRoot.MatchString(root)) {
		return fmt.Errorf("%w: invalid GCP cloud scope", shared.ErrValidation)
	}
	return nil
}

func (c *Connector) projects(ctx context.Context, clients clients, root string) ([]string, []cloudposture.CoverageIssue, error) {
	root = strings.Trim(strings.TrimSpace(root), "/")
	if !strings.HasPrefix(root, "organizations/") && !strings.HasPrefix(root, "folders/") {
		return []string{strings.TrimPrefix(root, "projects/")}, nil, nil
	}
	parents, gaps, err := c.folderParents(ctx, clients.hierarchy, root)
	if err != nil {
		return nil, gaps, err
	}
	var projects []string
	for _, parent := range parents {
		for token := ""; ; {
			call := clients.resources.Projects.List().Context(ctx).PageSize(int64(c.opts.MaxProjects)).PageToken(token)
			parts := strings.SplitN(parent, "/", 2)
			call.Filter("parent.type:" + strings.TrimSuffix(parts[0], "s") + " parent.id:" + parts[1])
			page, pageErr := call.Do()
			if pageErr != nil {
				gaps = append(gaps, coverage(parent, "projects", errorCode(pageErr), "project enumeration unavailable"))
				break
			}
			for _, project := range page.Projects {
				if project.ProjectId == "" {
					continue
				}
				projects = append(projects, project.ProjectId)
				if len(projects) == c.opts.MaxProjects {
					if page.NextPageToken != "" || parent != parents[len(parents)-1] {
						gaps = append(gaps, coverage(root, "projects", "limit_reached", "project enumeration limit reached"))
					}
					return projects, gaps, nil
				}
			}
			if page.NextPageToken == "" {
				break
			}
			token = page.NextPageToken
		}
	}
	sort.Strings(projects)
	return projects, gaps, nil
}

// folderParents returns the bounded breadth-first hierarchy rooted at root.
// A coverage gap is emitted only when a configured bound excludes an unvisited page or folder.
func (c *Connector) folderParents(ctx context.Context, service *cloudresourcemanagerv3.Service, root string) ([]string, []cloudposture.CoverageIssue, error) {
	parents := []string{root}
	queue := []string{root}
	folders := 0
	for len(queue) != 0 {
		parent := queue[0]
		queue = queue[1:]
		for token := ""; ; {
			page, err := service.Folders.List().Parent(parent).Context(ctx).PageSize(int64(c.opts.MaxFolders)).PageToken(token).Do()
			if err != nil {
				return parents, []cloudposture.CoverageIssue{coverage(parent, "folders", errorCode(err), "folder enumeration unavailable")}, nil
			}
			for _, folder := range page.Folders {
				if folder.Name == "" || folder.State == "DELETE_REQUESTED" {
					continue
				}
				if folders == c.opts.MaxFolders {
					return parents, []cloudposture.CoverageIssue{coverage(root, "folders", "limit_reached", "folder enumeration limit reached")}, nil
				}
				folders++
				parents = append(parents, folder.Name)
				queue = append(queue, folder.Name)
			}
			if page.NextPageToken == "" {
				break
			}
			token = page.NextPageToken
		}
	}
	return parents, nil, nil
}

func (c *Connector) enumerateProject(ctx context.Context, clients clients, project string, inv *cloudposture.Inventory) []cloudposture.CoverageIssue {
	var gaps []cloudposture.CoverageIssue
	instances, err := c.instances(ctx, clients.compute, project, inv, &gaps)
	if err != nil {
		gaps = append(gaps, coverage(project, "compute", errorCode(err), "compute enumeration unavailable"))
	}
	if err := c.networkReachability(ctx, clients.compute, project, instances, inv, &gaps); err != nil {
		gaps = append(gaps, coverage(project, "network", errorCode(err), "network reachability enumeration unavailable"))
	}
	if err := c.networks(ctx, clients.compute, project, inv); err != nil {
		gaps = append(gaps, coverage(project, "network", errorCode(err), "network enumeration unavailable"))
	}
	if err := c.buckets(ctx, clients.storage, project, inv, &gaps); err != nil {
		gaps = append(gaps, coverage(project, "storage", errorCode(err), "storage enumeration unavailable"))
	}
	if err := c.serviceAccounts(ctx, clients.identity, project, inv); err != nil {
		gaps = append(gaps, coverage(project, "identity", errorCode(err), "identity enumeration unavailable"))
	}
	if err := c.projectPolicy(ctx, clients.resources, project, inv); err != nil {
		gaps = append(gaps, coverage(project, "identity", errorCode(err), "IAM policy enumeration unavailable"))
	}
	return gaps
}

func (c *Connector) instances(ctx context.Context, service *compute.Service, project string, inv *cloudposture.Inventory, gaps *[]cloudposture.CoverageIssue) ([]*compute.Instance, error) {
	var instances []*compute.Instance
	for token := ""; ; {
		page, err := service.Instances.AggregatedList(project).Context(ctx).MaxResults(int64(c.opts.MaxResources)).PageToken(token).ReturnPartialSuccess(true).Do()
		if err != nil {
			return instances, err
		}
		for _, unreachable := range page.Unreachables {
			*gaps = append(*gaps, coverage(project, "compute", "unreachable", unreachable))
		}
		for _, scoped := range page.Items {
			for _, instance := range scoped.Instances {
				instances = append(instances, instance)
				if !c.add(inv, instanceResource(project, instance)) {
					return instances, nil
				}
			}
		}
		if page.NextPageToken == "" || len(inv.Resources) >= c.opts.MaxResources {
			return instances, nil
		}
		token = page.NextPageToken
	}
}

func (c *Connector) networkReachability(ctx context.Context, service *compute.Service, project string, instances []*compute.Instance, inv *cloudposture.Inventory, gaps *[]cloudposture.CoverageIssue) error {
	routes, err := c.routes(ctx, service, project)
	if err != nil {
		return err
	}
	firewalls, err := c.firewalls(ctx, service, project)
	if err != nil {
		return err
	}
	for _, instance := range instances {
		if !hasExternalAddress(instance) {
			continue
		}
		reachable, known := externallyReachable(instance, routes, firewalls)
		for index := range inv.Resources {
			if inv.Resources[index].ID != instanceID(project, instance) {
				continue
			}
			if known {
				inv.Resources[index].PublicNetwork = cloudposture.StateDisabled
				if reachable {
					inv.Resources[index].PublicNetwork = cloudposture.StateEnabled
				}
			} else {
				*gaps = append(*gaps, coverage(instanceID(project, instance), "network", "reachability_unknown", "effective ingress route or firewall rule cannot be resolved safely"))
			}
			break
		}
	}
	return nil
}

func (c *Connector) routes(ctx context.Context, service *compute.Service, project string) ([]*compute.Route, error) {
	var routes []*compute.Route
	for token := ""; ; {
		page, err := service.Routes.List(project).Context(ctx).MaxResults(int64(c.opts.MaxResources - len(routes))).PageToken(token).Do()
		if err != nil {
			return nil, err
		}
		remaining := c.opts.MaxResources - len(routes)
		if len(page.Items) > remaining {
			page.Items = page.Items[:remaining]
		}
		routes = append(routes, page.Items...)
		if len(routes) == c.opts.MaxResources && page.NextPageToken != "" {
			return routes, errResourceLimit
		}
		if page.NextPageToken == "" {
			return routes, nil
		}
		token = page.NextPageToken
	}
}

func (c *Connector) firewalls(ctx context.Context, service *compute.Service, project string) ([]*compute.Firewall, error) {
	var firewalls []*compute.Firewall
	for token := ""; ; {
		page, err := service.Firewalls.List(project).Context(ctx).MaxResults(int64(c.opts.MaxResources - len(firewalls))).PageToken(token).Do()
		if err != nil {
			return nil, err
		}
		remaining := c.opts.MaxResources - len(firewalls)
		if len(page.Items) > remaining {
			page.Items = page.Items[:remaining]
		}
		firewalls = append(firewalls, page.Items...)
		if len(firewalls) == c.opts.MaxResources && page.NextPageToken != "" {
			return firewalls, errResourceLimit
		}
		if page.NextPageToken == "" {
			return firewalls, nil
		}
		token = page.NextPageToken
	}
}

func hasExternalAddress(instance *compute.Instance) bool {
	for _, nic := range instance.NetworkInterfaces {
		if nic != nil && (len(nic.AccessConfigs) != 0 || len(nic.Ipv6AccessConfigs) != 0 || nic.Ipv6AccessType == "EXTERNAL") {
			return true
		}
	}
	return false
}

func externallyReachable(instance *compute.Instance, routes []*compute.Route, firewalls []*compute.Firewall) (bool, bool) {
	for _, nic := range instance.NetworkInterfaces {
		if nic == nil || nic.Network == "" || !hasInternetRoute(nic.Network, routes) {
			continue
		}
		matched, reachable := firewallReachability(instance, nic.Network, firewalls)
		if matched {
			return reachable, true
		}
	}
	return false, false
}

func hasInternetRoute(network string, routes []*compute.Route) bool {
	for _, route := range routes {
		if route == nil || resourceURLID(route.Network) != resourceURLID(network) || !isDefaultRoute(route.DestRange) {
			continue
		}
		if strings.Contains(route.NextHopGateway, "default-internet-gateway") {
			return true
		}
	}
	return false
}

func isDefaultRoute(destination string) bool {
	prefix, err := netip.ParsePrefix(destination)
	return err == nil && prefix.Bits() == 0
}

func firewallReachability(instance *compute.Instance, network string, firewalls []*compute.Firewall) (bool, bool) {
	var effective *compute.Firewall
	for _, firewall := range firewalls {
		if firewall == nil || firewall.Disabled || strings.EqualFold(firewall.Direction, "EGRESS") || resourceURLID(firewall.Network) != resourceURLID(network) || !appliesTo(instance, firewall) || !allowsInternet(firewall) {
			continue
		}
		if effective == nil || firewall.Priority < effective.Priority || (firewall.Priority == effective.Priority && len(firewall.Denied) != 0) {
			effective = firewall
		}
	}
	if effective == nil {
		return false, false
	}
	return len(effective.Allowed) != 0, true
}

func appliesTo(instance *compute.Instance, firewall *compute.Firewall) bool {
	if len(firewall.TargetTags) == 0 && len(firewall.TargetServiceAccounts) == 0 {
		return true
	}
	for _, tag := range firewall.TargetTags {
		if instance.Tags != nil {
			for _, actual := range instance.Tags.Items {
				if tag == actual {
					return true
				}
			}
		}
	}
	for _, target := range firewall.TargetServiceAccounts {
		for _, account := range instance.ServiceAccounts {
			if account != nil && target == account.Email {
				return true
			}
		}
	}
	return false
}

func allowsInternet(firewall *compute.Firewall) bool {
	for _, source := range firewall.SourceRanges {
		prefix, err := netip.ParsePrefix(source)
		if err == nil && prefix.Bits() == 0 {
			return true
		}
	}
	return false
}

func (c *Connector) networks(ctx context.Context, service *compute.Service, project string, inv *cloudposture.Inventory) error {
	for token := ""; ; {
		page, err := service.Networks.List(project).Context(ctx).MaxResults(int64(c.opts.MaxResources)).PageToken(token).Do()
		if err != nil {
			return err
		}
		for _, network := range page.Items {
			if !c.add(inv, cloudposture.Resource{Provider: cloudposture.ProviderGCP, AccountID: project, ID: networkID(project, network), Name: network.Name, Kind: asset.KindExposure, ResourceType: "gcp_network", Public: cloudposture.StateUnknown, Encrypted: cloudposture.StateUnknown}) {
				return nil
			}
		}
		if page.NextPageToken == "" || len(inv.Resources) >= c.opts.MaxResources {
			return nil
		}
		token = page.NextPageToken
	}
}

func (c *Connector) buckets(ctx context.Context, service *storage.Service, project string, inv *cloudposture.Inventory, gaps *[]cloudposture.CoverageIssue) error {
	for token := ""; ; {
		page, err := service.Buckets.List(project).Context(ctx).MaxResults(int64(c.opts.MaxResources)).PageToken(token).Do()
		if err != nil {
			return err
		}
		for _, unreachable := range page.Unreachable {
			*gaps = append(*gaps, coverage(project, "storage", "unreachable", unreachable))
		}
		for _, bucket := range page.Items {
			public, policyKnown := bucketACLPosture(bucket)
			if bucket.IamConfiguration != nil && bucket.IamConfiguration.PublicAccessPrevention == "enforced" {
				public, policyKnown = cloudposture.StateDisabled, true
			} else {
				policy, policyErr := service.Buckets.GetIamPolicy(bucket.Name).Context(ctx).OptionsRequestedPolicyVersion(3).Do()
				if policyErr != nil {
					// A public ACL entity already establishes the posture definitively; only
					// downgrade to unknown (and drop policyKnown) when the ACL was inconclusive.
					if public != cloudposture.StateEnabled {
						public = cloudposture.StateUnknown
						policyKnown = false
					}
					*gaps = append(*gaps, coverage(bucket.Name, "storage", errorCode(policyErr), "bucket IAM policy unavailable"))
				} else if policyHasPublicMember(policy) {
					public, policyKnown = cloudposture.StateEnabled, true
				} else if policyHasConditionalBinding(policy) {
					// A public ACL entity already establishes the posture definitively; a
					// conditional binding only leaves it unknown when the ACL was inconclusive.
					if public != cloudposture.StateEnabled {
						public = cloudposture.StateUnknown
						policyKnown = false
					}
					*gaps = append(*gaps, coverage(bucket.Name, "storage", "conditional_policy", "conditional bucket policy cannot be resolved safely"))
				} else {
					policyKnown = true
					if public == cloudposture.StateUnknown {
						public = cloudposture.StateDisabled
					}
				}
			}
			if !c.add(inv, cloudposture.Resource{Provider: cloudposture.ProviderGCP, AccountID: project, ID: "projects/" + project + "/buckets/" + bucket.Name, Name: bucket.Name, Kind: asset.KindStorage, ResourceType: "gcp_bucket", Public: public, Encrypted: cloudposture.StateEnabled, PolicyKnown: policyKnown}) {
				return nil
			}
		}
		if page.NextPageToken == "" || len(inv.Resources) >= c.opts.MaxResources {
			return nil
		}
		token = page.NextPageToken
	}
}

func bucketACLPosture(bucket *storage.Bucket) (cloudposture.State, bool) {
	for _, acl := range bucket.Acl {
		if acl != nil && publicACLEntity(acl.Entity) {
			return cloudposture.StateEnabled, true
		}
	}
	for _, acl := range bucket.DefaultObjectAcl {
		if acl != nil && publicACLEntity(acl.Entity) {
			return cloudposture.StateEnabled, true
		}
	}
	return cloudposture.StateUnknown, false
}

func publicACLEntity(entity string) bool {
	return entity == "allUsers" || entity == "allAuthenticatedUsers"
}

func policyHasPublicMember(policy *storage.Policy) bool {
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if publicACLEntity(member) {
				return true
			}
		}
	}
	return false
}

func policyHasConditionalBinding(policy *storage.Policy) bool {
	for _, binding := range policy.Bindings {
		if binding.Condition != nil && len(binding.Members) != 0 {
			return true
		}
	}
	return false
}

func (c *Connector) serviceAccounts(ctx context.Context, service *iam.Service, project string, inv *cloudposture.Inventory) error {
	for token := ""; ; {
		page, err := service.Projects.ServiceAccounts.List("projects/" + project).Context(ctx).PageSize(100).PageToken(token).Do()
		if err != nil {
			return err
		}
		for _, account := range page.Accounts {
			if !c.add(inv, cloudposture.Resource{Provider: cloudposture.ProviderGCP, AccountID: project, ID: account.Name, Name: account.Email, Kind: asset.KindIdentity, ResourceType: "gcp_service_account", Public: cloudposture.StateUnknown, Encrypted: cloudposture.StateUnknown}) {
				return nil
			}
		}
		if page.NextPageToken == "" || len(inv.Resources) >= c.opts.MaxResources {
			return nil
		}
		token = page.NextPageToken
	}
}

func (c *Connector) add(inv *cloudposture.Inventory, resource cloudposture.Resource) bool {
	if len(inv.Resources) >= c.opts.MaxResources {
		return false
	}
	inv.Resources = append(inv.Resources, resource)
	return true
}

func (c *Connector) projectPolicy(ctx context.Context, service *cloudresourcemanager.Service, project string, inv *cloudposture.Inventory) error {
	policy, err := service.Projects.GetIamPolicy(project, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return err
	}
	for _, binding := range policy.Bindings {
		highPrivilege := binding.Role == "roles/owner" || binding.Role == "roles/editor" || strings.Contains(strings.ToLower(binding.Role), "admin")
		conditionSuffix := ""
		policyKnown := binding.Condition == nil
		if binding.Condition != nil {
			sum := sha256.Sum256([]byte(binding.Condition.Expression + "|" + binding.Condition.Title + "|" + binding.Condition.Description))
			conditionSuffix = "/condition-" + hex.EncodeToString(sum[:8])
		}
		for _, member := range binding.Members {
			wildcard := member == "allUsers" || member == "allAuthenticatedUsers"
			if !c.add(inv, cloudposture.Resource{Provider: cloudposture.ProviderGCP, AccountID: project, ID: "projects/" + project + "/iam/" + binding.Role + "/" + member + conditionSuffix, Name: member, Kind: asset.KindIdentity, ResourceType: "gcp_iam_binding", HighPrivilege: highPrivilege, WildcardTarget: wildcard, PolicyKnown: policyKnown}) {
				return nil
			}
		}
	}
	return nil
}

func instanceResource(project string, instance *compute.Instance) cloudposture.Resource {
	publicAddress := cloudposture.StateDisabled
	if hasExternalAddress(instance) {
		publicAddress = cloudposture.StateEnabled
	}
	// An external address alone does not establish an effective firewall and route path.
	return cloudposture.Resource{Provider: cloudposture.ProviderGCP, AccountID: project, ID: instanceID(project, instance), Name: instance.Name, Kind: asset.KindWorkload, ResourceType: "gcp_compute_instance", Region: lastPathSegment(instance.Zone), Public: publicAddress, Encrypted: cloudposture.StateUnknown, PublicNetwork: cloudposture.StateUnknown}
}

func instanceID(project string, instance *compute.Instance) string {
	if instance.SelfLink != "" {
		return resourceURLID(instance.SelfLink)
	}
	return "projects/" + project + "/zones/" + lastPathSegment(instance.Zone) + "/instances/" + instance.Name
}

func networkID(project string, network *compute.Network) string {
	if network.SelfLink != "" {
		return resourceURLID(network.SelfLink)
	}
	return "projects/" + project + "/global/networks/" + network.Name
}

func resourceURLID(value string) string {
	if i := strings.Index(value, "/projects/"); i >= 0 {
		return value[i+1:]
	}
	return strings.TrimPrefix(value, "/")
}

func lastPathSegment(value string) string {
	return strings.Trim(strings.TrimSpace(value), "/")[strings.LastIndex(strings.Trim(strings.TrimSpace(value), "/"), "/")+1:]
}

func coverage(scope, category, code, detail string) cloudposture.CoverageIssue {
	return cloudposture.CoverageIssue{Provider: cloudposture.ProviderGCP, Scope: scope, Category: category, Code: code, Detail: detail}
}

func errorCode(err error) string {
	if errors.Is(err, errResourceLimit) {
		return "limit_reached"
	}
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		if apiErr.Code == http.StatusForbidden || apiErr.Code == http.StatusUnauthorized {
			return "permission_denied"
		}
		if apiErr.Code == http.StatusNotFound || apiErr.Code == http.StatusRequestTimeout || apiErr.Code == http.StatusTooManyRequests || apiErr.Code >= 500 {
			return "unreachable"
		}
	}
	return "enumeration_failed"
}

func sortCoverage(gaps []cloudposture.CoverageIssue) {
	sort.Slice(gaps, func(i, j int) bool {
		a, b := gaps[i], gaps[j]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Detail < b.Detail
	})
}

func (c *Connector) wait(ctx context.Context) error {
	c.mu.Lock()
	wait := time.Until(c.next)
	if wait < 0 {
		wait = 0
	}
	c.next = time.Now().Add(wait + c.opts.MinRequestWait)
	c.mu.Unlock()
	if wait == 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Connector) authorize(scope ports.CloudScope) func(context.Context, string, string) error {
	return func(ctx context.Context, category, name string) error {
		return ports.AuthorizeCloudOperation(ctx, scope, category, name)
	}
}

type limitedTransport struct {
	base      http.RoundTripper
	wait      func(context.Context) error
	authorize func(context.Context, string, string) error
}

func (t limitedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := t.wait(request.Context()); err != nil {
		return nil, err
	}
	if t.authorize != nil {
		category := "identity"
		switch {
		case strings.Contains(request.URL.Path, "instances"), strings.Contains(request.URL.Path, "firewalls"), strings.Contains(request.URL.Path, "routes"), strings.Contains(request.URL.Path, "networks"):
			category = "network"
		case strings.Contains(request.URL.Path, "buckets") || strings.Contains(request.URL.Path, "/b/"):
			category = "storage"
		case strings.Contains(request.URL.Path, "folders") || strings.Contains(request.URL.Path, "projects"):
			category = "projects"
		}
		target := request.URL.Path
		if request.URL.Host != "" {
			target = request.URL.Host + target
		}
		if err := t.authorize(request.Context(), category, request.Method+" "+target); err != nil {
			return nil, err
		}
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(request)
}
