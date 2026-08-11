// Package azure implements the read-only Azure Resource Graph cloud-posture connector.
package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultPageSize       int32 = 1000
	defaultMaxPages             = 1000
	defaultMaxResources         = 100000
	defaultMinRequestWait       = 200 * time.Millisecond
)

const resourcesQuery = `union Resources, ResourceContainers
| where type in~ ('microsoft.storage/storageaccounts', 'microsoft.storage/storageaccounts/blobservices/containers', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachinescalesets', 'microsoft.containerservice/managedclusters', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults', 'microsoft.sql/servers', 'microsoft.documentdb/databaseaccounts', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.network/routetables', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.authorization/roleassignments', 'microsoft.authorization/roledefinitions')
| project id, name, type, location, subscriptionId, properties`

type resourceGraphClient interface {
	Resources(context.Context, armresourcegraph.QueryRequest, *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error)
}

// Config bounds Resource Graph pagination. Zero values use conservative defaults.
type Config struct {
	PageSize       int32
	MaxPages       int
	MaxResources   int
	MinRequestWait time.Duration
}

// Connector observes Azure resources without mutation.
type Connector struct {
	vault          ports.CredentialVault
	client         resourceGraphClient
	newClient      func([]byte, ports.CloudScope) (resourceGraphClient, error)
	pageSize       int32
	maxPages       int
	maxResources   int
	minRequestWait time.Duration
	mu             sync.Mutex
	next           time.Time
}

var _ ports.CloudConnector = (*Connector)(nil)

// New creates an Azure connector. Credential material is resolved only while a scope runs.
func New(vault ports.CredentialVault, cfg Config) (*Connector, error) {
	if vault == nil {
		return nil, fmt.Errorf("%w: Azure connector requires a credential vault", shared.ErrValidation)
	}
	return newConnector(vault, nil, newResourceGraphClient, cfg)
}

func newConnector(vault ports.CredentialVault, client resourceGraphClient, newClient func([]byte, ports.CloudScope) (resourceGraphClient, error), cfg Config) (*Connector, error) {
	if client == nil && (vault == nil || newClient == nil) {
		return nil, fmt.Errorf("%w: Azure connector requires a credential vault", shared.ErrValidation)
	}
	if cfg.PageSize < 0 {
		return nil, fmt.Errorf("%w: Azure page size must not be negative", shared.ErrValidation)
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = defaultPageSize
	}
	if cfg.PageSize > defaultPageSize {
		return nil, fmt.Errorf("%w: Azure page size exceeds %d", shared.ErrValidation, defaultPageSize)
	}
	if cfg.MaxPages < 0 {
		return nil, fmt.Errorf("%w: Azure page limit must not be negative", shared.ErrValidation)
	}
	if cfg.MaxPages == 0 {
		cfg.MaxPages = defaultMaxPages
	}
	if cfg.MinRequestWait < 0 {
		return nil, fmt.Errorf("%w: Azure request interval must not be negative", shared.ErrValidation)
	}
	if cfg.MinRequestWait == 0 {
		cfg.MinRequestWait = defaultMinRequestWait
	}
	if cfg.MaxResources < 0 {
		return nil, fmt.Errorf("%w: Azure resource limit must not be negative", shared.ErrValidation)
	}
	if cfg.MaxResources == 0 {
		cfg.MaxResources = defaultMaxResources
	}
	return &Connector{vault: vault, client: client, newClient: newClient, pageSize: cfg.PageSize, maxPages: cfg.MaxPages, maxResources: cfg.MaxResources, minRequestWait: cfg.MinRequestWait}, nil
}

// Enumerate retrieves a subscription's Resource Graph inventory. Remote query failures and bounds are
// explicit coverage gaps, never a clean inventory.
func (c *Connector) Enumerate(ctx context.Context, scope ports.CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	if err := validateScope(scope); err != nil {
		return cloudposture.Inventory{}, nil, err
	}
	root, managementGroup, err := azureScope(scope.Root)
	if err != nil {
		return cloudposture.Inventory{}, nil, err
	}
	_, scopeKey, err := cloudposture.NormalizeRoot(scope.Provider, scope.Root)
	if err != nil {
		return cloudposture.Inventory{}, nil, err
	}
	scope.ScopeKey = scopeKey
	inventory := cloudposture.Inventory{Provider: cloudposture.ProviderAzure, ScopeKey: scopeKey, Complete: true}
	if !managementGroup {
		inventory.Resources = append(inventory.Resources, accountResource(root, scopeKey))
	}
	client := c.client
	if client == nil {
		secret, err := c.vault.Resolve(ctx, scope.EngagementID, scope.CredentialRef)
		if err != nil {
			return cloudposture.Inventory{}, nil, fmt.Errorf("resolve Azure credential reference: %w", err)
		}
		defer clear(secret)
		client, err = c.newClient(secret, scope)
		if err != nil {
			return cloudposture.Inventory{}, nil, err
		}
	}
	var gaps []cloudposture.CoverageIssue
	var all []graphResource
	var skipToken string
	for page := 0; page < c.maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return inventory, gaps, err
		}
		if err := c.wait(ctx); err != nil {
			return inventory, gaps, err
		}
		if err := ports.AuthorizeCloudOperation(ctx, scope, "resource-graph", "resources"); err != nil {
			return inventory, gaps, err
		}
		response, err := client.Resources(ctx, resourcesRequest(root, managementGroup, c.pageSize, skipToken), nil)
		if err != nil {
			return incomplete(inventory, gaps, root, queryFailureCode(err))
		}
		resources, err := decodeResources(response.Data)
		if err != nil {
			return incomplete(inventory, gaps, root, "resource_graph_response_invalid")
		}
		if len(all)+len(resources) > c.maxResources {
			return incomplete(inventory, gaps, root, "resource_graph_resource_limit")
		}
		all = append(all, resources...)
		if response.SkipToken == nil || strings.TrimSpace(*response.SkipToken) == "" {
			if response.ResultTruncated != nil && *response.ResultTruncated == armresourcegraph.ResultTruncatedTrue {
				return incomplete(inventory, gaps, root, "resource_graph_result_truncated")
			}
			break
		}
		next := strings.TrimSpace(*response.SkipToken)
		if next == skipToken {
			return incomplete(inventory, gaps, root, "resource_graph_non_advancing_cursor")
		}
		skipToken = next
		if page == c.maxPages-1 {
			return incomplete(inventory, gaps, root, "resource_graph_page_limit")
		}
	}
	for _, resource := range all {
		if normalized, ok := normalizeResource(resource); ok {
			normalized.ScopeKey = scopeKey
			inventory.Resources = append(inventory.Resources, normalized)
		}
	}
	if managementGroup {
		addDiscoveredSubscriptions(&inventory, all, scopeKey)
		gaps = append(gaps, coverage(root, "subscription-discovery", "partial_scope_possible", "Azure Resource Graph may omit inaccessible management-group subscriptions"))
	}
	applyNetworkFacts(&inventory, all)
	applyRoleFacts(&inventory, all)
	appendKnownLimitations(&inventory, &gaps, root)
	inventory.Complete = false
	inventory.Sort()
	sortCoverage(gaps)
	return inventory, gaps, nil
}

func accountResource(subscription, scopeKey string) cloudposture.Resource {
	return cloudposture.Resource{Provider: cloudposture.ProviderAzure, ScopeKey: scopeKey, AccountID: subscription, ID: "/subscriptions/" + subscription, Name: subscription, Kind: asset.KindCloudAccount, ResourceType: "azure:subscription", Public: cloudposture.StateUnknown, Encrypted: cloudposture.StateUnknown}
}

func addDiscoveredSubscriptions(inventory *cloudposture.Inventory, resources []graphResource, scopeKey string) {
	seen := map[string]struct{}{}
	for _, resource := range resources {
		subscription := strings.TrimSpace(resource.SubscriptionID)
		key := normalizedID(subscription)
		if subscription == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		inventory.Resources = append(inventory.Resources, accountResource(subscription, scopeKey))
	}
}

func incomplete(inventory cloudposture.Inventory, gaps []cloudposture.CoverageIssue, scope, code string) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	inventory.Complete = false
	inventory.Sort()
	return inventory, append(gaps, coverage(scope, "inventory", code, "")), nil
}

func coverage(scope, category, code, detail string) cloudposture.CoverageIssue {
	return cloudposture.CoverageIssue{Provider: cloudposture.ProviderAzure, Scope: scope, Category: category, Code: code, Detail: detail}
}

func queryFailureCode(err error) string {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "forbidden") || strings.Contains(message, "unauthorized") || strings.Contains(message, "authorizationfailed") || strings.Contains(message, "status code 401") || strings.Contains(message, "status code 403") {
		return "resource_graph_query_denied"
	}
	return "resource_graph_query_failed"
}

func appendKnownLimitations(inventory *cloudposture.Inventory, gaps *[]cloudposture.CoverageIssue, scope string) {
	for _, category := range []string{"network-effective-security", "identity-last-use"} {
		*gaps = append(*gaps, coverage(scope, category, "unsupported", "connector does not call Azure Network Watcher or identity activity APIs"))
	}
	inventory.Complete = false
}

func (c *Connector) Evaluate(ctx context.Context, inventory cloudposture.Inventory) ([]cloudposture.PostureFinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return cloudposture.Evaluate(inventory)
}

func (c *Connector) wait(ctx context.Context) error {
	if c.minRequestWait == 0 {
		return nil
	}
	c.mu.Lock()
	wait := time.Until(c.next)
	if wait < 0 {
		wait = 0
	}
	c.next = time.Now().Add(wait + c.minRequestWait)
	c.mu.Unlock()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func resourcesRequest(root string, managementGroup bool, pageSize int32, skipToken string) armresourcegraph.QueryRequest {
	format := armresourcegraph.ResultFormatObjectArray
	options := &armresourcegraph.QueryRequestOptions{Top: &pageSize, ResultFormat: &format}
	if managementGroup {
		partial := true
		options.AllowPartialScopes = &partial
	}
	if skipToken != "" {
		options.SkipToken = &skipToken
	}
	request := armresourcegraph.QueryRequest{Query: ptr(resourcesQuery), Options: options}
	if managementGroup {
		request.ManagementGroups = []*string{ptr(root)}
	} else {
		request.Subscriptions = []*string{ptr(root)}
	}
	return request
}

type graphResource struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Type           string          `json:"type"`
	Location       string          `json:"location"`
	SubscriptionID string          `json:"subscriptionId"`
	Properties     json.RawMessage `json:"properties"`
}

func decodeResources(data any) ([]graphResource, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var resources []graphResource
	if err := json.Unmarshal(raw, &resources); err != nil {
		return nil, err
	}
	return resources, nil
}

func normalizeResource(resource graphResource) (cloudposture.Resource, bool) {
	id := strings.TrimSpace(resource.ID)
	resourceType := strings.ToLower(strings.TrimSpace(resource.Type))
	if id == "" || resourceType == "" {
		return cloudposture.Resource{}, false
	}
	kind, sensitive, ok := azureKind(resourceType)
	if !ok {
		return cloudposture.Resource{}, false
	}
	out := cloudposture.Resource{Provider: cloudposture.ProviderAzure, AccountID: strings.TrimSpace(resource.SubscriptionID), ID: id, Name: strings.TrimSpace(resource.Name), Kind: kind, ResourceType: resourceType, Region: strings.TrimSpace(resource.Location), Public: cloudposture.StateUnknown, Encrypted: cloudposture.StateUnknown, Sensitive: sensitive, PublicNetwork: cloudposture.StateUnknown}
	properties := resourceProperties(resource)
	if resourceType == "microsoft.storage/storageaccounts" {
		out.Encrypted = storageEncryption(properties)
	}
	if resourceType == "microsoft.storage/storageaccounts/blobservices/containers" {
		out.Public = containerPublicAccess(properties)
	}
	return out, true
}

func azureKind(resourceType string) (asset.Kind, bool, bool) {
	switch resourceType {
	case "microsoft.storage/storageaccounts", "microsoft.storage/storageaccounts/blobservices/containers":
		return asset.KindStorage, false, true
	case "microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets":
		return asset.KindHost, false, true
	case "microsoft.containerservice/managedclusters":
		return asset.KindWorkload, false, true
	case "microsoft.managedidentity/userassignedidentities", "microsoft.authorization/roleassignments", "microsoft.authorization/roledefinitions":
		return asset.KindIdentity, false, true
	case "microsoft.keyvault/vaults", "microsoft.sql/servers", "microsoft.documentdb/databaseaccounts":
		return asset.KindStorage, true, true
	case "microsoft.network/networkinterfaces", "microsoft.network/publicipaddresses", "microsoft.network/routetables", "microsoft.network/networksecuritygroups", "microsoft.network/virtualnetworks":
		return asset.KindExposure, false, true
	}
	return "", false, false
}

func containerPublicAccess(properties map[string]any) cloudposture.State {
	switch strings.ToLower(strings.TrimSpace(stringValue(properties["publicAccess"]))) {
	case "blob", "container":
		return cloudposture.StateEnabled
	case "none", "off", "disabled":
		return cloudposture.StateDisabled
	}
	return cloudposture.StateUnknown
}

func storageEncryption(properties map[string]any) cloudposture.State {
	enabled, ok := nestedBool(properties, "encryption", "services", "blob", "enabled")
	if !ok {
		return cloudposture.StateUnknown
	}
	if enabled {
		return cloudposture.StateEnabled
	}
	return cloudposture.StateDisabled
}

func nestedBool(value map[string]any, keys ...string) (bool, bool) {
	var current any = value
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			return false, false
		}
		current = object[key]
	}
	result, ok := current.(bool)
	return result, ok
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func resourceProperties(resource graphResource) map[string]any {
	properties := map[string]any{}
	_ = json.Unmarshal(resource.Properties, &properties)
	return properties
}

func objects(value any) []map[string]any {
	items, _ := value.([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if object, ok := item.(map[string]any); ok {
			out = append(out, object)
		}
	}
	return out
}

func objectID(value any) string {
	if object, ok := value.(map[string]any); ok {
		return strings.TrimSpace(stringValue(object["id"]))
	}
	return ""
}

func normalizedID(id string) string { return strings.ToLower(strings.TrimSpace(id)) }

type nicFact struct {
	vmID, nsgID, subnetID string
	publicIPs             []string
}
type subnetFact struct{ nsgID, routeTableID string }
type routeFact struct{ virtualApplianceDefaultRoute bool }

func applyNetworkFacts(inventory *cloudposture.Inventory, resources []graphResource) {
	nics := map[string]nicFact{}
	publicIPs := map[string]bool{}
	nsgs := map[string][]map[string]any{}
	subnets := map[string]subnetFact{}
	routes := map[string]routeFact{}
	for _, resource := range resources {
		properties := resourceProperties(resource)
		switch strings.ToLower(resource.Type) {
		case "microsoft.network/networkinterfaces":
			fact := nicFact{vmID: objectID(properties["virtualMachine"]), nsgID: objectID(properties["networkSecurityGroup"])}
			for _, configuration := range objects(properties["ipConfigurations"]) {
				if fact.subnetID == "" {
					fact.subnetID = objectID(configuration["subnet"])
				}
				if id := objectID(configuration["publicIPAddress"]); id != "" {
					fact.publicIPs = append(fact.publicIPs, id)
				}
			}
			nics[normalizedID(resource.ID)] = fact
		case "microsoft.network/publicipaddresses":
			publicIPs[normalizedID(resource.ID)] = strings.TrimSpace(stringValue(properties["ipAddress"])) != ""
		case "microsoft.network/networksecuritygroups":
			nsgs[normalizedID(resource.ID)] = objects(properties["securityRules"])
		case "microsoft.network/routetables":
			routes[normalizedID(resource.ID)] = routeFact{virtualApplianceDefaultRoute: hasVirtualApplianceDefaultRoute(objects(properties["routes"]))}
		case "microsoft.network/virtualnetworks":
			for _, subnet := range objects(properties["subnets"]) {
				subnets[normalizedID(stringValue(subnet["id"]))] = subnetFact{nsgID: objectID(subnet["networkSecurityGroup"]), routeTableID: objectID(subnet["routeTable"])}
			}
		}
	}
	byID := map[string]int{}
	for index, resource := range inventory.Resources {
		byID[normalizedID(resource.ID)] = index
	}
	for _, resource := range inventory.Resources {
		if resource.ResourceType != "microsoft.network/networkinterfaces" {
			continue
		}
		nic := nics[normalizedID(resource.ID)]
		if nic.vmID == "" || !effectivePublicNetwork(nic, publicIPs, nsgs, subnets, routes) {
			continue
		}
		if index, ok := byID[normalizedID(nic.vmID)]; ok {
			inventory.Resources[index].Public = cloudposture.StateEnabled
			inventory.Resources[index].PublicNetwork = cloudposture.StateEnabled
		}
	}
}

func effectivePublicNetwork(nic nicFact, publicIPs map[string]bool, nsgs map[string][]map[string]any, subnets map[string]subnetFact, routes map[string]routeFact) bool {
	if len(nic.publicIPs) == 0 || nic.subnetID == "" {
		return false
	}
	for _, publicIP := range nic.publicIPs {
		if !publicIPs[normalizedID(publicIP)] {
			return false
		}
	}
	if nic.nsgID != "" && !nsgAllowsPublicInbound(nsgs, nic.nsgID) {
		return false
	}
	subnet, ok := subnets[normalizedID(nic.subnetID)]
	if !ok || (subnet.nsgID != "" && !nsgAllowsPublicInbound(nsgs, subnet.nsgID)) {
		return false
	}
	if subnet.routeTableID != "" {
		route, ok := routes[normalizedID(subnet.routeTableID)]
		if !ok || route.virtualApplianceDefaultRoute {
			return false
		}
	}
	return true
}

func nsgAllowsPublicInbound(nsgs map[string][]map[string]any, id string) bool {
	type candidate struct {
		priority float64
		allow    bool
	}
	rules, ok := nsgs[normalizedID(id)]
	if !ok {
		return false
	}
	var matches []candidate
	for _, rule := range rules {
		properties, ok := rule["properties"].(map[string]any)
		if !ok {
			properties = rule
		}
		if !strings.EqualFold(stringValue(properties["direction"]), "Inbound") || !publicSource(properties) || !allDestinations(properties) {
			continue
		}
		access := strings.ToLower(stringValue(properties["access"]))
		priority, ok := properties["priority"].(float64)
		if ok && (access == "allow" || access == "deny") {
			matches = append(matches, candidate{priority, access == "allow"})
		}
	}
	if len(matches) == 0 {
		return false
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].priority < matches[j].priority })
	return matches[0].allow
}

func publicSource(properties map[string]any) bool {
	for _, source := range append([]string{stringValue(properties["sourceAddressPrefix"])}, stringsSlice(properties["sourceAddressPrefixes"])...) {
		switch strings.ToLower(strings.TrimSpace(source)) {
		case "*", "internet", "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
}
func allDestinations(properties map[string]any) bool {
	for _, destination := range append([]string{stringValue(properties["destinationAddressPrefix"])}, stringsSlice(properties["destinationAddressPrefixes"])...) {
		if strings.TrimSpace(destination) == "*" {
			return true
		}
	}
	return false
}
func stringsSlice(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}
func hasVirtualApplianceDefaultRoute(routes []map[string]any) bool {
	for _, route := range routes {
		properties, ok := route["properties"].(map[string]any)
		if !ok {
			properties = route
		}
		if strings.EqualFold(stringValue(properties["addressPrefix"]), "0.0.0.0/0") && strings.EqualFold(stringValue(properties["nextHopType"]), "VirtualAppliance") {
			return true
		}
	}
	return false
}

type roleDefinition struct{ wildcard, highPrivilege bool }

func applyRoleFacts(inventory *cloudposture.Inventory, resources []graphResource) {
	definitions := map[string]roleDefinition{}
	assignmentDefinitions := map[string]string{}
	for _, resource := range resources {
		properties := resourceProperties(resource)
		switch strings.ToLower(resource.Type) {
		case "microsoft.authorization/roledefinitions":
			definitions[normalizedID(resource.ID)] = roleDefinition{wildcard: roleHasWildcard(properties), highPrivilege: roleIsHighPrivilege(properties)}
		case "microsoft.authorization/roleassignments":
			assignmentDefinitions[normalizedID(resource.ID)] = normalizedID(stringValue(properties["roleDefinitionId"]))
		}
	}
	for index := range inventory.Resources {
		resource := &inventory.Resources[index]
		switch resource.ResourceType {
		case "microsoft.authorization/roledefinitions":
			definition := definitions[normalizedID(resource.ID)]
			resource.WildcardAction, resource.HighPrivilege = definition.wildcard, definition.highPrivilege
		case "microsoft.authorization/roleassignments":
			definition, known := definitions[assignmentDefinitions[normalizedID(resource.ID)]]
			resource.PolicyKnown, resource.WildcardAction, resource.HighPrivilege = known, definition.wildcard, definition.highPrivilege
		}
	}
}
func roleHasWildcard(properties map[string]any) bool {
	for _, permission := range objects(properties["permissions"]) {
		for _, action := range append(stringsSlice(permission["actions"]), stringsSlice(permission["dataActions"])...) {
			if strings.Contains(action, "*") {
				return true
			}
		}
	}
	return false
}
func roleIsHighPrivilege(properties map[string]any) bool {
	switch strings.ToLower(strings.TrimSpace(stringValue(properties["roleName"]))) {
	case "owner", "contributor", "user access administrator":
		return true
	}
	for _, permission := range objects(properties["permissions"]) {
		for _, action := range append(stringsSlice(permission["actions"]), stringsSlice(permission["dataActions"])...) {
			action = strings.ToLower(action)
			if action == "*" || strings.HasPrefix(action, "microsoft.authorization/") || strings.HasSuffix(action, "/write") || strings.HasSuffix(action, "/delete") {
				return true
			}
		}
	}
	return false
}
func sortCoverage(gaps []cloudposture.CoverageIssue) {
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].Category != gaps[j].Category {
			return gaps[i].Category < gaps[j].Category
		}
		if gaps[i].Scope != gaps[j].Scope {
			return gaps[i].Scope < gaps[j].Scope
		}
		return gaps[i].Code < gaps[j].Code
	})
}

func validateScope(scope ports.CloudScope) error {
	if scope.Provider != cloudposture.ProviderAzure || scope.EngagementID.IsZero() || strings.TrimSpace(scope.Root) == "" || strings.TrimSpace(scope.CredentialRef) == "" {
		return fmt.Errorf("%w: invalid Azure cloud scope", shared.ErrValidation)
	}
	_, _, err := azureScope(scope.Root)
	return err
}

func azureScope(root string) (string, bool, error) {
	root = strings.Trim(strings.TrimSpace(root), "/")
	lower := strings.ToLower(root)
	if strings.HasPrefix(lower, "subscriptions/") {
		root = root[len("subscriptions/"):]
		if root != "" && !strings.Contains(root, "/") {
			return root, false, nil
		}
	}
	if strings.HasPrefix(lower, "managementgroups/") {
		root = root[len("managementGroups/"):]
		if root != "" && !strings.Contains(root, "/") {
			return root, true, nil
		}
	}
	if root != "" && !strings.Contains(root, "/") {
		return root, false, nil
	}
	return "", false, fmt.Errorf("%w: Azure scope root must be a subscription ID or management group", shared.ErrValidation)
}

func ptr[T any](value T) *T { return &value }

type vaultCredential struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type azureTransport struct {
	next  http.RoundTripper
	scope ports.CloudScope
}

func (t azureTransport) Do(request *http.Request) (*http.Response, error) {
	category := "resource-graph"
	if strings.Contains(strings.ToLower(request.URL.Host), "login.microsoft") || strings.Contains(strings.ToLower(request.URL.Path), "oauth") {
		category = "identity"
	}
	if err := ports.AuthorizeCloudOperation(request.Context(), t.scope, category, request.Method+" "+request.URL.Host+request.URL.Path); err != nil {
		return nil, err
	}
	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(request)
}

func newResourceGraphClient(secret []byte, scope ports.CloudScope) (resourceGraphClient, error) {
	var credential vaultCredential
	if err := json.Unmarshal(secret, &credential); err != nil || strings.TrimSpace(credential.TenantID) == "" || strings.TrimSpace(credential.ClientID) == "" || strings.TrimSpace(credential.ClientSecret) == "" {
		return nil, fmt.Errorf("%w: invalid Azure credential material", shared.ErrValidation)
	}
	transport := azureTransport{next: http.DefaultTransport, scope: scope}
	clientOptions := azcore.ClientOptions{Transport: transport, Retry: policy.RetryOptions{MaxRetries: -1}}
	token, err := azidentity.NewClientSecretCredential(credential.TenantID, credential.ClientID, credential.ClientSecret, &azidentity.ClientSecretCredentialOptions{ClientOptions: clientOptions})
	if err != nil {
		return nil, fmt.Errorf("create Azure client-secret credential: %w", err)
	}
	client, err := armresourcegraph.NewClient(token, &arm.ClientOptions{ClientOptions: clientOptions})
	if err != nil {
		return nil, fmt.Errorf("create Azure Resource Graph client: %w", err)
	}
	return client, nil
}
