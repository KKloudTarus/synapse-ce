package misconfig

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxARMResources       = 10000
	maxARMDepth           = 64
	maxARMNodeWalk        = 100000
	maxARMFindings        = 2000
	maxARMFindingsPerRule = 100
)

var armSecretKeyRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|connection[_-]?string)$`)

type armResource struct {
	node       *yaml.Node
	properties *yaml.Node
	identity   *yaml.Node
	tags       *yaml.Node
	dependsOn  *yaml.Node
	typ        string
	name       string
	apiVersion string
	location   string
	parentType string
	parentName string
	line       int
}

type armScanner struct {
	rel       string
	source    string
	root      *yaml.Node
	resources []armResource
	findings  []ports.MisconfigRawFinding
	ruleCount map[string]int
}

// looksARM is a conservative content sniff for an Azure Resource Manager deployment template. Bicep
// compilation emits the same deploymentTemplate schema and resources array, so compiled Bicep is covered.
func looksARM(data []byte) bool {
	t := strings.ToLower(string(data))
	return strings.Contains(t, "deploymenttemplate.json") && strings.Contains(t, `"resources"`)
}

// scanARM parses an ARM JSON template through yaml.Node (JSON is a YAML subset) to retain source lines.
// It never evaluates ARM expressions and treats dynamic values as unknown rather than insecure literals.
func scanARM(rel string, data []byte) []ports.MisconfigRawFinding {
	if tooDeepYAML(data) {
		return nil
	}
	var root yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&root); err != nil {
		return nil
	}
	doc := documentRoot(&root)
	if !armTemplateRoot(doc) {
		return nil
	}

	s := &armScanner{rel: rel, source: string(data), root: doc, ruleCount: make(map[string]int)}
	s.collectResources(mapValue(doc, "resources"), 0, "", "")
	for _, res := range s.resources {
		s.scanResource(res)
	}
	s.scanOutputs(mapValue(doc, "outputs"))
	s.scanParameters(mapValue(doc, "parameters"))
	s.scanUnusedSymbols(mapValue(doc, "parameters"), "parameters", "arm-unused-parameter", "Unused ARM parameter")
	s.scanUnusedSymbols(mapValue(doc, "variables"), "variables", "arm-unused-variable", "Unused ARM variable")
	s.scanMissingDiagnostics()
	return s.findings
}

func armTemplateRoot(root *yaml.Node) bool {
	if root == nil || root.Kind != yaml.MappingNode {
		return false
	}
	schema, ok := armLiteral(mapValue(root, "$schema"))
	if !ok || !strings.Contains(strings.ToLower(schema), "deploymenttemplate.json") {
		return false
	}
	return mapValue(root, "resources") != nil
}

func (s *armScanner) collectResources(items *yaml.Node, depth int, parentType, parentName string) {
	if depth > maxARMDepth || len(s.resources) >= maxARMResources || items == nil {
		return
	}

	start, step := 0, 1
	switch items.Kind {
	case yaml.SequenceNode:
	case yaml.MappingNode:
		// ARM languageVersion 2.0 keys root resources by symbolic name.
		start, step = 1, 2
	default:
		return
	}

	for i := start; i < len(items.Content); i += step {
		if len(s.resources) >= maxARMResources {
			break
		}
		node := items.Content[i]
		if node == nil || node.Kind != yaml.MappingNode {
			continue
		}
		typ, ok := armLiteral(mapValue(node, "type"))
		if !ok || typ == "" {
			continue
		}
		name, _ := armLiteral(mapValue(node, "name"))
		typ = armNestedResourceType(parentType, typ)
		name = armNestedResourceName(parentName, name)
		apiVersion, _ := armLiteral(mapValue(node, "apiVersion"))
		location, _ := armLiteral(mapValue(node, "location"))
		res := armResource{
			node:       node,
			properties: mapValue(node, "properties"),
			identity:   mapValue(node, "identity"),
			tags:       mapValue(node, "tags"),
			dependsOn:  mapValue(node, "dependsOn"),
			typ:        strings.ToLower(typ),
			name:       name,
			apiVersion: apiVersion,
			location:   location,
			parentType: parentType,
			parentName: parentName,
			line:       node.Line,
		}
		s.resources = append(s.resources, res)
		s.collectResources(mapValue(node, "resources"), depth+1, res.typ, res.name)
	}
}

func armNestedResourceType(parentType, typ string) string {
	if parentType == "" {
		return typ
	}
	if !strings.Contains(typ, "/") || strings.EqualFold(typ, "providers/diagnosticSettings") {
		return parentType + "/" + typ
	}
	return typ
}

func armNestedResourceName(parentName, name string) string {
	if parentName != "" && name != "" && !strings.Contains(name, "/") {
		return parentName + "/" + name
	}
	return name
}

func (s *armScanner) add(res armResource, rule, title string, sev shared.Severity, line int, desc string) {
	if len(s.findings) >= maxARMFindings || s.ruleCount[rule] >= maxARMFindingsPerRule {
		return
	}
	if line <= 0 {
		line = res.line
	}
	resource := "ARM " + clip(res.typ)
	if res.name != "" {
		resource += " " + clip(res.name)
	}
	s.findings = append(s.findings, ports.MisconfigRawFinding{
		File: s.rel, Line: line, RuleID: rule, Title: title, Severity: sev,
		Resource: resource, Description: desc,
	})
	s.ruleCount[rule]++
}

func (s *armScanner) scanResource(res armResource) {
	props := res.properties
	switch res.typ {
	case "microsoft.storage/storageaccounts":
		if armBool(mapValue(props, "allowBlobPublicAccess"), false) == armTrue {
			s.add(res, "arm-storage-public-blob", "Storage account permits public blob access", shared.SeverityHigh, armLine(mapValue(props, "allowBlobPublicAccess"), res.line),
				"allowBlobPublicAccess is true, so containers can be configured for anonymous access. Set it to false and authorize access through Microsoft Entra ID or scoped SAS tokens.")
		}
		if armPublicNetwork(props) {
			s.add(res, "arm-storage-public-network", "Storage account allows public network access", shared.SeverityMedium, res.line,
				"The storage account explicitly allows public network access or uses a network ACL default action of Allow. Disable public access and use private endpoints or an explicit network allow-list.")
		}
		if armBool(mapValue(props, "supportsHttpsTrafficOnly"), true) == armFalse {
			s.add(res, "arm-storage-https-only-off", "Storage account permits insecure HTTP traffic", shared.SeverityHigh, armLine(mapValue(props, "supportsHttpsTrafficOnly"), res.line),
				"supportsHttpsTrafficOnly is false, allowing unencrypted HTTP requests. Set it to true so clients must use TLS.")
		}
		if armTLSBelow12(mapValue(props, "minimumTlsVersion")) {
			s.add(res, "arm-storage-min-tls-below-12", "Storage account permits TLS below 1.2", shared.SeverityMedium, armLine(mapValue(props, "minimumTlsVersion"), res.line),
				"minimumTlsVersion is below TLS 1.2. Set it to TLS1_2 or a newer supported version.")
		}
		enc := mapValue(props, "encryption")
		if armBool(mapValue(enc, "requireInfrastructureEncryption"), false) != armTrue {
			s.add(res, "arm-storage-infrastructure-encryption-disabled", "Storage infrastructure encryption is not enabled", shared.SeverityMedium, res.line,
				"The storage account does not require infrastructure encryption, so data is protected by only one encryption layer. Set encryption.requireInfrastructureEncryption to true where supported.")
		}

	case "microsoft.network/networksecuritygroups":
		s.scanNSGRules(res, mapValue(props, "securityRules"))

	case "microsoft.network/networksecuritygroups/securityrules":
		s.scanNSGRule(res, props)

	case "microsoft.network/networkinterfaces":
		for _, cfg := range seqItems(mapValue(props, "ipConfigurations")) {
			if mapValue(mapValue(cfg, "properties"), "publicIPAddress") != nil {
				s.add(res, "arm-public-ip-on-nic", "Network interface attaches a public IP address", shared.SeverityMedium, cfg.Line,
					"An IP configuration references a publicIPAddress resource, exposing the attached workload to the internet. Prefer private addressing and an application gateway, load balancer, or bastion where public ingress is required.")
				break
			}
		}

	case "microsoft.network/publicipaddresses":
		s.add(res, "arm-public-ip-resource", "Public IP address resource requires review", shared.SeverityLow, res.line,
			"The template provisions a public IP address. Confirm that internet exposure is necessary, protected by a narrowly scoped network policy, and monitored.")

	case "microsoft.containerservice/managedclusters":
		if armBool(mapValue(props, "enableRBAC"), true) == armFalse {
			s.add(res, "arm-aks-rbac-disabled", "AKS role-based access control is disabled", shared.SeverityHigh, armLine(mapValue(props, "enableRBAC"), res.line),
				"enableRBAC is false, so Kubernetes authorization is not enforced through RBAC. Enable RBAC and grant only the required roles.")
		}
		private := mapValue(mapValue(props, "apiServerAccessProfile"), "enablePrivateCluster")
		if armBool(private, false) == armFalse {
			s.add(res, "arm-aks-private-cluster-disabled", "AKS API server is not private", shared.SeverityMedium, res.line,
				"The cluster does not enable a private API server. Enable apiServerAccessProfile.enablePrivateCluster or tightly restrict authorized IP ranges.")
		}
		s.scanManagedIdentity(res)

	case "microsoft.keyvault/vaults":
		if armPublicNetwork(props) {
			s.add(res, "arm-keyvault-public-network", "Key Vault allows public network access", shared.SeverityHigh, res.line,
				"The vault explicitly allows public network access or uses a network ACL default action of Allow. Disable public access and use private endpoints or a strict allow-list.")
		}
		if armBool(mapValue(props, "enableRbacAuthorization"), false) == armFalse {
			s.add(res, "arm-keyvault-rbac-disabled", "Key Vault Azure RBAC authorization is not enabled", shared.SeverityMedium, res.line,
				"The vault does not enable Azure RBAC authorization. Prefer enableRbacAuthorization: true and least-privilege role assignments over legacy access policies.")
		}
		if armBool(mapValue(props, "enablePurgeProtection"), false) == armFalse {
			s.add(res, "arm-keyvault-purge-protection-disabled", "Key Vault purge protection is not enabled", shared.SeverityMedium, res.line,
				"The vault does not enable purge protection, so a deleted vault or secret can be permanently removed during the retention period. Set enablePurgeProtection to true.")
		}

	case "microsoft.sql/servers":
		if v, ok := armLiteral(mapValue(props, "publicNetworkAccess")); ok && strings.EqualFold(v, "Enabled") {
			s.add(res, "arm-sql-public-network", "SQL server allows public network access", shared.SeverityHigh, armLine(mapValue(props, "publicNetworkAccess"), res.line),
				"publicNetworkAccess is Enabled, exposing the SQL endpoint to public networks. Disable it and use private endpoints.")
		}
		if armNumericBelow(mapValue(props, "minimalTlsVersion"), 1.2) {
			s.add(res, "arm-sql-min-tls-below-12", "SQL server permits TLS below 1.2", shared.SeverityMedium, armLine(mapValue(props, "minimalTlsVersion"), res.line),
				"minimalTlsVersion is below 1.2. Require TLS 1.2 or newer for database connections.")
		}

	case "microsoft.sql/servers/databases/transparentdataencryption":
		if v, ok := armLiteral(mapValue(props, "status")); ok && strings.EqualFold(v, "Disabled") {
			s.add(res, "arm-sql-tde-disabled", "SQL transparent data encryption is disabled", shared.SeverityHigh, armLine(mapValue(props, "status"), res.line),
				"Transparent data encryption is explicitly Disabled. Set status to Enabled to protect database files and backups at rest.")
		}

	case "microsoft.sql/servers/auditingsettings", "microsoft.sql/servers/databases/auditingsettings":
		if v, ok := armLiteral(mapValue(props, "state")); ok && strings.EqualFold(v, "Disabled") {
			s.add(res, "arm-sql-auditing-disabled", "SQL auditing is disabled", shared.SeverityMedium, armLine(mapValue(props, "state"), res.line),
				"The auditing setting is Disabled, leaving database activity without an audit trail. Enable auditing and send records to a protected destination.")
		}

	case "microsoft.web/sites":
		if v, ok := armLiteral(mapValue(props, "publicNetworkAccess")); ok && strings.EqualFold(v, "Enabled") {
			s.add(res, "arm-webapp-public-network", "Web app allows public network access", shared.SeverityMedium, armLine(mapValue(props, "publicNetworkAccess"), res.line),
				"publicNetworkAccess is Enabled. Confirm the application is intended to be internet-facing and otherwise disable it in favor of private endpoints.")
		}
		siteConfig := mapValue(props, "siteConfig")
		if armNumericBelow(mapValue(siteConfig, "minTlsVersion"), 1.2) {
			s.add(res, "arm-webapp-min-tls-below-12", "Web app permits TLS below 1.2", shared.SeverityMedium, armLine(mapValue(siteConfig, "minTlsVersion"), res.line),
				"siteConfig.minTlsVersion is below 1.2. Require TLS 1.2 or newer.")
		}
		s.scanManagedIdentity(res)

	case "microsoft.compute/virtualmachines":
		enc := mapValue(mapValue(props, "securityProfile"), "encryptionAtHost")
		if armBool(enc, false) == armFalse {
			s.add(res, "arm-vm-encryption-at-host-disabled", "Virtual machine host encryption is not enabled", shared.SeverityMedium, res.line,
				"securityProfile.encryptionAtHost is not true. Enable encryption at host where supported so temporary disks and host caches are encrypted.")
		}
		s.scanManagedIdentity(res)

	case "microsoft.insights/diagnosticsettings":
		s.scanDiagnosticSettings(res)

	case "microsoft.security/pricings":
		if v, ok := armLiteral(mapValue(props, "pricingTier")); ok && strings.EqualFold(v, "Free") {
			s.add(res, "arm-defender-pricing-free", "Microsoft Defender plan uses the Free tier", shared.SeverityLow, armLine(mapValue(props, "pricingTier"), res.line),
				"pricingTier is Free, so the protected resource type does not receive the full Defender for Cloud protections. Review whether the Standard tier is required for the workload.")
		}
	}

	if res.typ != "microsoft.insights/diagnosticsettings" && armDiagnosticSettingsType(res.typ) {
		s.scanDiagnosticSettings(res)
	}
	s.scanCommonResourceRules(res)
	s.scanHardcodedSecrets(res)
}

func (s *armScanner) scanDiagnosticSettings(res armResource) {
	logs := mapValue(res.properties, "logs")
	enabled := false
	for _, log := range seqItems(logs) {
		if armBool(mapValue(log, "enabled"), false) == armTrue {
			enabled = true
			break
		}
	}
	if !enabled {
		s.add(res, "arm-diagnostic-logs-disabled", "Diagnostic setting has no enabled log categories", shared.SeverityLow, res.line,
			"The diagnostic setting contains no enabled log category. Enable the relevant logs and route them to a monitored Log Analytics workspace, Event Hub, or storage account.")
	}
}

func (s *armScanner) scanCommonResourceRules(res armResource) {
	if res.location != "" && !armExpression(res.location) && !strings.EqualFold(res.location, "global") {
		s.add(res, "arm-location-hardcoded", "Resource location is hardcoded", shared.SeverityInfo, armLine(mapValue(res.node, "location"), res.line),
			"The resource location is a fixed literal. Use resourceGroup().location or a parameter so the template remains portable between regions.")
	}
	if armOldAPIVersion(res.apiVersion) {
		s.add(res, "arm-apiversion-old", "Resource uses a very old API version", shared.SeverityInfo, armLine(mapValue(res.node, "apiVersion"), res.line),
			"The resource apiVersion predates 2020 and may miss current properties, defaults, and platform behavior. Upgrade to a supported stable API version after compatibility testing.")
	}
	if armShouldTag(res.typ) && (res.tags == nil || res.tags.Kind != yaml.MappingNode || len(res.tags.Content) == 0) {
		s.add(res, "arm-missing-tags", "Resource has no governance tags", shared.SeverityInfo, res.line,
			"The resource declares no tags. Add the organization-required ownership, environment, cost-center, and data-classification tags.")
	}
	if armGlobalNameType(res.typ) && res.name != "" && !armExpression(res.name) {
		s.add(res, "arm-resource-name-hardcoded", "Globally scoped resource name is hardcoded", shared.SeverityInfo, armLine(mapValue(res.node, "name"), res.line),
			"A globally scoped resource uses a fixed literal name, which can collide across deployments. Derive the name from parameters and uniqueString() while preserving a stable prefix.")
	}
	for _, dep := range seqItems(res.dependsOn) {
		if v, ok := armLiteral(dep); ok && v != "" && !armExpression(v) {
			s.add(res, "arm-dependson-literal-id", "dependsOn contains a literal resource identifier", shared.SeverityInfo, dep.Line,
				"A dependsOn entry is a literal string instead of an ARM resourceId() expression. Use resourceId() so dependency identifiers remain correct across scopes and names.")
			break
		}
	}
}

func (s *armScanner) scanNSGRules(res armResource, rules *yaml.Node) {
	for _, item := range seqItems(rules) {
		s.scanNSGRule(res, mapValue(item, "properties"))
	}
}

func (s *armScanner) scanNSGRule(res armResource, props *yaml.Node) {
	direction, _ := armLiteral(mapValue(props, "direction"))
	access, _ := armLiteral(mapValue(props, "access"))
	if !strings.EqualFold(access, "Allow") {
		return
	}
	if strings.EqualFold(direction, "Inbound") && armOpenPrefix(props, "source") {
		s.add(res, "arm-nsg-open-inbound", "Network security rule allows internet-wide inbound access", shared.SeverityHigh, armLine(props, res.line),
			"An Allow inbound rule accepts traffic from any source. Restrict sourceAddressPrefix/sourceAddressPrefixes and destination ports to the minimum required ranges.")
	}
	if strings.EqualFold(direction, "Outbound") && armOpenPrefix(props, "destination") {
		s.add(res, "arm-nsg-open-egress", "Network security rule allows internet-wide outbound access", shared.SeverityMedium, armLine(props, res.line),
			"An Allow outbound rule permits traffic to any destination, easing command-and-control and data exfiltration after compromise. Restrict destination prefixes and ports.")
	}
}

func (s *armScanner) scanManagedIdentity(res armResource) {
	if res.identity == nil || res.identity.Kind != yaml.MappingNode {
		s.add(res, "arm-managed-identity-missing", "Resource has no managed identity", shared.SeverityLow, res.line,
			"The resource declares no managed identity. Prefer a system-assigned or user-assigned identity over embedded application credentials where the service supports it.")
		return
	}
	if typ, ok := armLiteral(mapValue(res.identity, "type")); ok && (typ == "" || strings.EqualFold(typ, "None")) {
		s.add(res, "arm-managed-identity-missing", "Resource has no managed identity", shared.SeverityLow, armLine(mapValue(res.identity, "type"), res.line),
			"The resource identity type is None. Prefer a managed identity over embedded application credentials where the service supports it.")
	}
}

func (s *armScanner) scanHardcodedSecrets(res armResource) {
	walked := 0
	var walk func(*yaml.Node, int)
	walk = func(n *yaml.Node, depth int) {
		if n == nil || depth > maxARMDepth || walked >= maxARMNodeWalk {
			return
		}
		walked++
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				key, val := n.Content[i].Value, n.Content[i+1]
				if armSecretKeyRe.MatchString(key) {
					if v, ok := armLiteral(val); ok && armSensitiveLiteral(v) {
						s.add(res, "arm-hardcoded-secret", "Hardcoded secret in ARM template", shared.SeverityHigh, val.Line,
							"A secret-like property contains a plaintext literal. Store the value in Key Vault and reference it through a secure parameter or deployment-time secret reference; never emit the value in findings or logs.")
						return
					}
				}
				walk(val, depth+1)
			}
			return
		}
		for _, child := range n.Content {
			walk(child, depth+1)
		}
	}
	walk(res.properties, 0)
}

func (s *armScanner) scanParameters(parameters *yaml.Node) {
	if parameters == nil || parameters.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(parameters.Content); i += 2 {
		key, param := parameters.Content[i], parameters.Content[i+1]
		typ, _ := armLiteral(mapValue(param, "type"))
		if strings.EqualFold(typ, "secureString") || strings.EqualFold(typ, "secureObject") {
			if v, ok := armLiteral(mapValue(param, "defaultValue")); ok && armSensitiveLiteral(v) {
				fake := armResource{typ: "template/parameters", name: key.Value, line: key.Line}
				s.add(fake, "arm-hardcoded-secret", "Hardcoded secret in ARM template", shared.SeverityHigh, armLine(mapValue(param, "defaultValue"), key.Line),
					"A secure parameter has a plaintext default value. Remove the default and supply the secret through Key Vault or a protected deployment input; never emit the value in findings or logs.")
			}
		}
		metadata := mapValue(param, "metadata")
		if desc, ok := armLiteral(mapValue(metadata, "description")); !ok || strings.TrimSpace(desc) == "" {
			fake := armResource{typ: "template/parameters", name: key.Value, line: key.Line}
			s.add(fake, "arm-parameter-missing-description", "ARM parameter has no description", shared.SeverityInfo, key.Line,
				"The parameter has no metadata.description. Document its purpose, expected format, and security sensitivity so operators can supply it safely.")
		}
	}
}

func (s *armScanner) scanOutputs(outputs *yaml.Node) {
	if outputs == nil || outputs.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(outputs.Content); i += 2 {
		key, out := outputs.Content[i], outputs.Content[i+1]
		value := mapValue(out, "value")
		v, _ := armLiteral(value)
		lower := strings.ToLower(v)
		if armSecretKeyRe.MatchString(key.Value) || strings.Contains(lower, "listkeys(") || strings.Contains(lower, "listsecrets(") || strings.Contains(lower, "getsecret(") {
			fake := armResource{typ: "template/output", name: key.Value, line: key.Line}
			s.add(fake, "arm-secret-in-output", "ARM output may expose secret material", shared.SeverityHigh, armLine(value, key.Line),
				"An output is secret-like or evaluates a key/secret function. Remove sensitive outputs and pass secrets directly to the consuming resource through Key Vault references.")
		}
	}
}

func (s *armScanner) scanUnusedSymbols(symbols *yaml.Node, functionName, ruleID, title string) {
	if symbols == nil || symbols.Kind != yaml.MappingNode {
		return
	}
	lowerSource := strings.ToLower(s.source)
	for i := 0; i+1 < len(symbols.Content); i += 2 {
		key, value := symbols.Content[i], symbols.Content[i+1]
		needle1 := strings.ToLower(functionName + "('" + key.Value + "')")
		needle2 := strings.ToLower(functionName + "(\"" + key.Value + "\")")
		if strings.Contains(lowerSource, needle1) || strings.Contains(lowerSource, needle2) {
			continue
		}
		fake := armResource{typ: "template/" + functionName, name: key.Value, line: key.Line}
		s.add(fake, ruleID, title, shared.SeverityInfo, key.Line,
			"The declared "+strings.TrimSuffix(functionName, "s")+" is never referenced by the template. Remove it or use it so the deployment contract stays clear and maintainable.")
		_ = value
	}
}

func (s *armScanner) scanMissingDiagnostics() {
	var diagnostics []armResource
	for _, res := range s.resources {
		if armDiagnosticSettingsType(res.typ) {
			diagnostics = append(diagnostics, res)
		}
	}
	for _, res := range s.resources {
		if !armDiagnosticTarget(res.typ) || res.name == "" || armExpression(res.name) {
			continue // cannot prove a diagnostic scope match for a dynamic or missing resource name
		}
		covered := false
		for _, diag := range diagnostics {
			if strings.EqualFold(diag.parentType, res.typ) && strings.EqualFold(diag.parentName, res.name) {
				covered = true
				break
			}
			scope, _ := armLiteral(mapValue(diag.node, "scope"))
			if scope == "" {
				scope, _ = armLiteral(mapValue(diag.properties, "scope"))
			}
			if armScopeMentionsName(scope, res.name) {
				covered = true
				break
			}
		}
		if !covered {
			s.add(res, "arm-no-diagnostic-settings", "Resource has no diagnostic settings", shared.SeverityLow, res.line,
				"No Microsoft.Insights/diagnosticSettings resource is scoped to this sensitive resource. Enable the relevant logs and metrics and route them to a monitored destination.")
		}
	}
}

func armDiagnosticSettingsType(typ string) bool {
	typ = strings.ToLower(typ)
	return typ == "microsoft.insights/diagnosticsettings" ||
		strings.HasSuffix(typ, "/providers/diagnosticsettings")
}

func armScopeMentionsName(scope, name string) bool {
	if scope == "" || name == "" || armExpression(name) {
		return false
	}
	scope = strings.ToLower(scope)
	name = strings.ToLower(name)
	trimmed := strings.TrimRight(scope, "])'\" ")
	return strings.Contains(scope, "'"+name+"'") ||
		strings.Contains(scope, `"`+name+`"`) ||
		strings.HasSuffix(trimmed, "/"+name)
}

type armTriState uint8

const (
	armUnknown armTriState = iota
	armFalse
	armTrue
)

func armBool(n *yaml.Node, missing bool) armTriState {
	if n == nil {
		if missing {
			return armTrue
		}
		return armFalse
	}
	v, ok := armLiteral(n)
	if !ok || armExpression(v) {
		return armUnknown
	}
	if strings.EqualFold(v, "true") {
		return armTrue
	}
	if strings.EqualFold(v, "false") {
		return armFalse
	}
	return armUnknown
}

func armLiteral(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	return n.Value, true
}

func armLine(n *yaml.Node, fallback int) int {
	if n != nil && n.Line > 0 {
		return n.Line
	}
	return fallback
}

func armExpression(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]")
}

func armSensitiveLiteral(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || armExpression(v) || strings.HasPrefix(v, "@Microsoft.KeyVault(") {
		return false
	}
	lower := strings.ToLower(v)
	if lower == "changeme" || lower == "replace-me" || strings.Contains(lower, "<secret") || strings.Contains(lower, "${") {
		return false
	}
	return len(v) >= 4
}

func armTLSBelow12(n *yaml.Node) bool {
	v, ok := armLiteral(n)
	if !ok || armExpression(v) {
		return false
	}
	v = strings.ToUpper(strings.ReplaceAll(v, ".", "_"))
	return v == "TLS1_0" || v == "TLS1_1" || v == "1_0" || v == "1_1"
}

func armNumericBelow(n *yaml.Node, min float64) bool {
	v, ok := armLiteral(n)
	if !ok || armExpression(v) {
		return false
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(v), "TLS")), 64)
	return err == nil && f < min
}

func armPublicNetwork(props *yaml.Node) bool {
	if v, ok := armLiteral(mapValue(props, "publicNetworkAccess")); ok && strings.EqualFold(v, "Enabled") {
		return true
	}
	if v, ok := armLiteral(mapValue(mapValue(props, "networkAcls"), "defaultAction")); ok && strings.EqualFold(v, "Allow") {
		return true
	}
	return false
}

func armOpenPrefix(props *yaml.Node, prefix string) bool {
	open := func(v string) bool {
		v = strings.TrimSpace(strings.ToLower(v))
		return v == "*" || v == "internet" || v == "0.0.0.0/0" || v == "::/0"
	}
	if v, ok := armLiteral(mapValue(props, prefix+"AddressPrefix")); ok && open(v) {
		return true
	}
	for _, item := range seqItems(mapValue(props, prefix+"AddressPrefixes")) {
		if v, ok := armLiteral(item); ok && open(v) {
			return true
		}
	}
	return false
}

func armOldAPIVersion(v string) bool {
	if armExpression(v) || len(v) < 10 {
		return false
	}
	date := v[:10]
	if _, err := fmt.Sscanf(date, "%4d-%2d-%2d", new(int), new(int), new(int)); err != nil {
		return false
	}
	return date < "2020-01-01"
}

func armShouldTag(typ string) bool {
	if strings.HasPrefix(typ, "microsoft.insights/") || strings.HasPrefix(typ, "microsoft.authorization/") || strings.HasPrefix(typ, "microsoft.security/") {
		return false
	}
	return strings.Count(typ, "/") == 1
}

func armGlobalNameType(typ string) bool {
	switch typ {
	case "microsoft.storage/storageaccounts", "microsoft.keyvault/vaults", "microsoft.containerregistry/registries":
		return true
	default:
		return false
	}
}

func armDiagnosticTarget(typ string) bool {
	switch typ {
	case "microsoft.storage/storageaccounts", "microsoft.keyvault/vaults", "microsoft.sql/servers", "microsoft.containerservice/managedclusters":
		return true
	default:
		return false
	}
}
