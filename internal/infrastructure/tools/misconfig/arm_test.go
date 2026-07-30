package misconfig

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

const armSchema = `"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"`

func TestLooksARM(t *testing.T) {
	arm := []byte(`{` + armSchema + `,"contentVersion":"1.0.0.0","resources":[]}`)
	if !looksARM(arm) {
		t.Fatal("deploymentTemplate JSON should be classified as ARM")
	}
	if looksARM([]byte(`{"AWSTemplateFormatVersion":"2010-09-09","Resources":{}}`)) {
		t.Fatal("CloudFormation JSON must not be classified as ARM")
	}
	if looksARM([]byte(`{"resources":[]}`)) {
		t.Fatal("ordinary JSON with a resources key must not be classified as ARM")
	}
}

func TestARMRepresentativeRuleFamilies(t *testing.T) {
	tmpl := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "adminPassword": {"type":"secureString","defaultValue":"real-secret-value","metadata":{"description":"Administrator password"}},
    "unused": {"type":"string","metadata":{"description":"Unused input"}}
  },
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2018-01-01",
      "name": "companyprodstore",
      "location": "eastus",
      "properties": {
        "allowBlobPublicAccess": true,
        "supportsHttpsTrafficOnly": false,
        "minimumTlsVersion": "TLS1_0",
        "publicNetworkAccess": "Enabled",
        "encryption": {"requireInfrastructureEncryption": false}
      }
    },
    {
      "type": "Microsoft.Network/networkSecurityGroups",
      "apiVersion": "2023-01-01",
      "name": "open-nsg",
      "properties": {
        "securityRules": [
          {"name":"in","properties":{"direction":"Inbound","access":"Allow","sourceAddressPrefix":"0.0.0.0/0"}},
          {"name":"out","properties":{"direction":"Outbound","access":"Allow","destinationAddressPrefix":"*"}}
        ]
      }
    },
    {
      "type": "Microsoft.Insights/diagnosticSettings",
      "apiVersion": "2021-05-01-preview",
      "name": "diag",
      "properties": {"logs":[{"category":"AuditEvent","enabled":false}]}
    }
  ],
  "outputs": {
    "storageKey": {"type":"string","value":"[listKeys(resourceId('Microsoft.Storage/storageAccounts','companyprodstore'),'2023-01-01').keys[0].value]"}
  }
}`
	got := ruleIDs(scan(t, map[string]string{"azuredeploy.json": tmpl}))
	for _, want := range []string{
		"arm-storage-public-blob",
		"arm-storage-public-network",
		"arm-storage-https-only-off",
		"arm-storage-min-tls-below-12",
		"arm-storage-infrastructure-encryption-disabled",
		"arm-nsg-open-inbound",
		"arm-nsg-open-egress",
		"arm-hardcoded-secret",
		"arm-secret-in-output",
		"arm-diagnostic-logs-disabled",
		"arm-location-hardcoded",
		"arm-apiversion-old",
		"arm-missing-tags",
		"arm-unused-parameter",
		"arm-resource-name-hardcoded",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected %s, got %v", want, keys(got))
		}
	}
}

func TestARMDynamicExpressionsFailClosed(t *testing.T) {
	tmpl := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "flag": {"type":"bool","metadata":{"description":"Security flag"}},
    "secret": {"type":"secureString","metadata":{"description":"Secret input"}}
  },
  "resources": [
    {
      "type": "Microsoft.KeyVault/vaults",
      "apiVersion": "2023-07-01",
      "name": "[concat('kv', uniqueString(resourceGroup().id))]",
      "location": "[resourceGroup().location]",
      "tags": {"owner":"security"},
      "properties": {
        "publicNetworkAccess": "[if(parameters('flag'),'Enabled','Disabled')]",
        "enableRbacAuthorization": "[parameters('flag')]",
        "enablePurgeProtection": "[parameters('flag')]",
        "adminPassword": "[parameters('secret')]"
      }
    }
  ]
}`
	got := ruleIDs(scan(t, map[string]string{"azuredeploy.json": tmpl}))
	for _, unwanted := range []string{
		"arm-keyvault-public-network",
		"arm-keyvault-rbac-disabled",
		"arm-keyvault-purge-protection-disabled",
		"arm-hardcoded-secret",
		"arm-location-hardcoded",
		"arm-resource-name-hardcoded",
	} {
		if _, ok := got[unwanted]; ok {
			t.Errorf("dynamic expression must suppress %s; got %v", unwanted, keys(got))
		}
	}
}

func TestARMSecretValueNeverCopiedToFinding(t *testing.T) {
	const secret = "do-not-copy-this-secret"
	tmpl := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type":"Microsoft.Web/sites",
    "apiVersion":"2023-01-01",
    "name":"app",
    "properties":{"clientSecret":"` + secret + `"}
  }]
}`
	for _, f := range scan(t, map[string]string{"azuredeploy.json": tmpl}) {
		if strings.Contains(f.Description, secret) || strings.Contains(f.Resource, secret) || strings.Contains(f.Title, secret) {
			t.Fatalf("finding leaked secret value: %+v", f)
		}
	}
}

func TestARMNestedResourceRules(t *testing.T) {
	tmpl := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type":"Microsoft.Sql/servers",
    "apiVersion":"2023-01-01",
    "name":"sql",
    "properties":{"publicNetworkAccess":"Disabled","minimalTlsVersion":"1.2"},
    "resources":[{
      "type":"Microsoft.Sql/servers/databases/transparentDataEncryption",
      "apiVersion":"2023-01-01",
      "name":"sql/db/current",
      "properties":{"status":"Disabled"}
    }]
  }]
}`
	got := ruleIDs(scan(t, map[string]string{"azuredeploy.json": tmpl}))
	if _, ok := got["arm-sql-tde-disabled"]; !ok {
		t.Errorf("nested TDE resource should be scanned, got %v", keys(got))
	}
}

func TestARMLanguageVersion2ResourcesObject(t *testing.T) {
	tmpl := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "languageVersion": "2.0",
  "contentVersion": "1.0.0.0",
  "resources": {
    "storage": {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "companyprodstore",
      "properties": {
        "allowBlobPublicAccess": true
      }
    }
  }
}`
	got := ruleIDs(scan(t, map[string]string{"azuredeploy.json": tmpl}))
	if _, ok := got["arm-storage-public-blob"]; !ok {
		t.Errorf("languageVersion 2.0 resource object should be scanned, got %v", keys(got))
	}
}

func TestARMNestedRelativeChildType(t *testing.T) {
	tmpl := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type": "Microsoft.Sql/servers",
    "apiVersion": "2023-01-01",
    "name": "sql",
    "resources": [{
      "type": "databases",
      "apiVersion": "2023-01-01",
      "name": "app",
      "resources": [{
        "type": "transparentDataEncryption",
        "apiVersion": "2023-01-01",
        "name": "current",
        "properties": {"status": "Disabled"}
      }]
    }]
  }]
}`
	findings := scan(t, map[string]string{"azuredeploy.json": tmpl})
	for _, finding := range findings {
		if finding.RuleID == "arm-sql-tde-disabled" {
			if !strings.Contains(finding.Resource, "sql/app/current") {
				t.Fatalf("nested resource name was not normalized: %q", finding.Resource)
			}
			return
		}
	}
	t.Fatalf("relative nested TDE resource should be scanned, got %v", keys(ruleIDs(findings)))
}

func TestARMExtensionDiagnosticSettingsSuppressMissingFinding(t *testing.T) {
	tmpl := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type": "Microsoft.Storage/storageAccounts",
    "apiVersion": "2023-01-01",
    "name": "companyprodstore",
    "resources": [{
      "type": "providers/diagnosticSettings",
      "apiVersion": "2021-05-01-preview",
      "name": "Microsoft.Insights/default",
      "properties": {
        "logs": [{"category": "StorageRead", "enabled": true}]
      }
    }]
  }]
}`
	got := ruleIDs(scan(t, map[string]string{"azuredeploy.json": tmpl}))
	if _, ok := got["arm-no-diagnostic-settings"]; ok {
		t.Errorf("nested extension diagnostic setting should cover its parent, got %v", keys(got))
	}
	if _, ok := got["arm-diagnostic-logs-disabled"]; ok {
		t.Errorf("extension diagnostic setting with enabled logs should be recognized, got %v", keys(got))
	}
}

func TestARMDepthBombSkipped(t *testing.T) {
	bomb := append([]byte(`{`+armSchema+`,"resources":`), bytes.Repeat([]byte("["), 300000)...)
	bomb = append(bomb, bytes.Repeat([]byte("]"), 300000)...)
	bomb = append(bomb, '}')
	if got := scanARM("bomb.json", bomb); got != nil {
		t.Fatalf("deep ARM input should be skipped, got %d findings", len(got))
	}
}

func TestARMFindingCaps(t *testing.T) {
	var resources strings.Builder
	for i := 0; i < maxARMFindingsPerRule+25; i++ {
		if i > 0 {
			resources.WriteByte(',')
		}
		resources.WriteString(`{"type":"Microsoft.Network/publicIPAddresses","apiVersion":"2023-01-01","name":"pip`)
		resources.WriteString(strconv.Itoa(i))
		resources.WriteString(`","tags":{"owner":"network"},"properties":{}}`)
	}
	tmpl := `{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#","contentVersion":"1.0.0.0","resources":[` + resources.String() + `]}`
	count := 0
	for _, finding := range scanARM("azuredeploy.json", []byte(tmpl)) {
		if finding.RuleID == "arm-public-ip-resource" {
			count++
		}
	}
	if count != maxARMFindingsPerRule {
		t.Fatalf("per-rule finding cap mismatch: got %d, want %d", count, maxARMFindingsPerRule)
	}
}
