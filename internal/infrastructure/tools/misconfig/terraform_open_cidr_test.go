package misconfig

import "testing"

// A validation that REFUSES 0.0.0.0/0 is the mitigation, so flagging it reports the guard as the defect.
// The rule used to match the literal anywhere in the line, which made a blocking condition and an allowing
// attribute indistinguishable.
func TestTerraformOpenCIDRIgnoresBlockingCondition(t *testing.T) {
	fs := scan(t, map[string]string{
		"variables.tf": `
variable "allowed_cidrs" {
  type = list(string)
  validation {
    condition     = !contains(var.allowed_cidrs, "0.0.0.0/0")
    error_message = "0.0.0.0/0 is not an allowed ingress CIDR."
  }
}
`,
	})
	if _, ok := ruleIDs(fs)["terraform-open-cidr"]; ok {
		t.Fatalf("a validation that refuses 0.0.0.0/0 must not be reported as opening it, got %v", ruleIDs(fs))
	}
}

// A default route to 0.0.0.0/0 on a route table is ordinary routing, and the attribute that carries it is
// destination_cidr_block, not a firewall range.
func TestTerraformOpenCIDRIgnoresDefaultRoute(t *testing.T) {
	fs := scan(t, map[string]string{
		"route.tf": `
resource "aws_route" "default" {
  route_table_id         = aws_route_table.main.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.gw.id
}
`,
	})
	if _, ok := ruleIDs(fs)["terraform-open-cidr"]; ok {
		t.Fatalf("a default route must not be reported as an open firewall rule, got %v", ruleIDs(fs))
	}
}

// The real defect still fires, including when the list spans several lines.
func TestTerraformOpenCIDRFlagsAllowingAttribute(t *testing.T) {
	fs := scan(t, map[string]string{
		"sg.tf": `
resource "aws_security_group" "web" {
  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }
}
`,
	})
	if _, ok := ruleIDs(fs)["terraform-open-cidr"]; !ok {
		t.Fatalf("an ingress rule allowing 0.0.0.0/0 must still be reported, got %v", ruleIDs(fs))
	}
}

// Azure expresses the same rule through source_address_prefix on a resource type that carries neither
// "security_group" nor "firewall" nor "ingress", which the old resource-type gate could not reach.
func TestTerraformOpenCIDRFlagsAzureNetworkSecurityRule(t *testing.T) {
	fs := scan(t, map[string]string{
		"nsg.tf": `
resource "azurerm_network_security_rule" "ssh" {
  direction             = "Inbound"
  access                = "Allow"
  destination_port_range = "22"
  source_address_prefix = "0.0.0.0/0"
}
`,
	})
	if _, ok := ruleIDs(fs)["terraform-open-cidr"]; !ok {
		t.Fatalf("an Azure NSG rule allowing 0.0.0.0/0 must be reported, got %v", ruleIDs(fs))
	}
}

// GCP names the egress direction in the attribute itself, so the egress rule is reported rather than the
// higher-severity ingress one.
func TestTerraformOpenCIDRUsesAttributeDirection(t *testing.T) {
	fs := scan(t, map[string]string{
		"fw.tf": `
resource "google_compute_firewall" "out" {
  destination_ranges = ["0.0.0.0/0"]
}
`,
	})
	ids := ruleIDs(fs)
	if _, ok := ids["terraform-open-egress"]; !ok {
		t.Fatalf("destination_ranges of 0.0.0.0/0 must be reported as open egress, got %v", ids)
	}
	if _, ok := ids["terraform-open-cidr"]; ok {
		t.Fatalf("an egress range must not also be reported as open ingress, got %v", ids)
	}
}
