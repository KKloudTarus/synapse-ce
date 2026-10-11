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

// aws_security_group_rule declares its direction with a type attribute rather than an ingress/egress
// sub-block, and the resource type names neither direction. An allow-all egress rule written that way was
// reported as an open INGRESS rule, at high severity instead of medium.
func TestTerraformOpenCIDRReadsDirectionAttribute(t *testing.T) {
	fs := scan(t, map[string]string{
		"rules.tf": `
resource "aws_security_group_rule" "all_egress" {
  description       = "Allow all egress"
  type              = "egress"
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.this.id
}
`,
	})
	ids := ruleIDs(fs)
	if _, ok := ids["terraform-open-egress"]; !ok {
		t.Fatalf(`type = "egress" must be read as the direction, got %v`, ids)
	}
	if _, ok := ids["terraform-open-cidr"]; ok {
		t.Fatalf("an egress rule must not also be reported as open ingress, got %v", ids)
	}
}

// The same attribute in the other direction keeps the higher-severity ingress rule.
func TestTerraformOpenCIDRDirectionAttributeIngress(t *testing.T) {
	fs := scan(t, map[string]string{
		"rules.tf": `
resource "aws_security_group_rule" "ssh_in" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
`,
	})
	ids := ruleIDs(fs)
	if _, ok := ids["terraform-open-cidr"]; !ok {
		t.Fatalf(`type = "ingress" must report the open ingress rule, got %v`, ids)
	}
	if _, ok := ids["terraform-open-egress"]; ok {
		t.Fatalf("an ingress rule must not be reported as egress, got %v", ids)
	}
}

// A direction attribute belonging to a NEIGHBOURING rule must not be read: the block walk stops at the
// brace that closes the block the CIDR sits in.
func TestTerraformOpenCIDRDirectionDoesNotLeakAcrossBlocks(t *testing.T) {
	fs := scan(t, map[string]string{
		"rules.tf": `
resource "aws_security_group_rule" "egress_all" {
  type        = "egress"
  cidr_blocks = ["10.0.0.0/8"]
}

resource "aws_security_group_rule" "ssh_in" {
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["0.0.0.0/0"]
}
`,
	})
	ids := ruleIDs(fs)
	if _, ok := ids["terraform-open-cidr"]; !ok {
		t.Fatalf("a rule declaring no direction must keep the ingress reading, got %v", ids)
	}
	if _, ok := ids["terraform-open-egress"]; ok {
		t.Fatalf("the previous block's egress type must not leak into this one, got %v", ids)
	}
}
