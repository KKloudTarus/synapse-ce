locals {
  prefix = "${var.name}-staging"

  tags = merge(var.additional_tags, {
    Name        = local.prefix
    application = "synapse"
    environment = "staging"
    managed-by  = "terraform"
    owner       = var.owner
    cost-center = var.cost_center
    expires-at  = var.expires_at
    epic        = "583"
    disposable  = "true"
  })

  private_subnet_cidrs        = [for index in range(length(var.availability_zones)) : cidrsubnet(var.vpc_cidr, 4, index)]
  public_subnet_cidrs         = [for index in range(length(var.availability_zones)) : cidrsubnet(var.vpc_cidr, 4, index + 8)]
  worker_subnet_cidrs         = [for index in range(length(var.availability_zones)) : cidrsubnet(var.vpc_cidr, 8, index + 240)]
  grant_nlb_subnet_cidrs      = [for index in range(length(var.availability_zones)) : cidrsubnet(var.vpc_cidr, 12, index + 3888)]
  grant_nlb_private_addresses = [for cidr in local.grant_nlb_subnet_cidrs : cidrhost(cidr, 4)]

  worker_tags = {
    component      = "execution-worker"
    execution-tier = "native-ec2"
    issues         = "589-591"
  }
}
