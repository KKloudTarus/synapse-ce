data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "selected" {
  state = "available"
}

data "aws_iam_policy_document" "staging_kms" {
  statement {
    sid       = "EnableAccountIAMPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowAutoScalingEncryptedVolumes"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
    }
  }

  statement {
    sid       = "AllowAutoScalingGrantCreation"
    effect    = "Allow"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

resource "aws_kms_key" "staging" {
  description             = "Encryption key for ${local.prefix} data services"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.staging_kms.json

  tags = merge(local.tags, { Name = "${local.prefix}-data" })
}

resource "aws_kms_alias" "staging" {
  name          = "alias/${local.prefix}-data"
  target_key_id = aws_kms_key.staging.key_id
}

resource "aws_vpc" "staging" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.tags, { Name = "${local.prefix}-vpc" })
}

resource "aws_internet_gateway" "staging" {
  vpc_id = aws_vpc.staging.id

  tags = merge(local.tags, { Name = "${local.prefix}-igw" })
}

resource "aws_subnet" "public" {
  for_each = toset(var.availability_zones)

  vpc_id                  = aws_vpc.staging.id
  availability_zone       = each.value
  cidr_block              = local.public_subnet_cidrs[index(var.availability_zones, each.value)]
  map_public_ip_on_launch = false

  tags = merge(local.tags, {
    Name                     = "${local.prefix}-public-${each.value}"
    "kubernetes.io/role/elb" = "1"
  })
}

resource "aws_subnet" "private" {
  for_each = toset(var.availability_zones)

  vpc_id            = aws_vpc.staging.id
  availability_zone = each.value
  cidr_block        = local.private_subnet_cidrs[index(var.availability_zones, each.value)]

  tags = merge(local.tags, {
    Name                              = "${local.prefix}-private-${each.value}"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

resource "aws_subnet" "worker" {
  for_each = toset(var.availability_zones)

  vpc_id            = aws_vpc.staging.id
  availability_zone = each.value
  cidr_block        = local.worker_subnet_cidrs[index(var.availability_zones, each.value)]

  tags = merge(local.tags, local.worker_tags, {
    Name = "${local.prefix}-worker-${each.value}"
  })
}

resource "aws_subnet" "grant_nlb" {
  for_each = toset(var.availability_zones)

  vpc_id            = aws_vpc.staging.id
  availability_zone = each.value
  cidr_block        = local.grant_nlb_subnet_cidrs[index(var.availability_zones, each.value)]

  tags = merge(local.tags, local.worker_tags, {
    Name                              = "${local.prefix}-grant-nlb-${each.value}"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = merge(local.tags, { Name = "${local.prefix}-nat" })
}

resource "aws_nat_gateway" "staging" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[var.availability_zones[0]].id

  depends_on = [aws_internet_gateway.staging]
  tags       = merge(local.tags, { Name = "${local.prefix}-nat" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.staging.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.staging.id
  }

  tags = merge(local.tags, { Name = "${local.prefix}-public" })
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.staging.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.staging.id
  }

  tags = merge(local.tags, { Name = "${local.prefix}-private" })
}

resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "worker" {
  for_each       = aws_subnet.worker
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "grant_nlb" {
  for_each       = aws_subnet.grant_nlb
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "cluster" {
  name        = "${local.prefix}-eks-control-plane"
  description = "Restricts EKS control-plane access to managed nodes"
  vpc_id      = aws_vpc.staging.id

  tags = merge(local.tags, { Name = "${local.prefix}-eks-control-plane" })
}

resource "aws_security_group" "nodes" {
  name        = "${local.prefix}-eks-nodes"
  description = "Restricts managed EKS Linux node traffic"
  vpc_id      = aws_vpc.staging.id

  egress {
    description = "Allow nodes to reach AWS APIs and package registries through NAT"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.prefix}-eks-nodes" })
}

resource "aws_vpc_security_group_ingress_rule" "cluster_from_nodes" {
  security_group_id            = aws_security_group.cluster.id
  referenced_security_group_id = aws_security_group.nodes.id
  from_port                    = 443
  ip_protocol                  = "tcp"
  to_port                      = 443
  description                  = "Kubelet and pod traffic to private EKS API"
}

resource "aws_vpc_security_group_ingress_rule" "nodes_from_cluster" {
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.cluster.id
  from_port                    = 1025
  ip_protocol                  = "tcp"
  to_port                      = 65535
  description                  = "Control plane to kubelet and webhook ports"
}

resource "aws_vpc_security_group_ingress_rule" "nodes_self" {
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "-1"
  description                  = "Node-to-node and pod overlay traffic"
}

resource "aws_security_group" "database" {
  name        = "${local.prefix}-postgres"
  description = "Restricts PostgreSQL to application and execution tiers"
  vpc_id      = aws_vpc.staging.id

  tags = merge(local.tags, { Name = "${local.prefix}-postgres" })
}

resource "aws_vpc_security_group_ingress_rule" "postgres_from_nodes" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.nodes.id
  from_port                    = 5432
  ip_protocol                  = "tcp"
  to_port                      = 5432
  description                  = "PostgreSQL from application pods on EKS nodes"
}
