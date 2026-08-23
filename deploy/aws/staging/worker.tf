resource "aws_security_group" "worker" {
  name        = "${local.prefix}-execution-worker"
  description = "Private native execution workers; no inbound access"
  vpc_id      = aws_vpc.staging.id

  tags = merge(local.tags, local.worker_tags, { Name = "${local.prefix}-execution-worker" })
}

resource "aws_security_group" "grant_authority_nlb" {
  name        = "${local.prefix}-grant-authority-nlb"
  description = "Private egress-grant NLB reachable only by native execution workers"
  vpc_id      = aws_vpc.staging.id

  tags = merge(local.tags, local.worker_tags, { Name = "${local.prefix}-grant-authority-nlb" })
}

resource "aws_vpc_security_group_ingress_rule" "grant_authority_from_workers" {
  security_group_id            = aws_security_group.grant_authority_nlb.id
  referenced_security_group_id = aws_security_group.worker.id
  from_port                    = 443
  ip_protocol                  = "tcp"
  to_port                      = 443
  description                  = "Machine-authenticated grant requests from native workers"
}

resource "aws_vpc_security_group_egress_rule" "grant_authority_to_nodes" {
  security_group_id            = aws_security_group.grant_authority_nlb.id
  referenced_security_group_id = aws_security_group.nodes.id
  from_port                    = var.worker_grant_authority_backend_port
  ip_protocol                  = "tcp"
  to_port                      = var.worker_grant_authority_backend_port
  description                  = "Grant-authority traffic to EKS pod targets"
}

resource "aws_vpc_security_group_egress_rule" "worker_egress" {
  security_group_id = aws_security_group.worker.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Host egress through NAT; the root-owned broker enforces per-run scope"
}


resource "aws_vpc_security_group_ingress_rule" "postgres_from_workers" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.worker.id
  from_port                    = 5432
  ip_protocol                  = "tcp"
  to_port                      = 5432
  description                  = "PostgreSQL from private native execution workers"
}

resource "aws_security_group" "worker_image_builder" {
  name        = "${local.prefix}-worker-image-builder"
  description = "Private EC2 Image Builder instances; no inbound access"
  vpc_id      = aws_vpc.staging.id

  egress {
    description = "Reach package repositories and AWS APIs through NAT"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, local.worker_tags, {
    Name      = "${local.prefix}-worker-image-builder"
    component = "image-builder"
  })
}

resource "aws_imagebuilder_component" "worker" {
  name        = "${local.prefix}-worker"
  description = "Install and validate the pinned Synapse native worker package"
  platform    = "Linux"
  version     = var.worker_image_definition_version
  kms_key_id  = aws_kms_key.staging.arn
  tags        = merge(local.tags, local.worker_tags, { component = "image-builder" })

  data = yamlencode({
    name          = "InstallSynapseWorker"
    description   = "Install a digest-pinned worker RPM and prove exact-runner startup conformance"
    schemaVersion = 1.0
    phases = [
      {
        name = "build"
        steps = [
          {
            name   = "DownloadPinnedPackage"
            action = "ExecuteBash"
            inputs = {
              commands = [
                "aws s3 cp 's3://${aws_s3_bucket.evidence.id}/${var.worker_package_s3_key}' /tmp/synapse-worker.rpm",
                "printf '%s  %s\\n' '${var.worker_package_sha256}' /tmp/synapse-worker.rpm | sha256sum -c -",
              ]
            }
          },
          {
            name   = "InstallWorker"
            action = "ExecuteBash"
            inputs = {
              commands = [
                "dnf install -y /tmp/synapse-worker.rpm",
                "rm -f /tmp/synapse-worker.rpm",
                "systemctl daemon-reload",
              ]
            }
          },
        ]
      },
      {
        name = "validate"
        steps = [
          {
            name   = "InstallPrivateTrustAnchor"
            action = "ExecuteBash"
            inputs = {
              commands = [
                "aws s3 cp 's3://${aws_s3_bucket.evidence.id}/${var.worker_trust_anchor_s3_key}' /etc/pki/ca-trust/source/anchors/synapse-private-ca.pem",
                "printf '%s  %s\\n' '${var.worker_trust_anchor_sha256}' /etc/pki/ca-trust/source/anchors/synapse-private-ca.pem | sha256sum -c -",
                "update-ca-trust extract",
                "openssl verify -CAfile /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/pki/ca-trust/source/anchors/synapse-private-ca.pem",
                "install -d -o root -g synapse-worker -m 0750 /etc/synapse/database-ca",
                "curl --fail --silent --show-error --proto '=https' --tlsv1.2 'https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem' --output /etc/synapse/database-ca/ca.crt",
                "chown root:synapse-worker /etc/synapse/database-ca/ca.crt",
                "chmod 0640 /etc/synapse/database-ca/ca.crt",
                "openssl crl2pkcs7 -nocrl -certfile /etc/synapse/database-ca/ca.crt | openssl pkcs7 -print_certs -noout >/dev/null",
              ]
            }
          },
          {
            name   = "ValidatePackageAndUnits"
            action = "ExecuteBash"
            inputs = {
              commands = [
                "rpm -q synapse-worker",
                "systemd-analyze verify /usr/lib/systemd/system/synapse-worker-runtime-env.service /usr/lib/systemd/system/synapse-egress-broker.service /usr/lib/systemd/system/synapse-worker-sandbox-check.service /usr/lib/systemd/system/synapse-worker.service",
                "test -x /opt/synapse/synapse-worker",
                "test -x /opt/synapse/synapse-egress-broker",
                "test -x /opt/synapse/synapse-sandbox-check",
                "grep -Fq 'User=root' /usr/lib/systemd/system/synapse-egress-broker.service",
                "grep -Fq 'Group=synapse-worker' /usr/lib/systemd/system/synapse-egress-broker.service",
                "grep -Fq 'RuntimeDirectory=synapse-egress-broker netns' /usr/lib/systemd/system/synapse-egress-broker.service",
                "grep -Fq 'RuntimeDirectoryMode=0750' /usr/lib/systemd/system/synapse-egress-broker.service",
                "grep -Fq 'CapabilityBoundingSet=CAP_CHOWN CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_PTRACE' /usr/lib/systemd/system/synapse-egress-broker.service",
                "grep -Fq 'CapabilityBoundingSet=' /usr/lib/systemd/system/synapse-worker.service",
                "grep -Fq 'Delegate=yes' /usr/lib/systemd/system/synapse-worker-sandbox-check.service",
                "grep -Fq 'CapabilityBoundingSet=' /usr/lib/systemd/system/synapse-worker-sandbox-check.service",
              ]
            }
          },
          {
            name   = "ValidateExactSandboxRunner"
            action = "ExecuteBash"
            inputs = {
              commands = [
                "systemd-run --wait --collect --unit=synapse-image-sandbox-check --property=User=synapse-worker --property=Group=synapse-worker --property=Delegate=yes --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= --property=PrivateTmp=yes --property=PrivateDevices=yes /opt/synapse/synapse-sandbox-check -mode=full -strict",
              ]
            }
          },
        ]
      },
    ]
  })
}

resource "aws_imagebuilder_image_recipe" "worker" {
  name         = "${local.prefix}-worker"
  description  = "Hardened AL2023 Synapse native execution worker"
  parent_image = var.worker_parent_image
  version      = var.worker_image_definition_version
  tags         = merge(local.tags, local.worker_tags, { component = "image-builder" })

  component {
    component_arn = aws_imagebuilder_component.worker.arn
  }

  systems_manager_agent {
    uninstall_after_build = false
  }
}

resource "aws_imagebuilder_infrastructure_configuration" "worker" {
  name                          = "${local.prefix}-worker"
  description                   = "Private Image Builder host for the Synapse worker AMI"
  instance_profile_name         = aws_iam_instance_profile.worker_image_builder.name
  instance_types                = [var.worker_image_builder_instance_type]
  security_group_ids            = [aws_security_group.worker_image_builder.id]
  subnet_id                     = aws_subnet.private[var.availability_zones[0]].id
  terminate_instance_on_failure = true
  tags                          = merge(local.tags, local.worker_tags, { component = "image-builder" })
  resource_tags = {
    for key, value in merge(local.tags, local.worker_tags, { component = "image-builder" }) :
    key => value if key != "Name"
  }

  instance_metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}

resource "aws_imagebuilder_distribution_configuration" "worker" {
  name        = "${local.prefix}-worker"
  description = "Publish the encrypted worker AMI only in the staging region"
  tags        = merge(local.tags, local.worker_tags, { component = "image-builder" })

  distribution {
    region = var.aws_region

    ami_distribution_configuration {
      name       = "${local.prefix}-worker-{{ imagebuilder:buildDate }}"
      kms_key_id = aws_kms_key.staging.arn
      ami_tags   = merge(local.tags, local.worker_tags)
    }
  }
}

resource "aws_imagebuilder_image" "worker" {
  image_recipe_arn                 = aws_imagebuilder_image_recipe.worker.arn
  infrastructure_configuration_arn = aws_imagebuilder_infrastructure_configuration.worker.arn
  distribution_configuration_arn   = aws_imagebuilder_distribution_configuration.worker.arn
  enhanced_image_metadata_enabled  = true
  tags                             = merge(local.tags, local.worker_tags, { component = "image-builder" })

  image_tests_configuration {
    image_tests_enabled = true
    timeout_minutes     = 60
  }
}

locals {
  worker_ami_id = tolist(aws_imagebuilder_image.worker.output_resources[0].amis)[0].image
}

resource "aws_launch_template" "worker" {
  name_prefix            = "${local.prefix}-worker-"
  description            = "Private non-root Synapse execution workers"
  image_id               = local.worker_ami_id
  instance_type          = var.worker_instance_type
  update_default_version = true

  iam_instance_profile {
    name = aws_iam_instance_profile.worker.name
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
    instance_metadata_tags      = "disabled"
  }

  network_interfaces {
    associate_public_ip_address = false
    delete_on_termination       = true
    security_groups             = [aws_security_group.worker.id]
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.staging.arn
      volume_size           = var.worker_root_volume_gib
      volume_type           = "gp3"
    }
  }

  user_data = base64encode(<<-USERDATA
    #!/bin/bash
    set -euo pipefail
    install -d -o root -g synapse-worker -m 0750 /etc/synapse-worker
    cat >/etc/synapse-worker/bootstrap.env <<'BOOTSTRAP'
    AWS_REGION=${var.aws_region}
    SYNAPSE_WORKER_SECRET_ID=${var.worker_runtime_secret_arn}
    BOOTSTRAP
    chown root:root /etc/synapse-worker/bootstrap.env
    chmod 0600 /etc/synapse-worker/bootstrap.env
    systemctl enable --now synapse-worker.service
  USERDATA
  )

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, local.worker_tags)
  }

  tag_specifications {
    resource_type = "volume"
    tags          = merge(local.tags, local.worker_tags)
  }

  tags = merge(local.tags, local.worker_tags)
}

resource "aws_autoscaling_group" "worker" {
  name                      = "${local.prefix}-execution-worker"
  desired_capacity          = var.worker_desired_size
  min_size                  = var.worker_min_size
  max_size                  = var.worker_max_size
  health_check_type         = "EC2"
  health_check_grace_period = 300
  vpc_zone_identifier       = [for subnet in aws_subnet.worker : subnet.id]

  launch_template {
    id      = aws_launch_template.worker.id
    version = tostring(aws_launch_template.worker.latest_version)
  }

  instance_refresh {
    strategy = "Rolling"

    preferences {
      auto_rollback                = true
      instance_warmup              = 300
      min_healthy_percentage       = 50
      skip_matching                = true
      scale_in_protected_instances = "Ignore"
      standby_instances            = "Ignore"
    }
  }

  dynamic "tag" {
    for_each = merge(local.tags, local.worker_tags)
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}
