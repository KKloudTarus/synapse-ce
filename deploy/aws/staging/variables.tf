variable "aws_region" {
  description = "AWS region. This disposable staging stack is intentionally limited to us-east-1."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "aws_region must be us-east-1 for this staging automation."
  }
}

variable "name" {
  description = "Short lowercase identifier used in all resource names."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}$", var.name))
    error_message = "name must be 3-25 lowercase letters, digits, or hyphens and start with a letter."
  }
}

variable "owner" {
  description = "Individual or team responsible for the disposable environment."
  type        = string

  validation {
    condition     = length(trimspace(var.owner)) > 0 && length(var.owner) <= 128
    error_message = "owner must be a non-empty value of at most 128 characters."
  }
}

variable "cost_center" {
  description = "Billing allocation tag value."
  type        = string

  validation {
    condition     = length(trimspace(var.cost_center)) > 0 && length(var.cost_center) <= 128
    error_message = "cost_center must be a non-empty value of at most 128 characters."
  }
}

variable "expires_at" {
  description = "RFC3339 UTC expiry for this disposable environment; teardown refuses before this time."
  type        = string

  validation {
    condition     = can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.expires_at)) && endswith(var.expires_at, "Z")
    error_message = "expires_at must be an RFC3339 UTC timestamp, for example 2026-09-01T00:00:00Z."
  }
}

variable "additional_tags" {
  description = "Optional non-reserved tags. Reserved lifecycle and ownership tags cannot be overridden."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for key, value in var.additional_tags :
      !contains(["Name", "application", "environment", "managed-by", "owner", "cost-center", "expires-at"], key) && length(trimspace(value)) > 0
    ])
    error_message = "additional_tags may not override reserved tags and values must be non-empty."
  }
}

variable "availability_zones" {
  description = "Exactly three available us-east-1 Availability Zones for EKS and RDS high availability."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]

  validation {
    condition     = length(var.availability_zones) == 3 && length(distinct(var.availability_zones)) == 3 && alltrue([for az in var.availability_zones : startswith(az, "us-east-1")])
    error_message = "availability_zones must contain three distinct us-east-1 Availability Zones."
  }
}

variable "vpc_cidr" {
  description = "CIDR range assigned to the staging VPC."
  type        = string
  default     = "10.83.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR."
  }
}

variable "cluster_version" {
  description = "Supported EKS Kubernetes version approved for the staging environment."
  type        = string
  default     = "1.35"

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+$", var.cluster_version))
    error_message = "cluster_version must use a major.minor Kubernetes version."
  }
}

variable "node_instance_types" {
  description = "Managed Linux worker node instance types."
  type        = list(string)
  default     = ["t3.large"]

  validation {
    condition     = length(var.node_instance_types) > 0
    error_message = "At least one node instance type is required."
  }
}

variable "node_desired_size" {
  description = "Desired managed worker node count."
  type        = number
  default     = 2

  validation {
    condition     = var.node_desired_size >= 1 && var.node_desired_size <= 6
    error_message = "node_desired_size must be between 1 and 6."
  }
}

variable "node_min_size" {
  description = "Minimum managed worker node count."
  type        = number
  default     = 1
}

variable "node_max_size" {
  description = "Maximum managed worker node count."
  type        = number
  default     = 4

  validation {
    condition     = var.node_max_size >= var.node_min_size && var.node_max_size <= 6 && var.node_desired_size >= var.node_min_size && var.node_desired_size <= var.node_max_size
    error_message = "Require 1 <= node_min_size <= node_desired_size <= node_max_size <= 6."
  }
}

variable "db_instance_class" {
  description = "RDS PostgreSQL instance class for staging."
  type        = string
  default     = "db.t4g.medium"

  validation {
    condition     = startswith(var.db_instance_class, "db.")
    error_message = "db_instance_class must be an RDS DB instance class."
  }
}

variable "db_name" {
  description = "Initial PostgreSQL database name."
  type        = string
  default     = "synapse"

  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,62}$", var.db_name))
    error_message = "db_name must start with a lowercase letter and contain only lowercase letters, digits, or underscores."
  }
}

variable "app_service_account_name" {
  description = "Kubernetes service-account name eligible for the application IRSA role."
  type        = string
  default     = "synapse-api"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.app_service_account_name))
    error_message = "app_service_account_name must be a valid DNS-label Kubernetes name."
  }
}

variable "app_namespace" {
  description = "Kubernetes namespace eligible for the application IRSA role."
  type        = string
  default     = "synapse"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.app_namespace))
    error_message = "app_namespace must be a valid DNS-label Kubernetes namespace."
  }
}

variable "cognito_domain_prefix" {
  description = "Globally unique Cognito hosted-UI domain prefix; it must not include a domain suffix."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,62}$", var.cognito_domain_prefix))
    error_message = "cognito_domain_prefix must be 3-63 lowercase letters, digits, or hyphens and start with a letter."
  }
}

variable "cognito_callback_urls" {
  description = "HTTPS application callback URLs registered with Cognito."
  type        = list(string)

  validation {
    condition     = length(var.cognito_callback_urls) > 0 && alltrue([for url in var.cognito_callback_urls : startswith(url, "https://")])
    error_message = "cognito_callback_urls must contain one or more HTTPS URLs."
  }
}

variable "cognito_logout_urls" {
  description = "HTTPS application logout URLs registered with Cognito."
  type        = list(string)

  validation {
    condition     = length(var.cognito_logout_urls) > 0 && alltrue([for url in var.cognito_logout_urls : startswith(url, "https://")])
    error_message = "cognito_logout_urls must contain one or more HTTPS URLs."
  }
}

variable "worker_parent_image" {
  description = "Exact x86_64 AL2023 parent image identifier for EC2 Image Builder: an AMI ID or a version-pinned Image Builder ARN."
  type        = string

  validation {
    condition = can(regex("^ami-[0-9a-f]{8,17}$", var.worker_parent_image)) || can(regex(
      "^arn:[a-z0-9-]+:imagebuilder:us-east-1:(aws|[0-9]{12}):image/[A-Za-z0-9._/-]+/[0-9]+\\.[0-9]+\\.[0-9]+$",
      var.worker_parent_image,
    ))
    error_message = "worker_parent_image must be an exact AMI ID or a version-pinned us-east-1 Image Builder image ARN."
  }
}

variable "worker_release_version" {
  description = "Three-part numeric version used for the worker Image Builder component and recipe."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.worker_release_version))
    error_message = "worker_release_version must be a numeric major.minor.patch version."
  }
}

variable "worker_image_definition_version" {
  description = "Three-part Image Builder component and recipe version; bump whenever package metadata or build controls change."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.worker_image_definition_version))
    error_message = "worker_image_definition_version must be a numeric major.minor.patch version."
  }
}

variable "worker_package_s3_key" {
  description = "S3 object key of the prebuilt worker RPM in the staging evidence bucket."
  type        = string

  validation {
    condition     = length(var.worker_package_s3_key) <= 1024 && can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]*$", var.worker_package_s3_key)) && !strcontains(var.worker_package_s3_key, "..")
    error_message = "worker_package_s3_key must be a canonical non-traversing S3 object key."
  }
}

variable "worker_package_sha256" {
  description = "Lowercase SHA-256 digest of the pinned worker RPM."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.worker_package_sha256))
    error_message = "worker_package_sha256 must contain exactly 64 lowercase hexadecimal characters."
  }
}

variable "worker_trust_anchor_s3_key" {
  description = "S3 object key of the public private-CA certificate trusted by native workers."
  type        = string

  validation {
    condition     = length(var.worker_trust_anchor_s3_key) <= 1024 && can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]*$", var.worker_trust_anchor_s3_key)) && !strcontains(var.worker_trust_anchor_s3_key, "..")
    error_message = "worker_trust_anchor_s3_key must be a canonical non-traversing S3 object key."
  }
}

variable "worker_trust_anchor_sha256" {
  description = "Lowercase SHA-256 digest of the public private-CA certificate trusted by native workers."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.worker_trust_anchor_sha256))
    error_message = "worker_trust_anchor_sha256 must contain exactly 64 lowercase hexadecimal characters."
  }
}

variable "worker_runtime_secret_arn" {
  description = "Governed Secrets Manager ARN containing the native worker runtime configuration."
  type        = string

  validation {
    condition     = can(regex("^arn:[a-z0-9-]+:secretsmanager:us-east-1:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", var.worker_runtime_secret_arn))
    error_message = "worker_runtime_secret_arn must be a Secrets Manager secret ARN in us-east-1."
  }
}

variable "worker_grant_authority_backend_port" {
  description = "Private API pod port targeted by the TLS-terminating egress-grant NLB."
  type        = number
  default     = 8082

  validation {
    condition     = var.worker_grant_authority_backend_port >= 1024 && var.worker_grant_authority_backend_port <= 65535
    error_message = "worker_grant_authority_backend_port must be between 1024 and 65535."
  }
}

variable "worker_image_builder_instance_type" {
  description = "EC2 instance type used only while baking and testing the worker AMI."
  type        = string
  default     = "m6i.xlarge"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*[0-9][a-z0-9-]*\\.[a-z0-9]+$", var.worker_image_builder_instance_type))
    error_message = "worker_image_builder_instance_type must be a valid EC2 instance type."
  }
}

variable "worker_instance_type" {
  description = "EC2 instance type for native execution workers."
  type        = string
  default     = "m6i.xlarge"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*[0-9][a-z0-9-]*\\.[a-z0-9]+$", var.worker_instance_type))
    error_message = "worker_instance_type must be a valid EC2 instance type."
  }
}

variable "worker_root_volume_gib" {
  description = "Encrypted gp3 root-volume size for native execution workers."
  type        = number
  default     = 80

  validation {
    condition     = var.worker_root_volume_gib >= 40 && var.worker_root_volume_gib <= 1024
    error_message = "worker_root_volume_gib must be between 40 and 1024 GiB."
  }
}

variable "worker_desired_size" {
  description = "Desired native execution-worker capacity."
  type        = number
  default     = 1

  validation {
    condition     = var.worker_desired_size >= 1 && var.worker_desired_size <= 8
    error_message = "worker_desired_size must be between 1 and 8."
  }
}

variable "worker_min_size" {
  description = "Minimum native execution-worker capacity."
  type        = number
  default     = 1
}

variable "worker_max_size" {
  description = "Maximum native execution-worker capacity."
  type        = number
  default     = 4

  validation {
    condition     = var.worker_min_size >= 1 && var.worker_min_size <= var.worker_desired_size && var.worker_desired_size <= var.worker_max_size && var.worker_max_size <= 8
    error_message = "Require 1 <= worker_min_size <= worker_desired_size <= worker_max_size <= 8."
  }
}
