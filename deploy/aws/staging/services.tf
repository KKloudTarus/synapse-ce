resource "aws_ecr_repository" "app" {
  name                 = "${local.prefix}/synapse"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.staging.arn
  }

  tags = merge(local.tags, { Name = "${local.prefix}-synapse" })
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Retain only the ten newest staging images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_s3_bucket" "evidence" {
  bucket_prefix = "${local.prefix}-evidence-"
  force_destroy = true

  tags = merge(local.tags, { Name = "${local.prefix}-evidence" })
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.staging.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    id     = "expire-disposable-evidence"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_db_subnet_group" "postgres" {
  name       = "${local.prefix}-postgres"
  subnet_ids = [for subnet in aws_subnet.private : subnet.id]

  tags = merge(local.tags, { Name = "${local.prefix}-postgres" })
}

resource "aws_db_instance" "postgres" {
  identifier                      = "${local.prefix}-postgres"
  allocated_storage               = 50
  max_allocated_storage           = 100
  storage_type                    = "gp3"
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.staging.arn
  engine                          = "postgres"
  instance_class                  = var.db_instance_class
  db_name                         = var.db_name
  username                        = "synapse_admin"
  manage_master_user_password     = true
  master_user_secret_kms_key_id   = aws_kms_key.staging.arn
  port                            = 5432
  multi_az                        = true
  publicly_accessible             = false
  db_subnet_group_name            = aws_db_subnet_group.postgres.name
  vpc_security_group_ids          = [aws_security_group.database.id]
  backup_retention_period         = 7
  backup_window                   = "03:00-03:30"
  maintenance_window              = "sun:04:00-sun:04:30"
  auto_minor_version_upgrade      = true
  deletion_protection             = false
  skip_final_snapshot             = true
  copy_tags_to_snapshot           = true
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.staging.arn
  monitoring_interval             = 0
  apply_immediately               = false

  tags = merge(local.tags, { Name = "${local.prefix}-postgres" })
}

resource "aws_cognito_user_pool" "staging" {
  name                     = "${local.prefix}-users"
  auto_verified_attributes = ["email"]
  username_attributes      = ["email"]
  mfa_configuration        = "OPTIONAL"

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 3
  }

  software_token_mfa_configuration {
    enabled = true
  }

  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }

  schema {
    attribute_data_type = "String"
    name                = "email"
    required            = true
    mutable             = false

    string_attribute_constraints {
      min_length = 5
      max_length = 320
    }
  }

  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
  }

  tags = merge(local.tags, { Name = "${local.prefix}-users" })
}

resource "aws_cognito_user_pool_domain" "staging" {
  domain       = var.cognito_domain_prefix
  user_pool_id = aws_cognito_user_pool.staging.id
}

resource "aws_cognito_user_pool_client" "staging" {
  name                                 = "${local.prefix}-web"
  user_pool_id                         = aws_cognito_user_pool.staging.id
  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["email", "openid", "profile"]
  callback_urls                        = var.cognito_callback_urls
  logout_urls                          = var.cognito_logout_urls
  supported_identity_providers         = ["COGNITO"]
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
  access_token_validity                = 1
  id_token_validity                    = 1
  refresh_token_validity               = 1
  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }
}

resource "aws_cognito_user_group" "administrators" {
  name         = "administrators"
  user_pool_id = aws_cognito_user_pool.staging.id
  description  = "Staging environment administrators"
  precedence   = 1
}

resource "aws_cognito_user_group" "analysts" {
  name         = "analysts"
  user_pool_id = aws_cognito_user_pool.staging.id
  description  = "Staging environment assessment analysts"
  precedence   = 10
}

resource "aws_cognito_user_group" "readers" {
  name         = "readers"
  user_pool_id = aws_cognito_user_pool.staging.id
  description  = "Staging environment read-only users"
  precedence   = 20
}
