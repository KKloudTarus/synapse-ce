output "eks_cluster_name" {
  description = "EKS cluster name."
  value       = aws_eks_cluster.staging.name
}

output "eks_cluster_endpoint" {
  description = "Private EKS API endpoint; reachable only from within the VPC."
  value       = aws_eks_cluster.staging.endpoint
}

output "ecr_repository_url" {
  description = "Private ECR repository URL for staging images."
  value       = aws_ecr_repository.app.repository_url
}

output "evidence_bucket_name" {
  description = "Private, versioned, KMS-encrypted S3 evidence bucket name."
  value       = aws_s3_bucket.evidence.id
}

output "database_endpoint" {
  description = "Private PostgreSQL host and port."
  value       = aws_db_instance.postgres.endpoint
}

output "database_master_secret_arn" {
  description = "Secrets Manager ARN for the RDS-managed credentials; grant only the workload role access."
  value       = aws_db_instance.postgres.master_user_secret[0].secret_arn
  sensitive   = true
}

output "app_irsa_role_arn" {
  description = "IRSA role limited to the application service account, evidence bucket, and database secret."
  value       = aws_iam_role.app_irsa.arn
}

output "cognito_user_pool_id" {
  description = "Cognito user-pool identifier."
  value       = aws_cognito_user_pool.staging.id
}

output "cognito_client_id" {
  description = "Cognito OAuth client ID. The generated client secret is intentionally not output."
  value       = aws_cognito_user_pool_client.staging.id
}

output "cognito_issuer_url" {
  description = "OIDC issuer URL for token validation."
  value       = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.staging.id}"
}

output "cognito_hosted_ui_domain" {
  description = "Hosted-UI domain endpoint."
  value       = "https://${aws_cognito_user_pool_domain.staging.domain}.auth.${var.aws_region}.amazoncognito.com"
}
