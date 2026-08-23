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

output "worker_ami_id" {
  description = "Digest-pinned and conformance-tested native worker AMI ID."
  value       = local.worker_ami_id
}

output "worker_image_arn" {
  description = "EC2 Image Builder image ARN used by the worker launch template."
  value       = aws_imagebuilder_image.worker.arn
}

output "worker_launch_template_id" {
  description = "Private native worker launch-template identifier."
  value       = aws_launch_template.worker.id
}

output "worker_autoscaling_group_name" {
  description = "Native execution-worker Auto Scaling Group name."
  value       = aws_autoscaling_group.worker.name
}

output "worker_instance_profile_arn" {
  description = "Dedicated native worker instance-profile ARN."
  value       = aws_iam_instance_profile.worker.arn
}

output "worker_security_group_id" {
  description = "Dedicated native worker security-group identifier."
  value       = aws_security_group.worker.id
}

output "worker_grant_authority_nlb_security_group_id" {
  description = "Frontend security group for the private TLS egress-grant NLB; supply this to the Helm Service annotation."
  value       = aws_security_group.grant_authority_nlb.id
}

output "worker_grant_authority_nlb_private_ipv4_addresses" {
  description = "Fixed addresses reserved in dedicated NLB subnets; assign them to the authority NLB and admit them as /32s in NetworkPolicy."
  value       = local.grant_nlb_private_addresses
}

output "worker_grant_authority_nlb_subnet_ids" {
  description = "Dedicated private subnets for the internal egress-grant NLB; supply them to the Helm Service annotation."
  value       = [for subnet in aws_subnet.grant_nlb : subnet.id]
}

output "worker_private_subnet_ids" {
  description = "Dedicated private subnets used only by the native worker Auto Scaling Group."
  value       = [for subnet in aws_subnet.worker : subnet.id]
}

output "worker_private_subnet_cidrs" {
  description = "Dedicated native-worker subnet CIDRs; these are not used as authority admission ranges."
  value       = local.worker_subnet_cidrs
}
