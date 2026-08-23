# Terraform state handling

This configuration declares a partial S3 backend. Bootstrap a dedicated, encrypted Terraform-state bucket and DynamoDB lock table outside this disposable stack, with restricted access for the deployment identity only. Do not use the evidence bucket, local state, a personal bucket, or a bucket created by this configuration for state.

Copy `backend.hcl.example` to an ignored `backend.hcl`, replace only the placeholders with governed backend resource names, and initialize with the wrapper:

```bash
./scripts/status.sh --backend-config backend.hcl --var-file staging.tfvars
```

Use an ignored `staging.tfvars` file for non-secret deployment inputs. Never put AWS credentials, database credentials, Cognito client secrets, account IDs, or the generated `backend.hcl` in version control. Authenticate AWS through the approved workload identity or AWS credential chain instead.

The remote state reveals infrastructure metadata and can contain provider-managed sensitive values. Enable S3 versioning, SSE-KMS, public-access blocks, access logging, least-privilege bucket policies, DynamoDB point-in-time recovery, and a recovery process in the separately managed state backend. Limit state reads to Terraform operators; application workloads must not receive state access.

The wrappers initialize the configured remote backend but never create a backend. `provision.sh` refuses to apply without an explicit confirmation. `teardown.sh` also refuses to destroy until the supplied `expires_at` has passed and a second explicit confirmation is supplied.

## Private worker grant authority

Terraform places the native Auto Scaling Group in dedicated private worker subnets and creates a dedicated frontend security group for the internal egress-grant NLB. Its only ingress rule references the native worker security group on TCP/443; it does not admit the shared private-subnet CIDRs. The NLB may forward only to the API pod port configured by `worker_grant_authority_backend_port`.

Before installing the production chart:

1. Provision or select an ACM certificate whose private DNS name workers can resolve and validate. Certificate issuance and private Route 53 ownership remain governed inputs outside this disposable stack.
2. Set the chart's `service.beta.kubernetes.io/aws-load-balancer-security-groups` annotation to `worker_grant_authority_nlb_security_group_id`.
3. Set `service.beta.kubernetes.io/aws-load-balancer-subnets` to the comma-separated `worker_grant_authority_nlb_subnet_ids` output, set `service.beta.kubernetes.io/aws-load-balancer-private-ipv4-addresses` to `worker_grant_authority_nlb_private_ipv4_addresses`, and set `networkPolicySourceCIDRs` to the dedicated grant-NLB subnet CIDRs.
4. Set the ACM certificate ARN annotation and keep the NLB type `external`, scheme `internal`, target type `ip`, and backend-rule management enabled.
5. After AWS Load Balancer Controller creates the NLB, create a private Route 53 alias for the certificate name and place that HTTPS URL plus the dedicated machine token in the governed worker runtime secret. Do not put either token, signing seed, or secret payload in Terraform inputs or state.

The dedicated NLB subnet CIDRs make pod NetworkPolicy independent of client-source rewriting without admitting EKS-node or worker subnets. The frontend security group is the worker-identity boundary; NetworkPolicy admits only the dedicated NLB subnets to the machine listener. Verify both controls on EKS before allowing production claims.

Set `worker_release_version` to the packaged application version and use a distinct `worker_image_definition_version` for the immutable Image Builder component/recipe definition. Bump the image-definition version whenever package metadata or build controls change; AWS does not permit overwriting a published component version.

The worker AMI build also requires the public certificate for that private CA as a KMS-encrypted S3 object. Set `worker_trust_anchor_s3_key` and `worker_trust_anchor_sha256` to its exact object key and digest. Image Builder verifies the digest, installs the certificate into the AL2023 system trust store, and validates the resulting bundle. Never upload the CA private key or server private key.
