# Terraform state handling

This configuration declares a partial S3 backend. Bootstrap a dedicated, encrypted Terraform-state bucket and DynamoDB lock table outside this disposable stack, with restricted access for the deployment identity only. Do not use the evidence bucket, local state, a personal bucket, or a bucket created by this configuration for state.

Copy `backend.hcl.example` to an ignored `backend.hcl`, replace only the placeholders with governed backend resource names, and initialize with the wrapper:

```bash
./scripts/status.sh --backend-config backend.hcl --var-file staging.tfvars
```

Use an ignored `staging.tfvars` file for non-secret deployment inputs. Never put AWS credentials, database credentials, Cognito client secrets, account IDs, or the generated `backend.hcl` in version control. Authenticate AWS through the approved workload identity or AWS credential chain instead.

The remote state reveals infrastructure metadata and can contain provider-managed sensitive values. Enable S3 versioning, SSE-KMS, public-access blocks, access logging, least-privilege bucket policies, DynamoDB point-in-time recovery, and a recovery process in the separately managed state backend. Limit state reads to Terraform operators; application workloads must not receive state access.

The wrappers initialize the configured remote backend but never create a backend. `provision.sh` refuses to apply without an explicit confirmation. `teardown.sh` also refuses to destroy until the supplied `expires_at` has passed and a second explicit confirmation is supplied.
