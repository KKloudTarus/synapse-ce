# Cloud posture connectors

Synapse can enumerate live AWS, Azure, and Google Cloud state through read-only connectors. CSPM is disabled by default.

```env
SYNAPSE_CSPM_ENABLED=true
SYNAPSE_CSPM_PROVIDERS=aws,azure,gcp
SYNAPSE_CSPM_RATE=0
SYNAPSE_CSPM_HELPER_BIN=/opt/synapse/bin/synapse-cspm
SYNAPSE_TOOL_HASHES=synapse-cspm=<sha256>
# Include identity/token plus every selected provider control-plane endpoint.
SYNAPSE_CSPM_EGRESS_HOSTS=aws=organizations.us-east-1.amazonaws.com,aws=sts.us-east-1.amazonaws.com,aws=ec2.us-east-1.amazonaws.com,aws=s3.us-east-1.amazonaws.com,aws=iam.amazonaws.com,azure=login.microsoftonline.com,azure=management.azure.com,azure=graph.microsoft.com,gcp=oauth2.googleapis.com,gcp=cloudresourcemanager.googleapis.com,gcp=compute.googleapis.com,gcp=storage.googleapis.com,gcp=iam.googleapis.com
SYNAPSE_FLEET_ASSETS_ENABLED=true
```

`SYNAPSE_CSPM_RATE=0` selects the provider default. A positive value from 1 through 100 caps requests per second. CSPM requires PostgreSQL, `synapse-worker`, fleet assets, sandboxing, and kernel egress enforcement. The API only validates and enqueues a run; the worker requires an absolute helper path plus an authoritative SHA-256 in `SYNAPSE_TOOL_HASHES`, then launches the pinned `synapse-cspm` helper inside bubblewrap with seccomp, dropped capabilities, cgroup bounds, a curated read-only root, and a default-deny provider-host network namespace. Provider SDKs do not run in the API or worker process. Store credentials through the engagement credential vault and submit only `credential_ref`; credential values must not appear in API requests, queue payloads, logs, evidence, artifacts, or model context.

## Least privilege

Prefer workload identity, federation, or short-lived role assumption. The connector observes state and never calls mutation APIs.

### AWS

Grant `organizations:DescribeOrganization`, `organizations:ListAccounts`, `sts:AssumeRole`, and the read-only actions listed by the connector permission manifest for EC2 regions/instances/network paths, S3 bucket posture, and IAM users/roles/policies/last-use. For organizations, permit `sts:AssumeRole` only into the named inventory role in member accounts. Denied organization, account, or resource-category access is reported as a coverage gap.

### Azure

Use workload identity federation where possible. Assign `Reader` and Azure Resource Graph read access on each scanned subscription or management group. RBAC posture needs role-assignment and role-definition reads; storage exposure needs Blob container data-plane read access. A subscription, descendant, or category that the principal cannot read is a coverage gap.

### Google Cloud

Use Workload Identity Federation or service-account impersonation where possible. Grant project/folder/organization browser access, Compute Viewer, Storage bucket metadata/IAM/ACL reads, and IAM service-account reads. Allow `oauth2.googleapis.com` for OAuth token refresh in addition to the selected Google Cloud control-plane hosts. Token refresh remains inside the sandbox's default-deny egress boundary and is routed through the same parent-side per-operation authorization callback as provider API requests. Folder traversal, bucket PAP/IAM/ACL posture, and static route/firewall reachability are bounded; inaccessible descendants or ambiguous policy facts are coverage gaps.

## API lifecycle

`POST /api/v1/engagements/{id}/cspm/runs` returns `202 Accepted` with a durable run ID. Poll `GET /api/v1/engagements/{id}/cspm/runs/{run_id}` until `succeeded`, `partial`, `failed`, or `cancelled`. Every normalized target snapshot is sealed into the engagement evidence chain before assets and findings are published.

Canonical scope identities are `aws:organizations/o-*`, `azure:subscriptions/*`, `azure:managementGroups/*`, `gcp:projects/*`, `gcp:folders/*`, and `gcp:organizations/*`. Engagement scope matching remains exact.

## Coverage semantics

Connectors paginate all supported list operations and enforce request, page, resource, and time bounds. Missing permissions, throttling exhaustion, an unreachable child account, or a reached bound makes the run partial. Synapse does not translate partial inventory into a clean account.

Supported checks cover public storage, publicly reachable compute, wildcard identity grants, unused high-privilege identities when last-use evidence exists, explicitly disabled encryption, and public network paths to sensitive resources. Unknown provider facts do not produce secure conclusions.

When a file-derived expectation has a stable provider resource identity, Synapse compares `public` and `encrypted` controls to live state. A mismatch is a `cloud-iac-live-drift` finding. Dynamic or unmatched identities are coverage gaps, not drift findings.

Remediation is out of scope. Any future cloud change must use a separate governed response action.
