package aws

// leastPrivilegeActions lists the read-only AWS operations used by the connector.
// Grant organizations:ListAccounts and sts:AssumeRole to the organization reader.
// Grant the remaining actions to the per-account role referenced by RoleARNTemplate.
var leastPrivilegeActions = [...]string{
	"organizations:DescribeOrganization",
	"organizations:ListAccounts",
	"sts:AssumeRole",
	"ec2:DescribeRegions",
	"ec2:DescribeInstances",
	"ec2:DescribeSecurityGroups",
	"ec2:DescribeRouteTables",
	"ec2:DescribeNetworkAcls",
	"s3:ListAllMyBuckets",
	"s3:GetBucketPolicyStatus",
	"s3:GetEncryptionConfiguration",
	"iam:ListRoles",
	"iam:ListUsers",
	"iam:ListRolePolicies",
	"iam:GetRolePolicy",
	"iam:ListAttachedRolePolicies",
	"iam:ListUserPolicies",
	"iam:GetUserPolicy",
	"iam:ListAttachedUserPolicies",
	"iam:GetPolicy",
	"iam:GetPolicyVersion",
}

// LeastPrivilegeActions returns a copy of the read-only AWS permission manifest.
func LeastPrivilegeActions() []string {
	return append([]string(nil), leastPrivilegeActions[:]...)
}
