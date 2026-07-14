package misconfig

import (
	"bytes"
	"testing"
)

func TestCloudFormationDepthBombSkipped(t *testing.T) {
	// A compact block-nesting bomb ("- - - ... x", one line, linear bytes) would overflow yaml.v3's
	// recursive parser. The pre-decode depth guard must make it a per-file skip (nil), never a crash.
	bomb := append(bytes.Repeat([]byte("- "), 300000), 'x')
	if got := scanCloudFormation("bomb.yaml", bomb); got != nil {
		t.Fatalf("compact-nesting bomb should be skipped, got %d findings", len(got))
	}
}

func TestCloudFormationActionServiceWildcard(t *testing.T) {
	// A service-scoped action wildcard ("s3:*") is flagged even though the resource ARN ending in "*" is
	// legitimate scoping and on its own is not.
	tmpl := `Resources:
  P:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "s3:*"
            Resource: "arn:aws:s3:::bucket/*"
`
	got := ruleIDs(scan(t, map[string]string{"p.yaml": tmpl}))
	if _, ok := got["cloudformation-iam-wildcard"]; !ok {
		t.Errorf("service-scoped action wildcard s3:* should be flagged, got %v", keys(got))
	}
}

func TestCloudFormationInsecure(t *testing.T) {
	tmpl := `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Data:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres
      StorageEncrypted: false
      MasterUserPassword: hunter2super
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: open
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
  Policy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: broad
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
`
	got := ruleIDs(scan(t, map[string]string{"stack.yaml": tmpl}))
	for _, want := range []string{
		"cloudformation-public-bucket-acl",
		"cloudformation-s3-no-encryption",
		"cloudformation-rds-unencrypted",
		"cloudformation-plaintext-secret",
		"cloudformation-open-security-group",
		"cloudformation-iam-wildcard",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected CloudFormation rule %q, got %v", want, keys(got))
		}
	}
}

func TestCloudFormationSecure(t *testing.T) {
	// A hardened stack: encrypted + private bucket, encrypted DB with a dynamic-reference secret, scoped
	// ingress, and a scoped IAM statement.
	tmpl := `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Data:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      LoggingConfiguration:
        DestinationBucketName: log-bucket
      VersioningConfiguration:
        Status: Enabled
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres
      StorageEncrypted: true
      DeletionProtection: true
      MasterUserPassword: "{{resolve:secretsmanager:db:SecretString:password}}"
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: scoped
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 10.0.0.0/8
  Policy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: scoped
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: s3:GetObject
            Resource: arn:aws:s3:::data/*
`
	if got := scan(t, map[string]string{"stack.yaml": tmpl}); len(got) != 0 {
		t.Errorf("hardened CloudFormation should yield no findings, got %+v", got)
	}
}

func TestCloudFormationJSON(t *testing.T) {
	// JSON is valid YAML, so the same walker handles a JSON template. Also confirms the .json content sniff.
	tmpl := `{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Data": { "Type": "AWS::S3::Bucket", "Properties": { "AccessControl": "PublicReadWrite" } }
  }
}`
	got := ruleIDs(scan(t, map[string]string{"stack.json": tmpl}))
	if _, ok := got["cloudformation-public-bucket-acl"]; !ok {
		t.Errorf("JSON template public ACL not flagged, got %v", keys(got))
	}
}

func TestCloudFormationIntrinsicsTolerated(t *testing.T) {
	// A value supplied via a short-form intrinsic (!Ref) is not a literal, so it must not trip a literal
	// check, and the template must still parse (the bucket still gets the no-encryption finding).
	tmpl := `AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  Acl:
    Type: String
Resources:
  Data:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: !Ref Acl
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: true
      MasterUserPassword: !Ref DbSecret
`
	got := ruleIDs(scan(t, map[string]string{"stack.yaml": tmpl}))
	if _, ok := got["cloudformation-public-bucket-acl"]; ok {
		t.Errorf("!Ref AccessControl must not be flagged as a public literal ACL")
	}
	if _, ok := got["cloudformation-plaintext-secret"]; ok {
		t.Errorf("!Ref secret must not be flagged as a plaintext secret")
	}
	if _, ok := got["cloudformation-s3-no-encryption"]; !ok {
		t.Errorf("template with intrinsics must still parse and flag the unencrypted bucket, got %v", keys(got))
	}
}

func TestCloudFormationRulePackTriggers(t *testing.T) {
	// Representative new rules across families must each fire on a genuine violation.
	cases := []struct{ name, tmpl, want string }{
		{"rds public", "Resources:\n  DB:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      StorageEncrypted: true\n      PubliclyAccessible: true\n", "cloudformation-rds-public"},
		{"sg open egress", "Resources:\n  SG:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n      SecurityGroupEgress:\n        - CidrIp: \"0.0.0.0/0\"\n", "cloudformation-sg-open-egress"},
		{"lambda public", "Resources:\n  P:\n    Type: AWS::Lambda::Permission\n    Properties:\n      Principal: \"*\"\n", "cloudformation-lambda-public"},
		{"eks public", "Resources:\n  C:\n    Type: AWS::EKS::Cluster\n    Properties:\n      ResourcesVpcConfig:\n        EndpointPublicAccess: true\n", "cloudformation-eks-public-endpoint"},
		{"api no auth", "Resources:\n  M:\n    Type: AWS::ApiGateway::Method\n    Properties:\n      AuthorizationType: NONE\n", "cloudformation-api-no-auth"},
		{"wildcard principal", "Resources:\n  BP:\n    Type: AWS::S3::BucketPolicy\n    Properties:\n      PolicyDocument:\n        Statement:\n          - Effect: Allow\n            Principal: \"*\"\n            Action: s3:GetObject\n", "cloudformation-wildcard-principal"},
		{"ebs unencrypted", "Resources:\n  V:\n    Type: AWS::EC2::Volume\n    Properties:\n      Size: 20\n", "cloudformation-ebs-unencrypted"},
		{"redshift unencrypted", "Resources:\n  C:\n    Type: AWS::Redshift::Cluster\n    Properties:\n      Encrypted: false\n", "cloudformation-redshift-unencrypted"},
		{"kms no rotation", "Resources:\n  K:\n    Type: AWS::KMS::Key\n    Properties:\n      Description: app\n", "cloudformation-kms-no-rotation"},
		{"ecr no scan", "Resources:\n  R:\n    Type: AWS::ECR::Repository\n    Properties:\n      RepositoryName: app\n", "cloudformation-ecr-no-scan"},
		{"cloudtrail no validation", "Resources:\n  T:\n    Type: AWS::CloudTrail::Trail\n    Properties:\n      IsMultiRegionTrail: true\n", "cloudformation-cloudtrail-no-log-validation"},
		{"ec2 imdsv2", "Resources:\n  I:\n    Type: AWS::EC2::Instance\n    Properties:\n      ImageId: ami-123\n", "cloudformation-ec2-imdsv2"},
		{"log retention", "Resources:\n  LG:\n    Type: AWS::Logs::LogGroup\n    Properties:\n      LogGroupName: /app\n", "cloudformation-log-retention-missing"},
		{"lambda no dlq", "Resources:\n  F:\n    Type: AWS::Lambda::Function\n    Properties:\n      FunctionName: w\n", "cloudformation-lambda-no-dlq"},
		{"rds no backup", "Resources:\n  DB:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      StorageEncrypted: true\n      BackupRetentionPeriod: 0\n", "cloudformation-rds-no-backup"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{"template.yaml": tc.tmpl}))
			if _, ok := got[tc.want]; !ok {
				t.Errorf("expected %s, got %v", tc.want, keys(got))
			}
		})
	}
}

func TestCloudFormationRulePackNoFalsePositives(t *testing.T) {
	// A hardened stack touching the new resource types must yield zero findings.
	tmpl := `Resources:
  Vol:
    Type: AWS::EC2::Volume
    Properties:
      Size: 20
      Encrypted: true
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      SqsManagedSseEnabled: true
      RedrivePolicy: '{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:111122223333:dlq","maxReceiveCount":5}'
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
  Key:
    Type: AWS::KMS::Key
    Properties:
      EnableKeyRotation: true
  Repo:
    Type: AWS::ECR::Repository
    Properties:
      ImageScanningConfiguration:
        ScanOnPush: true
  Trail:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsMultiRegionTrail: true
      EnableLogFileValidation: true
`
	if got := scan(t, map[string]string{"stack.yaml": tmpl}); len(got) != 0 {
		t.Errorf("hardened CloudFormation should yield no findings, got %+v", got)
	}
}

func TestCloudFormationReviewFixes(t *testing.T) {
	// go-arch review fixes: AWS insecure-by-default cases + single-statement policy.
	cases := []struct{ name, tmpl, want string }{
		{"eks endpoint default public (omitted)", "Resources:\n  C:\n    Type: AWS::EKS::Cluster\n    Properties:\n      ResourcesVpcConfig:\n        SubnetIds: [subnet-1]\n", "cloudformation-eks-public-endpoint"},
		{"imdsv2 metadata without httptokens", "Resources:\n  I:\n    Type: AWS::EC2::Instance\n    Properties:\n      ImageId: ami-123\n      MetadataOptions:\n        HttpEndpoint: enabled\n", "cloudformation-ec2-imdsv2"},
		{"single-statement policy wildcard principal", "Resources:\n  BP:\n    Type: AWS::S3::BucketPolicy\n    Properties:\n      PolicyDocument:\n        Statement:\n          Effect: Allow\n          Principal: \"*\"\n          Action: s3:GetObject\n", "cloudformation-wildcard-principal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{"template.yaml": tc.tmpl}))
			if _, ok := got[tc.want]; !ok {
				t.Errorf("expected %s, got %v", tc.want, keys(got))
			}
		})
	}
	// The EKS compliant form (explicitly false) must NOT fire.
	got := ruleIDs(scan(t, map[string]string{"template.yaml": "Resources:\n  C:\n    Type: AWS::EKS::Cluster\n    Properties:\n      ResourcesVpcConfig:\n        EndpointPublicAccess: false\n"}))
	if _, bad := got["cloudformation-eks-public-endpoint"]; bad {
		t.Errorf("EndpointPublicAccess:false must not fire; got %v", keys(got))
	}
}
