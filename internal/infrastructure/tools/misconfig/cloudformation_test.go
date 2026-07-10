package misconfig

import "testing"

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
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres
      StorageEncrypted: true
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
