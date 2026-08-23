data "aws_iam_policy_document" "worker_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "worker" {
  name               = "${local.prefix}-execution-worker"
  assume_role_policy = data.aws_iam_policy_document.worker_assume.json
  tags               = merge(local.tags, local.worker_tags)
}

resource "aws_iam_role_policy_attachment" "worker_ssm" {
  role       = aws_iam_role.worker.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "worker_runtime" {
  statement {
    sid       = "ReadGovernedRuntimeSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.worker_runtime_secret_arn]
  }

  statement {
    sid       = "DecryptRuntimeAndEvidenceData"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.staging.arn]
  }

  statement {
    sid       = "ListEvidenceBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]
  }

  statement {
    sid     = "UseEvidenceObjects"
    effect  = "Allow"
    actions = ["s3:AbortMultipartUpload", "s3:GetObject", "s3:PutObject"]
    resources = [
      "${aws_s3_bucket.evidence.arn}/*",
    ]
  }
}

resource "aws_iam_role_policy" "worker_runtime" {
  name   = "${local.prefix}-execution-runtime"
  role   = aws_iam_role.worker.id
  policy = data.aws_iam_policy_document.worker_runtime.json
}

resource "aws_iam_instance_profile" "worker" {
  name = "${local.prefix}-execution-worker"
  role = aws_iam_role.worker.name
  tags = merge(local.tags, local.worker_tags)
}

resource "aws_iam_role" "worker_image_builder" {
  name               = "${local.prefix}-worker-image-builder"
  assume_role_policy = data.aws_iam_policy_document.worker_assume.json
  tags               = merge(local.tags, local.worker_tags, { component = "image-builder" })
}

resource "aws_iam_role_policy_attachment" "worker_image_builder" {
  role       = aws_iam_role.worker_image_builder.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/EC2InstanceProfileForImageBuilder"
}

resource "aws_iam_role_policy_attachment" "worker_image_builder_ssm" {
  role       = aws_iam_role.worker_image_builder.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "worker_image_builder_artifact" {
  statement {
    sid     = "ReadPinnedWorkerPackage"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    resources = [
      "${aws_s3_bucket.evidence.arn}/${var.worker_package_s3_key}",
      "${aws_s3_bucket.evidence.arn}/${var.worker_trust_anchor_s3_key}",
    ]
  }

  statement {
    sid       = "DecryptPinnedWorkerPackage"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.staging.arn]
  }
}

resource "aws_iam_role_policy" "worker_image_builder_artifact" {
  name   = "${local.prefix}-read-worker-package"
  role   = aws_iam_role.worker_image_builder.id
  policy = data.aws_iam_policy_document.worker_image_builder_artifact.json
}

resource "aws_iam_instance_profile" "worker_image_builder" {
  name = "${local.prefix}-worker-image-builder"
  role = aws_iam_role.worker_image_builder.name
  tags = merge(local.tags, local.worker_tags, { component = "image-builder" })
}
