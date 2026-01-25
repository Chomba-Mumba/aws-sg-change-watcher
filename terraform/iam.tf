data "aws_iam_policy_document" "trail_policy" {
    statement {
        sid = "AWSCloudTrailAclCheck"
        effect = "Allow"

        principals {
            type = "Service"
            identifiers = ["cloudtrail.amazonaws.com"]
        }

        actions = ["s3:GetBucketAcl"]
        resources = [aws_s3_bucket.ec2_trail_bucket.arn]
        condition {
            test = "StringEquals"
            variable = "aws:SourceArn"
            values = ["arn:${data.aws_partition.current.partition}:cloudtrail:${var.region}:${data.aws_caller_identity.current.account_id}:trail/ec2-trail"]
        }
    }

    statement {
        sid = "AWSCloudTrailWrite"
        effect = "Allow"

        principals {
            type = "Service"
            identifiers = ["cloudtrail.amazonaws.com"]
        }

        actions = ["s3:PutObject"]
        resources = ["${aws_s3_bucket.ec2_trail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

        condition {
            test = "StringEquals"
            variable = "s3:x-amz-acl"
            values = ["bucket-owner-full-control"]
        }
        condition {
            test = "StringEquals"
            variable = "aws:SourceArn"
            values = ["arn:${data.aws_partition.current.partition}:cloudtrail:${var.region}:${data.aws_caller_identity.current.account_id}:trail/ec2-trail"]
        }
    }
}

resource "aws_s3_bucket_policy" "trail_bucket_policy" {
    bucket = aws_s3_bucket.ec2_trail_bucket.id
    policy = data.aws_iam_policy_document.trail_policy.json
}