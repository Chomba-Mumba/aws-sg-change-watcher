resource "aws_cloudwatch_event_rule" "manage_sg_rule" {
    name = "manage-sg"
    description = "Manage changes in AWS security groups"

    event_pattern = jsonencode({
        source = ["aws.ec2"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
            eventSource = ["ec2.amazonaws.com"],
            eventName = [
                //api action names
                "AuthorizeSecurityGroupIngress",
                "RevokeSecurityGroupIngress",
                "CreateSecurityGroup",
                "DeleteSecurityGroup",
                "ModifySecurityGroupRules",
                "UpdateSecurityGroupRule"
            ]
        }
    })

    tags = {
        project = "security_group_manager"
    }
}

resource "aws_cloudwatch_event_target" "lambda" {
    rule = aws_cloudwatch_event_rule.manage_sg_rule.name
    target_id = "SendToLambda"
    arn = aws_lambda_function.manage_sg_lambda.arn
}

// log events and errors to cloudwatch

resource "aws_cloudwatch_log_group" "manage_sg_lg" {
    name = "manage_sg_lg"
}

data "aws_iam_policy_document" "manage_sg_log_policy_doc" {
    statement {
        actions = [
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:PutLogEventsBatch",
        ]

        resources = ["arn:aws:logs:*"]

        principals {
            identifiers = ["es.amazonaws.com"]
            type = "Service"
        }
    }
}

resource "aws_cloudwatch_log_resource_policy" "manage_sg_log_policy" {
    policy_document = data.aws_iam_policy_document.manage_sg_log_policy_doc.json
    policy_name = "manage-sg-log-policy"
}

resource "aws_cloudwatch_event_target" "log_target" {
    rule = aws_cloudwatch_event_rule.manage_sg_rule.name
    target_id = "SendToCloudWatch"
    arn = aws_cloudwatch_log_group.manage_sg_lg.arn
}

