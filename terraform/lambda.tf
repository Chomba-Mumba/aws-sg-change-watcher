data "aws_iam_policy_document" "assume_role_policy" {
    statement {
        effect = "Allow"

        principals {
            type = "Service"
            identifiers = ["lambda.amazonaws.com"]
        }

        actions = ["sts:AssumeRole"]
    }
}

resource "aws_cloudwatch_log_group" "manage_sg_lambda_lg" {
    name = "/aws/lambda/manage_sg_rules_lambda"
    retention_in_days = 14

    tags = {
        Project = "securtityGroupManager"
    }
} 

resource "aws_iam_role_policy_attachment" "lambda_policy" {
    role = aws_iam_role.manage_sg_role.name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "manage_sg_role" {
    name = "remove_default_sg_rules_role"
    assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
}

resource "aws_lambda_function" "manage_sg_lambda" {
    filename = var.manage_sg_file
    function_name = "manage_sg_rules_lambda"

    role = aws_iam_role.manage_sg_role.arn
    handler = "bootstrap"
    runtime = "provided.al2023"

    architectures = ["arm64"]
 
    tags = {
        Project = "securtityGroupManager"
    }

    depends_on = [aws_cloudwatch_log_group.manage_sg_lambda_lg]

}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.manage_sg_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.manage_sg_rule.arn
}
