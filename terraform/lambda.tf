data "aws_iam_policy_document" "assume_role" {
    statement {
        effect = "Allow"

        principals {
            type = "Service"
            identifiers = ["lambda.amazonaws.com"]
        }

        actions = ["sts:AssumeRole"]
    }
}

resource "aws_iam_role" "manage_sg_role" {
    name = "remove_default_sg_rules_role"
    assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_lambda_function" "manage_sg_lambda" {
    filename = var.manage_sg_file
    function_name = "manage_sg_rules"

    role = aws_iam_role.manage_sg_role.arn
    handler = "bootstrap"
    runtime = "provided.al2023"

    tags = {
        project = "security_group_manager"
    }
}