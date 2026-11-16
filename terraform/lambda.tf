# the erasure responder: one lambda that turns an art. 17 request into
# a signed certificate. its role can do exactly three things: read the
# bucket, scrub the subject prefix, and schedule deletion of the
# subject's kms alias target. nothing else.

resource "aws_iam_role" "responder" {
  name = "rtbf-responder"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "responder" {
  name = "rtbf-responder-scoped"
  role = aws_iam_role.responder.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ScrubSubjectObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObjectVersion", "s3:DeleteObjectVersion", "s3:ListBucket"]
        Resource = [aws_s3_bucket.exports.arn, "${aws_s3_bucket.exports.arn}/*"]
      },
      {
        Sid      = "CryptoShredSubjectKeys"
        Effect   = "Allow"
        Action   = ["kms:ListAliases", "kms:ScheduleKeyDeletion"]
        Resource = "*"
      },
      {
        Sid      = "AppendLedger"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.ledger.arn
      },
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.responder.arn}:*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "responder" {
  name              = "/aws/lambda/rtbf-responder"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "responder" {
  function_name = "rtbf-responder"
  role          = aws_iam_role.responder.arn
  handler       = "handler.handler"
  runtime       = "python3.12"
  architectures = ["x86_64"]
  memory_size   = var.lambda_memory
  timeout       = 120
  filename      = "${path.module}/../lambda.zip"

  environment {
    variables = {
      RTBF_SALT_PLACEMENT = "kms-injected" # salt + keys are fetched at runtime
      RTBF_BUCKET         = var.bucket_name
      RTBF_LEDGER_TABLE   = var.ledger_table
    }
  }

  depends_on = [aws_cloudwatch_log_group.responder]
}

# weekly sweep: catch any erasure window that expired while the
# responder was down or a request stalled in a queue.
resource "aws_cloudwatch_event_rule" "sweep" {
  name                = "rtbf-weekly-sweep"
  schedule_expression = "rate(7 days)"
}

resource "aws_cloudwatch_event_target" "sweep" {
  rule = aws_cloudwatch_event_rule.sweep.name
  arn  = aws_lambda_function.responder.arn
}

resource "aws_lambda_permission" "sweep" {
  statement_id  = "AllowWeeklySweep"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sweep.arn
}

resource "aws_cloudwatch_metric_alarm" "responder_errors" {
  alarm_name          = "rtbf-responder-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  dimensions = {
    FunctionName = aws_lambda_function.responder.function_name
  }
  alarm_description = "an erasure request failed - a subject is waiting"
}
