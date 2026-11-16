output "bucket_arn" {
  description = "the versioned export bucket the erasure lambda scrubs"
  value       = aws_s3_bucket.exports.arn
}

output "operator_cmk_arn" {
  description = "the cmk wrapping all per-subject data keys"
  value       = aws_kms_key.operator.arn
}

output "ledger_table_name" {
  description = "dynamodb table holding the hash-chained erasure ledger"
  value       = aws_dynamodb_table.ledger.name
}

output "responder_function_name" {
  description = "the lambda to invoke with an art. 17 request event"
  value       = aws_lambda_function.responder.function_name
}
