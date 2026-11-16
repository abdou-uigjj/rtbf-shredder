# storage: versioned bucket under the operator cmk + the ledger table.
# versioning is not optional here: s3 delete leaves a delete-marker,
# and a subject's data "erased" from the live prefix but alive in
# version history is exactly the gap this pipeline exists to close.

resource "aws_s3_bucket" "exports" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_versioning" "exports" {
  bucket = aws_s3_bucket.exports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.operator.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# the tamper-evident ledger lives in dynamodb. the lambda appends the
# same hash-chained entries the local ledger uses; pitr guards against
# an operator "losing" entries.
resource "aws_dynamodb_table" "ledger" {
  name         = var.ledger_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "sid"
  range_key    = "seq"

  attribute {
    name = "sid"
    type = "S"
  }
  attribute {
    name = "seq"
    type = "N"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }
}
