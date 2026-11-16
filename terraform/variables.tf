variable "region" {
  description = "aws region the erasure pipeline lives in"
  type        = string
  default     = "eu-central-1"
}

variable "bucket_name" {
  description = "versioned bucket holding the sealed subject exports"
  type        = string
}

variable "ledger_table" {
  description = "dynamodb table name for the erasure ledger"
  type        = string
  default     = "rtbf-erasure-ledger"
}

variable "operator_key_alias" {
  description = "alias of the cmk that wraps every per-subject data key"
  type        = string
  default     = "alias/rtbf-operator"
}

variable "cert_public_key_b64" {
  description = "base64 ed25519 public key embedded in the lambda for receipt signing context"
  type        = string
  default     = ""
}

variable "lambda_memory" {
  description = "lambda memory for the erasure responder"
  type        = number
  default     = 512
}

variable "log_retention_days" {
  description = "cloudwatch retention. erasure logs may carry pseudonyms, keep it short"
  type        = number
  default     = 30
}
