# the operator cmk: wraps one data key per subject. erasure of a
# subject = scheduling deletion of their data key; the cmk itself
# survives because the other subjects' keys depend on it.
resource "aws_kms_key" "operator" {
  description             = "rtbf operator cmk - wraps per-subject data keys"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  key_usage               = "ENCRYPT_DECRYPT"
}

resource "aws_kms_alias" "operator" {
  name          = var.operator_key_alias
  target_key_id = aws_kms_key.operator.key_id
}

# per-subject keys are created by the erasure lambda, one alias per
# subject pseudonym: alias/rtbf-<sid>. deleting that key is the
# cryptographic erasure event the certificate attests to.
