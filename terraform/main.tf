provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project = "rtbf-shredder"
      purpose = "gdpr-art17-erasure"
    }
  }
}
