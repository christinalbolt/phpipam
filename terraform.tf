terraform {
  backend "s3" {
    bucket  = "ait-state-us-east-1"
    acl     = "bucket-owner-full-control"
    key     = "ait_prod/prod/us-east-1/phpipam.tfstate"
    region  = "us-east-1"
    encrypt = "true"
  }
}

terraform {
  required_version = ">= 1.8.2"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50.0"
    }
  }
}
