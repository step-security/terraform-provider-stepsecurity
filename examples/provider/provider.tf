# Copyright (c) HashiCorp, Inc.

terraform {
  required_providers {
    stepsecurity = {
      source = "registry.terraform.io/step-security/stepsecurity"
    }
  }
}

provider "stepsecurity" {
  api_base_url = "http://localhost:1234"
  api_key      = "09876"
  customer     = "abcdefg"
}