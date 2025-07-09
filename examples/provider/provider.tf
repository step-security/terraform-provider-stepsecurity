
terraform {
  required_providers {
    stepsecurity = {
      source = "step-security/stepsecurity"
    }
  }
}

provider "stepsecurity" {
  api_base_url = "http://localhost:1234"
  api_key      = "09876"
  customer     = "abcdefg"
}