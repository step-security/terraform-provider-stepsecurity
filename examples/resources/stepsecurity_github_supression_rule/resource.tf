
terraform {
  required_providers {
    stepsecurity = {
      source = "step-security/stepsecurity"
    }
  }
}

provider "stepsecurity" {
  api_key  = "xxxxxxxx" # can also be set as env variable STEP_SECURITY_API_KEY
  customer = "abcdefg"  # can also be set as env variable STEP_SECURITY_CUSTOMER
}

# github supression rule for findings detected by stepsecurity.
resource "stepsecurity_github_supression_rule" "rule-1" {
  # Rule to ignore new connections to amazon aws from any process across all repositories in customer tenant
  name        = "ignore-new-connections-to-amazon-aws"
  type        = "anomalous_outbound_network_call"
  action      = "ignore"
  description = "test"
  destination {
    domain = "*.amazonaws.com"
  }
  process = "*"
  owner   = "*"
}


resource "stepsecurity_github_supression_rule" "rule-2" {
  # Rule to ignore source code overwritten findings on specific files in 'test' job of 'test' workflow in 'test' repo 
  name        = "ignore-source-code-overwritten-on-specific-files"
  type        = "source_code_overwritten"
  action      = "ignore"
  description = "test"
  file        = "file.txt"
  file_path   = "/path/to/file.txt"
  owner       = "*"
  repo        = "test"
  workflow    = "test"
  job         = "test"
}
