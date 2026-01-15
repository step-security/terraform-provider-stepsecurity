
terraform {
  required_providers {
    stepsecurity = {
      source = "step-security/stepsecurity"
    }
  }
}

provider "stepsecurity" {
  api_key  = "step_83242593-2f34-4199-8087-4a802b6663ab" # can also be set as env variable STEP_SECURITY_API_KEY
  customer = "step-integration-tests"  # can also be set as env variable STEP_SECURITY_CUSTOMER
  api_base_url = "https://int.api.stepsecurity.io"
}

# github supression rule for findings detected by stepsecurity.
# resource "stepsecurity_github_supression_rule" "rule-1" {
#   # Rule to ignore new connections to amazon aws from any process across all repositories in customer tenant
#   name        = "ignore-new-connections-to-amazon-aws"
#   type        = "anomalous_outbound_network_call"
#   action      = "ignore"
#   description = "test"
#   destination = {
#     domain = "*.amazonaws.com"
#   }
#   process = "*"
#   owner   = "*"
# }


# resource "stepsecurity_github_supression_rule" "rule-2" {
#   # Rule to ignore source code overwritten findings on specific files in 'test' job of 'test' workflow in 'test' repo 
#   name        = "ignore-source-code-overwritten-on-specific-files"
#   type        = "source_code_overwritten"
#   action      = "ignore"
#   description = "test"
#   file        = "file.txt"
#   file_path   = "/path/to/file.txt"
#   owner       = "*"
#   repo        = "test"
#   workflow    = "test"
#   job         = "test"
# }

resource "stepsecurity_github_supression_rule" "rule-test-vamshi" {
  # Rule to ignore source code overwritten findings on specific files in 'test' job of 'test' workflow in 'test' repo 
  name        = "test-vamshi"
  type        = "runner_worker_memory_read"
  action      = "ignore"
  description = "test"
  owner       = "*"
  repo        = "*"
  workflow    = "*"
  job         = "*"
  process     = "python3"
}