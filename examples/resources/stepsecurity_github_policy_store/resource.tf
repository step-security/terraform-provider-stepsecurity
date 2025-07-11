
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

# policy that can be referenced in workflows in 'test-organization' to block egress traffic in
resource "stepsecurity_github_policy_store" "test-organization" {
  owner         = "test-organization"
  policy_name   = "test-policy"
  egress_policy = "block"
  allowed_endpoints = [
    "github.com:443",
    "api.github.com:443",
    "registry.npmjs.org:443"
  ]
  disable_telemetry       = false
  disable_sudo            = false
  disable_file_monitoring = false
}

# For importing existing github policy store polcies to terraform state
import {
  to = stepsecurity_github_policy_store.test-organization
  id = "test-organization:::test-policy" # format is <owner>:::<policy_name>
}
  