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

# Policy with block mode and basic endpoints
resource "stepsecurity_github_policy_store" "audit-policy" {
  owner         = "test-organization"
  policy_name   = "audit-policy"
  egress_policy = "block"
  allowed_endpoints = [
    "github.com:443",
    "api.github.com:443",
    "registry.npmjs.org:443"
  ]
}

# Policy with audit mode and custom endpoints
resource "stepsecurity_github_policy_store" "custom-policy" {
  owner         = "test-organization"
  policy_name   = "custom-policy"
  egress_policy = "audit"
  allowed_endpoints = [
    "github.com:443",
    "api.github.com:443",
    "registry.npmjs.org:443",
    "docker.io:443"
  ]
}

# For importing existing github policy store policies to terraform state
import {
  to = stepsecurity_github_policy_store.audit-policy
  id = "test-organization:::audit-policy" # format is <owner>:::<policy_name>
}
