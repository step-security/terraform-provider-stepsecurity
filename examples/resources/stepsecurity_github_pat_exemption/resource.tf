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

# Exempt one classic token of an organization until a date, with the change
# record that approved it. The token is named by its last eight characters.
resource "stepsecurity_github_pat_exemption" "release_pipeline_token" {
  organization = "example-org"
  token_suffix = "a1b2c3d4"
  expires_at   = "2026-12-31T00:00:00Z"
  reason       = "Release pipeline token, rotation scheduled for the next quarter"
  record_id    = "CHG0012345"
}

# Exempt a fine-grained token, narrowed to its user. Omitting expires_at lets
# the server set eight days after the approval.
resource "stepsecurity_github_pat_exemption" "deploy_token" {
  organization = "example-org"
  token_id     = 1234567
  user_login   = "deploy-bot"
  reason       = "Deployment automation, replacement in progress"
}

# Tenant-wide: every classic token of one service account, but only on one
# GitHub Enterprise Server. Omit organization for tenant-wide exemptions and
# omit instance to cover every organization of the tenant.
resource "stepsecurity_github_pat_exemption" "service_account" {
  user_login  = "svc-ci"
  token_class = "classic"
  instance    = "ghes.example.com"
  expires_at  = "2027-03-31T00:00:00Z"
  reason      = "Service account tokens are rotated by the platform team"
}

# For importing an existing exemption to terraform state, use organization/key
# as listed by the API, or /key for a tenant-wide exemption.
import {
  to = stepsecurity_github_pat_exemption.release_pipeline_token
  id = "example-org/a1b2c3d4"
}
