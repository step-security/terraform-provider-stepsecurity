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

# PAT governance policy for a GitHub organization. The policy drives the
# personal-access-token controls (max age, no expiration, over-scoped, unused,
# inactive owner) and the resulting violation alerts and pre-expiry reminders.
# An enabled policy needs at least one active control.
resource "stepsecurity_github_pat_governance_policy" "example-org" {
  owner   = "example-org"
  enabled = true

  # Max-age control, per token class (days; 0 disables the class check).
  fine_grained_max_age_days = 90
  classic_max_age_days      = 90

  # Flag tokens without an expiration date.
  flag_no_expiry = true

  # Flag over-scoped tokens. Omit over_scoped_scopes to use the server
  # default (repo, admin:org, workflow).
  flag_over_scoped   = true
  over_scoped_scopes = ["repo", "admin:org", "workflow"]

  # Flag tokens with no sign of use for more than N days (0 disables).
  unused_days = 180

  # Optional: file and keep up to date a violations issue in this repository
  # of the organization on each alert.
  github_issue_repo = "security-alerts"

  # Pre-expiry reminder bands (days before expiry). Omit to use the server
  # default (30, 7, 1).
  expiry_reminder_days = [30, 7, 1]
}

# For importing an existing PAT governance policy to terraform state, use the
# owner/organization name as the import ID.
import {
  to = stepsecurity_github_pat_governance_policy.example-org
  id = "example-org"
}
