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

# The tenant-wide PAT governance policy: what every GitHub organization of the
# tenant follows unless it stores a policy of its own with
# stepsecurity_github_pat_governance_policy. There is one per tenant, so
# declare at most one instance of this resource. The settings are the same as
# the organization policy; see that resource for every attribute.
resource "stepsecurity_github_tenant_pat_governance_policy" "tenant" {
  enabled = true

  fine_grained_max_age_days = 90
  classic_max_age_days      = 90
  flag_no_expiry            = true
  flag_over_scoped          = true
  unused_days               = 180

  expiry_reminder_days     = [30, 7, 1]
  expiry_reminder_to_owner = true
  expiry_reminder_cc       = ["security-team@example.com"]

  classic_noncompliant_revoke_after_days      = 8
  fine_grained_noncompliant_revoke_after_days = 8
  notify_on_revocation                        = true
}

# For importing the existing tenant-wide policy to terraform state, use any
# import ID; it is ignored because the tenant comes from the provider.
import {
  to = stepsecurity_github_tenant_pat_governance_policy.tenant
  id = "tenant"
}
