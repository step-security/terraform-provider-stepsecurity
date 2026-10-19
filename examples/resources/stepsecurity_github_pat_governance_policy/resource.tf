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
# inactive owner), the resulting violation alerts, the pre-expiry reminder
# emails and the automatic revocations. An enabled policy needs at least one
# active control. An organization without a policy of its own follows the
# customer's tenant-wide policy; destroying this resource returns it to that.
resource "stepsecurity_github_pat_governance_policy" "example-org" {
  owner   = "example-org"
  enabled = true

  # Controls -----------------------------------------------------------------

  # Max-age control, per token class (days; 0 disables the class check).
  fine_grained_max_age_days = 90
  classic_max_age_days      = 90

  # Flag tokens without an expiration date.
  flag_no_expiry = true

  # Flag over-scoped tokens. Omit over_scoped_scopes to use the server
  # default (repo, admin:org, workflow).
  flag_over_scoped   = true
  over_scoped_scopes = ["repo", "admin:org", "workflow"]

  # Flag tokens with no sign of use for more than N days (0 disables). The
  # per-class limits win over the shared one; omit them to share it.
  unused_days         = 180
  classic_unused_days = 90

  # Optional: file and keep up to date a violations issue in this repository
  # of the organization on each alert.
  github_issue_repo = "security-alerts"

  # Pre-expiry reminders ----------------------------------------------------

  # Reminder bands (days before expiry). Omit to use the server default
  # (30, 7, 1). A class with its own list ignores the shared one; [0] sends
  # no reminders for that class.
  expiry_reminder_days         = [30, 7, 1]
  classic_expiry_reminder_days = [14, 1]

  # Address reminders to the token's user (their linked SSO email) and copy
  # these mailboxes on every reminder and revocation notice.
  expiry_reminder_to_owner = true
  expiry_reminder_cc       = ["security-team@example.com"]

  # Derive an email for enterprise managed users the SSO directory does not
  # list (First-last_shortcode becomes First.last@example.com).
  owner_email_fallback_domain = "example.com"

  # Custom reminder email per token class and band. Bands without a template
  # use the built-in email.
  expiry_reminder_templates = {
    classic = {
      "14" = {
        subject = "Your classic token {{token_name}} expires in {{days_left}} days"
        body    = "<p>Hi {{owner}}, rotate {{token_name}} in {{organization}} before {{expires_at}}: {{manage_url}}</p>"
      }
    }
  }

  # Automatic revocation -----------------------------------------------------

  # Revoke tokens that have stayed non-compliant for this many days without
  # an approved exception (0 disables).
  classic_noncompliant_revoke_after_days      = 8
  fine_grained_noncompliant_revoke_after_days = 8

  # Revoke a token 24 hours after its last reminder band was sent, here for
  # classic tokens only.
  auto_revoke_after_reminders         = false
  classic_auto_revoke_after_reminders = true

  # Email the token's user when StepSecurity revokes a token, optionally with
  # a custom notice (per class, else shared, else the built-in email).
  notify_on_revocation = true
  revocation_notification_template = {
    subject = "{{token_name}} was revoked in {{organization}}"
    body    = "<p>Hi {{owner}}, your {{token_type}} token was revoked on {{revoked_at}}. Reason: {{reason}}. Create a compliant token: {{manage_url}}</p>"
  }
}

# An organization can keep its own settings stored but follow the customer's
# tenant-wide policy instead; set use_tenant_policy back to false (or omit it)
# to enforce the organization's own settings again.
resource "stepsecurity_github_pat_governance_policy" "follows-tenant" {
  owner             = "another-org"
  enabled           = true
  flag_no_expiry    = true
  use_tenant_policy = true
}

# For importing an existing PAT governance policy to terraform state, use the
# owner/organization name as the import ID.
import {
  to = stepsecurity_github_pat_governance_policy.example-org
  id = "example-org"
}
