# Copyright (c) HashiCorp, Inc.

terraform {
  required_providers {
    stepsecurity = {
      source = "registry.terraform.io/step-security/stepsecurity"
    }
  }
}

provider "stepsecurity" {
  api_key  = "09876"
  customer = "abcdefg"
}

# creates policy for auto remediation of findings detected by stepsecurity in selected repos by creating a pr.
resource "stepsecurity_policy_driven_pr" "test-organization" {
  owner          = "test-organization"
  selected_repos = ["test-repo-1", "test-repo-2"]
  auto_remediation_options = {
    create_pr                                     = true
    create_issue                                  = false
    create_github_advanced_security_alert         = false
    harden_github_hosted_runner                   = true
    pin_actions_to_sha                            = true
    restrict_github_token_permissions             = false
    actions_to_exempt_while_pinning               = ["actions/checkout", "actions/setup-node"]
    actions_to_replace_with_step_security_actions = ["EnricoMi/publish-unit-test-result-action"]
  }
}
