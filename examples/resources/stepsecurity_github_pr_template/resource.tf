
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

# Configure PR template for policy-driven PRs
resource "stepsecurity_github_pr_template" "example" {
  owner          = "test-organization"
  title          = "ci: apply security best practices"
  summary        = "This PR implements security hardening recommendations from StepSecurity"
  commit_message = "chore: apply security hardening"
  labels         = ["security", "automated"]
}

# For importing existing PR template config to terraform state
# this will be helpful to manage existing PR template config using terraform
# alternative to this is to use terraform import command
import {
  to = stepsecurity_github_pr_template.example
  id = "test-organization"
}
