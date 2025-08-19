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

# Action Policy Example (all_orgs) - Allows only specific GitHub Actions across all orgs
resource "stepsecurity_github_run_policy" "action_policy_all_orgs" {
  owner    = "my-org"
  name     = "Allowed Actions Policy - All Orgs"
  all_orgs = true

  policy_config = {
    owner                = "my-org"
    name                 = "Allowed Actions Policy - All Orgs"
    enable_action_policy = true
    allowed_actions = {
      "actions/checkout"            = "allow"
      "step-security/harden-runner" = "allow"
      "actions/setup-node"          = "allow"
      "actions/setup-python"        = "allow"
      "actions/upload-artifact"     = "allow"
    }
  }
}

# Action Policy Example (all_repos) - Allows only specific GitHub Actions across all repos
resource "stepsecurity_github_run_policy" "action_policy_all_repos" {
  owner     = "my-org"
  name      = "Allowed Actions Policy - All Repos"
  all_repos = true

  policy_config = {
    owner                = "my-org"
    name                 = "Allowed Actions Policy - All Repos"
    enable_action_policy = true
    allowed_actions = {
      "actions/checkout"            = "allow"
      "step-security/harden-runner" = "allow"
      "actions/setup-node"          = "allow"
      "actions/setup-python"        = "allow"
      "actions/upload-artifact"     = "allow"
    }
  }
}

# Action Policy Example (dry_run) - Test action policy without enforcement
resource "stepsecurity_github_run_policy" "action_policy_dry_run" {
  owner     = "my-org"
  name      = "Action Policy - Dry Run"
  all_repos = true

  policy_config = {
    owner                = "my-org"
    name                 = "Action Policy - Dry Run"
    enable_action_policy = true
    allowed_actions = {
      "actions/checkout"            = "allow"
      "step-security/harden-runner" = "allow"
    }
    is_dry_run = true
  }
}

# Runner Label Policy Example (all_repos) - Restricts which runners can be used
resource "stepsecurity_github_run_policy" "runner_policy_all_repos" {
  owner     = "my-org"
  name      = "Runner Label Policy - All Repos"
  all_repos = true

  policy_config = {
    owner                    = "my-org"
    name                     = "Runner Label Policy - All Repos"
    enable_runs_on_policy    = true
    disallowed_runner_labels = ["self-hosted", "windows-latest", "macos-latest"]
  }
}

# Runner Label Policy Example (all_orgs) - Restricts which runners can be used across all orgs
resource "stepsecurity_github_run_policy" "runner_policy_all_orgs" {
  owner    = "my-org"
  name     = "Runner Label Policy - All Orgs"
  all_orgs = true

  policy_config = {
    owner                    = "my-org"
    name                     = "Runner Label Policy - All Orgs"
    enable_runs_on_policy    = true
    disallowed_runner_labels = ["self-hosted", "windows-latest"]
  }
}

# Runner Label Policy Example (dry_run) - Test runner policy without enforcement
resource "stepsecurity_github_run_policy" "runner_policy_dry_run" {
  owner     = "my-org"
  name      = "Runner Label Policy - Dry Run"
  all_repos = true

  policy_config = {
    owner                    = "my-org"
    name                     = "Runner Label Policy - Dry Run"
    enable_runs_on_policy    = true
    disallowed_runner_labels = ["self-hosted"]
    is_dry_run               = true
  }
}

# Secrets Policy Example (all_orgs) - Prevents secrets from being exfiltrated across all orgs
resource "stepsecurity_github_run_policy" "secrets_policy_all_orgs" {
  owner    = "my-org"
  name     = "Secrets Policy - All Orgs"
  all_orgs = true

  policy_config = {
    owner                 = "my-org"
    name                  = "Secrets Policy - All Orgs"
    enable_secrets_policy = true
  }
}

# Secrets Policy Example (all_repos) - Prevents secrets from being exfiltrated across all repos
resource "stepsecurity_github_run_policy" "secrets_policy_all_repos" {
  owner     = "my-org"
  name      = "Secrets Policy - All Repos"
  all_repos = true

  policy_config = {
    owner                 = "my-org"
    name                  = "Secrets Policy - All Repos"
    enable_secrets_policy = true
  }
}

# Secrets Policy Example (dry_run) - Test secrets policy without enforcement
resource "stepsecurity_github_run_policy" "secrets_policy_dry_run" {
  owner     = "my-org"
  name      = "Secrets Policy - Dry Run"
  all_repos = true

  policy_config = {
    owner                 = "my-org"
    name                  = "Secrets Policy - Dry Run"
    enable_secrets_policy = true
    is_dry_run            = true
  }
}

# Compromised Actions Policy Example (all_orgs) - Blocks known compromised actions across all orgs
resource "stepsecurity_github_run_policy" "compromised_actions_policy_all_orgs" {
  owner    = "my-org"
  name     = "Compromised Actions Policy - All Orgs"
  all_orgs = true

  policy_config = {
    owner                             = "my-org"
    name                              = "Compromised Actions Policy - All Orgs"
    enable_compromised_actions_policy = true
  }
}

# Compromised Actions Policy Example (all_repos) - Blocks known compromised actions across all repos
resource "stepsecurity_github_run_policy" "compromised_actions_policy_all_repos" {
  owner     = "my-org"
  name      = "Compromised Actions Policy - All Repos"
  all_repos = true

  policy_config = {
    owner                             = "my-org"
    name                              = "Compromised Actions Policy - All Repos"
    enable_compromised_actions_policy = true
  }
}

# Compromised Actions Policy Example (dry_run) - Test compromised actions policy without enforcement
resource "stepsecurity_github_run_policy" "compromised_actions_policy_dry_run" {
  owner     = "my-org"
  name      = "Compromised Actions Policy - Dry Run"
  all_repos = true

  policy_config = {
    owner                             = "my-org"
    name                              = "Compromised Actions Policy - Dry Run"
    enable_compromised_actions_policy = true
    is_dry_run                        = true
  }
}

# Repository-Specific Policy Example - Applies action policy to specific repositories only
resource "stepsecurity_github_run_policy" "repo_specific_action_policy" {
  owner        = "my-org"
  name         = "Critical Repositories Action Policy"
  repositories = ["critical-app", "payment-service", "user-auth"]

  policy_config = {
    owner                = "my-org"
    name                 = "Critical Repositories Action Policy"
    enable_action_policy = true
    allowed_actions = {
      "actions/checkout"            = "allow"
      "step-security/harden-runner" = "allow"
      "actions/setup-node"          = "allow"
    }
  }
}

# Repository-Specific Policy Example - Applies runner policy to specific repositories only
resource "stepsecurity_github_run_policy" "repo_specific_runner_policy" {
  owner        = "my-org"
  name         = "Critical Repositories Runner Policy"
  repositories = ["critical-app", "payment-service"]

  policy_config = {
    owner                    = "my-org"
    name                     = "Critical Repositories Runner Policy"
    enable_runs_on_policy    = true
    disallowed_runner_labels = ["self-hosted", "windows-latest"]
  }
}

# For importing existing run policy to terraform state
# this will be helpful to manage existing policy using terraform
# alternative to this is to use terraform import command
import {
  to = stepsecurity_github_run_policy.run_policy
  id = "my-org/ACTUAL_POLICY_ID"
}