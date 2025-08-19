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

# Retrieve all run policies for an organization
data "stepsecurity_github_run_policies" "all_policies" {
  owner = "my-org"
}

# Output the total number of policies
output "total_policies" {
  value = length(data.stepsecurity_github_run_policies.all_policies.run_policies)
}

# Output all policy names
output "policy_names" {
  value = [for policy in data.stepsecurity_github_run_policies.all_policies.run_policies : policy.name]
}

# Output policies by type
output "action_policies" {
  description = "Policies that control allowed GitHub Actions"
  value = [
    for policy in data.stepsecurity_github_run_policies.all_policies.run_policies :
    {
      name            = policy.name
      policy_id       = policy.policy_id
      allowed_actions = policy.policy_config.allowed_actions
    }
    if policy.policy_config.enable_action_policy
  ]
}

output "runner_policies" {
  description = "Policies that control allowed runner labels"
  value = [
    for policy in data.stepsecurity_github_run_policies.all_policies.run_policies :
    {
      name                     = policy.name
      policy_id                = policy.policy_id
      disallowed_runner_labels = policy.policy_config.disallowed_runner_labels
    }
    if policy.policy_config.enable_runs_on_policy
  ]
}

output "secrets_policies" {
  description = "Policies that prevent secrets exfiltration"
  value = [
    for policy in data.stepsecurity_github_run_policies.all_policies.run_policies :
    {
      name      = policy.name
      policy_id = policy.policy_id
      all_repos = policy.all_repos
      all_orgs  = policy.all_orgs
    }
    if policy.policy_config.enable_secrets_policy
  ]
}

output "compromised_action_policies" {
  description = "Policies that block compromised actions"
  value = [
    for policy in data.stepsecurity_github_run_policies.all_policies.run_policies :
    {
      name      = policy.name
      policy_id = policy.policy_id
      all_repos = policy.all_repos
      all_orgs  = policy.all_orgs
    }
    if policy.policy_config.enable_compromised_actions_policy
  ]
}

# Output dry run policies
output "dry_run_policies" {
  description = "Policies running in dry-run mode"
  value = [
    for policy in data.stepsecurity_github_run_policies.all_policies.run_policies :
    policy.name
    if policy.policy_config.is_dry_run
  ]
}

# Filter policies by scope
locals {
  org_wide_policies = [
    for policy in data.stepsecurity_github_run_policies.all_policies.run_policies :
    policy if policy.all_orgs
  ]

  repo_wide_policies = [
    for policy in data.stepsecurity_github_run_policies.all_policies.run_policies :
    policy if policy.all_repos
  ]

  specific_repo_policies = [
    for policy in data.stepsecurity_github_run_policies.all_policies.run_policies :
    policy if length(policy.repositories) > 0
  ]
}

output "org_wide_policies" {
  description = "Policies that apply to all organizations"
  value       = local.org_wide_policies
}

output "repo_wide_policies" {
  description = "Policies that apply to all repositories"
  value       = local.repo_wide_policies
}

output "specific_repo_policies" {
  description = "Policies that apply to specific repositories"
  value       = local.specific_repo_policies
}

# Use the data to create a summary report
resource "local_file" "policy_summary" {
  content = templatefile("${path.module}/policy_summary.tpl", {
    policies    = data.stepsecurity_github_run_policies.all_policies.run_policies
    owner       = data.stepsecurity_github_run_policies.all_policies.owner
    total_count = length(data.stepsecurity_github_run_policies.all_policies.run_policies)
  })
  filename = "${path.module}/policy_summary.txt"
}