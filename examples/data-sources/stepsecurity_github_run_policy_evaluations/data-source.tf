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

# Organization-level evaluations - retrieve all run policy evaluations
data "stepsecurity_github_run_policy_evaluations" "org_all_evaluations" {
  owner = "my-org"
}

# Organization-level evaluations - retrieve only blocked evaluations
data "stepsecurity_github_run_policy_evaluations" "org_blocked_evaluations" {
  owner  = "my-org"
  status = "Blocked"
}

# Organization-level evaluations - retrieve only allowed evaluations
data "stepsecurity_github_run_policy_evaluations" "org_allowed_evaluations" {
  owner  = "my-org"
  status = "Allowed"
}

# Repository-level evaluations - retrieve all run policy evaluations for a specific repo
data "stepsecurity_github_run_policy_evaluations" "repo_all_evaluations" {
  owner = "my-org"
  repo  = "my-repository"
}

# Repository-level evaluations - retrieve only blocked evaluations for a specific repo
data "stepsecurity_github_run_policy_evaluations" "repo_blocked_evaluations" {
  owner  = "my-org"
  repo   = "my-repository"
  status = "Blocked"
}

# Repository-level evaluations - retrieve only allowed evaluations for a specific repo
data "stepsecurity_github_run_policy_evaluations" "repo_allowed_evaluations" {
  owner  = "my-org"
  repo   = "my-repository"
  status = "Allowed"
}

# Organization-level outputs
output "organization_security_summary" {
  value = {
    total_evaluations = length(data.stepsecurity_github_run_policy_evaluations.org_all_evaluations.evaluations)
    blocked_runs      = length(data.stepsecurity_github_run_policy_evaluations.org_blocked_evaluations.evaluations)
    allowed_runs      = length(data.stepsecurity_github_run_policy_evaluations.org_allowed_evaluations.evaluations)
    success_rate = length(data.stepsecurity_github_run_policy_evaluations.org_all_evaluations.evaluations) > 0 ? (
      length(data.stepsecurity_github_run_policy_evaluations.org_allowed_evaluations.evaluations) /
      length(data.stepsecurity_github_run_policy_evaluations.org_all_evaluations.evaluations) * 100
    ) : 0
  }
}

# Repository-level outputs
output "repository_security_summary" {
  value = {
    total_evaluations = length(data.stepsecurity_github_run_policy_evaluations.repo_all_evaluations.evaluations)
    blocked_runs      = length(data.stepsecurity_github_run_policy_evaluations.repo_blocked_evaluations.evaluations)
    allowed_runs      = length(data.stepsecurity_github_run_policy_evaluations.repo_allowed_evaluations.evaluations)
    success_rate = length(data.stepsecurity_github_run_policy_evaluations.repo_all_evaluations.evaluations) > 0 ? (
      length(data.stepsecurity_github_run_policy_evaluations.repo_allowed_evaluations.evaluations) /
      length(data.stepsecurity_github_run_policy_evaluations.repo_all_evaluations.evaluations) * 100
    ) : 0
  }
}

# Repositories with security violations (organization-level)
output "repositories_with_violations" {
  value = distinct([
    for evaluation in data.stepsecurity_github_run_policy_evaluations.org_blocked_evaluations.evaluations :
    evaluation.repo_full_name
  ])
}

# Policy violation breakdown (can be used for both org and repo level)
locals {
  org_violation_types = {
    secret_violations = [
      for evaluation in data.stepsecurity_github_run_policy_evaluations.org_blocked_evaluations.evaluations :
      {
        repo_full_name = evaluation.repo_full_name
        workflow_name  = evaluation.workflow_name
        run_id         = evaluation.run_id
        commit_message = evaluation.commit_message
        head_branch    = evaluation.head_branch
      }
      if anytrue([
        for result in evaluation.policy_results :
        result.secrets_policy_status == "Blocked"
      ])
    ]

    action_violations = [
      for evaluation in data.stepsecurity_github_run_policy_evaluations.org_blocked_evaluations.evaluations :
      {
        repo_full_name = evaluation.repo_full_name
        workflow_name  = evaluation.workflow_name
        run_id         = evaluation.run_id
        commit_message = evaluation.commit_message
        head_branch    = evaluation.head_branch
        actions_blocked = flatten([
          for result in evaluation.policy_results :
          result.actions_not_allowed if result.action_policy_status == "Blocked"
        ])
      }
      if anytrue([
        for result in evaluation.policy_results :
        result.action_policy_status == "Blocked"
      ])
    ]

    compromised_action_violations = [
      for evaluation in data.stepsecurity_github_run_policy_evaluations.org_blocked_evaluations.evaluations :
      {
        repo_full_name = evaluation.repo_full_name
        workflow_name  = evaluation.workflow_name
        run_id         = evaluation.run_id
        commit_message = evaluation.commit_message
        head_branch    = evaluation.head_branch
        compromised_actions = flatten([
          for result in evaluation.policy_results :
          result.compromised_actions_detected if result.compromised_actions_policy_status == "Blocked"
        ])
      }
      if anytrue([
        for result in evaluation.policy_results :
        result.compromised_actions_policy_status == "Blocked"
      ])
    ]

    runner_violations = [
      for evaluation in data.stepsecurity_github_run_policy_evaluations.org_blocked_evaluations.evaluations :
      {
        repo_full_name = evaluation.repo_full_name
        workflow_name  = evaluation.workflow_name
        run_id         = evaluation.run_id
        commit_message = evaluation.commit_message
        head_branch    = evaluation.head_branch
        disallowed_runner_labels = flatten([
          for result in evaluation.policy_results :
          result.runner_labels_not_allowed if result.runs_on_policy_status == "Blocked"
        ])
      }
      if anytrue([
        for result in evaluation.policy_results :
        result.runs_on_policy_status == "Blocked"
      ])
    ]
  }

  repo_violation_types = {
    secret_violations = [
      for evaluation in data.stepsecurity_github_run_policy_evaluations.repo_blocked_evaluations.evaluations :
      {
        repo_full_name = evaluation.repo_full_name
        workflow_name  = evaluation.workflow_name
        run_id         = evaluation.run_id
        commit_message = evaluation.commit_message
        head_branch    = evaluation.head_branch
      }
      if anytrue([
        for result in evaluation.policy_results :
        result.secrets_policy_status == "Blocked"
      ])
    ]

    action_violations = [
      for evaluation in data.stepsecurity_github_run_policy_evaluations.repo_blocked_evaluations.evaluations :
      {
        repo_full_name = evaluation.repo_full_name
        workflow_name  = evaluation.workflow_name
        run_id         = evaluation.run_id
        commit_message = evaluation.commit_message
        head_branch    = evaluation.head_branch
        actions_blocked = flatten([
          for result in evaluation.policy_results :
          result.actions_not_allowed if result.action_policy_status == "Blocked"
        ])
      }
      if anytrue([
        for result in evaluation.policy_results :
        result.action_policy_status == "Blocked"
      ])
    ]
  }
}

output "org_violation_breakdown" {
  value = {
    secret_policy_violations      = length(local.org_violation_types.secret_violations)
    action_policy_violations      = length(local.org_violation_types.action_violations)
    compromised_action_violations = length(local.org_violation_types.compromised_action_violations)
    runner_policy_violations      = length(local.org_violation_types.runner_violations)
  }
}

output "repo_violation_breakdown" {
  value = {
    secret_policy_violations = length(local.repo_violation_types.secret_violations)
    action_policy_violations = length(local.repo_violation_types.action_violations)
  }
}

# Workflow analysis for organization
locals {
  org_workflow_stats = {
    for workflow_key, evaluations in groupby(
      data.stepsecurity_github_run_policy_evaluations.org_all_evaluations.evaluations,
      "workflow_name"
      ) : workflow_key => {
      total_runs = length(evaluations)
      blocked_runs = length([
        for eval in evaluations : eval
        if eval.status == "Blocked"
      ])
      repositories = distinct([
        for eval in evaluations : eval.repo_full_name
      ])
      violation_rate = length(evaluations) > 0 ? (
        length([for eval in evaluations : eval if eval.status == "Blocked"]) /
        length(evaluations) * 100
      ) : 0
    }
  }

  repo_workflow_stats = {
    for workflow_key, evaluations in groupby(
      data.stepsecurity_github_run_policy_evaluations.repo_all_evaluations.evaluations,
      "workflow_name"
      ) : workflow_key => {
      total_runs = length(evaluations)
      blocked_runs = length([
        for eval in evaluations : eval
        if eval.status == "Blocked"
      ])
      violation_rate = length(evaluations) > 0 ? (
        length([for eval in evaluations : eval if eval.status == "Blocked"]) /
        length(evaluations) * 100
      ) : 0
    }
  }
}

output "org_workflow_violation_stats" {
  value = [
    for workflow_name, stats in local.org_workflow_stats : {
      workflow_name  = workflow_name
      total_runs     = stats.total_runs
      blocked_runs   = stats.blocked_runs
      violation_rate = stats.violation_rate
      repositories   = stats.repositories
    } if stats.violation_rate > 0
  ]
}

output "repo_workflow_violation_stats" {
  value = [
    for workflow_name, stats in local.repo_workflow_stats : {
      workflow_name  = workflow_name
      total_runs     = stats.total_runs
      blocked_runs   = stats.blocked_runs
      violation_rate = stats.violation_rate
    } if stats.violation_rate > 0
  ]
}

# Generate comprehensive security reports
resource "local_file" "org_security_report" {
  content = templatefile("${path.module}/templates/org_security_report.md.tpl", {
    owner = data.stepsecurity_github_run_policy_evaluations.org_all_evaluations.owner

    # Summary stats
    total_evaluations = length(data.stepsecurity_github_run_policy_evaluations.org_all_evaluations.evaluations)
    blocked_runs      = length(data.stepsecurity_github_run_policy_evaluations.org_blocked_evaluations.evaluations)
    allowed_runs      = length(data.stepsecurity_github_run_policy_evaluations.org_allowed_evaluations.evaluations)
    success_rate = length(data.stepsecurity_github_run_policy_evaluations.org_all_evaluations.evaluations) > 0 ? (
      length(data.stepsecurity_github_run_policy_evaluations.org_allowed_evaluations.evaluations) /
      length(data.stepsecurity_github_run_policy_evaluations.org_all_evaluations.evaluations) * 100
    ) : 0

    # Detailed breakdowns
    violation_types = local.org_violation_types
    workflow_stats = [
      for workflow_name, stats in local.org_workflow_stats : {
        workflow_name  = workflow_name
        total_runs     = stats.total_runs
        blocked_runs   = stats.blocked_runs
        violation_rate = stats.violation_rate
        repositories   = stats.repositories
      } if stats.violation_rate > 0
    ]
    repositories_with_violations = distinct([
      for evaluation in data.stepsecurity_github_run_policy_evaluations.org_blocked_evaluations.evaluations :
      evaluation.repo_full_name
    ])
  })

  filename = "${path.module}/org_security_report_${formatdate("YYYY-MM-DD", timestamp())}.md"
}

resource "local_file" "repo_security_report" {
  content = templatefile("${path.module}/templates/repo_security_report.md.tpl", {
    owner = data.stepsecurity_github_run_policy_evaluations.repo_all_evaluations.owner
    repo  = "my-repository" # Since repo parameter is only in config, not in state

    # Summary stats
    total_evaluations = length(data.stepsecurity_github_run_policy_evaluations.repo_all_evaluations.evaluations)
    blocked_runs      = length(data.stepsecurity_github_run_policy_evaluations.repo_blocked_evaluations.evaluations)
    allowed_runs      = length(data.stepsecurity_github_run_policy_evaluations.repo_allowed_evaluations.evaluations)
    success_rate = length(data.stepsecurity_github_run_policy_evaluations.repo_all_evaluations.evaluations) > 0 ? (
      length(data.stepsecurity_github_run_policy_evaluations.repo_allowed_evaluations.evaluations) /
      length(data.stepsecurity_github_run_policy_evaluations.repo_all_evaluations.evaluations) * 100
    ) : 0

    # Detailed breakdowns
    violation_types = local.repo_violation_types
    workflow_stats = [
      for workflow_name, stats in local.repo_workflow_stats : {
        workflow_name  = workflow_name
        total_runs     = stats.total_runs
        blocked_runs   = stats.blocked_runs
        violation_rate = stats.violation_rate
      } if stats.violation_rate > 0
    ]
  })

  filename = "${path.module}/repo_security_report_${formatdate("YYYY-MM-DD", timestamp())}.md"
}