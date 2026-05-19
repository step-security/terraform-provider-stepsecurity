
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

resource "stepsecurity_github_supression_rule" "rule-secret-in-build-log" {
  name        = "test-secret-in-build-log"
  type        = "secret_in_build_log"
  action      = "ignore"
  description = "test"
  secret_type = "private-key"
  owner       = "test-owner"
  repo        = "test-repo"
  workflow    = "poc-detections.yml"
  job         = "*"
}

resource "stepsecurity_github_supression_rule" "rule-secret-in-artifact" {
  name          = "test-secret-in-artifact"
  type          = "secret_in_artifact"
  action        = "ignore"
  description   = "test"
  secret_type   = "github-pat"
  artifact_name = "build-artifact"
  owner         = "*"
  repo          = "*"
  workflow      = "*"
  job           = "*"
}

resource "stepsecurity_github_supression_rule" "rule-anomalous-outbound-network-call" {
  name        = "test-anomalous-outbound-network-call"
  type        = "anomalous_outbound_network_call"
  action      = "ignore"
  description = "test"
  destination = {
    domain = "4492e8135a9796de.example.com*"
  }
  process  = "*"
  owner    = "test-owner"
  repo     = "test-repo"
  workflow = "new-poc.yml"
  job      = "*"
}

resource "stepsecurity_github_supression_rule" "rule-suspicious-network-call" {
  name        = "test-suspicious-network-call"
  type        = "suspicious_network_call"
  action      = "ignore"
  description = "test"
  endpoint    = "https://example.com"
  owner       = "*"
  repo        = "*"
  workflow    = "*"
  job         = "*"
}

resource "stepsecurity_github_supression_rule" "rule-https-outbound-network-call" {
  name        = "test-https-outbound-network-call"
  type        = "https_outbound_network_call"
  action      = "ignore"
  description = "test"
  host        = "api.github.com*"
  file_path   = "/repos/experiments/github-actions-goat/actions/runners/registration-token"
  owner       = "test-owner"
  repo        = "agent-bravo-test"
  workflow    = "warp.yml"
  job         = "*"
}

resource "stepsecurity_github_supression_rule" "rule-source-code-overwritten" {
  name        = "test-source-code-overwritten"
  type        = "source_code_overwritten"
  action      = "ignore"
  description = "test"
  file        = "Dockerfile"
  file_path   = "*"
  owner       = "test-owner"
  repo        = "auto-pdpr-test-54996-5"
  workflow    = "codeql.yml"
  job         = "*"
}

resource "stepsecurity_github_supression_rule" "rule-action-uses-imposter-commit" {
  name          = "test-action-uses-imposter-commit"
  type          = "action_uses_imposter_commit"
  action        = "ignore"
  description   = "test"
  github_action = "step-security/dummy-compromised-action"
  owner         = "test-owner"
  repo          = "test-repo"
  workflow      = "poc_workflow_int.yml"
  job           = "*"
}

resource "stepsecurity_github_supression_rule" "rule-runner-worker-memory-read" {
  name        = "test-runner-worker-memory-read"
  type        = "runner_worker_memory_read"
  action      = "ignore"
  description = "test"
  process     = "python3"
  owner       = "test-owner"
  repo        = "test-repo"
  workflow    = "poc_workflow_int.yml"
  job         = "*"
}

resource "stepsecurity_github_supression_rule" "rule-privileged-container" {
  name        = "test-privileged-container"
  type        = "privileged_container"
  action      = "ignore"
  description = "test"
  process     = "docker"
  owner       = "*"
  repo        = "*"
  workflow    = "*"
  job         = "*"
}

resource "stepsecurity_github_supression_rule" "rule-reverse-shell" {
  name        = "test-reverse-shell"
  type        = "reverse_shell"
  action      = "ignore"
  description = "test"
  process     = "bash"
  owner       = "*"
  repo        = "*"
  workflow    = "*"
  job         = "*"
}
