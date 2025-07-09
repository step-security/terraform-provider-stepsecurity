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

# github repo notification settings for findings detected by stepsecurity.
resource "stepsecurity_github_org_notification_settings" "test-organization" {
  owner = "test-organization"
  notification_channels = {
    slack_webhook_url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    teams_webhook_url = "https://outlook.office.com/webhook/00000000-0000-0000-0000-000000000000@00000000-0000-0000-0000-000000000000/IncomingWebhook/00000000000000000000000000000000"
    email             = "step-security@step-security.com"
  }
  notification_events = {
    domain_blocked                        = true
    file_overwrite                        = true
    new_endpoint_discovered               = true
    https_detections                      = true
    secrets_detected                      = true
    artifacts_secrets_detected            = true
    imposter_commits_detected             = true
    suspicious_network_call_detected      = true
    suspicious_process_events_detected    = true
    harden_runner_config_changes_detected = true
    non_compliant_artifact_detected       = false
    run_blocked_by_policy                 = false
  }
}
