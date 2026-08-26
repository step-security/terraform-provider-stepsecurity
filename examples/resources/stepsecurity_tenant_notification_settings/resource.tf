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

# Deliver to email and a Slack webhook, notify only on exact compromised
# versions, and subscribe to the Dev Machine Guard events that matter most.
#
# There is one notification record per tenant, so declare at most one instance
# of this resource.
resource "stepsecurity_tenant_notification_settings" "this" {
  notification_channels = {
    email             = "security@example.com"
    slack_webhook_url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
  }

  threat_intel = {
    enabled = true
    level   = "version" # all | name | version
  }

  developer_mdm = {
    new_ides           = true
    new_ide_extensions = true
    new_ai_agents      = true
    new_mcp_servers    = true
    new_agent_skills   = false
    suspicious_files   = true
    config_changes     = false
  }
}

# Dev Machine Guard only, delivered to Microsoft Teams. threat_intel is still
# required: this resource owns the whole record, so every section states its
# intent explicitly rather than leaving it to whatever was there before.
resource "stepsecurity_tenant_notification_settings" "dev_machine_guard_only" {
  notification_channels = {
    teams_webhook_url = "https://example.webhook.office.com/webhookb2/00000000-0000-0000-0000-000000000000@00000000-0000-0000-0000-000000000000/IncomingWebhook/00000000000000000000000000000000/00000000-0000-0000-0000-000000000000"
  }

  threat_intel = {
    enabled = false
  }

  developer_mdm = {
    suspicious_files = true
    config_changes   = true
  }
}

# Deliver Slack notifications through the Slack app installed for the tenant
# instead of a webhook. Note that the StepSecurity API cannot clear
# slack_notification_method or slack_channel_id once set — omit them to leave
# the tenant's current values alone.
resource "stepsecurity_tenant_notification_settings" "slack_oauth" {
  notification_channels = {
    email                     = "security@example.com"
    slack_notification_method = "oauth"
    slack_channel_id          = "C0123456789"
  }

  threat_intel = {
    enabled = true
    level   = "all"
  }

  developer_mdm = {
    new_mcp_servers = true
  }
}

# For importing the tenant's existing notification settings into Terraform state.
# The tenant comes from the provider configuration, so the id is a placeholder.
import {
  to = stepsecurity_tenant_notification_settings.this
  id = "abcdefg"
}
