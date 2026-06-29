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

resource "stepsecurity_developer_mdm_ide_extension_policy" "engineering_vscode" {
  name = "Engineering VS Code allowlist"
  mode = "allowlist"

  rules = [
    {
      publisher = "ms-python"
      name      = "python"
      stable    = true
    },
  ]
}

# Unassigned profile: bundles policies but is not applied to any device yet.
# A profile may reference at most one policy per category.
resource "stepsecurity_developer_mdm_profile" "unassigned" {
  name        = "Engineering (unassigned)"
  description = "Staged profile, not yet rolled out"

  policy_ids = [
    stepsecurity_developer_mdm_ide_extension_policy.engineering_vscode.policy_id,
  ]
}

# All-devices assignment: applies to all current and future devices,
# unless a device-specific profile overrides a device.
resource "stepsecurity_developer_mdm_profile" "all_devices" {
  name = "Engineering (all devices)"

  policy_ids = [
    stepsecurity_developer_mdm_ide_extension_policy.engineering_vscode.policy_id,
  ]

  assignment = {
    all_devices = true
  }
}

# Device-specific assignment: applies only to the listed device IDs.
# `device_ids` cannot be combined with `all_devices = true`.
resource "stepsecurity_developer_mdm_profile" "specific_devices" {
  name = "Engineering (specific devices)"

  policy_ids = [
    stepsecurity_developer_mdm_ide_extension_policy.engineering_vscode.policy_id,
  ]

  assignment = {
    device_ids = ["device-1", "device-2"]
  }
}
