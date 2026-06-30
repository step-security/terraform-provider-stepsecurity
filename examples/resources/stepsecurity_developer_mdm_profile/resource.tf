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
    { publisher = "ms-python", name = "python", stable = true },
  ]
}

# Bundle one or more policies and assign them. Omit `assignment` to leave the
# profile unassigned; see the schema for the all_devices / device_ids options.
resource "stepsecurity_developer_mdm_profile" "engineering" {
  name        = "Engineering"
  description = "Approved IDE extensions for engineering"

  policy_ids = [
    stepsecurity_developer_mdm_ide_extension_policy.engineering_vscode.policy_id,
  ]

  assignment = {
    all_devices = true
  }
}
