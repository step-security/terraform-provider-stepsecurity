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

# Allowlist permitting only the listed VS Code extensions; everything else is blocked.
resource "stepsecurity_developer_mdm_ide_extension_policy" "engineering_vscode" {
  name        = "Engineering VS Code allowlist"
  description = "Only approved extensions for engineering workstations"
  mode        = "allowlist"

  rules = [
    { publisher = "ms-python", name = "python", stable = true },           # stable channel
    { publisher = "github" },                                              # whole publisher
    { publisher = "redhat", name = "vscode-yaml", versions = ["1.15.0"] }, # pinned version
  ]
}
