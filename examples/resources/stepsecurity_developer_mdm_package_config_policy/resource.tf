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

# Points managed devices' npm config (~/.npmrc) at the tenant's StepSecurity secure registry.
# The registry URL and the tenant's registry auth key are injected by StepSecurity at compile time.
resource "stepsecurity_developer_mdm_package_config_policy" "npm_secure_registry" {
  name        = "npm secure registry"
  description = "Route npm installs through the StepSecurity secure registry"
}

# A policy on its own enforces nothing; it has to be bundled into a profile and assigned.
# npm secure-registry enforcement runs on the agent channel, so this profile must use
# enforcement = "dmg" — an "mdm" profile never writes .npmrc.
resource "stepsecurity_developer_mdm_profile" "npm_secure_registry" {
  name        = "npm secure registry"
  enforcement = "dmg"

  policy_ids = [
    stepsecurity_developer_mdm_package_config_policy.npm_secure_registry.policy_id,
  ]

  assignment = {
    all_devices = true
  }
}
