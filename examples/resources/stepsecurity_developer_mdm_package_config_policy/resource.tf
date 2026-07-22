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
# The registry URL and per-device auth token are injected by StepSecurity at compile time.
resource "stepsecurity_developer_mdm_package_config_policy" "npm_secure_registry" {
  name        = "npm secure registry"
  description = "Route npm installs through the StepSecurity secure registry"
}
