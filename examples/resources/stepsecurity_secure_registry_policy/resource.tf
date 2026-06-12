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

# Enable both controls for the npm registry
resource "stepsecurity_secure_registry_policy" "npm_full" {
  registry = "npm"

  cooldown_control = {
    enabled        = true
    period_in_days = 7
    exemption_list = ["@babel/core@*", "react", "@scope/*", "lodash@4.17.21"]
  }

  compromised_packages_control = {
    enabled = true
  }
}

# Enable only the compromised packages control
resource "stepsecurity_secure_registry_policy" "npm_compromised_only" {
  registry = "npm"

  compromised_packages_control = {
    enabled = true
  }
}

# Enable only the cooldown control with no exemptions
resource "stepsecurity_secure_registry_policy" "npm_cooldown_only" {
  registry = "npm"

  cooldown_control = {
    enabled        = true
    period_in_days = 3
  }
}

# For importing an existing npm registry policy into Terraform state
# alternative to this is to use the terraform import command
import {
  to = stepsecurity_secure_registry_policy.npm_full
  id = "npm"
}

# Enable both controls for the PyPI registry
resource "stepsecurity_secure_registry_policy" "pypi_full" {
  registry = "pypi"

  cooldown_control = {
    enabled        = true
    period_in_days = 7
    exemption_list = ["requests@*", "django@1.*", "flask@3.0.3"]
  }

  compromised_packages_control = {
    enabled = true
  }
}

# Enable only the compromised packages control for PyPI
resource "stepsecurity_secure_registry_policy" "pypi_compromised_only" {
  registry = "pypi"

  compromised_packages_control = {
    enabled = true
  }
}

# Enable only the cooldown control for PyPI with no exemptions
resource "stepsecurity_secure_registry_policy" "pypi_cooldown_only" {
  registry = "pypi"

  cooldown_control = {
    enabled        = true
    period_in_days = 3
  }
}

# For importing an existing PyPI registry policy into Terraform state
import {
  to = stepsecurity_secure_registry_policy.pypi_full
  id = "pypi"
}
