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

# Allowlist: permit only the listed extensions and block everything else.
# Mixes a stable-channel allow, a whole-publisher allow, and exact version pins.
resource "stepsecurity_developer_mdm_ide_extension_policy" "engineering_vscode" {
  name        = "Engineering VS Code allowlist"
  description = "Only approved extensions for engineering workstations"
  mode        = "allowlist"

  rules = [
    # Allow the stable channel of a specific extension.
    {
      publisher = "ms-python"
      name      = "python"
      stable    = true
    },
    # Allow every extension from a publisher (omit name).
    {
      publisher = "github"
    },
    # Pin exact versions. `versions` is allowlist-only and requires `name`.
    # An optional `@platform` suffix targets a platform-specific build.
    {
      publisher = "redhat"
      name      = "vscode-yaml"
      versions  = ["1.15.0", "1.15.0@linux-x64"]
    },
  ]
}

# Blocklist: block the listed extensions and allow everything else.
# `versions` and `stable` are not valid on blocklist rules.
resource "stepsecurity_developer_mdm_ide_extension_policy" "blocked_extensions" {
  name        = "Blocked extensions"
  description = "Deny known-bad publishers and extensions"
  mode        = "blocklist"

  rules = [
    {
      publisher = "suspicious-publisher"
    },
    {
      publisher = "another-publisher"
      name      = "risky-extension"
    },
  ]
}

# Empty rules are valid but powerful. Set them deliberately:
#   - An empty `allowlist` blocks EVERY extension.
#   - An empty `blocklist` allows EVERY extension.
resource "stepsecurity_developer_mdm_ide_extension_policy" "block_all" {
  name  = "Block all extensions"
  mode  = "allowlist"
  rules = []
}
