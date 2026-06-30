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

# Read-only: compile a profile's import artifact for an OS. Creates no remote
# object. `os` is windows | macos | linux; category/target default per schema.
data "stepsecurity_developer_mdm_profile_export" "macos" {
  profile_id = "f591dc70-0164-4216-9f41-1ec4d7c62226"
  os         = "macos"
}

# `content` is the decoded artifact body — pass it straight to local_file.content
# (do not jsondecode). filename, content_type, and hash are also exported.
output "export_filename" {
  value = data.stepsecurity_developer_mdm_profile_export.macos.filename
}
