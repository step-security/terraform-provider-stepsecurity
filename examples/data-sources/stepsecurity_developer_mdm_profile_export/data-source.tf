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

# Export the compiled MDM artifact for each OS. This is read-only and creates
# no remote object. `os` must be one of "windows", "macos", or "linux".
# `category` is optional and defaults to "ide_extension".
# `target` is optional and defaults to "vscode".
data "stepsecurity_developer_mdm_profile_export" "windows" {
  profile_id = "f591dc70-0164-4216-9f41-1ec4d7c62226"
  os         = "windows"
  target     = "vscode"
}

data "stepsecurity_developer_mdm_profile_export" "linux" {
  profile_id = "f591dc70-0164-4216-9f41-1ec4d7c62226"
  os         = "linux"
  target     = "vscode"
}

data "stepsecurity_developer_mdm_profile_export" "macos" {
  profile_id = "f591dc70-0164-4216-9f41-1ec4d7c62226"
  os         = "macos"
  target     = "vscode"
}

# The `content` attribute is the decoded artifact body. Do not `jsondecode` it.
# It can be passed to another provider or exposed with `terraform output -raw`,
# though outputting full artifact content may be noisy.
output "linux_export_filename" {
  value = data.stepsecurity_developer_mdm_profile_export.linux.filename
}

output "linux_export_content_type" {
  value = data.stepsecurity_developer_mdm_profile_export.linux.content_type
}

output "linux_export_hash" {
  value = data.stepsecurity_developer_mdm_profile_export.linux.hash
}
