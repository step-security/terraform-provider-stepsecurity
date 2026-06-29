# One-command download workflow: export the artifact and write it to disk with
# HashiCorp's `local_file`. The StepSecurity provider does not manage local
# files; file side effects belong to the `hashicorp/local` provider.
#
# Notes:
#   - `terraform apply` writes files to the machine RUNNING Terraform. On
#     Terraform Cloud or CI, that is the remote runner, not your laptop.
#   - Do NOT `jsondecode` the export `content`; the provider already exposes the
#     decoded artifact body, ready to write as-is.
#   - For Linux, do NOT deserialize the inner `AllowedExtensions` value. VS Code's
#     Linux policy loader expects it to be a stringified JSON value.

terraform {
  required_providers {
    stepsecurity = {
      source = "step-security/stepsecurity"
    }

    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

provider "stepsecurity" {
  api_key  = "xxxxxxxx" # can also be set as env variable STEP_SECURITY_API_KEY
  customer = "abcdefg"  # can also be set as env variable STEP_SECURITY_CUSTOMER
}

data "stepsecurity_developer_mdm_profile_export" "windows" {
  profile_id = "f591dc70-0164-4216-9f41-1ec4d7c62226"
  os         = "windows"
}

data "stepsecurity_developer_mdm_profile_export" "linux" {
  profile_id = "f591dc70-0164-4216-9f41-1ec4d7c62226"
  os         = "linux"
}

data "stepsecurity_developer_mdm_profile_export" "macos" {
  profile_id = "f591dc70-0164-4216-9f41-1ec4d7c62226"
  os         = "macos"
}

resource "local_file" "windows_vscode_policy" {
  filename             = "${path.module}/exports/${data.stepsecurity_developer_mdm_profile_export.windows.filename}"
  content              = data.stepsecurity_developer_mdm_profile_export.windows.content
  file_permission      = "0644"
  directory_permission = "0755"
}

resource "local_file" "linux_vscode_policy" {
  filename             = "${path.module}/exports/${data.stepsecurity_developer_mdm_profile_export.linux.filename}"
  content              = data.stepsecurity_developer_mdm_profile_export.linux.content
  file_permission      = "0644"
  directory_permission = "0755"
}

resource "local_file" "macos_vscode_policy" {
  filename             = "${path.module}/exports/${data.stepsecurity_developer_mdm_profile_export.macos.filename}"
  content              = data.stepsecurity_developer_mdm_profile_export.macos.content
  file_permission      = "0644"
  directory_permission = "0755"
}
