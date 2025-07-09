# Copyright (c) HashiCorp, Inc.

terraform {
  required_providers {
    stepsecurity = {
      source = "registry.terraform.io/step-security/stepsecurity"
    }
  }
}

provider "stepsecurity" {
  api_key  = "09876"
  customer = "abcdefg"
}

# creates a githubuser in stepsecurity console to have read access to the organization.
resource "stepsecurity_user" "github_user" {
  user_name = "test-user-1"
  auth_type = "Github"
  policies = [
    {
      type         = "github"
      role         = "auditor"
      scope        = "organization"
      organization = "test-organization"
    }
  ]
}

# creates sso user in stepsecurity console to have tenant admin access to all organizations under the tenant.
resource "stepsecurity_user" "sso_user" {
  email     = "test-user-2@test.com"
  auth_type = "SSO"
  policies = [
    {
      type  = "github"
      role  = "admin"
      scope = "customer"
    }
  ]
}

# creates user that provides read access to the organization for all users with email suffix 'test.com'.
resource "stepsecurity_user" "email_suffix_user" {
  email_suffix = "test.com"
  auth_type    = "sso"
  policies = [
    {
      type         = "github"
      role         = "auditor"
      scope        = "organization"
      organization = "test-organization"
    }
  ]
}
