
terraform {
  required_providers {
    stepsecurity = {
      source = "step-security/stepsecurity"
    }
  }
}

provider "stepsecurity" {
  api_key  = "09876"
  customer = "abcdefg"
}

data "stepsecurity_users" "users" {
}

output "users" {
  value = data.stepsecurity_users.users.users
}

