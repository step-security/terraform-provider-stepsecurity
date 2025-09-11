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


# Policy attachment with specific workflows
resource "stepsecurity_github_policy_store_attachment" "workflow-attachment" {
  owner       = "test-organization"
  policy_name = "workflow-policy"

  org = {
    apply_to_org = false
    repositories = [
      {
        name          = "myrepo"
        apply_to_repo = false
        workflows     = ["ci.yml", "deploy.yml"]
      },
      {
        name          = "other-repo"
        apply_to_repo = false
        workflows     = ["test.yml"]
      }
    ]
  }
}

# Policy attachment to entire repositories
resource "stepsecurity_github_policy_store_attachment" "repo-attachment" {
  owner       = "test-organization"
  policy_name = "repo-policy"

  org = {
    apply_to_org = false
    repositories = [
      {
        name          = "frontend-app"
        apply_to_repo = true
        workflows     = []
      },
      {
        name          = "backend-api"
        apply_to_repo = true
        workflows     = []
      },
      {
        name          = "shared-libs"
        apply_to_repo = true
        workflows     = []
      }
    ]
  }
}

# Policy attachment to entire organization
resource "stepsecurity_github_policy_store_attachment" "org-attachment" {
  owner       = "test-organization"
  policy_name = "org-policy"

  org = {
    apply_to_org = true
    repositories = []
  }
}

# Policy attachment to clusters
resource "stepsecurity_github_policy_store_attachment" "cluster-attachment" {
  owner       = "test-organization"
  policy_name = "cluster-policy"

  clusters = [
    "production-k8s-cluster",
    "staging-k8s-cluster"
  ]
}

# Complex attachment with mixed org and cluster attachments
resource "stepsecurity_github_policy_store_attachment" "mixed-attachment" {
  owner       = "test-organization"
  policy_name = "workflow-policy"

  org = {
    apply_to_org = false
    repositories = [
      {
        name          = "critical-repo"
        apply_to_repo = true
        workflows     = []
      },
      {
        name          = "staging-repo"
        apply_to_repo = false
        workflows     = ["test.yml", "deploy-staging.yml"]
      }
    ]
  }

  clusters = [
    "dev-k8s-cluster"
  ]
}

# For importing existing policy attachments to terraform state
import {
  to = stepsecurity_github_policy_store_attachment.workflow-attachment
  id = "test-organization:::workflow-policy" # format is <owner>:::<policy_name>
}