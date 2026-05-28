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

# A read-only role that grants visibility into Workflow Runs, Baseline,
# Detections, and the Reports dashboard. Useful for security analysts who
# audit but don't need to mutate any state.
resource "stepsecurity_role" "security_analyst" {
  name        = "security-analyst"
  description = "Read-only access to runs, baseline, detections, reports."
  permissions = [
    { resource = "workflow-runs", action = "read" },
    { resource = "baseline",      action = "read" },
    { resource = "detections",    action = "read" },
    { resource = "reports",       action = "read" },
  ]
}

# A developer role that can manage detections + run policies but cannot touch
# admin-console resources (members, integrations, etc.).
resource "stepsecurity_role" "developer" {
  name        = "developer"
  description = "Can read all signals; can write detections + run policies."
  permissions = [
    { resource = "workflow-runs", action = "read" },
    { resource = "baseline",      action = "read" },
    { resource = "detections",    action = "read" },
    { resource = "detections",    action = "write" },
    { resource = "run-policies",  action = "read" },
    { resource = "run-policies",  action = "write" },
    { resource = "github-checks", action = "read" },
  ]
}

# Assign the role to a user. Note that the user resource accepts the custom
# role's *name* (not its UUID) — the API resolves the name to the role at
# request time, and renaming the role rewrites all assignments automatically.
resource "stepsecurity_user" "alice" {
  email     = "alice@example.com"
  auth_type = "SSO"
  policies = [
    {
      type  = "github"
      role  = stepsecurity_role.developer.name
      scope = "customer"
    }
  ]
}

# Importing an existing custom role into terraform state.
# The id is the role's UUID — visible in the console (Admin Console → Roles)
# or via `GET /v1/{customer}/roles`.
import {
  to = stepsecurity_role.developer
  id = "00000000-0000-0000-0000-000000000000"
}
