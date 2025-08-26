#!/bin/bash

# GitHub run policies can be imported using the owner and policy ID separated by a forward slash
# Format: owner/policy_id

# Replace 'my-org' with your GitHub organization name
# Replace 'policy-id-12345' with the actual policy ID from StepSecurity
terraform import stepsecurity_github_run_policy.action_policy my-org/policy-id-12345

# You can find the policy ID by:
# 1. Using the stepsecurity_github_run_policies data source
# 2. Checking the StepSecurity dashboard
# 3. Using the StepSecurity API directly:
#    GET https://agent.api.stepsecurity.io/v1/github/my-org/actions/run-policies