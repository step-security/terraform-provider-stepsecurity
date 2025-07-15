package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
)

type GitHubPolicyStorePolicy struct {
	Owner                 string   `json:"owner"`
	PolicyName            string   `json:"policyName"`
	AllowedEndpoints      []string `json:"allowed_endpoints"`
	EgressPolicy          string   `json:"egress_policy"`
	DisableTelemetry      bool     `json:"disable_telemetry"`
	DisableSudo           bool     `json:"disable_sudo"`
	DisableFileMonitoring bool     `json:"disable_file_monitoring"`
}

func (c *APIClient) CreateGitHubPolicyStorePolicy(ctx context.Context, policy *GitHubPolicyStorePolicy) error {
	if policy == nil {
		return fmt.Errorf("empty policy provided")
	}
	URI := fmt.Sprintf("%s/v1/github/%s/actions/policies/%s", c.BaseURL, policy.Owner, policy.PolicyName)
	_, err := c.post(ctx, URI, policy)
	if err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}
	return nil
}

func (c *APIClient) GetGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) (*GitHubPolicyStorePolicy, error) {
	URI := fmt.Sprintf("%s/v1/github/%s/actions/policies/%s", c.BaseURL, owner, policyName)
	respBody, err := c.get(ctx, URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}
	var policy GitHubPolicyStorePolicy
	if err := json.Unmarshal(respBody, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return &policy, nil
}

func (c *APIClient) DeleteGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) error {
	URI := fmt.Sprintf("%s/v1/github/%s/actions/policies/%s", c.BaseURL, owner, policyName)
	_, err := c.delete(ctx, URI)
	if err != nil {
		return fmt.Errorf("failed to delete config: %w", err)
	}
	return nil
}
