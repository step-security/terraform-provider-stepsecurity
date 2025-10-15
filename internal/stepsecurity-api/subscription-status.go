package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
)

type SubscriptionStatus struct {
	Tier            string          `json:"tier"`
	Status          string          `json:"status"`
	AppFeatureFlags AppFeatureFlags `json:"app_feature_flags"`
}

type AppFeatureFlags struct {
	IsPolicyDrivenPrV2Enabled bool `json:"is_policy_driven_pr_v2_enabled"`
}

func (c *APIClient) GetSubscriptionStatus(ctx context.Context, owner, repo string) (*SubscriptionStatus, error) {
	URI := fmt.Sprintf("%s/v1/github/%s/%s/actions/subscription-status", c.BaseURL, owner, repo)
	respBody, err := c.get(ctx, URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription status: %w", err)
	}

	var status SubscriptionStatus
	if err := json.Unmarshal(respBody, &status); err != nil {
		return nil, fmt.Errorf("failed to unmarshal subscription status: %w", err)
	}

	return &status, nil
}
