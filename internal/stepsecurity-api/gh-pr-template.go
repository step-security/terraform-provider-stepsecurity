package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
)

type GitHubPRTemplate struct {
	Title         string   `json:"title"`
	Summary       string   `json:"summary"`
	CommitMessage string   `json:"commit_message"`
	Labels        []string `json:"labels,omitempty"`
}

func (c *APIClient) GetGitHubPRTemplate(ctx context.Context, owner string) (*GitHubPRTemplate, error) {
	URI := fmt.Sprintf("%s/v1/github/%s/pr-template", c.BaseURL, owner)
	respBody, err := c.get(ctx, URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get PR template: %w", err)
	}

	var template GitHubPRTemplate
	if err := json.Unmarshal(respBody, &template); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PR template: %w", err)
	}

	return &template, nil
}

func (c *APIClient) UpdateGitHubPRTemplate(ctx context.Context, owner string, template GitHubPRTemplate) error {
	URI := fmt.Sprintf("%s/v1/github/%s/pr-template", c.BaseURL, owner)
	_, err := c.post(ctx, URI, template)
	if err != nil {
		return fmt.Errorf("failed to update PR template: %w", err)
	}

	return nil
}
