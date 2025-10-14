package stepsecurityapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Client interface {

	// Users
	ListUsers(ctx context.Context) ([]User, error)
	CreateUser(ctx context.Context, user CreateUserRequest) (*CreateUserResponse, error)
	GetUser(ctx context.Context, userID string) (*User, error)
	UpdateUser(ctx context.Context, updateRequest UpdateUserRequest) error
	DeleteUser(ctx context.Context, userID string) error

	// GitHub Notification Settings
	CreateNotificationSettings(ctx context.Context, notificationSettingsReq GitHubNotificationSettingsRequest) error
	GetNotificationSettings(ctx context.Context, owner string) (*NotificationSettings, error)
	UpdateNotificationSettings(ctx context.Context, notificationSettingsReq GitHubNotificationSettingsRequest) error
	DeleteNotificationSettings(ctx context.Context, owner string) error

	// policy-driven PRs
	CreatePolicyDrivenPRPolicy(ctx context.Context, createRequest PolicyDrivenPRPolicy) error
	GetPolicyDrivenPRPolicy(ctx context.Context, owner string, repos []string) (*PolicyDrivenPRPolicy, error)
	DiscoverPolicyDrivenPRConfig(ctx context.Context, owner string) (*PolicyDrivenPRPolicy, error)
	UpdatePolicyDrivenPRPolicy(ctx context.Context, updateRequest PolicyDrivenPRPolicy, removedRepos []string) error
	DeletePolicyDrivenPRPolicy(ctx context.Context, owner string, repos []string) error
	GetSubscriptionStatus(ctx context.Context, owner, repo string) (*SubscriptionStatus, error)

	// GitHub Policy Store
	CreateGitHubPolicyStorePolicy(ctx context.Context, policy *GitHubPolicyStorePolicy) error
	GetGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) (*GitHubPolicyStorePolicy, error)
	DeleteGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) error
	AttachGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string, request *GitHubPolicyAttachRequest) error
	DetachGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) error

	// Suppression Rules
	CreateSuppressionRule(ctx context.Context, rule SuppressionRule) (*SuppressionRule, error)
	ReadSuppressionRule(ctx context.Context, ruleID string) (*SuppressionRule, error)
	UpdateSuppressionRule(ctx context.Context, rule SuppressionRule) error
	DeleteSuppressionRule(ctx context.Context, ruleID string) error

	// GitHub Run Policies
	ListRunPolicies(ctx context.Context, owner string) ([]RunPolicy, error)
	CreateRunPolicy(ctx context.Context, owner string, policy CreateRunPolicyRequest) (*RunPolicy, error)
	GetRunPolicy(ctx context.Context, owner string, policyID string) (*RunPolicy, error)
	UpdateRunPolicy(ctx context.Context, owner string, policyID string, policy UpdateRunPolicyRequest) (*RunPolicy, error)
	DeleteRunPolicy(ctx context.Context, owner string, policyID string) error

	GetPRChecksConfig(ctx context.Context, owner string) (GitHubPRChecksConfig, error)
	UpdatePRChecksConfig(ctx context.Context, owner string, req GitHubPRChecksConfig) error
	DeletePRChecksConfig(ctx context.Context, owner string) error
}

type APIClient struct {
	HTTPClient *http.Client
	BaseURL    string
	APIKey     string
	Customer   string
}

func NewClient(baseURL, apiKey, customer string) (Client, error) {
	return &APIClient{
		HTTPClient: &http.Client{},
		BaseURL:    baseURL,
		APIKey:     apiKey,
		Customer:   customer,
	}, nil
}

func (c *APIClient) do(req *http.Request) ([]byte, error) {
	if req == nil {
		return nil, nil
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated || res.StatusCode == http.StatusNoContent {
		return body, err
	}

	return nil, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
}

func (c *APIClient) get(ctx context.Context, URI string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", URI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *APIClient) update(ctx context.Context, URI string, payload any, method string) ([]byte, error) {
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, URI, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	return c.do(httpReq)
}

func (c *APIClient) post(ctx context.Context, URI string, payload any) ([]byte, error) {
	return c.update(ctx, URI, payload, "POST")
}

func (c *APIClient) put(ctx context.Context, URI string, payload any) ([]byte, error) {
	return c.update(ctx, URI, payload, "PUT")
}

func (c *APIClient) delete(ctx context.Context, URI string) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "DELETE", URI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	return c.do(httpReq)
}
