// Copyright (c) HashiCorp, Inc.

package stepsecurityapi

import (
	"context"
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
	GetPolicyDrivenPRPolicy(ctx context.Context, owner string) (*PolicyDrivenPRPolicy, error)
	UpdatePolicyDrivenPRPolicy(ctx context.Context, updateRequest PolicyDrivenPRPolicy, removedRepos []string) error
	DeletePolicyDrivenPRPolicy(ctx context.Context, owner string, repos []string) error
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
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}

	return body, err
}
