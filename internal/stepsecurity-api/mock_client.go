package stepsecurityapi

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// Mock client for testing - implements all required methods
type MockStepSecurityClient struct {
	mock.Mock
}

// User methods
func (m *MockStepSecurityClient) CreateUser(ctx context.Context, req CreateUserRequest) (*CreateUserResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*CreateUserResponse), args.Error(1)
}

func (m *MockStepSecurityClient) GetUser(ctx context.Context, id string) (*User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockStepSecurityClient) UpdateUser(ctx context.Context, req UpdateUserRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DeleteUser(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStepSecurityClient) ListUsers(ctx context.Context) ([]User, error) {
	args := m.Called(ctx)
	return args.Get(0).([]User), args.Error(1)
}

// GitHub Notification Settings methods
func (m *MockStepSecurityClient) CreateNotificationSettings(ctx context.Context, req GitHubNotificationSettingsRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockStepSecurityClient) GetNotificationSettings(ctx context.Context, owner string) (*NotificationSettings, error) {
	args := m.Called(ctx, owner)
	return args.Get(0).(*NotificationSettings), args.Error(1)
}

func (m *MockStepSecurityClient) UpdateNotificationSettings(ctx context.Context, req GitHubNotificationSettingsRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DeleteNotificationSettings(ctx context.Context, owner string) error {
	args := m.Called(ctx, owner)
	return args.Error(0)
}

// Policy-driven PR methods
func (m *MockStepSecurityClient) CreatePolicyDrivenPRPolicy(ctx context.Context, req PolicyDrivenPRPolicy) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockStepSecurityClient) GetPolicyDrivenPRPolicy(ctx context.Context, owner string) (*PolicyDrivenPRPolicy, error) {
	args := m.Called(ctx, owner)
	return args.Get(0).(*PolicyDrivenPRPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) UpdatePolicyDrivenPRPolicy(ctx context.Context, req PolicyDrivenPRPolicy, removedRepos []string) error {
	args := m.Called(ctx, req, removedRepos)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DeletePolicyDrivenPRPolicy(ctx context.Context, owner string, repos []string) error {
	args := m.Called(ctx, owner, repos)
	return args.Error(0)
}

func (m *MockStepSecurityClient) CreateGitHubPolicyStorePolicy(ctx context.Context, policy *GitHubPolicyStorePolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *MockStepSecurityClient) GetGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) (*GitHubPolicyStorePolicy, error) {
	args := m.Called(ctx, owner, policyName)
	return args.Get(0).(*GitHubPolicyStorePolicy), args.Error(1)
}

func (m *MockStepSecurityClient) DeleteGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) error {
	args := m.Called(ctx, owner, policyName)
	return args.Error(0)
}

func (m *MockStepSecurityClient) CreateSuppressionRule(ctx context.Context, rule SuppressionRule) (*SuppressionRule, error) {
	args := m.Called(ctx, rule)
	return args.Get(0).(*SuppressionRule), args.Error(1)
}

func (m *MockStepSecurityClient) ReadSuppressionRule(ctx context.Context, ruleID string) (*SuppressionRule, error) {
	args := m.Called(ctx, ruleID)
	return args.Get(0).(*SuppressionRule), args.Error(1)
}

func (m *MockStepSecurityClient) UpdateSuppressionRule(ctx context.Context, rule SuppressionRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DeleteSuppressionRule(ctx context.Context, ruleID string) error {
	args := m.Called(ctx, ruleID)
	return args.Error(0)
}
