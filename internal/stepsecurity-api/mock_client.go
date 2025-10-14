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

func (m *MockStepSecurityClient) GetPolicyDrivenPRPolicy(ctx context.Context, owner string, repos []string) (*PolicyDrivenPRPolicy, error) {
	args := m.Called(ctx, owner, repos)
	return args.Get(0).(*PolicyDrivenPRPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) DiscoverPolicyDrivenPRConfig(ctx context.Context, owner string) (*PolicyDrivenPRPolicy, error) {
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

func (m *MockStepSecurityClient) GetSubscriptionStatus(ctx context.Context, owner, repo string) (*SubscriptionStatus, error) {
	args := m.Called(ctx, owner, repo)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*SubscriptionStatus), args.Error(1)
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

func (m *MockStepSecurityClient) AttachGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string, request *GitHubPolicyAttachRequest) error {
	args := m.Called(ctx, owner, policyName, request)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DetachGitHubPolicyStorePolicy(ctx context.Context, owner string, policyName string) error {
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

// GitHub Run Policy methods
func (m *MockStepSecurityClient) ListRunPolicies(ctx context.Context, owner string) ([]RunPolicy, error) {
	args := m.Called(ctx, owner)
	return args.Get(0).([]RunPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) CreateRunPolicy(ctx context.Context, owner string, policy CreateRunPolicyRequest) (*RunPolicy, error) {
	args := m.Called(ctx, owner, policy)
	return args.Get(0).(*RunPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) GetRunPolicy(ctx context.Context, owner string, policyID string) (*RunPolicy, error) {
	args := m.Called(ctx, owner, policyID)
	return args.Get(0).(*RunPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) UpdateRunPolicy(ctx context.Context, owner string, policyID string, policy UpdateRunPolicyRequest) (*RunPolicy, error) {
	args := m.Called(ctx, owner, policyID, policy)
	return args.Get(0).(*RunPolicy), args.Error(1)
}

func (m *MockStepSecurityClient) DeleteRunPolicy(ctx context.Context, owner string, policyID string) error {
	args := m.Called(ctx, owner, policyID)
	return args.Error(0)
}

// GitHub PR Checks methods
func (m *MockStepSecurityClient) GetPRChecksConfig(ctx context.Context, owner string) (GitHubPRChecksConfig, error) {
	args := m.Called(ctx, owner)
	return args.Get(0).(GitHubPRChecksConfig), args.Error(1)
}

func (m *MockStepSecurityClient) UpdatePRChecksConfig(ctx context.Context, owner string, req GitHubPRChecksConfig) error {
	args := m.Called(ctx, owner, req)
	return args.Error(0)
}

func (m *MockStepSecurityClient) DeletePRChecksConfig(ctx context.Context, owner string) error {
	args := m.Called(ctx, owner)
	return args.Error(0)
}
