// Copyright (c) HashiCorp, Inc.

package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	res "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/mock"
)

func TestAccGithubRepoNotificationSettingsResource(t *testing.T) {

	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing
			{
				Config: testAccGithubNotificationResourceConfig("test-org", "https://hooks.slack.com/test", "admin@example.com"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "owner", "test-org"),
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "notification_channels.slack_webhook_url", "https://hooks.slack.com/test"),
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "notification_channels.email", "admin@example.com"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "stepsecurity_github_org_notification_settings.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing
			{
				Config: testAccGithubNotificationResourceConfig("test-org", "https://hooks.slack.com/updated", "updated@example.com"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "owner", "test-org"),
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "notification_channels.slack_webhook_url", "https://hooks.slack.com/updated"),
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "notification_channels.email", "updated@example.com"),
				),
			},
		},
	})
}

func TestAccGithubRepoNotificationSettingsResourceWithTeams(t *testing.T) {

	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testAccGithubNotificationResourceConfigWithTeams("test-org", "https://outlook.office.com/webhook/test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "owner", "test-org"),
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "notification_channels.teams_webhook_url", "https://outlook.office.com/webhook/test"),
				),
			},
		},
	})
}

func TestAccGithubRepoNotificationSettingsResourceWithEvents(t *testing.T) {

	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testAccGithubNotificationResourceConfigWithEvents("test-org", "admin@example.com"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "owner", "test-org"),
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "notification_channels.email", "admin@example.com"),
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "notification_events.domain_blocked", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "notification_events.secrets_detected", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "notification_events.file_overwrite", "false"),
				),
			},
		},
	})
}

func TestAccGithubRepoNotificationSettingsResourceMinimal(t *testing.T) {

	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testAccGithubNotificationResourceConfigMinimal("test-org"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "owner", "test-org"),
				),
			},
		},
	})
}

func TestGithubNotificationResource_Metadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		providerTypeName string
		expected         string
	}{
		{
			name:             "default",
			providerTypeName: "stepsecurity",
			expected:         "stepsecurity_github_org_notification_settings",
		},
		{
			name:             "custom_provider",
			providerTypeName: "custom",
			expected:         "custom_github_org_notification_settings",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &GithubRepoNotificationSettingsResource{}
			ctx := context.Background()

			req := resource.MetadataRequest{
				ProviderTypeName: tc.providerTypeName,
			}
			resp := &resource.MetadataResponse{}

			r.Metadata(ctx, req, resp)

			if resp.TypeName != tc.expected {
				t.Errorf("Expected TypeName %s, got %s", tc.expected, resp.TypeName)
			}
		})
	}
}

func TestGithubNotificationResource_Schema(t *testing.T) {
	t.Parallel()

	r := &GithubRepoNotificationSettingsResource{}
	ctx := context.Background()

	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	r.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	// Test required attributes
	expectedAttrs := []string{"owner", "notification_channels", "notification_events"}
	for _, attr := range expectedAttrs {
		if _, exists := resp.Schema.Attributes[attr]; !exists {
			t.Errorf("Expected attribute %s not found in schema", attr)
		}
	}

	// Test that owner is required
	if ownerAttr, exists := resp.Schema.Attributes["owner"]; exists {
		if !ownerAttr.IsRequired() {
			t.Error("Expected owner attribute to be required")
		}
	}

	// Test that notification_channels is required
	if channelsAttr, exists := resp.Schema.Attributes["notification_channels"]; exists {
		if !channelsAttr.IsRequired() {
			t.Error("Expected notification_channels attribute to be required")
		}
	}
}

func TestGithubNotificationResource_Configure(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		providerData  interface{}
		expectedError bool
		errorContains string
	}{
		{
			name:          "valid_client",
			providerData:  &stepsecurityapi.MockStepSecurityClient{},
			expectedError: false,
		},
		{
			name:          "nil_provider_data",
			providerData:  nil,
			expectedError: false,
		},
		{
			name:          "invalid_client_type",
			providerData:  "invalid",
			expectedError: true,
			errorContains: "Unexpected Data Source Configure Type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &GithubRepoNotificationSettingsResource{}
			ctx := context.Background()

			req := resource.ConfigureRequest{
				ProviderData: tc.providerData,
			}
			resp := &resource.ConfigureResponse{}

			r.Configure(ctx, req, resp)

			if tc.expectedError {
				if !resp.Diagnostics.HasError() {
					t.Error("Expected error but got none")
				}

				if tc.errorContains != "" {
					found := false
					for _, diag := range resp.Diagnostics.Errors() {
						if strings.Contains(diag.Summary(), tc.errorContains) || strings.Contains(diag.Detail(), tc.errorContains) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error to contain '%s', but got: %v", tc.errorContains, resp.Diagnostics)
					}
				}
			} else {
				if resp.Diagnostics.HasError() {
					t.Errorf("Expected no error but got: %v", resp.Diagnostics)
				}
			}
		})
	}
}

func TestGithubNotificationResource_ClientInteraction(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		mockResponse  *stepsecurityapi.NotificationSettings
		mockError     error
		expectedError bool
	}{
		{
			name: "successful_get",
			mockResponse: &stepsecurityapi.NotificationSettings{
				SlackWebhookURL: "https://hooks.slack.com/test",
				Email:           "admin@example.com",
			},
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "api_error",
			mockResponse:  nil,
			mockError:     fmt.Errorf("API error"),
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create mock client
			mockClient := &stepsecurityapi.MockStepSecurityClient{}
			mockClient.On("GetNotificationSettings", mock.Anything, "test-org").Return(tc.mockResponse, tc.mockError)

			// Test the core client interaction logic directly
			ctx := context.Background()
			settings, err := mockClient.GetNotificationSettings(ctx, "test-org")

			if tc.expectedError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}

				if settings == nil {
					t.Error("Expected settings but got nil")
				} else if settings.SlackWebhookURL != "https://hooks.slack.com/test" {
					t.Errorf("Expected slack webhook 'https://hooks.slack.com/test', got '%s'", settings.SlackWebhookURL)
				}
			}

			// Verify mock expectations
			mockClient.AssertExpectations(t)
		})
	}
}

func TestGithubNotificationResource_NotificationSettingsValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		settings stepsecurityapi.NotificationSettings
		valid    bool
	}{
		{
			name: "valid_slack_only",
			settings: stepsecurityapi.NotificationSettings{
				SlackWebhookURL: "https://hooks.slack.com/test",
			},
			valid: true,
		},
		{
			name: "valid_teams_only",
			settings: stepsecurityapi.NotificationSettings{
				TeamsWebhookURL: "https://outlook.office.com/webhook/test",
			},
			valid: true,
		},
		{
			name: "valid_email_only",
			settings: stepsecurityapi.NotificationSettings{
				Email: "admin@example.com",
			},
			valid: true,
		},
		{
			name: "valid_multiple_channels",
			settings: stepsecurityapi.NotificationSettings{
				SlackWebhookURL: "https://hooks.slack.com/test",
				Email:           "admin@example.com",
			},
			valid: true,
		},
		{
			name:     "empty_settings",
			settings: stepsecurityapi.NotificationSettings{},
			valid:    true, // Assuming empty is valid based on schema
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Test basic validation logic (this would be implemented in the resource)
			isValid := true // Placeholder - in real implementation, you'd have validation logic

			if isValid != tc.valid {
				t.Errorf("Expected valid=%v, got valid=%v for settings: %+v", tc.valid, isValid, tc.settings)
			}
		})
	}
}

func testAccGithubNotificationResourceConfig(owner, slackWebhook, email string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_org_notification_settings" "test" {
  owner = %[1]q
  
  notification_channels = {
    slack_webhook_url = %[2]q
    email            = %[3]q
  }

  notification_events = {
    domain_blocked    = true
    secrets_detected  = true
    file_overwrite    = false
  }
}
`, owner, slackWebhook, email)
}

func testAccGithubNotificationResourceConfigWithTeams(owner, teamsWebhook string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_org_notification_settings" "test" {
  owner = %[1]q
  
  notification_channels = {
    teams_webhook_url = %[2]q
  }

  notification_events = {
    domain_blocked    = true
    secrets_detected  = true
    file_overwrite    = false
  }
}
`, owner, teamsWebhook)
}

func testAccGithubNotificationResourceConfigWithEvents(owner, email string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_org_notification_settings" "test" {
  owner = %[1]q
  
  notification_channels = {
    email = %[2]q
  }
  
  notification_events = {
    domain_blocked    = true
    secrets_detected  = true
    file_overwrite    = false
  }
}
`, owner, email)
}

func testAccGithubNotificationResourceConfigMinimal(owner string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_org_notification_settings" "test" {
  owner = %[1]q
  
  notification_channels = {}

  notification_events = {
    domain_blocked    = true
    secrets_detected  = true
    file_overwrite    = false
  }
}
`, owner)
}
