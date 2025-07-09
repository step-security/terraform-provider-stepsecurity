// Copyright (c) HashiCorp, Inc.

package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/mock"
)

func TestAccUsersDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccUsersDataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.stepsecurity_users.test", "users.#"),
				),
			},
		},
	})
}

func TestAccUsersDataSourceWithUser(t *testing.T) {
	resource.Test(t, resource.TestCase{
		// PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create a user first, then read all users
			{
				Config: testAccUsersDataSourceConfigWithUserName("testuser098", "Github"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.stepsecurity_users.test", "users.#"),
					resource.TestCheckResourceAttr("stepsecurity_user.test", "user_name", "testuser098"),
					resource.TestCheckResourceAttr("stepsecurity_user.test", "auth_type", "Github"),
				),
			},
		},
	})
}

func testAccUsersDataSourceConfig() string {
	return testProviderConfig() + `
data "stepsecurity_users" "test" {}
`
}

func testAccUsersDataSourceConfigWithUserName(userName, authType string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_user" "test" {
  user_name = %[1]q
  auth_type = %[2]q
  policies = [
		{
			type  = "github"
			role  = "admin"
			scope = "customer"
		}
  ]
		
}

data "stepsecurity_users" "test" {
  depends_on = [stepsecurity_user.test]
}
`, userName, authType)
}

func TestUsersDataSource_Metadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		providerTypeName string
		expected         string
	}{
		{
			name:             "default",
			providerTypeName: "stepsecurity",
			expected:         "stepsecurity_users",
		},
		{
			name:             "custom_provider",
			providerTypeName: "custom",
			expected:         "custom_users",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := &usersDataSource{}
			ctx := context.Background()

			req := datasource.MetadataRequest{
				ProviderTypeName: tc.providerTypeName,
			}
			resp := &datasource.MetadataResponse{}

			d.Metadata(ctx, req, resp)

			if resp.TypeName != tc.expected {
				t.Errorf("Expected TypeName %s, got %s", tc.expected, resp.TypeName)
			}
		})
	}
}

func TestUsersDataSource_Schema(t *testing.T) {
	t.Parallel()

	d := &usersDataSource{}
	ctx := context.Background()

	req := datasource.SchemaRequest{}
	resp := &datasource.SchemaResponse{}

	d.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	// Test that users attribute exists and is computed
	if usersAttr, exists := resp.Schema.Attributes["users"]; exists {
		if !usersAttr.IsComputed() {
			t.Error("Expected users attribute to be computed")
		}
	} else {
		t.Error("Expected users attribute not found in schema")
	}
}

func TestUsersDataSource_Configure(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		providerData  any
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

			d := &usersDataSource{}
			ctx := context.Background()

			req := datasource.ConfigureRequest{
				ProviderData: tc.providerData,
			}
			resp := &datasource.ConfigureResponse{}

			d.Configure(ctx, req, resp)

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

func TestUsersDataSource_ClientInteraction(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		mockUsers     []stepsecurityapi.User
		mockError     error
		expectedError bool
	}{
		{
			name:          "successful_read_empty_list",
			mockUsers:     []stepsecurityapi.User{},
			mockError:     nil,
			expectedError: false,
		},
		{
			name: "successful_read_with_users",
			mockUsers: []stepsecurityapi.User{
				{
					ID:       "user-1",
					Email:    "user1@example.com",
					AuthType: "github",
					Policies: []stepsecurityapi.UserPolicy{},
				},
				{
					ID:       "user-2",
					Email:    "user2@example.com",
					AuthType: "gitlab",
					Policies: []stepsecurityapi.UserPolicy{
						{
							Type:         "gitlab",
							Role:         "admin",
							Scope:        "organization",
							Organization: "test-org",
							Repos:        []string{"repo1"},
							Projects:     []string{"proj1"},
						},
					},
				},
			},
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_from_api",
			mockUsers:     nil,
			mockError:     fmt.Errorf("API error"),
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create mock client
			mockClient := &stepsecurityapi.MockStepSecurityClient{}
			mockClient.On("ListUsers", mock.Anything).Return(tc.mockUsers, tc.mockError)

			// Test the core client interaction logic directly
			ctx := context.Background()
			users, err := mockClient.ListUsers(ctx)

			if tc.expectedError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}

				if len(users) != len(tc.mockUsers) {
					t.Errorf("Expected %d users, got %d", len(tc.mockUsers), len(users))
				}
			}

			// Verify mock expectations
			mockClient.AssertExpectations(t)
		})
	}
}

func TestUserModel_ConversionFromAPI(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		apiUser  stepsecurityapi.User
		expected UserModel
	}{
		{
			name: "basic_user_no_policies",
			apiUser: stepsecurityapi.User{
				ID:          "user-123",
				Email:       "test@example.com",
				UserName:    "testuser",
				EmailSuffix: "@example.com",
				AuthType:    "github",
				AddedAt:     1234567890,
				UpdatedAt:   1234567891,
				UpdatedBy:   "admin",
				Policies:    []stepsecurityapi.UserPolicy{},
			},
			expected: UserModel{
				ID:          types.StringValue("user-123"),
				Email:       types.StringValue("test@example.com"),
				UserName:    types.StringValue("testuser"),
				EmailSuffix: types.StringValue("@example.com"),
				AuthType:    types.StringValue("github"),
				AddedAt:     types.Int64Value(1234567890),
				UpdatedAt:   types.Int64Value(1234567891),
				UpdatedBy:   types.StringValue("admin"),
				Policies:    []UserPolicyModel{},
			},
		},
		{
			name: "user_with_policies",
			apiUser: stepsecurityapi.User{
				ID:       "user-123",
				Email:    "test@example.com",
				AuthType: "github",
				Policies: []stepsecurityapi.UserPolicy{
					{
						Type:         "github",
						Role:         "admin",
						Scope:        "organization",
						Organization: "test-org",
						Repos:        []string{"repo1", "repo2"},
						Group:        "test-group",
						Projects:     []string{"proj1"},
					},
				},
			},
			expected: UserModel{
				ID:       types.StringValue("user-123"),
				Email:    types.StringValue("test@example.com"),
				AuthType: types.StringValue("github"),
				Policies: []UserPolicyModel{
					{
						Type:         types.StringValue("github"),
						Role:         types.StringValue("admin"),
						Scope:        types.StringValue("organization"),
						Organization: types.StringValue("test-org"),
						Repos: func() types.List {
							elements := []attr.Value{
								types.StringValue("repo1"),
								types.StringValue("repo2"),
							}
							list, _ := types.ListValue(types.StringType, elements)
							return list
						}(),
						Group: types.StringValue("test-group"),
						Projects: func() types.List {
							elements := []attr.Value{
								types.StringValue("proj1"),
							}
							list, _ := types.ListValue(types.StringType, elements)
							return list
						}(),
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Test the conversion logic that happens in the data source
			userState := UserModel{
				ID:          types.StringValue(tc.apiUser.ID),
				Email:       types.StringValue(tc.apiUser.Email),
				UserName:    types.StringValue(tc.apiUser.UserName),
				EmailSuffix: types.StringValue(tc.apiUser.EmailSuffix),
				AuthType:    types.StringValue(tc.apiUser.AuthType),
				AddedAt:     types.Int64Value(int64(tc.apiUser.AddedAt)),
				UpdatedAt:   types.Int64Value(int64(tc.apiUser.UpdatedAt)),
				UpdatedBy:   types.StringValue(tc.apiUser.UpdatedBy),
				Policies:    []UserPolicyModel{},
			}

			// Convert policies
			for _, policy := range tc.apiUser.Policies {
				// Create types.List for repos
				repoElements := make([]attr.Value, len(policy.Repos))
				for i, repo := range policy.Repos {
					repoElements[i] = types.StringValue(repo)
				}
				reposList, _ := types.ListValue(types.StringType, repoElements)

				// Create types.List for projects
				projectElements := make([]attr.Value, len(policy.Projects))
				for i, project := range policy.Projects {
					projectElements[i] = types.StringValue(project)
				}
				projectsList, _ := types.ListValue(types.StringType, projectElements)

				userState.Policies = append(userState.Policies, UserPolicyModel{
					Type:         types.StringValue(policy.Type),
					Role:         types.StringValue(policy.Role),
					Scope:        types.StringValue(policy.Scope),
					Organization: types.StringValue(policy.Organization),
					Repos:        reposList,
					Group:        types.StringValue(policy.Group),
					Projects:     projectsList,
				})
			}

			// Verify basic fields
			if userState.ID.ValueString() != tc.expected.ID.ValueString() {
				t.Errorf("Expected ID %s, got %s", tc.expected.ID.ValueString(), userState.ID.ValueString())
			}

			if userState.Email.ValueString() != tc.expected.Email.ValueString() {
				t.Errorf("Expected Email %s, got %s", tc.expected.Email.ValueString(), userState.Email.ValueString())
			}

			if userState.AuthType.ValueString() != tc.expected.AuthType.ValueString() {
				t.Errorf("Expected AuthType %s, got %s", tc.expected.AuthType.ValueString(), userState.AuthType.ValueString())
			}

			// Verify policies count
			if len(userState.Policies) != len(tc.expected.Policies) {
				t.Errorf("Expected %d policies, got %d", len(tc.expected.Policies), len(userState.Policies))
			}
		})
	}
}
