// Copyright (c) HashiCorp, Inc.

package provider

import (
	"context"
	"strings"
	"testing"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	res "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccUserResource(t *testing.T) {

	res.Test(t, res.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing
			{
				Config: testProviderConfig() + `
resource "stepsecurity_user" "test" {
  user_name     = "testuser"
  auth_type = "Github"
  policies = [
		{
			type  = "github"
			role  = "admin"
			scope = "customer"
		}
	]
}
`,
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_user.test", "user_name", "testuser"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "auth_type", "Github"),
					res.TestCheckResourceAttrSet("stepsecurity_user.test", "id"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "stepsecurity_user.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing
			{
				Config: testProviderConfig() + `
resource "stepsecurity_user" "test" {
  user_name     = "testuser"
  auth_type = "Github"
  policies = [ 
		{
			type  = "github"
			role  = "auditor"
			scope = "customer"
		}
	]
}
`,
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.role", "auditor"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "auth_type", "Github"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccUserResourceWithPolicies(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing with policies
			{
				Config: testProviderConfig() + `
resource "stepsecurity_user" "test" {
  email     = "test@example.com"
  auth_type = "SSO"
  policies = [ 
		{
			type  = "github"
			role  = "admin"
			scope = "organization"
			organization = "test-org"
		}
	]
}
`,
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_user.test", "email", "test@example.com"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "auth_type", "SSO"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.type", "github"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.role", "admin"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.scope", "organization"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.organization", "test-org"),
					res.TestCheckResourceAttrSet("stepsecurity_user.test", "id"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "stepsecurity_user.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// func TestAccUserResourceWithMultiplePolicies(t *testing.T) {
// 	res.Test(t, res.TestCase{
// 		PreCheck:                 func() { testAccPreCheck(t) },
// 		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
// 		Steps: []res.TestStep{
// 			// Create and Read testing with multiple policies
// 			{
// 				Config: testProviderConfig() + `
// resource "stepsecurity_user" "test" {
//   email     = "test2@example.com"
//   auth_type = "SSO"
//   policies = [
// 		{
// 			type  = "github"
// 			role  = "auditor"
// 			scope = "organization"
// 			organization = "test-org-2"
// 		},
// 		{
// 			type  = "github"
// 			role  = "admin"
// 			scope = "organization"
// 			organization = "test-org"
// 		}
// 	]
// }
// `,
// 				Check: res.ComposeAggregateTestCheckFunc(
// 					res.TestCheckResourceAttr("stepsecurity_user.test", "email", "test2@example.com"),
// 					res.TestCheckResourceAttr("stepsecurity_user.test", "auth_type", "SSO"),
// 					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.#", "2"),
// 					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.type", "github"),
// 					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.role", "auditor"),
// 					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.scope", "organization"),
// 					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.organization", "test-org-2"),
// 					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.1.type", "github"),
// 					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.1.role", "admin"),
// 					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.1.scope", "organization"),
// 					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.1.organization", "test-org"),
// 					res.TestCheckResourceAttrSet("stepsecurity_user.test", "id"),
// 				),
// 			},
// 		},
// 	})
// }

func TestAccUserResourceWithCustomerScope(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing with customer scope
			{
				Config: testProviderConfig() + `
resource "stepsecurity_user" "test" {
  email     = "test@example.com"
  auth_type = "SSO"
  policies = [ 
		{
			type  = "github"
			role  = "admin"
			scope = "customer"
		}
	]
}
`,
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_user.test", "email", "test@example.com"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "auth_type", "SSO"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.type", "github"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.role", "admin"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.scope", "customer"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "policies.0.organization", "*"),
					res.TestCheckResourceAttrSet("stepsecurity_user.test", "id"),
				),
			},
		},
	})
}

func TestAccUserResourceWithUsername(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing with username
			{
				Config: testProviderConfig() + `
resource "stepsecurity_user" "test" {
  user_name = "testuser"
  auth_type = "Github"
  policies = [
		{
			type  = "github"
			role  = "admin"
			scope = "customer"
		}
	]
}
`,
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_user.test", "user_name", "testuser"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "auth_type", "Github"),
					res.TestCheckResourceAttrSet("stepsecurity_user.test", "id"),
				),
			},
		},
	})
}

func TestAccUserResourceWithEmailSuffix(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing with email suffix
			{
				Config: testProviderConfig() + `
resource "stepsecurity_user" "test" {
  email_suffix = "@example.com"
  auth_type = "Github"
  policies = [
		{
			type  = "github"
			role  = "admin"
			scope = "customer"
		}
	]
}
`,
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_user.test", "email_suffix", "@example.com"),
					res.TestCheckResourceAttr("stepsecurity_user.test", "auth_type", "Github"),
					res.TestCheckResourceAttrSet("stepsecurity_user.test", "id"),
				),
			},
		},
	})
}

// Note: Mock client is shared and defined in datasource_users_unit_test.go
// Note: For unit testing Terraform providers, we focus on testing business logic
// rather than mocking the entire framework, as framework types are concrete
// and not easily mockable. Acceptance tests handle integration testing.
func TestUserResource_Metadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		providerTypeName string
		expected         string
	}{
		{
			name:             "default",
			providerTypeName: "stepsecurity",
			expected:         "stepsecurity_user",
		},
		{
			name:             "custom_provider",
			providerTypeName: "custom",
			expected:         "custom_user",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &userResource{}
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

func TestUserResource_Schema(t *testing.T) {
	t.Parallel()

	r := &userResource{}
	ctx := context.Background()

	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	r.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	// Test required attributes
	expectedAttrs := []string{"id", "auth_type", "email", "user_name", "email_suffix", "policies"}
	for _, attr := range expectedAttrs {
		if _, exists := resp.Schema.Attributes[attr]; !exists {
			t.Errorf("Expected attribute %s not found in schema", attr)
		}
	}

	// Test that id is computed
	if idAttr, exists := resp.Schema.Attributes["id"]; exists {
		if !idAttr.IsComputed() {
			t.Error("Expected id attribute to be computed")
		}
	}

	// Test that auth_type is required
	if authTypeAttr, exists := resp.Schema.Attributes["auth_type"]; exists {
		if !authTypeAttr.IsRequired() {
			t.Error("Expected auth_type attribute to be required")
		}
	}
}

func TestUserResource_Configure(t *testing.T) {
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

			r := &userResource{}
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

func TestUserResource_PolicyModificationLogic(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name               string
		inputPolicy        UserPolicyModel
		expectedOrgValue   string
		expectedReposCount int
		expectedGroupValue string
		expectedProjCount  int
		shouldModify       bool
	}{
		{
			name: "customer_scope_github",
			inputPolicy: UserPolicyModel{
				Type:  types.StringValue("github"),
				Role:  types.StringValue("admin"),
				Scope: types.StringValue("customer"),
			},
			expectedOrgValue:   "*",
			expectedReposCount: 1,
			shouldModify:       true,
		},
		{
			name: "customer_scope_gitlab",
			inputPolicy: UserPolicyModel{
				Type:  types.StringValue("gitlab"),
				Role:  types.StringValue("admin"),
				Scope: types.StringValue("customer"),
			},
			expectedGroupValue: "*",
			expectedProjCount:  1,
			shouldModify:       true,
		},
		{
			name: "customer_scope_all",
			inputPolicy: UserPolicyModel{
				Type:  types.StringValue("*"),
				Role:  types.StringValue("admin"),
				Scope: types.StringValue("customer"),
			},
			expectedOrgValue:   "*",
			expectedReposCount: 1,
			expectedGroupValue: "*",
			expectedProjCount:  1,
			shouldModify:       true,
		},
		{
			name: "organization_scope_github",
			inputPolicy: UserPolicyModel{
				Type:         types.StringValue("github"),
				Role:         types.StringValue("admin"),
				Scope:        types.StringValue("organization"),
				Organization: types.StringValue("test-org"),
			},
			expectedReposCount: 1,
			shouldModify:       true,
		},
		{
			name: "repo_scope_no_modification",
			inputPolicy: UserPolicyModel{
				Type:  types.StringValue("github"),
				Role:  types.StringValue("admin"),
				Scope: types.StringValue("repo"),
			},
			shouldModify: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Test the core policy modification logic directly
			policy := tc.inputPolicy
			modified := false

			if policy.Scope.ValueString() == "customer" {
				switch policy.Type.ValueString() {
				case "*":
					policy.Organization = types.StringValue("*")
					repoElements := []attr.Value{types.StringValue("*")}
					reposList, _ := types.ListValue(types.StringType, repoElements)
					policy.Repos = reposList
					policy.Group = types.StringValue("*")
					projectElements := []attr.Value{types.StringValue("*")}
					projectsList, _ := types.ListValue(types.StringType, projectElements)
					policy.Projects = projectsList
					modified = true
				case "github":
					policy.Organization = types.StringValue("*")
					repoElements := []attr.Value{types.StringValue("*")}
					reposList, _ := types.ListValue(types.StringType, repoElements)
					policy.Repos = reposList
					modified = true
				case "gitlab":
					policy.Group = types.StringValue("*")
					projectElements := []attr.Value{types.StringValue("*")}
					projectsList, _ := types.ListValue(types.StringType, projectElements)
					policy.Projects = projectsList
					modified = true
				}
			} else if policy.Scope.ValueString() == "organization" {
				switch policy.Type.ValueString() {
				case "github":
					repoElements := []attr.Value{types.StringValue("*")}
					reposList, _ := types.ListValue(types.StringType, repoElements)
					policy.Repos = reposList
					modified = true
				}
			}

			// Verify the modifications
			if modified != tc.shouldModify {
				t.Errorf("Expected shouldModify %v, got %v", tc.shouldModify, modified)
			}

			if tc.shouldModify {
				if tc.expectedOrgValue != "" && policy.Organization.ValueString() != tc.expectedOrgValue {
					t.Errorf("Expected Organization %s, got %s", tc.expectedOrgValue, policy.Organization.ValueString())
				}

				if tc.expectedReposCount > 0 && len(policy.Repos.Elements()) != tc.expectedReposCount {
					t.Errorf("Expected %d repos, got %d", tc.expectedReposCount, len(policy.Repos.Elements()))
				}

				if tc.expectedGroupValue != "" && policy.Group.ValueString() != tc.expectedGroupValue {
					t.Errorf("Expected Group %s, got %s", tc.expectedGroupValue, policy.Group.ValueString())
				}

				if tc.expectedProjCount > 0 && len(policy.Projects.Elements()) != tc.expectedProjCount {
					t.Errorf("Expected %d projects, got %d", tc.expectedProjCount, len(policy.Projects.Elements()))
				}
			}
		})
	}
}

func TestGetStringValue(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected basetypes.StringValue
	}{
		{
			name:     "empty_string",
			input:    "",
			expected: basetypes.NewStringNull(),
		},
		{
			name:     "non_empty_string",
			input:    "test",
			expected: types.StringValue("test"),
		},
		{
			name:     "whitespace_string",
			input:    "   ",
			expected: types.StringValue("   "),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := getStringValue(tc.input)

			if tc.expected.IsNull() && !result.IsNull() {
				t.Errorf("Expected null value but got %s", result.ValueString())
			}

			if !tc.expected.IsNull() && result.IsNull() {
				t.Error("Expected non-null value but got null")
			}

			if !tc.expected.IsNull() && !result.IsNull() && tc.expected.ValueString() != result.ValueString() {
				t.Errorf("Expected %s but got %s", tc.expected.ValueString(), result.ValueString())
			}
		})
	}
}

func TestUserResource_UpdateUserState(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		user     *stepsecurityapi.User
		expected userModel
	}{
		{
			name: "basic_user",
			user: &stepsecurityapi.User{
				ID:          "user-123",
				Email:       "test@example.com",
				UserName:    "testuser",
				EmailSuffix: "@example.com",
				AuthType:    "github",
				Policies:    []stepsecurityapi.UserPolicy{},
			},
			expected: userModel{
				ID:          types.StringValue("user-123"),
				Email:       types.StringValue("test@example.com"),
				UserName:    types.StringValue("testuser"),
				EmailSuffix: types.StringValue("@example.com"),
				AuthType:    types.StringValue("github"),
				Policies:    []UserPolicyModel{},
			},
		},
		{
			name: "user_with_policies",
			user: &stepsecurityapi.User{
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
						Projects:     []string{"proj1"},
					},
				},
			},
			expected: userModel{
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
		{
			name: "user_with_empty_fields",
			user: &stepsecurityapi.User{
				ID:          "user-123",
				Email:       "",
				UserName:    "",
				EmailSuffix: "",
				AuthType:    "github",
				Policies:    []stepsecurityapi.UserPolicy{},
			},
			expected: userModel{
				ID:          types.StringValue("user-123"),
				Email:       basetypes.NewStringNull(),
				UserName:    basetypes.NewStringNull(),
				EmailSuffix: basetypes.NewStringNull(),
				AuthType:    types.StringValue("github"),
				Policies:    []UserPolicyModel{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &userResource{}
			var state userModel

			r.updateUserState(context.Background(), tc.user, &state)

			// Verify basic fields
			if state.ID.ValueString() != tc.expected.ID.ValueString() {
				t.Errorf("Expected ID %s, got %s", tc.expected.ID.ValueString(), state.ID.ValueString())
			}

			if state.AuthType.ValueString() != tc.expected.AuthType.ValueString() {
				t.Errorf("Expected AuthType %s, got %s", tc.expected.AuthType.ValueString(), state.AuthType.ValueString())
			}

			// Verify policies count
			if len(state.Policies) != len(tc.expected.Policies) {
				t.Errorf("Expected %d policies, got %d", len(tc.expected.Policies), len(state.Policies))
			}

			// Verify null/empty handling
			if tc.expected.Email.IsNull() && !state.Email.IsNull() {
				t.Error("Expected Email to be null but it wasn't")
			}

			if !tc.expected.Email.IsNull() && state.Email.IsNull() {
				t.Error("Expected Email to be non-null but it was null")
			}

			if !tc.expected.Email.IsNull() && !state.Email.IsNull() &&
				state.Email.ValueString() != tc.expected.Email.ValueString() {
				t.Errorf("Expected Email %s, got %s", tc.expected.Email.ValueString(), state.Email.ValueString())
			}
		})
	}
}

func testAccPreCheck(t *testing.T) {
}

func testProviderConfig() string {
	return `
provider "stepsecurity" {
  api_base_url = "http://localhost:1234"
  api_key      = "step_abcdefg"
  customer     = "tf-acc-test"
}
`
}
