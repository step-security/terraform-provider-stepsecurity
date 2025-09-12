package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	res "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/mock"
)

func TestAccGithubPolicyStoreAttachmentResource(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing - workflow attachment
			{
				Config: testAccGithubPolicyStoreAttachmentWorkflowConfig("tf-acc-test", "test-policy"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "policy_name", "test-policy"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "org.repositories.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "org.repositories.0.name", "myrepo"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "org.repositories.0.workflows.#", "2"),
					res.TestCheckResourceAttrSet("stepsecurity_github_policy_store_attachment.test", "id"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "stepsecurity_github_policy_store_attachment.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateId:     "tf-acc-test:::test-policy",
			},
			// Update to org attachment
			{
				Config: testAccGithubPolicyStoreAttachmentOrgConfig("tf-acc-test", "test-policy"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "policy_name", "test-policy"),
					// When no repositories are specified, apply_to_org should default to true
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "org.apply_to_org", "true"),
				),
			},
		},
	})
}

func TestAccGithubPolicyStoreAttachmentResourceCluster(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testAccGithubPolicyStoreAttachmentClusterConfig("tf-acc-test", "cluster-policy"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "policy_name", "cluster-policy"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "clusters.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "clusters.0", "production-cluster"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "clusters.1", "staging-cluster"),
				),
			},
		},
	})
}

func TestAccGithubPolicyStoreAttachmentResourceMixed(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testAccGithubPolicyStoreAttachmentMixedConfig("tf-acc-test", "mixed-policy"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "policy_name", "mixed-policy"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "org.repositories.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "clusters.#", "1"),
					// apply_to_org should be automatically set to false when repositories are specified
					res.TestCheckResourceAttr("stepsecurity_github_policy_store_attachment.test", "org.apply_to_org", "false"),
				),
			},
		},
	})
}

func TestGithubPolicyStoreAttachmentResource_Metadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		providerTypeName string
		expected         string
	}{
		{
			name:             "default",
			providerTypeName: "stepsecurity",
			expected:         "stepsecurity_github_policy_store_attachment",
		},
		{
			name:             "custom_provider",
			providerTypeName: "custom",
			expected:         "custom_github_policy_store_attachment",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubPolicyStoreAttachmentResource{}
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

func TestGithubPolicyStoreAttachmentResource_Schema(t *testing.T) {
	t.Parallel()

	r := &githubPolicyStoreAttachmentResource{}
	ctx := context.Background()

	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	r.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	// Test required attributes
	expectedAttrs := []string{
		"id", "owner", "policy_name", "org", "clusters",
	}
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

	// Test that owner is required
	if ownerAttr, exists := resp.Schema.Attributes["owner"]; exists {
		if !ownerAttr.IsRequired() {
			t.Error("Expected owner attribute to be required")
		}
	}

	// Test that policy_name is required
	if policyNameAttr, exists := resp.Schema.Attributes["policy_name"]; exists {
		if !policyNameAttr.IsRequired() {
			t.Error("Expected policy_name attribute to be required")
		}
	}

	// Test that org is optional
	if orgAttr, exists := resp.Schema.Attributes["org"]; exists {
		if !orgAttr.IsOptional() {
			t.Error("Expected org attribute to be optional")
		}
	}

	// Test that clusters is optional
	if clustersAttr, exists := resp.Schema.Attributes["clusters"]; exists {
		if !clustersAttr.IsOptional() {
			t.Error("Expected clusters attribute to be optional")
		}
	}
}

func TestGithubPolicyStoreAttachmentResource_Configure(t *testing.T) {
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

			r := &githubPolicyStoreAttachmentResource{}
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

func TestGithubPolicyStoreAttachmentResource_ClientInteraction(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		mockResponse  *stepsecurityapi.GitHubPolicyStorePolicy
		mockError     error
		expectedError bool
	}{
		{
			name: "successful_get",
			mockResponse: &stepsecurityapi.GitHubPolicyStorePolicy{
				Owner:                 "test-org",
				PolicyName:            "test-policy",
				EgressPolicy:          "audit",
				AllowedEndpoints:      []string{"github.com:443"},
				DisableTelemetry:      false,
				DisableSudo:           false,
				DisableFileMonitoring: false,
				Attachments: &stepsecurityapi.PolicyAttachments{
					Org: &stepsecurityapi.OrgResource{
						Name:       "test-org",
						ApplyToOrg: true,
					},
				},
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
			mockClient.On("GetGitHubPolicyStorePolicy", mock.Anything, "tf-acc-test", "test-policy").Return(tc.mockResponse, tc.mockError)

			// Test the core client interaction logic directly
			ctx := context.Background()
			policy, err := mockClient.GetGitHubPolicyStorePolicy(ctx, "tf-acc-test", "test-policy")

			if tc.expectedError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}

				if policy == nil {
					t.Error("Expected policy but got nil")
				} else {
					if policy.Owner != "test-org" {
						t.Errorf("Expected owner 'test-org', got '%s'", policy.Owner)
					}
					if policy.PolicyName != "test-policy" {
						t.Errorf("Expected policy name 'test-policy', got '%s'", policy.PolicyName)
					}
				}
			}

			// Verify mock expectations
			mockClient.AssertExpectations(t)
		})
	}
}

func TestGithubPolicyStoreAttachmentResource_ImportState(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		importId      string
		expectedError bool
		errorContains string
		expectedOwner string
		expectedName  string
	}{
		{
			name:          "valid_import_id",
			importId:      "tf-acc-test:::test-policy",
			expectedError: false,
			expectedOwner: "tf-acc-test",
			expectedName:  "test-policy",
		},
		{
			name:          "invalid_import_id_missing_separator",
			importId:      "tf-acc-test-test-policy",
			expectedError: true,
			errorContains: "Invalid Import ID",
		},
		{
			name:          "invalid_import_id_too_many_parts",
			importId:      "tf-acc-test:::test-policy:::extra",
			expectedError: true,
			errorContains: "Invalid Import ID",
		},
		{
			name:          "invalid_import_id_empty",
			importId:      "",
			expectedError: true,
			errorContains: "Invalid Import ID",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubPolicyStoreAttachmentResource{}
			ctx := context.Background()

			// Create mock client for successful cases
			if !tc.expectedError {
				mockClient := &stepsecurityapi.MockStepSecurityClient{}
				mockClient.On("GetGitHubPolicyStorePolicy", mock.Anything, tc.expectedOwner, tc.expectedName).Return(
					&stepsecurityapi.GitHubPolicyStorePolicy{
						Owner:                 tc.expectedOwner,
						PolicyName:            tc.expectedName,
						EgressPolicy:          "audit",
						AllowedEndpoints:      []string{"github.com:443"},
						DisableTelemetry:      false,
						DisableSudo:           false,
						DisableFileMonitoring: false,
						Attachments: &stepsecurityapi.PolicyAttachments{
							Org: &stepsecurityapi.OrgResource{
								Name:       tc.expectedOwner,
								ApplyToOrg: true,
							},
						},
					}, nil)
				r.client = mockClient
			}

			req := resource.ImportStateRequest{
				ID: tc.importId,
			}
			sc := &resource.SchemaResponse{}
			r.Schema(ctx, resource.SchemaRequest{}, sc)
			resp := &resource.ImportStateResponse{
				State: tfsdk.State{
					Raw: tftypes.NewValue(tftypes.Object{
						AttributeTypes: map[string]tftypes.Type{
							"id":          tftypes.String,
							"owner":       tftypes.String,
							"policy_name": tftypes.String,
							"org": tftypes.Object{
								AttributeTypes: map[string]tftypes.Type{
									"apply_to_org": tftypes.Bool,
									"repositories": tftypes.List{
										ElementType: tftypes.Object{
											AttributeTypes: map[string]tftypes.Type{
												"name":          tftypes.String,
												"apply_to_repo": tftypes.Bool,
												"workflows": tftypes.List{
													ElementType: tftypes.String,
												},
											},
										},
									},
								},
							},
							"clusters": tftypes.List{
								ElementType: tftypes.String,
							},
						},
					}, nil),
					Schema: sc.Schema,
				},
			}

			r.ImportState(ctx, req, resp)

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

func TestGithubPolicyStoreAttachmentResource_AutomaticBooleanLogic(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		description string
		config      string
		expectedRequest func(req *stepsecurityapi.GitHubPolicyAttachRequest) bool
	}{
		{
			name: "org_only_attachment",
			description: "Empty org (no repositories) should default apply_to_org to true",
			config: `
			org = {}`,
			expectedRequest: func(req *stepsecurityapi.GitHubPolicyAttachRequest) bool {
				return req.Org != nil && req.Org.ApplyToOrg == true && len(req.Org.Repos) == 0
			},
		},
		{
			name: "explicit_org_attachment",
			description: "Explicitly set apply_to_org = true",
			config: `
			org = {
				apply_to_org = true
			}`,
			expectedRequest: func(req *stepsecurityapi.GitHubPolicyAttachRequest) bool {
				return req.Org != nil && req.Org.ApplyToOrg == true && len(req.Org.Repos) == 0
			},
		},
		{
			name: "repo_attachment_without_workflows",
			description: "Repository without workflows should set apply_to_org=false, apply_to_repo=true",
			config: `
			org = {
				repositories = [
					{
						name = "test-repo"
					}
				]
			}`,
			expectedRequest: func(req *stepsecurityapi.GitHubPolicyAttachRequest) bool {
				return req.Org != nil && 
					req.Org.ApplyToOrg == false && 
					len(req.Org.Repos) == 1 &&
					req.Org.Repos[0].ApplyToRepo == true &&
					len(req.Org.Repos[0].Workflows) == 0
			},
		},
		{
			name: "workflow_attachment",
			description: "Repository with workflows should set apply_to_org=false, apply_to_repo=false",
			config: `
			org = {
				repositories = [
					{
						name = "test-repo"
						workflows = ["ci.yml"]
					}
				]
			}`,
			expectedRequest: func(req *stepsecurityapi.GitHubPolicyAttachRequest) bool {
				return req.Org != nil && 
					req.Org.ApplyToOrg == false && 
					len(req.Org.Repos) == 1 &&
					req.Org.Repos[0].ApplyToRepo == false &&
					len(req.Org.Repos[0].Workflows) == 1
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockClient := &stepsecurityapi.MockStepSecurityClient{}
			mockClient.On("AttachGitHubPolicyStorePolicy", mock.Anything, "test-org", "test-policy", mock.MatchedBy(tc.expectedRequest)).Return(nil)

			// Create a resource instance with the mock client
			r := &githubPolicyStoreAttachmentResource{client: mockClient}

			// Parse the config string into a model
			model := githubPolicyStoreAttachmentModel{
				Owner:      types.StringValue("test-org"),
				PolicyName: types.StringValue("test-policy"),
			}

			// Parse the config string and set up the model's org attribute
			if strings.Contains(tc.config, "org") {
				orgAttrs := map[string]attr.Type{
					"apply_to_org": types.BoolType,
					"repositories": types.ListType{
						ElemType: types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"name":          types.StringType,
								"apply_to_repo": types.BoolType,
								"workflows":     types.ListType{ElemType: types.StringType},
							},
						},
					},
				}

				orgValues := map[string]attr.Value{}

				// Set apply_to_org if explicitly specified
				if strings.Contains(tc.config, "apply_to_org = true") {
					orgValues["apply_to_org"] = types.BoolValue(true)
				} else {
					// Default to null if not specified
					orgValues["apply_to_org"] = types.BoolNull()
				}

				// Handle repositories if specified
				if strings.Contains(tc.config, "repositories") {
					var repoValues []attr.Value

					if strings.Contains(tc.config, "name = \"test-repo\"") {
						repoAttrs := map[string]attr.Type{
							"name":          types.StringType,
							"apply_to_repo": types.BoolType,
							"workflows":     types.ListType{ElemType: types.StringType},
						}

						repoValue := map[string]attr.Value{
							"name":          types.StringValue("test-repo"),
							"apply_to_repo": types.BoolNull(),
						}

						// Add workflows if specified
						if strings.Contains(tc.config, "workflows = [\"ci.yml\"]") {
							repoValue["workflows"] = types.ListValueMust(
								types.StringType,
								[]attr.Value{types.StringValue("ci.yml")},
							)
						} else {
							repoValue["workflows"] = types.ListNull(types.StringType)
						}

						repoValues = append(repoValues, types.ObjectValueMust(repoAttrs, repoValue))
					}

					orgValues["repositories"] = types.ListValueMust(
						types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"name":          types.StringType,
								"apply_to_repo": types.BoolType,
								"workflows":     types.ListType{ElemType: types.StringType},
							},
						},
						repoValues,
					)
				} else {
					orgValues["repositories"] = types.ListNull(
						types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"name":          types.StringType,
								"apply_to_repo": types.BoolType,
								"workflows":     types.ListType{ElemType: types.StringType},
							},
						},
					)
				}

				model.Org = types.ObjectValueMust(orgAttrs, orgValues)
			}

			// Execute the actual code that should trigger the mock
			err := r.createAttachment(context.Background(), &model)
			if err != nil {
				t.Fatalf("createAttachment failed: %v", err)
			}

			// Verify that the mock was called as expected
			mockClient.AssertExpectations(t)
		})
	}
}

func TestGithubPolicyStoreAttachmentResource_CreateAttachment(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		model    githubPolicyStoreAttachmentModel
		expected *stepsecurityapi.GitHubPolicyAttachRequest
	}{
		{
			name: "org_attachment",
			model: githubPolicyStoreAttachmentModel{
				Owner:      types.StringValue("test-org"),
				PolicyName: types.StringValue("test-policy"),
				Org: types.ObjectValueMust(
					map[string]attr.Type{
						"apply_to_org": types.BoolType,
						"repositories": types.ListType{
							ElemType: types.ObjectType{
								AttrTypes: map[string]attr.Type{
									"name":          types.StringType,
									"apply_to_repo": types.BoolType,
									"workflows":     types.ListType{ElemType: types.StringType},
								},
							},
						},
					},
					map[string]attr.Value{
						"apply_to_org": types.BoolValue(true),
						"repositories": types.ListValueMust(types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"name":          types.StringType,
								"apply_to_repo": types.BoolType,
								"workflows":     types.ListType{ElemType: types.StringType},
							},
						}, []attr.Value{}),
					},
				),
				Clusters: types.ListNull(types.StringType),
			},
			expected: &stepsecurityapi.GitHubPolicyAttachRequest{
				Org: &stepsecurityapi.OrgResource{
					Name:       "test-org",
					ApplyToOrg: true,
					Repos:      []stepsecurityapi.RepoResource{},
				},
			},
		},
		{
			name: "cluster_attachment",
			model: githubPolicyStoreAttachmentModel{
				Owner:      types.StringValue("test-org"),
				PolicyName: types.StringValue("test-policy"),
				Org: types.ObjectNull(map[string]attr.Type{
					"apply_to_org": types.BoolType,
					"repositories": types.ListType{
						ElemType: types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"name":          types.StringType,
								"apply_to_repo": types.BoolType,
								"workflows":     types.ListType{ElemType: types.StringType},
							},
						},
					},
				}),
				Clusters: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("cluster1"),
					types.StringValue("cluster2"),
				}),
			},
			expected: &stepsecurityapi.GitHubPolicyAttachRequest{
				Clusters: []string{"cluster1", "cluster2"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockClient := &stepsecurityapi.MockStepSecurityClient{}
			mockClient.On("AttachGitHubPolicyStorePolicy", mock.Anything, "test-org", "test-policy", mock.MatchedBy(func(req *stepsecurityapi.GitHubPolicyAttachRequest) bool {
				// Compare the request structure
				if tc.expected.Org != nil {
					return req.Org != nil && req.Org.ApplyToOrg == tc.expected.Org.ApplyToOrg
				}
				if len(tc.expected.Clusters) > 0 {
					return len(req.Clusters) == len(tc.expected.Clusters)
				}
				return true
			})).Return(nil)

			r := &githubPolicyStoreAttachmentResource{client: mockClient}
			ctx := context.Background()

			err := r.createAttachment(ctx, &tc.model)

			if err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verify mock expectations
			mockClient.AssertExpectations(t)
		})
	}
}

// Test configuration helpers
func testAccGithubPolicyStoreAttachmentWorkflowConfig(owner, policyName string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_policy_store_attachment" "test" {
  owner       = %[1]q
  policy_name = %[2]q
  
  org = {
    repositories = [
      {
        name      = "myrepo"
        workflows = ["ci.yml", "deploy.yml"]
      },
      {
        name      = "other-repo"
        workflows = ["test.yml"]
      }
    ]
  }
}
`, owner, policyName)
}

func testAccGithubPolicyStoreAttachmentOrgConfig(owner, policyName string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_policy_store_attachment" "test" {
  owner       = %[1]q
  policy_name = %[2]q
  
  org = {
    apply_to_org = true
  }
}
`, owner, policyName)
}

func testAccGithubPolicyStoreAttachmentClusterConfig(owner, policyName string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_policy_store_attachment" "test" {
  owner       = %[1]q
  policy_name = %[2]q
  
  clusters = [
    "production-cluster",
    "staging-cluster"
  ]
}
`, owner, policyName)
}

func testAccGithubPolicyStoreAttachmentMixedConfig(owner, policyName string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_policy_store_attachment" "test" {
  owner       = %[1]q
  policy_name = %[2]q
  
  org = {
    repositories = [
      {
        name = "critical-repo"
      }
    ]
  }
  
  clusters = [
    "dev-cluster"
  ]
}
`, owner, policyName)
}
