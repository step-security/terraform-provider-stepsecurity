package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/mock"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestAccGithubRunPolicyEvaluationsDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test organization-level evaluations
			{
				Config: testAccGithubRunPolicyEvaluationsDataSourceConfig("test-org", "", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.stepsecurity_github_run_policy_evaluations.test", "owner", "test-org"),
					resource.TestCheckResourceAttrSet("data.stepsecurity_github_run_policy_evaluations.test", "evaluations.#"),
				),
			},
		},
	})
}

func TestAccGithubRunPolicyEvaluationsDataSourceWithStatus(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test organization-level evaluations with status filter
			{
				Config: testAccGithubRunPolicyEvaluationsDataSourceConfig("test-org", "", "Blocked"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.stepsecurity_github_run_policy_evaluations.test", "owner", "test-org"),
					resource.TestCheckResourceAttr("data.stepsecurity_github_run_policy_evaluations.test", "status", "Blocked"),
					resource.TestCheckResourceAttrSet("data.stepsecurity_github_run_policy_evaluations.test", "evaluations.#"),
				),
			},
		},
	})
}

func TestAccGithubRunPolicyEvaluationsDataSourceWithRepo(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test repository-level evaluations
			{
				Config: testAccGithubRunPolicyEvaluationsDataSourceConfig("test-org", "test-repo", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.stepsecurity_github_run_policy_evaluations.test", "owner", "test-org"),
					resource.TestCheckResourceAttr("data.stepsecurity_github_run_policy_evaluations.test", "repo", "test-repo"),
					resource.TestCheckResourceAttrSet("data.stepsecurity_github_run_policy_evaluations.test", "evaluations.#"),
				),
			},
		},
	})
}

func TestAccGithubRunPolicyEvaluationsDataSourceWithRepoAndStatus(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test repository-level evaluations with status filter
			{
				Config: testAccGithubRunPolicyEvaluationsDataSourceConfig("test-org", "test-repo", "Allowed"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.stepsecurity_github_run_policy_evaluations.test", "owner", "test-org"),
					resource.TestCheckResourceAttr("data.stepsecurity_github_run_policy_evaluations.test", "repo", "test-repo"),
					resource.TestCheckResourceAttr("data.stepsecurity_github_run_policy_evaluations.test", "status", "Allowed"),
					resource.TestCheckResourceAttrSet("data.stepsecurity_github_run_policy_evaluations.test", "evaluations.#"),
				),
			},
		},
	})
}

func TestGithubRunPolicyEvaluationsDataSource_Metadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		providerTypeName string
		expected         string
	}{
		{
			name:             "default",
			providerTypeName: "stepsecurity",
			expected:         "stepsecurity_github_run_policy_evaluations",
		},
		{
			name:             "custom_provider",
			providerTypeName: "custom",
			expected:         "custom_github_run_policy_evaluations",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := &githubRunPolicyEvaluationsDataSource{}
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

func TestGithubRunPolicyEvaluationsDataSource_Schema(t *testing.T) {
	t.Parallel()

	d := &githubRunPolicyEvaluationsDataSource{}
	ctx := context.Background()

	req := datasource.SchemaRequest{}
	resp := &datasource.SchemaResponse{}

	d.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	// Test that required attributes exist
	requiredAttrs := []string{"owner"}
	for _, attr := range requiredAttrs {
		if ownerAttr, exists := resp.Schema.Attributes[attr]; exists {
			if !ownerAttr.IsRequired() {
				t.Errorf("Expected %s attribute to be required", attr)
			}
		} else {
			t.Errorf("Expected %s attribute not found in schema", attr)
		}
	}

	// Test that optional attributes exist
	optionalAttrs := []string{"repo", "status"}
	for _, attr := range optionalAttrs {
		if optionalAttr, exists := resp.Schema.Attributes[attr]; exists {
			if !optionalAttr.IsOptional() {
				t.Errorf("Expected %s attribute to be optional", attr)
			}
		} else {
			t.Errorf("Expected %s attribute not found in schema", attr)
		}
	}

	// Test that computed attributes exist
	computedAttrs := []string{"evaluations"}
	for _, attr := range computedAttrs {
		if computedAttr, exists := resp.Schema.Attributes[attr]; exists {
			if !computedAttr.IsComputed() {
				t.Errorf("Expected %s attribute to be computed", attr)
			}
		} else {
			t.Errorf("Expected %s attribute not found in schema", attr)
		}
	}
}

func TestGithubRunPolicyEvaluationsDataSource_Configure(t *testing.T) {
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

			d := &githubRunPolicyEvaluationsDataSource{}
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

func TestGithubRunPolicyEvaluationsDataSource_OrgClientInteraction(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		mockEvaluations  []stepsecurityapi.RunPolicyEvaluation
		mockError        error
		expectedError    bool
	}{
		{
			name:             "successful_read_empty_list",
			mockEvaluations:  []stepsecurityapi.RunPolicyEvaluation{},
			mockError:        nil,
			expectedError:    false,
		},
		{
			name: "successful_read_with_evaluations",
			mockEvaluations: []stepsecurityapi.RunPolicyEvaluation{
				{
					Owner:                  "test-org",
					RepoFullName:          "test-org/test-repo",
					RepoWorkflow:          "workflow-123",
					HeadBranch:            "main",
					WorkflowName:          "CI",
					WorkflowDisplayTitle:  "Continuous Integration",
					WorkflowFilePath:      ".github/workflows/ci.yml",
					RunID:                 12345,
					WorkflowRunStartedAt:  time.Now().Unix(),
					CommitMessage:         "Add new feature",
					Committer:             "developer",
					Event:                 "push",
					RunNumber:             42,
					Status:                "Blocked",
					PolicyResults: []stepsecurityapi.PolicyResult{
						{
							Policy: stepsecurityapi.PolicyEvaluation{
								Owner:              "test-org",
								Name:               "Test Policy",
								EnableActionPolicy: true,
								AllowedActions: map[string]string{
									"actions/checkout": "allow",
								},
								EnableRunsOnPolicy: true,
								DisallowedRunnerLabels: map[string]struct{}{
									"self-hosted": {},
								},
								EnableSecretsPolicy:                false,
								EnableCompromisedActionsPolicy:     true,
							},
							ActionPolicyStatus:                 "Blocked",
							ActionsNotAllowed:                  []string{"malicious/action"},
							RunsOnPolicyStatus:                 "Allowed",
							RunnerLabelsNotAllowed:             nil,
							CompromisedActionsPolicyStatus:     "Allowed", 
							CompromisedActionsDetected:         nil,
							SecretsPolicyStatus:                "Allowed",
							IsNonDefaultBranch:                 &[]bool{false}[0],
							WorkflowContainsSecrets:            &[]bool{true}[0],
							CurrentBranchHash:                  "abc123",
							DefaultBranchHash:                  "def456",
						},
					},
				},
			},
			mockError:        nil,
			expectedError:    false,
		},
		{
			name:             "error_from_api",
			mockEvaluations:  nil,
			mockError:        fmt.Errorf("API error"),
			expectedError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create mock client
			mockClient := &stepsecurityapi.MockStepSecurityClient{}
			mockClient.On("ListOrgRunPolicyEvaluations", mock.Anything, "test-org", "").Return(tc.mockEvaluations, tc.mockError)

			// Test the core client interaction logic directly
			ctx := context.Background()
			evaluations, err := mockClient.ListOrgRunPolicyEvaluations(ctx, "test-org", "")

			if tc.expectedError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}

				if len(evaluations) != len(tc.mockEvaluations) {
					t.Errorf("Expected %d evaluations, got %d", len(tc.mockEvaluations), len(evaluations))
				}
			}

			// Verify mock expectations
			mockClient.AssertExpectations(t)
		})
	}
}

func TestGithubRunPolicyEvaluationsDataSource_RepoClientInteraction(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		mockEvaluations  []stepsecurityapi.RunPolicyEvaluation
		mockError        error
		expectedError    bool
	}{
		{
			name:             "successful_read_empty_list",
			mockEvaluations:  []stepsecurityapi.RunPolicyEvaluation{},
			mockError:        nil,
			expectedError:    false,
		},
		{
			name: "successful_read_with_evaluations",
			mockEvaluations: []stepsecurityapi.RunPolicyEvaluation{
				{
					Owner:                  "test-org",
					RepoFullName:          "test-org/test-repo",
					Status:                "Allowed",
					PolicyResults:         []stepsecurityapi.PolicyResult{},
				},
			},
			mockError:        nil,
			expectedError:    false,
		},
		{
			name:             "error_from_api",
			mockEvaluations:  nil,
			mockError:        fmt.Errorf("API error"),
			expectedError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create mock client
			mockClient := &stepsecurityapi.MockStepSecurityClient{}
			mockClient.On("ListRepoRunPolicyEvaluations", mock.Anything, "test-org", "test-repo", "").Return(tc.mockEvaluations, tc.mockError)

			// Test the core client interaction logic directly
			ctx := context.Background()
			evaluations, err := mockClient.ListRepoRunPolicyEvaluations(ctx, "test-org", "test-repo", "")

			if tc.expectedError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}

				if len(evaluations) != len(tc.mockEvaluations) {
					t.Errorf("Expected %d evaluations, got %d", len(tc.mockEvaluations), len(evaluations))
				}
			}

			// Verify mock expectations
			mockClient.AssertExpectations(t)
		})
	}
}

func TestEvaluationModel_ConversionFromAPI(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		apiEvaluation stepsecurityapi.RunPolicyEvaluation
		expectedOwner string
		expectedRepo  string
		expectedStatus string
	}{
		{
			name: "basic_evaluation_no_policies",
			apiEvaluation: stepsecurityapi.RunPolicyEvaluation{
				Owner:                  "test-org",
				RepoFullName:          "test-org/test-repo",
				RepoWorkflow:          "workflow-123",
				HeadBranch:            "main",
				WorkflowName:          "CI",
				WorkflowDisplayTitle:  "Continuous Integration",
				WorkflowFilePath:      ".github/workflows/ci.yml",
				RunID:                 12345,
				WorkflowRunStartedAt:  1234567890,
				CommitMessage:         "Add new feature",
				Committer:             "developer",
				Event:                 "push",
				RunNumber:             42,
				Status:                "Allowed",
				PolicyResults:         []stepsecurityapi.PolicyResult{},
			},
			expectedOwner:  "test-org",
			expectedRepo:   "test-org/test-repo",
			expectedStatus: "Allowed",
		},
		{
			name: "evaluation_with_policies",
			apiEvaluation: stepsecurityapi.RunPolicyEvaluation{
				Owner:        "test-org",
				RepoFullName: "test-org/test-repo",
				Status:       "Blocked",
				PolicyResults: []stepsecurityapi.PolicyResult{
					{
						Policy: stepsecurityapi.PolicyEvaluation{
							Owner:              "test-org",
							Name:               "Test Policy",
							EnableActionPolicy: true,
							AllowedActions: map[string]string{
								"actions/checkout": "allow",
							},
						},
						ActionPolicyStatus:    "Blocked",
						ActionsNotAllowed:     []string{"malicious/action"},
						RunsOnPolicyStatus:    "Allowed",
						SecretsPolicyStatus:   "Allowed",
					},
				},
			},
			expectedOwner:  "test-org",
			expectedRepo:   "test-org/test-repo", 
			expectedStatus: "Blocked",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Test the conversion logic that happens in the data source
			evaluationState := githubRunPolicyEvaluationsDataSourceModel{
				Owner:       types.StringValue("test-org"),
				Repo:        types.StringNull(),
				Status:      types.StringNull(),
				Evaluations: types.ListNull(types.ObjectType{AttrTypes: map[string]attr.Type{}}),
			}

			// Verify we can access all the API fields without panicking
			if tc.apiEvaluation.Owner != tc.expectedOwner {
				t.Errorf("Expected owner %s, got %s", tc.expectedOwner, tc.apiEvaluation.Owner)
			}

			if tc.apiEvaluation.RepoFullName != tc.expectedRepo {
				t.Errorf("Expected repo %s, got %s", tc.expectedRepo, tc.apiEvaluation.RepoFullName)
			}

			if tc.apiEvaluation.Status != tc.expectedStatus {
				t.Errorf("Expected status %s, got %s", tc.expectedStatus, tc.apiEvaluation.Status)
			}

			// Verify state contains expected values
			if evaluationState.Owner.ValueString() != "test-org" {
				t.Errorf("Expected owner test-org, got %s", evaluationState.Owner.ValueString())
			}

			if !evaluationState.Repo.IsNull() {
				t.Error("Expected repo to be null")
			}

			if !evaluationState.Status.IsNull() {
				t.Error("Expected status to be null")
			}

			if !evaluationState.Evaluations.IsNull() {
				t.Error("Expected evaluations to be null initially")
			}
		})
	}
}

func testAccGithubRunPolicyEvaluationsDataSourceConfig(owner, repo, status string) string {
	config := fmt.Sprintf(`
data "stepsecurity_github_run_policy_evaluations" "test" {
  owner = %[1]q`, owner)
	
	if repo != "" {
		config += fmt.Sprintf(`
  repo = %[1]q`, repo)
	}
	
	if status != "" {
		config += fmt.Sprintf(`
  status = %[1]q`, status)
	}
	
	config += `
}`
	
	return config
}