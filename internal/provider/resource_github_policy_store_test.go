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

func TestAccGithubPolicyStoreResource(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing
			{
				Config: testAccGithubPolicyStoreResourceConfig("tf-acc-test", "test-policy", "audit"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "policy_name", "test-policy"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "egress_policy", "audit"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "allowed_endpoints.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "allowed_endpoints.0", "github.com:443"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "disable_telemetry", "false"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "disable_sudo", "false"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "disable_file_monitoring", "false"),
					res.TestCheckResourceAttrSet("stepsecurity_github_policy_store.test", "id"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "stepsecurity_github_policy_store.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateId:     "tf-acc-test:::test-policy",
			},
			// Update and Read testing
			{
				Config: testAccGithubPolicyStoreResourceConfig("tf-acc-test", "test-policy", "block"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "policy_name", "test-policy"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "egress_policy", "block"),
				),
			},
		},
	})
}

func TestAccGithubPolicyStoreResourceWithCustomEndpoints(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testAccGithubPolicyStoreResourceConfigWithCustomEndpoints("tf-acc-test", "test-policy-custom"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "policy_name", "test-policy-custom"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "egress_policy", "block"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "allowed_endpoints.#", "3"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "allowed_endpoints.0", "github.com:443"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "allowed_endpoints.1", "api.github.com:443"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "allowed_endpoints.2", "registry.npmjs.org:443"),
				),
			},
		},
	})
}

func TestAccGithubPolicyStoreResourceWithAllOptions(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testAccGithubPolicyStoreResourceConfigWithAllOptions("tf-acc-test", "test-policy-full"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "policy_name", "test-policy-full"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "egress_policy", "block"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "disable_telemetry", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "disable_sudo", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "disable_file_monitoring", "true"),
				),
			},
		},
	})
}

func TestAccGithubPolicyStoreResourceMinimal(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testAccGithubPolicyStoreResourceConfigMinimal("tf-acc-test", "test-policy-minimal"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "policy_name", "test-policy-minimal"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "egress_policy", "audit"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "allowed_endpoints.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "allowed_endpoints.0", "github.com:443"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "disable_telemetry", "false"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "disable_sudo", "false"),
					res.TestCheckResourceAttr("stepsecurity_github_policy_store.test", "disable_file_monitoring", "false"),
				),
			},
		},
	})
}

func TestGithubPolicyStoreResource_Metadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		providerTypeName string
		expected         string
	}{
		{
			name:             "default",
			providerTypeName: "stepsecurity",
			expected:         "stepsecurity_github_policy_store",
		},
		{
			name:             "custom_provider",
			providerTypeName: "custom",
			expected:         "custom_github_policy_store",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubPolicyStoreResource{}
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

func TestGithubPolicyStoreResource_Schema(t *testing.T) {
	t.Parallel()

	r := &githubPolicyStoreResource{}
	ctx := context.Background()

	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	r.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	// Test required attributes
	expectedAttrs := []string{
		"id", "owner", "policy_name", "egress_policy", "allowed_endpoints",
		"disable_telemetry", "disable_sudo", "disable_file_monitoring",
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

	// Test that egress_policy is required
	if egressPolicyAttr, exists := resp.Schema.Attributes["egress_policy"]; exists {
		if !egressPolicyAttr.IsRequired() {
			t.Error("Expected egress_policy attribute to be required")
		}
	}
}

func TestGithubPolicyStoreResource_Configure(t *testing.T) {
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

			r := &githubPolicyStoreResource{}
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

func TestGithubPolicyStoreResource_ClientInteraction(t *testing.T) {
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

func TestGithubPolicyStoreResource_ImportState(t *testing.T) {
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

			r := &githubPolicyStoreResource{}
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
							"owner":         tftypes.String,
							"policy_name":   tftypes.String,
							"egress_policy": tftypes.String,
							"allowed_endpoints": tftypes.List{
								ElementType: tftypes.String,
							},
							"disable_telemetry":       tftypes.Bool,
							"disable_sudo":            tftypes.Bool,
							"disable_file_monitoring": tftypes.Bool,
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

func TestGithubPolicyStoreResource_UpdateState(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		policy   *stepsecurityapi.GitHubPolicyStorePolicy
		expected githubPolicyStoreModel
	}{
		{
			name: "basic_policy",
			policy: &stepsecurityapi.GitHubPolicyStorePolicy{
				Owner:                 "tf-acc-test",
				PolicyName:            "test-policy",
				EgressPolicy:          "audit",
				AllowedEndpoints:      []string{"github.com:443"},
				DisableTelemetry:      false,
				DisableSudo:           false,
				DisableFileMonitoring: false,
			},
			expected: githubPolicyStoreModel{
				ID:           types.StringValue("tf-acc-test:::test-policy"),
				Owner:        types.StringValue("tf-acc-test"),
				PolicyName:   types.StringValue("test-policy"),
				EgressPolicy: types.StringValue("audit"),
				AllowedEndpoints: types.ListValueMust(
					types.StringType,
					[]attr.Value{types.StringValue("github.com:443")},
				),
				DisableTelemetry:      types.BoolValue(false),
				DisableSudo:           types.BoolValue(false),
				DisableFileMonitoring: types.BoolValue(false),
			},
		},
		{
			name: "policy_with_multiple_endpoints",
			policy: &stepsecurityapi.GitHubPolicyStorePolicy{
				Owner:                 "tf-acc-test",
				PolicyName:            "test-policy",
				EgressPolicy:          "block",
				AllowedEndpoints:      []string{"github.com:443", "api.github.com:443", "registry.npmjs.org:443"},
				DisableTelemetry:      true,
				DisableSudo:           true,
				DisableFileMonitoring: true,
			},
			expected: githubPolicyStoreModel{
				ID:           types.StringValue("tf-acc-test:::test-policy"),
				Owner:        types.StringValue("tf-acc-test"),
				PolicyName:   types.StringValue("test-policy"),
				EgressPolicy: types.StringValue("block"),
				AllowedEndpoints: types.ListValueMust(
					types.StringType,
					[]attr.Value{
						types.StringValue("github.com:443"),
						types.StringValue("api.github.com:443"),
						types.StringValue("registry.npmjs.org:443"),
					},
				),
				DisableTelemetry:      types.BoolValue(true),
				DisableSudo:           types.BoolValue(true),
				DisableFileMonitoring: types.BoolValue(true),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubPolicyStoreResource{}
			var state githubPolicyStoreModel

			r.updateGitHubPolicyStorePolicyState(tc.policy, &state)

			// Verify basic fields
			if state.ID.ValueString() != tc.expected.ID.ValueString() {
				t.Errorf("Expected ID %s, got %s", tc.expected.ID.ValueString(), state.ID.ValueString())
			}

			if state.Owner.ValueString() != tc.expected.Owner.ValueString() {
				t.Errorf("Expected Owner %s, got %s", tc.expected.Owner.ValueString(), state.Owner.ValueString())
			}

			if state.PolicyName.ValueString() != tc.expected.PolicyName.ValueString() {
				t.Errorf("Expected PolicyName %s, got %s", tc.expected.PolicyName.ValueString(), state.PolicyName.ValueString())
			}

			if state.EgressPolicy.ValueString() != tc.expected.EgressPolicy.ValueString() {
				t.Errorf("Expected EgressPolicy %s, got %s", tc.expected.EgressPolicy.ValueString(), state.EgressPolicy.ValueString())
			}

			// Verify boolean fields
			if state.DisableTelemetry.ValueBool() != tc.expected.DisableTelemetry.ValueBool() {
				t.Errorf("Expected DisableTelemetry %t, got %t", tc.expected.DisableTelemetry.ValueBool(), state.DisableTelemetry.ValueBool())
			}

			if state.DisableSudo.ValueBool() != tc.expected.DisableSudo.ValueBool() {
				t.Errorf("Expected DisableSudo %t, got %t", tc.expected.DisableSudo.ValueBool(), state.DisableSudo.ValueBool())
			}

			if state.DisableFileMonitoring.ValueBool() != tc.expected.DisableFileMonitoring.ValueBool() {
				t.Errorf("Expected DisableFileMonitoring %t, got %t", tc.expected.DisableFileMonitoring.ValueBool(), state.DisableFileMonitoring.ValueBool())
			}

			// Verify list elements count
			if len(state.AllowedEndpoints.Elements()) != len(tc.expected.AllowedEndpoints.Elements()) {
				t.Errorf("Expected %d allowed endpoints, got %d", len(tc.expected.AllowedEndpoints.Elements()), len(state.AllowedEndpoints.Elements()))
			}
		})
	}
}

func TestGithubPolicyStoreResource_GetPolicy(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		model    githubPolicyStoreModel
		expected *stepsecurityapi.GitHubPolicyStorePolicy
	}{
		{
			name: "basic_model",
			model: githubPolicyStoreModel{
				Owner:        types.StringValue("tf-acc-test"),
				PolicyName:   types.StringValue("test-policy"),
				EgressPolicy: types.StringValue("audit"),
				AllowedEndpoints: types.ListValueMust(
					types.StringType,
					[]attr.Value{types.StringValue("github.com:443")},
				),
				DisableTelemetry:      types.BoolValue(false),
				DisableSudo:           types.BoolValue(false),
				DisableFileMonitoring: types.BoolValue(false),
			},
			expected: &stepsecurityapi.GitHubPolicyStorePolicy{
				Owner:                 "tf-acc-test",
				PolicyName:            "test-policy",
				EgressPolicy:          "audit",
				AllowedEndpoints:      []string{"github.com:443"},
				DisableTelemetry:      false,
				DisableSudo:           false,
				DisableFileMonitoring: false,
			},
		},
		{
			name: "model_with_multiple_endpoints",
			model: githubPolicyStoreModel{
				Owner:        types.StringValue("tf-acc-test"),
				PolicyName:   types.StringValue("test-policy"),
				EgressPolicy: types.StringValue("block"),
				AllowedEndpoints: types.ListValueMust(
					types.StringType,
					[]attr.Value{
						types.StringValue("github.com:443"),
						types.StringValue("api.github.com:443"),
						types.StringValue("registry.npmjs.org:443"),
					},
				),
				DisableTelemetry:      types.BoolValue(true),
				DisableSudo:           types.BoolValue(true),
				DisableFileMonitoring: types.BoolValue(true),
			},
			expected: &stepsecurityapi.GitHubPolicyStorePolicy{
				Owner:                 "tf-acc-test",
				PolicyName:            "test-policy",
				EgressPolicy:          "block",
				AllowedEndpoints:      []string{"github.com:443", "api.github.com:443", "registry.npmjs.org:443"},
				DisableTelemetry:      true,
				DisableSudo:           true,
				DisableFileMonitoring: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubPolicyStoreResource{}
			result := r.getGitHubPolicyStorePolicy(tc.model)

			if result.Owner != tc.expected.Owner {
				t.Errorf("Expected Owner %s, got %s", tc.expected.Owner, result.Owner)
			}

			if result.PolicyName != tc.expected.PolicyName {
				t.Errorf("Expected PolicyName %s, got %s", tc.expected.PolicyName, result.PolicyName)
			}

			if result.EgressPolicy != tc.expected.EgressPolicy {
				t.Errorf("Expected EgressPolicy %s, got %s", tc.expected.EgressPolicy, result.EgressPolicy)
			}

			if len(result.AllowedEndpoints) != len(tc.expected.AllowedEndpoints) {
				t.Errorf("Expected %d allowed endpoints, got %d", len(tc.expected.AllowedEndpoints), len(result.AllowedEndpoints))
			}

			for i, endpoint := range result.AllowedEndpoints {
				if endpoint != tc.expected.AllowedEndpoints[i] {
					t.Errorf("Expected endpoint %s at index %d, got %s", tc.expected.AllowedEndpoints[i], i, endpoint)
				}
			}

			if result.DisableTelemetry != tc.expected.DisableTelemetry {
				t.Errorf("Expected DisableTelemetry %t, got %t", tc.expected.DisableTelemetry, result.DisableTelemetry)
			}

			if result.DisableSudo != tc.expected.DisableSudo {
				t.Errorf("Expected DisableSudo %t, got %t", tc.expected.DisableSudo, result.DisableSudo)
			}

			if result.DisableFileMonitoring != tc.expected.DisableFileMonitoring {
				t.Errorf("Expected DisableFileMonitoring %t, got %t", tc.expected.DisableFileMonitoring, result.DisableFileMonitoring)
			}
		})
	}
}

func testAccGithubPolicyStoreResourceConfig(owner, policyName, egressPolicy string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_policy_store" "test" {
  owner         = %[1]q
  policy_name   = %[2]q
  egress_policy = %[3]q
}
`, owner, policyName, egressPolicy)
}

func testAccGithubPolicyStoreResourceConfigWithCustomEndpoints(owner, policyName string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_policy_store" "test" {
  owner         = %[1]q
  policy_name   = %[2]q
  egress_policy = "block"
  
  allowed_endpoints = [
    "github.com:443",
    "api.github.com:443",
    "registry.npmjs.org:443"
  ]
}
`, owner, policyName)
}

func testAccGithubPolicyStoreResourceConfigWithAllOptions(owner, policyName string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_policy_store" "test" {
  owner         = %[1]q
  policy_name   = %[2]q
  egress_policy = "block"
  
  allowed_endpoints = [
    "github.com:443",
    "api.github.com:443"
  ]
  
  disable_telemetry       = true
  disable_sudo            = true
  disable_file_monitoring = true
}
`, owner, policyName)
}

func testAccGithubPolicyStoreResourceConfigMinimal(owner, policyName string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_policy_store" "test" {
  owner         = %[1]q
  policy_name   = %[2]q
  egress_policy = "audit"
}
`, owner, policyName)
}
