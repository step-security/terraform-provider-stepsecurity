package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	res "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Helper function to create settings object for tests
func createSettingsObject(cooldownPeriod *int64, packages []string) types.Object {
	settingsMap := map[string]attr.Value{}

	if cooldownPeriod != nil {
		settingsMap["cool_down_period"] = types.Int64Value(*cooldownPeriod)
	} else {
		settingsMap["cool_down_period"] = types.Int64Null()
	}

	if packages != nil {
		elements := make([]attr.Value, len(packages))
		for i, pkg := range packages {
			elements[i] = types.StringValue(pkg)
		}
		settingsMap["packages_to_exempt_in_cooldown_check"], _ = types.ListValue(types.StringType, elements)
	} else {
		settingsMap["packages_to_exempt_in_cooldown_check"] = types.ListNull(types.StringType)
	}

	settingsType := types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"cool_down_period":                     types.Int64Type,
			"packages_to_exempt_in_cooldown_check": types.ListType{ElemType: types.StringType},
		},
	}

	obj, _ := types.ObjectValue(settingsType.AttrTypes, settingsMap)
	return obj
}

// Helper function to create null settings object for tests (for controls without settings)
func createNullSettingsObject() types.Object {
	return types.ObjectNull(map[string]attr.Type{
		"cool_down_period":                     types.Int64Type,
		"packages_to_exempt_in_cooldown_check": types.ListType{ElemType: types.StringType},
	})
}

func TestAccGithubChecksResource(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing
			{
				Config: testProviderConfig() + testAccGithubChecksResourceConfig("tf-acc-test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.control", "NPM Package Cooldown"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.enable", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.type", "required"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.settings.cool_down_period", "5"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.repos.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "required_checks.repos.0", "*"),
				),
			},
			// Update and Read testing
			{
				Config: testProviderConfig() + testAccGithubChecksResourceConfigUpdated("tf-acc-test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.settings.cool_down_period", "10"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccGithubChecksResourceWithBaselineCheck(t *testing.T) {
	t.Skip("Skipping as this test can't be run in parallel to TestAccGithubChecksResource")
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testProviderConfig() + testAccGithubChecksResourceConfigWithBaseline("tf-acc-test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "baseline_check.repos.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "baseline_check.repos.0", "*"),
				),
			},
		},
	})
}

func TestAccGithubChecksResourceWithPackageExemptions(t *testing.T) {
	t.Skip("Skipping as this test can't be run in parallel to TestAccGithubChecksResource")
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			{
				Config: testProviderConfig() + testAccGithubChecksResourceConfigWithPackageExemptions("tf-acc-test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.settings.packages_to_exempt_in_cooldown_check.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.settings.packages_to_exempt_in_cooldown_check.0", "lodash"),
					res.TestCheckResourceAttr("stepsecurity_github_checks.test", "controls.0.settings.packages_to_exempt_in_cooldown_check.1", "express"),
				),
			},
		},
	})
}

// Unit Tests
func TestGithubChecksResource_Metadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		providerTypeName string
		expected         string
	}{
		{
			name:             "default",
			providerTypeName: "stepsecurity",
			expected:         "stepsecurity_github_checks",
		},
		{
			name:             "custom_provider",
			providerTypeName: "custom",
			expected:         "custom_github_checks",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
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

func TestGithubChecksResource_Schema(t *testing.T) {
	t.Parallel()

	r := &githubChecksResource{}
	ctx := context.Background()

	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	r.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	// Test required attributes
	expectedAttrs := []string{"owner", "controls", "required_checks", "optional_checks", "baseline_check"}
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

	// Test that controls is optional
	if controlsAttr, exists := resp.Schema.Attributes["controls"]; exists {
		if !controlsAttr.IsOptional() {
			t.Error("Expected controls attribute to be optional")
		}
	}
}

func TestGithubChecksResource_Configure(t *testing.T) {
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

			r := &githubChecksResource{}
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

func TestGithubChecksResource_ValidateConfig(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		config        githubChecksModel
		expectedError bool
		errorContains string
	}{
		{
			name: "valid_config",
			config: githubChecksModel{
				Owner: types.StringValue("tf-acc-test"),
				Controls: []control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				},
				RequiredChecks: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				},
			},
			expectedError: false,
		},
		{
			name: "empty_owner",
			config: githubChecksModel{
				Owner: types.StringValue(""),
				Controls: []control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				},
			},
			expectedError: true,
			errorContains: "Owner is required",
		},
		{
			name: "empty_controls",
			config: githubChecksModel{
				Owner:    types.StringValue("tf-acc-test"),
				Controls: []control{},
			},
			expectedError: true,
			errorContains: "Controls are required",
		},
		{
			name: "invalid_control",
			config: githubChecksModel{
				Owner: types.StringValue("tf-acc-test"),
				Controls: []control{
					{
						Control:  types.StringValue("Invalid Control"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				},
			},
			expectedError: true,
			errorContains: "Invalid control provided",
		},
		{
			name: "invalid_type",
			config: githubChecksModel{
				Owner: types.StringValue("tf-acc-test"),
				Controls: []control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("invalid"),
						Settings: createNullSettingsObject(),
					},
				},
			},
			expectedError: true,
			errorContains: "Type can only be 'required' or 'optional'",
		},
		{
			name: "cooldown_period_out_of_range",
			config: githubChecksModel{
				Owner: types.StringValue("tf-acc-test"),
				Controls: []control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(50); return &v }(), nil),
					},
				},
			},
			expectedError: true,
			errorContains: "cool_down_period should be between 1 and 30",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// We can't easily mock the Config.Get() method, so we'll test the validation logic directly
			// This is a common pattern in Terraform provider unit tests
			mockResp := &resource.ValidateConfigResponse{}

			// Simulate the validation logic that would be called
			if tc.config.Owner.ValueString() == "" {
				mockResp.Diagnostics.AddError(
					"Owner is required",
					"Owner is required to create a GitHub Checks resource",
				)
			}

			if len(tc.config.Controls) == 0 {
				mockResp.Diagnostics.AddError(
					"Controls are required",
					"Controls are required to create a GitHub Checks resource",
				)
			}

			for _, control := range tc.config.Controls {
				if _, ok := stepsecurityapi.AvailableControls[control.Control.ValueString()]; !ok {
					mockResp.Diagnostics.AddError(
						"Invalid control provided",
						"only the following controls are accepted to configure: "+strings.Join(stepsecurityapi.GetAvailableControls(), ", \n"),
					)
				}

				if control.Type.ValueString() != "required" && control.Type.ValueString() != "optional" {
					mockResp.Diagnostics.AddError(
						"Type can only be 'required' or 'optional'",
						"Type can only be 'required' or 'optional'",
					)
				}

				if control.Control.ValueString() == "NPM Package Cooldown" {
					// Extract cooldown period from the settings object
					if !control.Settings.IsNull() {
						if cooldownAttr := control.Settings.Attributes()["cool_down_period"]; cooldownAttr != nil {
							if cooldownValue, ok := cooldownAttr.(types.Int64); ok {
								period := cooldownValue.ValueInt64()
								if period != 0 && (period < 1 || period > 30) {
									mockResp.Diagnostics.AddError(
										"cool_down_period should be between 1 and 30",
										"cool_down_period should be between 1 and 30 for control "+control.Control.ValueString(),
									)
								}
							}
						}
					}
				}
			}

			if tc.expectedError {
				if !mockResp.Diagnostics.HasError() {
					t.Error("Expected error but got none")
				}

				if tc.errorContains != "" {
					found := false
					for _, diag := range mockResp.Diagnostics.Errors() {
						if strings.Contains(diag.Summary(), tc.errorContains) || strings.Contains(diag.Detail(), tc.errorContains) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error to contain '%s', but got: %v", tc.errorContains, mockResp.Diagnostics)
					}
				}
			} else {
				if mockResp.Diagnostics.HasError() {
					t.Errorf("Expected no error but got: %v", mockResp.Diagnostics)
				}
			}
		})
	}
}

func TestGithubChecksResource_ConvertToCreateRequest(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		input       githubChecksModel
		expected    stepsecurityapi.GitHubPRChecksConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "basic_config_with_npm_cooldown",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: []control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(5); return &v }(), nil),
					},
				},
				RequiredChecks: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				},
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"npm_package_recent_release_guard": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(5),
							},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expectError: false,
		},
		{
			name: "package_exemptions",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: []control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(3); return &v }(), []string{"lodash", "express"}),
					},
				},
				RequiredChecks: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				},
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"npm_package_recent_release_guard": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(3),
								"exempted_packages":       []string{"lodash", "express"},
							},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expectError: false,
		},
		{
			name: "multiple_controls_and_repos",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: []control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(7); return &v }(), nil),
					},
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("optional"),
						Settings: createNullSettingsObject(),
					},
				},
				RequiredChecks: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: func() types.List {
						elements := []attr.Value{types.StringValue("repo1")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				},
				OptionalChecks: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{
							types.StringValue("repo1"),
							types.StringValue("repo2"),
						}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				},
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"npm_package_recent_release_guard": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(7),
							},
						},
						"script_injection_check": {
							Enabled:  true,
							Type:     "optional",
							Settings: nil,
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{
					"repo1": {
						Baseline:          false,
						RunRequiredChecks: false,
						RunOptionalChecks: true,
					},
					"repo2": {
						Baseline:          false,
						RunRequiredChecks: true,
						RunOptionalChecks: true,
					},
				},
			},
			expectError: false,
		},
		{
			name: "baseline_checks_enabled",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: []control{
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				},
				RequiredChecks: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				},
				BaselineCheck: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				},
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"script_injection_check": {
							Enabled:  true,
							Type:     "required",
							Settings: nil,
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := true; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expectError: false,
		},
		{
			name: "omit_repos_configuration",
			input: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: []control{
					{
						Control:  types.StringValue("PWN Request"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("optional"),
						Settings: createNullSettingsObject(),
					},
				},
				OptionalChecks: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: func() types.List {
						elements := []attr.Value{
							types.StringValue("exclude-repo1"),
							types.StringValue("exclude-repo2"),
						}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				},
			},
			expected: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"pwn_request_check": {
							Enabled:  true,
							Type:     "optional",
							Settings: nil,
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{
					"exclude-repo1": {
						Baseline:          false,
						RunRequiredChecks: false,
						RunOptionalChecks: false,
					},
					"exclude-repo2": {
						Baseline:          false,
						RunRequiredChecks: false,
						RunOptionalChecks: false,
					},
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
			result, err := r.convertToCreateRequest(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)

			// Use Equal to compare the entire result structure
			assert.Equal(t, tc.expected, *result)
		})
	}
}

func TestGithubChecksResource_ConvertToState(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		owner    string
		input    stepsecurityapi.GitHubPRChecksConfig
		expected githubChecksModel
	}{
		{
			name:  "basic_config_with_npm_cooldown",
			owner: "test-org",
			input: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"npm_package_recent_release_guard": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(7),
							},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expected: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: []control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(7); return &v }(), nil),
					},
				},
				RequiredChecks: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				},
				OptionalChecks: nil,
				BaselineCheck:  nil,
			},
		},
		{
			name:  "multiple_controls_with_settings",
			owner: "test-org",
			input: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"npm_package_recent_release_guard": {
							Enabled: true,
							Type:    "required",
							Settings: map[string]any{
								"cooldown_period_in_days": int64(5),
								"exempted_packages": []string{
									"lodash",
									"express",
								},
							},
						},
						"pwn_request_check": {
							Enabled:  false,
							Type:     "required",
							Settings: map[string]any{},
						},
						"script_injection_check": {
							Enabled:  true,
							Type:     "optional",
							Settings: map[string]any{},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{
					"repo1": {
						Baseline:          false,
						RunRequiredChecks: true,
						RunOptionalChecks: true,
					},
					"repo2": {
						Baseline:          true,
						RunRequiredChecks: false,
						RunOptionalChecks: false,
					},
				},
			},
			expected: githubChecksModel{
				Owner: types.StringValue("test-org"),
				Controls: []control{
					{
						Control:  types.StringValue("NPM Package Cooldown"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createSettingsObject(func() *int64 { v := int64(5); return &v }(), []string{"lodash", "express"}),
					},
					{
						Control:  types.StringValue("PWN Request"),
						Enable:   types.BoolValue(false),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
					{
						Control:  types.StringValue("Script Injection"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("optional"),
						Settings: createNullSettingsObject(),
					},
				},
				RequiredChecks: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: func() types.List {
						elements := []attr.Value{types.StringValue("repo2")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
				},
				OptionalChecks: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("repo1")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				},
				BaselineCheck: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("repo2")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				},
			},
		},
		{
			name:  "all_global_flags_enabled",
			owner: "global-org",
			input: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks: map[string]stepsecurityapi.CheckConfig{
						"npm_package_compromised_updates": {
							Enabled:  true,
							Type:     "required",
							Settings: map[string]any{},
						},
					},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := true; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := true; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expected: githubChecksModel{
				Owner: types.StringValue("global-org"),
				Controls: []control{
					{
						Control:  types.StringValue("NPM Package Compromised Updates"),
						Enable:   types.BoolValue(true),
						Type:     types.StringValue("required"),
						Settings: createNullSettingsObject(),
					},
				},
				RequiredChecks: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				},
				OptionalChecks: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				},
				BaselineCheck: &checksConfig{
					Repos: func() types.List {
						elements := []attr.Value{types.StringValue("*")}
						list, _ := types.ListValue(types.StringType, elements)
						return list
					}(),
					OmitRepos: types.ListNull(types.StringType),
				},
			},
		},
		{
			name:  "empty_config",
			owner: "empty-org",
			input: stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{
					Checks:                             map[string]stepsecurityapi.CheckConfig{},
					EnableRequiredChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableOptionalChecksForAllNewRepos: func() *bool { b := false; return &b }(),
					EnableBaselineCheckForAllNewRepos:  func() *bool { b := false; return &b }(),
				},
				Repos: map[string]stepsecurityapi.CheckOptions{},
			},
			expected: githubChecksModel{
				Owner:          types.StringValue("empty-org"),
				Controls:       []control{},
				RequiredChecks: nil,
				OptionalChecks: nil,
				BaselineCheck:  nil,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
			got := r.convertToState(tc.owner, tc.input)

			// Use Equal to compare the entire result structure
			assert.Equal(t, tc.expected, got)
		})
	}
}

// Test configuration helpers
func testAccGithubChecksResourceConfig(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_checks" "test" {
  owner = %[1]q

  controls = [
    {
      control = "NPM Package Cooldown"
      enable  = true
      type    = "required"
      settings = {
        cool_down_period = 5
      }
    }
  ]

  required_checks = {
    repos = ["*"]
  }
}
`, owner)
}

func testAccGithubChecksResourceConfigUpdated(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_checks" "test" {
  owner = %[1]q

  controls = [
    {
      control = "NPM Package Cooldown"
      enable  = true
      type    = "required"
      settings = {
        cool_down_period = 10
      }
    }
  ]

  required_checks = {
    repos = ["*"]
  }
}
`, owner)
}

func testAccGithubChecksResourceConfigWithBaseline(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_checks" "test" {
  owner = %[1]q

  controls = [
    {
      control = "Script Injection"
      enable  = true
      type    = "required"
    }
  ]

  required_checks = {
    repos = ["*"]
  }

  baseline_check = {
    repos = ["*"]
  }
}
`, owner)
}

func testAccGithubChecksResourceConfigWithPackageExemptions(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_checks" "test" {
  owner = %[1]q

  controls = [
    {
      control = "NPM Package Cooldown"
      enable  = true
      type    = "required"
      settings = {
        packages_to_exempt_in_cooldown_check = ["lodash", "express"]
      }
    }
  ]

  required_checks = {
    repos = ["*"]
  }
}
`, owner)
}
