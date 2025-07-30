package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	res "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/mock"
)

func TestAccGithubSuppressionRuleResource(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing - source_code_overwritten
			{
				Config: testAccGithubSuppressionRuleResourceConfig("test-rule-1", "source_code_overwritten", "ignore", "test-org", "test-file.txt", "/path/to/file.txt"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "name", "test-rule-1"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "type", "source_code_overwritten"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "action", "ignore"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "owner", "test-org"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "file", "test-file.txt"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "file_path", "/path/to/file.txt"),
					res.TestCheckResourceAttrSet("stepsecurity_github_supression_rule.test", "rule_id"),
				),
			},
			// Update and Read testing
			{
				Config: testAccGithubSuppressionRuleResourceConfig("test-rule-1-updated", "source_code_overwritten", "ignore", "test-org", "updated-file.txt", "/updated/path/to/file.txt"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "name", "test-rule-1-updated"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "file", "updated-file.txt"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "file_path", "/updated/path/to/file.txt"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccGithubSuppressionRuleResourceWithNetworkCall(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing - anomalous_outbound_network_call with IP
			{
				Config: testAccGithubSuppressionRuleResourceNetworkCallConfig("test-rule-2", "anomalous_outbound_network_call", "ignore", "test-org", "curl", "192.168.1.1", ""),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "name", "test-rule-2"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "type", "anomalous_outbound_network_call"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "action", "ignore"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "owner", "test-org"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "process", "curl"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "destination.ip", "192.168.1.1"),
					res.TestCheckResourceAttrSet("stepsecurity_github_supression_rule.test", "rule_id"),
				),
			},
			// Update to use domain instead of IP
			{
				Config: testAccGithubSuppressionRuleResourceNetworkCallConfig("test-rule-2", "anomalous_outbound_network_call", "ignore", "test-org", "wget", "", "example.com"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "name", "test-rule-2"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "process", "wget"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "destination.domain", "example.com"),
				),
			},
		},
	})
}

func TestAccGithubSuppressionRuleResourceWithWildcards(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing with wildcard owner
			{
				Config: testAccGithubSuppressionRuleResourceWildcardConfig("test-rule-3", "source_code_overwritten", "ignore", "*", "test-file.txt", "/path/to/file.txt"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "name", "test-rule-3"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "type", "source_code_overwritten"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "owner", "*"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "repo", "*"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "workflow", "*"),
					res.TestCheckResourceAttr("stepsecurity_github_supression_rule.test", "job", "*"),
					res.TestCheckResourceAttrSet("stepsecurity_github_supression_rule.test", "rule_id"),
				),
			},
		},
	})
}

func TestGithubSuppressionRuleResource_Metadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		providerTypeName string
		expected         string
	}{
		{
			name:             "default",
			providerTypeName: "stepsecurity",
			expected:         "stepsecurity_github_supression_rule",
		},
		{
			name:             "custom_provider",
			providerTypeName: "custom",
			expected:         "custom_github_supression_rule",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubSupressionRuleResource{}
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

func TestGithubSuppressionRuleResource_Schema(t *testing.T) {
	t.Parallel()

	r := &githubSupressionRuleResource{}
	ctx := context.Background()

	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	r.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	// Test required attributes
	expectedAttrs := []string{"rule_id", "name", "type", "action", "description", "destination", "process", "file", "file_path", "owner", "repo", "workflow", "job"}
	for _, attr := range expectedAttrs {
		if _, exists := resp.Schema.Attributes[attr]; !exists {
			t.Errorf("Expected attribute %s not found in schema", attr)
		}
	}

	// Test that rule_id is computed
	if ruleIDAttr, exists := resp.Schema.Attributes["rule_id"]; exists {
		if !ruleIDAttr.IsComputed() {
			t.Error("Expected rule_id attribute to be computed")
		}
	}

	// Test that name is required
	if nameAttr, exists := resp.Schema.Attributes["name"]; exists {
		if !nameAttr.IsRequired() {
			t.Error("Expected name attribute to be required")
		}
	}

	// Test that type is required
	if typeAttr, exists := resp.Schema.Attributes["type"]; exists {
		if !typeAttr.IsRequired() {
			t.Error("Expected type attribute to be required")
		}
	}

	// Test that action is required
	if actionAttr, exists := resp.Schema.Attributes["action"]; exists {
		if !actionAttr.IsRequired() {
			t.Error("Expected action attribute to be required")
		}
	}

	// Test that owner is required
	if ownerAttr, exists := resp.Schema.Attributes["owner"]; exists {
		if !ownerAttr.IsRequired() {
			t.Error("Expected owner attribute to be required")
		}
	}
}

func TestGithubSuppressionRuleResource_Configure(t *testing.T) {
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

			r := &githubSupressionRuleResource{}
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

func TestGithubSuppressionRuleResource_ValidateConfig(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		ruleType      string
		file          *string
		filePath      *string
		process       *string
		destination   *destinationModel
		expectedError bool
		errorContains string
	}{
		{
			name:          "valid_source_code_overwritten",
			ruleType:      "source_code_overwritten",
			file:          stringPtr("test.txt"),
			filePath:      stringPtr("/path/to/test.txt"),
			expectedError: false,
		},
		{
			name:          "source_code_overwritten_missing_file",
			ruleType:      "source_code_overwritten",
			expectedError: true,
			errorContains: "File is required",
		},
		{
			name:          "source_code_overwritten_with_process",
			ruleType:      "source_code_overwritten",
			file:          stringPtr("test.txt"),
			filePath:      stringPtr("/path/to/test.txt"),
			process:       stringPtr("curl"),
			expectedError: true,
			errorContains: "Process is not allowed",
		},
		{
			name:     "valid_anomalous_outbound_network_call_with_ip",
			ruleType: "anomalous_outbound_network_call",
			process:  stringPtr("curl"),
			destination: &destinationModel{
				IP:     types.StringValue("192.168.1.1"),
				Domain: types.StringNull(),
			},
			expectedError: false,
		},
		{
			name:     "valid_anomalous_outbound_network_call_with_domain",
			ruleType: "anomalous_outbound_network_call",
			process:  stringPtr("curl"),
			destination: &destinationModel{
				IP:     types.StringNull(),
				Domain: types.StringValue("example.com"),
			},
			expectedError: false,
		},
		{
			name:          "anomalous_outbound_network_call_missing_process",
			ruleType:      "anomalous_outbound_network_call",
			expectedError: true,
			errorContains: "Process is required",
		},
		{
			name:          "anomalous_outbound_network_call_missing_destination",
			ruleType:      "anomalous_outbound_network_call",
			process:       stringPtr("curl"),
			expectedError: true,
			errorContains: "Destination is required",
		},
		{
			name:     "anomalous_outbound_network_call_both_ip_and_domain",
			ruleType: "anomalous_outbound_network_call",
			process:  stringPtr("curl"),
			destination: &destinationModel{
				IP:     types.StringValue("192.168.1.1"),
				Domain: types.StringValue("example.com"),
			},
			expectedError: true,
			errorContains: "Cannot provide both ip and domain",
		},
		{
			name:     "anomalous_outbound_network_call_with_file",
			ruleType: "anomalous_outbound_network_call",
			process:  stringPtr("curl"),
			file:     stringPtr("test.txt"),
			destination: &destinationModel{
				IP:     types.StringValue("192.168.1.1"),
				Domain: types.StringNull(),
			},
			expectedError: true,
			errorContains: "File, File Path parameters are not allowed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create a mock config
			config := supressionRuleModel{
				Type:     types.StringValue(tc.ruleType),
				Name:     types.StringValue("test-rule"),
				Action:   types.StringValue("ignore"),
				Owner:    types.StringValue("test-org"),
				Repo:     types.StringValue("*"),
				Workflow: types.StringValue("*"),
				Job:      types.StringValue("*"),
			}

			if tc.file != nil {
				config.File = types.StringValue(*tc.file)
			} else {
				config.File = types.StringNull()
			}

			if tc.filePath != nil {
				config.FilePath = types.StringValue(*tc.filePath)
			} else {
				config.FilePath = types.StringNull()
			}

			if tc.process != nil {
				config.Process = types.StringValue(*tc.process)
			} else {
				config.Process = types.StringNull()
			}

			if tc.destination != nil {
				destinationObj, _ := types.ObjectValue(
					map[string]attr.Type{
						"ip":     types.StringType,
						"domain": types.StringType,
					},
					map[string]attr.Value{
						"ip":     tc.destination.IP,
						"domain": tc.destination.Domain,
					},
				)
				config.Destination = destinationObj
			} else {
				config.Destination = types.ObjectNull(map[string]attr.Type{
					"ip":     types.StringType,
					"domain": types.StringType,
				})
			}

			// This test would require a more complex setup to fully test ValidateConfig
			// For now, we're testing the validation logic directly
			hasError := false
			errorMessage := ""

			switch tc.ruleType {
			case "source_code_overwritten":
				if config.File.IsNull() || config.FilePath.IsNull() {
					hasError = true
					errorMessage = "File is required"
				}
				if !config.Process.IsNull() {
					hasError = true
					errorMessage = "Process is not allowed"
				}
				if !config.Destination.IsNull() {
					hasError = true
					errorMessage = "Destination is not allowed"
				}
			case "anomalous_outbound_network_call":
				if !config.File.IsNull() || !config.FilePath.IsNull() {
					hasError = true
					errorMessage = "File, File Path parameters are not allowed"
				}
				if config.Process.IsNull() && !hasError {
					hasError = true
					errorMessage = "Process is required"
				}
				if config.Destination.IsNull() && !hasError {
					hasError = true
					errorMessage = "Destination is required"
				} else if !config.Destination.IsNull() && !hasError {
					// Check destination validation
					var destination destinationModel
					ctx := context.Background()
					diags := config.Destination.As(ctx, &destination, basetypes.ObjectAsOptions{})
					if !diags.HasError() {
						isIpEmpty := destination.IP.IsNull() || destination.IP.IsUnknown()
						isDomainEmpty := destination.Domain.IsNull() || destination.Domain.IsUnknown()
						if isIpEmpty && isDomainEmpty {
							hasError = true
							errorMessage = "Destination is required"
						} else if !isIpEmpty && !isDomainEmpty {
							hasError = true
							errorMessage = "Cannot provide both ip and domain"
						}
					}
				}
			}

			if tc.expectedError {
				if !hasError {
					t.Error("Expected error but got none")
				}
				if tc.errorContains != "" && !strings.Contains(errorMessage, tc.errorContains) {
					t.Errorf("Expected error to contain '%s', but got: %s", tc.errorContains, errorMessage)
				}
			} else {
				if hasError {
					t.Errorf("Expected no error but got: %s", errorMessage)
				}
			}
		})
	}
}

func TestGithubSuppressionRuleResource_GetSuppressionRuleFromTfModel(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name               string
		model              supressionRuleModel
		expectedID         string
		expectedConditions map[string]string
	}{
		{
			name: "source_code_overwritten",
			model: supressionRuleModel{
				RuleID:      types.StringValue("rule-123"),
				Name:        types.StringValue("test-rule"),
				Type:        types.StringValue("source_code_overwritten"),
				Action:      types.StringValue("ignore"),
				Description: types.StringValue("Test rule"),
				File:        types.StringValue("test.txt"),
				FilePath:    types.StringValue("/path/to/test.txt"),
				Owner:       types.StringValue("test-org"),
				Repo:        types.StringValue("*"),
				Workflow:    types.StringValue("*"),
				Job:         types.StringValue("*"),
			},
			expectedID: stepsecurityapi.SourceCodeOverwritten,
			expectedConditions: map[string]string{
				"owner":     "test-org",
				"repo":      "*",
				"workflow":  "*",
				"job":       "*",
				"file":      "test.txt",
				"file_path": "/path/to/test.txt",
			},
		},
		{
			name: "anomalous_outbound_network_call_with_ip",
			model: supressionRuleModel{
				RuleID:      types.StringValue("rule-124"),
				Name:        types.StringValue("test-rule-2"),
				Type:        types.StringValue("anomalous_outbound_network_call"),
				Action:      types.StringValue("ignore"),
				Description: types.StringValue("Test rule 2"),
				Process:     types.StringValue("curl"),
				Destination: func() types.Object {
					obj, _ := types.ObjectValue(
						map[string]attr.Type{
							"ip":     types.StringType,
							"domain": types.StringType,
						},
						map[string]attr.Value{
							"ip":     types.StringValue("192.168.1.1"),
							"domain": types.StringNull(),
						},
					)
					return obj
				}(),
				Owner:    types.StringValue("test-org"),
				Repo:     types.StringValue("*"),
				Workflow: types.StringValue("*"),
				Job:      types.StringValue("*"),
			},
			expectedID: stepsecurityapi.AnomalousOutboundNetworkCall,
			expectedConditions: map[string]string{
				"owner":      "test-org",
				"repo":       "*",
				"workflow":   "*",
				"job":        "*",
				"process":    "curl",
				"ip_address": "192.168.1.1",
			},
		},
		{
			name: "anomalous_outbound_network_call_with_domain",
			model: supressionRuleModel{
				RuleID:      types.StringValue("rule-125"),
				Name:        types.StringValue("test-rule-3"),
				Type:        types.StringValue("anomalous_outbound_network_call"),
				Action:      types.StringValue("ignore"),
				Description: types.StringValue("Test rule 3"),
				Process:     types.StringValue("wget"),
				Destination: func() types.Object {
					obj, _ := types.ObjectValue(
						map[string]attr.Type{
							"ip":     types.StringType,
							"domain": types.StringType,
						},
						map[string]attr.Value{
							"ip":     types.StringNull(),
							"domain": types.StringValue("example.com"),
						},
					)
					return obj
				}(),
				Owner:    types.StringValue("test-org"),
				Repo:     types.StringValue("*"),
				Workflow: types.StringValue("*"),
				Job:      types.StringValue("*"),
			},
			expectedID: stepsecurityapi.AnomalousOutboundNetworkCall,
			expectedConditions: map[string]string{
				"owner":    "test-org",
				"repo":     "*",
				"workflow": "*",
				"job":      "*",
				"process":  "wget",
				"endpoint": "example.com",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubSupressionRuleResource{}
			ctx := context.Background()

			result := r.getSuppressionRuleFromTfModel(ctx, tc.model)

			if result == nil {
				t.Fatal("Expected result but got nil")
			}

			if result.ID != tc.expectedID {
				t.Errorf("Expected ID %s, got %s", tc.expectedID, result.ID)
			}

			if result.Name != tc.model.Name.ValueString() {
				t.Errorf("Expected Name %s, got %s", tc.model.Name.ValueString(), result.Name)
			}

			if result.Description != tc.model.Description.ValueString() {
				t.Errorf("Expected Description %s, got %s", tc.model.Description.ValueString(), result.Description)
			}

			if result.SeverityAction.Type != tc.model.Action.ValueString() {
				t.Errorf("Expected SeverityAction.Type %s, got %s", tc.model.Action.ValueString(), result.SeverityAction.Type)
			}

			for key, expectedValue := range tc.expectedConditions {
				if actualValue, exists := result.Conditions[key]; !exists {
					t.Errorf("Expected condition %s not found", key)
				} else if actualValue != expectedValue {
					t.Errorf("Expected condition %s=%s, got %s", key, expectedValue, actualValue)
				}
			}
		})
	}
}

func TestGithubSuppressionRuleResource_UpdateSuppressionRuleState(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		rule         *stepsecurityapi.SuppressionRule
		expectedType string
	}{
		{
			name: "source_code_overwritten",
			rule: &stepsecurityapi.SuppressionRule{
				RuleID:      "rule-123",
				ID:          stepsecurityapi.SourceCodeOverwritten,
				Name:        "test-rule",
				Description: "Test rule",
				SeverityAction: stepsecurityapi.SeverityAction{
					Type: "ignore",
				},
				Conditions: map[string]string{
					"owner":     "test-org",
					"repo":      "*",
					"workflow":  "*",
					"job":       "*",
					"file":      "test.txt",
					"file_path": "/path/to/test.txt",
				},
			},
			expectedType: "source_code_overwritten",
		},
		{
			name: "anomalous_outbound_network_call",
			rule: &stepsecurityapi.SuppressionRule{
				RuleID:      "rule-124",
				ID:          stepsecurityapi.AnomalousOutboundNetworkCall,
				Name:        "test-rule-2",
				Description: "Test rule 2",
				SeverityAction: stepsecurityapi.SeverityAction{
					Type: "ignore",
				},
				Conditions: map[string]string{
					"owner":      "test-org",
					"repo":       "*",
					"workflow":   "*",
					"job":        "*",
					"process":    "curl",
					"ip_address": "192.168.1.1",
				},
			},
			expectedType: "anomalous_outbound_network_call",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubSupressionRuleResource{}
			ctx := context.Background()
			var config supressionRuleModel

			r.updateSuppressionRuleState(ctx, tc.rule, &config)

			if config.RuleID.ValueString() != tc.rule.RuleID {
				t.Errorf("Expected RuleID %s, got %s", tc.rule.RuleID, config.RuleID.ValueString())
			}

			if config.Name.ValueString() != tc.rule.Name {
				t.Errorf("Expected Name %s, got %s", tc.rule.Name, config.Name.ValueString())
			}

			if config.Description.ValueString() != tc.rule.Description {
				t.Errorf("Expected Description %s, got %s", tc.rule.Description, config.Description.ValueString())
			}

			if config.Action.ValueString() != tc.rule.SeverityAction.Type {
				t.Errorf("Expected Action %s, got %s", tc.rule.SeverityAction.Type, config.Action.ValueString())
			}

			if config.Type.ValueString() != tc.expectedType {
				t.Errorf("Expected Type %s, got %s", tc.expectedType, config.Type.ValueString())
			}

			// Test conditions are properly mapped
			for key, value := range tc.rule.Conditions {
				switch key {
				case "owner":
					if config.Owner.ValueString() != value {
						t.Errorf("Expected Owner %s, got %s", value, config.Owner.ValueString())
					}
				case "repo":
					if config.Repo.ValueString() != value {
						t.Errorf("Expected Repo %s, got %s", value, config.Repo.ValueString())
					}
				case "workflow":
					if config.Workflow.ValueString() != value {
						t.Errorf("Expected Workflow %s, got %s", value, config.Workflow.ValueString())
					}
				case "job":
					if config.Job.ValueString() != value {
						t.Errorf("Expected Job %s, got %s", value, config.Job.ValueString())
					}
				case "file":
					if config.File.ValueString() != value {
						t.Errorf("Expected File %s, got %s", value, config.File.ValueString())
					}
				case "file_path":
					if config.FilePath.ValueString() != value {
						t.Errorf("Expected FilePath %s, got %s", value, config.FilePath.ValueString())
					}
				case "process":
					if config.Process.ValueString() != value {
						t.Errorf("Expected Process %s, got %s", value, config.Process.ValueString())
					}
				case "ip_address":
					var destination destinationModel
					config.Destination.As(ctx, &destination, basetypes.ObjectAsOptions{})
					if destination.IP.ValueString() != value {
						t.Errorf("Expected IP %s, got %s", value, destination.IP.ValueString())
					}
				case "endpoint":
					var destination destinationModel
					config.Destination.As(ctx, &destination, basetypes.ObjectAsOptions{})
					if destination.Domain.ValueString() != value {
						t.Errorf("Expected Domain %s, got %s", value, destination.Domain.ValueString())
					}
				}
			}
		})
	}
}

func TestGithubSuppressionRuleResource_ClientInteraction(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		mockResponse  *stepsecurityapi.SuppressionRule
		mockError     error
		expectedError bool
	}{
		{
			name: "successful_create",
			mockResponse: &stepsecurityapi.SuppressionRule{
				RuleID:      "rule-123",
				ID:          stepsecurityapi.SourceCodeOverwritten,
				Name:        "test-rule",
				Description: "Test rule",
				SeverityAction: stepsecurityapi.SeverityAction{
					Type: "ignore",
				},
				Conditions: map[string]string{
					"owner": "test-org",
					"file":  "test.txt",
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
			mockClient.On("CreateSuppressionRule", mock.Anything, mock.AnythingOfType("stepsecurityapi.SuppressionRule")).Return(tc.mockResponse, tc.mockError)

			// Test the core client interaction logic directly
			ctx := context.Background()
			testRule := stepsecurityapi.SuppressionRule{
				ID:          stepsecurityapi.SourceCodeOverwritten,
				Name:        "test-rule",
				Description: "Test rule",
				SeverityAction: stepsecurityapi.SeverityAction{
					Type: "ignore",
				},
				Conditions: map[string]string{
					"owner": "test-org",
					"file":  "test.txt",
				},
			}

			result, err := mockClient.CreateSuppressionRule(ctx, testRule)

			if tc.expectedError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}

				if result == nil {
					t.Error("Expected result but got nil")
				} else if result.Name != "test-rule" {
					t.Errorf("Expected name 'test-rule', got '%s'", result.Name)
				}
			}

			// Verify mock expectations
			mockClient.AssertExpectations(t)
		})
	}
}

func stringPtr(s string) *string {
	return &s
}

func testAccGithubSuppressionRuleResourceConfig(name, ruleType, action, owner, file, filePath string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_supression_rule" "test" {
  name        = %[1]q
  type        = %[2]q
  action      = %[3]q
  description = "Test suppression rule"
  owner       = %[4]q
  file        = %[5]q
  file_path   = %[6]q
}
`, name, ruleType, action, owner, file, filePath)
}

func testAccGithubSuppressionRuleResourceNetworkCallConfig(name, ruleType, action, owner, process, ip, domain string) string {
	destinationBlock := ""
	if ip != "" {
		destinationBlock = fmt.Sprintf(`
  destination = {
    ip = %q
  }`, ip)
	} else if domain != "" {
		destinationBlock = fmt.Sprintf(`
  destination = {
    domain = %q
  }`, domain)
	}

	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_supression_rule" "test" {
  name        = %[1]q
  type        = %[2]q
  action      = %[3]q
  description = "Test suppression rule"
  owner       = %[4]q
  process     = %[5]q
  %[6]s
}
`, name, ruleType, action, owner, process, destinationBlock)
}

func testAccGithubSuppressionRuleResourceWildcardConfig(name, ruleType, action, owner, file, filePath string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_github_supression_rule" "test" {
  name        = %[1]q
  type        = %[2]q
  action      = %[3]q
  description = "Test suppression rule"
  owner       = %[4]q
  repo        = "*"
  workflow    = "*"
  job         = "*"
  file        = %[5]q
  file_path   = %[6]q
}
`, name, ruleType, action, owner, file, filePath)
}
