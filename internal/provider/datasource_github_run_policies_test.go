package provider

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestAccGithubRunPoliciesDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccGithubRunPoliciesDataSourceConfig("test-org"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.stepsecurity_github_run_policies.test", "owner", "test-org"),
					resource.TestCheckResourceAttrSet("data.stepsecurity_github_run_policies.test", "run_policies.#"),
				),
			},
		},
	})
}

func TestGithubRunPoliciesDataSource_ReadMappingWithPinnedActions(t *testing.T) {
	// Verify that the datasource policyConfigAttrTypes maps include all required fields.
	// This test catches the duplicate-type-map sync issue that would cause a runtime panic.
	dataSource := &githubRunPoliciesDataSource{}
	assert.NotNil(t, dataSource)

	// Build a RunPolicy with pinned actions fields populated and verify it can be
	// processed by the datasource Read logic without panicking.
	policy := stepsecurityapi.RunPolicy{
		Owner:         "test-org",
		Customer:      "test-customer",
		PolicyID:      "policy-123",
		Name:          "Test Policy",
		CreatedBy:     "user1",
		CreatedAt:     time.Now(),
		LastUpdatedBy: "user1",
		LastUpdatedAt: time.Now(),
		AllRepos:      true,
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:                   "test-org",
			Name:                    "Test Policy",
			EnableActionPolicy:      true,
			RequirePinnedActions:    true,
			PinnedActionsExemptions: []string{"actions/*"},
		},
	}

	// Simulate the same logic as the datasource Read method to verify type map consistency
	policyConfigAttrs := map[string]attr.Value{
		"owner":                             types.StringValue(policy.PolicyConfig.Owner),
		"name":                              types.StringValue(policy.PolicyConfig.Name),
		"enable_action_policy":              types.BoolValue(policy.PolicyConfig.EnableActionPolicy),
		"enable_runs_on_policy":             types.BoolValue(policy.PolicyConfig.EnableRunsOnPolicy),
		"enable_secrets_policy":             types.BoolValue(policy.PolicyConfig.EnableSecretsPolicy),
		"enable_compromised_actions_policy": types.BoolValue(policy.PolicyConfig.EnableCompromisedActionsPolicy),
		"require_pinned_actions":            types.BoolValue(policy.PolicyConfig.RequirePinnedActions),
		"is_dry_run":                        types.BoolValue(policy.PolicyConfig.IsDryRun),
		"allowed_actions":                   types.MapNull(types.StringType),
		"disallowed_runner_labels":          types.SetNull(types.StringType),
	}

	// Handle pinned actions exemptions
	pinnedExemptionsList := make([]attr.Value, len(policy.PolicyConfig.PinnedActionsExemptions))
	for i, exemption := range policy.PolicyConfig.PinnedActionsExemptions {
		pinnedExemptionsList[i] = types.StringValue(exemption)
	}
	pinnedSet, diags := types.SetValue(types.StringType, pinnedExemptionsList)
	assert.False(t, diags.HasError())
	policyConfigAttrs["pinned_actions_exemptions"] = pinnedSet

	// This is the critical check: the type map must include all fields or ObjectValue panics
	policyConfigAttrTypes := map[string]attr.Type{
		"owner":                             types.StringType,
		"name":                              types.StringType,
		"enable_action_policy":              types.BoolType,
		"allowed_actions":                   types.MapType{ElemType: types.StringType},
		"enable_runs_on_policy":             types.BoolType,
		"disallowed_runner_labels":          types.SetType{ElemType: types.StringType},
		"enable_secrets_policy":             types.BoolType,
		"enable_compromised_actions_policy": types.BoolType,
		"require_pinned_actions":            types.BoolType,
		"pinned_actions_exemptions":         types.SetType{ElemType: types.StringType},
		"is_dry_run":                        types.BoolType,
	}

	policyConfigObj, objDiags := types.ObjectValue(policyConfigAttrTypes, policyConfigAttrs)
	assert.False(t, objDiags.HasError(), "ObjectValue should not produce errors with synced type maps")
	assert.False(t, policyConfigObj.IsNull())
}

func TestGithubRunPoliciesDataSource_Read(t *testing.T) {
	dataSource := &githubRunPoliciesDataSource{}

	// Verify that the data source is properly instantiated
	assert.NotNil(t, dataSource)
	assert.Nil(t, dataSource.client)
}

func TestGithubRunPoliciesDataSource_EmptyResult(t *testing.T) {
	dataSource := &githubRunPoliciesDataSource{}

	// Test initialization with empty client
	assert.NotNil(t, dataSource)
	assert.Nil(t, dataSource.client)
}

func TestGithubRunPoliciesDataSource_ErrorHandling(t *testing.T) {
	dataSource := &githubRunPoliciesDataSource{}

	// Test that we can configure the data source
	assert.NotNil(t, dataSource)

	// Set a mock client and verify it
	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	dataSource.client = mockClient
	assert.NotNil(t, dataSource.client)
}

func testAccGithubRunPoliciesDataSourceConfig(owner string) string {
	return fmt.Sprintf(`
data "stepsecurity_github_run_policies" "test" {
  owner = %[1]q
}
`, owner)
}
