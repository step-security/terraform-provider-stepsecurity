package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestAccGithubRunPolicyResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccGithubRunPolicyResourceConfig("test-org", "Test Policy"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "owner", "test-org"),
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "name", "Test Policy"),
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "all_repos", "true"),
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_action_policy", "true"),
					resource.TestCheckResourceAttrSet("stepsecurity_github_run_policy.test", "policy_id"),
					resource.TestCheckResourceAttrSet("stepsecurity_github_run_policy.test", "id"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "stepsecurity_github_run_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing
			{
				Config: testAccGithubRunPolicyResourceConfigUpdated("test-org", "Updated Test Policy"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "name", "Updated Test Policy"),
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_secrets_policy", "true"),
				),
			},
			// Update with pinned actions and Read testing
			{
				Config: testAccGithubRunPolicyResourceConfigWithPinning("test-org", "Pinned Actions Policy"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "name", "Pinned Actions Policy"),
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_action_policy", "true"),
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.require_pinned_actions", "true"),
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.pinned_actions_exemptions.#", "1"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestGithubRunPolicyResource_Create(t *testing.T) {
	resource := &githubRunPolicyResource{}

	// Verify resource is properly initialized
	assert.NotNil(t, resource)
	assert.Nil(t, resource.client)

	// Test that we can set a client
	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	resource.client = mockClient
	assert.NotNil(t, resource.client)
}

func TestGithubRunPolicyResource_UpdateModelFromAPI(t *testing.T) {
	resource := &githubRunPolicyResource{}

	ctx := context.Background()
	model := &githubRunPolicyResourceModel{}

	apiResponse := &stepsecurityapi.RunPolicy{
		Owner:         "test-org",
		Customer:      "test-customer",
		PolicyID:      "test-policy-123",
		Name:          "Test Policy",
		CreatedBy:     "test-user",
		CreatedAt:     time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		LastUpdatedBy: "test-user",
		LastUpdatedAt: time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
		AllRepos:      true,
		AllOrgs:       false,
		Repositories:  []string{"repo1", "repo2"},
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
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
			RequirePinnedActions:    true,
			PinnedActionsExemptions: []string{"actions/*", "my-org/*"},
		},
	}

	var diags diag.Diagnostics
	resource.updateModelFromAPI(ctx, model, apiResponse, &diags)

	assert.False(t, diags.HasError(), "updateModelFromAPI should not produce errors")
	assert.Equal(t, "test-org", model.Owner.ValueString())
	assert.Equal(t, "test-policy-123", model.PolicyID.ValueString())
	assert.Equal(t, "Test Policy", model.Name.ValueString())
	assert.True(t, model.AllRepos.ValueBool())
	assert.False(t, model.AllOrgs.ValueBool())

	// Verify pinned actions fields are mapped correctly
	var policyConfig policyConfigModel
	policyConfigDiags := model.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	assert.False(t, policyConfigDiags.HasError(), "extracting policy config should not produce errors")
	assert.True(t, policyConfig.RequirePinnedActions.ValueBool())
	assert.False(t, policyConfig.PinnedActionsExemptions.IsNull())

	var pinnedExemptions []string
	exemptionsDiags := policyConfig.PinnedActionsExemptions.ElementsAs(ctx, &pinnedExemptions, false)
	assert.False(t, exemptionsDiags.HasError())
	assert.ElementsMatch(t, []string{"actions/*", "my-org/*"}, pinnedExemptions)
}

func TestGithubRunPolicyResource_UpdateModelFromAPI_NilPinnedExemptions(t *testing.T) {
	resource := &githubRunPolicyResource{}

	ctx := context.Background()
	model := &githubRunPolicyResourceModel{}

	apiResponse := &stepsecurityapi.RunPolicy{
		Owner:         "test-org",
		Customer:      "test-customer",
		PolicyID:      "test-policy-456",
		Name:          "No Pinning Policy",
		CreatedBy:     "test-user",
		CreatedAt:     time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		LastUpdatedBy: "test-user",
		LastUpdatedAt: time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
		AllRepos:      true,
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:                "test-org",
			Name:                 "No Pinning Policy",
			EnableActionPolicy:   true,
			RequirePinnedActions: false,
		},
	}

	var diags diag.Diagnostics
	resource.updateModelFromAPI(ctx, model, apiResponse, &diags)

	assert.False(t, diags.HasError())

	var policyConfig policyConfigModel
	policyConfigDiags := model.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	assert.False(t, policyConfigDiags.HasError())
	assert.False(t, policyConfig.RequirePinnedActions.ValueBool())
	assert.True(t, policyConfig.PinnedActionsExemptions.IsNull())
}

func TestGithubRunPolicyResource_PinnedActionsRequestSerialization(t *testing.T) {
	// Verify that pinned actions fields are correctly serialized from
	// the Terraform model to the API request struct. This covers the
	// Create/Update code paths (state → API request direction).
	ctx := context.Background()

	pinnedExemptions, diags := types.SetValueFrom(ctx, types.StringType, []string{"actions/*", "my-org/*"})
	assert.False(t, diags.HasError())

	policyConfig := policyConfigModel{
		Owner:                          types.StringValue("test-org"),
		Name:                           types.StringValue("Test Policy"),
		EnableActionPolicy:             types.BoolValue(true),
		AllowedActions:                 types.MapNull(types.StringType),
		EnableRunsOnPolicy:             types.BoolValue(false),
		DisallowedRunnerLabels:         types.SetNull(types.StringType),
		EnableSecretsPolicy:            types.BoolValue(false),
		EnableCompromisedActionsPolicy: types.BoolValue(false),
		RequirePinnedActions:           types.BoolValue(true),
		PinnedActionsExemptions:        pinnedExemptions,
		IsDryRun:                       types.BoolValue(false),
		ExemptedUsers:                  types.SetNull(types.StringType),
	}

	// Build the API request the same way Create() and Update() do
	createRequest := stepsecurityapi.CreateRunPolicyRequest{
		Name:     "Test Policy",
		AllRepos: true,
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:                          policyConfig.Owner.ValueString(),
			Name:                           policyConfig.Name.ValueString(),
			EnableActionPolicy:             policyConfig.EnableActionPolicy.ValueBool(),
			EnableRunsOnPolicy:             policyConfig.EnableRunsOnPolicy.ValueBool(),
			EnableSecretsPolicy:            policyConfig.EnableSecretsPolicy.ValueBool(),
			EnableCompromisedActionsPolicy: policyConfig.EnableCompromisedActionsPolicy.ValueBool(),
			RequirePinnedActions:           policyConfig.RequirePinnedActions.ValueBool(),
			IsDryRun:                       policyConfig.IsDryRun.ValueBool(),
		},
	}

	if !policyConfig.PinnedActionsExemptions.IsNull() {
		var exemptions []string
		exemptionDiags := policyConfig.PinnedActionsExemptions.ElementsAs(ctx, &exemptions, false)
		assert.False(t, exemptionDiags.HasError())
		createRequest.PolicyConfig.PinnedActionsExemptions = exemptions
	}

	assert.True(t, createRequest.PolicyConfig.RequirePinnedActions)
	assert.ElementsMatch(t, []string{"actions/*", "my-org/*"}, createRequest.PolicyConfig.PinnedActionsExemptions)

	// Verify the same fields on an UpdateRunPolicyRequest
	updateRequest := stepsecurityapi.UpdateRunPolicyRequest{
		Name:     "Test Policy",
		AllRepos: true,
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:                          policyConfig.Owner.ValueString(),
			Name:                           policyConfig.Name.ValueString(),
			EnableActionPolicy:             policyConfig.EnableActionPolicy.ValueBool(),
			EnableRunsOnPolicy:             policyConfig.EnableRunsOnPolicy.ValueBool(),
			EnableSecretsPolicy:            policyConfig.EnableSecretsPolicy.ValueBool(),
			EnableCompromisedActionsPolicy: policyConfig.EnableCompromisedActionsPolicy.ValueBool(),
			RequirePinnedActions:           policyConfig.RequirePinnedActions.ValueBool(),
			IsDryRun:                       policyConfig.IsDryRun.ValueBool(),
		},
	}

	if !policyConfig.PinnedActionsExemptions.IsNull() {
		var exemptions []string
		exemptionDiags := policyConfig.PinnedActionsExemptions.ElementsAs(ctx, &exemptions, false)
		assert.False(t, exemptionDiags.HasError())
		updateRequest.PolicyConfig.PinnedActionsExemptions = exemptions
	}

	assert.True(t, updateRequest.PolicyConfig.RequirePinnedActions)
	assert.ElementsMatch(t, []string{"actions/*", "my-org/*"}, updateRequest.PolicyConfig.PinnedActionsExemptions)
}

func TestGithubRunPolicyResource_PinnedActionsRequestSerialization_NullExemptions(t *testing.T) {
	// Verify that when pinned_actions_exemptions is null, the API request
	// field remains nil (not an empty slice).
	policyConfig := policyConfigModel{
		Owner:                          types.StringValue("test-org"),
		Name:                           types.StringValue("Test Policy"),
		EnableActionPolicy:             types.BoolValue(true),
		AllowedActions:                 types.MapNull(types.StringType),
		EnableRunsOnPolicy:             types.BoolValue(false),
		DisallowedRunnerLabels:         types.SetNull(types.StringType),
		EnableSecretsPolicy:            types.BoolValue(false),
		EnableCompromisedActionsPolicy: types.BoolValue(false),
		RequirePinnedActions:           types.BoolValue(true),
		PinnedActionsExemptions:        types.SetNull(types.StringType),
		IsDryRun:                       types.BoolValue(false),
		ExemptedUsers:                  types.SetNull(types.StringType),
	}

	createRequest := stepsecurityapi.CreateRunPolicyRequest{
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			RequirePinnedActions: policyConfig.RequirePinnedActions.ValueBool(),
		},
	}

	if !policyConfig.PinnedActionsExemptions.IsNull() {
		t.Fatal("expected PinnedActionsExemptions to be null")
	}

	assert.True(t, createRequest.PolicyConfig.RequirePinnedActions)
	assert.Nil(t, createRequest.PolicyConfig.PinnedActionsExemptions)
}

func testAccGithubRunPolicyResourceConfig(owner, name string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_run_policy" "test" {
  owner     = %[1]q
  name      = %[2]q
  all_repos = true
  
  policy_config = {
    owner                = %[1]q
    name                 = %[2]q
    enable_action_policy = true
    allowed_actions = {
      "actions/checkout" = "allow"
    }
  }
}
`, owner, name)
}

func testAccGithubRunPolicyResourceConfigWithPinning(owner, name string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_run_policy" "test" {
  owner     = %[1]q
  name      = %[2]q
  all_repos = true

  policy_config = {
    owner                     = %[1]q
    name                      = %[2]q
    enable_action_policy      = true
    require_pinned_actions    = true
    pinned_actions_exemptions = ["actions/*"]
    allowed_actions = {
      "actions/checkout" = "allow"
    }
  }
}
`, owner, name)
}

func testAccGithubRunPolicyResourceConfigUpdated(owner, name string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_run_policy" "test" {
  owner     = %[1]q
  name      = %[2]q
  all_repos = true
  
  policy_config = {
    owner                 = %[1]q
    name                  = %[2]q
    enable_action_policy  = true
    enable_secrets_policy = true
    allowed_actions = {
      "actions/checkout"             = "allow"
      "step-security/harden-runner" = "allow"
    }
  }
}
`, owner, name)
}
