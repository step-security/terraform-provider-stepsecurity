package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	resourcehelper "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestAccGithubRunPolicyResource(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			// Create and Read testing
			{
				Config: testAccGithubRunPolicyResourceConfig("test-org", "Test Policy"),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "owner", "test-org"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "name", "Test Policy"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "all_repos", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_action_policy", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_harden_runner_policy", "true"),
					resourcehelper.TestCheckTypeSetElemAttr("stepsecurity_github_run_policy.test", "policy_config.harden_runner_labels.*", "ubuntu-step-security"),
					resourcehelper.TestCheckTypeSetElemAttr("stepsecurity_github_run_policy.test", "policy_config.harden_runner_custom_actions.*", "my-org/harden-runner"),
					resourcehelper.TestCheckResourceAttrSet("stepsecurity_github_run_policy.test", "policy_id"),
					resourcehelper.TestCheckResourceAttrSet("stepsecurity_github_run_policy.test", "id"),
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
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "name", "Updated Test Policy"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_secrets_policy", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_harden_runner_policy", "true"),
					resourcehelper.TestCheckTypeSetElemAttr("stepsecurity_github_run_policy.test", "policy_config.harden_runner_labels.*", "ubuntu-step-security"),
					resourcehelper.TestCheckTypeSetElemAttr("stepsecurity_github_run_policy.test", "policy_config.harden_runner_custom_actions.*", "my-org/harden-runner"),
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
	hardenRunnerLabels := []string{"ubuntu-step-security", "linux-secure"}
	hardenRunnerCustomActions := []string{"my-org/harden-runner", "octo/harden-runner-action"}

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
			Owner:                    "test-org",
			Name:                     "Test Policy",
			EnableActionPolicy:       true,
			EnableHardenRunnerPolicy: true,
			AllowedActions: map[string]string{
				"actions/checkout": "allow",
			},
			EnableRunsOnPolicy: true,
			DisallowedRunnerLabels: map[string]struct{}{
				"self-hosted": {},
			},
			HardenRunnerLabels:        &hardenRunnerLabels,
			HardenRunnerCustomActions: &hardenRunnerCustomActions,
		},
	}

	var diags diag.Diagnostics
	resource.updateModelFromAPI(ctx, model, apiResponse, &diags)

	assert.Equal(t, "test-org", model.Owner.ValueString())
	assert.Equal(t, "test-policy-123", model.PolicyID.ValueString())
	assert.Equal(t, "Test Policy", model.Name.ValueString())
	assert.True(t, model.AllRepos.ValueBool())
	assert.False(t, model.AllOrgs.ValueBool())

	var policyConfig policyConfigModel
	diags = model.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError())
	assert.True(t, policyConfig.EnableHardenRunnerPolicy.ValueBool())
	assert.ElementsMatch(t, []string{"ubuntu-step-security", "linux-secure"}, setStrings(t, policyConfig.HardenRunnerLabels))
	assert.ElementsMatch(t, []string{"my-org/harden-runner", "octo/harden-runner-action"}, setStrings(t, policyConfig.HardenRunnerCustomActions))
}

func TestGithubRunPolicyResource_UpdateSendsEmptyHardenRunnerSets(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	previousLabels := []string{"ubuntu-step-security"}
	previousActions := []string{"my-org/harden-runner"}
	now := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)

	state := githubRunPolicyResourceModel{
		Owner:        types.StringValue("test-org"),
		Name:         types.StringValue("Test Policy"),
		PolicyID:     types.StringValue("policy-123"),
		AllRepos:     types.BoolValue(true),
		AllOrgs:      types.BoolValue(false),
		Repositories: types.ListNull(types.StringType),
		PolicyConfig: testRunPolicyConfigObjectValue(policyConfigModel{
			Owner:                          types.StringValue("test-org"),
			Name:                           types.StringValue("Test Policy"),
			EnableActionPolicy:             types.BoolValue(false),
			AllowedActions:                 types.MapNull(types.StringType),
			EnableHardenRunnerPolicy:       types.BoolValue(true),
			HardenRunnerLabels:             types.SetValueMust(types.StringType, testStringAttrValues(previousLabels)),
			HardenRunnerCustomActions:      types.SetValueMust(types.StringType, testStringAttrValues(previousActions)),
			EnableRunsOnPolicy:             types.BoolValue(false),
			DisallowedRunnerLabels:         types.SetNull(types.StringType),
			EnableSecretsPolicy:            types.BoolValue(false),
			EnableCompromisedActionsPolicy: types.BoolValue(false),
			IsDryRun:                       types.BoolValue(false),
			ExemptedUsers:                  types.SetNull(types.StringType),
		}),
		CreatedBy:     types.StringValue("test-user"),
		CreatedAt:     types.StringValue(now.Format(time.RFC3339)),
		LastUpdatedBy: types.StringValue("test-user"),
		LastUpdatedAt: types.StringValue(now.Format(time.RFC3339)),
	}

	plan := githubRunPolicyResourceModel{
		Owner:        types.StringValue("test-org"),
		Name:         types.StringValue("Updated Policy"),
		PolicyID:     types.StringValue("policy-123"),
		AllRepos:     types.BoolValue(true),
		AllOrgs:      types.BoolValue(false),
		Repositories: types.ListNull(types.StringType),
		PolicyConfig: testRunPolicyConfigObjectValue(policyConfigModel{
			Owner:                          types.StringValue("test-org"),
			Name:                           types.StringValue("Updated Policy"),
			EnableActionPolicy:             types.BoolValue(false),
			AllowedActions:                 types.MapNull(types.StringType),
			EnableHardenRunnerPolicy:       types.BoolValue(true),
			HardenRunnerLabels:             types.SetValueMust(types.StringType, []attr.Value{}),
			HardenRunnerCustomActions:      types.SetValueMust(types.StringType, []attr.Value{}),
			EnableRunsOnPolicy:             types.BoolValue(false),
			DisallowedRunnerLabels:         types.SetNull(types.StringType),
			EnableSecretsPolicy:            types.BoolValue(false),
			EnableCompromisedActionsPolicy: types.BoolValue(false),
			IsDryRun:                       types.BoolValue(false),
			ExemptedUsers:                  types.SetNull(types.StringType),
		}),
		CreatedBy:     types.StringNull(),
		CreatedAt:     types.StringNull(),
		LastUpdatedBy: types.StringNull(),
		LastUpdatedAt: types.StringNull(),
	}

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.
		On("UpdateRunPolicy", mock.Anything, "test-org", "policy-123", mock.MatchedBy(func(req stepsecurityapi.UpdateRunPolicyRequest) bool {
			if req.Name != "Updated Policy" || !req.PolicyConfig.EnableHardenRunnerPolicy {
				return false
			}
			if req.PolicyConfig.Owner != "test-org" || req.PolicyConfig.Name != "Updated Policy" {
				return false
			}
			if req.PolicyConfig.HardenRunnerLabels == nil || req.PolicyConfig.HardenRunnerCustomActions == nil {
				return false
			}

			return len(*req.PolicyConfig.HardenRunnerLabels) == 0 &&
				len(*req.PolicyConfig.HardenRunnerCustomActions) == 0
		})).
		Return(&stepsecurityapi.RunPolicy{
			Owner:         "test-org",
			PolicyID:      "policy-123",
			Name:          "Updated Policy",
			CreatedBy:     "test-user",
			CreatedAt:     now,
			LastUpdatedBy: "reviewer",
			LastUpdatedAt: now,
			AllRepos:      true,
			AllOrgs:       false,
			PolicyConfig: stepsecurityapi.RunPolicyConfig{
				Owner:                    "test-org",
				Name:                     "Updated Policy",
				EnableHardenRunnerPolicy: true,
				// agent-api uses []string with `omitempty`, so cleared values can come back omitted.
				HardenRunnerLabels:        nil,
				HardenRunnerCustomActions: nil,
			},
		}, nil).
		Once()

	r := &githubRunPolicyResource{client: mockClient}
	req := fwresource.UpdateRequest{
		Plan:  testGithubRunPolicyPlan(t, plan),
		State: testGithubRunPolicyState(t, state),
	}
	resp := &fwresource.UpdateResponse{
		State: tfsdk.State{Schema: testGithubRunPolicyResourceSchema(t)},
	}

	r.Update(ctx, req, resp)

	require.False(t, resp.Diagnostics.HasError())
	mockClient.AssertExpectations(t)

	var updatedState githubRunPolicyResourceModel
	diags := resp.State.Get(ctx, &updatedState)
	require.False(t, diags.HasError())

	var policyConfig policyConfigModel
	diags = updatedState.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError())

	assert.True(t, policyConfig.EnableHardenRunnerPolicy.ValueBool())
	assert.False(t, policyConfig.HardenRunnerLabels.IsNull())
	assert.False(t, policyConfig.HardenRunnerCustomActions.IsNull())
	assert.Empty(t, setStrings(t, policyConfig.HardenRunnerLabels))
	assert.Empty(t, setStrings(t, policyConfig.HardenRunnerCustomActions))
}

func testGithubRunPolicyResourceSchema(t *testing.T) resourceschema.Schema {
	t.Helper()

	r := &githubRunPolicyResource{}
	resp := &fwresource.SchemaResponse{}
	r.Schema(context.Background(), fwresource.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError())

	return resp.Schema
}

func testGithubRunPolicyPlan(t *testing.T, model githubRunPolicyResourceModel) tfsdk.Plan {
	t.Helper()

	plan := tfsdk.Plan{Schema: testGithubRunPolicyResourceSchema(t)}
	diags := plan.Set(context.Background(), model)
	require.False(t, diags.HasError())

	return plan
}

func testGithubRunPolicyState(t *testing.T, model githubRunPolicyResourceModel) tfsdk.State {
	t.Helper()

	state := tfsdk.State{Schema: testGithubRunPolicyResourceSchema(t)}
	diags := state.Set(context.Background(), model)
	require.False(t, diags.HasError())

	return state
}

func testRunPolicyConfigObjectValue(policyConfig policyConfigModel) types.Object {
	return types.ObjectValueMust(map[string]attr.Type{
		"owner":                             types.StringType,
		"name":                              types.StringType,
		"enable_action_policy":              types.BoolType,
		"allowed_actions":                   types.MapType{ElemType: types.StringType},
		"enable_harden_runner_policy":       types.BoolType,
		"harden_runner_labels":              types.SetType{ElemType: types.StringType},
		"harden_runner_custom_actions":      types.SetType{ElemType: types.StringType},
		"enable_runs_on_policy":             types.BoolType,
		"disallowed_runner_labels":          types.SetType{ElemType: types.StringType},
		"enable_secrets_policy":             types.BoolType,
		"enable_compromised_actions_policy": types.BoolType,
		"is_dry_run":                        types.BoolType,
		"exempted_users":                    types.SetType{ElemType: types.StringType},
	}, map[string]attr.Value{
		"owner":                             policyConfig.Owner,
		"name":                              policyConfig.Name,
		"enable_action_policy":              policyConfig.EnableActionPolicy,
		"allowed_actions":                   policyConfig.AllowedActions,
		"enable_harden_runner_policy":       policyConfig.EnableHardenRunnerPolicy,
		"harden_runner_labels":              policyConfig.HardenRunnerLabels,
		"harden_runner_custom_actions":      policyConfig.HardenRunnerCustomActions,
		"enable_runs_on_policy":             policyConfig.EnableRunsOnPolicy,
		"disallowed_runner_labels":          policyConfig.DisallowedRunnerLabels,
		"enable_secrets_policy":             policyConfig.EnableSecretsPolicy,
		"enable_compromised_actions_policy": policyConfig.EnableCompromisedActionsPolicy,
		"is_dry_run":                        policyConfig.IsDryRun,
		"exempted_users":                    policyConfig.ExemptedUsers,
	})
}

func testStringAttrValues(values []string) []attr.Value {
	result := make([]attr.Value, len(values))
	for i, value := range values {
		result[i] = types.StringValue(value)
	}

	return result
}

func setStrings(t *testing.T, value types.Set) []string {
	t.Helper()

	var result []string
	diags := value.ElementsAs(context.Background(), &result, false)
	require.False(t, diags.HasError())
	return result
}

func testAccGithubRunPolicyResourceConfig(owner, name string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_run_policy" "test" {
  owner     = %[1]q
  name      = %[2]q
  all_repos = true

  policy_config = {
    owner                        = %[1]q
    name                         = %[2]q
    enable_action_policy         = true
    enable_harden_runner_policy  = true
    harden_runner_labels         = ["ubuntu-step-security"]
    harden_runner_custom_actions = ["my-org/harden-runner"]
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
    owner                        = %[1]q
    name                         = %[2]q
    enable_action_policy         = true
    enable_harden_runner_policy  = true
    enable_secrets_policy        = true
    harden_runner_labels         = ["ubuntu-step-security"]
    harden_runner_custom_actions = ["my-org/harden-runner"]
    allowed_actions = {
      "actions/checkout"             = "allow"
      "step-security/harden-runner" = "allow"
    }
  }
}
`, owner, name)
}
