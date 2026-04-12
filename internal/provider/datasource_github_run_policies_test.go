package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

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

func TestGithubRunPoliciesDataSource_ReadMapsHardenRunnerFields(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	labels := []string{"ubuntu-step-security", "linux-secure"}
	customActions := []string{"acme/harden-runner", "octo/harden-runner-action"}
	now := time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.
		On("ListRunPolicies", mock.Anything, "test-org").
		Return([]stepsecurityapi.RunPolicy{
			{
				Owner:         "test-org",
				Customer:      "test-customer",
				PolicyID:      "policy-123",
				Name:          "Test Policy",
				CreatedBy:     "test-user",
				CreatedAt:     now,
				LastUpdatedBy: "test-user",
				LastUpdatedAt: now,
				AllRepos:      true,
				AllOrgs:       false,
				PolicyConfig: stepsecurityapi.RunPolicyConfig{
					Owner:                     "test-org",
					Name:                      "Test Policy",
					EnableHardenRunnerPolicy:  true,
					HardenRunnerLabels:        &labels,
					HardenRunnerCustomActions: &customActions,
				},
			},
		}, nil).
		Once()

	d := &githubRunPoliciesDataSource{client: mockClient}
	req := fwdatasource.ReadRequest{
		Config: testGithubRunPoliciesDataSourceConfigValue(t, githubRunPoliciesDataSourceModel{
			Owner:       types.StringValue("test-org"),
			RunPolicies: types.ListNull(types.ObjectType{AttrTypes: testRunPolicyDataSourceAttrTypes()}),
		}),
	}
	resp := &fwdatasource.ReadResponse{
		State: tfsdk.State{Schema: testGithubRunPoliciesDataSourceSchema(t)},
	}

	d.Read(ctx, req, resp)

	require.False(t, resp.Diagnostics.HasError())
	mockClient.AssertExpectations(t)

	var state githubRunPoliciesDataSourceModel
	diags := resp.State.Get(ctx, &state)
	require.False(t, diags.HasError())

	var runPolicies []githubRunPolicyDataSourceEntryModel
	diags = state.RunPolicies.ElementsAs(ctx, &runPolicies, false)
	require.False(t, diags.HasError())
	require.Len(t, runPolicies, 1)

	var policyConfig githubRunPolicyDataSourcePolicyConfigModel
	diags = runPolicies[0].PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError())

	assert.True(t, policyConfig.EnableHardenRunnerPolicy.ValueBool())
	assert.ElementsMatch(t, labels, setStrings(t, policyConfig.HardenRunnerLabels))
	assert.ElementsMatch(t, customActions, setStrings(t, policyConfig.HardenRunnerCustomActions))
}

type githubRunPolicyDataSourceEntryModel struct {
	Owner         types.String `tfsdk:"owner"`
	Customer      types.String `tfsdk:"customer"`
	PolicyID      types.String `tfsdk:"policy_id"`
	Name          types.String `tfsdk:"name"`
	CreatedBy     types.String `tfsdk:"created_by"`
	CreatedAt     types.String `tfsdk:"created_at"`
	LastUpdatedBy types.String `tfsdk:"last_updated_by"`
	LastUpdatedAt types.String `tfsdk:"last_updated_at"`
	AllRepos      types.Bool   `tfsdk:"all_repos"`
	AllOrgs       types.Bool   `tfsdk:"all_orgs"`
	Repositories  types.List   `tfsdk:"repositories"`
	PolicyConfig  types.Object `tfsdk:"policy_config"`
}

type githubRunPolicyDataSourcePolicyConfigModel struct {
	Owner                          types.String `tfsdk:"owner"`
	Name                           types.String `tfsdk:"name"`
	EnableActionPolicy             types.Bool   `tfsdk:"enable_action_policy"`
	AllowedActions                 types.Map    `tfsdk:"allowed_actions"`
	EnableHardenRunnerPolicy       types.Bool   `tfsdk:"enable_harden_runner_policy"`
	HardenRunnerLabels             types.Set    `tfsdk:"harden_runner_labels"`
	HardenRunnerCustomActions      types.Set    `tfsdk:"harden_runner_custom_actions"`
	EnableRunsOnPolicy             types.Bool   `tfsdk:"enable_runs_on_policy"`
	DisallowedRunnerLabels         types.Set    `tfsdk:"disallowed_runner_labels"`
	EnableSecretsPolicy            types.Bool   `tfsdk:"enable_secrets_policy"`
	EnableCompromisedActionsPolicy types.Bool   `tfsdk:"enable_compromised_actions_policy"`
	IsDryRun                       types.Bool   `tfsdk:"is_dry_run"`
}

func testGithubRunPoliciesDataSourceSchema(t *testing.T) datasourceschema.Schema {
	t.Helper()

	d := &githubRunPoliciesDataSource{}
	resp := &fwdatasource.SchemaResponse{}
	d.Schema(context.Background(), fwdatasource.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError())

	return resp.Schema
}

func testGithubRunPoliciesDataSourceConfigValue(t *testing.T, model githubRunPoliciesDataSourceModel) tfsdk.Config {
	t.Helper()

	state := tfsdk.State{Schema: testGithubRunPoliciesDataSourceSchema(t)}
	diags := state.Set(context.Background(), model)
	require.False(t, diags.HasError())

	return tfsdk.Config{
		Raw:    state.Raw,
		Schema: testGithubRunPoliciesDataSourceSchema(t),
	}
}

func testRunPolicyDataSourceAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"owner":           types.StringType,
		"customer":        types.StringType,
		"policy_id":       types.StringType,
		"name":            types.StringType,
		"created_by":      types.StringType,
		"created_at":      types.StringType,
		"last_updated_by": types.StringType,
		"last_updated_at": types.StringType,
		"all_repos":       types.BoolType,
		"all_orgs":        types.BoolType,
		"repositories":    types.ListType{ElemType: types.StringType},
		"policy_config": types.ObjectType{AttrTypes: map[string]attr.Type{
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
		}},
	}
}

func testAccGithubRunPoliciesDataSourceConfig(owner string) string {
	return fmt.Sprintf(`
data "stepsecurity_github_run_policies" "test" {
  owner = %[1]q
}
`, owner)
}
