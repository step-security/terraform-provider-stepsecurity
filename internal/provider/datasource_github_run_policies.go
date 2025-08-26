package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &githubRunPoliciesDataSource{}
	_ datasource.DataSourceWithConfigure = &githubRunPoliciesDataSource{}
)

// NewGithubRunPoliciesDataSource is a helper function to simplify the provider implementation.
func NewGithubRunPoliciesDataSource() datasource.DataSource {
	return &githubRunPoliciesDataSource{}
}

// githubRunPoliciesDataSource is the data source implementation.
type githubRunPoliciesDataSource struct {
	client stepsecurityapi.Client
}

// githubRunPoliciesDataSourceModel maps the data source schema data.
type githubRunPoliciesDataSourceModel struct {
	Owner        types.String `tfsdk:"owner"`
	RunPolicies  types.List   `tfsdk:"run_policies"`
}

// Metadata returns the data source type name.
func (d *githubRunPoliciesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_run_policies"
}

// Schema defines the schema for the data source.
func (d *githubRunPoliciesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves GitHub Actions run policies from StepSecurity.",
		Attributes: map[string]schema.Attribute{
			"owner": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The GitHub organization or user to retrieve policies for.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"run_policies": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "List of run policies for the specified owner.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"owner": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The owner of the policy.",
						},
						"customer": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The customer associated with the policy.",
						},
						"policy_id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The unique identifier for this policy.",
						},
						"name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The name of the run policy.",
						},
						"created_by": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The user who created this policy.",
						},
						"created_at": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The timestamp when this policy was created.",
						},
						"last_updated_by": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The user who last updated this policy.",
						},
						"last_updated_at": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The timestamp when this policy was last updated.",
						},
						"all_repos": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Whether this policy applies to all repositories in the organization.",
						},
						"all_orgs": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Whether this policy applies to all organizations.",
						},
						"repositories": schema.ListAttribute{
							ElementType:         types.StringType,
							Computed:            true,
							MarkdownDescription: "List of specific repositories this policy applies to.",
						},
						"policy_config": schema.SingleNestedAttribute{
							Computed:            true,
							MarkdownDescription: "The configuration for this run policy.",
							Attributes: map[string]schema.Attribute{
								"owner": schema.StringAttribute{
									Computed:            true,
									MarkdownDescription: "The owner of the policy configuration.",
								},
								"name": schema.StringAttribute{
									Computed:            true,
									MarkdownDescription: "The name of the policy configuration.",
								},
								"enable_action_policy": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether the action policy is enabled.",
								},
								"allowed_actions": schema.MapAttribute{
									ElementType:         types.StringType,
									Computed:            true,
									MarkdownDescription: "Map of allowed actions and their permissions.",
								},
								"enable_runs_on_policy": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether the runs-on policy is enabled.",
								},
								"disallowed_runner_labels": schema.SetAttribute{
									ElementType:         types.StringType,
									Computed:            true,
									MarkdownDescription: "Set of disallowed runner labels.",
								},
								"enable_secrets_policy": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether the secrets policy is enabled.",
								},
								"enable_compromised_actions_policy": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether the compromised actions policy is enabled.",
								},
								"is_dry_run": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether this policy is in dry-run mode.",
								},
							},
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *githubRunPoliciesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(stepsecurityapi.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected stepsecurityapi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

// Read refreshes the Terraform state with the latest data.
func (d *githubRunPoliciesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state githubRunPoliciesDataSourceModel
	diags := req.Config.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get run policies from API
	policies, err := d.client.ListRunPolicies(ctx, state.Owner.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading run policies",
			"Could not read run policies for owner "+state.Owner.ValueString()+": "+err.Error(),
		)
		return
	}

	// Convert API response to Terraform state
	runPoliciesList := make([]attr.Value, 0, len(policies))

	for _, policy := range policies {
		// Handle repositories list
		var reposList types.List
		if policy.Repositories != nil {
			repoValues := make([]attr.Value, len(policy.Repositories))
			for i, repo := range policy.Repositories {
				repoValues[i] = types.StringValue(repo)
			}
			reposList, _ = types.ListValue(types.StringType, repoValues)
		} else {
			reposList = types.ListNull(types.StringType)
		}

		// Handle policy configuration
		policyConfigAttrs := map[string]attr.Value{
			"owner":                            types.StringValue(policy.PolicyConfig.Owner),
			"name":                             types.StringValue(policy.PolicyConfig.Name),
			"enable_action_policy":             types.BoolValue(policy.PolicyConfig.EnableActionPolicy),
			"enable_runs_on_policy":            types.BoolValue(policy.PolicyConfig.EnableRunsOnPolicy),
			"enable_secrets_policy":            types.BoolValue(policy.PolicyConfig.EnableSecretsPolicy),
			"enable_compromised_actions_policy": types.BoolValue(policy.PolicyConfig.EnableCompromisedActionsPolicy),
			"is_dry_run":                       types.BoolValue(policy.PolicyConfig.IsDryRun),
		}

		// Handle allowed actions map
		if policy.PolicyConfig.AllowedActions != nil {
			allowedActionsMap := make(map[string]attr.Value)
			for action, permission := range policy.PolicyConfig.AllowedActions {
				allowedActionsMap[action] = types.StringValue(permission)
			}
			mapValue, _ := types.MapValue(types.StringType, allowedActionsMap)
			policyConfigAttrs["allowed_actions"] = mapValue
		} else {
			policyConfigAttrs["allowed_actions"] = types.MapNull(types.StringType)
		}

		// Handle disallowed runner labels set
		if policy.PolicyConfig.DisallowedRunnerLabels != nil {
			disallowedLabelsList := make([]attr.Value, 0, len(policy.PolicyConfig.DisallowedRunnerLabels))
			for label := range policy.PolicyConfig.DisallowedRunnerLabels {
				disallowedLabelsList = append(disallowedLabelsList, types.StringValue(label))
			}
			setValue, _ := types.SetValue(types.StringType, disallowedLabelsList)
			policyConfigAttrs["disallowed_runner_labels"] = setValue
		} else {
			policyConfigAttrs["disallowed_runner_labels"] = types.SetNull(types.StringType)
		}

		// Create the policy config object
		policyConfigAttrTypes := map[string]attr.Type{
			"owner":                            types.StringType,
			"name":                             types.StringType,
			"enable_action_policy":             types.BoolType,
			"allowed_actions":                  types.MapType{ElemType: types.StringType},
			"enable_runs_on_policy":            types.BoolType,
			"disallowed_runner_labels":         types.SetType{ElemType: types.StringType},
			"enable_secrets_policy":            types.BoolType,
			"enable_compromised_actions_policy": types.BoolType,
			"is_dry_run":                       types.BoolType,
		}

		policyConfigObj, _ := types.ObjectValue(policyConfigAttrTypes, policyConfigAttrs)

		// Create run policy object
		runPolicyAttrs := map[string]attr.Value{
			"owner":             types.StringValue(policy.Owner),
			"customer":          types.StringValue(policy.Customer),
			"policy_id":         types.StringValue(policy.PolicyID),
			"name":              types.StringValue(policy.Name),
			"created_by":        types.StringValue(policy.CreatedBy),
			"created_at":        types.StringValue(policy.CreatedAt.Format(time.RFC3339)),
			"last_updated_by":   types.StringValue(policy.LastUpdatedBy),
			"last_updated_at":   types.StringValue(policy.LastUpdatedAt.Format(time.RFC3339)),
			"all_repos":         types.BoolValue(policy.AllRepos),
			"all_orgs":          types.BoolValue(policy.AllOrgs),
			"repositories":      reposList,
			"policy_config":     policyConfigObj,
		}

		runPolicyAttrTypes := map[string]attr.Type{
			"owner":             types.StringType,
			"customer":          types.StringType,
			"policy_id":         types.StringType,
			"name":              types.StringType,
			"created_by":        types.StringType,
			"created_at":        types.StringType,
			"last_updated_by":   types.StringType,
			"last_updated_at":   types.StringType,
			"all_repos":         types.BoolType,
			"all_orgs":          types.BoolType,
			"repositories":      types.ListType{ElemType: types.StringType},
			"policy_config":     types.ObjectType{AttrTypes: policyConfigAttrTypes},
		}

		runPolicyObj, _ := types.ObjectValue(runPolicyAttrTypes, runPolicyAttrs)
		runPoliciesList = append(runPoliciesList, runPolicyObj)
	}

	// Create the final list
	runPolicyAttrTypes := map[string]attr.Type{
		"owner":             types.StringType,
		"customer":          types.StringType,
		"policy_id":         types.StringType,
		"name":              types.StringType,
		"created_by":        types.StringType,
		"created_at":        types.StringType,
		"last_updated_by":   types.StringType,
		"last_updated_at":   types.StringType,
		"all_repos":         types.BoolType,
		"all_orgs":          types.BoolType,
		"repositories":      types.ListType{ElemType: types.StringType},
		"policy_config": types.ObjectType{AttrTypes: map[string]attr.Type{
			"owner":                            types.StringType,
			"name":                             types.StringType,
			"enable_action_policy":             types.BoolType,
			"allowed_actions":                  types.MapType{ElemType: types.StringType},
			"enable_runs_on_policy":            types.BoolType,
			"disallowed_runner_labels":         types.SetType{ElemType: types.StringType},
			"enable_secrets_policy":            types.BoolType,
			"enable_compromised_actions_policy": types.BoolType,
			"is_dry_run":                       types.BoolType,
		}},
	}

	runPoliciesListValue, _ := types.ListValue(types.ObjectType{AttrTypes: runPolicyAttrTypes}, runPoliciesList)
	state.RunPolicies = runPoliciesListValue

	// Set the state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}