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
	_ datasource.DataSource              = &githubRunPolicyEvaluationsDataSource{}
	_ datasource.DataSourceWithConfigure = &githubRunPolicyEvaluationsDataSource{}
)

// NewGithubRunPolicyEvaluationsDataSource is a helper function to simplify the provider implementation.
func NewGithubRunPolicyEvaluationsDataSource() datasource.DataSource {
	return &githubRunPolicyEvaluationsDataSource{}
}

// githubRunPolicyEvaluationsDataSource is the data source implementation.
type githubRunPolicyEvaluationsDataSource struct {
	client stepsecurityapi.Client
}

// githubRunPolicyEvaluationsDataSourceModel maps the data source schema data.
type githubRunPolicyEvaluationsDataSourceModel struct {
	Owner       types.String `tfsdk:"owner"`
	Repo        types.String `tfsdk:"repo"`
	Status      types.String `tfsdk:"status"`
	Evaluations types.List   `tfsdk:"evaluations"`
}

// Metadata returns the data source type name.
func (d *githubRunPolicyEvaluationsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_run_policy_evaluations"
}

// Schema defines the schema for the data source.
func (d *githubRunPolicyEvaluationsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves GitHub Actions run policy evaluations from StepSecurity. Can retrieve evaluations for an entire organization or a specific repository.",
		Attributes: map[string]schema.Attribute{
			"owner": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The GitHub organization or user to retrieve policy evaluations for.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"repo": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The name of the repository to retrieve policy evaluations for. If not specified, retrieves evaluations for the entire organization.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"status": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Filter evaluations by status. Allowed values: 'Allowed', 'Blocked'. If not specified, returns all evaluations.",
				Validators: []validator.String{
					stringvalidator.OneOf("Allowed", "Blocked"),
				},
			},
			"evaluations": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "List of run policy evaluations.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"owner": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The owner of the repository.",
						},
						"repo_full_name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The full name of the repository.",
						},
						"repo_workflow": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The repository workflow identifier.",
						},
						"head_branch": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The head branch of the workflow run.",
						},
						"workflow_name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The name of the workflow.",
						},
						"workflow_display_title": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The display title of the workflow.",
						},
						"workflow_file_path": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The file path of the workflow.",
						},
						"run_id": schema.Int64Attribute{
							Computed:            true,
							MarkdownDescription: "The ID of the workflow run.",
						},
						"workflow_run_started_at": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The timestamp when the workflow run started.",
						},
						"commit_message": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The commit message that triggered the run.",
						},
						"committer": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The person who made the commit.",
						},
						"event": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The event that triggered the workflow run.",
						},
						"run_number": schema.Int64Attribute{
							Computed:            true,
							MarkdownDescription: "The run number.",
						},
						"status": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The overall status of the policy evaluation (Allowed/Blocked).",
						},
						"policy_results": schema.ListNestedAttribute{
							Computed:            true,
							MarkdownDescription: "The results of individual policy evaluations.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"policy_owner": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "The owner of the policy.",
									},
									"policy_name": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "The name of the policy.",
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
									"action_policy_status": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "Status of the action policy evaluation.",
									},
									"actions_not_allowed": schema.ListAttribute{
										ElementType:         types.StringType,
										Computed:            true,
										MarkdownDescription: "List of actions that were not allowed.",
									},
									"runs_on_policy_status": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "Status of the runs-on policy evaluation.",
									},
									"runner_labels_not_allowed": schema.ListAttribute{
										ElementType:         types.StringType,
										Computed:            true,
										MarkdownDescription: "List of runner labels that were not allowed.",
									},
									"compromised_actions_policy_status": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "Status of the compromised actions policy evaluation.",
									},
									"compromised_actions_detected": schema.ListAttribute{
										ElementType:         types.StringType,
										Computed:            true,
										MarkdownDescription: "List of compromised actions that were detected.",
									},
									"secrets_policy_status": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "Status of the secrets policy evaluation.",
									},
									"is_non_default_branch": schema.BoolAttribute{
										Computed:            true,
										MarkdownDescription: "Whether the run is on a non-default branch.",
									},
									"workflow_contains_secrets": schema.BoolAttribute{
										Computed:            true,
										MarkdownDescription: "Whether the workflow contains secrets.",
									},
									"current_branch_hash": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "The hash of the current branch.",
									},
									"default_branch_hash": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "The hash of the default branch.",
									},
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
func (d *githubRunPolicyEvaluationsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *githubRunPolicyEvaluationsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state githubRunPolicyEvaluationsDataSourceModel
	diags := req.Config.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get status filter if provided
	var status string
	if !state.Status.IsNull() {
		status = state.Status.ValueString()
	}

	// Get run policy evaluations from API - choose org or repo level based on repo parameter
	var evaluations []stepsecurityapi.RunPolicyEvaluation
	var err error

	if state.Repo.IsNull() {
		// Organization-level evaluations
		evaluations, err = d.client.ListOrgRunPolicyEvaluations(ctx, state.Owner.ValueString(), status)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error reading organization run policy evaluations",
				"Could not read run policy evaluations for owner "+state.Owner.ValueString()+": "+err.Error(),
			)
			return
		}
	} else {
		// Repository-level evaluations
		evaluations, err = d.client.ListRepoRunPolicyEvaluations(ctx, state.Owner.ValueString(), state.Repo.ValueString(), status)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error reading repository run policy evaluations",
				"Could not read run policy evaluations for "+state.Owner.ValueString()+"/"+state.Repo.ValueString()+": "+err.Error(),
			)
			return
		}
	}

	// Convert API response to Terraform state
	evaluationsList := make([]attr.Value, 0, len(evaluations))

	for _, evaluation := range evaluations {
		// Convert policy results
		policyResultsList := make([]attr.Value, 0, len(evaluation.PolicyResults))

		for _, policyResult := range evaluation.PolicyResults {
			// Handle allowed actions map
			var allowedActionsMap types.Map
			if policyResult.Policy.AllowedActions != nil {
				allowedActions := make(map[string]attr.Value)
				for action, permission := range policyResult.Policy.AllowedActions {
					allowedActions[action] = types.StringValue(permission)
				}
				allowedActionsMap, _ = types.MapValue(types.StringType, allowedActions)
			} else {
				allowedActionsMap = types.MapNull(types.StringType)
			}

			// Handle disallowed runner labels set
			var disallowedRunnerLabelsSet types.Set
			if policyResult.Policy.DisallowedRunnerLabels != nil {
				disallowedLabels := make([]attr.Value, 0, len(policyResult.Policy.DisallowedRunnerLabels))
				for label := range policyResult.Policy.DisallowedRunnerLabels {
					disallowedLabels = append(disallowedLabels, types.StringValue(label))
				}
				disallowedRunnerLabelsSet, _ = types.SetValue(types.StringType, disallowedLabels)
			} else {
				disallowedRunnerLabelsSet = types.SetNull(types.StringType)
			}

			// Handle actions not allowed list
			var actionsNotAllowedList types.List
			if policyResult.ActionsNotAllowed != nil {
				actionsNotAllowed := make([]attr.Value, len(policyResult.ActionsNotAllowed))
				for i, action := range policyResult.ActionsNotAllowed {
					actionsNotAllowed[i] = types.StringValue(action)
				}
				actionsNotAllowedList, _ = types.ListValue(types.StringType, actionsNotAllowed)
			} else {
				actionsNotAllowedList = types.ListNull(types.StringType)
			}

			// Handle runner labels not allowed list
			var runnerLabelsNotAllowedList types.List
			if policyResult.RunnerLabelsNotAllowed != nil {
				runnerLabelsNotAllowed := make([]attr.Value, len(policyResult.RunnerLabelsNotAllowed))
				for i, label := range policyResult.RunnerLabelsNotAllowed {
					runnerLabelsNotAllowed[i] = types.StringValue(label)
				}
				runnerLabelsNotAllowedList, _ = types.ListValue(types.StringType, runnerLabelsNotAllowed)
			} else {
				runnerLabelsNotAllowedList = types.ListNull(types.StringType)
			}

			// Handle compromised actions detected list
			var compromisedActionsDetectedList types.List
			if policyResult.CompromisedActionsDetected != nil {
				compromisedActionsDetected := make([]attr.Value, len(policyResult.CompromisedActionsDetected))
				for i, action := range policyResult.CompromisedActionsDetected {
					compromisedActionsDetected[i] = types.StringValue(action)
				}
				compromisedActionsDetectedList, _ = types.ListValue(types.StringType, compromisedActionsDetected)
			} else {
				compromisedActionsDetectedList = types.ListNull(types.StringType)
			}

			// Handle boolean pointers
			var isNonDefaultBranch types.Bool
			if policyResult.IsNonDefaultBranch != nil {
				isNonDefaultBranch = types.BoolValue(*policyResult.IsNonDefaultBranch)
			} else {
				isNonDefaultBranch = types.BoolNull()
			}

			var workflowContainsSecrets types.Bool
			if policyResult.WorkflowContainsSecrets != nil {
				workflowContainsSecrets = types.BoolValue(*policyResult.WorkflowContainsSecrets)
			} else {
				workflowContainsSecrets = types.BoolNull()
			}

			// Create policy result object
			policyResultAttrs := map[string]attr.Value{
				"policy_owner":                         types.StringValue(policyResult.Policy.Owner),
				"policy_name":                          types.StringValue(policyResult.Policy.Name),
				"enable_action_policy":                 types.BoolValue(policyResult.Policy.EnableActionPolicy),
				"allowed_actions":                      allowedActionsMap,
				"enable_runs_on_policy":                types.BoolValue(policyResult.Policy.EnableRunsOnPolicy),
				"disallowed_runner_labels":             disallowedRunnerLabelsSet,
				"enable_secrets_policy":                types.BoolValue(policyResult.Policy.EnableSecretsPolicy),
				"enable_compromised_actions_policy":    types.BoolValue(policyResult.Policy.EnableCompromisedActionsPolicy),
				"action_policy_status":                 types.StringValue(policyResult.ActionPolicyStatus),
				"actions_not_allowed":                  actionsNotAllowedList,
				"runs_on_policy_status":                types.StringValue(policyResult.RunsOnPolicyStatus),
				"runner_labels_not_allowed":            runnerLabelsNotAllowedList,
				"compromised_actions_policy_status":    types.StringValue(policyResult.CompromisedActionsPolicyStatus),
				"compromised_actions_detected":         compromisedActionsDetectedList,
				"secrets_policy_status":                types.StringValue(policyResult.SecretsPolicyStatus),
				"is_non_default_branch":                isNonDefaultBranch,
				"workflow_contains_secrets":            workflowContainsSecrets,
				"current_branch_hash":                  types.StringValue(policyResult.CurrentBranchHash),
				"default_branch_hash":                  types.StringValue(policyResult.DefaultBranchHash),
			}

			policyResultAttrTypes := map[string]attr.Type{
				"policy_owner":                         types.StringType,
				"policy_name":                          types.StringType,
				"enable_action_policy":                 types.BoolType,
				"allowed_actions":                      types.MapType{ElemType: types.StringType},
				"enable_runs_on_policy":                types.BoolType,
				"disallowed_runner_labels":             types.SetType{ElemType: types.StringType},
				"enable_secrets_policy":                types.BoolType,
				"enable_compromised_actions_policy":    types.BoolType,
				"action_policy_status":                 types.StringType,
				"actions_not_allowed":                  types.ListType{ElemType: types.StringType},
				"runs_on_policy_status":                types.StringType,
				"runner_labels_not_allowed":            types.ListType{ElemType: types.StringType},
				"compromised_actions_policy_status":    types.StringType,
				"compromised_actions_detected":         types.ListType{ElemType: types.StringType},
				"secrets_policy_status":                types.StringType,
				"is_non_default_branch":                types.BoolType,
				"workflow_contains_secrets":            types.BoolType,
				"current_branch_hash":                  types.StringType,
				"default_branch_hash":                  types.StringType,
			}

			policyResultObj, _ := types.ObjectValue(policyResultAttrTypes, policyResultAttrs)
			policyResultsList = append(policyResultsList, policyResultObj)
		}

		// Create policy results list
		policyResultsListValue, _ := types.ListValue(types.ObjectType{AttrTypes: map[string]attr.Type{
			"policy_owner":                         types.StringType,
			"policy_name":                          types.StringType,
			"enable_action_policy":                 types.BoolType,
			"allowed_actions":                      types.MapType{ElemType: types.StringType},
			"enable_runs_on_policy":                types.BoolType,
			"disallowed_runner_labels":             types.SetType{ElemType: types.StringType},
			"enable_secrets_policy":                types.BoolType,
			"enable_compromised_actions_policy":    types.BoolType,
			"action_policy_status":                 types.StringType,
			"actions_not_allowed":                  types.ListType{ElemType: types.StringType},
			"runs_on_policy_status":                types.StringType,
			"runner_labels_not_allowed":            types.ListType{ElemType: types.StringType},
			"compromised_actions_policy_status":    types.StringType,
			"compromised_actions_detected":         types.ListType{ElemType: types.StringType},
			"secrets_policy_status":                types.StringType,
			"is_non_default_branch":                types.BoolType,
			"workflow_contains_secrets":            types.BoolType,
			"current_branch_hash":                  types.StringType,
			"default_branch_hash":                  types.StringType,
		}}, policyResultsList)

		// Create evaluation object
		evaluationAttrs := map[string]attr.Value{
			"owner":                    types.StringValue(evaluation.Owner),
			"repo_full_name":           types.StringValue(evaluation.RepoFullName),
			"repo_workflow":            types.StringValue(evaluation.RepoWorkflow),
			"head_branch":              types.StringValue(evaluation.HeadBranch),
			"workflow_name":            types.StringValue(evaluation.WorkflowName),
			"workflow_display_title":   types.StringValue(evaluation.WorkflowDisplayTitle),
			"workflow_file_path":       types.StringValue(evaluation.WorkflowFilePath),
			"run_id":                   types.Int64Value(evaluation.RunID),
			"workflow_run_started_at":  types.StringValue(time.Unix(evaluation.WorkflowRunStartedAt, 0).Format(time.RFC3339)),
			"commit_message":           types.StringValue(evaluation.CommitMessage),
			"committer":                types.StringValue(evaluation.Committer),
			"event":                    types.StringValue(evaluation.Event),
			"run_number":               types.Int64Value(int64(evaluation.RunNumber)),
			"status":                   types.StringValue(evaluation.Status),
			"policy_results":           policyResultsListValue,
		}

		evaluationAttrTypes := map[string]attr.Type{
			"owner":                    types.StringType,
			"repo_full_name":           types.StringType,
			"repo_workflow":            types.StringType,
			"head_branch":              types.StringType,
			"workflow_name":            types.StringType,
			"workflow_display_title":   types.StringType,
			"workflow_file_path":       types.StringType,
			"run_id":                   types.Int64Type,
			"workflow_run_started_at":  types.StringType,
			"commit_message":           types.StringType,
			"committer":                types.StringType,
			"event":                    types.StringType,
			"run_number":               types.Int64Type,
			"status":                   types.StringType,
			"policy_results": types.ListType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{
				"policy_owner":                         types.StringType,
				"policy_name":                          types.StringType,
				"enable_action_policy":                 types.BoolType,
				"allowed_actions":                      types.MapType{ElemType: types.StringType},
				"enable_runs_on_policy":                types.BoolType,
				"disallowed_runner_labels":             types.SetType{ElemType: types.StringType},
				"enable_secrets_policy":                types.BoolType,
				"enable_compromised_actions_policy":    types.BoolType,
				"action_policy_status":                 types.StringType,
				"actions_not_allowed":                  types.ListType{ElemType: types.StringType},
				"runs_on_policy_status":                types.StringType,
				"runner_labels_not_allowed":            types.ListType{ElemType: types.StringType},
				"compromised_actions_policy_status":    types.StringType,
				"compromised_actions_detected":         types.ListType{ElemType: types.StringType},
				"secrets_policy_status":                types.StringType,
				"is_non_default_branch":                types.BoolType,
				"workflow_contains_secrets":            types.BoolType,
				"current_branch_hash":                  types.StringType,
				"default_branch_hash":                  types.StringType,
			}}},
		}

		evaluationObj, _ := types.ObjectValue(evaluationAttrTypes, evaluationAttrs)
		evaluationsList = append(evaluationsList, evaluationObj)
	}

	// Create the final evaluations list
	evaluationsListValue, _ := types.ListValue(types.ObjectType{AttrTypes: map[string]attr.Type{
		"owner":                    types.StringType,
		"repo_full_name":           types.StringType,
		"repo_workflow":            types.StringType,
		"head_branch":              types.StringType,
		"workflow_name":            types.StringType,
		"workflow_display_title":   types.StringType,
		"workflow_file_path":       types.StringType,
		"run_id":                   types.Int64Type,
		"workflow_run_started_at":  types.StringType,
		"commit_message":           types.StringType,
		"committer":                types.StringType,
		"event":                    types.StringType,
		"run_number":               types.Int64Type,
		"status":                   types.StringType,
		"policy_results": types.ListType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{
			"policy_owner":                         types.StringType,
			"policy_name":                          types.StringType,
			"enable_action_policy":                 types.BoolType,
			"allowed_actions":                      types.MapType{ElemType: types.StringType},
			"enable_runs_on_policy":                types.BoolType,
			"disallowed_runner_labels":             types.SetType{ElemType: types.StringType},
			"enable_secrets_policy":                types.BoolType,
			"enable_compromised_actions_policy":    types.BoolType,
			"action_policy_status":                 types.StringType,
			"actions_not_allowed":                  types.ListType{ElemType: types.StringType},
			"runs_on_policy_status":                types.StringType,
			"runner_labels_not_allowed":            types.ListType{ElemType: types.StringType},
			"compromised_actions_policy_status":    types.StringType,
			"compromised_actions_detected":         types.ListType{ElemType: types.StringType},
			"secrets_policy_status":                types.StringType,
			"is_non_default_branch":                types.BoolType,
			"workflow_contains_secrets":            types.BoolType,
			"current_branch_hash":                  types.StringType,
			"default_branch_hash":                  types.StringType,
		}}},
	}}, evaluationsList)

	state.Evaluations = evaluationsListValue

	// Set the state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}