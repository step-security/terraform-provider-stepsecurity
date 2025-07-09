package provider

import (
	"context"
	"fmt"
	"slices"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &policyDrivenPRResource{}
	_ resource.ResourceWithConfigure      = &policyDrivenPRResource{}
	_ resource.ResourceWithValidateConfig = &policyDrivenPRResource{}
	_ resource.ResourceWithImportState    = &policyDrivenPRResource{}
)

// NewPolicyDrivenPRResource is a helper function to simplify the provider implementation.
func NewPolicyDrivenPRResource() resource.Resource {
	return &policyDrivenPRResource{}
}

// policyDrivenPRResource is the resource implementation.
type policyDrivenPRResource struct {
	client stepsecurityapi.Client
}

// Configure adds the provider configured client to the resource.
func (r *policyDrivenPRResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(stepsecurityapi.Client)

	if !ok || client == nil {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected stepsecurityapi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

// Metadata returns the resource type name.
func (r *policyDrivenPRResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_driven_pr"
}

// Schema defines the schema for the resource.
func (r *policyDrivenPRResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The ID of the policy-driven PR. This is same as the owner/organization name.",
			},
			"owner": schema.StringAttribute{
				Required:    true,
				Description: "The owner/organization name where the policy-driven PR's to be created.",
			},
			"auto_remediation_options": schema.SingleNestedAttribute{
				Required: true,
				Attributes: map[string]schema.Attribute{
					"create_pr": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Create a PR when a finding is detected.",
						Default:     booldefault.StaticBool(true),
					},
					"create_issue": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Create an issue when a finding is detected.",
						Default:     booldefault.StaticBool(false),
					},
					"create_github_advanced_security_alert": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Create a GitHub Advanced Security alert when a finding is detected. Note that this triggers only when issue creation is enabled.",
						Default:     booldefault.StaticBool(false),
					},
					"harden_github_hosted_runner": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "When enabled, this creates a PR/issue to install security agent on the GitHub-hosted runner to prevent exfiltration of credentials, monitor the build process, and detect compromised dependencies.",
						Default:     booldefault.StaticBool(false),
					},
					"pin_actions_to_sha": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "When enabled, this creates a PR/issue to pin actions to SHA. GitHub's Security Hardening guide recommends pinning actions to full length commit for third party actions.",
						Default:     booldefault.StaticBool(false),
					},
					"restrict_github_token_permissions": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "When enabled, this creates a PR/issue to restrict GitHub token permissions. GitHub's Security Hardening guide recommends restricting permissions to the minimum required",
						Default:     booldefault.StaticBool(false),
					},
					"actions_to_exempt_while_pinning": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Description: "List of actions to exempt while pinning actions to SHA. When exempted, the action will not be pinned to SHA.",
						Default: listdefault.StaticValue(
							types.ListValueMust(
								types.StringType,
								[]attr.Value{},
							),
						),
					},
					"actions_to_replace_with_step_security_actions": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Description: "List of actions to replace with Step Security actions. When provided, the actions will be replaced with Step Security actions.",
						Default: listdefault.StaticValue(
							types.ListValueMust(
								types.StringType,
								[]attr.Value{},
							),
						),
					},
				},
			},
			"selected_repos": schema.ListAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "List of repositories to apply the policy-driven PR to. Can provide ['*'] to apply to all current and future repositories.",
			},
		},
	}
}

// ImportState implements resource.ResourceWithImportState.
func (r *policyDrivenPRResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID should be the owner name
	owner := req.ID

	// Set the owner in the state
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("owner"), owner)...)

	// Now call Read to populate the rest of the state
	readReq := resource.ReadRequest{
		State: resp.State,
	}
	readResp := &resource.ReadResponse{
		State: resp.State,
	}

	r.Read(ctx, readReq, readResp)

	// Copy any diagnostics and updated state from Read
	resp.Diagnostics.Append(readResp.Diagnostics...)
	resp.State = readResp.State
}

type policyDrivenPRModel struct {
	ID                    types.String `tfsdk:"id"`
	Owner                 types.String `tfsdk:"owner"`
	AutoRemdiationOptions types.Object `tfsdk:"auto_remediation_options"`
	SelectedRepos         types.List   `tfsdk:"selected_repos"`
}

type autoRemdiationOptionsModel struct {
	CreatePR                                types.Bool `tfsdk:"create_pr"`
	CreateIssue                             types.Bool `tfsdk:"create_issue"`
	CreateGitHubAdvancedSecurityAlert       types.Bool `tfsdk:"create_github_advanced_security_alert"`
	PinActionsToSHA                         types.Bool `tfsdk:"pin_actions_to_sha"`
	HardenGitHubHostedRunner                types.Bool `tfsdk:"harden_github_hosted_runner"`
	RestrictGitHubTokenPermissions          types.Bool `tfsdk:"restrict_github_token_permissions"`
	ActionsToExemptWhilePinning             types.List `tfsdk:"actions_to_exempt_while_pinning"`
	ActionsToReplaceWithStepSecurityActions types.List `tfsdk:"actions_to_replace_with_step_security_actions"`
}

type ActionsToReplaceModel struct {
	ActionName         string `tfsdk:"action_name"`
	StepSecurityAction string `tfsdk:"stepsecurity_action"`
}

func (r *policyDrivenPRResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config policyDrivenPRModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.SelectedRepos.IsNull() || len(config.SelectedRepos.Elements()) == 0 {
		resp.Diagnostics.AddError(
			"Selected Repos is required",
			"At least one repo is required in selected_repos",
		)
	}

	// Extract auto_remediation_options for validation
	if !config.AutoRemdiationOptions.IsNull() && !config.AutoRemdiationOptions.IsUnknown() {
		var options autoRemdiationOptionsModel
		diags := config.AutoRemdiationOptions.As(ctx, &options, basetypes.ObjectAsOptions{})
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		if !options.CreatePR.IsNull() && !options.CreateIssue.IsNull() &&
			options.CreatePR.ValueBool() && options.CreateIssue.ValueBool() {
			resp.Diagnostics.AddError(
				"Create PR and Create Issue cannot be both true",
				"Create PR and Create Issue cannot be both true",
			)
		}

		if !options.CreateGitHubAdvancedSecurityAlert.IsNull() && !options.CreateIssue.IsNull() &&
			options.CreateGitHubAdvancedSecurityAlert.ValueBool() && !options.CreateIssue.ValueBool() {
			resp.Diagnostics.AddError(
				"GitHub Advanced Security Alert can only be true if Create Issue is true",
				"GitHub Advanced Security Alert can only be triggered when issue creation is enabled",
			)
		}
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *policyDrivenPRResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyDrivenPRModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract auto_remediation_options
	var options autoRemdiationOptionsModel
	diags = plan.AutoRemdiationOptions.As(ctx, &options, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert Terraform types to Go types for API
	var selectedRepos []string
	if !plan.SelectedRepos.IsNull() {
		elements := plan.SelectedRepos.Elements()
		selectedRepos = make([]string, len(elements))
		for i, elem := range elements {
			selectedRepos[i] = elem.(types.String).ValueString()
		}
	}

	var actionsToExempt []string
	if !options.ActionsToExemptWhilePinning.IsNull() {
		elements := options.ActionsToExemptWhilePinning.Elements()
		actionsToExempt = make([]string, len(elements))
		for i, elem := range elements {
			actionsToExempt[i] = elem.(types.String).ValueString()
		}
	}

	var actionsToReplace []string
	if !options.ActionsToReplaceWithStepSecurityActions.IsNull() {
		elements := options.ActionsToReplaceWithStepSecurityActions.Elements()
		actionsToReplace = make([]string, len(elements))
		for i, elem := range elements {
			actionsToReplace[i] = elem.(types.String).ValueString()
		}
	}

	// convert to stepsecurityapi.PolicyDrivenPRPolicy
	stepSecurityPolicy := stepsecurityapi.PolicyDrivenPRPolicy{
		Owner: plan.Owner.ValueString(),
		AutoRemdiationOptions: stepsecurityapi.AutoRemdiationOptions{
			CreatePR:                                options.CreatePR.ValueBool(),
			CreateIssue:                             options.CreateIssue.ValueBool(),
			CreateGitHubAdvancedSecurityAlert:       options.CreateGitHubAdvancedSecurityAlert.ValueBool(),
			PinActionsToSHA:                         options.PinActionsToSHA.ValueBool(),
			HardenGitHubHostedRunner:                options.HardenGitHubHostedRunner.ValueBool(),
			RestrictGitHubTokenPermissions:          options.RestrictGitHubTokenPermissions.ValueBool(),
			ActionsToExemptWhilePinning:             actionsToExempt,
			ActionsToReplaceWithStepSecurityActions: actionsToReplace,
		},
		SelectedRepos: selectedRepos,
	}

	// Create policy-driven PR in StepSecurity
	err := r.client.CreatePolicyDrivenPRPolicy(ctx, stepSecurityPolicy)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create Policy-Driven PR",
			err.Error(),
		)
		return
	}

	// Set the ID (use owner as the unique identifier)
	plan.ID = types.StringValue(plan.Owner.ValueString())

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *policyDrivenPRResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyDrivenPRModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get policy-driven PR from StepSecurity
	stepSecurityPolicy, err := r.client.GetPolicyDrivenPRPolicy(ctx, state.Owner.ValueString())
	if err != nil || stepSecurityPolicy == nil {
		resp.Diagnostics.AddError(
			"Unable to Read Policy-Driven PR",
			err.Error(),
		)
		return
	}

	// overwrite items with refreshed state
	r.updatePolicyDrivenPRState(ctx, *stepSecurityPolicy, &state)

	// Set state to fully populated data
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *policyDrivenPRResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policyDrivenPRModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state policyDrivenPRModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert state and plan repos to string slices for comparison
	var stateRepos []string
	if !state.SelectedRepos.IsNull() {
		elements := state.SelectedRepos.Elements()
		stateRepos = make([]string, len(elements))
		for i, elem := range elements {
			stateRepos[i] = elem.(types.String).ValueString()
		}
	}

	var planRepos []string
	if !plan.SelectedRepos.IsNull() {
		elements := plan.SelectedRepos.Elements()
		planRepos = make([]string, len(elements))
		for i, elem := range elements {
			planRepos[i] = elem.(types.String).ValueString()
		}
	}

	var removedRepos []string
	for _, repo := range stateRepos {
		if !slices.Contains(planRepos, repo) {
			removedRepos = append(removedRepos, repo)
		}
	}

	// Extract auto_remediation_options from plan
	var planOptions autoRemdiationOptionsModel
	diags = plan.AutoRemdiationOptions.As(ctx, &planOptions, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var actionsToExempt []string
	if !planOptions.ActionsToExemptWhilePinning.IsNull() {
		elements := planOptions.ActionsToExemptWhilePinning.Elements()
		actionsToExempt = make([]string, len(elements))
		for i, elem := range elements {
			actionsToExempt[i] = elem.(types.String).ValueString()
		}
	}

	var actionsToReplace []string
	if !planOptions.ActionsToReplaceWithStepSecurityActions.IsNull() {
		elements := planOptions.ActionsToReplaceWithStepSecurityActions.Elements()
		actionsToReplace = make([]string, len(elements))
		for i, elem := range elements {
			actionsToReplace[i] = elem.(types.String).ValueString()
		}
	}

	policy := stepsecurityapi.PolicyDrivenPRPolicy{
		Owner: plan.Owner.ValueString(),
		AutoRemdiationOptions: stepsecurityapi.AutoRemdiationOptions{
			CreatePR:                                planOptions.CreatePR.ValueBool(),
			CreateIssue:                             planOptions.CreateIssue.ValueBool(),
			CreateGitHubAdvancedSecurityAlert:       planOptions.CreateGitHubAdvancedSecurityAlert.ValueBool(),
			PinActionsToSHA:                         planOptions.PinActionsToSHA.ValueBool(),
			HardenGitHubHostedRunner:                planOptions.HardenGitHubHostedRunner.ValueBool(),
			RestrictGitHubTokenPermissions:          planOptions.RestrictGitHubTokenPermissions.ValueBool(),
			ActionsToExemptWhilePinning:             actionsToExempt,
			ActionsToReplaceWithStepSecurityActions: actionsToReplace,
		},
		SelectedRepos: planRepos,
	}

	// Update policy-driven PR in StepSecurity
	err := r.client.UpdatePolicyDrivenPRPolicy(ctx, policy, removedRepos)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Update Policy-Driven PR",
			err.Error(),
		)
		return
	}

	// Set the ID (use owner as the unique identifier)
	plan.ID = types.StringValue(plan.Owner.ValueString())

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *policyDrivenPRResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyDrivenPRModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert state repos to string slice
	var stateRepos []string
	if !state.SelectedRepos.IsNull() {
		elements := state.SelectedRepos.Elements()
		stateRepos = make([]string, len(elements))
		for i, elem := range elements {
			stateRepos[i] = elem.(types.String).ValueString()
		}
	}

	// Delete policy-driven PR from StepSecurity
	err := r.client.DeletePolicyDrivenPRPolicy(ctx, state.Owner.ValueString(), stateRepos)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Delete Policy-Driven PR",
			err.Error(),
		)
		return
	}
}

func (r *policyDrivenPRResource) updatePolicyDrivenPRState(ctx context.Context, stepSecurityPolicy stepsecurityapi.PolicyDrivenPRPolicy, state *policyDrivenPRModel) {
	// Update basic fields
	state.ID = types.StringValue(stepSecurityPolicy.Owner)
	state.Owner = types.StringValue(stepSecurityPolicy.Owner)

	// Create auto_remediation_options object
	exemptElements := make([]types.String, len(stepSecurityPolicy.AutoRemdiationOptions.ActionsToExemptWhilePinning))
	for i, action := range stepSecurityPolicy.AutoRemdiationOptions.ActionsToExemptWhilePinning {
		exemptElements[i] = types.StringValue(action)
	}
	exemptList, _ := types.ListValueFrom(ctx, types.StringType, exemptElements)

	replaceElements := make([]types.String, len(stepSecurityPolicy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions))
	for i, action := range stepSecurityPolicy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions {
		replaceElements[i] = types.StringValue(action)
	}
	replaceList, _ := types.ListValueFrom(ctx, types.StringType, replaceElements)

	optionsObj, _ := types.ObjectValue(
		map[string]attr.Type{
			"create_pr":                                     types.BoolType,
			"create_issue":                                  types.BoolType,
			"create_github_advanced_security_alert":         types.BoolType,
			"harden_github_hosted_runner":                   types.BoolType,
			"pin_actions_to_sha":                            types.BoolType,
			"restrict_github_token_permissions":             types.BoolType,
			"actions_to_exempt_while_pinning":               types.ListType{ElemType: types.StringType},
			"actions_to_replace_with_step_security_actions": types.ListType{ElemType: types.StringType},
		},
		map[string]attr.Value{
			"create_pr":                                     types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.CreatePR),
			"create_issue":                                  types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.CreateIssue),
			"create_github_advanced_security_alert":         types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.CreateGitHubAdvancedSecurityAlert),
			"harden_github_hosted_runner":                   types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.HardenGitHubHostedRunner),
			"pin_actions_to_sha":                            types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.PinActionsToSHA),
			"restrict_github_token_permissions":             types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.RestrictGitHubTokenPermissions),
			"actions_to_exempt_while_pinning":               exemptList,
			"actions_to_replace_with_step_security_actions": replaceList,
		},
	)
	state.AutoRemdiationOptions = optionsObj

	// Only update selected_repos if it's null/unknown (preserve planned values)
	if state.SelectedRepos.IsNull() || state.SelectedRepos.IsUnknown() {
		repoElements := make([]types.String, len(stepSecurityPolicy.SelectedRepos))
		for i, repo := range stepSecurityPolicy.SelectedRepos {
			repoElements[i] = types.StringValue(repo)
		}
		repoList, _ := types.ListValueFrom(ctx, types.StringType, repoElements)
		state.SelectedRepos = repoList
	}
}
