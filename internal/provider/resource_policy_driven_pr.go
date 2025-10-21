package provider

import (
	"context"
	"fmt"
	"slices"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &policyDrivenPRResource{}
	_ resource.ResourceWithConfigure      = &policyDrivenPRResource{}
	_ resource.ResourceWithValidateConfig = &policyDrivenPRResource{}
	_ resource.ResourceWithModifyPlan     = &policyDrivenPRResource{}
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
					"secure_docker_file": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "When enabled, this creates a PR/issue to secure Dockerfile by pinning base images to SHA.",
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
					"update_precommit_file": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Description: "List of pre-commit file paths to update (e.g., ['.pre-commit-config.yaml']).",
						Default: listdefault.StaticValue(
							types.ListValueMust(
								types.StringType,
								[]attr.Value{},
							),
						),
					},
					"package_ecosystem": schema.ListNestedAttribute{
						Optional:    true,
						Description: "List of package ecosystems to enable for dependency updates.",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"package": schema.StringAttribute{
									Required:    true,
									Description: "Package ecosystem (e.g., 'npm', 'pip', 'docker').",
								},
								"interval": schema.StringAttribute{
									Required:    true,
									Description: "Update interval (e.g., 'daily', 'weekly', 'monthly').",
								},
							},
						},
					},
					"add_workflows": schema.StringAttribute{
						Optional:    true,
						Description: "Additional workflows to add as part of policy-driven PR.",
					},
					"action_commit_map": schema.MapAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Description: "Map of actions to their corresponding commit SHAs to bypass pinning",
					},
				},
			},
			"selected_repos": schema.ListAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "List of repositories to apply the policy-driven PR to. Use ['*'] to apply to all repositories.",
			},
			"excluded_repos": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "List of repositories to exclude when selected_repos is ['*']. It restores their original configs (preserving configs from other Terraform resources) or deletes configs for repos that had none.",
				Default: listdefault.StaticValue(
					types.ListValueMust(
						types.StringType,
						[]attr.Value{},
					),
				),
			},
		},
	}
}

// ImportState implements resource.ResourceWithImportState.
func (r *policyDrivenPRResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID should be the owner name
	owner := req.ID

	// Discover the policy configuration for this owner
	policy, err := r.client.DiscoverPolicyDrivenPRConfig(ctx, owner)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Import Policy-Driven PR",
			fmt.Sprintf("Failed to discover policy configuration: %s", err.Error()),
		)
		return
	}

	if policy == nil || len(policy.SelectedRepos) == 0 {
		resp.Diagnostics.AddError(
			"Unable to Import Policy-Driven PR",
			fmt.Sprintf("No policy-driven PR configuration found for owner '%s'", owner),
		)
		return
	}

	// Convert the discovered policy to Terraform state
	var state policyDrivenPRModel
	state.ID = types.StringValue(owner)
	state.Owner = types.StringValue(owner)

	// Set selected_repos
	repoElements := make([]types.String, len(policy.SelectedRepos))
	for i, repo := range policy.SelectedRepos {
		repoElements[i] = types.StringValue(repo)
	}
	repoList, _ := types.ListValueFrom(ctx, types.StringType, repoElements)
	state.SelectedRepos = repoList

	// Set excluded_repos (empty by default for import)
	state.ExcludedRepos = types.ListValueMust(types.StringType, []attr.Value{})

	// Set auto_remediation_options
	exemptElements := make([]types.String, len(policy.AutoRemdiationOptions.ActionsToExemptWhilePinning))
	for i, action := range policy.AutoRemdiationOptions.ActionsToExemptWhilePinning {
		exemptElements[i] = types.StringValue(action)
	}
	exemptList, _ := types.ListValueFrom(ctx, types.StringType, exemptElements)

	replaceElements := make([]types.String, len(policy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions))
	for i, action := range policy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions {
		replaceElements[i] = types.StringValue(action)
	}
	replaceList, _ := types.ListValueFrom(ctx, types.StringType, replaceElements)

	var packageEcosystemList types.List
	if len(policy.AutoRemdiationOptions.PackageEcosystem) > 0 {
		var ecosystemObjects []attr.Value
		for _, ecosystem := range policy.AutoRemdiationOptions.PackageEcosystem {
			obj, _ := types.ObjectValue(
				map[string]attr.Type{
					"package":  types.StringType,
					"interval": types.StringType,
				},
				map[string]attr.Value{
					"package":  types.StringValue(ecosystem.Package),
					"interval": types.StringValue(ecosystem.Interval),
				},
			)
			ecosystemObjects = append(ecosystemObjects, obj)
		}
		packageEcosystemList, _ = types.ListValue(
			types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"package":  types.StringType,
					"interval": types.StringType,
				},
			},
			ecosystemObjects,
		)
	} else {
		packageEcosystemList = types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"package":  types.StringType,
				"interval": types.StringType,
			},
		})
	}

	var updatePrecommitFileList types.List
	if len(policy.AutoRemdiationOptions.UpdatePrecommitFile) > 0 {
		fileElements := make([]types.String, len(policy.AutoRemdiationOptions.UpdatePrecommitFile))
		for i, file := range policy.AutoRemdiationOptions.UpdatePrecommitFile {
			fileElements[i] = types.StringValue(file)
		}
		updatePrecommitFileList, _ = types.ListValueFrom(ctx, types.StringType, fileElements)
	} else {
		// Return empty list instead of null to match schema default
		updatePrecommitFileList = types.ListValueMust(types.StringType, []attr.Value{})
	}

	var addWorkflowsValue types.String
	if policy.AutoRemdiationOptions.AddWorkflows != "" {
		addWorkflowsValue = types.StringValue(policy.AutoRemdiationOptions.AddWorkflows)
	} else {
		addWorkflowsValue = types.StringNull()
	}

	optionsObj, _ := types.ObjectValue(
		map[string]attr.Type{
			"create_pr":                                     types.BoolType,
			"create_issue":                                  types.BoolType,
			"create_github_advanced_security_alert":         types.BoolType,
			"harden_github_hosted_runner":                   types.BoolType,
			"pin_actions_to_sha":                            types.BoolType,
			"restrict_github_token_permissions":             types.BoolType,
			"secure_docker_file":                            types.BoolType,
			"actions_to_exempt_while_pinning":               types.ListType{ElemType: types.StringType},
			"actions_to_replace_with_step_security_actions": types.ListType{ElemType: types.StringType},
			"update_precommit_file":                         types.ListType{ElemType: types.StringType},
			"package_ecosystem": types.ListType{
				ElemType: types.ObjectType{
					AttrTypes: map[string]attr.Type{
						"package":  types.StringType,
						"interval": types.StringType,
					},
				},
			},
			"add_workflows": types.StringType,
		},
		map[string]attr.Value{
			"create_pr":                                     types.BoolValue(policy.AutoRemdiationOptions.CreatePR),
			"create_issue":                                  types.BoolValue(policy.AutoRemdiationOptions.CreateIssue),
			"create_github_advanced_security_alert":         types.BoolValue(policy.AutoRemdiationOptions.CreateGitHubAdvancedSecurityAlert),
			"harden_github_hosted_runner":                   types.BoolValue(policy.AutoRemdiationOptions.HardenGitHubHostedRunner),
			"pin_actions_to_sha":                            types.BoolValue(policy.AutoRemdiationOptions.PinActionsToSHA),
			"restrict_github_token_permissions":             types.BoolValue(policy.AutoRemdiationOptions.RestrictGitHubTokenPermissions),
			"secure_docker_file":                            types.BoolValue(policy.AutoRemdiationOptions.SecureDockerFile),
			"actions_to_exempt_while_pinning":               exemptList,
			"actions_to_replace_with_step_security_actions": replaceList,
			"update_precommit_file":                         updatePrecommitFileList,
			"package_ecosystem":                             packageEcosystemList,
			"add_workflows":                                 addWorkflowsValue,
		},
	)
	state.AutoRemdiationOptions = optionsObj

	// Set the state
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

type policyDrivenPRModel struct {
	ID                    types.String `tfsdk:"id"`
	Owner                 types.String `tfsdk:"owner"`
	AutoRemdiationOptions types.Object `tfsdk:"auto_remediation_options"`
	SelectedRepos         types.List   `tfsdk:"selected_repos"`
	ExcludedRepos         types.List   `tfsdk:"excluded_repos"`
}

type autoRemdiationOptionsModel struct {
	CreatePR                                types.Bool   `tfsdk:"create_pr"`
	CreateIssue                             types.Bool   `tfsdk:"create_issue"`
	CreateGitHubAdvancedSecurityAlert       types.Bool   `tfsdk:"create_github_advanced_security_alert"`
	PinActionsToSHA                         types.Bool   `tfsdk:"pin_actions_to_sha"`
	HardenGitHubHostedRunner                types.Bool   `tfsdk:"harden_github_hosted_runner"`
	RestrictGitHubTokenPermissions          types.Bool   `tfsdk:"restrict_github_token_permissions"`
	SecureDockerFile                        types.Bool   `tfsdk:"secure_docker_file"`
	ActionsToExemptWhilePinning             types.List   `tfsdk:"actions_to_exempt_while_pinning"`
	ActionsToReplaceWithStepSecurityActions types.List   `tfsdk:"actions_to_replace_with_step_security_actions"`
	UpdatePrecommitFile                     types.List   `tfsdk:"update_precommit_file"`
	PackageEcosystem                        types.List   `tfsdk:"package_ecosystem"`
	AddWorkflows                            types.String `tfsdk:"add_workflows"`
}

type packageEcosystemModel struct {
	Package  types.String `tfsdk:"package"`
	Interval types.String `tfsdk:"interval"`
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
		return
	}

	// Get selected repos
	var selectedRepos []string
	elements := config.SelectedRepos.Elements()
	for _, elem := range elements {
		selectedRepos = append(selectedRepos, elem.(types.String).ValueString())
	}

	// Validate excluded_repos only makes sense with wildcard
	hasWildcard := len(selectedRepos) == 1 && selectedRepos[0] == "*"
	if !config.ExcludedRepos.IsNull() && len(config.ExcludedRepos.Elements()) > 0 {
		if !hasWildcard {
			resp.Diagnostics.AddError(
				"Invalid Configuration",
				"excluded_repos can only be used when selected_repos is ['*'] (wildcard for all repos)",
			)
		}
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

// ModifyPlan is called during terraform plan to check v2 features and show warnings
func (r *policyDrivenPRResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// If the entire plan is null, the resource is being destroyed, so we don't need to validate
	if req.Plan.Raw.IsNull() {
		return
	}

	// If the state is null, this is a create operation
	// If both state and plan are present, this is an update operation
	var plan policyDrivenPRModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract auto_remediation_options
	if plan.AutoRemdiationOptions.IsNull() || plan.AutoRemdiationOptions.IsUnknown() {
		return
	}

	var options autoRemdiationOptionsModel
	diags = plan.AutoRemdiationOptions.As(ctx, &options, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check v2 features during plan phase
	hasUpdatePrecommit := !options.UpdatePrecommitFile.IsNull() && !options.UpdatePrecommitFile.IsUnknown() && len(options.UpdatePrecommitFile.Elements()) > 0
	hasPackageEcosystem := !options.PackageEcosystem.IsNull() && !options.PackageEcosystem.IsUnknown() && len(options.PackageEcosystem.Elements()) > 0
	hasAddWorkflows := !options.AddWorkflows.IsNull() && !options.AddWorkflows.IsUnknown() && options.AddWorkflows.ValueString() != ""
	hasV2Features := hasUpdatePrecommit || hasPackageEcosystem || hasAddWorkflows

	if !hasV2Features {
		return
	}

	// Get selected repos to determine which repo to check
	var selectedRepos []string
	if !plan.SelectedRepos.IsNull() {
		elements := plan.SelectedRepos.Elements()
		selectedRepos = make([]string, len(elements))
		for i, elem := range elements {
			selectedRepos[i] = elem.(types.String).ValueString()
		}
	}

	// Determine which repo to check for subscription status
	checkRepo := "[all]"
	if len(selectedRepos) > 0 && selectedRepos[0] != "*" {
		checkRepo = selectedRepos[0]
	}

	status, err := r.client.GetSubscriptionStatus(ctx, plan.Owner.ValueString(), checkRepo)

	if err != nil {
		tflog.Warn(ctx, "Failed to check subscription status during plan, skipping v2 validation", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	if status == nil {
		tflog.Warn(ctx, "Subscription status returned nil during plan, skipping v2 validation", map[string]interface{}{})
		return
	}

	v2Enabled := status.AppFeatureFlags.IsPolicyDrivenPrV2Enabled

	if !v2Enabled {
		warningMessage := "Policy-driven PR v2 is not enabled for this subscription. The following v2-only features will be ignored:\n"
		if hasUpdatePrecommit {
			warningMessage += "- update_precommit_file\n"
		}
		if hasPackageEcosystem {
			warningMessage += "- package_ecosystem\n"
		}
		if hasAddWorkflows {
			warningMessage += "- add_workflows\n"
		}
		warningMessage += "\nTo use these features, please upgrade your subscription to enable policy-driven PR v2."

		resp.Diagnostics.AddWarning(
			"Policy-driven PR v2 Not Enabled",
			warningMessage,
		)
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

	var excludedRepos []string
	if !plan.ExcludedRepos.IsNull() {
		elements := plan.ExcludedRepos.Elements()
		excludedRepos = make([]string, len(elements))
		for i, elem := range elements {
			excludedRepos[i] = elem.(types.String).ValueString()
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

	// Extract new optional fields
	var packageEcosystem []stepsecurityapi.DependabotConfig
	if !options.PackageEcosystem.IsNull() {
		var ecosystemModels []packageEcosystemModel
		diags := options.PackageEcosystem.ElementsAs(ctx, &ecosystemModels, false)
		resp.Diagnostics.Append(diags...)
		if !resp.Diagnostics.HasError() {
			for _, model := range ecosystemModels {
				packageEcosystem = append(packageEcosystem, stepsecurityapi.DependabotConfig{
					Package:  model.Package.ValueString(),
					Interval: model.Interval.ValueString(),
				})
			}
		}
	}

	var updatePrecommitFile []string
	if !options.UpdatePrecommitFile.IsNull() {
		elements := options.UpdatePrecommitFile.Elements()
		updatePrecommitFile = make([]string, len(elements))
		for i, elem := range elements {
			updatePrecommitFile[i] = elem.(types.String).ValueString()
		}
	}

	// Automatically compute config levels based on selected_repos
	// If selected_repos = ["*"], use org-level config
	// Otherwise, use repo-level config
	hasWildcard := len(selectedRepos) == 1 && selectedRepos[0] == "*"
	useOrgLevel := hasWildcard
	useRepoLevel := !hasWildcard

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
			SecureDockerFile:                        options.SecureDockerFile.ValueBool(),
			ActionsToExemptWhilePinning:             actionsToExempt,
			ActionsToReplaceWithStepSecurityActions: actionsToReplace,
			UpdatePrecommitFile:                     updatePrecommitFile,
			PackageEcosystem:                        packageEcosystem,
			AddWorkflows:                            options.AddWorkflows.ValueString(),
		},
		SelectedRepos:      selectedRepos,
		UseRepoLevelConfig: useRepoLevel,
		UseOrgLevelConfig:  useOrgLevel,
	}

	// Handle excluded repos: Save their current configs before applying org-level config
	var excludedRepoConfigs map[string]*stepsecurityapi.PolicyDrivenPRPolicy
	var err error
	if len(selectedRepos) == 1 && selectedRepos[0] == "*" && len(excludedRepos) > 0 {
		excludedRepoConfigs = make(map[string]*stepsecurityapi.PolicyDrivenPRPolicy)
		for _, repo := range excludedRepos {
			// Read current config for this excluded repo
			currentConfig, err := r.client.GetPolicyDrivenPRPolicy(ctx, plan.Owner.ValueString(), []string{repo})
			if err != nil {
				tflog.Warn(ctx, "Failed to get current config for excluded repo", map[string]interface{}{
					"repo":  repo,
					"error": err.Error(),
				})
				continue
			}
			// Store the config if it exists and has settings
			if currentConfig != nil {
				excludedRepoConfigs[repo] = currentConfig
			}
		}
	}

	// Create policy-driven PR in StepSecurity
	err = r.client.CreatePolicyDrivenPRPolicy(ctx, stepSecurityPolicy)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create Policy-Driven PR",
			err.Error(),
		)
		return
	}

	// Restore original configs for excluded repos to prevent them from inheriting org-level config
	if len(excludedRepoConfigs) > 0 {
		for repo, originalConfig := range excludedRepoConfigs {
			// Restore the original config for this repo
			originalConfig.SelectedRepos = []string{repo}
			err = r.client.CreatePolicyDrivenPRPolicy(ctx, *originalConfig)
			if err != nil {
				resp.Diagnostics.AddError(
					"Unable to Restore Config for Excluded Repo",
					fmt.Sprintf("Failed to restore config for repo %s: %s", repo, err.Error()),
				)
				return
			}
			tflog.Info(ctx, "Restored original config for excluded repo", map[string]interface{}{
				"repo": repo,
			})
		}
	} else if len(selectedRepos) == 1 && selectedRepos[0] == "*" && len(excludedRepos) > 0 {
		// For excluded repos that had no previous config, delete them to prevent inheritance
		err = r.client.DeletePolicyDrivenPRPolicy(ctx, plan.Owner.ValueString(), excludedRepos)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Exclude Repos from Policy-Driven PR",
				fmt.Sprintf("Failed to exclude repos: %s", err.Error()),
			)
			return
		}
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

	// Get current state repos to determine what to query
	var stateSelectedRepos []string
	if !state.SelectedRepos.IsNull() {
		elements := state.SelectedRepos.Elements()
		stateSelectedRepos = make([]string, len(elements))
		for i, elem := range elements {
			stateSelectedRepos[i] = elem.(types.String).ValueString()
		}
	}

	var stateExcludedRepos []string
	if !state.ExcludedRepos.IsNull() {
		elements := state.ExcludedRepos.Elements()
		stateExcludedRepos = make([]string, len(elements))
		for i, elem := range elements {
			stateExcludedRepos[i] = elem.(types.String).ValueString()
		}
	}

	// Query based on what's in the state
	// For org-level (selected_repos = ["*"]), query org config
	// For repo-level, query specific repos
	var reposToQuery []string
	if len(stateSelectedRepos) == 1 && stateSelectedRepos[0] == "*" {
		reposToQuery = []string{"*"}
	} else {
		reposToQuery = append([]string{}, stateSelectedRepos...)
	}

	// Get policy-driven PR from StepSecurity
	stepSecurityPolicy, err := r.client.GetPolicyDrivenPRPolicy(ctx, state.Owner.ValueString(), reposToQuery)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Policy-Driven PR",
			err.Error(),
		)
		return
	}

	if stepSecurityPolicy == nil {
		resp.Diagnostics.AddError(
			"Unable to Read Policy-Driven PR",
			"Policy returned nil",
		)
		return
	}

	// Extract current state's v2 feature values before updating
	var currentStateOptions autoRemdiationOptionsModel
	var hasV2FeaturesInState bool
	if !state.AutoRemdiationOptions.IsNull() {
		diags := state.AutoRemdiationOptions.As(ctx, &currentStateOptions, basetypes.ObjectAsOptions{})
		if diags.HasError() {
			// If we can't extract, just continue without preserving
			hasV2FeaturesInState = false
		} else {
			// Check if state has v2 features
			hasUpdatePrecommit := !currentStateOptions.UpdatePrecommitFile.IsNull() && len(currentStateOptions.UpdatePrecommitFile.Elements()) > 0
			hasPackageEcosystem := !currentStateOptions.PackageEcosystem.IsNull() && len(currentStateOptions.PackageEcosystem.Elements()) > 0
			hasAddWorkflows := !currentStateOptions.AddWorkflows.IsNull() && currentStateOptions.AddWorkflows.ValueString() != ""
			hasV2FeaturesInState = hasUpdatePrecommit || hasPackageEcosystem || hasAddWorkflows
		}
	}

	// Check if v2 is enabled
	checkRepo := "[all]"
	if len(stateSelectedRepos) > 0 && stateSelectedRepos[0] != "*" {
		checkRepo = stateSelectedRepos[0]
	}

	var v2Enabled bool
	if hasV2FeaturesInState {
		status, err := r.client.GetSubscriptionStatus(ctx, state.Owner.ValueString(), checkRepo)
		if err != nil {
			tflog.Warn(ctx, "Failed to check subscription status during read, assuming v2 disabled", map[string]interface{}{
				"error": err.Error(),
			})
			v2Enabled = false
		} else if status != nil {
			v2Enabled = status.AppFeatureFlags.IsPolicyDrivenPrV2Enabled
		}
	}

	// Preserve features from state if API returns empty but state has values (avoid unnecessary diffs)
	// This handles both v1 features that might not be supported and v2 features when v2 is disabled
	if hasV2FeaturesInState && !v2Enabled {
		// Preserve v2 features from current state
		stepSecurityPolicy.AutoRemdiationOptions.UpdatePrecommitFile = []string{}
		if !currentStateOptions.UpdatePrecommitFile.IsNull() {
			elements := currentStateOptions.UpdatePrecommitFile.Elements()
			for _, elem := range elements {
				stepSecurityPolicy.AutoRemdiationOptions.UpdatePrecommitFile = append(
					stepSecurityPolicy.AutoRemdiationOptions.UpdatePrecommitFile,
					elem.(types.String).ValueString(),
				)
			}
		}

		stepSecurityPolicy.AutoRemdiationOptions.PackageEcosystem = []stepsecurityapi.DependabotConfig{}
		if !currentStateOptions.PackageEcosystem.IsNull() {
			var ecosystemModels []packageEcosystemModel
			currentStateOptions.PackageEcosystem.ElementsAs(ctx, &ecosystemModels, false)
			for _, model := range ecosystemModels {
				stepSecurityPolicy.AutoRemdiationOptions.PackageEcosystem = append(
					stepSecurityPolicy.AutoRemdiationOptions.PackageEcosystem,
					stepsecurityapi.DependabotConfig{
						Package:  model.Package.ValueString(),
						Interval: model.Interval.ValueString(),
					},
				)
			}
		}

		if !currentStateOptions.AddWorkflows.IsNull() {
			stepSecurityPolicy.AutoRemdiationOptions.AddWorkflows = currentStateOptions.AddWorkflows.ValueString()
		}

		tflog.Info(ctx, "Preserving v2 features in state as v2 is not enabled")
	}

	// Also preserve v1 features if API returns empty arrays but state has values
	if len(stepSecurityPolicy.AutoRemdiationOptions.ActionsToExemptWhilePinning) == 0 &&
		!currentStateOptions.ActionsToExemptWhilePinning.IsNull() &&
		len(currentStateOptions.ActionsToExemptWhilePinning.Elements()) > 0 {
		elements := currentStateOptions.ActionsToExemptWhilePinning.Elements()
		for _, elem := range elements {
			stepSecurityPolicy.AutoRemdiationOptions.ActionsToExemptWhilePinning = append(
				stepSecurityPolicy.AutoRemdiationOptions.ActionsToExemptWhilePinning,
				elem.(types.String).ValueString(),
			)
		}
		tflog.Info(ctx, "Preserving actions_to_exempt_while_pinning from state")
	}

	if len(stepSecurityPolicy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions) == 0 &&
		!currentStateOptions.ActionsToReplaceWithStepSecurityActions.IsNull() &&
		len(currentStateOptions.ActionsToReplaceWithStepSecurityActions.Elements()) > 0 {
		elements := currentStateOptions.ActionsToReplaceWithStepSecurityActions.Elements()
		for _, elem := range elements {
			stepSecurityPolicy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions = append(
				stepSecurityPolicy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions,
				elem.(types.String).ValueString(),
			)
		}
		tflog.Info(ctx, "Preserving actions_to_replace_with_step_security_actions from state")
	}

	// Update state with API response, preserving selected_repos and excluded_repos from state
	r.updatePolicyDrivenPRState(ctx, *stepSecurityPolicy, &state, stateSelectedRepos, stateExcludedRepos)

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

	var stateExcludedRepos []string
	if !state.ExcludedRepos.IsNull() {
		elements := state.ExcludedRepos.Elements()
		stateExcludedRepos = make([]string, len(elements))
		for i, elem := range elements {
			stateExcludedRepos[i] = elem.(types.String).ValueString()
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

	var planExcludedRepos []string
	if !plan.ExcludedRepos.IsNull() {
		elements := plan.ExcludedRepos.Elements()
		planExcludedRepos = make([]string, len(elements))
		for i, elem := range elements {
			planExcludedRepos[i] = elem.(types.String).ValueString()
		}
	}

	// Determine repos to be removed
	var removedRepos []string

	// If switching from org-level to repo-level, need to delete org config
	stateIsOrgLevel := len(stateRepos) == 1 && stateRepos[0] == "*"
	planIsOrgLevel := len(planRepos) == 1 && planRepos[0] == "*"

	if stateIsOrgLevel && !planIsOrgLevel {
		// Switching from org-level to repo-level
		removedRepos = append(removedRepos, "*")
	} else if !stateIsOrgLevel && !planIsOrgLevel {
		// Both repo-level, check for removed repos
		for _, repo := range stateRepos {
			if !slices.Contains(planRepos, repo) {
				removedRepos = append(removedRepos, repo)
			}
		}
	}

	// Handle repos that were excluded in state but not in plan (need to add them back)
	for _, repo := range stateExcludedRepos {
		if !slices.Contains(planExcludedRepos, repo) {
			// Repo was excluded before but not anymore, will be added by create call
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

	// Extract new optional fields for update
	var packageEcosystemPlan []stepsecurityapi.DependabotConfig
	if !planOptions.PackageEcosystem.IsNull() {
		var ecosystemModels []packageEcosystemModel
		diags := planOptions.PackageEcosystem.ElementsAs(ctx, &ecosystemModels, false)
		resp.Diagnostics.Append(diags...)
		if !resp.Diagnostics.HasError() {
			for _, model := range ecosystemModels {
				packageEcosystemPlan = append(packageEcosystemPlan, stepsecurityapi.DependabotConfig{
					Package:  model.Package.ValueString(),
					Interval: model.Interval.ValueString(),
				})
			}
		}
	}

	var updatePrecommitFilePlan []string
	if !planOptions.UpdatePrecommitFile.IsNull() {
		elements := planOptions.UpdatePrecommitFile.Elements()
		updatePrecommitFilePlan = make([]string, len(elements))
		for i, elem := range elements {
			updatePrecommitFilePlan[i] = elem.(types.String).ValueString()
		}
	}

	// Automatically compute config levels based on planRepos
	// If planRepos = ["*"], use org-level config
	// Otherwise, use repo-level config
	planHasWildcard := len(planRepos) == 1 && planRepos[0] == "*"
	useOrgLevel := planHasWildcard
	useRepoLevel := !planHasWildcard

	policy := stepsecurityapi.PolicyDrivenPRPolicy{
		Owner: plan.Owner.ValueString(),
		AutoRemdiationOptions: stepsecurityapi.AutoRemdiationOptions{
			CreatePR:                                planOptions.CreatePR.ValueBool(),
			CreateIssue:                             planOptions.CreateIssue.ValueBool(),
			CreateGitHubAdvancedSecurityAlert:       planOptions.CreateGitHubAdvancedSecurityAlert.ValueBool(),
			PinActionsToSHA:                         planOptions.PinActionsToSHA.ValueBool(),
			HardenGitHubHostedRunner:                planOptions.HardenGitHubHostedRunner.ValueBool(),
			RestrictGitHubTokenPermissions:          planOptions.RestrictGitHubTokenPermissions.ValueBool(),
			SecureDockerFile:                        planOptions.SecureDockerFile.ValueBool(),
			ActionsToExemptWhilePinning:             actionsToExempt,
			ActionsToReplaceWithStepSecurityActions: actionsToReplace,
			UpdatePrecommitFile:                     updatePrecommitFilePlan,
			PackageEcosystem:                        packageEcosystemPlan,
			AddWorkflows:                            planOptions.AddWorkflows.ValueString(),
		},
		SelectedRepos:      planRepos,
		UseRepoLevelConfig: useRepoLevel,
		UseOrgLevelConfig:  useOrgLevel,
	}

	// Handle excluded repos: Save their current configs before updating org-level config
	var excludedRepoConfigs map[string]*stepsecurityapi.PolicyDrivenPRPolicy
	if len(planRepos) == 1 && planRepos[0] == "*" && len(planExcludedRepos) > 0 {
		excludedRepoConfigs = make(map[string]*stepsecurityapi.PolicyDrivenPRPolicy)
		for _, repo := range planExcludedRepos {
			// Read current config for this excluded repo
			currentConfig, err := r.client.GetPolicyDrivenPRPolicy(ctx, plan.Owner.ValueString(), []string{repo})
			if err != nil {
				tflog.Warn(ctx, "Failed to get current config for excluded repo", map[string]interface{}{
					"repo":  repo,
					"error": err.Error(),
				})
				continue
			}
			// Store the config if it exists and has settings
			if currentConfig != nil {
				excludedRepoConfigs[repo] = currentConfig
			}
		}
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

	// Restore original configs for excluded repos to prevent them from inheriting org-level config
	if len(excludedRepoConfigs) > 0 {
		for repo, originalConfig := range excludedRepoConfigs {
			// Restore the original config for this repo
			originalConfig.SelectedRepos = []string{repo}
			err = r.client.CreatePolicyDrivenPRPolicy(ctx, *originalConfig)
			if err != nil {
				resp.Diagnostics.AddError(
					"Unable to Restore Config for Excluded Repo",
					fmt.Sprintf("Failed to restore config for repo %s: %s", repo, err.Error()),
				)
				return
			}
			tflog.Info(ctx, "Restored original config for excluded repo", map[string]interface{}{
				"repo": repo,
			})
		}
	}

	// Handle newly excluded repos that had no previous config - delete them to prevent inheritance
	for _, repo := range planExcludedRepos {
		if !slices.Contains(stateExcludedRepos, repo) {
			// Check if this repo had a config that we restored
			if _, restored := excludedRepoConfigs[repo]; !restored {
				// New exclusion with no previous config - delete it
				err = r.client.DeletePolicyDrivenPRPolicy(ctx, plan.Owner.ValueString(), []string{repo})
				if err != nil {
					resp.Diagnostics.AddError(
						"Unable to Exclude Repo from Policy-Driven PR",
						fmt.Sprintf("Failed to exclude repo %s: %s", repo, err.Error()),
					)
					return
				}
			}
		}
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

func (r *policyDrivenPRResource) updatePolicyDrivenPRState(ctx context.Context, stepSecurityPolicy stepsecurityapi.PolicyDrivenPRPolicy, state *policyDrivenPRModel, stateSelectedRepos []string, stateExcludedRepos []string) {
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

	// Handle new optional fields
	var packageEcosystemList types.List
	if len(stepSecurityPolicy.AutoRemdiationOptions.PackageEcosystem) > 0 {
		var ecosystemObjects []attr.Value
		for _, ecosystem := range stepSecurityPolicy.AutoRemdiationOptions.PackageEcosystem {
			obj, _ := types.ObjectValue(
				map[string]attr.Type{
					"package":  types.StringType,
					"interval": types.StringType,
				},
				map[string]attr.Value{
					"package":  types.StringValue(ecosystem.Package),
					"interval": types.StringValue(ecosystem.Interval),
				},
			)
			ecosystemObjects = append(ecosystemObjects, obj)
		}
		packageEcosystemList, _ = types.ListValue(
			types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"package":  types.StringType,
					"interval": types.StringType,
				},
			},
			ecosystemObjects,
		)
	} else {
		packageEcosystemList = types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"package":  types.StringType,
				"interval": types.StringType,
			},
		})
	}

	var updatePrecommitFileList types.List
	if len(stepSecurityPolicy.AutoRemdiationOptions.UpdatePrecommitFile) > 0 {
		fileElements := make([]types.String, len(stepSecurityPolicy.AutoRemdiationOptions.UpdatePrecommitFile))
		for i, file := range stepSecurityPolicy.AutoRemdiationOptions.UpdatePrecommitFile {
			fileElements[i] = types.StringValue(file)
		}
		updatePrecommitFileList, _ = types.ListValueFrom(ctx, types.StringType, fileElements)
	} else {
		// Return empty list instead of null to match schema default
		updatePrecommitFileList = types.ListValueMust(types.StringType, []attr.Value{})
	}

	var addWorkflowsValue types.String
	if stepSecurityPolicy.AutoRemdiationOptions.AddWorkflows != "" {
		addWorkflowsValue = types.StringValue(stepSecurityPolicy.AutoRemdiationOptions.AddWorkflows)
	} else {
		addWorkflowsValue = types.StringNull()
	}

	optionsObj, _ := types.ObjectValue(
		map[string]attr.Type{
			"create_pr":                                     types.BoolType,
			"create_issue":                                  types.BoolType,
			"create_github_advanced_security_alert":         types.BoolType,
			"harden_github_hosted_runner":                   types.BoolType,
			"pin_actions_to_sha":                            types.BoolType,
			"restrict_github_token_permissions":             types.BoolType,
			"secure_docker_file":                            types.BoolType,
			"actions_to_exempt_while_pinning":               types.ListType{ElemType: types.StringType},
			"actions_to_replace_with_step_security_actions": types.ListType{ElemType: types.StringType},
			"update_precommit_file":                         types.ListType{ElemType: types.StringType},
			"package_ecosystem": types.ListType{
				ElemType: types.ObjectType{
					AttrTypes: map[string]attr.Type{
						"package":  types.StringType,
						"interval": types.StringType,
					},
				},
			},
			"add_workflows": types.StringType,
		},
		map[string]attr.Value{
			"create_pr":                                     types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.CreatePR),
			"create_issue":                                  types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.CreateIssue),
			"create_github_advanced_security_alert":         types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.CreateGitHubAdvancedSecurityAlert),
			"harden_github_hosted_runner":                   types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.HardenGitHubHostedRunner),
			"pin_actions_to_sha":                            types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.PinActionsToSHA),
			"restrict_github_token_permissions":             types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.RestrictGitHubTokenPermissions),
			"secure_docker_file":                            types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.SecureDockerFile),
			"actions_to_exempt_while_pinning":               exemptList,
			"actions_to_replace_with_step_security_actions": replaceList,
			"update_precommit_file":                         updatePrecommitFileList,
			"package_ecosystem":                             packageEcosystemList,
			"add_workflows":                                 addWorkflowsValue,
		},
	)
	state.AutoRemdiationOptions = optionsObj

	// Note: We do NOT set UseRepoLevelConfig and UseOrgLevelConfig here.
	// These fields represent the user's intent and should be preserved from the existing state.
	// When org-level config is applied to specific repos (not wildcard), the API stores it per-repo,
	// making it impossible to distinguish from repo-level config when reading back.
	// Therefore, we trust the state to maintain the user's original configuration intent.

	// Preserve selected_repos and excluded_repos from state to avoid diffs
	// This ensures that the order and exact values match what the user configured
	if len(stateSelectedRepos) > 0 {
		repoElements := make([]types.String, len(stateSelectedRepos))
		for i, repo := range stateSelectedRepos {
			repoElements[i] = types.StringValue(repo)
		}
		repoList, _ := types.ListValueFrom(ctx, types.StringType, repoElements)
		state.SelectedRepos = repoList
	}

	if len(stateExcludedRepos) > 0 {
		excludedElements := make([]types.String, len(stateExcludedRepos))
		for i, repo := range stateExcludedRepos {
			excludedElements[i] = types.StringValue(repo)
		}
		excludedList, _ := types.ListValueFrom(ctx, types.StringType, excludedElements)
		state.ExcludedRepos = excludedList
	}
}
