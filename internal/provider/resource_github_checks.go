package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &githubChecksResource{}
	_ resource.ResourceWithConfigure      = &githubChecksResource{}
	_ resource.ResourceWithValidateConfig = &githubChecksResource{}
	_ resource.ResourceWithModifyPlan     = &githubChecksResource{}
	_ resource.ResourceWithImportState    = &githubChecksResource{}
)

// NewUserResource is a helper function to simplify the provider implementation.
func NewGitHubChecksResource() resource.Resource {
	return &githubChecksResource{}
}

// orderResource is the resource implementation.
type githubChecksResource struct {
	client stepsecurityapi.Client
}

// Metadata returns the resource type name.
func (r *githubChecksResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_checks"
}

// Configure adds the provider configured client to the resource.
func (r *githubChecksResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Schema defines the schema for the resource.
func (r *githubChecksResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"owner": schema.StringAttribute{
				Required:    true,
				Description: "Owner(organization) Name",
			},
			"controls": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"control": schema.StringAttribute{
							Required:    true,
							Description: "Control name. Available controls: " + strings.Join(stepsecurityapi.GetAvailableControls(), ", "),
						},
						"enable": schema.BoolAttribute{
							Required:    true,
							Description: "Whether the control is enabled",
						},
						"type": schema.StringAttribute{
							Required:    true,
							Description: "Check type where this control should run.Can only be 'required'/'optional' ",
						},
						"settings": schema.SingleNestedAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Settings for the control",
							Attributes: map[string]schema.Attribute{
								"cool_down_period": schema.Int64Attribute{
									Optional:    true,
									Computed:    true,
									Default:     int64default.StaticInt64(2),
									Description: "Cooldown period values (e.g., days). Only applicable to npm cooldown check. Default is 2 days.",
								},
								"packages_to_exempt_in_cooldown_check": schema.ListAttribute{
									Optional:    true,
									ElementType: types.StringType,
									Description: "Package names to exempt from cooldown checks.  Only applicable to npm cooldown check",
								},
							},
						},
					},
				},
			},
			"required_checks": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Configuration for required checks",
				Attributes: map[string]schema.Attribute{
					"repos": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "List of repositories the checks apply to (supports '*')",
					},
					"omit_repos": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "List of repositories to omit while running 'required' check. Can be specified only when '*' is specified in repos section.",
					},
				},
			},
			"optional_checks": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Configuration for optional checks",
				Attributes: map[string]schema.Attribute{
					"repos": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "List of repositories the checks apply to (supports '*')",
					},
					"omit_repos": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "List of repositories to omit for 'optional' check. Can be specified only when '*' is specified in repos section.",
					},
				},
			},
			"baseline_check": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Configuration for baseline check",
				Attributes: map[string]schema.Attribute{
					"repos": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "List of repositories the baseline applies to (supports '*')",
					},
					"omit_repos": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "List of repositories for baseline check.Can be specified only when '*' is specified in repos section.",
					},
				},
			},
		},
	}
}

func (r *githubChecksResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	owner := req.ID
	// Set the owner and ID in the state
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

type githubChecksModel struct {
	Owner          types.String  `tfsdk:"owner"`
	Controls       []control     `tfsdk:"controls"`
	RequiredChecks *checksConfig `tfsdk:"required_checks"`
	OptionalChecks *checksConfig `tfsdk:"optional_checks"`
	BaselineCheck  *checksConfig `tfsdk:"baseline_check"`
}

type checksConfig struct {
	Repos     types.List `tfsdk:"repos"`
	OmitRepos types.List `tfsdk:"omit_repos"`
}

type control struct {
	Control  types.String `tfsdk:"control"`
	Enable   types.Bool   `tfsdk:"enable"`
	Type     types.String `tfsdk:"type"`
	Settings types.Object `tfsdk:"settings"`
}

func (r *githubChecksResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config githubChecksModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.Owner.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Owner is required",
			"Owner is required to create a GitHub Checks resource",
		)
	}

	if len(config.Controls) == 0 {
		resp.Diagnostics.AddError(
			"Controls are required",
			"Controls are required to create a GitHub Checks resource",
		)
	}

	hasRequired := false
	hasOptional := false
	for _, control := range config.Controls {
		if _, ok := stepsecurityapi.AvailableControls[control.Control.ValueString()]; !ok {
			resp.Diagnostics.AddError(
				"Invalid control provided",
				"only the following controls are accepted to configure: "+strings.Join(stepsecurityapi.GetAvailableControls(), ", \n"),
			)
		}

		if control.Type.ValueString() == "required" && control.Enable.ValueBool() {
			hasRequired = true
		}
		if control.Type.ValueString() == "optional" && control.Enable.ValueBool() {
			hasOptional = true
		}
		if control.Type.ValueString() != "required" && control.Type.ValueString() != "optional" {
			resp.Diagnostics.AddError(
				"Type can only be 'required' or 'optional'",
				"Type can only be 'required' or 'optional'",
			)
		}

		if control.Control.ValueString() != "NPM Package Cooldown" && !control.Settings.IsNull() {
			resp.Diagnostics.AddError(
				"can't provide settings",
				"can't provide settings for control "+control.Control.ValueString(),
			)
		}

		if control.Control.ValueString() == "NPM Package Cooldown" && !control.Settings.IsNull() {
			// Extract cooldown period from the object
			if cooldownAttr := control.Settings.Attributes()["cool_down_period"]; cooldownAttr != nil {
				if cooldownValue, ok := cooldownAttr.(types.Int64); ok {
					period := cooldownValue.ValueInt64()
					if period != 0 && (period < 1 || period > 30) {
						resp.Diagnostics.AddError(
							"cool_down_period should be between 1 and 30",
							"cool_down_period should be between 1 and 30 for control "+control.Control.ValueString(),
						)
					}
				}
			}
		}

	}

	if config.RequiredChecks != nil && len(config.RequiredChecks.Repos.Elements()) != 0 && !hasRequired {
		resp.Diagnostics.AddError(
			"can't provide repos for required checks without enabling any control for required checks",
			"No control of type 'required' is enabled to apply to the repos",
		)
	}

	if config.OptionalChecks != nil && len(config.OptionalChecks.Repos.Elements()) != 0 && !hasOptional {
		resp.Diagnostics.AddError(
			"can't provide repos for optional checks without enabling any control for optional checks",
			"No control of type 'optional' is enabled to apply to the repos",
		)
	}

	isRequiredCheckAppliedForAllRepos := false
	isOptionalCheckAppliedForAllRepos := false
	isBaselineCheckAppliedForAllRepos := false

	if config.RequiredChecks != nil {
		for _, repo := range config.RequiredChecks.Repos.Elements() {
			if repo.(types.String).ValueString() == "*" {
				isRequiredCheckAppliedForAllRepos = true
			}
		}
	}
	if config.OptionalChecks != nil {
		for _, repo := range config.OptionalChecks.Repos.Elements() {
			if repo.(types.String).ValueString() == "*" {
				isOptionalCheckAppliedForAllRepos = true
			}
		}
	}
	if config.BaselineCheck != nil {
		for _, repo := range config.BaselineCheck.Repos.Elements() {
			if repo.(types.String).ValueString() == "*" {
				isBaselineCheckAppliedForAllRepos = true
			}
		}
	}

	if config.RequiredChecks != nil {
		if !isRequiredCheckAppliedForAllRepos && len(config.RequiredChecks.OmitRepos.Elements()) != 0 {
			resp.Diagnostics.AddError(
				"can't provide omit_repos for required checks without enabling it for all repos",
				"omit_repos can only be provided when repos is set to '*'",
			)
		} else if isRequiredCheckAppliedForAllRepos && len(config.RequiredChecks.Repos.Elements()) != 1 {
			resp.Diagnostics.AddError(
				"can't provide additional values for repos for required checks when repos set to '*'",
				"additional values for repos are not allowed when repos have a value '*'",
			)
		}
	}

	if config.OptionalChecks != nil {
		if !isOptionalCheckAppliedForAllRepos && len(config.OptionalChecks.OmitRepos.Elements()) != 0 {
			resp.Diagnostics.AddError(
				"can't provide omit_repos for optional checks without enabling it for all repos",
				"omit_repos can only be provided when repos is set to '*'",
			)
		} else if isOptionalCheckAppliedForAllRepos && len(config.OptionalChecks.Repos.Elements()) != 1 {
			resp.Diagnostics.AddError(
				"can't provide additional values for repos for optional checks when repos set to '*'",
				"additional values for repos are not allowed when repos have a value '*'",
			)
		}
	}

	if config.BaselineCheck != nil {
		if !isBaselineCheckAppliedForAllRepos && len(config.BaselineCheck.OmitRepos.Elements()) != 0 {
			resp.Diagnostics.AddError(
				"can't provide omit_repos for baseline checks without enabling it for all repos",
				"omit_repos can only be provided when repos is set to '*'",
			)
		} else if isBaselineCheckAppliedForAllRepos && len(config.BaselineCheck.Repos.Elements()) != 1 {
			resp.Diagnostics.AddError(
				"can't provide additional values for repos for baseline checks when repos set to '*'",
				"additional values for repos are not allowed when repos have a value '*'",
			)
		}
	}

}

func (r *githubChecksResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {

	// Skip ModifyPlan during destroy operations
	if req.Plan.Raw.IsNull() {
		tflog.Info(ctx, "Skipping ModifyPlan during destroy", map[string]any{})
		return
	}

	var plan githubChecksModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	for ind, control := range plan.Controls {

		if control.Control.ValueString() == "NPM Package Cooldown" && control.Settings.IsNull() {
			// Create object with default settings
			settingsMap := map[string]attr.Value{
				"cool_down_period":                     types.Int64Value(2),
				"packages_to_exempt_in_cooldown_check": types.ListNull(types.StringType),
			}
			settingsType := types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"cool_down_period":                     types.Int64Type,
					"packages_to_exempt_in_cooldown_check": types.ListType{ElemType: types.StringType},
				},
			}
			control.Settings, _ = types.ObjectValue(settingsType.AttrTypes, settingsMap)
			plan.Controls[ind] = control
		}
	}

	// Sort controls by name to ensure deterministic order
	// This prevents Terraform from detecting changes due to inconsistent ordering
	sort.Slice(plan.Controls, func(i, j int) bool {
		return plan.Controls[i].Control.ValueString() < plan.Controls[j].Control.ValueString()
	})

	// Set the plan back (either because it was modified or to ensure consistent ordering)
	diags = resp.Plan.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Create creates the resource and sets the initial Terraform state.
func (r *githubChecksResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan githubChecksModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest, err := r.convertToCreateRequest(plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating GitHub Checks",
			err.Error(),
		)
		return
	}

	err = r.client.UpdatePRChecksConfig(ctx, plan.Owner.ValueString(), *createRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating GitHub Checks",
			err.Error(),
		)
		return
	}

	plan = r.convertToState(plan.Owner.ValueString(), *createRequest)
	plan.Owner = types.StringValue(plan.Owner.ValueString())

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Read refreshes the Terraform state with the latest data.
func (r *githubChecksResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state githubChecksModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	config, err := r.client.GetPRChecksConfig(ctx, state.Owner.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading GitHub Checks",
			err.Error(),
		)
		return
	}

	state = r.convertToState(state.Owner.ValueString(), config)

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *githubChecksResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan githubChecksModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRequest, err := r.convertToCreateRequest(plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating GitHub Checks",
			err.Error(),
		)
		return
	}

	err = r.client.UpdatePRChecksConfig(ctx, plan.Owner.ValueString(), *updateRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating GitHub Checks",
			err.Error(),
		)
		return
	}

	plan = r.convertToState(plan.Owner.ValueString(), *updateRequest)
	plan.Owner = types.StringValue(plan.Owner.ValueString())

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *githubChecksResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {

	var state githubChecksModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.Owner.IsNull() || state.Owner.IsUnknown() {
		resp.Diagnostics.AddError(
			"Error deleting GitHub Checks",
			"Could not determine owner from state",
		)
		return
	}

	err := r.client.DeletePRChecksConfig(ctx, state.Owner.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting GitHub Checks",
			err.Error(),
		)
		return
	}

}

func (r *githubChecksResource) convertToCreateRequest(plan githubChecksModel) (*stepsecurityapi.GitHubPRChecksConfig, error) {
	prChecksConfig := stepsecurityapi.GitHubPRChecksConfig{}
	prChecksConfig.Checks = make(map[string]stepsecurityapi.CheckConfig)
	for _, control := range plan.Controls {
		controlName := control.Control.ValueString()
		checkConfig := stepsecurityapi.CheckConfig{
			Enabled: control.Enable.ValueBool(),
			Type:    control.Type.ValueString(),
		}
		if controlName == "NPM Package Cooldown" {
			if control.Settings.IsNull() {
				control.Settings = types.ObjectNull(map[string]attr.Type{
					"cool_down_period":                     types.Int64Type,
					"packages_to_exempt_in_cooldown_check": types.ListType{ElemType: types.StringType},
				})
			}
			cooldownPeriod := int64(2) // default
			var exemptPackages []string

			// Extract values from the settings object
			settingsAttrs := control.Settings.Attributes()
			if cooldownAttr, ok := settingsAttrs["cool_down_period"]; ok {
				if cooldownValue, ok := cooldownAttr.(types.Int64); ok && !cooldownValue.IsNull() && !cooldownValue.IsUnknown() {
					cooldownPeriod = cooldownValue.ValueInt64()
				}
			}

			if packagesAttr, ok := settingsAttrs["packages_to_exempt_in_cooldown_check"]; ok {
				if packagesList, ok := packagesAttr.(types.List); ok && !packagesList.IsNull() {
					for _, packageValue := range packagesList.Elements() {
						if packageString, ok := packageValue.(types.String); ok && !packageString.IsNull() && !packageString.IsUnknown() {
							exemptPackages = append(exemptPackages, packageString.ValueString())
						}
					}
				}
			}

			checkConfig.Settings = map[string]any{
				"cooldown_period_in_days": cooldownPeriod,
			}
			if len(exemptPackages) > 0 {
				checkConfig.Settings["exempted_packages"] = exemptPackages
			}
		}
		prChecksConfig.Checks[stepsecurityapi.AvailableControls[controlName]] = checkConfig
	}

	isRequiredCheckAppliedForAllRepos := false
	isOptionalCheckAppliedForAllRepos := false
	isBaselineCheckAppliedForAllRepos := false

	if plan.RequiredChecks != nil {
		for _, repo := range plan.RequiredChecks.Repos.Elements() {
			repoName := repo.(types.String).ValueString()
			if repoName == "*" {
				isRequiredCheckAppliedForAllRepos = true
				continue
			}
		}
	}

	if plan.OptionalChecks != nil {
		for _, repo := range plan.OptionalChecks.Repos.Elements() {
			repoName := repo.(types.String).ValueString()
			if repoName == "*" {
				isOptionalCheckAppliedForAllRepos = true
				continue
			}
		}
	}

	if plan.BaselineCheck != nil {
		for _, repo := range plan.BaselineCheck.Repos.Elements() {
			repoName := repo.(types.String).ValueString()
			if repoName == "*" {
				isBaselineCheckAppliedForAllRepos = true
				continue
			}
		}
	}

	repos := map[string]stepsecurityapi.CheckOptions{}
	if plan.RequiredChecks != nil {
		for _, repo := range plan.RequiredChecks.Repos.Elements() {
			repoName := repo.(types.String).ValueString()
			if repoName == "*" {
				continue
			}
			repos[repoName] = stepsecurityapi.CheckOptions{
				Baseline:          isBaselineCheckAppliedForAllRepos,
				RunRequiredChecks: true,
				RunOptionalChecks: isOptionalCheckAppliedForAllRepos,
			}
		}
	}

	if plan.OptionalChecks != nil {
		for _, repo := range plan.OptionalChecks.Repos.Elements() {
			repoName := repo.(types.String).ValueString()
			if repoName == "*" {
				continue
			}
			if val, ok := repos[repoName]; ok {
				val.RunOptionalChecks = true
				repos[repoName] = val
				continue
			}
			repos[repoName] = stepsecurityapi.CheckOptions{
				Baseline:          isBaselineCheckAppliedForAllRepos,
				RunRequiredChecks: isRequiredCheckAppliedForAllRepos,
				RunOptionalChecks: true,
			}
		}
	}

	if plan.BaselineCheck != nil {
		for _, repo := range plan.BaselineCheck.Repos.Elements() {
			repoName := repo.(types.String).ValueString()
			if repoName == "*" {
				continue
			}
			if val, ok := repos[repoName]; ok {
				val.Baseline = true
				repos[repoName] = val
				continue
			}
			repos[repoName] = stepsecurityapi.CheckOptions{
				Baseline:          true,
				RunRequiredChecks: isRequiredCheckAppliedForAllRepos,
				RunOptionalChecks: isOptionalCheckAppliedForAllRepos,
			}
		}
	}

	// process omit repos
	if isRequiredCheckAppliedForAllRepos && plan.RequiredChecks != nil {
		for _, repo := range plan.RequiredChecks.OmitRepos.Elements() {
			repoName := repo.(types.String).ValueString()
			if val, ok := repos[repoName]; ok {
				val.RunRequiredChecks = false
				repos[repoName] = val
				continue
			}
			repos[repoName] = stepsecurityapi.CheckOptions{
				Baseline:          isBaselineCheckAppliedForAllRepos,
				RunRequiredChecks: false,
				RunOptionalChecks: isOptionalCheckAppliedForAllRepos,
			}
		}
	}
	if isOptionalCheckAppliedForAllRepos && plan.OptionalChecks != nil {
		for _, repo := range plan.OptionalChecks.OmitRepos.Elements() {
			repoName := repo.(types.String).ValueString()
			if val, ok := repos[repoName]; ok {
				val.RunOptionalChecks = false
				repos[repoName] = val
				continue
			}
			repos[repoName] = stepsecurityapi.CheckOptions{
				Baseline:          isBaselineCheckAppliedForAllRepos,
				RunRequiredChecks: isRequiredCheckAppliedForAllRepos,
				RunOptionalChecks: false,
			}
		}
	}
	if isBaselineCheckAppliedForAllRepos && plan.BaselineCheck != nil {
		for _, repo := range plan.BaselineCheck.OmitRepos.Elements() {
			repoName := repo.(types.String).ValueString()
			if val, ok := repos[repoName]; ok {
				val.Baseline = false
				repos[repoName] = val
				continue
			}
			repos[repoName] = stepsecurityapi.CheckOptions{
				Baseline:          false,
				RunRequiredChecks: isRequiredCheckAppliedForAllRepos,
				RunOptionalChecks: isOptionalCheckAppliedForAllRepos,
			}
		}
	}

	prChecksConfig.EnableBaselineCheckForAllNewRepos = &isBaselineCheckAppliedForAllRepos
	prChecksConfig.EnableRequiredChecksForAllNewRepos = &isRequiredCheckAppliedForAllRepos
	prChecksConfig.EnableOptionalChecksForAllNewRepos = &isOptionalCheckAppliedForAllRepos
	prChecksConfig.Repos = repos
	return &prChecksConfig, nil
}

func (r *githubChecksResource) convertToState(owner string, config stepsecurityapi.GitHubPRChecksConfig) githubChecksModel {
	model := githubChecksModel{}
	model.Owner = types.StringValue(owner)

	// Initialize Controls as empty slice instead of nil
	model.Controls = []control{}

	// Don't initialize pointer fields yet - only initialize them if needed

	// Controls
	for checkName := range config.Checks {
		controlName := stepsecurityapi.GetControlName(checkName)
		checkConfig := config.Checks[checkName]

		c := control{
			Control: types.StringValue(controlName),
			Type:    types.StringValue(checkConfig.Type),
			Enable:  types.BoolValue(checkConfig.Enabled),
		}

		// Handle settings for NPM Package Cooldown
		if controlName == "NPM Package Cooldown" && checkConfig.Settings != nil {
			var cooldownPeriod types.Int64
			var packagesList types.List

			if cooldownValue, ok := checkConfig.Settings["cooldown_period_in_days"]; ok {
				if period, ok := cooldownValue.(int64); ok {
					cooldownPeriod = types.Int64Value(period)
				} else if period, ok := cooldownValue.(float64); ok {
					cooldownPeriod = types.Int64Value(int64(period))
				} else {
					// Default to 2 if wrong type
					cooldownPeriod = types.Int64Value(2)
				}
			} else {
				// Default to 2 if not present
				cooldownPeriod = types.Int64Value(2)
			}

			// Handle packages_to_exempt_in_cooldown_check
			if exemptPackages, ok := checkConfig.Settings["exempted_packages"]; ok {
				var elements []attr.Value
				// Handle both []string and []any types from API response
				if packages, ok := exemptPackages.([]string); ok && len(packages) > 0 {
					for _, pkg := range packages {
						elements = append(elements, types.StringValue(pkg))
					}
					packagesList, _ = types.ListValue(types.StringType, elements)
				} else if packages, ok := exemptPackages.([]any); ok && len(packages) > 0 {
					for _, pkg := range packages {
						if pkgStr, ok := pkg.(string); ok {
							elements = append(elements, types.StringValue(pkgStr))
						}
					}
					packagesList, _ = types.ListValue(types.StringType, elements)
				} else {
					// Empty array or wrong type - create null list with correct type
					packagesList = types.ListNull(types.StringType)
				}
			} else {
				// Field doesn't exist - create null list with correct type
				packagesList = types.ListNull(types.StringType)
			}

			// Create object with settings
			settingsMap := map[string]attr.Value{
				"cool_down_period":                     cooldownPeriod,
				"packages_to_exempt_in_cooldown_check": packagesList,
			}
			settingsType := types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"cool_down_period":                     types.Int64Type,
					"packages_to_exempt_in_cooldown_check": types.ListType{ElemType: types.StringType},
				},
			}
			c.Settings, _ = types.ObjectValue(settingsType.AttrTypes, settingsMap)
		} else {
			// For non-NPM controls or controls without settings, set to null
			c.Settings = types.ObjectNull(map[string]attr.Type{
				"cool_down_period":                     types.Int64Type,
				"packages_to_exempt_in_cooldown_check": types.ListType{ElemType: types.StringType},
			})
		}

		model.Controls = append(model.Controls, c)
	}

	// Sort controls by name to ensure deterministic order
	// This prevents Terraform from detecting changes due to random map iteration order
	sort.Slice(model.Controls, func(i, j int) bool {
		return model.Controls[i].Control.ValueString() < model.Controls[j].Control.ValueString()
	})

	// Flags for applying checks to all repos
	isBaselineAll := config.EnableBaselineCheckForAllNewRepos != nil && *config.EnableBaselineCheckForAllNewRepos
	isRequiredAll := config.EnableRequiredChecksForAllNewRepos != nil && *config.EnableRequiredChecksForAllNewRepos
	isOptionalAll := config.EnableOptionalChecksForAllNewRepos != nil && *config.EnableOptionalChecksForAllNewRepos

	// Pre-set '*' lists when applicable
	if isBaselineAll {
		if model.BaselineCheck == nil {
			model.BaselineCheck = &checksConfig{}
		}
		model.BaselineCheck.Repos, _ = types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
	}
	if isRequiredAll {
		if model.RequiredChecks == nil {
			model.RequiredChecks = &checksConfig{}
		}
		model.RequiredChecks.Repos, _ = types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
	}
	if isOptionalAll {
		if model.OptionalChecks == nil {
			model.OptionalChecks = &checksConfig{}
		}
		model.OptionalChecks.Repos, _ = types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
	}

	// Build per-repo lists
	var baselineRepos []attr.Value
	var baselineOmitRepos []attr.Value
	var requiredRepos []attr.Value
	var requiredOmitRepos []attr.Value
	var optionalRepos []attr.Value
	var optionalOmitRepos []attr.Value

	for name, opts := range config.Repos {
		// Baseline
		if !isBaselineAll && opts.Baseline {
			baselineRepos = append(baselineRepos, types.StringValue(name))
		} else if isBaselineAll && !opts.Baseline {
			baselineOmitRepos = append(baselineOmitRepos, types.StringValue(name))
		}

		// Required
		if !isRequiredAll && opts.RunRequiredChecks {
			requiredRepos = append(requiredRepos, types.StringValue(name))
		} else if isRequiredAll && !opts.RunRequiredChecks {
			requiredOmitRepos = append(requiredOmitRepos, types.StringValue(name))
		}

		// Optional
		if !isOptionalAll && opts.RunOptionalChecks {
			optionalRepos = append(optionalRepos, types.StringValue(name))
		} else if isOptionalAll && !opts.RunOptionalChecks {
			optionalOmitRepos = append(optionalOmitRepos, types.StringValue(name))
		}
	}

	// Check if we have any controls of each type to determine if we need check configs
	hasRequiredControls := false
	hasOptionalControls := false

	for _, control := range model.Controls {
		if control.Enable.ValueBool() {
			switch control.Type.ValueString() {
			case "required":
				hasRequiredControls = true
			case "optional":
				hasOptionalControls = true
			}
		}
	}

	// Always initialize all check configs to prevent null values in Terraform state
	// This ensures that if any configuration exists, all nested lists are properly initialized

	// RequiredChecks - initialize if there are required controls or any required activity
	if hasRequiredControls || isRequiredAll || len(requiredRepos) > 0 || len(requiredOmitRepos) > 0 {
		model.RequiredChecks = &checksConfig{}
		if isRequiredAll {
			model.RequiredChecks.Repos, _ = types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
		} else {
			model.RequiredChecks.Repos, _ = types.ListValue(types.StringType, requiredRepos)
		}
		// Only set OmitRepos if there are actually repos to omit
		if len(requiredOmitRepos) > 0 {
			model.RequiredChecks.OmitRepos, _ = types.ListValue(types.StringType, requiredOmitRepos)
		} else {
			// No omit repos - set as typed null
			model.RequiredChecks.OmitRepos = types.ListNull(types.StringType)
		}
	}

	// OptionalChecks - initialize if there are optional controls or any optional activity
	if hasOptionalControls || isOptionalAll || len(optionalRepos) > 0 || len(optionalOmitRepos) > 0 {
		model.OptionalChecks = &checksConfig{}
		if isOptionalAll {
			model.OptionalChecks.Repos, _ = types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
		} else {
			model.OptionalChecks.Repos, _ = types.ListValue(types.StringType, optionalRepos)
		}
		// Only set OmitRepos if there are actually repos to omit
		if len(optionalOmitRepos) > 0 {
			model.OptionalChecks.OmitRepos, _ = types.ListValue(types.StringType, optionalOmitRepos)
		} else {
			// No omit repos - set as typed null
			model.OptionalChecks.OmitRepos = types.ListNull(types.StringType)
		}
	}

	// BaselineCheck - initialize if baseline is enabled globally or has any baseline activity
	if isBaselineAll || len(baselineRepos) > 0 || len(baselineOmitRepos) > 0 {
		model.BaselineCheck = &checksConfig{}
		if isBaselineAll {
			model.BaselineCheck.Repos, _ = types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
		} else {
			model.BaselineCheck.Repos, _ = types.ListValue(types.StringType, baselineRepos)
		}
		// Only set OmitRepos if there are actually repos to omit
		if len(baselineOmitRepos) > 0 {
			model.BaselineCheck.OmitRepos, _ = types.ListValue(types.StringType, baselineOmitRepos)
		} else {
			// No omit repos - set as typed null
			model.BaselineCheck.OmitRepos = types.ListNull(types.StringType)
		}
	}

	return model
}
