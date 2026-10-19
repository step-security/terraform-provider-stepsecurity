package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
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
			"custom_description": schema.StringAttribute{
				Optional:    true,
				Description: "Custom description text appended to all check summaries.",
			},
			"controls": schema.ListNestedAttribute{
				Required: true,
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
									Description: "Cooldown period values (e.g., days). Only applicable to npm/PyPI/Maven/NuGet cooldown checks. Default is 2 days.",
								},
								"packages_to_exempt_in_cooldown_check": schema.ListAttribute{
									Optional:    true,
									ElementType: types.StringType,
									Description: "Package names to exempt from cooldown checks. Only applicable to npm/PyPI/Maven/NuGet cooldown checks.",
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
	if owner == "" || strings.Contains(owner, "/") {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Expected the GitHub organization name (e.g. \"my-org\"), got %q. Do not include a \"/\".", req.ID),
		)
		return
	}
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
	Owner             types.String `tfsdk:"owner"`
	Controls          types.List   `tfsdk:"controls"`
	RequiredChecks    types.Object `tfsdk:"required_checks"`
	OptionalChecks    types.Object `tfsdk:"optional_checks"`
	BaselineCheck     types.Object `tfsdk:"baseline_check"`
	CustomDescription types.String `tfsdk:"custom_description"`
}

type checksConfig struct {
	Repos     types.List `tfsdk:"repos"`
	OmitRepos types.List `tfsdk:"omit_repos"`
}

// checksConfigAttrTypes returns the attribute types of a required_checks/optional_checks/
// baseline_check object.
func checksConfigAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"repos":      types.ListType{ElemType: types.StringType},
		"omit_repos": types.ListType{ElemType: types.StringType},
	}
}

// decodeChecksConfig decodes a required_checks/optional_checks/baseline_check types.Object
// into a *checksConfig. It returns nil (no error) when the object is null OR unknown; every
// caller already treats a nil *checksConfig as "not configured, skip", which is also the
// correct behavior to defer to a later plan when the whole object isn't known yet. Binding an
// unknown object into a plain *checksConfig (rather than types.Object) is what caused a
// customer-reported crash for required_checks.
func decodeChecksConfig(ctx context.Context, obj types.Object) (*checksConfig, diag.Diagnostics) {
	if obj.IsNull() || obj.IsUnknown() {
		return nil, nil
	}
	var c checksConfig
	diags := obj.As(ctx, &c, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return nil, diags
	}
	return &c, nil
}

// encodeChecksConfig converts a *checksConfig back into the types.Object it is bound to,
// producing a null object when cfg is nil. Repos/OmitRepos are normalized to a properly
// typed null list when left as the Go zero value types.List{} (no element type set) —
// building the object via reflection (ObjectValueFrom) on that zero value fails a strict
// type check and silently degrades to an Unknown object, which would reintroduce the
// unknown-value crash this type is meant to prevent.
func encodeChecksConfig(_ context.Context, cfg *checksConfig) types.Object {
	if cfg == nil {
		return types.ObjectNull(checksConfigAttrTypes())
	}
	repos := cfg.Repos
	if repos.IsNull() {
		repos = types.ListNull(types.StringType)
	}
	omitRepos := cfg.OmitRepos
	if omitRepos.IsNull() {
		omitRepos = types.ListNull(types.StringType)
	}
	obj, _ := types.ObjectValue(checksConfigAttrTypes(), map[string]attr.Value{
		"repos":      repos,
		"omit_repos": omitRepos,
	})
	return obj
}

type control struct {
	Control  types.String `tfsdk:"control"`
	Enable   types.Bool   `tfsdk:"enable"`
	Type     types.String `tfsdk:"type"`
	Settings types.Object `tfsdk:"settings"`
}

// controlSettingsAttrTypes returns the attribute types for a control's "settings" object.
func controlSettingsAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"cool_down_period":                     types.Int64Type,
		"packages_to_exempt_in_cooldown_check": types.ListType{ElemType: types.StringType},
	}
}

// controlObjectType returns the object type of a single element of the "controls" list.
// The "controls" attribute is bound to types.List (rather than a plain Go slice) so that
// the framework can represent an unknown list value (e.g. when it is derived from a value
// that is not known until apply); a plain []control cannot represent "unknown".
func controlObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"control": types.StringType,
			"enable":  types.BoolType,
			"type":    types.StringType,
			"settings": types.ObjectType{
				AttrTypes: controlSettingsAttrTypes(),
			},
		},
	}
}

// isCooldownControl reports whether a control takes cooldown settings.
func isCooldownControl(name string) bool {
	switch name {
	case "NPM Package Cooldown", "PyPI Package Cooldown", "Maven Package Cooldown", "NuGet Package Cooldown":
		return true
	}
	return false
}

// diagsToError flattens error diagnostics into a single error.
func diagsToError(diags diag.Diagnostics) error {
	msgs := make([]string, 0, len(diags))
	for _, d := range diags.Errors() {
		msgs = append(msgs, fmt.Sprintf("%s: %s", d.Summary(), d.Detail()))
	}
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}

func (r *githubChecksResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config githubChecksModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.Owner.IsUnknown() && !config.Owner.IsNull() && config.Owner.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Owner is required",
			"Owner is required to create a GitHub Checks resource",
		)
	}

	requiredChecks, diags2 := decodeChecksConfig(ctx, config.RequiredChecks)
	resp.Diagnostics.Append(diags2...)
	optionalChecks, diags3 := decodeChecksConfig(ctx, config.OptionalChecks)
	resp.Diagnostics.Append(diags3...)
	baselineCheck, diags4 := decodeChecksConfig(ctx, config.BaselineCheck)
	resp.Diagnostics.Append(diags4...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasRequired := false
	hasOptional := false
	// controlsIndeterminate is true whenever we could not fully evaluate every control's
	// type/enable state (the whole list is unknown, or an individual control's fields are
	// unknown). In that case hasRequired/hasOptional cannot be trusted, so cross-checks that
	// depend on them must be skipped until a later plan when the values are known.
	controlsIndeterminate := false

	if config.Controls.IsUnknown() {
		// The whole controls list is unknown (e.g., it is derived from a value that
		// isn't known until apply, such as a for_each over an unresolved collection).
		// Skip control-level validation until the value is known; it will be
		// re-validated on a subsequent plan.
		controlsIndeterminate = true
	} else if config.Controls.IsNull() || len(config.Controls.Elements()) == 0 {
		resp.Diagnostics.AddError(
			"Controls are required",
			"Controls are required to create a GitHub Checks resource",
		)
	} else {
		var controls []control
		diags = config.Controls.ElementsAs(ctx, &controls, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		seen := make(map[string]bool, len(controls))
		for _, control := range controls {
			if !control.Control.IsUnknown() && !control.Control.IsNull() {
				name := control.Control.ValueString()
				if seen[name] {
					resp.Diagnostics.AddError(
						"Duplicate control",
						"control "+name+" is listed more than once",
					)
				}
				seen[name] = true
			}

			// Skip validation if control attributes are unknown (e.g., when using for_each or count)
			if control.Control.IsUnknown() || control.Type.IsUnknown() || control.Enable.IsUnknown() {
				controlsIndeterminate = true
				continue
			}

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

			isCooldown := isCooldownControl(control.Control.ValueString())
			if !isCooldown && !control.Settings.IsNull() && !control.Settings.IsUnknown() {
				resp.Diagnostics.AddError(
					"can't provide settings",
					"can't provide settings for control "+control.Control.ValueString(),
				)
			}

			if isCooldown && !control.Settings.IsNull() && !control.Settings.IsUnknown() {
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
	}

	if !controlsIndeterminate && requiredChecks != nil && len(requiredChecks.Repos.Elements()) != 0 && !hasRequired {
		resp.Diagnostics.AddError(
			"can't provide repos for required checks without enabling any control for required checks",
			"No control of type 'required' is enabled to apply to the repos",
		)
	}

	if !controlsIndeterminate && optionalChecks != nil && len(optionalChecks.Repos.Elements()) != 0 && !hasOptional {
		resp.Diagnostics.AddError(
			"can't provide repos for optional checks without enabling any control for optional checks",
			"No control of type 'optional' is enabled to apply to the repos",
		)
	}

	isRequiredCheckAppliedForAllRepos := false
	isOptionalCheckAppliedForAllRepos := false
	isBaselineCheckAppliedForAllRepos := false

	if requiredChecks != nil && !requiredChecks.Repos.IsUnknown() {
		for _, repo := range requiredChecks.Repos.Elements() {
			repoStr, ok := repo.(types.String)
			if ok && !repoStr.IsUnknown() && repoStr.ValueString() == "*" {
				isRequiredCheckAppliedForAllRepos = true
			}
		}
	}
	if optionalChecks != nil && !optionalChecks.Repos.IsUnknown() {
		for _, repo := range optionalChecks.Repos.Elements() {
			repoStr, ok := repo.(types.String)
			if ok && !repoStr.IsUnknown() && repoStr.ValueString() == "*" {
				isOptionalCheckAppliedForAllRepos = true
			}
		}
	}
	if baselineCheck != nil && !baselineCheck.Repos.IsUnknown() {
		for _, repo := range baselineCheck.Repos.Elements() {
			repoStr, ok := repo.(types.String)
			if ok && !repoStr.IsUnknown() && repoStr.ValueString() == "*" {
				isBaselineCheckAppliedForAllRepos = true
			}
		}
	}

	if requiredChecks != nil {
		if !requiredChecks.OmitRepos.IsUnknown() && !isRequiredCheckAppliedForAllRepos && len(requiredChecks.OmitRepos.Elements()) != 0 {
			resp.Diagnostics.AddError(
				"can't provide omit_repos for required checks without enabling it for all repos",
				"omit_repos can only be provided when repos is set to '*'",
			)
		} else if !requiredChecks.Repos.IsUnknown() && isRequiredCheckAppliedForAllRepos && len(requiredChecks.Repos.Elements()) != 1 {
			resp.Diagnostics.AddError(
				"can't provide additional values for repos for required checks when repos set to '*'",
				"additional values for repos are not allowed when repos have a value '*'",
			)
		}
	}

	if optionalChecks != nil {
		if !optionalChecks.OmitRepos.IsUnknown() && !isOptionalCheckAppliedForAllRepos && len(optionalChecks.OmitRepos.Elements()) != 0 {
			resp.Diagnostics.AddError(
				"can't provide omit_repos for optional checks without enabling it for all repos",
				"omit_repos can only be provided when repos is set to '*'",
			)
		} else if !optionalChecks.Repos.IsUnknown() && isOptionalCheckAppliedForAllRepos && len(optionalChecks.Repos.Elements()) != 1 {
			resp.Diagnostics.AddError(
				"can't provide additional values for repos for optional checks when repos set to '*'",
				"additional values for repos are not allowed when repos have a value '*'",
			)
		}
	}

	if baselineCheck != nil {
		if !baselineCheck.OmitRepos.IsUnknown() && !isBaselineCheckAppliedForAllRepos && len(baselineCheck.OmitRepos.Elements()) != 0 {
			resp.Diagnostics.AddError(
				"can't provide omit_repos for baseline checks without enabling it for all repos",
				"omit_repos can only be provided when repos is set to '*'",
			)
		} else if !baselineCheck.Repos.IsUnknown() && isBaselineCheckAppliedForAllRepos && len(baselineCheck.Repos.Elements()) != 1 {
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

	if plan.Controls.IsUnknown() || plan.Controls.IsNull() {
		return
	}

	var controls []control
	diags = plan.Controls.ElementsAs(ctx, &controls, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// settings is Optional+Computed, so when a control leaves it out of the config the
	// framework plans it as unknown on every create/update, which shows as
	// "(known after apply)". Apply always resolves an omitted settings the same way (the
	// cooldown defaults for cooldown controls, null for the rest), so plan that value
	// directly. The config is matched by index, since the plan's controls list mirrors it.
	var configControls []control
	if !req.Config.Raw.IsNull() {
		var configControlsList types.List
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("controls"), &configControlsList)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if configControlsList.IsNull() || configControlsList.IsUnknown() {
			return
		}
		resp.Diagnostics.Append(configControlsList.ElementsAs(ctx, &configControls, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if len(configControls) != len(controls) {
		return
	}

	modified := false

	for ind, control := range controls {
		if !configControls[ind].Settings.IsNull() || control.Control.IsUnknown() {
			continue
		}

		var planned types.Object
		if isCooldownControl(control.Control.ValueString()) {
			planned, _ = types.ObjectValue(controlSettingsAttrTypes(), map[string]attr.Value{
				"cool_down_period":                     types.Int64Value(2),
				"packages_to_exempt_in_cooldown_check": types.ListNull(types.StringType),
			})
		} else {
			planned = types.ObjectNull(controlSettingsAttrTypes())
		}
		if !control.Settings.Equal(planned) {
			control.Settings = planned
			controls[ind] = control
			modified = true
		}
	}

	// Set the plan back (either because it was modified )
	if modified {
		newControls, listDiags := types.ListValueFrom(ctx, controlObjectType(), controls)
		resp.Diagnostics.Append(listDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.Controls = newControls

		diags = resp.Plan.Set(ctx, plan)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
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

	createRequest, err := r.convertToCreateRequest(ctx, plan)
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

	state := r.convertToState(ctx, plan.Owner.ValueString(), *createRequest)
	state.Owner = types.StringValue(plan.Owner.ValueString())
	r.updateStateListsWithOrderFromPlan(ctx, plan, &state)

	diags = resp.State.Set(ctx, state)
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

	newState := r.convertToState(ctx, state.Owner.ValueString(), config)
	r.updateStateListsWithOrderFromPlan(ctx, state, &newState)

	diags = resp.State.Set(ctx, newState)
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

	updateRequest, err := r.convertToCreateRequest(ctx, plan)
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

	state := r.convertToState(ctx, plan.Owner.ValueString(), *updateRequest)
	state.Owner = types.StringValue(plan.Owner.ValueString())
	r.updateStateListsWithOrderFromPlan(ctx, plan, &state)

	diags = resp.State.Set(ctx, state)
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

func (r *githubChecksResource) convertToCreateRequest(ctx context.Context, plan githubChecksModel) (*stepsecurityapi.GitHubPRChecksConfig, error) {
	prChecksConfig := stepsecurityapi.GitHubPRChecksConfig{}
	prChecksConfig.Checks = make(map[string]stepsecurityapi.CheckConfig)

	var controls []control
	if !plan.Controls.IsNull() && !plan.Controls.IsUnknown() {
		diags := plan.Controls.ElementsAs(ctx, &controls, false)
		if diags.HasError() {
			return nil, diagsToError(diags)
		}
	}

	requiredChecks, diags := decodeChecksConfig(ctx, plan.RequiredChecks)
	if diags.HasError() {
		return nil, diagsToError(diags)
	}
	optionalChecks, diags := decodeChecksConfig(ctx, plan.OptionalChecks)
	if diags.HasError() {
		return nil, diagsToError(diags)
	}
	baselineCheck, diags := decodeChecksConfig(ctx, plan.BaselineCheck)
	if diags.HasError() {
		return nil, diagsToError(diags)
	}

	for _, control := range controls {
		controlName := control.Control.ValueString()
		checkConfig := stepsecurityapi.CheckConfig{
			Enabled: control.Enable.ValueBool(),
			Type:    control.Type.ValueString(),
		}
		if isCooldownControl(controlName) {
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

	if requiredChecks != nil {
		for _, repo := range requiredChecks.Repos.Elements() {
			repoName := repo.(types.String).ValueString()
			if repoName == "*" {
				isRequiredCheckAppliedForAllRepos = true
				continue
			}
		}
	}

	if optionalChecks != nil {
		for _, repo := range optionalChecks.Repos.Elements() {
			repoName := repo.(types.String).ValueString()
			if repoName == "*" {
				isOptionalCheckAppliedForAllRepos = true
				continue
			}
		}
	}

	if baselineCheck != nil {
		for _, repo := range baselineCheck.Repos.Elements() {
			repoName := repo.(types.String).ValueString()
			if repoName == "*" {
				isBaselineCheckAppliedForAllRepos = true
				continue
			}
		}
	}

	repos := map[string]stepsecurityapi.CheckOptions{}
	if requiredChecks != nil {
		for _, repo := range requiredChecks.Repos.Elements() {
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

	if optionalChecks != nil {
		for _, repo := range optionalChecks.Repos.Elements() {
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

	if baselineCheck != nil {
		for _, repo := range baselineCheck.Repos.Elements() {
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
	if isRequiredCheckAppliedForAllRepos && requiredChecks != nil {
		for _, repo := range requiredChecks.OmitRepos.Elements() {
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
	if isOptionalCheckAppliedForAllRepos && optionalChecks != nil {
		for _, repo := range optionalChecks.OmitRepos.Elements() {
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
	if isBaselineCheckAppliedForAllRepos && baselineCheck != nil {
		for _, repo := range baselineCheck.OmitRepos.Elements() {
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
	if !plan.CustomDescription.IsNull() && !plan.CustomDescription.IsUnknown() {
		prChecksConfig.CustomDescription = plan.CustomDescription.ValueString()
	}
	return &prChecksConfig, nil
}

func (r *githubChecksResource) convertToState(ctx context.Context, owner string, config stepsecurityapi.GitHubPRChecksConfig) githubChecksModel {
	model := githubChecksModel{}
	model.Owner = types.StringValue(owner)
	if config.CustomDescription != "" {
		model.CustomDescription = types.StringValue(config.CustomDescription)
	} else {
		model.CustomDescription = types.StringNull()
	}

	// Initialize controls as an empty slice instead of nil
	controls := []control{}

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

		// Handle settings for cooldown controls
		if isCooldownControl(controlName) && checkConfig.Settings != nil {
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
			c.Settings, _ = types.ObjectValue(controlSettingsAttrTypes(), settingsMap)
		} else {
			// For non-NPM controls or controls without settings, set to null
			c.Settings = types.ObjectNull(controlSettingsAttrTypes())
		}

		controls = append(controls, c)
	}

	// Sort controls by name to ensure deterministic order
	// This prevents Terraform from detecting changes due to random map iteration order
	sort.Slice(controls, func(i, j int) bool {
		return controls[i].Control.ValueString() < controls[j].Control.ValueString()
	})

	model.Controls, _ = types.ListValueFrom(ctx, controlObjectType(), controls)

	// Flags for applying checks to all repos
	isBaselineAll := config.EnableBaselineCheckForAllNewRepos != nil && *config.EnableBaselineCheckForAllNewRepos
	isRequiredAll := config.EnableRequiredChecksForAllNewRepos != nil && *config.EnableRequiredChecksForAllNewRepos
	isOptionalAll := config.EnableOptionalChecksForAllNewRepos != nil && *config.EnableOptionalChecksForAllNewRepos

	var requiredChecks, optionalChecks, baselineCheck *checksConfig

	// Pre-set '*' lists when applicable
	if isBaselineAll {
		if baselineCheck == nil {
			baselineCheck = &checksConfig{}
		}
		baselineCheck.Repos, _ = types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
	}
	if isRequiredAll {
		if requiredChecks == nil {
			requiredChecks = &checksConfig{}
		}
		requiredChecks.Repos, _ = types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
	}
	if isOptionalAll {
		if optionalChecks == nil {
			optionalChecks = &checksConfig{}
		}
		optionalChecks.Repos, _ = types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
	}

	// Build per-repo lists
	var baselineRepos []attr.Value
	var baselineOmitRepos []attr.Value
	var requiredRepos []attr.Value
	var requiredOmitRepos []attr.Value
	var optionalRepos []attr.Value
	var optionalOmitRepos []attr.Value

	// config.Repos is a map, and Go randomizes map iteration order on every range. Iterating
	// it directly would emit these lists in a different order on each read, so two reads of a
	// byte-identical API response (e.g. the plan phase and the apply phase of one run) would
	// disagree on ordering and Terraform would render a spurious reordering diff. Iterating a
	// sorted key list instead makes every read deterministic. Controls are sorted below for
	// the same reason.
	repoNames := make([]string, 0, len(config.Repos))
	for name := range config.Repos {
		repoNames = append(repoNames, name)
	}
	sort.Strings(repoNames)

	for _, name := range repoNames {
		opts := config.Repos[name]
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

	// Each block is built only from what the backend stores (repos, omit_repos, '*'). The
	// backend has no record of whether the user wrote an empty block, so the block's shape
	// is brought in line with the plan (or prior state) afterwards in
	// updateStateListsWithOrderFromPlan.

	// RequiredChecks
	if isRequiredAll || len(requiredRepos) > 0 || len(requiredOmitRepos) > 0 {
		requiredChecks = &checksConfig{}
		if isRequiredAll {
			requiredChecks.Repos, _ = types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
		} else {
			requiredChecks.Repos, _ = types.ListValue(types.StringType, requiredRepos)
		}
		// Only set OmitRepos if there are actually repos to omit
		if len(requiredOmitRepos) > 0 {
			requiredChecks.OmitRepos, _ = types.ListValue(types.StringType, requiredOmitRepos)
		} else {
			// No omit repos - set as typed null
			requiredChecks.OmitRepos = types.ListNull(types.StringType)
		}
	}

	// OptionalChecks
	if isOptionalAll || len(optionalRepos) > 0 || len(optionalOmitRepos) > 0 {
		optionalChecks = &checksConfig{}
		if isOptionalAll {
			optionalChecks.Repos, _ = types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
		} else {
			optionalChecks.Repos, _ = types.ListValue(types.StringType, optionalRepos)
		}
		// Only set OmitRepos if there are actually repos to omit
		if len(optionalOmitRepos) > 0 {
			optionalChecks.OmitRepos, _ = types.ListValue(types.StringType, optionalOmitRepos)
		} else {
			// No omit repos - set as typed null
			optionalChecks.OmitRepos = types.ListNull(types.StringType)
		}
	}

	// BaselineCheck
	if isBaselineAll || len(baselineRepos) > 0 || len(baselineOmitRepos) > 0 {
		baselineCheck = &checksConfig{}
		if isBaselineAll {
			baselineCheck.Repos, _ = types.ListValue(types.StringType, []attr.Value{types.StringValue("*")})
		} else {
			baselineCheck.Repos, _ = types.ListValue(types.StringType, baselineRepos)
		}
		// Only set OmitRepos if there are actually repos to omit
		if len(baselineOmitRepos) > 0 {
			baselineCheck.OmitRepos, _ = types.ListValue(types.StringType, baselineOmitRepos)
		} else {
			// No omit repos - set as typed null
			baselineCheck.OmitRepos = types.ListNull(types.StringType)
		}
	}

	model.RequiredChecks = encodeChecksConfig(ctx, requiredChecks)
	model.OptionalChecks = encodeChecksConfig(ctx, optionalChecks)
	model.BaselineCheck = encodeChecksConfig(ctx, baselineCheck)

	return model
}

// updateStateListsWithOrderFromPlan brings state built from the API in line with plan, which
// is the plan in Create/Update and the prior state in Read (null blocks/controls on import).
// The backend only stores controls and per-repo flags, so anything it can't express is taken
// from plan:
//   - the shape of required_checks/optional_checks/baseline_check (see alignChecksBlock);
//   - list order, and null vs empty for repos, omit_repos and packages_to_exempt_in_cooldown_check;
//   - the order of controls.
//
// Controls that the backend has enabled but plan doesn't contain are kept (appended), so a
// control enabled outside Terraform shows up as drift. Disabled controls that plan doesn't
// contain are dropped: the backend keeps every control it has ever seen (removing a control
// or destroying the resource only disables it), so those are not drift.
func (r *githubChecksResource) updateStateListsWithOrderFromPlan(ctx context.Context, plan githubChecksModel, state *githubChecksModel) {
	if state == nil {
		return
	}

	state.RequiredChecks = r.alignChecksBlock(ctx, plan.RequiredChecks, state.RequiredChecks)
	state.OptionalChecks = r.alignChecksBlock(ctx, plan.OptionalChecks, state.OptionalChecks)
	state.BaselineCheck = r.alignChecksBlock(ctx, plan.BaselineCheck, state.BaselineCheck)

	if state.Controls.IsUnknown() || state.Controls.IsNull() {
		return
	}

	var planControls, stateControls []control
	if !plan.Controls.IsUnknown() && !plan.Controls.IsNull() {
		if diags := plan.Controls.ElementsAs(ctx, &planControls, false); diags.HasError() {
			return
		}
	}
	if diags := state.Controls.ElementsAs(ctx, &stateControls, false); diags.HasError() {
		return
	}

	stateByName := make(map[string]control, len(stateControls))
	for _, ctrl := range stateControls {
		stateByName[ctrl.Control.ValueString()] = ctrl
	}

	// Controls in plan order, using the values from state. A control missing from state
	// (removed outside Terraform) is left out so the diff is visible.
	ordered := make([]control, 0, len(stateControls))
	inPlan := make(map[string]bool, len(planControls))
	for _, planCtrl := range planControls {
		name := planCtrl.Control.ValueString()
		stateCtrl, ok := stateByName[name]
		if !ok || inPlan[name] {
			continue
		}
		inPlan[name] = true
		stateCtrl.Settings = alignSettings(planCtrl.Settings, stateCtrl.Settings)
		ordered = append(ordered, stateCtrl)
	}
	// stateControls is sorted by name, so extras are appended in a stable order.
	for _, stateCtrl := range stateControls {
		if !inPlan[stateCtrl.Control.ValueString()] && stateCtrl.Enable.ValueBool() {
			ordered = append(ordered, stateCtrl)
		}
	}
	state.Controls, _ = types.ListValueFrom(ctx, controlObjectType(), ordered)
}

// alignChecksBlock returns stateObj (a required_checks/optional_checks/baseline_check block
// built from the API) reshaped to match planObj where the API data can't tell them apart.
//   - plan null: stateObj as built from the API. In Create/Update that is null, since nothing
//     was sent for the block; in Read/import a non-null block is real drift.
//   - plan set, state null: the API has no repos for the block, so return an empty block in
//     the plan's shape. An empty block in config is valid ("not applied to any repo yet").
//   - both set: take the plan's repos/omit_repos where they hold the same repos, keeping the
//     plan's order and its null vs [] choice.
func (r *githubChecksResource) alignChecksBlock(ctx context.Context, planObj, stateObj types.Object) types.Object {
	planCfg, diags := decodeChecksConfig(ctx, planObj)
	if diags.HasError() || planCfg == nil {
		return stateObj
	}
	stateCfg, diags := decodeChecksConfig(ctx, stateObj)
	if diags.HasError() {
		return stateObj
	}

	if stateCfg == nil {
		stateCfg = &checksConfig{
			Repos:     types.ListValueMust(types.StringType, []attr.Value{}),
			OmitRepos: types.ListNull(types.StringType),
		}
	}

	stateCfg.Repos = r.alignStringList(planCfg.Repos, stateCfg.Repos)
	stateCfg.OmitRepos = r.alignStringList(planCfg.OmitRepos, stateCfg.OmitRepos)
	return encodeChecksConfig(ctx, stateCfg)
}

// alignStringList returns planList when it holds the same strings as stateList, ignoring
// order and treating null and [] as equal; otherwise stateList.
func (r *githubChecksResource) alignStringList(planList, stateList types.List) types.List {
	if planList.IsUnknown() {
		return stateList
	}
	equal := cmp.Equal(
		r.listToStringSlice(planList),
		r.listToStringSlice(stateList),
		cmpopts.SortSlices(func(a, b string) bool { return a < b }),
		cmpopts.EquateEmpty(),
	)
	if equal {
		return planList
	}
	return stateList
}

// alignSettings keeps an empty packages_to_exempt_in_cooldown_check from plan. Empty lists
// aren't sent to the API, so state built from it has null there instead.
func alignSettings(planSettings, stateSettings types.Object) types.Object {
	if planSettings.IsNull() || planSettings.IsUnknown() || stateSettings.IsNull() || stateSettings.IsUnknown() {
		return stateSettings
	}
	planPackages, ok := planSettings.Attributes()["packages_to_exempt_in_cooldown_check"].(types.List)
	if !ok || planPackages.IsNull() || planPackages.IsUnknown() || len(planPackages.Elements()) != 0 {
		return stateSettings
	}
	statePackages, ok := stateSettings.Attributes()["packages_to_exempt_in_cooldown_check"].(types.List)
	if !ok || !statePackages.IsNull() {
		return stateSettings
	}
	attrs := stateSettings.Attributes()
	attrs["packages_to_exempt_in_cooldown_check"] = planPackages
	aligned, diags := types.ObjectValue(controlSettingsAttrTypes(), attrs)
	if diags.HasError() {
		return stateSettings
	}
	return aligned
}

// listToStringSlice converts types.List to []string
func (r *githubChecksResource) listToStringSlice(list types.List) []string {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	elements := list.Elements()
	result := make([]string, 0, len(elements))
	for _, elem := range elements {
		if strVal, ok := elem.(types.String); ok {
			result = append(result, strVal.ValueString())
		}
	}
	return result
}
