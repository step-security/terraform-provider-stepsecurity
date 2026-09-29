package provider

import (
	"context"
	"fmt"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// maxPATThresholdDays mirrors the agent-api bound on every day-valued
// threshold in the PAT governance policy.
const maxPATThresholdDays = 3650

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &githubPATGovernancePolicyResource{}
	_ resource.ResourceWithConfigure   = &githubPATGovernancePolicyResource{}
	_ resource.ResourceWithImportState = &githubPATGovernancePolicyResource{}
)

// NewGithubPATGovernancePolicyResource is a helper function to simplify the provider implementation.
func NewGithubPATGovernancePolicyResource() resource.Resource {
	return &githubPATGovernancePolicyResource{}
}

// githubPATGovernancePolicyResource is the resource implementation.
type githubPATGovernancePolicyResource struct {
	client stepsecurityapi.Client
}

// Configure adds the provider configured client to the resource.
func (r *githubPATGovernancePolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(stepsecurityapi.Client)

	if !ok || client == nil {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected stepsecurityapi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

// Metadata returns the resource type name.
func (r *githubPATGovernancePolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_pat_governance_policy"
}

// Schema defines the schema for the resource.
func (r *githubPATGovernancePolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the PAT governance policy for a GitHub organization. The policy drives the " +
			"personal-access-token controls on the StepSecurity dashboard (max age, no expiration, over-scoped, " +
			"unused, inactive owner) and the resulting violation alerts and pre-expiry reminders. " +
			"An enabled policy needs at least one active control. Deleting the resource disables the policy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The ID of the PAT governance policy. This is same as the owner/organization name.",
			},
			"owner": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The owner/organization name the policy applies to.",
			},
			"enabled": schema.BoolAttribute{
				Required:    true,
				Description: "Whether the PAT governance policy is enforced. An enabled policy needs at least one active control.",
			},
			"fine_grained_max_age_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				Description: "Maximum allowed age in days for fine-grained PATs, measured from the org-access grant time. 0 disables the check.",
				Validators: []validator.Int64{
					int64validator.Between(0, maxPATThresholdDays),
				},
			},
			"classic_max_age_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				Description: "Maximum allowed age in days for classic PATs, measured from the SSO authorization time. 0 disables the check.",
				Validators: []validator.Int64{
					int64validator.Between(0, maxPATThresholdDays),
				},
			},
			"flag_no_expiry": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Flag tokens without an expiration date, or whose expiration is set further out than the class max age allows.",
			},
			"flag_over_scoped": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Flag over-scoped tokens: classic PATs carrying coarse scopes, and fine-grained PATs granting write access across all repositories.",
			},
			"over_scoped_scopes": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Classic PAT scopes treated as over-scoped. Omit to use the server default (repo, admin:org, workflow). Only used when flag_over_scoped is true.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
				},
			},
			"unused_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				Description: "Flag tokens with no sign of use for more than this many days (never-used tokens count from their grant/authorization time). 0 disables the check.",
				Validators: []validator.Int64{
					int64validator.Between(0, maxPATThresholdDays),
				},
			},
			"github_issue_repo": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "Bare repository name in this organization where a violations issue is filed and kept up to date on each alert. Empty disables the GitHub-issue alert channel.",
			},
			"expiry_reminder_days": schema.ListAttribute{
				ElementType: types.Int64Type,
				Optional:    true,
				Description: "Pre-expiry reminder bands in days before expiry, each reminded once per token. Omit to use the server default (30, 7, 1).",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.ValueInt64sAre(int64validator.Between(1, maxPATThresholdDays)),
				},
			},
		},
	}
}

// ImportState implements resource.ResourceWithImportState.
func (r *githubPATGovernancePolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

type githubPATGovernancePolicyModel struct {
	ID                    types.String `tfsdk:"id"`
	Owner                 types.String `tfsdk:"owner"`
	Enabled               types.Bool   `tfsdk:"enabled"`
	FineGrainedMaxAgeDays types.Int64  `tfsdk:"fine_grained_max_age_days"`
	ClassicMaxAgeDays     types.Int64  `tfsdk:"classic_max_age_days"`
	FlagNoExpiry          types.Bool   `tfsdk:"flag_no_expiry"`
	FlagOverScoped        types.Bool   `tfsdk:"flag_over_scoped"`
	OverScopedScopes      types.List   `tfsdk:"over_scoped_scopes"`
	UnusedDays            types.Int64  `tfsdk:"unused_days"`
	GitHubIssueRepo       types.String `tfsdk:"github_issue_repo"`
	ExpiryReminderDays    types.List   `tfsdk:"expiry_reminder_days"`
}

// toAPIPolicy converts the planned model into the API request payload.
func (m *githubPATGovernancePolicyModel) toAPIPolicy(ctx context.Context) (stepsecurityapi.PATGovernancePolicy, error) {
	policy := stepsecurityapi.PATGovernancePolicy{
		Enabled:               m.Enabled.ValueBool(),
		FineGrainedMaxAgeDays: m.FineGrainedMaxAgeDays.ValueInt64(),
		ClassicMaxAgeDays:     m.ClassicMaxAgeDays.ValueInt64(),
		FlagNoExpiry:          m.FlagNoExpiry.ValueBool(),
		FlagOverScoped:        m.FlagOverScoped.ValueBool(),
		UnusedDays:            m.UnusedDays.ValueInt64(),
		GitHubIssueRepo:       m.GitHubIssueRepo.ValueString(),
	}

	if !m.OverScopedScopes.IsNull() && !m.OverScopedScopes.IsUnknown() {
		if diags := m.OverScopedScopes.ElementsAs(ctx, &policy.OverScopedScopes, false); diags.HasError() {
			return policy, fmt.Errorf("failed to convert over_scoped_scopes: %v", diags.Errors())
		}
	}

	if !m.ExpiryReminderDays.IsNull() && !m.ExpiryReminderDays.IsUnknown() {
		if diags := m.ExpiryReminderDays.ElementsAs(ctx, &policy.ExpiryReminderDays, false); diags.HasError() {
			return policy, fmt.Errorf("failed to convert expiry_reminder_days: %v", diags.Errors())
		}
	}

	return policy, nil
}

// setFromAPIPolicy refreshes the model from the API response.
func (m *githubPATGovernancePolicyModel) setFromAPIPolicy(ctx context.Context, policy *stepsecurityapi.PATGovernancePolicy) error {
	m.ID = types.StringValue(m.Owner.ValueString())
	m.Enabled = types.BoolValue(policy.Enabled)
	m.FineGrainedMaxAgeDays = types.Int64Value(policy.FineGrainedMaxAgeDays)
	m.ClassicMaxAgeDays = types.Int64Value(policy.ClassicMaxAgeDays)
	m.FlagNoExpiry = types.BoolValue(policy.FlagNoExpiry)
	m.FlagOverScoped = types.BoolValue(policy.FlagOverScoped)
	m.UnusedDays = types.Int64Value(policy.UnusedDays)
	m.GitHubIssueRepo = types.StringValue(policy.GitHubIssueRepo)

	if len(policy.OverScopedScopes) > 0 {
		scopes, diags := types.ListValueFrom(ctx, types.StringType, policy.OverScopedScopes)
		if diags.HasError() {
			return fmt.Errorf("failed to convert over_scoped_scopes: %v", diags.Errors())
		}
		m.OverScopedScopes = scopes
	} else {
		m.OverScopedScopes = types.ListNull(types.StringType)
	}

	if len(policy.ExpiryReminderDays) > 0 {
		bands, diags := types.ListValueFrom(ctx, types.Int64Type, policy.ExpiryReminderDays)
		if diags.HasError() {
			return fmt.Errorf("failed to convert expiry_reminder_days: %v", diags.Errors())
		}
		m.ExpiryReminderDays = bands
	} else {
		m.ExpiryReminderDays = types.ListNull(types.Int64Type)
	}

	return nil
}

// Create creates the resource and sets the initial Terraform state.
func (r *githubPATGovernancePolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan githubPATGovernancePolicyModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := plan.toAPIPolicy(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Create PAT Governance Policy", err.Error())
		return
	}

	if err := r.client.UpdatePATGovernancePolicy(ctx, plan.Owner.ValueString(), policy); err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create PAT Governance Policy",
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
func (r *githubPATGovernancePolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state githubPATGovernancePolicyModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.client.GetPATGovernancePolicy(ctx, state.Owner.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read PAT Governance Policy",
			err.Error(),
		)
		return
	}

	// The API reports an org that has never configured a policy as a null
	// policy, which for Terraform means the resource no longer exists.
	if policy == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	if err := state.setFromAPIPolicy(ctx, policy); err != nil {
		resp.Diagnostics.AddError("Unable to Read PAT Governance Policy", err.Error())
		return
	}

	// Set state to fully populated data
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *githubPATGovernancePolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan githubPATGovernancePolicyModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := plan.toAPIPolicy(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Update PAT Governance Policy", err.Error())
		return
	}

	if err := r.client.UpdatePATGovernancePolicy(ctx, plan.Owner.ValueString(), policy); err != nil {
		resp.Diagnostics.AddError(
			"Unable to Update PAT Governance Policy",
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
func (r *githubPATGovernancePolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state githubPATGovernancePolicyModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The API has no DELETE endpoint: deleting writes a disabled policy with
	// every control off, which stops all evaluation and alerting.
	err := r.client.DeletePATGovernancePolicy(ctx, state.Owner.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Delete PAT Governance Policy",
			err.Error(),
		)
		return
	}
}
