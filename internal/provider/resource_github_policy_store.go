package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &githubPolicyStoreResource{}
	_ resource.ResourceWithConfigure   = &githubPolicyStoreResource{}
	_ resource.ResourceWithImportState = &githubPolicyStoreResource{}
)

// NewOrderResource is a helper function to simplify the provider implementation.
func NewGithubPolicyStoreResource() resource.Resource {
	return &githubPolicyStoreResource{}
}

// orderResource is the resource implementation.
type githubPolicyStoreResource struct {
	client stepsecurityapi.Client
}

// Metadata returns the resource type name.
func (r *githubPolicyStoreResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_policy_store"
}

// Schema defines the schema for the resource.
func (r *githubPolicyStoreResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the policy store. This is combination of owner and policy name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"owner": schema.StringAttribute{
				Required:    true,
				Description: "Github Organization(owner) name",
			},
			"policy_name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the policy",
			},
			"egress_policy": schema.StringAttribute{
				Required:    true,
				Description: "Egress policy mode. Can be 'audit' or 'block'",
			},
			"allowed_endpoints": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Default: listdefault.StaticValue(
					types.ListValueMust(
						types.StringType,
						[]attr.Value{
							types.StringValue("github.com:443"),
						},
					),
				),
				Description: "List of allowed endpoints. This specifies list of enpoints to allow when egress policy is set to 'block' mode",
			},
			"disable_telemetry": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "This disables telemetry collection.",
			},
			"disable_sudo": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "This disables sudo access for HardenRunner agent",
			},
			"disable_file_monitoring": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "This disables file monitoring",
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *githubPolicyStoreResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

type githubPolicyStoreModel struct {
	ID                    types.String `tfsdk:"id"`
	Owner                 types.String `tfsdk:"owner"`
	PolicyName            types.String `tfsdk:"policy_name"`
	EgressPolicy          types.String `tfsdk:"egress_policy"`
	AllowedEndpoints      types.List   `tfsdk:"allowed_endpoints"`
	DisableTelemetry      types.Bool   `tfsdk:"disable_telemetry"`
	DisableSudo           types.Bool   `tfsdk:"disable_sudo"`
	DisableFileMonitoring types.Bool   `tfsdk:"disable_file_monitoring"`
}

// ImportState implements resource.ResourceWithImportState.
func (r *githubPolicyStoreResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID should be the owner name
	id := req.ID

	// Split the ID into owner and policy name
	splitted := strings.Split(id, ":::")
	if len(splitted) != 2 {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected owner:::policy_name, got: %s", id),
		)
		return
	}

	// Set the owner/policy name in the state
	owner := splitted[0]
	policyName := splitted[1]
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("owner"), owner)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("policy_name"), policyName)...)

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

// Create creates the resource and sets the initial Terraform state.
func (r *githubPolicyStoreResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan githubPolicyStoreModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy := r.getGitHubPolicyStorePolicy(plan)
	if err := r.client.CreateGitHubPolicyStorePolicy(ctx, policy); err != nil {
		resp.Diagnostics.AddError(
			"Failed to create policy",
			fmt.Sprintf("Error creating policy: %s", err),
		)
		return
	}

	// get the policy and update state
	policy, err := r.client.GetGitHubPolicyStorePolicy(ctx, plan.Owner.ValueString(), plan.PolicyName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read policy after create",
			fmt.Sprintf("Error reading policy after create: %s", err),
		)
		return
	}

	// update the state
	r.updateGitHubPolicyStorePolicyState(policy, &plan)

	// Set state to fully populated data
	diags := resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Read refreshes the Terraform state with the latest data.
func (r *githubPolicyStoreResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state githubPolicyStoreModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.client.GetGitHubPolicyStorePolicy(ctx, state.Owner.ValueString(), state.PolicyName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read policy",
			fmt.Sprintf("Error reading policy: %s", err),
		)
		return
	}

	// update the state
	r.updateGitHubPolicyStorePolicyState(policy, &state)
	// Set state to fully populated data
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Update updates the resource and sets the updated Terraform state on success.
func (r *githubPolicyStoreResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan githubPolicyStoreModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy := r.getGitHubPolicyStorePolicy(plan)
	if err := r.client.CreateGitHubPolicyStorePolicy(ctx, policy); err != nil {
		resp.Diagnostics.AddError(
			"Failed to update policy",
			fmt.Sprintf("Error updating policy: %s", err),
		)
		return
	}

	// get the policy and update state
	policy, err := r.client.GetGitHubPolicyStorePolicy(ctx, plan.Owner.ValueString(), plan.PolicyName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read policy after update",
			fmt.Sprintf("Error reading policy after update: %s", err),
		)
		return
	}

	// update the state

	var state githubPolicyStoreModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.updateGitHubPolicyStorePolicyState(policy, &state)

	// Set state to fully populated data
	diags := resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *githubPolicyStoreResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state githubPolicyStoreModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteGitHubPolicyStorePolicy(ctx, state.Owner.ValueString(), state.PolicyName.ValueString()); err != nil {
		resp.Diagnostics.AddError(
			"Failed to delete policy",
			fmt.Sprintf("Error deleting policy: %s", err),
		)
		return
	}
}

func (r *githubPolicyStoreResource) updateGitHubPolicyStorePolicyState(policy *stepsecurityapi.GitHubPolicyStorePolicy, state *githubPolicyStoreModel) {

	var allowedEndpoints []attr.Value
	for _, endpoint := range policy.AllowedEndpoints {
		allowedEndpoints = append(allowedEndpoints, types.StringValue(endpoint))
	}

	state.ID = types.StringValue(policy.Owner + ":::" + policy.PolicyName)
	state.Owner = types.StringValue(policy.Owner)
	state.PolicyName = types.StringValue(policy.PolicyName)
	state.AllowedEndpoints = types.ListValueMust(
		types.StringType,
		allowedEndpoints,
	)
	state.EgressPolicy = types.StringValue(policy.EgressPolicy)
	state.DisableTelemetry = types.BoolValue(policy.DisableTelemetry)
	state.DisableSudo = types.BoolValue(policy.DisableSudo)
	state.DisableFileMonitoring = types.BoolValue(policy.DisableFileMonitoring)
}

func (r *githubPolicyStoreResource) getGitHubPolicyStorePolicy(plan githubPolicyStoreModel) *stepsecurityapi.GitHubPolicyStorePolicy {
	var allowedEndpoints []string
	for _, ep := range plan.AllowedEndpoints.Elements() {
		allowedEndpoints = append(allowedEndpoints, ep.(types.String).ValueString())
	}

	return &stepsecurityapi.GitHubPolicyStorePolicy{
		Owner:                 plan.Owner.ValueString(),
		PolicyName:            plan.PolicyName.ValueString(),
		AllowedEndpoints:      allowedEndpoints,
		EgressPolicy:          plan.EgressPolicy.ValueString(),
		DisableTelemetry:      plan.DisableTelemetry.ValueBool(),
		DisableSudo:           plan.DisableSudo.ValueBool(),
		DisableFileMonitoring: plan.DisableFileMonitoring.ValueBool(),
	}
}
