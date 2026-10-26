package provider

import (
	"context"
	"fmt"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &githubTenantPATGovernancePolicyResource{}
	_ resource.ResourceWithConfigure   = &githubTenantPATGovernancePolicyResource{}
	_ resource.ResourceWithImportState = &githubTenantPATGovernancePolicyResource{}
)

// NewGithubTenantPATGovernancePolicyResource is a helper function to simplify the provider implementation.
func NewGithubTenantPATGovernancePolicyResource() resource.Resource {
	return &githubTenantPATGovernancePolicyResource{}
}

// githubTenantPATGovernancePolicyResource manages the customer's tenant-wide
// PAT governance policy, the policy every organization follows unless it
// stores a policy of its own.
type githubTenantPATGovernancePolicyResource struct {
	client stepsecurityapi.Client
}

// githubTenantPATGovernancePolicyModel is the tenant-wide policy: the shared
// settings and nothing else. The tenant is the one configured on the
// provider, and a tenant policy cannot defer to anything above it.
type githubTenantPATGovernancePolicyModel struct {
	patPolicySettingsModel
}

// Configure adds the provider configured client to the resource.
func (r *githubTenantPATGovernancePolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *githubTenantPATGovernancePolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_tenant_pat_governance_policy"
}

// Schema defines the schema for the resource.
func (r *githubTenantPATGovernancePolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the tenant-wide PAT governance policy of the customer configured on the provider: " +
			"the policy every GitHub organization follows unless it stores a policy of its own " +
			"(see stepsecurity_github_pat_governance_policy). The settings are the same as the organization policy " +
			"and an enabled policy needs at least one active control. There is exactly one tenant-wide policy per " +
			"customer, so declare at most one instance of this resource. Destroying the resource removes the " +
			"tenant-wide policy; organizations without their own policy then follow the built-in default, which " +
			"only displays violations and never sends reminders or revokes tokens.",
		Attributes: patPolicySettingsAttributes(),
	}
}

// Create stores the tenant-wide policy and sets the initial Terraform state.
func (r *githubTenantPATGovernancePolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan githubTenantPATGovernancePolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.write(ctx, &plan, "Unable to Create Tenant PAT Governance Policy", resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the stored tenant-wide policy. No
// prior state is needed: the tenant is fixed by the provider configuration,
// which also makes import trivial.
func (r *githubTenantPATGovernancePolicyResource) Read(ctx context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	policy, err := r.client.GetTenantPATGovernancePolicy(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Read Tenant PAT Governance Policy", err.Error())
		return
	}

	// No stored tenant policy means the resource no longer exists; the
	// organizations follow the built-in default.
	if policy == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	var state githubTenantPATGovernancePolicyModel
	if err := state.setFromAPIPolicy(ctx, policy); err != nil {
		resp.Diagnostics.AddError("Unable to Read Tenant PAT Governance Policy", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update replaces the tenant-wide policy and sets the updated Terraform state.
func (r *githubTenantPATGovernancePolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan githubTenantPATGovernancePolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.write(ctx, &plan, "Unable to Update Tenant PAT Governance Policy", resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete removes the tenant-wide policy; organizations without a policy of
// their own then follow the built-in default.
func (r *githubTenantPATGovernancePolicyResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.DeleteTenantPATGovernancePolicy(ctx); err != nil {
		resp.Diagnostics.AddError("Unable to Delete Tenant PAT Governance Policy", err.Error())
	}
}

// ImportState imports the single tenant-wide policy of the customer configured
// on the provider. The import ID identifies nothing, there is one policy per
// tenant, so any value is accepted and ignored.
func (r *githubTenantPATGovernancePolicyResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	readResp := &resource.ReadResponse{State: resp.State}
	r.Read(ctx, resource.ReadRequest{State: resp.State}, readResp)
	resp.Diagnostics.Append(readResp.Diagnostics...)
	resp.State = readResp.State
}

// write pushes the planned settings to the API.
func (r *githubTenantPATGovernancePolicyResource) write(ctx context.Context, plan *githubTenantPATGovernancePolicyModel, summary string, addError func(summary, detail string)) {
	policy, err := plan.toAPIPolicy(ctx)
	if err != nil {
		addError(summary, err.Error())
		return
	}
	if err := r.client.UpdateTenantPATGovernancePolicy(ctx, policy); err != nil {
		addError(summary, err.Error())
	}
}
