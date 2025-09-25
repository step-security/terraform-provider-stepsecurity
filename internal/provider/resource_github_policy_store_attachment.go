package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// applyToRepoDefault is a plan modifier that sets apply_to_repo based on workflows
type applyToRepoDefault struct{}

func (m applyToRepoDefault) Description(ctx context.Context) string {
	return "Sets apply_to_repo to false when workflows are specified, true otherwise"
}

func (m applyToRepoDefault) MarkdownDescription(ctx context.Context) string {
	return "Sets apply_to_repo to false when workflows are specified, true otherwise"
}

func (m applyToRepoDefault) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	// Skip if we already have a configured value
	if !req.ConfigValue.IsNull() {
		return
	}

	// Get the workflows attribute from the same object
	workflowsPath := req.Path.ParentPath().AtName("workflows")
	var workflows types.List
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, workflowsPath, &workflows)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set apply_to_repo based on whether workflows are specified
	hasWorkflows := !workflows.IsNull() && len(workflows.Elements()) > 0
	resp.PlanValue = types.BoolValue(!hasWorkflows)
}

// applyToOrgDefault is a plan modifier that sets apply_to_org based on repositories
type applyToOrgDefault struct{}

func (m applyToOrgDefault) Description(ctx context.Context) string {
	return "Sets apply_to_org to true when no repositories are specified or repositories is empty, false otherwise"
}

func (m applyToOrgDefault) MarkdownDescription(ctx context.Context) string {
	return "Sets apply_to_org to true when no repositories are specified or repositories is empty, false otherwise"
}

func (m applyToOrgDefault) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	// Skip if we already have a configured value
	if !req.ConfigValue.IsNull() {
		return
	}

	// Get the repositories attribute from the same object
	repositoriesPath := req.Path.ParentPath().AtName("repositories")
	var repositories types.List
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, repositoriesPath, &repositories)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set apply_to_org based on whether repositories are specified
	hasRepositories := !repositories.IsNull() && len(repositories.Elements()) > 0
	resp.PlanValue = types.BoolValue(!hasRepositories)
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &githubPolicyStoreAttachmentResource{}
	_ resource.ResourceWithConfigure   = &githubPolicyStoreAttachmentResource{}
	_ resource.ResourceWithImportState = &githubPolicyStoreAttachmentResource{}
)

// NewGithubPolicyStoreAttachmentResource is a helper function to simplify the provider implementation.
func NewGithubPolicyStoreAttachmentResource() resource.Resource {
	return &githubPolicyStoreAttachmentResource{}
}

// githubPolicyStoreAttachmentResource is the resource implementation.
type githubPolicyStoreAttachmentResource struct {
	client stepsecurityapi.Client
}

// Metadata returns the resource type name.
func (r *githubPolicyStoreAttachmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_policy_store_attachment"
}

// Schema defines the schema for the resource.
func (r *githubPolicyStoreAttachmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the policy attachment. This is combination of owner and policy name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"owner": schema.StringAttribute{
				Required:    true,
				Description: "GitHub Organization (owner) name",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"policy_name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the policy to attach",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"org": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Organization-level attachment configuration",
				Attributes: map[string]schema.Attribute{
					"apply_to_org": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "If true, applies to entire organization. Defaults to true when no repositories are specified, false when repositories are specified",
						PlanModifiers: []planmodifier.Bool{
							applyToOrgDefault{},
						},
					},
					"repositories": schema.ListNestedAttribute{
						Optional:    true,
						Description: "List of repository-level attachments",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"name": schema.StringAttribute{
									Required:    true,
									Description: "Repository name",
								},
								"apply_to_repo": schema.BoolAttribute{
									Optional:    true,
									Computed:    true,
									Description: "If true, applies to entire repository. Automatically set to false when workflows are specified, otherwise defaults to true",
									PlanModifiers: []planmodifier.Bool{
										applyToRepoDefault{},
									},
								},
								"workflows": schema.ListAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Description: "List of specific workflows",
								},
							},
						},
					},
				},
			},
			"clusters": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "List of cluster names for cluster-level attachments",
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *githubPolicyStoreAttachmentResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

type orgAttachmentModel struct {
	ApplyToOrg   types.Bool `tfsdk:"apply_to_org"`
	Repositories types.List `tfsdk:"repositories"`
}

type repoAttachmentModel struct {
	Name        types.String `tfsdk:"name"`
	ApplyToRepo types.Bool   `tfsdk:"apply_to_repo"`
	Workflows   types.List   `tfsdk:"workflows"`
}

type githubPolicyStoreAttachmentModel struct {
	ID         types.String `tfsdk:"id"`
	Owner      types.String `tfsdk:"owner"`
	PolicyName types.String `tfsdk:"policy_name"`
	Org        types.Object `tfsdk:"org"`
	Clusters   types.List   `tfsdk:"clusters"`
}

// ImportState implements resource.ResourceWithImportState.
func (r *githubPolicyStoreAttachmentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID should be the owner:::policy_name format
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
func (r *githubPolicyStoreAttachmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan githubPolicyStoreAttachmentModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate the configuration - ensure at least one attachment type is specified
	if plan.Org.IsNull() && (plan.Clusters.IsNull() || len(plan.Clusters.Elements()) == 0) {
		resp.Diagnostics.AddError("Invalid Configuration", "At least one attachment (org or clusters) must be specified")
		return
	}

	// Create attachment
	if err := r.createAttachment(ctx, &plan); err != nil {
		resp.Diagnostics.AddError(
			"Failed to attach policy",
			fmt.Sprintf("Error attaching policy: %s", err),
		)
		return
	}

	// Set state
	plan.ID = types.StringValue(plan.Owner.ValueString() + ":::" + plan.PolicyName.ValueString())

	// Set state to fully populated data
	diags := resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *githubPolicyStoreAttachmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state githubPolicyStoreAttachmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get policy with attachments
	policy, err := r.client.GetGitHubPolicyStorePolicy(ctx, state.Owner.ValueString(), state.PolicyName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read policy attachments",
			fmt.Sprintf("Error reading policy attachments: %s", err),
		)
		return
	}

	// Update state with attachment information
	r.updateAttachmentState(policy, &state)

	// Set state to fully populated data
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *githubPolicyStoreAttachmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan githubPolicyStoreAttachmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate the configuration - ensure at least one attachment type is specified
	if plan.Org.IsNull() && (plan.Clusters.IsNull() || len(plan.Clusters.Elements()) == 0) {
		resp.Diagnostics.AddError("Invalid Configuration", "At least one attachment (org or clusters) must be specified")
		return
	}

	// First detach existing attachment
	if err := r.client.DetachGitHubPolicyStorePolicy(ctx, plan.Owner.ValueString(), plan.PolicyName.ValueString()); err != nil {
		resp.Diagnostics.AddError(
			"Failed to detach policy",
			fmt.Sprintf("Error detaching policy: %s", err),
		)
		return
	}

	// Then create new attachment
	if err := r.createAttachment(ctx, &plan); err != nil {
		resp.Diagnostics.AddError(
			"Failed to attach policy",
			fmt.Sprintf("Error attaching policy: %s", err),
		)
		return
	}

	// Set state to fully populated data
	diags := resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *githubPolicyStoreAttachmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state githubPolicyStoreAttachmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Detach the policy
	if err := r.client.DetachGitHubPolicyStorePolicy(ctx, state.Owner.ValueString(), state.PolicyName.ValueString()); err != nil {
		resp.Diagnostics.AddError(
			"Failed to detach policy",
			fmt.Sprintf("Error detaching policy: %s", err),
		)
		return
	}
}

// Helper functions
func (r *githubPolicyStoreAttachmentResource) createAttachment(ctx context.Context, plan *githubPolicyStoreAttachmentModel) error {
	owner := plan.Owner.ValueString()
	policyName := plan.PolicyName.ValueString()

	// Build the hierarchical attachment request
	request := &stepsecurityapi.GitHubPolicyAttachRequest{}

	// Handle org-level attachments
	if !plan.Org.IsNull() {
		orgAttrs := plan.Org.Attributes()

		orgResource := &stepsecurityapi.OrgResource{
			Name: owner,
		}

		// First, handle repositories to determine if apply_to_org should be automatically set
		var hasRepositories bool
		var repos []stepsecurityapi.RepoResource

		if reposAttr, exists := orgAttrs["repositories"]; exists && !reposAttr.IsNull() {
			reposList := reposAttr.(types.List)
			hasRepositories = len(reposList.Elements()) > 0

			for _, repoObj := range reposList.Elements() {
				repoAttrs := repoObj.(types.Object).Attributes()

				repoResource := stepsecurityapi.RepoResource{}
				if nameAttr, exists := repoAttrs["name"]; exists {
					repoResource.Name = nameAttr.(types.String).ValueString()
				}

				// Check if workflows are specified first
				var hasWorkflows bool
				if workflowsAttr, exists := repoAttrs["workflows"]; exists && !workflowsAttr.IsNull() {
					workflowsList := workflowsAttr.(types.List)
					if len(workflowsList.Elements()) > 0 {
						hasWorkflows = true
						for _, workflow := range workflowsList.Elements() {
							repoResource.Workflows = append(repoResource.Workflows, workflow.(types.String).ValueString())
						}
					}
				}

				// Always calculate apply_to_repo based on workflows
				repoResource.ApplyToRepo = !hasWorkflows

				repos = append(repos, repoResource)
			}

			orgResource.Repos = repos
		}

		// Always calculate apply_to_org based on repositories
		orgResource.ApplyToOrg = !hasRepositories

		request.Org = orgResource
	}

	// Handle cluster-level attachments
	if !plan.Clusters.IsNull() && len(plan.Clusters.Elements()) > 0 {
		var clusters []string
		for _, cluster := range plan.Clusters.Elements() {
			clusters = append(clusters, cluster.(types.String).ValueString())
		}
		request.Clusters = clusters
	}

	return r.client.AttachGitHubPolicyStorePolicy(ctx, owner, policyName, request)
}

func (r *githubPolicyStoreAttachmentResource) updateAttachmentState(policy *stepsecurityapi.GitHubPolicyStorePolicy, state *githubPolicyStoreAttachmentModel) {
	state.ID = types.StringValue(policy.Owner + ":::" + policy.PolicyName)

	// If no attachments, clear the state
	if policy.Attachments == nil {
		state.Org = types.ObjectNull(map[string]attr.Type{
			"apply_to_org": types.BoolType,
			"repositories": types.ListType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{
				"name":          types.StringType,
				"apply_to_repo": types.BoolType,
				"workflows":     types.ListType{ElemType: types.StringType},
			}}},
		})
		state.Clusters = types.ListNull(types.StringType)
		return
	}

	// Handle org attachments
	if policy.Attachments.Org != nil {
		orgAttrs := map[string]attr.Value{
			"apply_to_org": types.BoolValue(policy.Attachments.Org.ApplyToOrg),
		}

		// Build repositories list
		var repoObjs []attr.Value
		for _, repo := range policy.Attachments.Org.Repos {
			var workflowAttrs []attr.Value
			for _, workflow := range repo.Workflows {
				workflowAttrs = append(workflowAttrs, types.StringValue(workflow))
			}

			// Handle empty workflows as null to match schema expectations
			var workflowsList types.List
			if len(workflowAttrs) == 0 {
				workflowsList = types.ListNull(types.StringType)
			} else {
				workflowsList = types.ListValueMust(types.StringType, workflowAttrs)
			}

			// Calculate apply_to_repo consistently with createAttachment logic
			hasWorkflows := len(repo.Workflows) > 0
			applyToRepo := !hasWorkflows

			repoAttrs := map[string]attr.Value{
				"name":          types.StringValue(repo.Name),
				"apply_to_repo": types.BoolValue(applyToRepo),
				"workflows":     workflowsList,
			}

			repoObjs = append(repoObjs, types.ObjectValueMust(map[string]attr.Type{
				"name":          types.StringType,
				"apply_to_repo": types.BoolType,
				"workflows":     types.ListType{ElemType: types.StringType},
			}, repoAttrs))
		}

		// Handle empty repositories as null to match schema expectations
		if len(repoObjs) == 0 {
			orgAttrs["repositories"] = types.ListNull(types.ObjectType{AttrTypes: map[string]attr.Type{
				"name":          types.StringType,
				"apply_to_repo": types.BoolType,
				"workflows":     types.ListType{ElemType: types.StringType},
			}})
		} else {
			orgAttrs["repositories"] = types.ListValueMust(types.ObjectType{AttrTypes: map[string]attr.Type{
				"name":          types.StringType,
				"apply_to_repo": types.BoolType,
				"workflows":     types.ListType{ElemType: types.StringType},
			}}, repoObjs)
		}

		state.Org = types.ObjectValueMust(map[string]attr.Type{
			"apply_to_org": types.BoolType,
			"repositories": types.ListType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{
				"name":          types.StringType,
				"apply_to_repo": types.BoolType,
				"workflows":     types.ListType{ElemType: types.StringType},
			}}},
		}, orgAttrs)
	} else {
		state.Org = types.ObjectNull(map[string]attr.Type{
			"apply_to_org": types.BoolType,
			"repositories": types.ListType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{
				"name":          types.StringType,
				"apply_to_repo": types.BoolType,
				"workflows":     types.ListType{ElemType: types.StringType},
			}}},
		})
	}

	// Handle cluster attachments
	if len(policy.Attachments.Clusters) > 0 {
		var clusterAttrs []attr.Value
		for _, cluster := range policy.Attachments.Clusters {
			clusterAttrs = append(clusterAttrs, types.StringValue(cluster))
		}
		state.Clusters = types.ListValueMust(types.StringType, clusterAttrs)
	} else {
		state.Clusters = types.ListNull(types.StringType)
	}
}
