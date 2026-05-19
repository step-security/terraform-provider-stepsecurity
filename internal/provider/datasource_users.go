package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &usersDataSource{}
	_ datasource.DataSourceWithConfigure = &usersDataSource{}
)

// NewUsersDataSource is a helper function to simplify the provider implementation.
func NewUsersDataSource() datasource.DataSource {
	return &usersDataSource{}
}

// usersDataSource is the data source implementation.
type usersDataSource struct {
	client stepsecurityapi.Client
}

// Metadata returns the data source type name.
func (d *usersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_users"
}

// Configure adds the provider configured client to the data source.
func (d *usersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

	d.client = client
}

// Schema defines the schema for the data source.
func (d *usersDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"users": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The ID of the user",
						},
						"email": schema.StringAttribute{
							Computed:    true,
							Description: "The email of the user",
						},
						"user_name": schema.StringAttribute{
							Computed:    true,
							Description: "The GitHub username of the user",
						},
						"email_suffix": schema.StringAttribute{
							Computed:    true,
							Description: "The email suffix of the user",
						},
						"auth_type": schema.StringAttribute{
							Computed:    true,
							Description: "The authentication type of the user.",
						},
						"added_at": schema.Int64Attribute{
							Computed:    true,
							Description: "The timestamp when the user was added.",
						},
						"updated_at": schema.Int64Attribute{
							Computed:    true,
							Description: "The timestamp when the user was updated.",
						},
						"updated_by": schema.StringAttribute{
							Computed:    true,
							Description: "The user who updated the user.",
						},
						"policies": schema.ListNestedAttribute{
							Computed: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Computed:    true,
										Description: "The CI/CD platform type",
									},
									"role": schema.StringAttribute{
										Computed:    true,
										Description: "The role of the user",
									},
									"scope": schema.StringAttribute{
										Computed:    true,
										Description: "The scope of the policy.",
									},
									"organization": schema.StringAttribute{
										Computed:    true,
										Description: "The organization name",
									},
									"repos": schema.ListAttribute{
										ElementType: types.StringType,
										Description: "The list of repositories",
										Computed:    true,
									},
									"group": schema.StringAttribute{
										Computed:    true,
										Description: "The group name. Valid only for gitlab type policy",
									},
									"projects": schema.ListAttribute{
										ElementType: types.StringType,
										Computed:    true,
										Description: "The list of projects. Valid only for gitlab type policy",
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

type usersDataSourceModel struct {
	Users []UserModel `tfsdk:"users"`
}

type UserModel struct {
	ID          types.String      `tfsdk:"id"`
	Email       types.String      `tfsdk:"email"`
	UserName    types.String      `tfsdk:"user_name"`
	EmailSuffix types.String      `tfsdk:"email_suffix"`
	AuthType    types.String      `tfsdk:"auth_type"`
	AddedAt     types.Int64       `tfsdk:"added_at"`
	UpdatedAt   types.Int64       `tfsdk:"updated_at"`
	UpdatedBy   types.String      `tfsdk:"updated_by"`
	Policies    []UserPolicyModel `tfsdk:"policies"`
}

type UserPolicyModel struct {
	Type         types.String `tfsdk:"type"`
	Role         types.String `tfsdk:"role"`
	Scope        types.String `tfsdk:"scope"`
	Organization types.String `tfsdk:"organization"`
	Repos        types.List   `tfsdk:"repos"`
	// NOTE that this points to server field in api...as there was change in internal implementation
	// Tf schema still points to 'Group' field to ensure backward compatibility. In future, this field will be deprecated and will be replaces with 'server'.
	Group    types.String `tfsdk:"group"`
	Projects types.List   `tfsdk:"projects"`
}

// Read refreshes the Terraform state with the latest data.
func (d *usersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {

	var state usersDataSourceModel

	users, err := d.client.ListUsers(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read StepSecurity Users",
			err.Error(),
		)
		return
	}

	// Map response body to model
	for _, user := range users {
		userState := UserModel{
			ID:          types.StringValue(user.ID),
			Email:       types.StringValue(user.Email),
			UserName:    types.StringValue(user.UserName),
			EmailSuffix: types.StringValue(user.EmailSuffix),
			AuthType:    types.StringValue(user.AuthType),
			AddedAt:     types.Int64Value(int64(user.AddedAt)),
			UpdatedAt:   types.Int64Value(int64(user.UpdatedAt)),
			UpdatedBy:   types.StringValue(user.UpdatedBy),
			Policies:    []UserPolicyModel{},
		}

		for _, policy := range user.Policies {
			// Create types.List for repos
			repoElements := make([]attr.Value, len(policy.Repos))
			for i, repo := range policy.Repos {
				repoElements[i] = types.StringValue(repo)
			}
			reposList, diags := types.ListValue(types.StringType, repoElements)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}

			// Create types.List for projects
			projectElements := make([]attr.Value, len(policy.Projects))
			for i, project := range policy.Projects {
				projectElements[i] = types.StringValue(project)
			}
			projectsList, diags := types.ListValue(types.StringType, projectElements)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}

			userState.Policies = append(userState.Policies, UserPolicyModel{
				Type:         types.StringValue(policy.Type),
				Role:         types.StringValue(policy.Role),
				Scope:        types.StringValue(policy.Scope),
				Organization: types.StringValue(policy.Organization),
				Repos:        reposList,
				Group:        types.StringValue(policy.Server), // map to 'server' field in api
				Projects:     projectsList,
			})
		}

		state.Users = append(state.Users, userState)
	}

	// Set state
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
