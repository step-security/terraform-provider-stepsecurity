package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// developerMDMComplianceAttrTypes is the shared compliance object schema used by both
// the device and profile compliance data sources.
var developerMDMComplianceAttrTypes = map[string]attr.Type{
	"device_id":     types.StringType,
	"category":      types.StringType,
	"target":        types.StringType,
	"profile_id":    types.StringType,
	"state":         types.StringType,
	"desired_hash":  types.StringType,
	"applied_hash":  types.StringType,
	"last_seen_at":  types.Int64Type,
	"agent_version": types.StringType,
	"platform":      types.StringType,
	"evaluated_at":  types.StringType,
}

// developerMDMComplianceRowModel maps a single compliance object for tfsdk decoding.
type developerMDMComplianceRowModel struct {
	DeviceID     types.String `tfsdk:"device_id"`
	Category     types.String `tfsdk:"category"`
	Target       types.String `tfsdk:"target"`
	ProfileID    types.String `tfsdk:"profile_id"`
	State        types.String `tfsdk:"state"`
	DesiredHash  types.String `tfsdk:"desired_hash"`
	AppliedHash  types.String `tfsdk:"applied_hash"`
	LastSeenAt   types.Int64  `tfsdk:"last_seen_at"`
	AgentVersion types.String `tfsdk:"agent_version"`
	Platform     types.String `tfsdk:"platform"`
	EvaluatedAt  types.String `tfsdk:"evaluated_at"`
}

// developerMDMComplianceSchemaAttributes returns the computed compliance list attribute,
// shared so both compliance data sources expose an identical object shape.
func developerMDMComplianceSchemaAttribute(description string) schema.ListNestedAttribute {
	return schema.ListNestedAttribute{
		Computed:            true,
		MarkdownDescription: description,
		NestedObject: schema.NestedAttributeObject{
			Attributes: map[string]schema.Attribute{
				"device_id":     schema.StringAttribute{Computed: true, MarkdownDescription: "Device identifier."},
				"category":      schema.StringAttribute{Computed: true, MarkdownDescription: "Policy category, e.g. `ide_extension`."},
				"target":        schema.StringAttribute{Computed: true, MarkdownDescription: "Policy target, e.g. `vscode`."},
				"profile_id":    schema.StringAttribute{Computed: true, MarkdownDescription: "Profile that governs this row, if any."},
				"state":         schema.StringAttribute{Computed: true, MarkdownDescription: "Compliance state such as `compliant`, `pending`, `drift_detected`, or `mdm_managed`."},
				"desired_hash":  schema.StringAttribute{Computed: true, MarkdownDescription: "Backend desired policy hash."},
				"applied_hash":  schema.StringAttribute{Computed: true, MarkdownDescription: "Agent-applied policy hash."},
				"last_seen_at":  schema.Int64Attribute{Computed: true, MarkdownDescription: "Unix timestamp the device was last seen."},
				"agent_version": schema.StringAttribute{Computed: true, MarkdownDescription: "Reporting agent version."},
				"platform":      schema.StringAttribute{Computed: true, MarkdownDescription: "Device platform, e.g. `darwin`."},
				"evaluated_at":  schema.StringAttribute{Computed: true, MarkdownDescription: "When the row was evaluated."},
			},
		},
	}
}

// developerMDMComplianceListValue converts API compliance rows into a Terraform list value.
func developerMDMComplianceListValue(rows []stepsecurityapi.DeveloperMDMComplianceView) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	objType := types.ObjectType{AttrTypes: developerMDMComplianceAttrTypes}

	elems := make([]attr.Value, 0, len(rows))
	for _, row := range rows {
		obj, objDiags := types.ObjectValue(developerMDMComplianceAttrTypes, map[string]attr.Value{
			"device_id":     types.StringValue(row.DeviceID),
			"category":      types.StringValue(row.Category),
			"target":        types.StringValue(row.Target),
			"profile_id":    types.StringValue(row.ProfileID),
			"state":         types.StringValue(row.State),
			"desired_hash":  types.StringValue(row.DesiredHash),
			"applied_hash":  types.StringValue(row.AppliedHash),
			"last_seen_at":  types.Int64Value(row.LastSeenAt),
			"agent_version": types.StringValue(row.AgentVersion),
			"platform":      types.StringValue(row.Platform),
			"evaluated_at":  types.StringValue(row.EvaluatedAt),
		})
		diags.Append(objDiags...)
		elems = append(elems, obj)
	}

	listValue, listDiags := types.ListValue(objType, elems)
	diags.Append(listDiags...)
	return listValue, diags
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &developerMDMDeviceComplianceDataSource{}
	_ datasource.DataSourceWithConfigure = &developerMDMDeviceComplianceDataSource{}
)

// NewDeveloperMDMDeviceComplianceDataSource is a helper function to simplify the provider implementation.
func NewDeveloperMDMDeviceComplianceDataSource() datasource.DataSource {
	return &developerMDMDeviceComplianceDataSource{}
}

// developerMDMDeviceComplianceDataSource is the data source implementation.
type developerMDMDeviceComplianceDataSource struct {
	client stepsecurityapi.Client
}

// developerMDMDeviceComplianceDataSourceModel maps the data source schema data.
type developerMDMDeviceComplianceDataSourceModel struct {
	DeviceID   types.String `tfsdk:"device_id"`
	Compliance types.List   `tfsdk:"compliance"`
}

// Metadata returns the data source type name.
func (d *developerMDMDeviceComplianceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_developer_mdm_device_compliance"
}

// Schema defines the schema for the data source.
func (d *developerMDMDeviceComplianceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads runtime Developer MDM compliance for a single device. This is read-only observability " +
			"and must not be used as desired state. Compliance states change outside Terraform and do not drive drift.",
		Attributes: map[string]schema.Attribute{
			"device_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Device identifier to read compliance for.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"compliance": developerMDMComplianceSchemaAttribute("Compliance rows reported for this device."),
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *developerMDMDeviceComplianceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// Read fetches device compliance rows and writes them to state.
func (d *developerMDMDeviceComplianceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config developerMDMDeviceComplianceDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := d.client.GetDeveloperMDMDeviceCompliance(ctx, config.DeviceID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading Developer MDM device compliance",
			"Could not read compliance for device "+config.DeviceID.ValueString()+": "+err.Error(),
		)
		return
	}

	listValue, diags := developerMDMComplianceListValue(response.Compliance)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	config.Compliance = listValue

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
