package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &githubSupressionRuleResource{}
	_ resource.ResourceWithConfigure      = &githubSupressionRuleResource{}
	_ resource.ResourceWithValidateConfig = &githubSupressionRuleResource{}
	_ resource.ResourceWithImportState    = &githubSupressionRuleResource{}
)

// NewGithubSupressionRuleResource is a helper function to simplify the provider implementation.
func NewGithubSupressionRuleResource() resource.Resource {
	return &githubSupressionRuleResource{}
}

// githubSupressionRuleResource is the resource implementation.
type githubSupressionRuleResource struct {
	client stepsecurityapi.Client
}

// Metadata returns the resource type name.
func (r *githubSupressionRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_supression_rule"
}

func (r *githubSupressionRuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *githubSupressionRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"rule_id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the rule.",
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "The type of the rule. Can be one of 'source_code_overwritten' or 'anomalous_outbound_network_call'",
				Validators: []validator.String{
					stringvalidator.OneOf("source_code_overwritten", "anomalous_outbound_network_call"),
				},
			},
			"action": schema.StringAttribute{
				Required:    true,
				Description: "The action to take when the rule is triggered. Can only be 'ignore' as of now.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "The description of the rule.",
			},
			"destination": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "The outbound network destination to ignore when the type is 'anomalous_outbound_network_call'. Can set either ip or domain not both. Use asterisks for wildcard matching. e.g. *.amazonaws.com:443 or 192.168.*.1:443",
				Attributes: map[string]schema.Attribute{
					"ip": schema.StringAttribute{
						Optional:    true,
						Description: "The IP address to ignore. Can only be set when domain is not set.",
					},
					"domain": schema.StringAttribute{
						Optional:    true,
						Description: "The domain to ignore. Can only be set when ip is not set.",
					},
				},
			},
			"process": schema.StringAttribute{
				Optional:    true,
				Description: "The process name to ignore when the type is 'anomalous_outbound_network_call'. Can Specify the exact process name or use wildcards for process, e.g. *twingate,*,*.exe",
			},
			"file": schema.StringAttribute{
				Optional:    true,
				Description: "The file name to ignore when the type is 'source_code_overwritten'",
			},
			"file_path": schema.StringAttribute{
				Optional:    true,
				Description: "The file path to ignore when the type is 'source_code_overwritten'.",
			},
			"owner": schema.StringAttribute{
				Required:    true,
				Description: "GitHub organization name on which the rule will be applied. Can be set to '*' to apply to all organizations in the tenant.",
			},
			"repo": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "GitHub repository name on which the rule will be applied.",
				Default:     stringdefault.StaticString("*"),
			},
			"workflow": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "GitHub workflow name on which the rule will be applied.",
				Default:     stringdefault.StaticString("*"),
			},
			"job": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "GitHub job name on which the rule will be applied.",
				Default:     stringdefault.StaticString("*"),
			},
		},
	}
}

func (r *githubSupressionRuleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var rule supressionRuleModel
	diags := req.Config.Get(ctx, &rule)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	switch rule.Type.ValueString() {
	case "source_code_overwritten":
		if rule.File.IsNull() || rule.File.IsUnknown() || rule.FilePath.IsNull() || rule.FilePath.IsUnknown() {
			resp.Diagnostics.AddError(
				"File is required",
				"File is required when type is source_code_overwritten",
			)
		}
		if !rule.Process.IsNull() {
			resp.Diagnostics.AddError(
				"Process is not allowed",
				"Process is not allowed when type is source_code_overwritten",
			)
		}
		if !rule.Destination.IsNull() {
			resp.Diagnostics.AddError(
				"Destination is not allowed",
				"Destination is not allowed when type is source_code_overwritten",
			)
		}
	case "anomalous_outbound_network_call":
		if !rule.File.IsNull() || !rule.FilePath.IsNull() {
			resp.Diagnostics.AddError(
				"File, File Path parameters are not allowed",
				"File, File Path parameters are not allowed when type is anomalous_outbound_network_call",
			)
		}
		if rule.Process.IsNull() || rule.Process.IsUnknown() {
			resp.Diagnostics.AddError(
				"Process is required",
				"Process is required when type is anomalous_outbound_network_call",
			)
		}
		if rule.Destination.IsNull() || rule.Destination.IsUnknown() {
			resp.Diagnostics.AddError(
				"Destination is required",
				"Destination is required when type is anomalous_outbound_network_call",
			)
		}
		var destination destinationModel
		diags := rule.Destination.As(ctx, &destination, basetypes.ObjectAsOptions{})
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		isIpEmpty := destination.IP.IsNull() || destination.IP.IsUnknown()
		isDomainEmpty := destination.Domain.IsNull() || destination.Domain.IsUnknown()
		if isIpEmpty && isDomainEmpty {
			resp.Diagnostics.AddError(
				"Destination is required",
				"Destination is required when type is anomalous_outbound_network_call. please provide either ip or domain.",
			)
		} else if !isIpEmpty && !isDomainEmpty {
			resp.Diagnostics.AddError(
				"Cannot provide both ip and domain in destination",
				"Destination can only have either ip or domain",
			)
		}
	}
}

func (r *githubSupressionRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("rule_id"), req, resp)
}

type supressionRuleModel struct {
	RuleID       types.String `tfsdk:"rule_id"`
	Name         types.String `tfsdk:"name"`
	Action       types.String `tfsdk:"action"`
	Type         types.String `tfsdk:"type"`
	Description  types.String `tfsdk:"description"`
	Destination  types.Object `tfsdk:"destination"`
	Process      types.String `tfsdk:"process"`
	File         types.String `tfsdk:"file"`
	FilePath     types.String `tfsdk:"file_path"`
	Owner        types.String `tfsdk:"owner"`
	Repo         types.String `tfsdk:"repo"`
	Workflow     types.String `tfsdk:"workflow"`
	Job          types.String `tfsdk:"job"`
	SecretType   types.String `tfsdk:"secret_type"`
	ArtifactName types.String `tfsdk:"artifact_name"`
	Endpoint     types.String `tfsdk:"endpoint"`
	Host         types.String `tfsdk:"host"`
}

type destinationModel struct {
	IP     types.String `tfsdk:"ip"`
	Domain types.String `tfsdk:"domain"`
}

// Create creates the resource and sets the initial Terraform state.
func (r *githubSupressionRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var config supressionRuleModel
	diags := req.Plan.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	suppressionRule := r.getSuppressionRuleFromTfModel(ctx, config)
	if suppressionRule == nil {
		resp.Diagnostics.AddError(
			"Failed to create suppression rule",
			"Failed to create suppression rule",
		)
		return
	}

	createdRule, err := r.client.CreateSuppressionRule(ctx, *suppressionRule)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to create suppression rule",
			err.Error(),
		)
		return
	}

	// populate data to store state
	r.updateSuppressionRuleState(ctx, createdRule, &config)

	// Set state to fully populated data
	diags = resp.State.Set(ctx, config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Read refreshes the Terraform state with the latest data.
func (r *githubSupressionRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state supressionRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	readRule, err := r.client.ReadSuppressionRule(ctx, state.RuleID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read suppression rule",
			err.Error(),
		)
		return
	}

	// populate data to store state
	r.updateSuppressionRuleState(ctx, readRule, &state)

	// Set state to fully populated data
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *githubSupressionRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan supressionRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	suppressionRule := r.getSuppressionRuleFromTfModel(ctx, plan)
	if suppressionRule == nil {
		resp.Diagnostics.AddError(
			"Failed to create suppression rule",
			"Failed to create suppression rule",
		)
		return
	}

	err := r.client.UpdateSuppressionRule(ctx, *suppressionRule)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to update suppression rule",
			err.Error(),
		)
		return
	}

	// get updated rule
	updatedRule, err := r.client.ReadSuppressionRule(ctx, plan.RuleID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read suppression rule",
			err.Error(),
		)
		return
	}

	// populate data to store state
	r.updateSuppressionRuleState(ctx, updatedRule, &plan)

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *githubSupressionRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state supressionRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteSuppressionRule(ctx, state.RuleID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to delete suppression rule",
			err.Error(),
		)
		return
	}
}

func (r *githubSupressionRuleResource) getSuppressionRuleFromTfModel(ctx context.Context, config supressionRuleModel) *stepsecurityapi.SuppressionRule {

	conditions := map[string]string{
		"owner":    config.Owner.ValueString(),
		"repo":     config.Repo.ValueString(),
		"workflow": config.Workflow.ValueString(),
		"job":      config.Job.ValueString(),
	}
	id := ""
	switch config.Type.ValueString() {
	case "source_code_overwritten":
		id = stepsecurityapi.SourceCodeOverwritten
		conditions["file"] = config.File.ValueString()
		conditions["file_path"] = config.FilePath.ValueString()

	case "anomalous_outbound_network_call":
		id = stepsecurityapi.AnomalousOutboundNetworkCall
		conditions["process"] = config.Process.ValueString()
		var destination destinationModel
		diags := config.Destination.As(ctx, &destination, basetypes.ObjectAsOptions{})
		if diags.HasError() {
			return nil
		}

		if !destination.IP.IsNull() && destination.IP.ValueString() != "" {
			conditions["ip_address"] = destination.IP.ValueString()
		}
		if !destination.Domain.IsNull() && destination.Domain.ValueString() != "" {
			conditions["endpoint"] = destination.Domain.ValueString()
		}

	case "secret-in-build-log":
		id = stepsecurityapi.SecretInBuildLog
		conditions["secret_type"] = config.SecretType.ValueString()

	case "secret-in-artifact":
		id = stepsecurityapi.SecretInArtifact
		conditions["secret_type"] = config.SecretType.ValueString()
		conditions["file"] = config.ArtifactName.ValueString()

	case "suspicious-network-call":
		id = stepsecurityapi.SuspiciousNetworkCall
		conditions["endpoint"] = config.Endpoint.ValueString()

	case "https-outbound-network-call":
		id = stepsecurityapi.HttpsOutboundNetworkCall
		conditions["host"] = config.Host.ValueString()
		conditions["file_path"] = config.FilePath.ValueString()

	case "action-uses-imposter-commit":
		id = stepsecurityapi.ActionUsesImpostedCommit
		conditions["action"] = config.Action.ValueString()

	case "runner-worker-memory-read":
		id = stepsecurityapi.RunnerWorkerMemoryRead
		conditions["current_exe"] = config.Process.ValueString()

	case "privileged-container":
		id = stepsecurityapi.DetectionPrivilegedContainer
		conditions["current_exe"] = config.Process.ValueString()

	case "reverse-shell":
		id = stepsecurityapi.DetectionReverseShell
		conditions["current_exe"] = config.Process.ValueString()

	}

	return &stepsecurityapi.SuppressionRule{
		RuleID:      config.RuleID.ValueString(),
		ID:          id,
		Name:        config.Name.ValueString(),
		Description: config.Description.ValueString(),
		SeverityAction: stepsecurityapi.SeverityAction{
			Type: config.Action.ValueString(),
		},
		Conditions: conditions,
	}

}

func (r *githubSupressionRuleResource) updateSuppressionRuleState(ctx context.Context, rule *stepsecurityapi.SuppressionRule, config *supressionRuleModel) {
	config.RuleID = types.StringValue(rule.RuleID)
	config.Name = types.StringValue(rule.Name)
	config.Description = types.StringValue(rule.Description)
	config.Action = types.StringValue(rule.SeverityAction.Type)

	switch rule.ID {
	case stepsecurityapi.SourceCodeOverwritten:
		config.Type = types.StringValue("source_code_overwritten")
	case stepsecurityapi.AnomalousOutboundNetworkCall:
		config.Type = types.StringValue("anomalous_outbound_network_call")
	case stepsecurityapi.HttpsOutboundNetworkCall:
		config.Type = types.StringValue("https_outbound_network_call")
	case stepsecurityapi.SecretInBuildLog:
		config.Type = types.StringValue("secret_in_build_log")
	case stepsecurityapi.SecretInArtifact:
		config.Type = types.StringValue("secret_in_artifact")
	case stepsecurityapi.ActionUsesImpostedCommit:
		config.Type = types.StringValue("action_uses_imposter_commit")
	case stepsecurityapi.DetectionPrivilegedContainer:
		config.Type = types.StringValue("privileged_container")
	case stepsecurityapi.DetectionReverseShell:
		config.Type = types.StringValue("reverse_shell")
	case stepsecurityapi.SuspiciousNetworkCall:
		config.Type = types.StringValue("suspicious_network_call")
	case stepsecurityapi.RunnerWorkerMemoryRead:
		config.Type = types.StringValue("runner_worker_memory_read")
	}

	for key, value := range rule.Conditions {
		switch key {
		case "owner":
			config.Owner = types.StringValue(value)
		case "repo":
			config.Repo = types.StringValue(value)
		case "workflow":
			config.Workflow = types.StringValue(value)
		case "job":
			config.Job = types.StringValue(value)
		case "file":
			config.File = types.StringValue(value)
		case "file_path":
			config.FilePath = types.StringValue(value)
		case "process":
			config.Process = types.StringValue(value)
		case "secret_type":
			config.SecretType = types.StringValue(value)
		case "artifact_name":
			config.ArtifactName = types.StringValue(value)
		case "host":
			config.Host = types.StringValue(value)
		case "ip_address":
			destination, _ := types.ObjectValue(
				map[string]attr.Type{
					"ip":     types.StringType,
					"domain": types.StringType,
				},
				map[string]attr.Value{
					"ip":     types.StringValue(value),
					"domain": types.StringNull(),
				},
			)
			config.Destination = destination

		case "endpoint":
			destination, _ := types.ObjectValue(
				map[string]attr.Type{
					"ip":     types.StringType,
					"domain": types.StringType,
				},
				map[string]attr.Value{
					"domain": types.StringValue(value),
					"ip":     types.StringNull(),
				},
			)
			config.Destination = destination

		}
	}
}
