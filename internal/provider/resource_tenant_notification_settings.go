package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

var (
	_ resource.Resource                   = &tenantNotificationSettingsResource{}
	_ resource.ResourceWithConfigure      = &tenantNotificationSettingsResource{}
	_ resource.ResourceWithImportState    = &tenantNotificationSettingsResource{}
	_ resource.ResourceWithValidateConfig = &tenantNotificationSettingsResource{}
)

// tenantNotificationChannelsAttrTypes defines the types for the
// notification_channels nested object.
var tenantNotificationChannelsAttrTypes = map[string]attr.Type{
	"email":                     types.StringType,
	"slack_webhook_url":         types.StringType,
	"teams_webhook_url":         types.StringType,
	"slack_notification_method": types.StringType,
	"slack_channel_id":          types.StringType,
}

// tenantThreatIntelAttrTypes defines the types for the threat_intel nested object.
var tenantThreatIntelAttrTypes = map[string]attr.Type{
	"enabled": types.BoolType,
	"level":   types.StringType,
}

// tenantDeveloperMDMEvent is one Dev Machine Guard event type: its Terraform
// attribute name, its documentation, and how to read and write it on the API
// options struct.
//
// A table rather than a hand-written block per event, so the schema, the request
// builder and the read path cannot drift apart as event types are added — adding
// one is a single entry here.
type tenantDeveloperMDMEvent struct {
	name        string
	description string
	get         func(stepsecurityapi.DeveloperMDMNotificationOptions) bool
	set         func(*stepsecurityapi.DeveloperMDMNotificationOptions, bool)
}

var tenantDeveloperMDMEvents = []tenantDeveloperMDMEvent{
	{
		name:        "new_ides",
		description: "Notify when Dev Machine Guard discovers a new IDE on the device fleet.",
		get:         func(o stepsecurityapi.DeveloperMDMNotificationOptions) bool { return o.NewIDEs.Enabled },
		set: func(o *stepsecurityapi.DeveloperMDMNotificationOptions, v bool) {
			o.NewIDEs.Enabled = v
		},
	},
	{
		name:        "new_ide_extensions",
		description: "Notify when Dev Machine Guard discovers a new IDE extension on the device fleet.",
		get:         func(o stepsecurityapi.DeveloperMDMNotificationOptions) bool { return o.NewIDEExtensions.Enabled },
		set: func(o *stepsecurityapi.DeveloperMDMNotificationOptions, v bool) {
			o.NewIDEExtensions.Enabled = v
		},
	},
	{
		name:        "new_ai_agents",
		description: "Notify when Dev Machine Guard discovers a new AI agent on the device fleet.",
		get:         func(o stepsecurityapi.DeveloperMDMNotificationOptions) bool { return o.NewAIAgents.Enabled },
		set: func(o *stepsecurityapi.DeveloperMDMNotificationOptions, v bool) {
			o.NewAIAgents.Enabled = v
		},
	},
	{
		name:        "new_mcp_servers",
		description: "Notify when Dev Machine Guard discovers a new MCP server on the device fleet.",
		get:         func(o stepsecurityapi.DeveloperMDMNotificationOptions) bool { return o.NewMCPServers.Enabled },
		set: func(o *stepsecurityapi.DeveloperMDMNotificationOptions, v bool) {
			o.NewMCPServers.Enabled = v
		},
	},
	{
		name:        "new_agent_skills",
		description: "Notify when Dev Machine Guard discovers a new agent skill on the device fleet.",
		get:         func(o stepsecurityapi.DeveloperMDMNotificationOptions) bool { return o.NewAgentSkills.Enabled },
		set: func(o *stepsecurityapi.DeveloperMDMNotificationOptions, v bool) {
			o.NewAgentSkills.Enabled = v
		},
	},
	{
		name:        "suspicious_files",
		description: "Notify when Dev Machine Guard detects a suspicious file on the device fleet.",
		get:         func(o stepsecurityapi.DeveloperMDMNotificationOptions) bool { return o.SuspiciousFiles.Enabled },
		set: func(o *stepsecurityapi.DeveloperMDMNotificationOptions, v bool) {
			o.SuspiciousFiles.Enabled = v
		},
	},
	{
		name:        "config_changes",
		description: "Notify when Dev Machine Guard detects a package manager configuration change on the device fleet.",
		get:         func(o stepsecurityapi.DeveloperMDMNotificationOptions) bool { return o.ConfigChanges.Enabled },
		set: func(o *stepsecurityapi.DeveloperMDMNotificationOptions, v bool) {
			o.ConfigChanges.Enabled = v
		},
	},
}

// tenantDeveloperMDMAttrTypes defines the types for the developer_mdm nested
// object, one bool per event in tenantDeveloperMDMEvents.
var tenantDeveloperMDMAttrTypes = func() map[string]attr.Type {
	attrTypes := make(map[string]attr.Type, len(tenantDeveloperMDMEvents))
	for _, event := range tenantDeveloperMDMEvents {
		attrTypes[event.name] = types.BoolType
	}
	return attrTypes
}()

func NewTenantNotificationSettingsResource() resource.Resource {
	return &tenantNotificationSettingsResource{}
}

type tenantNotificationSettingsResource struct {
	client stepsecurityapi.Client
}

type tenantNotificationSettingsModel struct {
	NotificationChannels types.Object `tfsdk:"notification_channels"`
	ThreatIntel          types.Object `tfsdk:"threat_intel"`
	DeveloperMDM         types.Object `tfsdk:"developer_mdm"`
}

type tenantNotificationChannelsModel struct {
	Email                   types.String `tfsdk:"email"`
	SlackWebhookURL         types.String `tfsdk:"slack_webhook_url"`
	TeamsWebhookURL         types.String `tfsdk:"teams_webhook_url"`
	SlackNotificationMethod types.String `tfsdk:"slack_notification_method"`
	SlackChannelID          types.String `tfsdk:"slack_channel_id"`
}

type tenantThreatIntelModel struct {
	Enabled types.Bool   `tfsdk:"enabled"`
	Level   types.String `tfsdk:"level"`
}

func (r *tenantNotificationSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant_notification_settings"
}

func (r *tenantNotificationSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	developerMDMAttributes := make(map[string]schema.Attribute, len(tenantDeveloperMDMEvents))
	for _, event := range tenantDeveloperMDMEvents {
		developerMDMAttributes[event.name] = schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			Default:             booldefault.StaticBool(false),
			MarkdownDescription: event.description,
		}
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the tenant-wide notification settings in StepSecurity: the shared delivery channels " +
			"(email, Slack, Microsoft Teams) plus the tenant's Threat Intel and Dev Machine Guard event subscriptions. " +
			"The tenant is the one configured on the provider.\n\n" +
			"There is exactly one of these records per tenant, so declare at most one instance of this resource.\n\n" +
			"~> **The delivery channels are shared with the Azure DevOps and GitLab notification settings.** " +
			"StepSecurity stores one set of channels per tenant and overwrites them on every write, whichever product " +
			"triggered it. This resource therefore owns them: applying it replaces the channels the Azure DevOps and " +
			"GitLab notification pages use, and saving either of those pages in the StepSecurity console shows up as " +
			"drift here. The event subscriptions are not shared — this resource never touches the Azure DevOps or " +
			"GitLab ones.",
		Attributes: map[string]schema.Attribute{
			"notification_channels": schema.SingleNestedAttribute{
				Required: true,
				MarkdownDescription: "Where the tenant's notifications are delivered. Every channel is optional, but " +
					"with none configured no notification is delivered, whatever is subscribed below.",
				Attributes: map[string]schema.Attribute{
					"email": schema.StringAttribute{
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString(""),
						MarkdownDescription: "Email address to deliver notifications to. Set to `\"\"` or omit to disable email delivery.",
					},
					"slack_webhook_url": schema.StringAttribute{
						Optional: true,
						Computed: true,
						Default:  stringdefault.StaticString(""),
						MarkdownDescription: "Slack incoming webhook URL to deliver notifications to, used when " +
							"`slack_notification_method` is `webhook`. Set to `\"\"` or omit to disable Slack webhook delivery.",
					},
					"teams_webhook_url": schema.StringAttribute{
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString(""),
						MarkdownDescription: "Microsoft Teams incoming webhook URL to deliver notifications to. Set to `\"\"` or omit to disable Teams delivery.",
					},
					"slack_notification_method": schema.StringAttribute{
						Optional: true,
						Computed: true,
						MarkdownDescription: "How Slack notifications are delivered: `webhook` uses `slack_webhook_url`, " +
							"`oauth` posts to `slack_channel_id` using the Slack app installed for the tenant. " +
							"Omit to leave the tenant's current method unchanged. The StepSecurity API cannot clear " +
							"this field, so it cannot be set to `\"\"`.",
						Validators: []validator.String{
							stringvalidator.OneOf("webhook", "oauth"),
						},
					},
					"slack_channel_id": schema.StringAttribute{
						Optional: true,
						Computed: true,
						MarkdownDescription: "Slack channel ID to post to when `slack_notification_method` is `oauth`. " +
							"Omit to leave the tenant's current channel unchanged. The StepSecurity API cannot clear " +
							"this field, so it cannot be set to `\"\"`.",
					},
				},
			},
			"threat_intel": schema.SingleNestedAttribute{
				Required: true,
				MarkdownDescription: "The tenant's Threat Intel notification subscription: a single on/off plus the " +
					"granularity of what warrants a notification. This covers tenant-scoped assets, such as " +
					"compromised components on the device fleet. Compromised components found in a GitHub " +
					"organization's pull requests and workflows notify per organization, configured on " +
					"`stepsecurity_github_org_notification_settings`.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:            true,
						MarkdownDescription: "Whether the tenant receives Threat Intel notifications at all.",
					},
					"level": schema.StringAttribute{
						Optional: true,
						Computed: true,
						Default:  stringdefault.StaticString(stepsecurityapi.ThreatIntelLevelVersion),
						MarkdownDescription: "Which incidents warrant a notification, ignored when `enabled` is `false`: " +
							"`all` for every Threat Intel incident whether or not this tenant is affected, " +
							"`name` only when this tenant is affected by a compromised package matched by name at any version, " +
							"`version` only when this tenant has the exact compromised version installed. Defaults to `version`.",
						Validators: []validator.String{
							stringvalidator.OneOf(
								stepsecurityapi.ThreatIntelLevelAll,
								stepsecurityapi.ThreatIntelLevelName,
								stepsecurityapi.ThreatIntelLevelVersion,
							),
						},
					},
				},
			},
			"developer_mdm": schema.SingleNestedAttribute{
				Required: true,
				MarkdownDescription: "The tenant's Dev Machine Guard notification subscription. The events are " +
					"independent of each other and each defaults to disabled.",
				Attributes: developerMDMAttributes,
			},
		},
	}
}

func (r *tenantNotificationSettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// ValidateConfig rejects the two configurations the StepSecurity API silently
// ignores, and warns about the one it silently accepts to no effect.
func (r *tenantNotificationSettingsResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config tenantNotificationSettingsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.NotificationChannels.IsNull() || config.NotificationChannels.IsUnknown() {
		return
	}

	var channels tenantNotificationChannelsModel
	resp.Diagnostics.Append(config.NotificationChannels.As(ctx, &channels, basetypes.ObjectAsOptions{})...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The API only assigns these when non-empty, so an explicit "" is a write
	// that does nothing — which Terraform would surface as drift that no apply
	// can ever settle. Rejecting it up front is clearer than that loop.
	for name, value := range map[string]types.String{
		"slack_notification_method": channels.SlackNotificationMethod,
		"slack_channel_id":          channels.SlackChannelID,
	} {
		if !value.IsUnknown() && !value.IsNull() && value.ValueString() == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("notification_channels").AtName(name),
				fmt.Sprintf("Cannot clear %s", name),
				fmt.Sprintf("The StepSecurity API ignores an empty %s, so setting it to \"\" would never take effect. "+
					"Omit the attribute to leave the tenant's current value unchanged.", name),
			)
		}
	}

	if anyEventEnabled(ctx, config, &resp.Diagnostics) && !anyChannelConfigured(channels) {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("notification_channels"),
			"Subscribed to notifications with no delivery channel",
			"Events are subscribed but no email address, Slack destination or Microsoft Teams webhook is "+
				"configured, so no notification will be delivered.",
		)
	}
}

func (r *tenantNotificationSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan tenantNotificationSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.write(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *tenantNotificationSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	settings, err := r.client.GetTenantNotificationSettings(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Read Tenant Notification Settings", err.Error())
		return
	}

	// The API stores no threat intel level once the tenant is unsubscribed, so an
	// unsubscribed tenant's level is carried over from prior state rather than
	// invented — otherwise `enabled = false, level = "all"` would drift forever.
	// On import there is no prior state, so the schema default stands in.
	priorLevel := stepsecurityapi.ThreatIntelLevelVersion
	if !req.State.Raw.IsNull() {
		var state tenantNotificationSettingsModel
		if diags := req.State.Get(ctx, &state); !diags.HasError() && !state.ThreatIntel.IsNull() {
			var threatIntel tenantThreatIntelModel
			if diags := state.ThreatIntel.As(ctx, &threatIntel, basetypes.ObjectAsOptions{}); !diags.HasError() {
				if level := threatIntel.Level.ValueString(); level != "" {
					priorLevel = level
				}
			}
		}
	}

	model := modelFromAPI(settings, priorLevel, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *tenantNotificationSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tenantNotificationSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.write(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete unsubscribes the tenant from every event and clears the shared
// channels. See DeleteTenantNotificationSettings for why the channels cannot be
// preserved.
func (r *tenantNotificationSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.DeleteTenantNotificationSettings(ctx); err != nil {
		resp.Diagnostics.AddError("Unable to Delete Tenant Notification Settings", err.Error())
	}
}

// ImportState imports the single notification record of the tenant configured on
// the provider. The import ID identifies nothing — there is only one record per
// tenant and the tenant comes from the provider — so it is ignored.
func (r *tenantNotificationSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	readResp := &resource.ReadResponse{State: resp.State}
	r.Read(ctx, resource.ReadRequest{State: resp.State}, readResp)
	resp.Diagnostics.Append(readResp.Diagnostics...)
	resp.State = readResp.State
}

// write pushes plan to the API and then resolves the attributes the API owns.
//
// slack_notification_method and slack_channel_id are optional-and-computed with
// no default: omitting them means "leave the tenant's current value alone", so
// their planned value is unknown on create and only the API can say what they
// ended up as. Reading the record back is the only way to fill those in.
func (r *tenantNotificationSettingsResource) write(ctx context.Context, plan *tenantNotificationSettingsModel, diags *diag.Diagnostics) {
	request := requestFromModel(ctx, plan, diags)
	if diags.HasError() {
		return
	}

	if err := r.client.UpdateTenantNotificationSettings(ctx, request); err != nil {
		diags.AddError("Unable to Update Tenant Notification Settings", err.Error())
		return
	}

	settings, err := r.client.GetTenantNotificationSettings(ctx)
	if err != nil {
		diags.AddError("Unable to Read Back Tenant Notification Settings", err.Error())
		return
	}

	var channels tenantNotificationChannelsModel
	diags.Append(plan.NotificationChannels.As(ctx, &channels, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return
	}
	channels.SlackNotificationMethod = types.StringValue(settings.SlackNotificationMethod)
	channels.SlackChannelID = types.StringValue(settings.SlackChannelID)

	channelsObj, channelDiags := types.ObjectValueFrom(ctx, tenantNotificationChannelsAttrTypes, channels)
	diags.Append(channelDiags...)
	if diags.HasError() {
		return
	}
	plan.NotificationChannels = channelsObj
}

// requestFromModel builds the API request from a plan or state model.
func requestFromModel(ctx context.Context, model *tenantNotificationSettingsModel, diags *diag.Diagnostics) stepsecurityapi.TenantNotificationSettings {
	var channels tenantNotificationChannelsModel
	diags.Append(model.NotificationChannels.As(ctx, &channels, basetypes.ObjectAsOptions{})...)

	var threatIntel tenantThreatIntelModel
	diags.Append(model.ThreatIntel.As(ctx, &threatIntel, basetypes.ObjectAsOptions{})...)

	if diags.HasError() {
		return stepsecurityapi.TenantNotificationSettings{}
	}

	request := stepsecurityapi.TenantNotificationSettings{
		Email:           channels.Email.ValueString(),
		SlackWebhookURL: channels.SlackWebhookURL.ValueString(),
		TeamsWebhookURL: channels.TeamsWebhookURL.ValueString(),
		// Unknown on create when omitted; ValueString() yields "", which the API
		// reads as "leave it alone" — exactly the intended meaning.
		SlackNotificationMethod: channels.SlackNotificationMethod.ValueString(),
		SlackChannelID:          channels.SlackChannelID.ValueString(),
		ThreatIntel: stepsecurityapi.ThreatIntelOptionsForLevel(
			threatIntel.Enabled.ValueBool(),
			threatIntel.Level.ValueString(),
		),
	}

	developerMDMAttrs := objectAttributes(model.DeveloperMDM)
	for _, event := range tenantDeveloperMDMEvents {
		event.set(&request.DeveloperMDM, boolAttribute(developerMDMAttrs, event.name))
	}

	return request
}

// modelFromAPI builds the Terraform model from an API record. priorLevel is used
// as the threat intel level when the tenant is unsubscribed, since the API keeps
// no level in that case.
func modelFromAPI(settings *stepsecurityapi.TenantNotificationSettings, priorLevel string, diags *diag.Diagnostics) tenantNotificationSettingsModel {
	level := settings.ThreatIntel.Level()
	if level == "" {
		level = priorLevel
	}

	channelsObj, channelDiags := types.ObjectValue(tenantNotificationChannelsAttrTypes, map[string]attr.Value{
		"email":                     types.StringValue(settings.Email),
		"slack_webhook_url":         types.StringValue(settings.SlackWebhookURL),
		"teams_webhook_url":         types.StringValue(settings.TeamsWebhookURL),
		"slack_notification_method": types.StringValue(settings.SlackNotificationMethod),
		"slack_channel_id":          types.StringValue(settings.SlackChannelID),
	})
	diags.Append(channelDiags...)

	threatIntelObj, threatIntelDiags := types.ObjectValue(tenantThreatIntelAttrTypes, map[string]attr.Value{
		"enabled": types.BoolValue(settings.ThreatIntel.Enabled()),
		"level":   types.StringValue(level),
	})
	diags.Append(threatIntelDiags...)

	developerMDMValues := make(map[string]attr.Value, len(tenantDeveloperMDMEvents))
	for _, event := range tenantDeveloperMDMEvents {
		developerMDMValues[event.name] = types.BoolValue(event.get(settings.DeveloperMDM))
	}
	developerMDMObj, developerMDMDiags := types.ObjectValue(tenantDeveloperMDMAttrTypes, developerMDMValues)
	diags.Append(developerMDMDiags...)

	return tenantNotificationSettingsModel{
		NotificationChannels: channelsObj,
		ThreatIntel:          threatIntelObj,
		DeveloperMDM:         developerMDMObj,
	}
}

// anyEventEnabled reports whether the config subscribes to anything. Unknown
// values count as not subscribed: the check only exists to warn, and warning on
// a value that is not settled yet would fire on configurations that turn out
// fine.
func anyEventEnabled(ctx context.Context, config tenantNotificationSettingsModel, diags *diag.Diagnostics) bool {
	if !config.ThreatIntel.IsNull() && !config.ThreatIntel.IsUnknown() {
		var threatIntel tenantThreatIntelModel
		diags.Append(config.ThreatIntel.As(ctx, &threatIntel, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return false
		}
		if threatIntel.Enabled.ValueBool() {
			return true
		}
	}

	developerMDMAttrs := objectAttributes(config.DeveloperMDM)
	for _, event := range tenantDeveloperMDMEvents {
		if boolAttribute(developerMDMAttrs, event.name) {
			return true
		}
	}

	return false
}

// anyChannelConfigured reports whether at least one delivery destination is
// configured. An unknown value counts as configured, since it may well resolve
// to one.
func anyChannelConfigured(channels tenantNotificationChannelsModel) bool {
	for _, value := range []types.String{
		channels.Email,
		channels.SlackWebhookURL,
		channels.TeamsWebhookURL,
		channels.SlackChannelID,
	} {
		if value.IsUnknown() || value.ValueString() != "" {
			return true
		}
	}
	return false
}

func objectAttributes(obj types.Object) map[string]attr.Value {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	return obj.Attributes()
}

// boolAttribute reads one bool out of an object's attributes, treating missing,
// null and unknown alike as false — which is also how the API treats an absent
// event subscription.
func boolAttribute(attrs map[string]attr.Value, name string) bool {
	value, ok := attrs[name].(types.Bool)
	if !ok || value.IsNull() || value.IsUnknown() {
		return false
	}
	return value.ValueBool()
}
