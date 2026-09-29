package provider

import (
	"context"
	"fmt"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
	"github.com/step-security/terraform-provider-stepsecurity/internal/utilities"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &GithubRepoNotificationSettingsResource{}
	_ resource.ResourceWithConfigure   = &GithubRepoNotificationSettingsResource{}
	_ resource.ResourceWithImportState = &GithubRepoNotificationSettingsResource{}
)

// NewOrderResource is a helper function to simplify the provider implementation.
func NewGithubRepoNotificationSettingsResource() resource.Resource {
	return &GithubRepoNotificationSettingsResource{}
}

// orderResource is the resource implementation.
type GithubRepoNotificationSettingsResource struct {
	client stepsecurityapi.Client
}

// Metadata returns the resource type name.
func (r *GithubRepoNotificationSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_org_notification_settings"
}

// Schema defines the schema for the resource.
func (r *GithubRepoNotificationSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The ID of the notification settings. This is the owner/organization name.",
			},
			"owner": schema.StringAttribute{
				Required:    true,
				Description: "The owner/organization name.",
			},
			"notification_channels": schema.SingleNestedAttribute{
				Required: true,
				Attributes: map[string]schema.Attribute{
					"slack_webhook_url": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Description: "The Slack webhook URL to receive notifications. If not provided, no notifications will be sent to Slack.",
						Default:     stringdefault.StaticString(" "),
					},
					"teams_webhook_url": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Description: "The Microsoft Teams webhook URL to receive notifications. If not provided, no notifications will be sent to Microsoft Teams.",
						Default:     stringdefault.StaticString(" "),
					},
					"email": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Description: "The email address to receive notifications. If not provided, no notifications will be sent to the email address.",
						Default:     stringdefault.StaticString(" "),
					},
					"slack_channel_id": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Description: "The Slack channel ID to post notifications to when using OAuth method. Required when slack_notification_method is 'oauth'.",
						Default:     stringdefault.StaticString(" "),
					},
					"slack_notification_method": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Description: "The method to use for sending Slack notifications. Valid values are 'webhook' (default) or 'oauth'.",
						Default:     stringdefault.StaticString("webhook"),
					},
				},
			},
			"notification_events": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"domain_blocked": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when outbound traffic to a domain is blocked.",
						Default:     booldefault.StaticBool(false),
					},
					"file_overwrite": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when source code file is overwritten",
						Default:     booldefault.StaticBool(false),
					},
					"new_endpoint_discovered": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when anomalous outbound call is discovered",
						Default:     booldefault.StaticBool(false),
					},
					"https_detections": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when anomalous HTTPS outbound call is discovered",
						Default:     booldefault.StaticBool(false),
					},
					"secrets_detected": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when secrets are detected in the build log",
						Default:     booldefault.StaticBool(false),
					},
					"artifacts_secrets_detected": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when secrets are detected in the build artifacts",
						Default:     booldefault.StaticBool(false),
					},
					"imposter_commits_detected": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when imposter commits are detected",
						Default:     booldefault.StaticBool(false),
					},
					"suspicious_network_call_detected": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when suspicious network calls are detected",
						Default:     booldefault.StaticBool(false),
					},
					"suspicious_process_events_detected": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when suspicious process events are detected",
						Default:     booldefault.StaticBool(false),
					},
					"harden_runner_config_changes_detected": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when harden runner config changes are detected",
						Default:     booldefault.StaticBool(false),
					},
					"non_compliant_artifact_detected": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when non-compliant artifacts are detected",
						Default:     booldefault.StaticBool(false),
					},
					"run_blocked_by_policy": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when a run policy is blocked",
						Default:     booldefault.StaticBool(false),
					},
					"baseline_check_failures": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when baseline PR checks fail",
						Default:     booldefault.StaticBool(false),
					},
					"required_check_failures": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when required PR checks fail",
						Default:     booldefault.StaticBool(false),
					},
					"optional_check_failures": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when optional PR checks fail",
						Default:     booldefault.StaticBool(false),
					},
					"pat_max_age_violation": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when a personal access token violates the PAT governance max-age control",
						Default:     booldefault.StaticBool(false),
					},
					"pat_no_expiry_violation": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when a personal access token violates the PAT governance no-expiration control",
						Default:     booldefault.StaticBool(false),
					},
					"pat_over_scoped_violation": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when a personal access token violates the PAT governance over-scoped control",
						Default:     booldefault.StaticBool(false),
					},
					"pat_unused_violation": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when a personal access token violates the PAT governance unused-token control",
						Default:     booldefault.StaticBool(false),
					},
					"pat_inactive_owner_violation": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify when a personal access token belongs to an owner who is no longer an active organization member",
						Default:     booldefault.StaticBool(false),
					},
					"pat_expiry_reminder": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Notify with pre-expiry reminders for personal access tokens that are about to expire",
						Default:     booldefault.StaticBool(false),
					},
				},
				Required: true,
			},
			"threat_intel": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				// Without this, an omitted block re-plans as unknown on every run
				// instead of keeping the value adopted from the API, so the plan
				// never settles.
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "The organization's Threat Intel notification subscription, covering compromised " +
					"components found in this organization's pull requests and workflows. Tenant-wide Threat Intel " +
					"notifications are configured separately, on `stepsecurity_tenant_notification_settings`.\n\n" +
					"Threat Intel notifications are opt-out: an organization that has never configured them is " +
					"notified about every incident. Omit this block to leave the organization's current setting " +
					"alone and adopt it into state.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:            true,
						MarkdownDescription: "Whether the organization receives Threat Intel notifications at all.",
					},
					"level": schema.StringAttribute{
						Optional: true,
						Computed: true,
						Default:  stringdefault.StaticString(stepsecurityapi.ThreatIntelLevelAll),
						MarkdownDescription: "Which incidents warrant a notification, ignored when `enabled` is `false`: " +
							"`all` for every Threat Intel incident whether or not this organization is affected, " +
							"`name` only when this organization is affected by a compromised package matched by name at " +
							"any version, `version` only when this organization uses the exact compromised version. " +
							"Defaults to `all`, matching the opt-out default.",
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
		},
	}
}

// githubThreatIntelAttrTypes defines the types for the threat_intel nested object.
var githubThreatIntelAttrTypes = map[string]attr.Type{
	"enabled": types.BoolType,
	"level":   types.StringType,
}

// Configure adds the provider configured client to the resource.
func (r *GithubRepoNotificationSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *GithubRepoNotificationSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID should be the owner name
	owner := req.ID

	// Set the owner and ID in the state
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("owner"), owner)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), owner)...)

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

type githubNotificationSettingsModel struct {
	ID                   types.String `tfsdk:"id"`
	Owner                types.String `tfsdk:"owner"`
	NotificationChannels types.Object `tfsdk:"notification_channels"`
	NotificationEvents   types.Object `tfsdk:"notification_events"`
	ThreatIntel          types.Object `tfsdk:"threat_intel"`
}

type githubThreatIntelModel struct {
	Enabled types.Bool   `tfsdk:"enabled"`
	Level   types.String `tfsdk:"level"`
}

type githubNotificationChannelsModel struct {
	SlackWebhookURL         types.String `tfsdk:"slack_webhook_url"`
	TeamsWebhookURL         types.String `tfsdk:"teams_webhook_url"`
	Email                   types.String `tfsdk:"email"`
	SlackChannelID          types.String `tfsdk:"slack_channel_id"`
	SlackNotificationMethod types.String `tfsdk:"slack_notification_method"`
}

type githubNotificationEventsModel struct {
	DomainBlocked                     types.Bool `tfsdk:"domain_blocked"`
	FileOverwrite                     types.Bool `tfsdk:"file_overwrite"`
	NewEndpointDiscovered             types.Bool `tfsdk:"new_endpoint_discovered"`
	HttpsDetections                   types.Bool `tfsdk:"https_detections"`
	SecretsDetected                   types.Bool `tfsdk:"secrets_detected"`
	ArtifactsSecretsDetected          types.Bool `tfsdk:"artifacts_secrets_detected"`
	ImposterCommitsDetected           types.Bool `tfsdk:"imposter_commits_detected"`
	SuspiciousNetworkCallDetected     types.Bool `tfsdk:"suspicious_network_call_detected"`
	SuspiciousProcessEventsDetected   types.Bool `tfsdk:"suspicious_process_events_detected"`
	HardenRunnerConfigChangesDetected types.Bool `tfsdk:"harden_runner_config_changes_detected"`
	NonCompliantArtifactDetected      types.Bool `tfsdk:"non_compliant_artifact_detected"`
	RunBlockedByPolicy                types.Bool `tfsdk:"run_blocked_by_policy"`
	BaselineCheckFailures             types.Bool `tfsdk:"baseline_check_failures"`
	RequiredCheckFailures             types.Bool `tfsdk:"required_check_failures"`
	OptionalCheckFailures             types.Bool `tfsdk:"optional_check_failures"`
	PATMaxAgeViolation                types.Bool `tfsdk:"pat_max_age_violation"`
	PATNoExpiryViolation              types.Bool `tfsdk:"pat_no_expiry_violation"`
	PATOverScopedViolation            types.Bool `tfsdk:"pat_over_scoped_violation"`
	PATUnusedViolation                types.Bool `tfsdk:"pat_unused_violation"`
	PATInactiveOwnerViolation         types.Bool `tfsdk:"pat_inactive_owner_violation"`
	PATExpiryReminder                 types.Bool `tfsdk:"pat_expiry_reminder"`
}

// Create creates the resource and sets the initial Terraform state.
func (r *GithubRepoNotificationSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan githubNotificationSettingsModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract notification channels
	var channels githubNotificationChannelsModel
	diags = plan.NotificationChannels.As(ctx, &channels, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract notification events
	var events githubNotificationEventsModel
	diags = plan.NotificationEvents.As(ctx, &events, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := stepsecurityapi.GitHubNotificationSettingsRequest{
		Owner: plan.Owner.ValueString(),
		NotificationSettings: stepsecurityapi.NotificationSettings{
			SlackWebhookURL:                    channels.SlackWebhookURL.ValueString(),
			TeamsWebhookURL:                    channels.TeamsWebhookURL.ValueString(),
			Email:                              channels.Email.ValueString(),
			SlackChannelID:                     channels.SlackChannelID.ValueString(),
			SlackNotificationMethod:            channels.SlackNotificationMethod.ValueString(),
			NotifyWhenDomainBlocked:            utilities.ConvertBoolToString(events.DomainBlocked.ValueBool()),
			NotifyOnFileOverwrite:              utilities.ConvertBoolToString(events.FileOverwrite.ValueBool()),
			NotifyWhenEndpointDiscovered:       utilities.ConvertBoolToString(events.NewEndpointDiscovered.ValueBool()),
			NotifyForHttpsDetections:           utilities.ConvertBoolToString(events.HttpsDetections.ValueBool()),
			NotifyForSecretsDetection:          utilities.ConvertBoolToString(events.SecretsDetected.ValueBool()),
			NotifyForArtifactSecretsDetection:  utilities.ConvertBoolToString(events.ArtifactsSecretsDetected.ValueBool()),
			NotifyForImposterCommitsDetection:  utilities.ConvertBoolToString(events.ImposterCommitsDetected.ValueBool()),
			NotifyForSuspiciousNetworkCall:     utilities.ConvertBoolToString(events.SuspiciousNetworkCallDetected.ValueBool()),
			NotifyForSuspiciousProcessEvents:   utilities.ConvertBoolToString(events.SuspiciousProcessEventsDetected.ValueBool()),
			NotifyForHardenRunnerConfigChange:  utilities.ConvertBoolToString(events.HardenRunnerConfigChangesDetected.ValueBool()),
			NotifyForNonCompliantArtifacts:     utilities.ConvertBoolToString(events.NonCompliantArtifactDetected.ValueBool()),
			NotifyForBlockedRunPolicy:          utilities.ConvertBoolToString(events.RunBlockedByPolicy.ValueBool()),
			NotifyForBaselineCheckFailures:     utilities.ConvertBoolToString(events.BaselineCheckFailures.ValueBool()),
			NotifyForRequiredCheckFailures:     utilities.ConvertBoolToString(events.RequiredCheckFailures.ValueBool()),
			NotifyForOptionalCheckFailures:     utilities.ConvertBoolToString(events.OptionalCheckFailures.ValueBool()),
			NotifyForPATMaxAgeViolation:        utilities.ConvertBoolToString(events.PATMaxAgeViolation.ValueBool()),
			NotifyForPATNoExpiryViolation:      utilities.ConvertBoolToString(events.PATNoExpiryViolation.ValueBool()),
			NotifyForPATOverScopedViolation:    utilities.ConvertBoolToString(events.PATOverScopedViolation.ValueBool()),
			NotifyForPATUnusedViolation:        utilities.ConvertBoolToString(events.PATUnusedViolation.ValueBool()),
			NotifyForPATInactiveOwnerViolation: utilities.ConvertBoolToString(events.PATInactiveOwnerViolation.ValueBool()),
			NotifyForPATExpiryReminder:         utilities.ConvertBoolToString(events.PATExpiryReminder.ValueBool()),
		},
	}

	r.applyThreatIntelToRequest(ctx, plan.ThreatIntel, &request.NotificationSettings, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create notification settings in StepSecurity
	err := r.client.CreateNotificationSettings(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create Notification Settings",
			err.Error(),
		)
		return
	}

	r.resolveThreatIntelState(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
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
func (r *GithubRepoNotificationSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var state githubNotificationSettingsModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get notification settings from StepSecurity
	settings, err := r.client.GetNotificationSettings(ctx, state.Owner.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Notification Settings",
			err.Error(),
		)
		return
	}

	// Update state with latest data
	state.ID = types.StringValue(state.Owner.ValueString())

	// Create notification channels object
	channelsObj, _ := types.ObjectValue(
		map[string]attr.Type{
			"slack_webhook_url":         types.StringType,
			"teams_webhook_url":         types.StringType,
			"email":                     types.StringType,
			"slack_channel_id":          types.StringType,
			"slack_notification_method": types.StringType,
		},
		map[string]attr.Value{
			"slack_webhook_url":         types.StringValue(settings.SlackWebhookURL),
			"teams_webhook_url":         types.StringValue(settings.TeamsWebhookURL),
			"email":                     types.StringValue(settings.Email),
			"slack_channel_id":          types.StringValue(settings.SlackChannelID),
			"slack_notification_method": types.StringValue(settings.SlackNotificationMethod),
		},
	)
	state.NotificationChannels = channelsObj

	// Create notification events object
	eventsObj, _ := types.ObjectValue(
		map[string]attr.Type{
			"domain_blocked":                        types.BoolType,
			"file_overwrite":                        types.BoolType,
			"new_endpoint_discovered":               types.BoolType,
			"https_detections":                      types.BoolType,
			"secrets_detected":                      types.BoolType,
			"artifacts_secrets_detected":            types.BoolType,
			"imposter_commits_detected":             types.BoolType,
			"suspicious_network_call_detected":      types.BoolType,
			"suspicious_process_events_detected":    types.BoolType,
			"harden_runner_config_changes_detected": types.BoolType,
			"non_compliant_artifact_detected":       types.BoolType,
			"run_blocked_by_policy":                 types.BoolType,
			"baseline_check_failures":               types.BoolType,
			"required_check_failures":               types.BoolType,
			"optional_check_failures":               types.BoolType,
			"pat_max_age_violation":                 types.BoolType,
			"pat_no_expiry_violation":               types.BoolType,
			"pat_over_scoped_violation":             types.BoolType,
			"pat_unused_violation":                  types.BoolType,
			"pat_inactive_owner_violation":          types.BoolType,
			"pat_expiry_reminder":                   types.BoolType,
		},
		map[string]attr.Value{
			"domain_blocked":                        types.BoolValue(utilities.ConvertStringToBool(settings.NotifyWhenDomainBlocked)),
			"file_overwrite":                        types.BoolValue(utilities.ConvertStringToBool(settings.NotifyOnFileOverwrite)),
			"new_endpoint_discovered":               types.BoolValue(utilities.ConvertStringToBool(settings.NotifyWhenEndpointDiscovered)),
			"https_detections":                      types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForHttpsDetections)),
			"secrets_detected":                      types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForSecretsDetection)),
			"artifacts_secrets_detected":            types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForArtifactSecretsDetection)),
			"imposter_commits_detected":             types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForImposterCommitsDetection)),
			"suspicious_network_call_detected":      types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForSuspiciousNetworkCall)),
			"suspicious_process_events_detected":    types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForSuspiciousProcessEvents)),
			"harden_runner_config_changes_detected": types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForHardenRunnerConfigChange)),
			"non_compliant_artifact_detected":       types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForNonCompliantArtifacts)),
			"run_blocked_by_policy":                 types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForBlockedRunPolicy)),
			"baseline_check_failures":               types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForBaselineCheckFailures)),
			"required_check_failures":               types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForRequiredCheckFailures)),
			"optional_check_failures":               types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForOptionalCheckFailures)),
			"pat_max_age_violation":                 types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForPATMaxAgeViolation)),
			"pat_no_expiry_violation":               types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForPATNoExpiryViolation)),
			"pat_over_scoped_violation":             types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForPATOverScopedViolation)),
			"pat_unused_violation":                  types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForPATUnusedViolation)),
			"pat_inactive_owner_violation":          types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForPATInactiveOwnerViolation)),
			"pat_expiry_reminder":                   types.BoolValue(utilities.ConvertStringToBool(settings.NotifyForPATExpiryReminder)),
		},
	)
	state.NotificationEvents = eventsObj

	state.ThreatIntel = githubThreatIntelObject(settings.OrgThreatIntelLevel, githubPriorThreatIntelLevel(ctx, state.ThreatIntel), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
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
func (r *GithubRepoNotificationSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan githubNotificationSettingsModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract notification channels
	var channels githubNotificationChannelsModel
	diags = plan.NotificationChannels.As(ctx, &channels, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract notification events
	var events githubNotificationEventsModel
	diags = plan.NotificationEvents.As(ctx, &events, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := stepsecurityapi.GitHubNotificationSettingsRequest{
		Owner: plan.Owner.ValueString(),
		NotificationSettings: stepsecurityapi.NotificationSettings{
			SlackWebhookURL:                    channels.SlackWebhookURL.ValueString(),
			TeamsWebhookURL:                    channels.TeamsWebhookURL.ValueString(),
			Email:                              channels.Email.ValueString(),
			SlackChannelID:                     channels.SlackChannelID.ValueString(),
			SlackNotificationMethod:            channels.SlackNotificationMethod.ValueString(),
			NotifyWhenDomainBlocked:            utilities.ConvertBoolToString(events.DomainBlocked.ValueBool()),
			NotifyOnFileOverwrite:              utilities.ConvertBoolToString(events.FileOverwrite.ValueBool()),
			NotifyWhenEndpointDiscovered:       utilities.ConvertBoolToString(events.NewEndpointDiscovered.ValueBool()),
			NotifyForHttpsDetections:           utilities.ConvertBoolToString(events.HttpsDetections.ValueBool()),
			NotifyForSecretsDetection:          utilities.ConvertBoolToString(events.SecretsDetected.ValueBool()),
			NotifyForArtifactSecretsDetection:  utilities.ConvertBoolToString(events.ArtifactsSecretsDetected.ValueBool()),
			NotifyForImposterCommitsDetection:  utilities.ConvertBoolToString(events.ImposterCommitsDetected.ValueBool()),
			NotifyForSuspiciousNetworkCall:     utilities.ConvertBoolToString(events.SuspiciousNetworkCallDetected.ValueBool()),
			NotifyForSuspiciousProcessEvents:   utilities.ConvertBoolToString(events.SuspiciousProcessEventsDetected.ValueBool()),
			NotifyForHardenRunnerConfigChange:  utilities.ConvertBoolToString(events.HardenRunnerConfigChangesDetected.ValueBool()),
			NotifyForNonCompliantArtifacts:     utilities.ConvertBoolToString(events.NonCompliantArtifactDetected.ValueBool()),
			NotifyForBlockedRunPolicy:          utilities.ConvertBoolToString(events.RunBlockedByPolicy.ValueBool()),
			NotifyForBaselineCheckFailures:     utilities.ConvertBoolToString(events.BaselineCheckFailures.ValueBool()),
			NotifyForRequiredCheckFailures:     utilities.ConvertBoolToString(events.RequiredCheckFailures.ValueBool()),
			NotifyForOptionalCheckFailures:     utilities.ConvertBoolToString(events.OptionalCheckFailures.ValueBool()),
			NotifyForPATMaxAgeViolation:        utilities.ConvertBoolToString(events.PATMaxAgeViolation.ValueBool()),
			NotifyForPATNoExpiryViolation:      utilities.ConvertBoolToString(events.PATNoExpiryViolation.ValueBool()),
			NotifyForPATOverScopedViolation:    utilities.ConvertBoolToString(events.PATOverScopedViolation.ValueBool()),
			NotifyForPATUnusedViolation:        utilities.ConvertBoolToString(events.PATUnusedViolation.ValueBool()),
			NotifyForPATInactiveOwnerViolation: utilities.ConvertBoolToString(events.PATInactiveOwnerViolation.ValueBool()),
			NotifyForPATExpiryReminder:         utilities.ConvertBoolToString(events.PATExpiryReminder.ValueBool()),
		},
	}

	r.applyThreatIntelToRequest(ctx, plan.ThreatIntel, &request.NotificationSettings, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update notification settings in StepSecurity
	err := r.client.UpdateNotificationSettings(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Update Notification Settings",
			err.Error(),
		)
		return
	}

	r.resolveThreatIntelState(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
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
func (r *GithubRepoNotificationSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state githubNotificationSettingsModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete notification settings in StepSecurity
	err := r.client.DeleteNotificationSettings(ctx, state.Owner.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Delete Notification Settings",
			err.Error(),
		)
		return
	}
}

// applyThreatIntelToRequest writes the threat intel block onto the request.
//
// An absent block leaves every threat intel field empty, which this API reads as
// "leave the organization's current value alone" — it only assigns the fields a
// request sends non-empty.
//
// The three per-source flags are written from the same on/off as the level, the
// way the console writes them, so backend paths that still read the flags agree
// with the authoritative level.
func (r *GithubRepoNotificationSettingsResource) applyThreatIntelToRequest(
	ctx context.Context,
	threatIntelObj types.Object,
	settings *stepsecurityapi.NotificationSettings,
	diags *diag.Diagnostics,
) {
	if threatIntelObj.IsNull() || threatIntelObj.IsUnknown() {
		return
	}

	var threatIntel githubThreatIntelModel
	diags.Append(threatIntelObj.As(ctx, &threatIntel, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return
	}

	enabled := threatIntel.Enabled.ValueBool()
	settings.OrgThreatIntelLevel = stepsecurityapi.OrgThreatIntelLevelFor(enabled, threatIntel.Level.ValueString())
	settings.NotifyForCompromisedNPMInPR = utilities.ConvertBoolToString(enabled)
	settings.NotifyForCompromisedPyPIInPR = utilities.ConvertBoolToString(enabled)
	settings.NotifyForCompromisedActionInWorkflow = utilities.ConvertBoolToString(enabled)
}

// resolveThreatIntelState fills in threat_intel after a write when the
// configuration omitted it. The attribute is optional-and-computed, so its
// planned value is unknown on create and only the API can say what the
// organization's setting actually is.
func (r *GithubRepoNotificationSettingsResource) resolveThreatIntelState(
	ctx context.Context,
	plan *githubNotificationSettingsModel,
	diags *diag.Diagnostics,
) {
	if !plan.ThreatIntel.IsUnknown() {
		return
	}

	settings, err := r.client.GetNotificationSettings(ctx, plan.Owner.ValueString())
	if err != nil {
		diags.AddError("Unable to Read Back Notification Settings", err.Error())
		return
	}

	plan.ThreatIntel = githubThreatIntelObject(settings.OrgThreatIntelLevel, stepsecurityapi.ThreatIntelLevelAll, diags)
}

// githubThreatIntelObject builds the threat_intel object from a stored level.
func githubThreatIntelObject(storedLevel, priorLevel string, diags *diag.Diagnostics) types.Object {
	enabled, level := stepsecurityapi.OrgThreatIntelSubscription(storedLevel, priorLevel)

	obj, objDiags := types.ObjectValue(githubThreatIntelAttrTypes, map[string]attr.Value{
		"enabled": types.BoolValue(enabled),
		"level":   types.StringValue(level),
	})
	diags.Append(objDiags...)

	return obj
}

// githubPriorThreatIntelLevel reads the level already in state, used when the
// organization is opted out and the API has no granularity to report. Falls back
// to the opt-out default so state written before threat intel was supported
// still refreshes cleanly.
func githubPriorThreatIntelLevel(ctx context.Context, threatIntelObj types.Object) string {
	if threatIntelObj.IsNull() || threatIntelObj.IsUnknown() {
		return stepsecurityapi.ThreatIntelLevelAll
	}

	var threatIntel githubThreatIntelModel
	if diags := threatIntelObj.As(ctx, &threatIntel, basetypes.ObjectAsOptions{}); diags.HasError() {
		return stepsecurityapi.ThreatIntelLevelAll
	}
	if level := threatIntel.Level.ValueString(); level != "" {
		return level
	}

	return stepsecurityapi.ThreatIntelLevelAll
}
