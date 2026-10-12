package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Notification profiles are extra notification destinations, each receiving
// only its own events, on top of a resource's notification_channels. The API
// stores them as "notification channels"; the console and this provider call
// them notification profiles, because notification_channels already names the
// default destinations on both resources.

const (
	profileTypeEmail        = "email"
	profileTypeSlackWebhook = "slack_webhook"
	profileTypeSlackOAuth   = "slack_oauth"
	profileTypeTeams        = "teams"

	// profileThreatIntelOff is the level of a profile that does not receive
	// Threat Intel notifications.
	profileThreatIntelOff = "off"

	maxNotificationProfiles = 20
)

var profileTypes = []string{profileTypeEmail, profileTypeSlackWebhook, profileTypeSlackOAuth, profileTypeTeams}

var profileThreatIntelLevels = []string{
	profileThreatIntelOff,
	stepsecurityapi.ThreatIntelLevelAll,
	stepsecurityapi.ThreatIntelLevelName,
	stepsecurityapi.ThreatIntelLevelVersion,
}

// orgProfileEvent maps an event name in configuration to the org notification
// settings field the API stores in a profile's events list. The names match
// notification_events where an event is in both.
type orgProfileEvent struct {
	name    string
	apiName string
}

var orgProfileEvents = []orgProfileEvent{
	{"domain_blocked", "notifyWhenDomainBlocked"},
	{"new_endpoint_discovered", "notifyWhenEndpointDiscovered"},
	{"https_detections", "notifyForHttpsDetections"},
	{"suspicious_network_call_detected", "notifyForSuspiciousNetworkCall"},
	{"suspicious_process_events_detected", "notifyForSuspiciousProcessEvents"},
	{"file_overwrite", "notifyOnFileOverwrite"},
	{"secret_exfiltration_detected", "notifyForSecretExfilDetection"},
	{"secrets_detected", "notifyForSecretsDetection"},
	{"artifacts_secrets_detected", "notifyForArtifactSecretsDetection"},
	{"run_blocked_by_policy", "notifyForBlockedRunPolicy"},
	{"baseline_check_failures", "notifyForBaselineCheckFailures"},
	{"required_check_failures", "notifyForRequiredCheckFailures"},
	{"optional_check_failures", "notifyForOptionalCheckFailures"},
	{"non_compliant_artifact_detected", "notifyForNonCompliantArtifacts"},
	{"imposter_commits_detected", "notifyForImposterCommitsDetection"},
	{"pat_max_age_violation", "notifyForPATMaxAgeViolation"},
	{"pat_no_expiry_violation", "notifyForPATNoExpiryViolation"},
	{"pat_over_scoped_violation", "notifyForPATOverScopedViolation"},
	{"pat_unused_violation", "notifyForPATUnusedViolation"},
	{"pat_inactive_owner_violation", "notifyForPATInactiveOwnerViolation"},
	{"pat_expiry_reminder", "notifyForPATExpiryReminder"},
	{"pat_abuse_detected", "notifyForPATAbuseDetection"},
}

func orgProfileEventNames() []string {
	names := make([]string, len(orgProfileEvents))
	for i, event := range orgProfileEvents {
		names[i] = event.name
	}
	return names
}

func tenantProfileDeveloperMDMEventNames() []string {
	names := make([]string, len(tenantDeveloperMDMEvents))
	for i, event := range tenantDeveloperMDMEvents {
		names[i] = event.name
	}
	return names
}

var orgProfileAttrTypes = map[string]attr.Type{
	"id":                 types.StringType,
	"name":               types.StringType,
	"type":               types.StringType,
	"target":             types.StringType,
	"events":             types.SetType{ElemType: types.StringType},
	"threat_intel_level": types.StringType,
}

var tenantProfileAttrTypes = map[string]attr.Type{
	"id":                   types.StringType,
	"name":                 types.StringType,
	"type":                 types.StringType,
	"target":               types.StringType,
	"threat_intel_level":   types.StringType,
	"developer_mdm_events": types.SetType{ElemType: types.StringType},
}

type orgProfileModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	Type             types.String `tfsdk:"type"`
	Target           types.String `tfsdk:"target"`
	Events           types.Set    `tfsdk:"events"`
	ThreatIntelLevel types.String `tfsdk:"threat_intel_level"`
}

type tenantProfileModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Type               types.String `tfsdk:"type"`
	Target             types.String `tfsdk:"target"`
	ThreatIntelLevel   types.String `tfsdk:"threat_intel_level"`
	DeveloperMDMEvents types.Set    `tfsdk:"developer_mdm_events"`
}

// profileBaseAttributes are the attributes every notification profile has.
func profileBaseAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Identifier StepSecurity assigns to the profile.",
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"name": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Name of the profile, at most 64 characters.",
			Validators:          []validator.String{stringvalidator.LengthBetween(1, 64)},
		},
		"type": schema.StringAttribute{
			Required: true,
			MarkdownDescription: "Where the profile delivers: `email`, `slack_webhook`, `slack_oauth` (a channel " +
				"posted to by the Slack app installed for the tenant) or `teams`.",
			Validators: []validator.String{stringvalidator.OneOf(profileTypes...)},
		},
		"target": schema.StringAttribute{
			Required: true,
			MarkdownDescription: "The destination for `type`: comma separated email addresses (at most 49), an " +
				"`https` webhook URL, or a Slack channel ID.",
		},
		"threat_intel_level": schema.StringAttribute{
			Optional: true,
			Computed: true,
			Default:  stringdefault.StaticString(profileThreatIntelOff),
			MarkdownDescription: "Threat Intel notifications for this profile: `off` (default), `all`, `name` or " +
				"`version`, with the same meaning as the resource's `threat_intel.level`.",
			Validators: []validator.String{stringvalidator.OneOf(profileThreatIntelLevels...)},
		},
	}
}

func eventSetAttribute(description string, names []string) schema.SetAttribute {
	return schema.SetAttribute{
		ElementType:         types.StringType,
		Optional:            true,
		Computed:            true,
		Default:             setdefault.StaticValue(types.SetValueMust(types.StringType, nil)),
		MarkdownDescription: description,
		Validators:          []validator.Set{setvalidator.ValueStringsAre(stringvalidator.OneOf(names...))},
	}
}

func profilesAttribute(description string, attributes map[string]schema.Attribute) schema.ListNestedAttribute {
	return schema.ListNestedAttribute{
		Optional:            true,
		Computed:            true,
		PlanModifiers:       []planmodifier.List{omittedProfilesKeepState{}},
		Validators:          []validator.List{listvalidator.SizeAtMost(maxNotificationProfiles)},
		MarkdownDescription: description,
		NestedObject:        schema.NestedAttributeObject{Attributes: attributes},
	}
}

func orgProfilesSchemaAttribute() schema.ListNestedAttribute {
	attributes := profileBaseAttributes()
	attributes["events"] = eventSetAttribute(
		"Events this profile receives. Names match `notification_events`, plus `secret_exfiltration_detected` "+
			"and the PAT governance events.",
		orgProfileEventNames(),
	)
	return profilesAttribute(
		"Additional notification destinations, each receiving only the events listed on it, on top of "+
			"`notification_channels`. At most 20. Omit to leave the organization's current profiles alone and adopt "+
			"them into state; set to `[]` to remove them all.",
		attributes,
	)
}

func tenantProfilesSchemaAttribute() schema.ListNestedAttribute {
	attributes := profileBaseAttributes()
	attributes["developer_mdm_events"] = eventSetAttribute(
		"Dev Machine Guard events this profile receives, named as in `developer_mdm`.",
		tenantProfileDeveloperMDMEventNames(),
	)
	return profilesAttribute(
		"Additional notification destinations, each receiving only its own Threat Intel and Dev Machine Guard "+
			"events, on top of `notification_channels`. At most 20. Omit to leave the tenant's current profiles "+
			"alone and adopt them into state; set to `[]` to remove them all.",
		attributes,
	)
}

// omittedProfilesKeepState plans an omitted profile list as whatever state
// holds, so leaving it out of the configuration never plans a change.
//
// Unlike UseStateForUnknown it also keeps a null state value: state written
// before this attribute existed holds null, and planning unknown there would
// show a change on the first plan after upgrading. Only on create, with no
// state at all, does the list stay unknown, to be read back after the write.
type omittedProfilesKeepState struct{}

func (omittedProfilesKeepState) Description(_ context.Context) string {
	return "Keeps the profiles in state when the configuration omits them."
}

func (m omittedProfilesKeepState) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (omittedProfilesKeepState) PlanModifyList(_ context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	if !req.ConfigValue.IsNull() || req.State.Raw.IsNull() {
		return
	}
	resp.PlanValue = req.StateValue
}

// profileID returns the planned id, or "" for a new profile so the API
// assigns one.
func profileID(id types.String) string {
	if id.IsNull() || id.IsUnknown() {
		return ""
	}
	return id.ValueString()
}

func profileSetStrings(ctx context.Context, set types.Set, diags *diag.Diagnostics) []string {
	if set.IsNull() || set.IsUnknown() {
		return nil
	}
	var values []string
	diags.Append(set.ElementsAs(ctx, &values, false)...)
	return values
}

// profilesNeedReadBack reports whether a planned list has values only the API
// can fill in: the whole list when omitted on create, or the id of a new
// profile.
func profilesNeedReadBack(ctx context.Context, list types.List, attrTypes map[string]attr.Type) bool {
	if list.IsUnknown() {
		return true
	}
	if list.IsNull() {
		return false
	}
	for _, element := range list.Elements() {
		obj, ok := element.(types.Object)
		if !ok {
			continue
		}
		if id, ok := obj.Attributes()["id"].(types.String); ok && id.IsUnknown() {
			return true
		}
	}
	return false
}

// orgProfilesToAPI builds the request list, or nil when the configuration
// leaves the profiles alone.
func orgProfilesToAPI(ctx context.Context, list types.List, diags *diag.Diagnostics) *[]stepsecurityapi.NotificationProfile {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var models []orgProfileModel
	diags.Append(list.ElementsAs(ctx, &models, false)...)
	if diags.HasError() {
		return nil
	}

	apiNames := make(map[string]string, len(orgProfileEvents))
	for _, event := range orgProfileEvents {
		apiNames[event.name] = event.apiName
	}

	profiles := make([]stepsecurityapi.NotificationProfile, 0, len(models))
	for _, m := range models {
		var events []string
		for _, name := range profileSetStrings(ctx, m.Events, diags) {
			events = append(events, apiNames[name])
		}
		if events == nil {
			events = []string{}
		}
		profiles = append(profiles, stepsecurityapi.NotificationProfile{
			ID:                  profileID(m.ID),
			Name:                m.Name.ValueString(),
			Type:                m.Type.ValueString(),
			Target:              m.Target.ValueString(),
			Events:              events,
			OrgThreatIntelLevel: m.ThreatIntelLevel.ValueString(),
		})
	}
	return &profiles
}

// orgProfilesFromAPI builds the state list. An event this provider does not
// know is kept under its API name, so the drift shows rather than the event
// being silently dropped on the next apply.
func orgProfilesFromAPI(profiles *[]stepsecurityapi.NotificationProfile, diags *diag.Diagnostics) types.List {
	names := make(map[string]string, len(orgProfileEvents))
	for _, event := range orgProfileEvents {
		names[event.apiName] = event.name
	}

	elements := []attr.Value{}
	if profiles != nil {
		for _, p := range *profiles {
			events := make([]attr.Value, 0, len(p.Events))
			for _, apiName := range p.Events {
				name, ok := names[apiName]
				if !ok {
					name = apiName
				}
				events = append(events, types.StringValue(name))
			}
			eventSet, setDiags := types.SetValue(types.StringType, events)
			diags.Append(setDiags...)

			level := p.OrgThreatIntelLevel
			if level == "" {
				level = profileThreatIntelOff
			}
			obj, objDiags := types.ObjectValue(orgProfileAttrTypes, map[string]attr.Value{
				"id":                 types.StringValue(p.ID),
				"name":               types.StringValue(p.Name),
				"type":               types.StringValue(p.Type),
				"target":             types.StringValue(p.Target),
				"events":             eventSet,
				"threat_intel_level": types.StringValue(level),
			})
			diags.Append(objDiags...)
			elements = append(elements, obj)
		}
	}

	list, listDiags := types.ListValue(types.ObjectType{AttrTypes: orgProfileAttrTypes}, elements)
	diags.Append(listDiags...)
	return list
}

// tenantProfilesToAPI builds the request list, or nil when the configuration
// leaves the profiles alone.
func tenantProfilesToAPI(ctx context.Context, list types.List, diags *diag.Diagnostics) *[]stepsecurityapi.TenantNotificationProfile {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var models []tenantProfileModel
	diags.Append(list.ElementsAs(ctx, &models, false)...)
	if diags.HasError() {
		return nil
	}

	profiles := make([]stepsecurityapi.TenantNotificationProfile, 0, len(models))
	for _, m := range models {
		level := m.ThreatIntelLevel.ValueString()
		profile := stepsecurityapi.TenantNotificationProfile{
			ID:          profileID(m.ID),
			Name:        m.Name.ValueString(),
			Type:        m.Type.ValueString(),
			Target:      m.Target.ValueString(),
			ThreatIntel: stepsecurityapi.ThreatIntelOptionsForLevel(level != profileThreatIntelOff, level),
		}
		subscribed := map[string]bool{}
		for _, name := range profileSetStrings(ctx, m.DeveloperMDMEvents, diags) {
			subscribed[name] = true
		}
		for _, event := range tenantDeveloperMDMEvents {
			event.set(&profile.DeveloperMDM, subscribed[event.name])
		}
		profiles = append(profiles, profile)
	}
	return &profiles
}

func tenantProfilesFromAPI(profiles *[]stepsecurityapi.TenantNotificationProfile, diags *diag.Diagnostics) types.List {
	elements := []attr.Value{}
	if profiles != nil {
		for _, p := range *profiles {
			level := p.ThreatIntel.Level()
			if level == "" {
				level = profileThreatIntelOff
			}
			events := []attr.Value{}
			for _, event := range tenantDeveloperMDMEvents {
				if event.get(p.DeveloperMDM) {
					events = append(events, types.StringValue(event.name))
				}
			}
			eventSet, setDiags := types.SetValue(types.StringType, events)
			diags.Append(setDiags...)

			obj, objDiags := types.ObjectValue(tenantProfileAttrTypes, map[string]attr.Value{
				"id":                   types.StringValue(p.ID),
				"name":                 types.StringValue(p.Name),
				"type":                 types.StringValue(p.Type),
				"target":               types.StringValue(p.Target),
				"threat_intel_level":   types.StringValue(level),
				"developer_mdm_events": eventSet,
			})
			diags.Append(objDiags...)
			elements = append(elements, obj)
		}
	}

	list, listDiags := types.ListValue(types.ObjectType{AttrTypes: tenantProfileAttrTypes}, elements)
	diags.Append(listDiags...)
	return list
}
