package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestTenantNotificationSettingsResource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaResp := &fwresource.SchemaResponse{}

	NewTenantNotificationSettingsResource().Schema(ctx, fwresource.SchemaRequest{}, schemaResp)

	require.False(t, schemaResp.Diagnostics.HasError(), "Schema() returned errors: %v", schemaResp.Diagnostics)

	attrs := schemaResp.Schema.Attributes
	for _, expected := range []string{"notification_channels", "threat_intel", "developer_mdm"} {
		assert.Contains(t, attrs, expected, "expected attribute %q in schema", expected)
	}

	// Every event in the table must be reachable from configuration, otherwise a
	// new event type would silently stay unsettable.
	developerMDM, ok := attrs["developer_mdm"].(resourceschema.SingleNestedAttribute)
	require.True(t, ok, "developer_mdm should be a single nested attribute")
	assert.Len(t, developerMDM.Attributes, len(tenantDeveloperMDMEvents))
	for _, event := range tenantDeveloperMDMEvents {
		assert.Contains(t, developerMDM.Attributes, event.name)
		assert.Contains(t, tenantDeveloperMDMAttrTypes, event.name)
	}
}

func TestTenantNotificationSettings_requestFromModel(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	model := &tenantNotificationSettingsModel{
		NotificationChannels: testTenantChannels(t, tenantNotificationChannelsModel{
			Email:                   types.StringValue("security@example.com"),
			SlackWebhookURL:         types.StringValue("https://hooks.slack.com/services/T/B/X"),
			TeamsWebhookURL:         types.StringValue(""),
			SlackNotificationMethod: types.StringValue("webhook"),
			SlackChannelID:          types.StringNull(),
		}),
		ThreatIntel:  testTenantThreatIntel(true, stepsecurityapi.ThreatIntelLevelName),
		DeveloperMDM: testTenantDeveloperMDM("new_ides", "suspicious_files"),
	}

	var diags diag.Diagnostics
	request := requestFromModel(ctx, model, &diags)
	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)

	assert.Equal(t, "security@example.com", request.Email)
	assert.Equal(t, "https://hooks.slack.com/services/T/B/X", request.SlackWebhookURL)
	assert.Empty(t, request.TeamsWebhookURL)
	assert.Equal(t, "webhook", request.SlackNotificationMethod)
	// Null means "leave the tenant's current channel alone", which the API reads
	// as an omitted field.
	assert.Empty(t, request.SlackChannelID)

	assert.Equal(t, stepsecurityapi.ThreatIntelNotificationOptions{NotifyOnPackageNameMatch: true}, request.ThreatIntel)

	assert.True(t, request.DeveloperMDM.NewIDEs.Enabled)
	assert.True(t, request.DeveloperMDM.SuspiciousFiles.Enabled)
	assert.False(t, request.DeveloperMDM.NewIDEExtensions.Enabled)
	assert.False(t, request.DeveloperMDM.NewAIAgents.Enabled)
	assert.False(t, request.DeveloperMDM.NewMCPServers.Enabled)
	assert.False(t, request.DeveloperMDM.NewAgentSkills.Enabled)
	assert.False(t, request.DeveloperMDM.ConfigChanges.Enabled)
}

// TestTenantNotificationSettings_requestFromModel_EveryEventIsWired guards the
// event table: a get/set pair copied from the wrong field would leave one event
// unsettable, or set two at once.
func TestTenantNotificationSettings_requestFromModel_EveryEventIsWired(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for _, event := range tenantDeveloperMDMEvents {
		event := event
		t.Run(event.name, func(t *testing.T) {
			t.Parallel()

			model := &tenantNotificationSettingsModel{
				NotificationChannels: testTenantChannels(t, tenantNotificationChannelsModel{
					Email:                   types.StringValue("security@example.com"),
					SlackWebhookURL:         types.StringValue(""),
					TeamsWebhookURL:         types.StringValue(""),
					SlackNotificationMethod: types.StringNull(),
					SlackChannelID:          types.StringNull(),
				}),
				ThreatIntel:  testTenantThreatIntel(false, stepsecurityapi.ThreatIntelLevelVersion),
				DeveloperMDM: testTenantDeveloperMDM(event.name),
			}

			var diags diag.Diagnostics
			request := requestFromModel(ctx, model, &diags)
			require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)

			enabled := 0
			for _, other := range tenantDeveloperMDMEvents {
				if other.get(request.DeveloperMDM) {
					enabled++
					assert.Equal(t, event.name, other.name, "%q enabled %q", event.name, other.name)
				}
			}
			assert.Equal(t, 1, enabled, "expected exactly one event enabled for %q", event.name)
		})
	}
}

func TestTenantNotificationSettings_modelFromAPI(t *testing.T) {
	t.Parallel()

	settings := &stepsecurityapi.TenantNotificationSettings{
		Email:                   "security@example.com",
		TeamsWebhookURL:         "https://example.webhook.office.com/hook",
		SlackNotificationMethod: "oauth",
		SlackChannelID:          "C0123456789",
		ThreatIntel:             stepsecurityapi.ThreatIntelOptionsForLevel(true, stepsecurityapi.ThreatIntelLevelAll),
		DeveloperMDM: stepsecurityapi.DeveloperMDMNotificationOptions{
			ConfigChanges: stepsecurityapi.DeveloperMDMEventSubscription{Enabled: true},
		},
	}

	var diags diag.Diagnostics
	model := modelFromAPI(settings, stepsecurityapi.ThreatIntelLevelVersion, &diags)
	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)

	channels := model.NotificationChannels.Attributes()
	assert.Equal(t, types.StringValue("security@example.com"), channels["email"])
	assert.Equal(t, types.StringValue(""), channels["slack_webhook_url"])
	assert.Equal(t, types.StringValue("https://example.webhook.office.com/hook"), channels["teams_webhook_url"])
	assert.Equal(t, types.StringValue("oauth"), channels["slack_notification_method"])
	assert.Equal(t, types.StringValue("C0123456789"), channels["slack_channel_id"])

	threatIntel := model.ThreatIntel.Attributes()
	assert.Equal(t, types.BoolValue(true), threatIntel["enabled"])
	assert.Equal(t, types.StringValue(stepsecurityapi.ThreatIntelLevelAll), threatIntel["level"])

	developerMDM := model.DeveloperMDM.Attributes()
	assert.Equal(t, types.BoolValue(true), developerMDM["config_changes"])
	assert.Equal(t, types.BoolValue(false), developerMDM["new_ides"])
}

// TestTenantNotificationSettings_modelFromAPI_PreservesLevelWhenDisabled covers
// the one attribute the API does not store: with no subscription there is no
// level to read back, so inventing one would make `enabled = false, level =
// "all"` drift on every refresh.
func TestTenantNotificationSettings_modelFromAPI_PreservesLevelWhenDisabled(t *testing.T) {
	t.Parallel()

	settings := &stepsecurityapi.TenantNotificationSettings{}

	var diags diag.Diagnostics
	model := modelFromAPI(settings, stepsecurityapi.ThreatIntelLevelAll, &diags)
	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)

	threatIntel := model.ThreatIntel.Attributes()
	assert.Equal(t, types.BoolValue(false), threatIntel["enabled"])
	assert.Equal(t, types.StringValue(stepsecurityapi.ThreatIntelLevelAll), threatIntel["level"])
}

func TestTenantNotificationSettingsResource_ValidateConfig(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		channels      tenantNotificationChannelsModel
		threatIntel   types.Object
		developerMDM  types.Object
		expectError   bool
		expectWarning bool
	}{
		{
			name: "valid",
			channels: tenantNotificationChannelsModel{
				Email:                   types.StringValue("security@example.com"),
				SlackWebhookURL:         types.StringValue(""),
				TeamsWebhookURL:         types.StringValue(""),
				SlackNotificationMethod: types.StringNull(),
				SlackChannelID:          types.StringNull(),
			},
			threatIntel:  testTenantThreatIntel(true, stepsecurityapi.ThreatIntelLevelVersion),
			developerMDM: testTenantDeveloperMDM(),
		},
		{
			name: "empty_slack_notification_method_rejected",
			channels: tenantNotificationChannelsModel{
				Email:                   types.StringValue("security@example.com"),
				SlackWebhookURL:         types.StringValue(""),
				TeamsWebhookURL:         types.StringValue(""),
				SlackNotificationMethod: types.StringValue(""),
				SlackChannelID:          types.StringNull(),
			},
			threatIntel:  testTenantThreatIntel(true, stepsecurityapi.ThreatIntelLevelVersion),
			developerMDM: testTenantDeveloperMDM(),
			expectError:  true,
		},
		{
			name: "empty_slack_channel_id_rejected",
			channels: tenantNotificationChannelsModel{
				Email:                   types.StringValue("security@example.com"),
				SlackWebhookURL:         types.StringValue(""),
				TeamsWebhookURL:         types.StringValue(""),
				SlackNotificationMethod: types.StringNull(),
				SlackChannelID:          types.StringValue(""),
			},
			threatIntel:  testTenantThreatIntel(true, stepsecurityapi.ThreatIntelLevelVersion),
			developerMDM: testTenantDeveloperMDM(),
			expectError:  true,
		},
		{
			name: "subscribed_with_no_channel_warns",
			channels: tenantNotificationChannelsModel{
				Email:                   types.StringValue(""),
				SlackWebhookURL:         types.StringValue(""),
				TeamsWebhookURL:         types.StringValue(""),
				SlackNotificationMethod: types.StringNull(),
				SlackChannelID:          types.StringNull(),
			},
			threatIntel:   testTenantThreatIntel(false, stepsecurityapi.ThreatIntelLevelVersion),
			developerMDM:  testTenantDeveloperMDM("new_mcp_servers"),
			expectWarning: true,
		},
		{
			name: "nothing_subscribed_with_no_channel_is_fine",
			channels: tenantNotificationChannelsModel{
				Email:                   types.StringValue(""),
				SlackWebhookURL:         types.StringValue(""),
				TeamsWebhookURL:         types.StringValue(""),
				SlackNotificationMethod: types.StringNull(),
				SlackChannelID:          types.StringNull(),
			},
			threatIntel:  testTenantThreatIntel(false, stepsecurityapi.ThreatIntelLevelVersion),
			developerMDM: testTenantDeveloperMDM(),
		},
		{
			// An unknown channel may still resolve to a real destination, so it
			// must not trip the warning.
			name: "unknown_channel_defers_the_warning",
			channels: tenantNotificationChannelsModel{
				Email:                   types.StringUnknown(),
				SlackWebhookURL:         types.StringValue(""),
				TeamsWebhookURL:         types.StringValue(""),
				SlackNotificationMethod: types.StringNull(),
				SlackChannelID:          types.StringNull(),
			},
			threatIntel:  testTenantThreatIntel(true, stepsecurityapi.ThreatIntelLevelVersion),
			developerMDM: testTenantDeveloperMDM(),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			r := &tenantNotificationSettingsResource{}

			model := tenantNotificationSettingsModel{
				NotificationChannels: testTenantChannels(t, tc.channels),
				ThreatIntel:          tc.threatIntel,
				DeveloperMDM:         tc.developerMDM,
			}

			resp := &fwresource.ValidateConfigResponse{}
			r.ValidateConfig(ctx, fwresource.ValidateConfigRequest{
				Config: testTenantNotificationSettingsConfig(t, model),
			}, resp)

			assert.Equal(t, tc.expectError, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)
			assert.Equal(t, tc.expectWarning, resp.Diagnostics.WarningsCount() > 0, "diagnostics: %v", resp.Diagnostics)
		})
	}
}

func testTenantNotificationSettingsSchema(t *testing.T) resourceschema.Schema {
	t.Helper()

	resp := &fwresource.SchemaResponse{}
	NewTenantNotificationSettingsResource().Schema(context.Background(), fwresource.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError(), "Schema() returned errors: %v", resp.Diagnostics)

	return resp.Schema
}

func testTenantNotificationSettingsConfig(t *testing.T, model tenantNotificationSettingsModel) tfsdk.Config {
	t.Helper()

	schema := testTenantNotificationSettingsSchema(t)
	plan := tfsdk.Plan{Schema: schema}
	require.False(t, plan.Set(context.Background(), model).HasError())

	return tfsdk.Config{Raw: plan.Raw, Schema: schema}
}

func testTenantChannels(t *testing.T, channels tenantNotificationChannelsModel) types.Object {
	t.Helper()

	obj, diags := types.ObjectValueFrom(context.Background(), tenantNotificationChannelsAttrTypes, channels)
	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)

	return obj
}

func testTenantThreatIntel(enabled bool, level string) types.Object {
	return types.ObjectValueMust(tenantThreatIntelAttrTypes, map[string]attr.Value{
		"enabled": types.BoolValue(enabled),
		"level":   types.StringValue(level),
	})
}

// testTenantDeveloperMDM builds a developer_mdm object with the named events
// enabled and every other event disabled.
func testTenantDeveloperMDM(enabled ...string) types.Object {
	enabledSet := make(map[string]bool, len(enabled))
	for _, name := range enabled {
		enabledSet[name] = true
	}

	values := make(map[string]attr.Value, len(tenantDeveloperMDMEvents))
	for _, event := range tenantDeveloperMDMEvents {
		values[event.name] = types.BoolValue(enabledSet[event.name])
	}

	return types.ObjectValueMust(tenantDeveloperMDMAttrTypes, values)
}
