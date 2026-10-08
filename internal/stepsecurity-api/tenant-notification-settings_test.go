package stepsecurityapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThreatIntelNotificationOptions_Level(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		options       ThreatIntelNotificationOptions
		expectedLevel string
		expectEnabled bool
	}{
		{
			name:          "unsubscribed",
			options:       ThreatIntelNotificationOptions{},
			expectedLevel: "",
			expectEnabled: false,
		},
		{
			name:          "all",
			options:       ThreatIntelNotificationOptions{NotifyForAllIncidents: true},
			expectedLevel: ThreatIntelLevelAll,
			expectEnabled: true,
		},
		{
			name:          "name",
			options:       ThreatIntelNotificationOptions{NotifyOnPackageNameMatch: true},
			expectedLevel: ThreatIntelLevelName,
			expectEnabled: true,
		},
		{
			name:          "version",
			options:       ThreatIntelNotificationOptions{NotifyOnVersionMatch: true},
			expectedLevel: ThreatIntelLevelVersion,
			expectEnabled: true,
		},
		{
			// A record written outside Terraform can have several flags set. The
			// console resolves it as all > name > version, and so must this, or
			// the two would disagree about the same tenant.
			name: "several_flags_resolve_by_precedence",
			options: ThreatIntelNotificationOptions{
				NotifyForAllIncidents:    true,
				NotifyOnPackageNameMatch: true,
				NotifyOnVersionMatch:     true,
			},
			expectedLevel: ThreatIntelLevelAll,
			expectEnabled: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expectedLevel, tc.options.Level())
			assert.Equal(t, tc.expectEnabled, tc.options.Enabled())
		})
	}
}

func TestThreatIntelOptionsForLevel(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		enabled  bool
		level    string
		expected ThreatIntelNotificationOptions
	}{
		{
			name:     "disabled_clears_every_flag",
			enabled:  false,
			level:    ThreatIntelLevelAll,
			expected: ThreatIntelNotificationOptions{},
		},
		{
			name:     "all",
			enabled:  true,
			level:    ThreatIntelLevelAll,
			expected: ThreatIntelNotificationOptions{NotifyForAllIncidents: true},
		},
		{
			name:     "name",
			enabled:  true,
			level:    ThreatIntelLevelName,
			expected: ThreatIntelNotificationOptions{NotifyOnPackageNameMatch: true},
		},
		{
			name:     "version",
			enabled:  true,
			level:    ThreatIntelLevelVersion,
			expected: ThreatIntelNotificationOptions{NotifyOnVersionMatch: true},
		},
		{
			name:     "unrecognized_level_yields_no_subscription",
			enabled:  true,
			level:    "sometimes",
			expected: ThreatIntelNotificationOptions{},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			options := ThreatIntelOptionsForLevel(tc.enabled, tc.level)
			assert.Equal(t, tc.expected, options)

			// Every level must survive the round trip, otherwise a clean apply
			// would be followed by a non-empty plan.
			if tc.enabled && tc.expected != (ThreatIntelNotificationOptions{}) {
				assert.Equal(t, tc.level, options.Level())
			}
		})
	}
}

func TestGetTenantNotificationSettings(t *testing.T) {
	t.Parallel()

	const response = `{
		"customer": "test-customer",
		"email": "security@example.com",
		"slack_webhook_url": "https://hooks.slack.com/services/T/B/X",
		"teams_webhook_url": "",
		"slack_notification_method": "webhook",
		"slack_channel_id": "C0123456789",
		"slack_oauth_bot_token": "xoxb-super-secret",
		"threat_intel_notification_options": {
			"notify_on_package_name_match": true,
			"notify_on_version_match": false,
			"notify_for_all_incidents": false
		},
		"developer_mdm_notification_options": {
			"new_ides": {"enabled": true},
			"new_mcp_servers": {"enabled": true}
		}
	}`

	var requestPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)

	client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}

	settings, err := client.GetTenantNotificationSettings(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "/v1/application/customers/test-customer/notifications", requestPath)
	assert.Equal(t, "security@example.com", settings.Email)
	assert.Equal(t, "https://hooks.slack.com/services/T/B/X", settings.SlackWebhookURL)
	assert.Equal(t, "webhook", settings.SlackNotificationMethod)
	assert.Equal(t, "C0123456789", settings.SlackChannelID)
	assert.Equal(t, ThreatIntelLevelName, settings.ThreatIntel.Level())
	assert.True(t, settings.DeveloperMDM.NewIDEs.Enabled)
	assert.True(t, settings.DeveloperMDM.NewMCPServers.Enabled)
	assert.False(t, settings.DeveloperMDM.ConfigChanges.Enabled)

	// The response carries a Slack bot token; the settings type must have no
	// field to hold it, so it cannot reach Terraform state.
	raw, err := json.Marshal(settings)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "xoxb-super-secret")
}

// TestGetTenantNotificationSettings_EmptySentinel covers the legacy "empty"
// string some tenants have persisted where a channel belongs. Every backend
// consumer treats it as unset, so surfacing it would show a value no
// configuration could ever match.
func TestGetTenantNotificationSettings_EmptySentinel(t *testing.T) {
	t.Parallel()

	const response = `{
		"email": "empty",
		"slack_webhook_url": "EMPTY",
		"teams_webhook_url": "empty",
		"slack_channel_id": "empty"
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)

	client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}

	settings, err := client.GetTenantNotificationSettings(context.Background())
	require.NoError(t, err)

	assert.Empty(t, settings.Email)
	assert.Empty(t, settings.SlackWebhookURL)
	assert.Empty(t, settings.TeamsWebhookURL)
	assert.Empty(t, settings.SlackChannelID)
}

func TestUpdateTenantNotificationSettings(t *testing.T) {
	t.Parallel()

	var (
		requestPath  string
		requestQuery string
		requestBody  map[string]any
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		requestQuery = r.URL.RawQuery
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &requestBody))
		assert.Equal(t, http.MethodPut, r.Method)
		_, _ = w.Write([]byte(`{"message":"Notification settings updated successfully"}`))
	}))
	t.Cleanup(server.Close)

	client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}

	err := client.UpdateTenantNotificationSettings(context.Background(), TenantNotificationSettings{
		Email:        "security@example.com",
		ThreatIntel:  ThreatIntelOptionsForLevel(true, ThreatIntelLevelVersion),
		DeveloperMDM: DeveloperMDMNotificationOptions{SuspiciousFiles: DeveloperMDMEventSubscription{Enabled: true}},
	})
	require.NoError(t, err)

	assert.Equal(t, "/v1/application/customers/test-customer/notifications", requestPath)
	assert.Equal(t, "source=tenant", requestQuery)

	// The shared channels must always be present, even when empty, since the API
	// clears them from the request body rather than preserving them.
	assert.Contains(t, requestBody, "email")
	assert.Contains(t, requestBody, "slack_webhook_url")
	assert.Contains(t, requestBody, "teams_webhook_url")

	// These two are only honoured when non-empty, so an unset value is omitted
	// rather than sent as "" — which reads the same to the API but says what is
	// meant.
	assert.NotContains(t, requestBody, "slack_notification_method")
	assert.NotContains(t, requestBody, "slack_channel_id")
}

func TestDeleteTenantNotificationSettings(t *testing.T) {
	t.Parallel()

	var requestBody TenantNotificationSettings
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &requestBody))
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "source=tenant", r.URL.RawQuery)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}

	require.NoError(t, client.DeleteTenantNotificationSettings(context.Background()))

	assert.Empty(t, requestBody.Email)
	assert.Empty(t, requestBody.SlackWebhookURL)
	assert.Empty(t, requestBody.TeamsWebhookURL)
	assert.False(t, requestBody.ThreatIntel.Enabled())
	assert.Equal(t, DeveloperMDMNotificationOptions{}, requestBody.DeveloperMDM)
}
