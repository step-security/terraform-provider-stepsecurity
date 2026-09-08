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

func TestOrgThreatIntelLevelFor(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		enabled  bool
		level    string
		expected string
	}{
		{name: "all", enabled: true, level: ThreatIntelLevelAll, expected: "all"},
		{name: "name", enabled: true, level: ThreatIntelLevelName, expected: "name"},
		{name: "version", enabled: true, level: ThreatIntelLevelVersion, expected: "version"},
		{
			// An empty level would read back as opted in, so disabling has to
			// write the explicit opt-out.
			name:     "disabled_writes_off",
			enabled:  false,
			level:    ThreatIntelLevelVersion,
			expected: OrgThreatIntelLevelOff,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, OrgThreatIntelLevelFor(tc.enabled, tc.level))
		})
	}
}

func TestOrgThreatIntelSubscription(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		stored          string
		priorLevel      string
		expectedEnabled bool
		expectedLevel   string
	}{
		{
			name:            "all",
			stored:          "all",
			priorLevel:      ThreatIntelLevelAll,
			expectedEnabled: true,
			expectedLevel:   ThreatIntelLevelAll,
		},
		{
			name:            "version",
			stored:          "version",
			priorLevel:      ThreatIntelLevelAll,
			expectedEnabled: true,
			expectedLevel:   ThreatIntelLevelVersion,
		},
		{
			// A disabled org has no stored granularity, so the configured one has
			// to survive the refresh.
			name:            "off_keeps_the_prior_level",
			stored:          OrgThreatIntelLevelOff,
			priorLevel:      ThreatIntelLevelName,
			expectedEnabled: false,
			expectedLevel:   ThreatIntelLevelName,
		},
		{
			// Org threat intel is opt-out: an org that never configured it is
			// notified about everything.
			name:            "unset_defaults_to_enabled_at_all",
			stored:          "",
			priorLevel:      ThreatIntelLevelVersion,
			expectedEnabled: true,
			expectedLevel:   ThreatIntelLevelAll,
		},
		{
			name:            "unrecognized_defaults_to_enabled_at_all",
			stored:          "sometimes",
			priorLevel:      ThreatIntelLevelVersion,
			expectedEnabled: true,
			expectedLevel:   ThreatIntelLevelAll,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enabled, level := OrgThreatIntelSubscription(tc.stored, tc.priorLevel)
			assert.Equal(t, tc.expectedEnabled, enabled)
			assert.Equal(t, tc.expectedLevel, level)
		})
	}
}

// TestDeleteNotificationSettingsOptsOutOfThreatIntel pins the one field where
// clearing is wrong: threat intel is opt-out, so a destroy that left the level
// empty would leave the org notified about every incident.
func TestDeleteNotificationSettingsOptsOutOfThreatIntel(t *testing.T) {
	t.Parallel()

	var request GitHubNotificationSettingsRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &request))
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}

	require.NoError(t, client.DeleteNotificationSettings(context.Background(), "test-owner"))

	assert.Equal(t, OrgThreatIntelLevelOff, request.OrgThreatIntelLevel)
	assert.Equal(t, "false", request.NotifyForCompromisedNPMInPR)
	assert.Equal(t, "false", request.NotifyForCompromisedPyPIInPR)
	assert.Equal(t, "false", request.NotifyForCompromisedActionInWorkflow)
}
