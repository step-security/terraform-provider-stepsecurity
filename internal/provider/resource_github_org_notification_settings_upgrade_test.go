package provider

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackfillNotificationEventsPATToggles(t *testing.T) {
	t.Parallel()

	// A state written before the PAT toggles existed: every other value must
	// survive untouched and each toggle must come out as false.
	v0 := []byte(`{"id":"test-org","owner":"test-org","notification_events":{"domain_blocked":true,"required_check_failures":false,"pat_unused_violation":null},"notification_channels":{"email":{"email_addresses":["security@example.com"]}}}`)
	upgraded, err := backfillNotificationEventsPATToggles(v0)
	require.NoError(t, err)

	var state map[string]any
	require.NoError(t, json.Unmarshal(upgraded, &state))
	events := state["notification_events"].(map[string]any)
	for _, name := range notificationEventsPATToggles {
		assert.Equal(t, false, events[name], name)
	}
	assert.Equal(t, true, events["domain_blocked"])
	assert.Equal(t, false, events["required_check_failures"])
	assert.Equal(t, "test-org", state["owner"])
	assert.Equal(t, []any{"security@example.com"}, state["notification_channels"].(map[string]any)["email"].(map[string]any)["email_addresses"])

	// A toggle already present keeps its value.
	v1 := []byte(`{"notification_events":{"pat_expiry_reminder":true}}`)
	upgraded, err = backfillNotificationEventsPATToggles(v1)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(upgraded, &state))
	assert.Equal(t, true, state["notification_events"].(map[string]any)["pat_expiry_reminder"])
	assert.Equal(t, false, state["notification_events"].(map[string]any)["pat_max_age_violation"])

	// No notification_events block: returned as is.
	bare := []byte(`{"id":"test-org","notification_events":null}`)
	upgraded, err = backfillNotificationEventsPATToggles(bare)
	require.NoError(t, err)
	assert.JSONEq(t, string(bare), string(upgraded))

	_, err = backfillNotificationEventsPATToggles([]byte(`not json`))
	assert.Error(t, err)
}
