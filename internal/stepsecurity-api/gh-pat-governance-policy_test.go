package stepsecurityapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The GET response carries the policy the org is evaluated with under
// "policy" and the org's own stored record under "org_policy". Terraform
// manages the org's own record, so that is what Get must return.
func TestGetPATGovernancePolicy_ReadsTheOrgsOwnRecord(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		response string
		want     *PATGovernancePolicy
	}{
		{
			// An org that follows the tenant policy: "policy" is the tenant's,
			// "org_policy" is null. The resource does not exist.
			name:     "no org policy, tenant policy shown as effective",
			response: `{"policy":{"enabled":true,"classic_max_age_days":30},"inherited":true,"has_org_policy":false,"use_tenant_policy":true,"org_policy":null}`,
			want:     nil,
		},
		{
			// An org with its own record set to follow the tenant policy:
			// "policy" is the tenant's, "org_policy" is the dormant own config.
			name:     "dormant org policy behind use_tenant_policy",
			response: `{"policy":{"enabled":true,"classic_max_age_days":30},"has_org_policy":true,"use_tenant_policy":true,"org_policy":{"enabled":true,"classic_max_age_days":90,"use_tenant_policy":true}}`,
			want:     &PATGovernancePolicy{Enabled: true, ClassicMaxAgeDays: 90, UseTenantPolicy: boolPtr(true)},
		},
		{
			name:     "own org policy in force",
			response: `{"policy":{"enabled":true,"flag_no_expiry":true,"classic_notify_on_revocation":false},"has_org_policy":true,"use_tenant_policy":false,"org_policy":{"enabled":true,"flag_no_expiry":true,"classic_notify_on_revocation":false}}`,
			want:     &PATGovernancePolicy{Enabled: true, FlagNoExpiry: true, ClassicNotifyOnRevocation: boolPtr(false)},
		},
		{
			// Older servers only return "policy", null when nothing is stored.
			name:     "legacy server, stored policy",
			response: `{"policy":{"enabled":true,"unused_days":180}}`,
			want:     &PATGovernancePolicy{Enabled: true, UnusedDays: 180},
		},
		{
			name:     "legacy server, nothing stored",
			response: `{"policy":null}`,
			want:     nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, "/v1/github/test-org/apps/pat-policy", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.response))
			}))
			defer server.Close()

			client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}
			got, err := client.GetPATGovernancePolicy(context.Background(), "test-org")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestUpdatePATGovernancePolicy_SendsEveryFieldAsTheAPISpellsIt(t *testing.T) {
	t.Parallel()

	var sent map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/v1/github/test-org/apps/pat-policy", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&sent))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"policy":{}}`))
	}))
	defer server.Close()

	zero := int64(0)
	client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}
	err := client.UpdatePATGovernancePolicy(context.Background(), "test-org", PATGovernancePolicy{
		Enabled:                                true,
		ClassicMaxAgeDays:                      60,
		ClassicUnusedDays:                      &zero,
		ClassicExpiryReminderDays:              []int64{0},
		ExpiryReminderTemplates:                map[string]map[string]PATReminderTemplate{"classic": {"7": {Subject: "s", Body: "b"}}},
		ExpiryReminderCC:                       []string{"security@example.com"},
		ExpiryReminderToOwner:                  true,
		OwnerEmailFallbackDomain:               "example.com",
		NotifyOnRevocation:                     true,
		FineGrainedNotifyOnRevocation:          boolPtr(false),
		RevocationNotificationTemplate:         &PATReminderTemplate{Subject: "rs", Body: "rb"},
		FineGrainedNoncompliantRevokeAfterDays: 3650,
		AutoRevokeAfterReminders:               true,
		ClassicAutoRevokeAfterReminders:        boolPtr(false),
		UseTenantPolicy:                        boolPtr(false),
	})
	require.NoError(t, err)

	// Wire names must match the agent-api PATPolicyConfig JSON tags exactly.
	for _, key := range []string{
		"enabled", "classic_max_age_days", "classic_unused_days", "classic_expiry_reminder_days",
		"expiry_reminder_templates", "expiry_reminder_cc", "expiry_reminder_to_owner",
		"owner_email_fallback_domain", "notify_on_revocation", "fine_grained_notify_on_revocation",
		"revocation_notification_template", "fine_grained_noncompliant_revoke_after_days",
		"auto_revoke_after_reminders", "classic_auto_revoke_after_reminders", "use_tenant_policy",
	} {
		assert.Contains(t, sent, key)
	}
	// A set pointer to zero/false is sent (it means "off for this class"),
	// while an unset pointer is omitted (it means "inherit").
	assert.JSONEq(t, `0`, string(sent["classic_unused_days"]))
	assert.JSONEq(t, `false`, string(sent["fine_grained_notify_on_revocation"]))
	assert.NotContains(t, sent, "classic_notify_on_revocation")
	assert.NotContains(t, sent, "fine_grained_auto_revoke_after_reminders")
	assert.NotContains(t, sent, "fine_grained_unused_days")
	assert.NotContains(t, sent, "updated_at")
	assert.JSONEq(t, `{"classic":{"7":{"subject":"s","body":"b"}}}`, string(sent["expiry_reminder_templates"]))
}

func TestDeletePATGovernancePolicy_UsesTheDeleteRoute(t *testing.T) {
	t.Parallel()

	var method, path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"deleted":true}`))
	}))
	defer server.Close()

	client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}
	require.NoError(t, client.DeletePATGovernancePolicy(context.Background(), "test-org"))
	assert.Equal(t, http.MethodDelete, method)
	assert.Equal(t, "/v1/github/test-org/apps/pat-policy", path)
}

func boolPtr(b bool) *bool { return &b }
