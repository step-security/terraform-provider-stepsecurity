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

// skip_immutable_release_tags carries omitempty. The API only updates the stored
// value when the key is sent, so a nil pointer must leave the key out, and false
// must still be sent so the setting can be turned off.

// captureSkipImmutableRequest records the first config POST and returns the raw
// control_settings.skip_immutable_release_tags value, and whether the key was present.
func captureSkipImmutableRequest(t *testing.T, skip *bool) (json.RawMessage, bool) {
	t.Helper()

	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body == nil {
			b, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			body = b
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-key", "test-customer")
	require.NoError(t, err)
	apiClient, ok := client.(*APIClient)
	require.True(t, ok, "expected the concrete APIClient")

	require.NoError(t, apiClient.CreatePolicyDrivenPRPolicy(context.Background(), PolicyDrivenPRPolicy{
		Owner:              "example-org",
		SelectedRepos:      []string{"example-repo"},
		UseRepoLevelConfig: true,
		AutoRemdiationOptions: AutoRemdiationOptions{
			CreatePR:                 true,
			PinActionsToSHA:          true,
			SkipImmutableReleaseTags: skip,
		},
	}))
	require.NotNil(t, body, "no request was captured")

	var payload struct {
		ControlSettings map[string]json.RawMessage `json:"control_settings"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))

	raw, present := payload.ControlSettings["skip_immutable_release_tags"]
	return raw, present
}

func TestCreatePolicyDrivenPRPolicy_SkipImmutableReleaseTags(t *testing.T) {
	on, off := true, false
	testCases := []struct {
		name        string
		skip        *bool
		wantPresent bool
		want        bool
	}{
		{name: "unset_is_left_out", skip: nil, wantPresent: false},
		{name: "true_is_sent", skip: &on, wantPresent: true, want: true},
		{name: "false_is_sent", skip: &off, wantPresent: true, want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			raw, present := captureSkipImmutableRequest(t, tc.skip)
			require.Equal(t, tc.wantPresent, present, "skip_immutable_release_tags key presence")
			if !tc.wantPresent {
				return
			}
			var got bool
			require.NoError(t, json.Unmarshal(raw, &got))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGetPolicyDrivenPRPolicy_ReadsSkipImmutableReleaseTags(t *testing.T) {
	testCases := []struct {
		name string
		row  string
		want *bool
	}{
		{
			name: "set",
			row:  `{"full_repo_name":"org/repoA","policy_driven_pr_configuration":{"use_repo_level_config":true,"use_org_level_config":false,"control_checks_config":{"ActionsShouldBePinned":{"trigger_github_issue":false,"trigger_github_pr":true}},"trigger_github_alert":false,"trigger_pr_instead_of_issue":true,"control_settings":{"skip_immutable_release_tags":true}}}`,
			want: func() *bool { b := true; return &b }(),
		},
		{
			name: "absent",
			row:  `{"full_repo_name":"org/repoA","policy_driven_pr_configuration":{"use_repo_level_config":true,"use_org_level_config":false,"control_checks_config":{"ActionsShouldBePinned":{"trigger_github_issue":false,"trigger_github_pr":true}},"trigger_github_alert":false,"trigger_pr_instead_of_issue":true,"control_settings":{}}}`,
			want: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newConfigsClient(t, tc.row)
			policy, err := client.GetPolicyDrivenPRPolicy(context.Background(), "org", []string{"repoA"})
			require.NoError(t, err)
			require.NotNil(t, policy)
			assert.Equal(t, tc.want, policy.AutoRemdiationOptions.SkipImmutableReleaseTags)
		})
	}
}
