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

// custom_workflow_paths is serialized without omitempty. The API keeps the stored
// folders when the key is missing, so removing them only works if the request
// carries an explicit empty list.

// captureCustomWorkflowPathsRequest records the first config POST and returns the
// raw control_settings.custom_workflow_paths value, and whether the key was present.
func captureCustomWorkflowPathsRequest(t *testing.T, paths []string) (json.RawMessage, bool) {
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
			CreatePR:            true,
			PinActionsToSHA:     true,
			CustomWorkflowPaths: paths,
		},
	}))
	require.NotNil(t, body, "no request was captured")

	var payload struct {
		ControlSettings map[string]json.RawMessage `json:"control_settings"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))

	raw, present := payload.ControlSettings["custom_workflow_paths"]
	return raw, present
}

func TestCreatePolicyDrivenPRPolicy_CustomWorkflowPathsAlwaysSent(t *testing.T) {
	testCases := []struct {
		name  string
		paths []string
		want  []string
	}{
		{name: "empty_slice_is_sent_as_empty_list", paths: []string{}, want: []string{}},
		{name: "paths_are_sent", paths: []string{"ci/workflows", "templates"}, want: []string{"ci/workflows", "templates"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			raw, present := captureCustomWorkflowPathsRequest(t, tc.paths)
			require.True(t, present, "custom_workflow_paths key must be present in control_settings")

			var got []string
			require.NoError(t, json.Unmarshal(raw, &got))
			require.NotNil(t, got, "custom_workflow_paths must be a list, got %s", raw)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGetPolicyDrivenPRPolicy_ReadsCustomWorkflowPaths(t *testing.T) {
	row := `{"full_repo_name":"org/repoA","policy_driven_pr_configuration":{"use_repo_level_config":true,"use_org_level_config":false,"control_checks_config":{"ActionsShouldBePinned":{"trigger_github_issue":false,"trigger_github_pr":true}},"trigger_github_alert":false,"trigger_pr_instead_of_issue":true,"control_settings":{"custom_workflow_paths":["ci/workflows","templates"]}}}`
	client := newConfigsClient(t, row)
	policy, err := client.GetPolicyDrivenPRPolicy(context.Background(), "org", []string{"repoA"})
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, []string{"ci/workflows", "templates"}, policy.AutoRemdiationOptions.CustomWorkflowPaths)
}
