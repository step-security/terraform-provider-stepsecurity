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

// dockerfile_patterns is serialized without omitempty. The API keeps the stored
// patterns when the key is missing, so removing them only works if the request
// carries an explicit empty list. These tests check the raw JSON, where the
// difference between a missing key and an empty list still exists.

// captureDockerfilePatternsRequest records the first config POST and returns the
// raw control_settings.dockerfile_patterns value, and whether the key was present.
func captureDockerfilePatternsRequest(t *testing.T, patterns []string) (json.RawMessage, bool) {
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
			CreatePR:           true,
			SecureDockerFile:   true,
			DockerfilePatterns: patterns,
		},
	}))
	require.NotNil(t, body, "no request was captured")

	var payload struct {
		ControlSettings map[string]json.RawMessage `json:"control_settings"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))

	raw, present := payload.ControlSettings["dockerfile_patterns"]
	return raw, present
}

func TestCreatePolicyDrivenPRPolicy_DockerfilePatternsAlwaysSent(t *testing.T) {
	testCases := []struct {
		name     string
		patterns []string
		want     []string
	}{
		{
			// The clearing case: removing the attribute sends an empty list.
			name:     "empty_slice_is_sent_as_empty_list",
			patterns: []string{},
			want:     []string{},
		},
		{
			name:     "patterns_are_sent",
			patterns: []string{"Dockerfile.*", "Containerfile"},
			want:     []string{"Dockerfile.*", "Containerfile"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			raw, present := captureDockerfilePatternsRequest(t, tc.patterns)
			require.True(t, present, "dockerfile_patterns key must be present in control_settings")

			var got []string
			require.NoError(t, json.Unmarshal(raw, &got))
			require.NotNil(t, got, "dockerfile_patterns must be a list, got %s", raw)
			assert.Equal(t, tc.want, got)
		})
	}
}
