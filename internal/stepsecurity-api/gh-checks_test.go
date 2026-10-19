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

// The backend PUT only adds or overwrites checks and repos, so UpdatePRChecksConfig has to
// send the ones that are no longer wanted explicitly.
func TestUpdatePRChecksConfig_SendsFullDesiredState(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		requiredAll   bool
		expectedRepos map[string]CheckOptions
	}{
		{
			name:        "no_wildcard",
			requiredAll: false,
			expectedRepos: map[string]CheckOptions{
				"kept":    {RunRequiredChecks: true},
				"removed": {},
			},
		},
		{
			// With repos = ["*"], every repo missing from the request falls back to "*".
			name:        "required_wildcard",
			requiredAll: true,
			expectedRepos: map[string]CheckOptions{
				"kept":        {RunRequiredChecks: true},
				"removed":     {RunRequiredChecks: true},
				"already-off": {RunRequiredChecks: true},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			existing := GitHubPRChecksConfig{
				ChecksConfig: ChecksConfig{
					Checks: map[string]CheckConfig{
						"script_injection_check":           {Enabled: true, Type: "required"},
						"npm_package_recent_release_guard": {Enabled: true, Type: "optional", Settings: map[string]any{"cooldown_period_in_days": float64(3)}},
						"pwn_request_check":                {Enabled: false, Type: "optional"},
					},
				},
				Repos: map[string]CheckOptions{
					"kept":        {RunRequiredChecks: true},
					"removed":     {RunRequiredChecks: true, RunOptionalChecks: true},
					"already-off": {},
				},
			}

			var sent GitHubPRChecksConfig
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					require.NoError(t, json.NewEncoder(w).Encode(existing))
					return
				}
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.NoError(t, json.Unmarshal(body, &sent))
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(server.Close)

			client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}

			req := GitHubPRChecksConfig{
				ChecksConfig: ChecksConfig{
					Checks: map[string]CheckConfig{
						"script_injection_check": {Enabled: true, Type: "required"},
					},
					EnableBaselineCheckForAllNewRepos:  new(false),
					EnableRequiredChecksForAllNewRepos: new(tc.requiredAll),
					EnableOptionalChecksForAllNewRepos: new(false),
				},
				Repos: map[string]CheckOptions{
					"kept": {RunRequiredChecks: true},
				},
			}

			require.NoError(t, client.UpdatePRChecksConfig(context.Background(), "test-owner", req))

			// Controls missing from the request are disabled; already-disabled ones aren't resent.
			assert.Equal(t, map[string]CheckConfig{
				"script_injection_check":           {Enabled: true, Type: "required"},
				"npm_package_recent_release_guard": {Enabled: false, Type: "optional", Settings: map[string]any{"cooldown_period_in_days": float64(3)}},
			}, sent.Checks)
			assert.Equal(t, tc.expectedRepos, sent.Repos)

			// The caller builds Terraform state from req, so it must not be modified.
			assert.Len(t, req.Checks, 1)
			assert.Len(t, req.Repos, 1)
		})
	}
}
