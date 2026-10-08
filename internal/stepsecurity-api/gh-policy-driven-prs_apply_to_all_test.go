package stepsecurityapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The [all] row is not proof of a wildcard policy. The console keeps it as the org
// template after "Apply to all repositories" is turned off, with its triggers intact,
// while the backend only fans it out to repos when apply_issue_pr_config_for_all_repos
// is set. These tests pin that import and refresh read the flag rather than the
// presence of triggers on [all].
//
// The rows below are the ones the API returned on int after selecting one repo,
// deselecting another, and leaving apply-to-all off.

const (
	allRowAppliedToAll    = `{"full_repo_name":"org/[all]","policy_driven_pr_configuration":{"use_repo_level_config":false,"use_org_level_config":true,"control_checks_config":{"GitHubHostedRunnerShouldBeHardened":{"trigger_github_issue":false,"trigger_github_pr":true}},"trigger_github_alert":false,"trigger_pr_instead_of_issue":true,"control_settings":{"apply_issue_pr_config_for_all_repos":true}}}`
	allRowNotAppliedToAll = `{"full_repo_name":"org/[all]","policy_driven_pr_configuration":{"use_repo_level_config":false,"use_org_level_config":true,"control_checks_config":{"GitHubHostedRunnerShouldBeHardened":{"trigger_github_issue":false,"trigger_github_pr":true}},"trigger_github_alert":false,"trigger_pr_instead_of_issue":true,"control_settings":{"apply_issue_pr_config_for_all_repos":false}}}`
	// allRowFlagAbsent has never had the flag written; the backend reads a missing flag as off.
	allRowFlagAbsent    = `{"full_repo_name":"org/[all]","policy_driven_pr_configuration":{"use_repo_level_config":false,"use_org_level_config":true,"control_checks_config":{"GitHubHostedRunnerShouldBeHardened":{"trigger_github_issue":false,"trigger_github_pr":true}},"trigger_github_alert":false,"trigger_pr_instead_of_issue":true,"control_settings":{}}}`
	repoRowDeselected   = `{"full_repo_name":"org/repoA","policy_driven_pr_configuration":{"use_repo_level_config":false,"use_org_level_config":false,"control_checks_config":null,"trigger_github_alert":false,"trigger_pr_instead_of_issue":false,"control_settings":{}}}`
	repoRowOrgSelected  = `{"full_repo_name":"org/repoB","policy_driven_pr_configuration":{"use_repo_level_config":false,"use_org_level_config":true,"control_checks_config":{"GitHubHostedRunnerShouldBeHardened":{"trigger_github_issue":false,"trigger_github_pr":true}},"trigger_github_alert":false,"trigger_pr_instead_of_issue":true,"control_settings":{"apply_issue_pr_config_for_all_repos":false}}}`
	repoRowRepoSelected = `{"full_repo_name":"org/repoC","policy_driven_pr_configuration":{"use_repo_level_config":true,"use_org_level_config":false,"control_checks_config":{"ActionsShouldBePinned":{"trigger_github_issue":false,"trigger_github_pr":true}},"trigger_github_alert":false,"trigger_pr_instead_of_issue":true,"control_settings":{"apply_issue_pr_config_for_all_repos":false}}}`
	// repoRowStaleTriggers keeps triggers but uses neither org nor repo config, so it is not part of the policy.
	repoRowStaleTriggers = `{"full_repo_name":"org/repoD","policy_driven_pr_configuration":{"use_repo_level_config":false,"use_org_level_config":false,"control_checks_config":{"GitHubHostedRunnerShouldBeHardened":{"trigger_github_issue":false,"trigger_github_pr":true}},"trigger_github_alert":false,"trigger_pr_instead_of_issue":true,"control_settings":{}}}`
)

// newConfigsClient returns a client whose config GETs all answer with the given rows,
// as the v2 endpoint does for [all]. Single-repo lookups filter the same list by name.
func newConfigsClient(t *testing.T, rows ...string) *APIClient {
	t.Helper()

	body := `{"repos":[`
	for i, row := range rows {
		if i > 0 {
			body += ","
		}
		body += row
	}
	body += `]}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected %s %s: reads must not write", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, "test-key", "test-customer")
	require.NoError(t, err)
	apiClient, ok := client.(*APIClient)
	require.True(t, ok, "expected the concrete APIClient")
	return apiClient
}

func TestDiscoverPolicyDrivenPRConfig_ApplyToAll(t *testing.T) {
	testCases := []struct {
		name          string
		rows          []string
		wantRepos     []string
		wantOrgLevel  bool
		wantHardening bool
	}{
		{
			// The reported case: [all] keeps its triggers after apply-to-all is turned
			// off, and only the repo that is still selected should be imported.
			name:          "apply_to_all_off_imports_selected_repos",
			rows:          []string{allRowNotAppliedToAll, repoRowDeselected, repoRowOrgSelected},
			wantRepos:     []string{"repoB"},
			wantOrgLevel:  false,
			wantHardening: true,
		},
		{
			name:          "apply_to_all_on_imports_wildcard",
			rows:          []string{allRowAppliedToAll, repoRowOrgSelected},
			wantRepos:     []string{"*"},
			wantOrgLevel:  true,
			wantHardening: true,
		},
		{
			name:          "flag_absent_is_not_wildcard",
			rows:          []string{allRowFlagAbsent, repoRowDeselected, repoRowOrgSelected},
			wantRepos:     []string{"repoB"},
			wantOrgLevel:  false,
			wantHardening: true,
		},
		{
			// Both org-config and repo-config selections count; a row with triggers but
			// neither flag set does not.
			name:          "selection_follows_level_flags",
			rows:          []string{allRowNotAppliedToAll, repoRowOrgSelected, repoRowRepoSelected, repoRowStaleTriggers},
			wantRepos:     []string{"repoB", "repoC"},
			wantOrgLevel:  false,
			wantHardening: true,
		},
		{
			name:      "nothing_selected_imports_nothing",
			rows:      []string{allRowNotAppliedToAll, repoRowDeselected, repoRowStaleTriggers},
			wantRepos: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newConfigsClient(t, tc.rows...)

			policy, err := client.DiscoverPolicyDrivenPRConfig(context.Background(), "org")
			require.NoError(t, err)
			require.NotNil(t, policy)

			assert.Equal(t, tc.wantRepos, policy.SelectedRepos)
			if tc.wantRepos == nil {
				return
			}
			assert.Equal(t, tc.wantOrgLevel, policy.UseOrgLevelConfig)
			assert.Equal(t, !tc.wantOrgLevel, policy.UseRepoLevelConfig)
			assert.Equal(t, tc.wantHardening, policy.AutoRemdiationOptions.HardenGitHubHostedRunner)
			assert.True(t, policy.AutoRemdiationOptions.CreatePR)
		})
	}
}

func TestGetPolicyDrivenPRPolicy_WildcardRequiresApplyToAll(t *testing.T) {
	t.Run("apply_to_all_on_reads_org_config", func(t *testing.T) {
		client := newConfigsClient(t, allRowAppliedToAll, repoRowOrgSelected)

		policy, err := client.GetPolicyDrivenPRPolicy(context.Background(), "org", []string{"*"})
		require.NoError(t, err)

		assert.True(t, policy.AutoRemdiationOptions.HardenGitHubHostedRunner)
		assert.True(t, policy.AutoRemdiationOptions.CreatePR)
		assert.True(t, policy.UseOrgLevelConfig)
		assert.False(t, policy.OrgConfigNotAppliedToAllRepos)
	})

	// Turning apply-to-all off outside Terraform has to read as drift: the org config
	// no longer reaches every repo, so nothing backs the wildcard.
	for name, allRow := range map[string]string{
		"apply_to_all_off_reads_as_not_configured": allRowNotAppliedToAll,
		"flag_absent_reads_as_not_configured":      allRowFlagAbsent,
	} {
		t.Run(name, func(t *testing.T) {
			client := newConfigsClient(t, allRow, repoRowOrgSelected)

			policy, err := client.GetPolicyDrivenPRPolicy(context.Background(), "org", []string{"*"})
			require.NoError(t, err)

			assert.Equal(t, AutoRemdiationOptions{}, policy.AutoRemdiationOptions)
			assert.True(t, policy.OrgConfigNotAppliedToAllRepos)
		})
	}

	// A disabled [all] row is not a policy the user would want to be warned about.
	t.Run("empty_all_row_does_not_warn", func(t *testing.T) {
		client := newConfigsClient(t,
			`{"full_repo_name":"org/[all]","policy_driven_pr_configuration":{"control_settings":{"apply_issue_pr_config_for_all_repos":false}}}`)

		policy, err := client.GetPolicyDrivenPRPolicy(context.Background(), "org", []string{"*"})
		require.NoError(t, err)

		assert.False(t, policy.OrgConfigNotAppliedToAllRepos)
	})
}

// Refresh of a specific-repo selection reads each repo's own row and never consults
// [all], so a leftover [all] row must not change it.
func TestGetPolicyDrivenPRPolicy_SpecificReposIgnoreAllRow(t *testing.T) {
	for _, allRow := range []string{allRowAppliedToAll, allRowNotAppliedToAll} {
		client := newConfigsClient(t, allRow, repoRowRepoSelected)

		policy, err := client.GetPolicyDrivenPRPolicy(context.Background(), "org", []string{"repoC"})
		require.NoError(t, err)

		assert.True(t, policy.AutoRemdiationOptions.PinActionsToSHA)
		assert.False(t, policy.AutoRemdiationOptions.HardenGitHubHostedRunner)
		assert.True(t, policy.UseRepoLevelConfig)
		assert.False(t, policy.OrgConfigNotAppliedToAllRepos)
	}
}
