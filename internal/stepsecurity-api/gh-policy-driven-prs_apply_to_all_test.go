package stepsecurityapi

import (
	"context"
	"fmt"
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
	// repoRowRepoSelectedSameAsB has its own repo-level config with repoB's settings.
	repoRowRepoSelectedSameAsB = `{"full_repo_name":"org/repoE","policy_driven_pr_configuration":{"use_repo_level_config":true,"use_org_level_config":false,"control_checks_config":{"GitHubHostedRunnerShouldBeHardened":{"trigger_github_issue":false,"trigger_github_pr":true}},"trigger_github_alert":false,"trigger_pr_instead_of_issue":true,"control_settings":{}}}`
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
			// Org-config and repo-config selections both count when their settings
			// match; a row with triggers but neither flag set does not.
			name:          "matching_org_and_repo_level_selections_import_together",
			rows:          []string{allRowNotAppliedToAll, repoRowOrgSelected, repoRowRepoSelectedSameAsB, repoRowStaleTriggers},
			wantRepos:     []string{"repoB", "repoE"},
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

// One resource sends one set of settings to every repo it selects. Importing repos
// whose settings differ into one resource would overwrite all but one group on the
// next apply, so import has to refuse instead of picking one repo's settings.
func TestDiscoverPolicyDrivenPRConfig_MixedSettings(t *testing.T) {
	t.Run("different_controls_fail_import", func(t *testing.T) {
		client := newConfigsClient(t, allRowNotAppliedToAll, repoRowOrgSelected, repoRowRepoSelected, repoRowRepoSelectedSameAsB)

		_, err := client.DiscoverPolicyDrivenPRConfig(context.Background(), "org")
		require.Error(t, err)

		msg := err.Error()
		assert.Contains(t, msg, "do not all have the same policy-driven PR settings")
		assert.Contains(t, msg, "  - repoB, repoE: create_pr, harden_github_hosted_runner\n")
		assert.Contains(t, msg, "  - repoC: create_pr, pin_actions_to_sha\n")
		assert.Contains(t, msg, "declare one stepsecurity_policy_driven_pr resource per group")
	})

	// Two repos with the same enabled controls can still differ in their lists.
	t.Run("different_exemptions_fail_import", func(t *testing.T) {
		client := newConfigsClient(t,
			`{"full_repo_name":"org/r1","policy_driven_pr_configuration":{"use_repo_level_config":true,"control_checks_config":{"ActionsShouldBePinned":{"trigger_github_pr":true}},"trigger_pr_instead_of_issue":true,"control_settings":{"exempted_actions":["actions/checkout"]}}}`,
			`{"full_repo_name":"org/r2","policy_driven_pr_configuration":{"use_repo_level_config":true,"control_checks_config":{"ActionsShouldBePinned":{"trigger_github_pr":true}},"trigger_pr_instead_of_issue":true,"control_settings":{"exempted_actions":["actions/setup-node"]}}}`,
		)

		_, err := client.DiscoverPolicyDrivenPRConfig(context.Background(), "org")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "  - r1: create_pr, pin_actions_to_sha\n")
		assert.Contains(t, err.Error(), "  - r2: create_pr, pin_actions_to_sha\n")
	})

	// List order, and an absent versus an empty list or map, mean the same to the API,
	// so they must not split repos with the same settings into separate groups.
	t.Run("order_and_empty_values_do_not_split_groups", func(t *testing.T) {
		client := newConfigsClient(t,
			`{"full_repo_name":"org/r1","policy_driven_pr_configuration":{"use_repo_level_config":true,"control_checks_config":{"ActionsShouldBePinned":{"trigger_github_pr":true}},"trigger_pr_instead_of_issue":true,"control_settings":{"exempted_actions":["a/x","b/y"],"labels_to_replace":{},"package_ecosystem":[{"package":"pip","interval":"weekly"},{"package":"npm","interval":"daily"}]}}}`,
			`{"full_repo_name":"org/r2","policy_driven_pr_configuration":{"use_org_level_config":true,"control_checks_config":{"ActionsShouldBePinned":{"trigger_github_pr":true}},"trigger_pr_instead_of_issue":true,"control_settings":{"exempted_actions":["b/y","a/x"],"package_ecosystem":[{"package":"npm","interval":"daily"},{"package":"pip","interval":"weekly"}],"apply_issue_pr_config_for_all_repos":false}}}`,
		)

		policy, err := client.DiscoverPolicyDrivenPRConfig(context.Background(), "org")
		require.NoError(t, err)
		assert.Equal(t, []string{"r1", "r2"}, policy.SelectedRepos)
		assert.True(t, policy.AutoRemdiationOptions.PinActionsToSHA)
	})

	// Large orgs must still get a readable error.
	t.Run("long_groups_are_truncated", func(t *testing.T) {
		rows := []string{repoRowRepoSelected}
		for i := range 15 {
			rows = append(rows, fmt.Sprintf(`{"full_repo_name":"org/h%02d","policy_driven_pr_configuration":{"use_org_level_config":true,"control_checks_config":{"GitHubHostedRunnerShouldBeHardened":{"trigger_github_pr":true}},"trigger_pr_instead_of_issue":true}}`, i))
		}
		client := newConfigsClient(t, rows...)

		_, err := client.DiscoverPolicyDrivenPRConfig(context.Background(), "org")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "h09 and 5 more: create_pr, harden_github_hosted_runner\n")
		assert.NotContains(t, err.Error(), "h10")
	})

	// A wildcard policy is one set of settings by definition, whatever repo rows hold.
	t.Run("apply_to_all_on_ignores_repo_rows", func(t *testing.T) {
		client := newConfigsClient(t, allRowAppliedToAll, repoRowOrgSelected, repoRowRepoSelected)

		policy, err := client.DiscoverPolicyDrivenPRConfig(context.Background(), "org")
		require.NoError(t, err)
		assert.Equal(t, []string{"*"}, policy.SelectedRepos)
	})
}
