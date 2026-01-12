package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// PolicyDrivenPRPolicy represents the Terraform resource model
type PolicyDrivenPRPolicy struct {
	Owner                 string                              `json:"owner"`
	AutoRemdiationOptions AutoRemdiationOptions               `json:"auto_remediation_options"`
	SelectedRepos         []string                            `json:"selected_repos"`
	SelectedReposFilter   ApplyIssuePRConfigForAllReposFilter `json:"selected_repos_filter"`
	UseRepoLevelConfig    bool                                `json:"use_repo_level_config"`
	UseOrgLevelConfig     bool                                `json:"use_org_level_config"`
}

type AutoRemdiationOptions struct {
	CreatePR                                bool               `json:"create_pr"`
	CreateIssue                             bool               `json:"create_issue"`
	CreateGitHubAdvancedSecurityAlert       bool               `json:"create_github_advanced_security_alert"`
	HardenGitHubHostedRunner                bool               `json:"harden_github_hosted_runner"`
	PinActionsToSHA                         bool               `json:"pin_actions_to_sha"`
	RestrictGitHubTokenPermissions          bool               `json:"restrict_github_token_permissions"`
	SecureDockerFile                        bool               `json:"secure_docker_file"`
	ActionsToExemptWhilePinning             []string           `json:"actions_to_exempt_while_pinning"`
	ImagesToExemptWhilePinning              []string           `json:"images_to_exempt_while_pinning"`
	ActionsToReplaceWithStepSecurityActions []string           `json:"actions_to_replace_with_step_security_actions"`
	UpdatePrecommitFile                     []string           `json:"update_precommit_file,omitempty"`
	PackageEcosystem                        []DependabotConfig `json:"package_ecosystem,omitempty"`
	AddWorkflows                            string             `json:"add_workflows,omitempty"`
	ActionCommitMap                         map[string]string  `json:"action_commit_map"`
}

// API request/response structures matching agent-api
type policyDrivenPRConfigOptions struct {
	UseRepoLevelConfig      *bool                       `json:"use_repo_level_config,omitempty"`
	UseOrgLevelConfig       *bool                       `json:"use_org_level_config,omitempty"`
	ControlChecksConfig     *controlChecksFeatureConfig `json:"control_checks_config,omitempty"`
	TriggerGithubAlert      *bool                       `json:"trigger_github_alert,omitempty"`
	TriggerPRInsteadOfIssue *bool                       `json:"trigger_pr_instead_of_issue,omitempty"`
	ControlSettings         *controlSettings            `json:"control_settings,omitempty"`
}

type controlChecksFeatureConfig map[string]issuePRConfig

type issuePRConfig struct {
	TriggerGithubIssue bool `json:"trigger_github_issue"`
	TriggerGithubPr    bool `json:"trigger_github_pr"`
}

type controlSettings struct {
	ExemptedActions                     []string                             `json:"exempted_actions,omitempty"`
	ActionsToReplace                    map[string]string                    `json:"actions_to_replace,omitempty"`
	UpdatePrecommitFile                 map[string]bool                      `json:"update_precommit_file,omitempty"`
	PackageEcosystem                    []DependabotConfig                   `json:"package_ecosystem,omitempty"`
	AddWorkflows                        string                               `json:"add_workflows,omitempty"`
	ApplyIssuePRConfigForAllRepos       *bool                                `json:"apply_issue_pr_config_for_all_repos,omitempty"`
	ApplyIssuePRConfigForAllReposFilter *ApplyIssuePRConfigForAllReposFilter `json:"apply_issue_pr_config_for_all_repos_filter,omitempty"`
	ActionCommitMap                     map[string]string                    `json:"action_commit_map"`
	ExemptedImages                      []string                             `json:"exempted_images,omitempty"`
}

type ApplyIssuePRConfigForAllReposFilter struct {
	ReposTopics []string `json:"repos_topics,omitempty"`
}

type DependabotConfig struct {
	Package  string `json:"package"`
	Interval string `json:"interval"`
}

type featureConfigResponse struct {
	FullRepoName                string                 `json:"full_repo_name"`
	PolicyDrivenPRConfiguration policyDrivenPRInternal `json:"policy_driven_pr_configuration"`
}

type policyDrivenPRInternal struct {
	UseRepoLevelConfig      bool                       `json:"use_repo_level_config"`
	UseOrgLevelConfig       bool                       `json:"use_org_level_config"`
	ControlChecksConfig     controlChecksFeatureConfig `json:"control_checks_config"`
	TriggerGithubAlert      bool                       `json:"trigger_github_alert"`
	TriggerPRInsteadOfIssue bool                       `json:"trigger_pr_instead_of_issue"`
	ControlSettings         controlSettings            `json:"control_settings,omitempty"`
}

func (c *APIClient) CreatePolicyDrivenPRPolicy(ctx context.Context, createRequest PolicyDrivenPRPolicy) error {
	tflog.Info(ctx, "Creating policy-driven PR policy", map[string]interface{}{
		"owner":                 createRequest.Owner,
		"selected_repos":        createRequest.SelectedRepos,
		"use_repo_level_config": createRequest.UseRepoLevelConfig,
		"use_org_level_config":  createRequest.UseOrgLevelConfig,
	})

	// Convert update_precommit_file from array to map
	updatePrecommitFileMap := make(map[string]bool)
	for _, file := range createRequest.AutoRemdiationOptions.UpdatePrecommitFile {
		updatePrecommitFileMap[file] = true
	}

	// Build actions to replace map
	actionsToReplace := make(map[string]string)
	for _, action := range createRequest.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions {
		actionsToReplace[action] = ""
	}

	// Build control checks config
	controlChecksConfig := make(controlChecksFeatureConfig)
	createPR := createRequest.AutoRemdiationOptions.CreatePR
	createIssue := createRequest.AutoRemdiationOptions.CreateIssue

	if createRequest.AutoRemdiationOptions.HardenGitHubHostedRunner {
		controlChecksConfig["GitHubHostedRunnerShouldBeHardened"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if createRequest.AutoRemdiationOptions.PinActionsToSHA {
		controlChecksConfig["ActionsShouldBePinned"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if createRequest.AutoRemdiationOptions.RestrictGitHubTokenPermissions {
		controlChecksConfig["GithubTokenShouldHaveMinPermission"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if createRequest.AutoRemdiationOptions.SecureDockerFile {
		controlChecksConfig["SecureDockerFile"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if len(createRequest.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions) > 0 {
		controlChecksConfig["MaintainedGitHubActionsShouldBeUsed"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if len(createRequest.AutoRemdiationOptions.UpdatePrecommitFile) > 0 {
		controlChecksConfig["UpdatePrecommitFile"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if len(createRequest.AutoRemdiationOptions.PackageEcosystem) > 0 {
		controlChecksConfig["UpdateDependabotFile"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if createRequest.AutoRemdiationOptions.AddWorkflows != "" {
		controlChecksConfig["AddWorkflows"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	// Build control settings
	// ApplyIssuePRConfigForAllRepos should only be true when applying org-level config to ALL repos (wildcard)
	// When applying org-level config to specific repos, it should be false
	hasWildcard := len(createRequest.SelectedRepos) == 1 && createRequest.SelectedRepos[0] == "*"
	applyToAllRepos := createRequest.UseOrgLevelConfig && hasWildcard
	cs := &controlSettings{
		ExemptedActions:                     createRequest.AutoRemdiationOptions.ActionsToExemptWhilePinning,
		ActionsToReplace:                    actionsToReplace,
		UpdatePrecommitFile:                 updatePrecommitFileMap,
		PackageEcosystem:                    createRequest.AutoRemdiationOptions.PackageEcosystem,
		AddWorkflows:                        createRequest.AutoRemdiationOptions.AddWorkflows,
		ActionCommitMap:                     createRequest.AutoRemdiationOptions.ActionCommitMap,
		ExemptedImages:                      createRequest.AutoRemdiationOptions.ImagesToExemptWhilePinning,
		ApplyIssuePRConfigForAllRepos:       &applyToAllRepos,
		ApplyIssuePRConfigForAllReposFilter: &createRequest.SelectedReposFilter,
	}

	useRepoLevel := createRequest.UseRepoLevelConfig
	useOrgLevel := createRequest.UseOrgLevelConfig
	triggerAlert := createRequest.AutoRemdiationOptions.CreateGitHubAdvancedSecurityAlert
	triggerPR := createPR

	// Build the config options
	configOptions := policyDrivenPRConfigOptions{
		UseRepoLevelConfig:      &useRepoLevel,
		UseOrgLevelConfig:       &useOrgLevel,
		ControlChecksConfig:     &controlChecksConfig,
		TriggerGithubAlert:      &triggerAlert,
		TriggerPRInsteadOfIssue: &triggerPR,
		ControlSettings:         cs,
	}

	// Handle different scenarios based on config level and selected repos
	if createRequest.UseOrgLevelConfig && hasWildcard {
		// For org-level config with wildcard, use [all] endpoint to apply to all repos
		return c.updateConfigForRepo(ctx, createRequest.Owner, "[all]", configOptions)
	}

	// For org-level config with specific repos OR repo-level config, apply to each specific repo
	for _, repo := range createRequest.SelectedRepos {
		if err := c.updateConfigForRepo(ctx, createRequest.Owner, repo, configOptions); err != nil {
			return fmt.Errorf("failed to update config for repo %s: %w", repo, err)
		}
	}

	return nil
}

func (c *APIClient) updateConfigForRepo(ctx context.Context, owner string, repo string, config policyDrivenPRConfigOptions) error {
	URI := fmt.Sprintf("%s/v1/github/%s/%s/policy-driven-pr/configs", c.BaseURL, owner, repo)

	uuid, err := uuid.GenerateUUID()
	if err != nil {
		return fmt.Errorf("error getting async event id: %w", err)
	}
	httpHeaders := map[string]string{
		"x-async-event-id": uuid,
	}

	// First attempt
	_, err = c.post(ctx, URI, config, WithHttpHeaders(httpHeaders))
	if err == nil {
		return nil
	}

	// If it's not a 503, fail immediately
	if !strings.Contains(err.Error(), "status: 503") {
		return fmt.Errorf("failed to update config for repo: %w", err)
	}

	// when status = 503 retry same request until it is completed or retry count is exhausted
	timeoutTimer := time.NewTimer(3 * time.Minute)
	periodicTicker := time.NewTicker(10 * time.Second) // poll for every 10 seconds
	defer func() {
		timeoutTimer.Stop()
		periodicTicker.Stop()
	}()

	type retryResp struct {
		Status int    `json:"status"`
		State  string `json:"state"` // in_progress, completed
		Data   any    `json:"data"`
	}

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while retrying update config for repo: %w", ctx.Err())
		case <-timeoutTimer.C:
			return fmt.Errorf("timeout exceeded while updating config for repo")
		case <-periodicTicker.C:
			response, err1 := c.post(ctx, URI, config, WithHttpHeaders(httpHeaders))
			if err1 != nil {
				return fmt.Errorf("failed to update config for repo: %w", err)
			}

			var resp retryResp
			err2 := json.Unmarshal(response, &resp)
			if err2 != nil {
				return fmt.Errorf("failed to update config for repo: %w", err)
			}

			if resp.State == "completed" {
				// check if status code is not 200 and return original error
				if resp.Status != 200 {
					return fmt.Errorf("failed to update config for repo: %w", err)
				}
				return nil
			}
		}
	}

}

func (c *APIClient) GetPolicyDrivenPRPolicy(ctx context.Context, owner string, repos []string) (*PolicyDrivenPRPolicy, error) {
	policy := &PolicyDrivenPRPolicy{
		Owner: owner,
	}

	if len(repos) == 0 {
		return policy, nil
	}

	tflog.Info(ctx, "Reading policy-driven PR policy", map[string]interface{}{
		"owner": owner,
		"repos": repos,
	})

	// Determine if this is org-level or repo-level based on repos parameter
	isOrgLevel := len(repos) > 0 && repos[0] == "*"

	var selectedConfig policyDrivenPRInternal
	var configFound bool

	if isOrgLevel {
		// Query org-level config
		config, err := c.getConfigForRepo(ctx, owner, "[all]")
		if err != nil {
			return policy, fmt.Errorf("failed to get org-level config: %w", err)
		}

		if config != nil && isConfigEnabled(*config) {
			selectedConfig = *config
			configFound = true
		}
	} else {
		// Query each repo individually for repo-level config
		// Use first repo's config as the template (all should be the same)
		for _, repo := range repos {
			config, err := c.getConfigForRepo(ctx, owner, repo)
			if err != nil {
				tflog.Warn(ctx, "Failed to get config for repo", map[string]interface{}{
					"repo":  repo,
					"error": err.Error(),
				})
				continue
			}

			if config != nil && isConfigEnabled(*config) {
				selectedConfig = *config
				configFound = true
				break
			}
		}
	}

	if !configFound {
		// No enabled configs found
		tflog.Info(ctx, "No enabled configs found", map[string]interface{}{
			"owner": owner,
			"repos": repos,
		})
		return policy, nil
	}

	// Extract feature flags from config
	enabledHardenRunner := selectedConfig.ControlChecksConfig["GitHubHostedRunnerShouldBeHardened"].TriggerGithubIssue ||
		selectedConfig.ControlChecksConfig["GitHubHostedRunnerShouldBeHardened"].TriggerGithubPr
	enabledPinning := selectedConfig.ControlChecksConfig["ActionsShouldBePinned"].TriggerGithubIssue ||
		selectedConfig.ControlChecksConfig["ActionsShouldBePinned"].TriggerGithubPr
	enabledTokenPermissions := selectedConfig.ControlChecksConfig["GithubTokenShouldHaveMinPermission"].TriggerGithubIssue ||
		selectedConfig.ControlChecksConfig["GithubTokenShouldHaveMinPermission"].TriggerGithubPr
	enabledSecureDocker := selectedConfig.ControlChecksConfig["SecureDockerFile"].TriggerGithubIssue ||
		selectedConfig.ControlChecksConfig["SecureDockerFile"].TriggerGithubPr

	// Extract actions to replace
	actionsToReplace := []string{}
	for action := range selectedConfig.ControlSettings.ActionsToReplace {
		actionsToReplace = append(actionsToReplace, action)
	}

	// Convert update_precommit_file from map to array
	updatePrecommitFiles := []string{}
	for file := range selectedConfig.ControlSettings.UpdatePrecommitFile {
		updatePrecommitFiles = append(updatePrecommitFiles, file)
	}

	// Set policy fields - repos will be set by the caller based on state
	policy.UseRepoLevelConfig = !isOrgLevel
	policy.UseOrgLevelConfig = isOrgLevel
	policy.AutoRemdiationOptions = AutoRemdiationOptions{
		CreatePR:                                selectedConfig.TriggerPRInsteadOfIssue,
		CreateIssue:                             !selectedConfig.TriggerPRInsteadOfIssue,
		CreateGitHubAdvancedSecurityAlert:       selectedConfig.TriggerGithubAlert,
		HardenGitHubHostedRunner:                enabledHardenRunner,
		PinActionsToSHA:                         enabledPinning,
		RestrictGitHubTokenPermissions:          enabledTokenPermissions,
		SecureDockerFile:                        enabledSecureDocker,
		ActionsToExemptWhilePinning:             selectedConfig.ControlSettings.ExemptedActions,
		ImagesToExemptWhilePinning:              selectedConfig.ControlSettings.ExemptedImages,
		ActionsToReplaceWithStepSecurityActions: actionsToReplace,
		UpdatePrecommitFile:                     updatePrecommitFiles,
		PackageEcosystem:                        selectedConfig.ControlSettings.PackageEcosystem,
		AddWorkflows:                            selectedConfig.ControlSettings.AddWorkflows,
	}

	// Populate SelectedReposFilter from API response
	if selectedConfig.ControlSettings.ApplyIssuePRConfigForAllReposFilter != nil {
		policy.SelectedReposFilter = *selectedConfig.ControlSettings.ApplyIssuePRConfigForAllReposFilter
	}

	return policy, nil
}

// getConfigForRepo queries repo's config
func (c *APIClient) getConfigForRepo(ctx context.Context, owner string, repo string) (*policyDrivenPRInternal, error) {
	URI := fmt.Sprintf("%s/v1/github/%s/%s/policy-driven-pr/configs", c.BaseURL, owner, repo)
	respBody, err := c.get(ctx, URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get config for repo %s: %w", repo, err)
	}

	var configs []featureConfigResponse
	if err := json.Unmarshal(respBody, &configs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configs: %w", err)
	}

	if len(configs) == 0 {
		return nil, nil
	}

	// when repos is "[all]", we may have multiple configs
	// we need to find the config for the specific repo and return it
	var selectedConfig *policyDrivenPRInternal
	for _, config := range configs {
		if config.FullRepoName == fmt.Sprintf("%s/%s", owner, repo) {
			selectedConfig = &config.PolicyDrivenPRConfiguration
			break
		}
	}

	// Return the first config (should only be one for a specific repo)
	return selectedConfig, nil
}

// DiscoverPolicyDrivenPRConfig queries [all] to discover if org-level or repo-level config exists
// Used during import to determine the configuration type
func (c *APIClient) DiscoverPolicyDrivenPRConfig(ctx context.Context, owner string) (*PolicyDrivenPRPolicy, error) {
	policy := &PolicyDrivenPRPolicy{
		Owner: owner,
	}

	// Query [all] to get all configs
	URI := fmt.Sprintf("%s/v1/github/%s/%s/policy-driven-pr/configs", c.BaseURL, owner, "[all]")
	respBody, err := c.get(ctx, URI)
	if err != nil {
		return policy, fmt.Errorf("failed to discover policy configs: %w", err)
	}

	var configs []featureConfigResponse
	if err := json.Unmarshal(respBody, &configs); err != nil {
		return policy, fmt.Errorf("failed to unmarshal configs: %w", err)
	}

	if len(configs) == 0 {
		return policy, nil
	}

	// Separate org-level and repo-level configs
	var orgLevelConfig *policyDrivenPRInternal
	var repoConfigs []string

	for _, cfg := range configs {
		// Check if this is the org-level config
		if cfg.FullRepoName == fmt.Sprintf("%s/[all]", owner) {
			orgLevelConfig = &cfg.PolicyDrivenPRConfiguration
		} else {
			// Extract repo name from full_repo_name (owner/repo)
			repoName := cfg.FullRepoName[len(owner)+1:]
			if isConfigEnabled(cfg.PolicyDrivenPRConfiguration) {
				repoConfigs = append(repoConfigs, repoName)
			}
		}
	}

	// Determine which config to use
	var selectedConfig policyDrivenPRInternal
	var selectedRepos []string
	var useOrgLevel bool

	if orgLevelConfig != nil && isConfigEnabled(*orgLevelConfig) {
		// Org-level config exists
		selectedConfig = *orgLevelConfig
		selectedRepos = []string{"*"}
		useOrgLevel = true
	} else if len(repoConfigs) > 0 {
		// Repo-level configs exist
		useOrgLevel = false
		// Use first repo config as template
		config, _ := c.getConfigForRepo(ctx, owner, repoConfigs[0])
		if config != nil {
			selectedConfig = *config
			selectedRepos = repoConfigs
		}
	} else {
		// No enabled configs found
		return policy, nil
	}

	// Extract feature flags
	enabledHardenRunner := selectedConfig.ControlChecksConfig["GitHubHostedRunnerShouldBeHardened"].TriggerGithubIssue ||
		selectedConfig.ControlChecksConfig["GitHubHostedRunnerShouldBeHardened"].TriggerGithubPr
	enabledPinning := selectedConfig.ControlChecksConfig["ActionsShouldBePinned"].TriggerGithubIssue ||
		selectedConfig.ControlChecksConfig["ActionsShouldBePinned"].TriggerGithubPr
	enabledTokenPermissions := selectedConfig.ControlChecksConfig["GithubTokenShouldHaveMinPermission"].TriggerGithubIssue ||
		selectedConfig.ControlChecksConfig["GithubTokenShouldHaveMinPermission"].TriggerGithubPr
	enabledSecureDocker := selectedConfig.ControlChecksConfig["SecureDockerFile"].TriggerGithubIssue ||
		selectedConfig.ControlChecksConfig["SecureDockerFile"].TriggerGithubPr

	// Extract actions to replace
	actionsToReplace := []string{}
	for action := range selectedConfig.ControlSettings.ActionsToReplace {
		actionsToReplace = append(actionsToReplace, action)
	}

	// Convert update_precommit_file from map to array
	updatePrecommitFiles := []string{}
	for file := range selectedConfig.ControlSettings.UpdatePrecommitFile {
		updatePrecommitFiles = append(updatePrecommitFiles, file)
	}

	policy.SelectedRepos = selectedRepos
	policy.UseRepoLevelConfig = !useOrgLevel
	policy.UseOrgLevelConfig = useOrgLevel
	policy.AutoRemdiationOptions = AutoRemdiationOptions{
		CreatePR:                                selectedConfig.TriggerPRInsteadOfIssue,
		CreateIssue:                             !selectedConfig.TriggerPRInsteadOfIssue,
		CreateGitHubAdvancedSecurityAlert:       selectedConfig.TriggerGithubAlert,
		HardenGitHubHostedRunner:                enabledHardenRunner,
		PinActionsToSHA:                         enabledPinning,
		RestrictGitHubTokenPermissions:          enabledTokenPermissions,
		SecureDockerFile:                        enabledSecureDocker,
		ActionsToExemptWhilePinning:             selectedConfig.ControlSettings.ExemptedActions,
		ImagesToExemptWhilePinning:              selectedConfig.ControlSettings.ExemptedImages,
		ActionsToReplaceWithStepSecurityActions: actionsToReplace,
		UpdatePrecommitFile:                     updatePrecommitFiles,
		PackageEcosystem:                        selectedConfig.ControlSettings.PackageEcosystem,
		AddWorkflows:                            selectedConfig.ControlSettings.AddWorkflows,
	}

	// Populate SelectedReposFilter from API response
	if selectedConfig.ControlSettings.ApplyIssuePRConfigForAllReposFilter != nil {
		policy.SelectedReposFilter = *selectedConfig.ControlSettings.ApplyIssuePRConfigForAllReposFilter
	}

	return policy, nil
}

// isConfigEnabled checks if a config has any enabled features
func isConfigEnabled(config policyDrivenPRInternal) bool {
	return config.TriggerGithubAlert ||
		config.TriggerPRInsteadOfIssue ||
		len(config.ControlChecksConfig) > 0
}

func (c *APIClient) DeletePolicyDrivenPRPolicy(ctx context.Context, owner string, repos []string) error {
	for _, repo := range repos {
		if repo == "*" {
			repo = "[all]"
		}
		URI := fmt.Sprintf("%s/v1/github/%s/%s/policy-driven-pr/configs", c.BaseURL, owner, repo)
		if _, err := c.delete(ctx, URI); err != nil {
			return fmt.Errorf("failed to delete config for repo %s: %w", repo, err)
		}
	}

	return nil
}

func (c *APIClient) UpdatePolicyDrivenPRPolicy(ctx context.Context, policy PolicyDrivenPRPolicy, removedRepos []string) error {
	// Remove configs for repos that were removed
	if len(removedRepos) > 0 {
		if err := c.DeletePolicyDrivenPRPolicy(ctx, policy.Owner, removedRepos); err != nil {
			return fmt.Errorf("failed to remove repos from policy: %w", err)
		}
	}

	// Update/create policy for current repos
	if err := c.CreatePolicyDrivenPRPolicy(ctx, policy); err != nil {
		return fmt.Errorf("failed to update policy driven PR policy: %w", err)
	}

	return nil
}
