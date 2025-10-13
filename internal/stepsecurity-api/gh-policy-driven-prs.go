package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// PolicyDrivenPRPolicy represents the Terraform resource model
type PolicyDrivenPRPolicy struct {
	Owner                 string                `json:"owner"`
	AutoRemdiationOptions AutoRemdiationOptions `json:"auto_remediation_options"`
	SelectedRepos         []string              `json:"selected_repos"`
	UseRepoLevelConfig    bool                  `json:"use_repo_level_config"`
	UseOrgLevelConfig     bool                  `json:"use_org_level_config"`
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
	ActionsToReplaceWithStepSecurityActions []string           `json:"actions_to_replace_with_step_security_actions"`
	UpdatePrecommitFile                     []string           `json:"update_precommit_file,omitempty"`
	PackageEcosystem                        []DependabotConfig `json:"package_ecosystem,omitempty"`
	AddWorkflows                            string             `json:"add_workflows,omitempty"`
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
	ExemptedActions               []string           `json:"exempted_actions,omitempty"`
	ActionsToReplace              map[string]string  `json:"actions_to_replace,omitempty"`
	UpdatePrecommitFile           map[string]bool    `json:"update_precommit_file,omitempty"`
	PackageEcosystem              []DependabotConfig `json:"package_ecosystem,omitempty"`
	AddWorkflows                  string             `json:"add_workflows,omitempty"`
	ApplyIssuePRConfigForAllRepos *bool              `json:"apply_issue_pr_config_for_all_repos,omitempty"`
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
	applyToAllRepos := createRequest.UseOrgLevelConfig
	cs := &controlSettings{
		ExemptedActions:               createRequest.AutoRemdiationOptions.ActionsToExemptWhilePinning,
		ActionsToReplace:              actionsToReplace,
		UpdatePrecommitFile:           updatePrecommitFileMap,
		PackageEcosystem:              createRequest.AutoRemdiationOptions.PackageEcosystem,
		AddWorkflows:                  createRequest.AutoRemdiationOptions.AddWorkflows,
		ApplyIssuePRConfigForAllRepos: &applyToAllRepos,
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

	// Handle different scenarios based on config level
	if createRequest.UseOrgLevelConfig {
		// For org-level config, use [all] endpoint to apply to all repos
		return c.updateConfigForRepo(ctx, createRequest.Owner, "[all]", configOptions)
	}

	// For repo-level config, apply to specific repos
	for _, repo := range createRequest.SelectedRepos {
		if err := c.updateConfigForRepo(ctx, createRequest.Owner, repo, configOptions); err != nil {
			return fmt.Errorf("failed to update config for repo %s: %w", repo, err)
		}
	}

	return nil
}

func (c *APIClient) updateConfigForRepo(ctx context.Context, owner string, repo string, config policyDrivenPRConfigOptions) error {
	URI := fmt.Sprintf("%s/v1/github/%s/%s/policy-driven-pr/configs", c.BaseURL, owner, repo)
	if _, err := c.post(ctx, URI, config); err != nil {
		return fmt.Errorf("failed to update config for repo: %w", err)
	}
	return nil
}

func (c *APIClient) GetPolicyDrivenPRPolicy(ctx context.Context, owner string) (*PolicyDrivenPRPolicy, error) {
	policy := &PolicyDrivenPRPolicy{
		Owner: owner,
	}

	// Get all repo configurations
	URI := fmt.Sprintf("%s/v1/github/%s/[all]/policy-driven-pr/configs", c.BaseURL, owner)
	respBody, err := c.get(ctx, URI)
	if err != nil {
		return policy, fmt.Errorf("failed to get policy-driven PR configs: %w", err)
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
	repoConfigs := make(map[string]policyDrivenPRInternal)

	for _, cfg := range configs {
		// Check if this is the org-level config
		if cfg.FullRepoName == fmt.Sprintf("%s/[all]", owner) {
			orgLevelConfig = &cfg.PolicyDrivenPRConfiguration
		} else {
			// Extract repo name from full_repo_name (owner/repo)
			repoName := cfg.FullRepoName[len(owner)+1:]
			if isConfigEnabled(cfg.PolicyDrivenPRConfiguration) {
				repoConfigs[repoName] = cfg.PolicyDrivenPRConfiguration
			}
		}
	}

	// Determine which config to use and which repos
	var selectedConfig policyDrivenPRInternal
	var selectedRepos []string
	var useOrgLevel bool

	if orgLevelConfig != nil && isConfigEnabled(*orgLevelConfig) {
		// Org-level config exists and is enabled
		selectedConfig = *orgLevelConfig
		selectedRepos = []string{"*"}
		useOrgLevel = true
	} else if len(repoConfigs) > 0 {
		// Repo-level configs
		useOrgLevel = false
		// Use first repo config as template (all should be the same)
		for _, config := range repoConfigs {
			selectedConfig = config
			break
		}
		// Collect all enabled repos
		for repoName := range repoConfigs {
			selectedRepos = append(selectedRepos, repoName)
		}
	}

	if len(selectedRepos) == 0 {
		// No enabled configs found
		return policy, nil
	}

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
		ActionsToReplaceWithStepSecurityActions: actionsToReplace,
		UpdatePrecommitFile:                     updatePrecommitFiles,
		PackageEcosystem:                        selectedConfig.ControlSettings.PackageEcosystem,
		AddWorkflows:                            selectedConfig.ControlSettings.AddWorkflows,
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
