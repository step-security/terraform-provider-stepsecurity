package stepsecurityapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type PolicyDrivenPRPolicy struct {
	Owner                 string                `json:"owner"`
	AutoRemdiationOptions AutoRemdiationOptions `json:"auto_remediation_options"`
	SelectedRepos         []string              `json:"selected_repos"`
}

type AutoRemdiationOptions struct {
	CreatePR                                bool     `json:"create_pr"`
	CreateIssue                             bool     `json:"create_issue"`
	CreateGitHubAdvancedSecurityAlert       bool     `json:"create_github_advanced_security_alert"`
	HardenGitHubHostedRunner                bool     `json:"harden_github_hosted_runner"`
	PinActionsToSHA                         bool     `json:"pin_actions_to_sha"`
	RestrictGitHubTokenPermissions          bool     `json:"restrict_github_token_permissions"`
	ActionsToExemptWhilePinning             []string `json:"actions_to_exempt_while_pinning"`
	ActionsToReplaceWithStepSecurityActions []string `json:"actions_to_replace_with_step_security_actions"`
}

type ActionsToReplace struct {
	ActionName         string `json:"action_name"`
	StepSecurityAction string `json:"stepsecurity_action"`
}

type featureConfigInternal struct {
	Repo                    string                   `json:"repo"`
	ControlChecksConfig     map[string]issuePRConfig `json:"control_checks_config"`
	TriggerGithubAlert      bool                     `json:"trigger_github_alert"` // when enabled github advanced alert is triggered for issues that are enabled
	TriggerPRInsteadOfIssue bool                     `json:"trigger_pr_instead_of_issue"`
}

type issuePRConfig struct {
	TriggerGithubIssue bool `json:"trigger_github_issue"`
	TriggerGithubPr    bool `json:"trigger_github_pr"`
}

type controlSettings struct {
	ExemptedActions               []string          `json:"exempted_actions"`
	ActionsToReplace              map[string]string `json:"actions_to_replace"`
	PinToImmutable                bool              `json:"pin_to_immutable"`
	ApplyIssuePRConfigForAllRepos bool              `json:"apply_issue_pr_config_for_all_repos"`
}

func (c *APIClient) CreatePolicyDrivenPRPolicy(ctx context.Context, createRequest PolicyDrivenPRPolicy) error {

	allRepos := false
	if slices.Contains(createRequest.SelectedRepos, "*") {
		createRequest.SelectedRepos = []string{"[all]"}
		allRepos = true
	}

	tflog.Info(ctx, "Creating policy-driven PR policy", map[string]interface{}{
		"owner":          createRequest.Owner,
		"selected_repos": createRequest.SelectedRepos,
		"auto_remediation_options.actions_to_replace_with_step_security_actions": createRequest.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions,
	})
	actionsToReplace := make(map[string]string)
	for _, action := range createRequest.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions {
		actionsToReplace[action] = ""
	}

	controlSettings := controlSettings{
		ExemptedActions:               createRequest.AutoRemdiationOptions.ActionsToExemptWhilePinning,
		ActionsToReplace:              actionsToReplace,
		ApplyIssuePRConfigForAllRepos: allRepos,
	}
	err := c.updateControlSettings(createRequest.Owner, controlSettings)
	if err != nil {
		return fmt.Errorf("failed to update control settings: %w", err)
	}

	controlChecksConfig := make(map[string]issuePRConfig)
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

	if len(createRequest.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions) > 0 {
		controlChecksConfig["MaintainedGitHubActionsShouldBeUsed"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	config := featureConfigInternal{
		ControlChecksConfig:     controlChecksConfig,
		TriggerGithubAlert:      createRequest.AutoRemdiationOptions.CreateGitHubAdvancedSecurityAlert,
		TriggerPRInsteadOfIssue: createPR,
	}

	for _, repo := range createRequest.SelectedRepos {
		err := c.updateConfigForRepo(createRequest.Owner, repo, config)
		if err != nil {
			return fmt.Errorf("failed to update config for repo: %w", err)
		}
	}

	return nil
}

func (c *APIClient) updateControlSettings(owner string, controlSettings controlSettings) error {
	URI := fmt.Sprintf("%s/v1/github/%s/control-settings", c.BaseURL, owner)
	controlSettingsReqBody, err := json.Marshal(controlSettings)
	if err != nil {
		return fmt.Errorf("failed to marshal control settings: %w", err)
	}
	req, err := http.NewRequest("POST", URI, bytes.NewReader(controlSettingsReqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = c.do(req)
	if err != nil {
		return fmt.Errorf("failed to create control settings: %w", err)
	}

	return nil
}

func (c *APIClient) updateConfigForRepo(owner string, repo string, config featureConfigInternal) error {
	URI := fmt.Sprintf("%s/v1/github/%s/%s/feature-configurations", c.BaseURL, owner, repo)
	reqBody, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	req, err := http.NewRequest("POST", URI, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = c.do(req)
	if err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}

	return nil
}

func (c *APIClient) getControlSettings(owner string) (controlSettings, error) {

	var controlSettings controlSettings
	URI := fmt.Sprintf("%s/v1/github/%s/control-settings", c.BaseURL, owner)
	req, err := http.NewRequest("GET", URI, nil)
	if err != nil {
		return controlSettings, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	respBody, err := c.do(req)
	if err != nil {
		return controlSettings, fmt.Errorf("failed to get control settings: %w", err)
	}

	if err := json.Unmarshal(respBody, &controlSettings); err != nil {
		return controlSettings, fmt.Errorf("failed to unmarshal control settings: %w", err)
	}

	return controlSettings, nil
}

func (c *APIClient) getConfig(owner string) ([]featureConfigInternal, error) {

	featureConfig := make([]featureConfigInternal, 0)
	URI := fmt.Sprintf("%s/v1/github/%s/[all]/feature-configurations", c.BaseURL, owner)
	req, err := http.NewRequest("GET", URI, nil)
	if err != nil {
		return featureConfig, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	respBody, err := c.do(req)
	if err != nil {
		return featureConfig, fmt.Errorf("failed to get feature config: %w", err)
	}

	if err := json.Unmarshal(respBody, &featureConfig); err != nil {
		return featureConfig, fmt.Errorf("failed to unmarshal feature config: %w", err)
	}

	return featureConfig, nil
}

func (c *APIClient) GetPolicyDrivenPRPolicy(ctx context.Context, owner string) (*PolicyDrivenPRPolicy, error) {

	policy := &PolicyDrivenPRPolicy{}

	controlSettings, err := c.getControlSettings(owner)
	if err != nil {
		return policy, fmt.Errorf("failed to get control settings: %w", err)
	}

	actionsToReplace := []string{}
	for _, action := range controlSettings.ActionsToReplace {
		actionsToReplace = append(actionsToReplace, action)
	}

	config, err := c.getConfig(owner)
	if err != nil {
		return policy, fmt.Errorf("failed to get feature config: %w", err)
	}

	defaultRepoConfig := featureConfigInternal{
		ControlChecksConfig:     make(map[string]issuePRConfig),
		TriggerGithubAlert:      false,
		TriggerPRInsteadOfIssue: false,
	}
	for _, repoConfig := range config {
		if repoConfig.TriggerGithubAlert || repoConfig.TriggerPRInsteadOfIssue {
			defaultRepoConfig = repoConfig
			break
		}
		for _, controlCheckConfig := range repoConfig.ControlChecksConfig {
			if controlCheckConfig.TriggerGithubIssue || controlCheckConfig.TriggerGithubPr {
				defaultRepoConfig = repoConfig
				break
			}
		}
	}

	enabledHardenRunner := defaultRepoConfig.ControlChecksConfig["GitHubHostedRunnerShouldBeHardened"].TriggerGithubIssue || defaultRepoConfig.ControlChecksConfig["GitHubHostedRunnerShouldBeHardened"].TriggerGithubPr
	enabledPinning := defaultRepoConfig.ControlChecksConfig["ActionsShouldBePinned"].TriggerGithubIssue || defaultRepoConfig.ControlChecksConfig["ActionsShouldBePinned"].TriggerGithubPr
	enabledTokenPermissions := defaultRepoConfig.ControlChecksConfig["GithubTokenShouldHaveMinPermission"].TriggerGithubIssue || defaultRepoConfig.ControlChecksConfig["GithubTokenShouldHaveMinPermission"].TriggerGithubPr

	repoNames := make([]string, 0)
	if controlSettings.ApplyIssuePRConfigForAllRepos {
		repoNames = append(repoNames, "*")
	} else {
		for _, repoConfig := range config {
			if repoConfig.TriggerPRInsteadOfIssue == defaultRepoConfig.TriggerPRInsteadOfIssue &&
				repoConfig.TriggerGithubAlert == defaultRepoConfig.TriggerGithubAlert &&
				reflect.DeepEqual(repoConfig.ControlChecksConfig, defaultRepoConfig.ControlChecksConfig) {
				repoNames = append(repoNames, repoConfig.Repo)
			}
		}
	}

	policy.Owner = owner
	policy.SelectedRepos = repoNames
	policy.AutoRemdiationOptions = AutoRemdiationOptions{
		CreatePR:                                defaultRepoConfig.TriggerPRInsteadOfIssue,
		CreateIssue:                             !defaultRepoConfig.TriggerPRInsteadOfIssue,
		CreateGitHubAdvancedSecurityAlert:       defaultRepoConfig.TriggerGithubAlert,
		HardenGitHubHostedRunner:                enabledHardenRunner,
		PinActionsToSHA:                         enabledPinning,
		RestrictGitHubTokenPermissions:          enabledTokenPermissions,
		ActionsToExemptWhilePinning:             controlSettings.ExemptedActions,
		ActionsToReplaceWithStepSecurityActions: actionsToReplace,
	}

	return policy, nil
}

func (c *APIClient) DeletePolicyDrivenPRPolicy(ctx context.Context, owner string, repos []string) error {

	controlSettings := controlSettings{
		ExemptedActions:               []string{},
		ActionsToReplace:              map[string]string{},
		ApplyIssuePRConfigForAllRepos: false,
	}

	err := c.updateControlSettings(owner, controlSettings)
	if err != nil {
		return fmt.Errorf("failed to update control settings: %w", err)
	}

	config := featureConfigInternal{
		ControlChecksConfig:     make(map[string]issuePRConfig),
		TriggerGithubAlert:      false,
		TriggerPRInsteadOfIssue: false,
	}

	for _, repo := range repos {
		if repo == "*" {
			repo = "[all]"
		}
		config.Repo = repo
		err := c.updateConfigForRepo(owner, repo, config)
		if err != nil {
			return fmt.Errorf("failed to delete config for repo: %w", err)
		}
	}

	return nil
}

func (c *APIClient) UpdatePolicyDrivenPRPolicy(ctx context.Context, policy PolicyDrivenPRPolicy, removedRepos []string) error {

	// remove each repo from policy
	err := c.DeletePolicyDrivenPRPolicy(ctx, policy.Owner, removedRepos)
	if err != nil {
		return fmt.Errorf("failed to update policy driven PR policy: %w", err)
	}

	// update policy
	err = c.CreatePolicyDrivenPRPolicy(ctx, policy)
	if err != nil {
		return fmt.Errorf("failed to update policy driven PR policy: %w", err)
	}

	return nil
}
