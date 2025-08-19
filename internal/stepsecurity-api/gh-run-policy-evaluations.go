package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// RunPolicyEvaluation represents a workflow run policy evaluation
type RunPolicyEvaluation struct {
	Owner                   string                 `json:"owner"`
	RepoFullName            string                 `json:"repo_full_name"`
	RepoWorkflow            string                 `json:"repo_workflow"`
	HeadBranch              string                 `json:"head_branch"`
	WorkflowName            string                 `json:"workflow_name"`
	WorkflowDisplayTitle    string                 `json:"workflow_display_title"`
	WorkflowFilePath        string                 `json:"workflow_file_path"`
	RunID                   int64                  `json:"run_id"`
	WorkflowRunStartedAt    int64                  `json:"workflow_run_started_at"`
	CommitMessage           string                 `json:"commit_message"`
	Committer               string                 `json:"committer"`
	Event                   string                 `json:"event"`
	RunNumber               int                    `json:"run_number"`
	PolicyResults           []PolicyResult         `json:"policy_results"`
	Status                  string                 `json:"status"`
}

// PolicyResult represents the result of a policy evaluation
type PolicyResult struct {
	Policy                          PolicyEvaluation `json:"policy"`
	ActionPolicyStatus              string           `json:"action_policy_status"`
	ActionsNotAllowed               []string         `json:"actions_not_allowed,omitempty"`
	RunsOnPolicyStatus              string           `json:"runs_on_policy_status"`
	RunnerLabelsNotAllowed          []string         `json:"runner_labels_not_allowed,omitempty"`
	CompromisedActionsPolicyStatus  string           `json:"compromised_actions_policy_status"`
	CompromisedActionsDetected      []string         `json:"compromised_actions_detected,omitempty"`
	SecretsPolicyStatus             string           `json:"secrets_policy_status"`
	IsNonDefaultBranch              *bool            `json:"is_non_default_branch,omitempty"`
	WorkflowContainsSecrets         *bool            `json:"workflow_contains_secrets,omitempty"`
	CurrentBranchHash               string           `json:"current_branch_hash,omitempty"`
	DefaultBranchHash               string           `json:"default_branch_hash,omitempty"`
}

// PolicyEvaluation represents the policy configuration used in evaluation
type PolicyEvaluation struct {
	Owner                          string              `json:"owner"`
	Name                           string              `json:"name"`
	EnableActionPolicy             bool                `json:"enable_action_policy,omitempty"`
	AllowedActions                 map[string]string   `json:"allowed_actions,omitempty"`
	EnableRunsOnPolicy             bool                `json:"enable_runs_on_policy,omitempty"`
	DisallowedRunnerLabels         map[string]struct{} `json:"disallowed_runner_labels,omitempty"`
	EnableSecretsPolicy            bool                `json:"enable_secrets_policy,omitempty"`
	EnableCompromisedActionsPolicy bool                `json:"enable_compromised_actions_policy,omitempty"`
}

// ListOrgRunPolicyEvaluations retrieves run policy evaluations for an organization
func (c *APIClient) ListOrgRunPolicyEvaluations(ctx context.Context, owner string, status string) ([]RunPolicyEvaluation, error) {
	uri := fmt.Sprintf("%s/v1/github/%s/actions/run-policy-evaluations", c.BaseURL, owner)
	
	// Add status query parameter if provided
	if status != "" {
		params := url.Values{}
		params.Add("status", status)
		uri += "?" + params.Encode()
	}

	body, err := c.get(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("failed to list organization run policy evaluations: %w", err)
	}

	var evaluations []RunPolicyEvaluation
	err = json.Unmarshal(body, &evaluations)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal organization run policy evaluations response: %w", err)
	}

	return evaluations, nil
}

// ListRepoRunPolicyEvaluations retrieves run policy evaluations for a specific repository
func (c *APIClient) ListRepoRunPolicyEvaluations(ctx context.Context, owner string, repo string, status string) ([]RunPolicyEvaluation, error) {
	uri := fmt.Sprintf("%s/v1/github/%s/%s/actions/run-policy-evaluations", c.BaseURL, owner, repo)
	
	// Add status query parameter if provided
	if status != "" {
		params := url.Values{}
		params.Add("status", status)
		uri += "?" + params.Encode()
	}

	body, err := c.get(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("failed to list repository run policy evaluations: %w", err)
	}

	var evaluations []RunPolicyEvaluation
	err = json.Unmarshal(body, &evaluations)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal repository run policy evaluations response: %w", err)
	}

	return evaluations, nil
}