package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
)

// PATGovernancePolicy is the org's PAT governance policy, mirroring the
// agent-api PATPolicyConfig JSON shape (GET/PUT /v1/github/{owner}/apps/pat-policy).
// Thresholds are in days; 0 disables that control. Age is measured from the
// org-access grant time (fine-grained) / SSO authorization time (classic).
type PATGovernancePolicy struct {
	Enabled bool `json:"enabled"`

	// Max-age control, per token class (days; 0 disables the class check).
	FineGrainedMaxAgeDays int64 `json:"fine_grained_max_age_days"`
	ClassicMaxAgeDays     int64 `json:"classic_max_age_days"`

	// No-expiry control.
	FlagNoExpiry bool `json:"flag_no_expiry"`

	// Over-scoped control. Empty OverScopedScopes means the server default
	// set (repo, admin:org, workflow).
	FlagOverScoped   bool     `json:"flag_over_scoped"`
	OverScopedScopes []string `json:"over_scoped_scopes,omitempty"`

	// Unused/stale control: no sign of use for more than N days (0 = off).
	UnusedDays int64 `json:"unused_days"`

	// Optional GitHub-issue alert channel: bare repo name in this org where a
	// violations issue is filed on each alert (empty = off).
	GitHubIssueRepo string `json:"github_issue_repo,omitempty"`

	// Pre-expiry reminder bands (days before expiry). Empty means the server
	// default (30, 7, 1).
	ExpiryReminderDays []int64 `json:"expiry_reminder_days,omitempty"`

	UpdatedAt string `json:"updated_at,omitempty"`
}

// patGovernancePolicyEnvelope is the response wrapper of both GET and PUT.
// GET also carries a "capabilities" object, which the provider ignores.
type patGovernancePolicyEnvelope struct {
	Policy *PATGovernancePolicy `json:"policy"`
}

// GetPATGovernancePolicy returns the org's PAT governance policy, or nil when
// the org has never configured one (the API returns 200 with a null policy).
func (c *APIClient) GetPATGovernancePolicy(ctx context.Context, owner string) (*PATGovernancePolicy, error) {
	URI := fmt.Sprintf("%s/v1/github/%s/apps/pat-policy", c.BaseURL, owner)
	respBody, err := c.get(ctx, URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get PAT governance policy: %w", err)
	}

	var envelope patGovernancePolicyEnvelope
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PAT governance policy: %w", err)
	}

	return envelope.Policy, nil
}

// UpdatePATGovernancePolicy creates or updates the org's PAT governance policy.
func (c *APIClient) UpdatePATGovernancePolicy(ctx context.Context, owner string, policy PATGovernancePolicy) error {
	URI := fmt.Sprintf("%s/v1/github/%s/apps/pat-policy", c.BaseURL, owner)
	if _, err := c.put(ctx, URI, policy); err != nil {
		return fmt.Errorf("failed to update PAT governance policy: %w", err)
	}

	return nil
}

// DeletePATGovernancePolicy disables the org's PAT governance policy. The API
// has no DELETE endpoint, so delete writes a disabled policy with every
// control off, which stops all evaluation and alerting.
func (c *APIClient) DeletePATGovernancePolicy(ctx context.Context, owner string) error {
	if err := c.UpdatePATGovernancePolicy(ctx, owner, PATGovernancePolicy{Enabled: false}); err != nil {
		return fmt.Errorf("failed to delete PAT governance policy: %w", err)
	}

	return nil
}
