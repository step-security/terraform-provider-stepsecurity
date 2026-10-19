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

	// Per-class unused limits; nil means the class uses UnusedDays, 0 disables
	// the staleness check for that class.
	FineGrainedUnusedDays *int64 `json:"fine_grained_unused_days,omitempty"`
	ClassicUnusedDays     *int64 `json:"classic_unused_days,omitempty"`

	// Per-class reminder bands; empty means the class uses ExpiryReminderDays.
	// A single 0 disables reminders for the class.
	FineGrainedExpiryReminderDays []int64 `json:"fine_grained_expiry_reminder_days,omitempty"`
	ClassicExpiryReminderDays     []int64 `json:"classic_expiry_reminder_days,omitempty"`

	// Custom reminder emails: token class ("classic" / "fine_grained") to band
	// (days before expiry, as a string) to template.
	ExpiryReminderTemplates map[string]map[string]PATReminderTemplate `json:"expiry_reminder_templates,omitempty"`

	// Extra recipients copied on reminders and notices, and whether the
	// token's user is emailed at all.
	ExpiryReminderCC      []string `json:"expiry_reminder_cc,omitempty"`
	ExpiryReminderToOwner bool     `json:"expiry_reminder_to_owner,omitempty"`

	// Email domain appended to managed-user logins when no identity is known.
	OwnerEmailFallbackDomain string `json:"owner_email_fallback_domain,omitempty"`

	// Revocation notices: the switch, per-class overrides (nil inherits) and
	// templates (per class, else the shared one, else the built-in email).
	NotifyOnRevocation                        bool                 `json:"notify_on_revocation,omitempty"`
	ClassicNotifyOnRevocation                 *bool                `json:"classic_notify_on_revocation,omitempty"`
	FineGrainedNotifyOnRevocation             *bool                `json:"fine_grained_notify_on_revocation,omitempty"`
	RevocationNotificationTemplate            *PATReminderTemplate `json:"revocation_notification_template,omitempty"`
	ClassicRevocationNotificationTemplate     *PATReminderTemplate `json:"classic_revocation_notification_template,omitempty"`
	FineGrainedRevocationNotificationTemplate *PATReminderTemplate `json:"fine_grained_revocation_notification_template,omitempty"`

	// Revoke tokens that stay non-compliant for this many days (0 = off).
	ClassicNoncompliantRevokeAfterDays     int64 `json:"classic_noncompliant_revoke_after_days,omitempty"`
	FineGrainedNoncompliantRevokeAfterDays int64 `json:"fine_grained_noncompliant_revoke_after_days,omitempty"`

	// Revoke after the final pre-expiry reminder, with per-class overrides
	// (nil inherits).
	AutoRevokeAfterReminders            bool  `json:"auto_revoke_after_reminders,omitempty"`
	ClassicAutoRevokeAfterReminders     *bool `json:"classic_auto_revoke_after_reminders,omitempty"`
	FineGrainedAutoRevokeAfterReminders *bool `json:"fine_grained_auto_revoke_after_reminders,omitempty"`

	// When true the organization follows the tenant-wide policy instead of
	// the fields above.
	UseTenantPolicy *bool `json:"use_tenant_policy,omitempty"`

	UpdatedAt string `json:"updated_at,omitempty"`
}

// PATReminderTemplate is a custom email: subject up to 200 characters, body
// (HTML) up to 20000 characters.
type PATReminderTemplate struct {
	Subject string `json:"subject,omitempty"`
	Body    string `json:"body,omitempty"`
}

// patGovernancePolicyEnvelope is the response wrapper of both GET and PUT.
// GET returns under "policy" the policy the organization is evaluated with:
// its own, else the customer's tenant-wide policy, else the built-in default.
// The organization's own stored record, which is what Terraform manages,
// comes under "org_policy", with "has_org_policy" saying whether one exists
// (an org can keep its own record dormant while use_tenant_policy is set).
// Older servers only return "policy", null when nothing is stored. GET also
// carries capabilities and template defaults, which the provider ignores.
type patGovernancePolicyEnvelope struct {
	Policy       *PATGovernancePolicy `json:"policy"`
	HasOrgPolicy *bool                `json:"has_org_policy,omitempty"`
	OrgPolicy    *PATGovernancePolicy `json:"org_policy,omitempty"`
}

// GetPATGovernancePolicy returns the org's own PAT governance policy, or nil
// when the org has none of its own (it then follows the tenant-wide policy or
// the built-in default, which Terraform does not manage here).
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

	// Prefer the org's own record when the server distinguishes it from the
	// effective policy; "policy" alone would show the inherited tenant policy
	// for an org that follows it, which is not what the resource manages.
	if envelope.HasOrgPolicy != nil {
		if !*envelope.HasOrgPolicy {
			return nil, nil
		}
		return envelope.OrgPolicy, nil
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

// DeletePATGovernancePolicy removes the org's own PAT governance policy, so
// the organization follows the customer's tenant-wide policy (or the built-in
// default) again. Deleting a policy that is already gone succeeds.
func (c *APIClient) DeletePATGovernancePolicy(ctx context.Context, owner string) error {
	URI := fmt.Sprintf("%s/v1/github/%s/apps/pat-policy", c.BaseURL, owner)
	if _, err := c.delete(ctx, URI); err != nil {
		return fmt.Errorf("failed to delete PAT governance policy: %w", err)
	}

	return nil
}
