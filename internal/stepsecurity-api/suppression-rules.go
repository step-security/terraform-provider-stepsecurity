package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	SourceCodeOverwritten        = "Source-Code-Overwritten"
	AnomalousOutboundNetworkCall = "New-Outbound-Network-Call"
	HttpsOutboundNetworkCall     = "HTTPS-Outbound-Network-Call"
	SecretInBuildLog             = "Secret-In-Build-Log"
	SecretInArtifact             = "Secret-In-Artifact"
	ActionUsesImpostedCommit     = "Action-Uses-Imposter-Commit"
	DetectionPrivilegedContainer = "Privileged-Container"
	DetectionReverseShell        = "Reverse-Shell"
	SuspiciousNetworkCall        = "Suspicious-Network-Call"
	RunnerWorkerMemoryRead       = "Runner-Worker-Memory-Read"
)

type SuppressionRule struct {
	RuleID         string            `json:"rule_id"`
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	Customer       string            `json:"customer"`
	Conditions     map[string]string `json:"conditions"`
	CreatedBy      string            `json:"created_by"`
	CreatedOn      string            `json:"created_on"`
	UpdatedBy      string            `json:"updated_by"`
	UpdatedOn      string            `json:"updated_on"`
	SeverityAction SeverityAction    `json:"severity_action"`
}

type SeverityAction struct {
	Type        string `json:"type"`
	NewSeverity string `json:"new_severity,omitempty"`
}

func (c *APIClient) CreateSuppressionRule(ctx context.Context, rule SuppressionRule) (*SuppressionRule, error) {
	URI := fmt.Sprintf("%s/v1/%s/detection-rules", c.BaseURL, c.Customer)
	response, err := c.post(ctx, URI, rule)
	if err != nil {
		return nil, fmt.Errorf("failed to create suppression rule: %w", err)
	}

	var resp SuppressionRule
	if err := json.Unmarshal(response, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal suppression rule: %w", err)
	}

	return &resp, nil
}

func (c *APIClient) ReadSuppressionRule(ctx context.Context, ruleID string) (*SuppressionRule, error) {
	URI := fmt.Sprintf("%s/v1/%s/detection-rules/%s", c.BaseURL, c.Customer, ruleID)
	response, err := c.get(ctx, URI)
	if err != nil {
		return nil, fmt.Errorf("failed to read suppression rule: %w", err)
	}

	var resp SuppressionRule
	if err := json.Unmarshal(response, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal suppression rule: %w", err)
	}

	return &resp, nil
}

func (c *APIClient) UpdateSuppressionRule(ctx context.Context, rule SuppressionRule) error {
	URI := fmt.Sprintf("%s/v1/%s/detection-rules/%s", c.BaseURL, c.Customer, rule.RuleID)
	tflog.Info(ctx, "Updating suppression rule", map[string]interface{}{
		"URI": URI,
	})
	_, err := c.put(ctx, URI, rule)
	if err != nil {
		return fmt.Errorf("failed to update suppression rule: %w", err)
	}

	return nil
}

func (c *APIClient) DeleteSuppressionRule(ctx context.Context, ruleID string) error {
	URI := fmt.Sprintf("%s/v1/%s/detection-rules/%s", c.BaseURL, c.Customer, ruleID)
	_, err := c.delete(ctx, URI)
	if err != nil {
		return fmt.Errorf("failed to delete suppression rule: %w", err)
	}

	return nil
}
