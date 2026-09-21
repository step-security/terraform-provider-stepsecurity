package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
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

// suppressionRuleIDNamespace is the fixed UUIDv5 namespace used to derive
// suppression rule ids. It must never change: the derived id IS the resource's
// identity on the server, so a new namespace would orphan every existing rule.
var suppressionRuleIDNamespace = uuid.MustParse("6f3c1a2e-9b47-5d18-8e0a-1c4b7d2f5a63")

// DeriveSuppressionRuleID computes a stable rule id from the rule's own
// definition. It is the idempotency key for rule creation.
//
// Why this exists: rule creation used to mint a server-side UUID per request.
// When the API returned 503 because the backend timed out evaluating existing
// detections, the rule had in fact been committed — but Terraform recorded
// nothing, so the next apply created a second rule with a second UUID. That is
// the duplicate-rule failure this closes. With a derived id, a retry of the
// same configuration presents the same id, and the API returns the rule that
// already exists instead of creating another.
//
// Consequence worth knowing: two rule resources with an identical customer,
// detection type, name, action and conditions derive the same id and therefore
// refer to the same server-side rule. Such definitions are duplicates of each
// other by any meaningful reading, but if you genuinely need two, give them
// distinct names.
func DeriveSuppressionRuleID(customer string, rule SuppressionRule) string {
	// Conditions is a map, so it has to be serialised in a fixed order or the
	// derived id would change between runs of the same configuration.
	keys := make([]string, 0, len(rule.Conditions))
	for k, v := range rule.Conditions {
		// Empty conditions are omitted: adding a condition and then clearing it
		// should leave the rule's identity where it started.
		if v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString(customer)
	sb.WriteString("\x00")
	sb.WriteString(rule.ID)
	sb.WriteString("\x00")
	sb.WriteString(rule.Name)
	sb.WriteString("\x00")
	sb.WriteString(rule.SeverityAction.Type)
	sb.WriteString("\x00")
	sb.WriteString(rule.SeverityAction.NewSeverity)
	for _, k := range keys {
		sb.WriteString("\x00")
		sb.WriteString(k)
		sb.WriteString("\x01")
		sb.WriteString(rule.Conditions[k])
	}

	return uuid.NewSHA1(suppressionRuleIDNamespace, []byte(sb.String())).String()
}

func (c *APIClient) CreateSuppressionRule(ctx context.Context, rule SuppressionRule) (*SuppressionRule, error) {
	URI := fmt.Sprintf("%s/v1/%s/detection-rules", c.BaseURL, c.Customer)

	// Send a derived rule id so the request carries its own idempotency key.
	// This is what makes the retry below safe: a repeat of a request that did
	// reach the backend returns the existing rule rather than creating a
	// second one.
	if rule.RuleID == "" {
		rule.RuleID = DeriveSuppressionRuleID(c.Customer, rule)
	}
	tflog.Info(ctx, "Creating suppression rule", map[string]interface{}{
		"URI":     URI,
		"rule_id": rule.RuleID,
	})

	response, err := c.postWithRetry(ctx, URI, rule)
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
	response, err := c.getWithRetry(ctx, URI)
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
	_, err := c.putWithRetry(ctx, URI, rule)
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
