package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// PATExemption mirrors the agent-api PATApprovalRecord: one exemption from the
// PAT governance policy, kept in an organization's registry or, through the
// tenant routes, in the customer's tenant-wide registry. A record names either
// one token (a classic token by its last eight characters, or a fine-grained
// token by its token id) or, with Scope "owner", every token of one GitHub
// user, optionally one token class. The server identifies a record by Key,
// which only the list endpoints return.
type PATExemption struct {
	TokenSuffix string `json:"token_suffix,omitempty"`
	TokenID     int64  `json:"token_id,omitempty"`
	// Owner is the GitHub login of the token's user: required for an
	// owner-scoped record, an optional narrowing for a token-scoped one.
	Owner      string `json:"owner,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	Source     string `json:"source,omitempty"`
	RecordID   string `json:"record_id,omitempty"`
	ApprovedAt string `json:"approved_at,omitempty"`
	Scope      string `json:"scope,omitempty"`
	TokenClass string `json:"token_class,omitempty"`
	Reason     string `json:"reason,omitempty"`
	CreatedBy  string `json:"created_by,omitempty"`
	// Organization is set on list rows only: the owning organization's name,
	// or PATExemptionTenantWideOrganization for the tenant-wide registry.
	Organization string `json:"organization,omitempty"`
	// Instance limits a tenant-wide record to the organizations of one GitHub
	// Enterprise Server (by its registered name) or to GitHub.com ("github.com").
	Instance string `json:"instance,omitempty"`
	// Key is the registry key, set on list rows; it is what Delete takes.
	Key string `json:"key,omitempty"`
}

// PATExemptionTenantWideOrganization is the Organization the API puts on list
// rows that belong to the tenant-wide registry.
const PATExemptionTenantWideOrganization = "Tenant-wide"

type patExemptionListEnvelope struct {
	Approvals []PATExemption `json:"approvals"`
}

type patExemptionEnvelope struct {
	Approval *PATExemption `json:"approval"`
}

// patExemptionsURI picks the registry: an organization's own, or the
// tenant-wide one of the configured customer when organization is empty.
func (c *APIClient) patExemptionsURI(organization string) string {
	if organization == "" {
		return fmt.Sprintf("%s/v1/%s/github/pats/approvals", c.BaseURL, c.Customer)
	}
	return fmt.Sprintf("%s/v1/github/%s/apps/pats/approvals", c.BaseURL, organization)
}

// ListPATExemptions returns the records of one registry. Both list endpoints
// mix in rows from the other level for display (an organization's list shows
// the tenant-wide records that apply to it, the tenant list rolls up every
// organization), so rows from the other level are dropped here.
func (c *APIClient) ListPATExemptions(ctx context.Context, organization string) ([]PATExemption, error) {
	respBody, err := c.get(ctx, c.patExemptionsURI(organization))
	if err != nil {
		return nil, fmt.Errorf("failed to list PAT exemptions: %w", err)
	}

	var envelope patExemptionListEnvelope
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PAT exemptions: %w", err)
	}

	wantTenantWide := organization == ""
	records := make([]PATExemption, 0, len(envelope.Approvals))
	for _, record := range envelope.Approvals {
		if (record.Organization == PATExemptionTenantWideOrganization) != wantTenantWide {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// UpsertPATExemption creates or replaces the record with the same registry key
// and returns it as the server stored it, defaults applied. The returned
// record carries no Key; list the registry to learn it.
func (c *APIClient) UpsertPATExemption(ctx context.Context, organization string, record PATExemption) (*PATExemption, error) {
	respBody, err := c.post(ctx, c.patExemptionsURI(organization), record)
	if err != nil {
		return nil, fmt.Errorf("failed to save PAT exemption: %w", err)
	}

	var envelope patExemptionEnvelope
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PAT exemption: %w", err)
	}
	if envelope.Approval == nil {
		return nil, fmt.Errorf("failed to save PAT exemption: empty response")
	}

	return envelope.Approval, nil
}

// DeletePATExemption removes one record by its registry key. Deleting a record
// that is already gone succeeds.
func (c *APIClient) DeletePATExemption(ctx context.Context, organization, key string) error {
	URI := c.patExemptionsURI(organization) + "?key=" + url.QueryEscape(key)
	if _, err := c.delete(ctx, URI); err != nil {
		return fmt.Errorf("failed to delete PAT exemption: %w", err)
	}

	return nil
}
