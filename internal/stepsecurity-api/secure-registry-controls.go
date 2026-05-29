package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
)

// SecureRegistryControls represents the security policy configuration for a registry.
type SecureRegistryControls struct {
	Customer            string                      `json:"customer"`
	Registry            string                      `json:"registry"`
	CooldownPeriod      *CooldownPeriodControl      `json:"cooldown_period,omitempty"`
	CompromisedPackages *CompromisedPackagesControl `json:"compromised_packages,omitempty"`
	UpdatedBy           string                      `json:"updated_by"`
	UpdatedAt           string                      `json:"updated_at"`
}

// CooldownPeriodControl blocks packages published within a configurable window.
type CooldownPeriodControl struct {
	Enabled       bool     `json:"enabled"`
	PeriodInDays  int      `json:"period_in_days"`
	ExemptionList []string `json:"exemption_list,omitempty"`
}

// CompromisedPackagesControl blocks packages flagged as compromised.
type CompromisedPackagesControl struct {
	Enabled bool `json:"enabled"`
}

// UpsertSecureRegistryControlsRequest is the PUT request body. Omitting a control
// preserves the existing backend value (partial upsert).
type UpsertSecureRegistryControlsRequest struct {
	CooldownPeriod      *CooldownPeriodControl      `json:"cooldown_period,omitempty"`
	CompromisedPackages *CompromisedPackagesControl `json:"compromised_packages,omitempty"`
}

func (c *APIClient) GetRegistryControls(ctx context.Context, registry string) (*SecureRegistryControls, error) {
	url := fmt.Sprintf("%s/v1/%s/secure-registry/controls/%s", c.BaseURL, c.Customer, registry)
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	var controls SecureRegistryControls
	if err := json.Unmarshal(body, &controls); err != nil {
		return nil, fmt.Errorf("failed to parse registry controls response: %w", err)
	}
	return &controls, nil
}

func (c *APIClient) UpsertRegistryControls(ctx context.Context, registry string, req UpsertSecureRegistryControlsRequest) (*SecureRegistryControls, error) {
	url := fmt.Sprintf("%s/v1/%s/secure-registry/controls/%s", c.BaseURL, c.Customer, registry)
	body, err := c.put(ctx, url, req)
	if err != nil {
		return nil, err
	}
	var controls SecureRegistryControls
	if err := json.Unmarshal(body, &controls); err != nil {
		return nil, fmt.Errorf("failed to parse upsert registry controls response: %w", err)
	}
	return &controls, nil
}

func (c *APIClient) DeleteRegistryControls(ctx context.Context, registry string) error {
	url := fmt.Sprintf("%s/v1/%s/secure-registry/controls/%s", c.BaseURL, c.Customer, registry)
	_, err := c.delete(ctx, url)
	return err
}
