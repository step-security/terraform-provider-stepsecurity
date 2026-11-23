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
	Typosquatting       *TyposquattingControl       `json:"typosquatting,omitempty"`
	CustomBlockList     *CustomBlockListControl     `json:"custom_block_list,omitempty"`
	NpmSettings         *NpmSettingsControl         `json:"npm_settings,omitempty"`
	GoSettings          *GoSettingsControl          `json:"go_settings,omitempty"`
	UpdatedBy           string                      `json:"updated_by"`
	UpdatedAt           string                      `json:"updated_at"`
}

// CooldownPeriodControl blocks packages published within a configurable window.
// The backend replaces the whole object on upsert, so omitting
// AutoExemptSecurityFixes clears any stored setting.
type CooldownPeriodControl struct {
	Enabled                 bool                     `json:"enabled"`
	PeriodInDays            int                      `json:"period_in_days"`
	ExemptionList           []string                 `json:"exemption_list,omitempty"`
	AutoExemptSecurityFixes *AutoExemptSecurityFixes `json:"auto_exempt_security_fixes,omitempty"`
}

// AutoExemptSecurityFixes lets the exact fixed version named by a verified,
// scored advisory through the cooldown window when the advisory meets the
// threshold. At most one of MinCVSSScore (0.1 to 10.0) and MinSeverity
// (critical, high, moderate, low) is set; one is required when Enabled is true.
type AutoExemptSecurityFixes struct {
	Enabled      bool     `json:"enabled"`
	MinCVSSScore *float64 `json:"min_cvss_score,omitempty"`
	MinSeverity  string   `json:"min_severity,omitempty"`
}

// CompromisedPackagesControl blocks packages flagged as compromised.
type CompromisedPackagesControl struct {
	Enabled bool `json:"enabled"`
}

// TyposquattingControl blocks package names that are heuristically similar to
// popular packages. It is an advisory control (fails open on detection errors).
// Only applicable to npm, pypi and maven; the backend rejects enabling it for
// other registries. Whitelist entries override false-positive detections.
type TyposquattingControl struct {
	Enabled   bool     `json:"enabled"`
	Whitelist []string `json:"whitelist,omitempty"`
}

// CustomBlockListControl explicitly blocks packages/versions matching glob patterns
// (exact names, `pkg@*` version globs, `@scope/*` for npm). Patterns are matched
// independently by the backend — order has no effect.
type CustomBlockListControl struct {
	Enabled  bool     `json:"enabled"`
	Patterns []string `json:"patterns,omitempty"`
	// BlockPseudoVersions lists module globs whose versions must be released tags.
	// Go only; the backend rejects it for other registries.
	BlockPseudoVersions []string `json:"block_pseudo_versions,omitempty"`
	// BlockYankedVersions hard-blocks crate versions yanked on crates.io.
	// Cargo only; the backend rejects it for other registries.
	BlockYankedVersions bool `json:"block_yanked_versions,omitempty"`
}

// NpmSettingsControl holds npm-specific non-security registry settings. Unlike the
// other controls it has no "enabled" toggle — RewriteTarballURLs is itself the
// setting. Only applicable when Registry == "npm"; the backend rejects any non-nil
// value for other registries.
//
// The two message templates are pointers because the backend treats them as
// preserve-on-omit: nil keeps the stored value, an empty string clears it.
type NpmSettingsControl struct {
	RewriteTarballURLs           bool    `json:"rewrite_tarball_urls"`
	BlockMessageTemplate         *string `json:"block_message_template,omitempty"`
	HiddenVersionsNoticeTemplate *string `json:"hidden_versions_notice_template,omitempty"`
}

// GoSettingsControl holds Go-specific non-security registry settings. Only
// applicable when Registry == "go".
type GoSettingsControl struct {
	ProxyChecksumDB bool `json:"proxy_checksum_db"`
}

// UpsertSecureRegistryControlsRequest is the PUT request body. Omitting a control
// preserves the existing backend value (partial upsert).
type UpsertSecureRegistryControlsRequest struct {
	CooldownPeriod      *CooldownPeriodControl      `json:"cooldown_period,omitempty"`
	CompromisedPackages *CompromisedPackagesControl `json:"compromised_packages,omitempty"`
	Typosquatting       *TyposquattingControl       `json:"typosquatting,omitempty"`
	CustomBlockList     *CustomBlockListControl     `json:"custom_block_list,omitempty"`
	NpmSettings         *NpmSettingsControl         `json:"npm_settings,omitempty"`
	GoSettings          *GoSettingsControl          `json:"go_settings,omitempty"`
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
