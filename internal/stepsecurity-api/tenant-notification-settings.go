package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Threat intel notification levels. The backend stores three mutually exclusive
// booleans; these are the levels they encode, matching what the console renders
// as a radio group.
const (
	// ThreatIntelLevelAll notifies about every incident, affected or not.
	ThreatIntelLevelAll = "all"
	// ThreatIntelLevelName notifies only when the tenant is affected by a
	// compromised package matched by name, at any version.
	ThreatIntelLevelName = "name"
	// ThreatIntelLevelVersion notifies only when the tenant has the exact
	// compromised version installed.
	ThreatIntelLevelVersion = "version"
)

// tenantNotificationSource is the `source` query parameter that scopes which
// options struct a write owns. "tenant" owns the two tenant-scoped products
// (threat intel and Developer MDM) and writes them together; the ADO and GitLab
// options belong to their own per-integration sources and are left untouched.
const tenantNotificationSource = "tenant"

// emptySentinel is a legacy value some tenants have persisted where a channel
// URL or address belongs. Every backend consumer treats it as unset, so it is
// normalized to "" on read rather than surfaced as a real value that would
// never match the configuration.
const emptySentinel = "empty"

// TenantNotificationSettings is the tenant-wide notification record: shared
// delivery channels plus one subscription struct per tenant-scoped product.
//
// Deliberately omits the Slack OAuth credentials the backend returns on GET
// (bot token, team ID, install metadata) so they cannot be pulled into Terraform
// state.
type TenantNotificationSettings struct {
	// Email, SlackWebhookURL and TeamsWebhookURL are shared across every
	// notification source. The backend assigns them unconditionally on write, so
	// an empty value clears the stored one.
	Email           string `json:"email"`
	SlackWebhookURL string `json:"slack_webhook_url"`
	TeamsWebhookURL string `json:"teams_webhook_url"`
	// SlackNotificationMethod ("webhook" or "oauth") and SlackChannelID are only
	// assigned by the backend when non-empty, so they can be set but not cleared
	// through this endpoint. Omitted when empty to make that explicit.
	SlackNotificationMethod string                          `json:"slack_notification_method,omitempty"`
	SlackChannelID          string                          `json:"slack_channel_id,omitempty"`
	ThreatIntel             ThreatIntelNotificationOptions  `json:"threat_intel_notification_options"`
	DeveloperMDM            DeveloperMDMNotificationOptions `json:"developer_mdm_notification_options"`
}

// ThreatIntelNotificationOptions is the tenant's threat intel subscription. The
// three flags are mutually exclusive in practice — together they encode one
// granularity level — so prefer Level and ThreatIntelOptionsForLevel over
// setting them directly.
type ThreatIntelNotificationOptions struct {
	NotifyOnPackageNameMatch bool `json:"notify_on_package_name_match"`
	NotifyOnVersionMatch     bool `json:"notify_on_version_match"`
	NotifyForAllIncidents    bool `json:"notify_for_all_incidents"`
}

// Enabled reports whether the tenant opted into threat intel notifications. It
// mirrors the backend's own gate: any flag set means opted in.
func (o ThreatIntelNotificationOptions) Enabled() bool {
	return o.NotifyForAllIncidents || o.NotifyOnPackageNameMatch || o.NotifyOnVersionMatch
}

// Level collapses the three flags into the level they encode, returning "" when
// the tenant is not opted in. Precedence is all > name > version, matching how
// the console reads the same record, so a row with several flags set resolves
// the same way in both places.
func (o ThreatIntelNotificationOptions) Level() string {
	switch {
	case o.NotifyForAllIncidents:
		return ThreatIntelLevelAll
	case o.NotifyOnPackageNameMatch:
		return ThreatIntelLevelName
	case o.NotifyOnVersionMatch:
		return ThreatIntelLevelVersion
	default:
		return ""
	}
}

// ThreatIntelOptionsForLevel is the inverse of Level: it builds the flags for a
// level, or all-false when disabled. An unrecognized level yields all-false
// rather than a partial subscription.
func ThreatIntelOptionsForLevel(enabled bool, level string) ThreatIntelNotificationOptions {
	if !enabled {
		return ThreatIntelNotificationOptions{}
	}
	return ThreatIntelNotificationOptions{
		NotifyForAllIncidents:    level == ThreatIntelLevelAll,
		NotifyOnPackageNameMatch: level == ThreatIntelLevelName,
		NotifyOnVersionMatch:     level == ThreatIntelLevelVersion,
	}
}

// DeveloperMDMEventSubscription wraps one event's on/off state. The backend
// models it as an object rather than a bare bool to leave room for per-event
// options, so the wire shape is preserved here even though "enabled" is
// currently the only field.
type DeveloperMDMEventSubscription struct {
	Enabled bool `json:"enabled"`
}

// DeveloperMDMNotificationOptions is the tenant's Dev Machine Guard
// subscription: one entry per notifiable event type. The events are independent
// of each other and every one defaults to off.
type DeveloperMDMNotificationOptions struct {
	NewIDEs          DeveloperMDMEventSubscription `json:"new_ides"`
	NewIDEExtensions DeveloperMDMEventSubscription `json:"new_ide_extensions"`
	NewAIAgents      DeveloperMDMEventSubscription `json:"new_ai_agents"`
	NewMCPServers    DeveloperMDMEventSubscription `json:"new_mcp_servers"`
	NewAgentSkills   DeveloperMDMEventSubscription `json:"new_agent_skills"`
	SuspiciousFiles  DeveloperMDMEventSubscription `json:"suspicious_files"`
	ConfigChanges    DeveloperMDMEventSubscription `json:"config_changes"`
}

func (c *APIClient) tenantNotificationsPath() string {
	return fmt.Sprintf("%s/v1/application/customers/%s/notifications", c.BaseURL, url.PathEscape(c.Customer))
}

// GetTenantNotificationSettings reads the tenant's notification record. The
// backend never 404s here: a tenant that has never saved settings gets an
// all-zero record back, which reads as "no channels, nothing subscribed".
func (c *APIClient) GetTenantNotificationSettings(ctx context.Context) (*TenantNotificationSettings, error) {
	body, err := c.get(ctx, c.tenantNotificationsPath())
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant notification settings: %w", err)
	}
	var settings TenantNotificationSettings
	if err := json.Unmarshal(body, &settings); err != nil {
		return nil, fmt.Errorf("failed to parse tenant notification settings response: %w", err)
	}
	settings.Email = unsentinel(settings.Email)
	settings.SlackWebhookURL = unsentinel(settings.SlackWebhookURL)
	settings.TeamsWebhookURL = unsentinel(settings.TeamsWebhookURL)
	settings.SlackChannelID = unsentinel(settings.SlackChannelID)
	return &settings, nil
}

// UpdateTenantNotificationSettings writes the whole record with source=tenant.
// There is no partial write: the shared channels are overwritten from the
// request on every call regardless of source, so req must carry the channels the
// tenant should end up with, not just the ones being changed.
func (c *APIClient) UpdateTenantNotificationSettings(ctx context.Context, req TenantNotificationSettings) error {
	uri := fmt.Sprintf("%s?source=%s", c.tenantNotificationsPath(), tenantNotificationSource)
	if _, err := c.put(ctx, uri, req); err != nil {
		return fmt.Errorf("failed to update tenant notification settings: %w", err)
	}
	return nil
}

// DeleteTenantNotificationSettings unsubscribes the tenant from every
// tenant-scoped event and clears the shared channels.
//
// The endpoint has no DELETE, and because a write always overwrites the channels
// there is no way to drop the subscriptions while preserving them — an omitted
// channel is an empty channel. Clearing them is therefore the only faithful
// meaning of destroying a resource that owns them.
func (c *APIClient) DeleteTenantNotificationSettings(ctx context.Context) error {
	return c.UpdateTenantNotificationSettings(ctx, TenantNotificationSettings{})
}

func unsentinel(v string) string {
	if strings.EqualFold(v, emptySentinel) {
		return ""
	}
	return v
}
