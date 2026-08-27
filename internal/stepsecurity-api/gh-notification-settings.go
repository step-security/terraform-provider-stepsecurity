package stepsecurityapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type GitHubNotificationSettingsRequest struct {
	Owner string `json:"owner"`
	NotificationSettings
}

type NotificationSettings struct {
	SlackWebhookURL                   string `json:"slackWebhookURL"`
	TeamsWebhookURL                   string `json:"teamsWebhookURL"`
	Email                             string `json:"email"`
	NotifyWhenDomainBlocked           string `json:"notifyWhenDomainBlocked"`
	NotifyOnFileOverwrite             string `json:"notifyOnFileOverwrite"`
	NotifyWhenEndpointDiscovered      string `json:"notifyWhenEndpointDiscovered"`
	NotifyForHttpsDetections          string `json:"notifyForHttpsDetections"`
	NotifyForSecretsDetection         string `json:"notifyForSecretsDetection"`
	NotifyForArtifactSecretsDetection string `json:"notifyForArtifactSecretsDetection"`
	NotifyForImposterCommitsDetection string `json:"notifyForImposterCommitsDetection"`
	NotifyForSuspiciousNetworkCall    string `json:"notifyForSuspiciousNetworkCall"`
	NotifyForSuspiciousProcessEvents  string `json:"notifyForSuspiciousProcessEvents"`
	NotifyForHardenRunnerConfigChange string `json:"notifyForHardenRunnerConfigChanged"`
	NotifyForNonCompliantArtifacts    string `json:"notifyForNonCompliantArtifacts"`
	NotifyForBlockedRunPolicy         string `json:"notifyForBlockedRunPolicy"`
	NotifyForBaselineCheckFailures    string `json:"notifyForBaselineCheckFailures"` // PR Check failure notifications
	NotifyForRequiredCheckFailures    string `json:"notifyForRequiredCheckFailures"` // PR Check failure notifications
	NotifyForOptionalCheckFailures    string `json:"notifyForOptionalCheckFailures"` // PR Check failure notifications
	SlackNotificationMethod           string `json:"slackNotificationMethod"`        // "webhook" (default) or "oauth"
	SlackChannelID                    string `json:"slackChannelID,omitempty"`       // For OAuth: channel to post to
	// OrgThreatIntelLevel is the org's threat intel opt-in granularity:
	// "off", "all", "name" or "version". It is authoritative; the backend only
	// consults the three NotifyForCompromised* flags below when it is empty.
	OrgThreatIntelLevel string `json:"orgThreatIntelLevel"`
	// NotifyForCompromisedNPMInPR, NotifyForCompromisedPyPIInPR and
	// NotifyForCompromisedActionInWorkflow are the per-source flags that predate
	// OrgThreatIntelLevel. They are written from the same on/off as the level, the
	// way the console writes them, so backend paths that still read them agree
	// with the level.
	NotifyForCompromisedNPMInPR          string `json:"notifyForCompromisedNPMInPR"`
	NotifyForCompromisedPyPIInPR         string `json:"notifyForCompromisedPyPIInPR"`
	NotifyForCompromisedActionInWorkflow string `json:"notifyForCompromisedActionInWorkflow"`
}

// OrgThreatIntelLevelOff is the stored level of an org that has explicitly opted
// out of threat intel notifications. It is distinct from an empty level, which
// means the org never configured them and defaults to notifying about
// everything.
const OrgThreatIntelLevelOff = "off"

// OrgThreatIntelLevelFor builds the stored level from an on/off plus a
// granularity, so disabling always writes the explicit opt-out rather than
// clearing the field — an empty level would read back as opted in.
func OrgThreatIntelLevelFor(enabled bool, level string) string {
	if !enabled {
		return OrgThreatIntelLevelOff
	}
	return level
}

// OrgThreatIntelSubscription resolves a stored level into the on/off and
// granularity a configuration expresses.
//
// Org threat intel is opt-out: only an explicit "off" disables it, and an org
// that never configured it notifies about every incident. An empty or
// unrecognized level therefore reads as enabled at "all", matching the backend's
// gate and what the console displays.
//
// A disabled org has no stored granularity, so priorLevel stands in — otherwise
// `enabled = false, level = "name"` would drift on every refresh.
func OrgThreatIntelSubscription(stored, priorLevel string) (enabled bool, level string) {
	switch stored {
	case ThreatIntelLevelAll, ThreatIntelLevelName, ThreatIntelLevelVersion:
		return true, stored
	case OrgThreatIntelLevelOff:
		return false, priorLevel
	default:
		return true, ThreatIntelLevelAll
	}
}

func (c *APIClient) CreateNotificationSettings(ctx context.Context, notificationSettingsReq GitHubNotificationSettingsRequest) error {

	body, err := json.Marshal(notificationSettingsReq)
	if err != nil {
		return fmt.Errorf("failed to marshal notification settings: %w", err)
	}

	URI := fmt.Sprintf("%s/v1/github/%s/actions/runs/notification-settings", c.BaseURL, notificationSettingsReq.Owner)
	req, err := http.NewRequest("POST", URI, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	_, err = c.do(req)
	if err != nil {
		return fmt.Errorf("failed to create notification settings: %w", err)
	}

	return nil
}

func (c *APIClient) GetNotificationSettings(ctx context.Context, owner string) (*NotificationSettings, error) {
	URI := fmt.Sprintf("%s/v1/github/%s/actions/runs/notification-settings", c.BaseURL, owner)
	req, err := http.NewRequest("GET", URI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	respBody, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get notification settings: %w", err)
	}

	var notificationSettings NotificationSettings
	if err := json.Unmarshal(respBody, &notificationSettings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal notification settings: %w", err)
	}

	return &notificationSettings, nil
}

func (c *APIClient) UpdateNotificationSettings(ctx context.Context, notificationSettingsReq GitHubNotificationSettingsRequest) error {
	return c.CreateNotificationSettings(ctx, notificationSettingsReq)
}

func (c *APIClient) DeleteNotificationSettings(ctx context.Context, owner string) error {

	deleteReq := GitHubNotificationSettingsRequest{
		Owner: owner,
		NotificationSettings: NotificationSettings{
			SlackWebhookURL:                   " ",
			TeamsWebhookURL:                   " ",
			Email:                             " ",
			NotifyWhenDomainBlocked:           "false",
			NotifyOnFileOverwrite:             "false",
			NotifyWhenEndpointDiscovered:      "false",
			NotifyForHttpsDetections:          "false",
			NotifyForSecretsDetection:         "false",
			NotifyForArtifactSecretsDetection: "false",
			NotifyForImposterCommitsDetection: "false",
			NotifyForSuspiciousNetworkCall:    "false",
			NotifyForSuspiciousProcessEvents:  "false",
			NotifyForHardenRunnerConfigChange: "false",
			NotifyForNonCompliantArtifacts:    "false",
			NotifyForBlockedRunPolicy:         "false",
			NotifyForBaselineCheckFailures:    "false",
			NotifyForRequiredCheckFailures:    "false",
			NotifyForOptionalCheckFailures:    "false",
			SlackNotificationMethod:           " ",
			SlackChannelID:                    " ",
			// Threat intel is opt-out, so destroying has to write the explicit
			// "off": clearing the level would leave the org notifying about every
			// incident.
			OrgThreatIntelLevel:                  OrgThreatIntelLevelOff,
			NotifyForCompromisedNPMInPR:          "false",
			NotifyForCompromisedPyPIInPR:         "false",
			NotifyForCompromisedActionInWorkflow: "false",
		},
	}

	return c.CreateNotificationSettings(ctx, deleteReq)
}
