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
		},
	}

	return c.CreateNotificationSettings(ctx, deleteReq)
}
