package ports

import "github.com/KKloudTarus/synapse-ce/internal/domain/notification"

// MattermostChannelConfig is a self-hosted incoming webhook. Its complete URL is
// a credential and is decrypted only at send time.
type MattermostChannelConfig struct {
	URL string `json:"url,omitempty"`
}

func (MattermostChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelMattermost
}

// RocketChatChannelConfig is a self-hosted incoming webhook. Its complete URL is
// a credential and is decrypted only at send time.
type RocketChatChannelConfig struct {
	URL string `json:"url,omitempty"`
}

func (RocketChatChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelRocketChat
}

// PagerDutyChannelConfig contains the routing key and the selected, pinned Events API region.
type PagerDutyChannelConfig struct {
	Region     string `json:"region,omitempty"`
	RoutingKey string `json:"routing_key,omitempty"`
}

func (PagerDutyChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelPagerDuty
}

// JSMChannelConfig contains the JSM Operations integration API key. The endpoint is provider
// owned and therefore intentionally absent from tenant configuration.
type JSMChannelConfig struct {
	APIKey string `json:"api_key,omitempty"`
}

func (JSMChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelJSM
}
