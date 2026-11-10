package main

import (
	"sync"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/pkg/errors"
)

// Plugin implements the Mattermost plugin interface.
type Plugin struct {
	plugin.MattermostPlugin

	// configurationLock synchronizes access to the configuration.
	configurationLock sync.RWMutex

	// configuration is the active plugin configuration.
	configuration *Configuration

	// botUserID is the user ID of the bot used for posting security notifications.
	botUserID string
}

// OnActivate is invoked when the plugin is activated.
func (p *Plugin) OnActivate() error {
	p.API.LogInfo("File Blocker NG plugin activating...")

	// Attempt to register a dedicated bot user for security alerts
	botUserID, err := p.API.EnsureBotUser(&model.Bot{
		Username:    "fileblocker",
		DisplayName: "File Blocker Security",
		Description: "Automated security alert bot for Mattermost File Blocker NG.",
	})
	if err != nil {
		p.API.LogWarn("Failed to ensure bot user, notifications will fallback to system", "err", err)
	} else {
		p.botUserID = botUserID
	}

	// Register /fileblocker slash command
	if err := p.API.RegisterCommand(getCommand()); err != nil {
		return errors.Wrap(err, "failed to register /fileblocker command")
	}

	p.API.LogInfo("File Blocker NG plugin activated successfully")
	return nil
}

// OnDeactivate is invoked when the plugin is deactivated.
func (p *Plugin) OnDeactivate() error {
	p.API.LogInfo("File Blocker NG plugin deactivated")
	return nil
}
