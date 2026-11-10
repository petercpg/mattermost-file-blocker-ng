package main

import (
	"strings"

	"github.com/mattermost/mattermost-file-blocker-ng/server/filter"
	"github.com/mattermost/mattermost-file-blocker-ng/server/i18n"
	"github.com/pkg/errors"
)

// Configuration represents the settings configurable via the System Console.
type Configuration struct {
	EnableBlocker        bool   `json:"EnableBlocker"`
	FilterMode           string `json:"FilterMode"`
	BlockedExtensions    string `json:"BlockedExtensions"`
	AllowedExtensions    string `json:"AllowedExtensions"`
	BlockedMimeTypes     string `json:"BlockedMimeTypes"`
	EnableDeepInspection bool   `json:"EnableDeepInspection"`
	InspectZipArchives   bool   `json:"InspectZipArchives"`
	AllowSystemAdmins    bool   `json:"AllowSystemAdmins"`
	ExemptChannelIDs     string `json:"ExemptChannelIDs"`
	CustomRejectMessage  string `json:"CustomRejectMessage"`
	AlertChannelID       string `json:"AlertChannelID"`
}

// Clone creates a shallow copy of the configuration.
func (c *Configuration) Clone() *Configuration {
	var clone = *c
	return &clone
}

// getConfiguration returns the current plugin configuration in a thread-safe manner.
func (p *Plugin) getConfiguration() *Configuration {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()

	if p.configuration == nil {
		return &Configuration{
			EnableBlocker:        true,
			FilterMode:           "blacklist",
			BlockedExtensions:    "exe, bat, cmd, sh, bash, ps1, psm1, dll, com, vbs, js, hta, scr, pif, reg, lnk",
			AllowedExtensions:    "pdf, doc, docx, xls, xlsx, ppt, pptx, png, jpg, jpeg, gif, txt, zip",
			BlockedMimeTypes:     "application/x-msdownload, application/x-sh, application/x-bat, application/x-executable",
			EnableDeepInspection: true,
			InspectZipArchives:   true,
			AllowSystemAdmins:    true,
			CustomRejectMessage:  "",
		}
	}

	return p.configuration
}

// setConfiguration replaces the active configuration in a thread-safe manner.
func (p *Plugin) setConfiguration(configuration *Configuration) {
	p.configurationLock.Lock()
	defer p.configurationLock.Unlock()

	p.configuration = configuration
}

// OnConfigurationChange is invoked when the System Console configuration changes.
func (p *Plugin) OnConfigurationChange() error {
	var configuration = new(Configuration)

	// Load the public configuration fields from the Mattermost server.
	if err := p.API.LoadPluginConfiguration(configuration); err != nil {
		return errors.Wrap(err, "failed to load plugin configuration")
	}

	p.setConfiguration(configuration)
	return nil
}

// BuildCheckConfig builds an optimized filter.CheckConfig from current settings.
func (p *Plugin) BuildCheckConfig() filter.CheckConfig {
	config := p.getConfiguration()

	mode := filter.ModeBlacklist
	if strings.EqualFold(config.FilterMode, string(filter.ModeWhitelist)) {
		mode = filter.ModeWhitelist
	}

	return filter.CheckConfig{
		Enabled:              config.EnableBlocker,
		Mode:                 mode,
		BlockedExtensions:    parseSet(config.BlockedExtensions),
		AllowedExtensions:    parseSet(config.AllowedExtensions),
		BlockedMimeTypes:     parseSlice(config.BlockedMimeTypes),
		EnableDeepInspection: config.EnableDeepInspection,
		InspectZipArchives:   config.InspectZipArchives,
	}
}

// GetExemptChannelIDs returns a set of exempt channel IDs.
func (p *Plugin) GetExemptChannelIDs() map[string]struct{} {
	return parseRawSet(p.getConfiguration().ExemptChannelIDs)
}

// FormatRejectMessage applies placeholders to the rejection message, falling back to i18n default if empty.
func FormatRejectMessage(template, filename, ext, reason string, locale ...string) string {
	msg := strings.TrimSpace(template)
	if msg == "" {
		loc := "en"
		if len(locale) > 0 && locale[0] != "" {
			loc = locale[0]
		}
		msg = i18n.T(loc, "msg.default_reject")
	}

	msg = strings.ReplaceAll(msg, "{{filename}}", filename)
	msg = strings.ReplaceAll(msg, "{{extension}}", ext)
	msg = strings.ReplaceAll(msg, "{{reason}}", reason)
	return msg
}

func parseSet(commaSeparated string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, item := range strings.Split(commaSeparated, ",") {
		clean := filter.NormalizeExtension(item)
		if clean != "" {
			set[clean] = struct{}{}
		}
	}
	return set
}

func parseRawSet(commaSeparated string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, item := range strings.Split(commaSeparated, ",") {
		clean := strings.TrimSpace(item)
		if clean != "" {
			set[clean] = struct{}{}
		}
	}
	return set
}

func parseSlice(commaSeparated string) []string {
	var items []string
	for _, item := range strings.Split(commaSeparated, ",") {
		clean := strings.TrimSpace(item)
		if clean != "" {
			items = append(items, clean)
		}
	}
	return items
}
