package main

import (
	"fmt"
	"strings"

	"github.com/mattermost/mattermost-file-blocker-ng/server/filter"
	"github.com/mattermost/mattermost-file-blocker-ng/server/i18n"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

const commandTrigger = "fileblocker"

func getCommand() *model.Command {
	return &model.Command{
		Trigger:          commandTrigger,
		DisplayName:      "File Blocker NG",
		Description:      "Manage and test Mattermost File Blocker NG policies",
		AutoComplete:     true,
		AutoCompleteDesc: "Available commands: status, test <filename>, help",
		AutoCompleteHint: "[command]",
	}
}

// ExecuteCommand handles slash command executions for /fileblocker
func (p *Plugin) ExecuteCommand(c *plugin.Context, args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	if args == nil {
		return nil, nil
	}

	locale := "en"
	if args.UserId != "" && p.API != nil {
		if user, err := p.API.GetUser(args.UserId); err == nil && user != nil && user.Locale != "" {
			locale = user.Locale
		}
	}

	raw := strings.TrimSpace(args.Command)
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return &model.CommandResponse{
			ResponseType: model.CommandResponseTypeEphemeral,
			Text:         i18n.T(locale, "cmd.provide_param"),
		}, nil
	}

	subcommand := ""
	if len(fields) > 1 {
		subcommand = strings.ToLower(fields[1])
	}

	switch subcommand {
	case "status":
		return p.handleCommandStatus(locale), nil
	case "test":
		if len(fields) < 3 {
			return &model.CommandResponse{
				ResponseType: model.CommandResponseTypeEphemeral,
				Text:         i18n.T(locale, "cmd.missing_arg"),
			}, nil
		}
		filename := fields[2]
		return p.handleCommandTest(filename, locale), nil
	case "help":
		fallthrough
	default:
		return p.handleCommandHelp(locale), nil
	}
}

func (p *Plugin) handleCommandStatus(locale string) *model.CommandResponse {
	config := p.getConfiguration()
	cfg := p.BuildCheckConfig()

	status := i18n.T(locale, "cmd.status_enabled")
	if !config.EnableBlocker {
		status = i18n.T(locale, "cmd.status_disabled")
	}

	modeText := i18n.T(locale, "cmd.status_mode_blacklist")
	if cfg.Mode == filter.ModeWhitelist {
		modeText = i18n.T(locale, "cmd.status_mode_whitelist")
	}

	deepText := i18n.T(locale, "cmd.status_deep_off")
	if config.EnableDeepInspection {
		deepText = i18n.T(locale, "cmd.status_deep_on")
	}

	zipText := i18n.T(locale, "cmd.status_zip_off")
	if config.InspectZipArchives {
		zipText = i18n.T(locale, "cmd.status_zip_on")
	}

	adminExempt := i18n.T(locale, "cmd.status_admin_no")
	if config.AllowSystemAdmins {
		adminExempt = i18n.T(locale, "cmd.status_admin_yes")
	}

	title := i18n.T(locale, "cmd.status_title")

	msg := fmt.Sprintf(
		"%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
		title,
		i18n.T(locale, "cmd.label_status", map[string]string{"value": status}),
		i18n.T(locale, "cmd.label_mode", map[string]string{"value": modeText}),
		i18n.T(locale, "cmd.label_blocked", map[string]string{"value": config.BlockedExtensions}),
		i18n.T(locale, "cmd.label_allowed", map[string]string{"value": config.AllowedExtensions}),
		i18n.T(locale, "cmd.label_deep", map[string]string{"value": deepText}),
		i18n.T(locale, "cmd.label_zip", map[string]string{"value": zipText}),
		i18n.T(locale, "cmd.label_admin", map[string]string{"value": adminExempt}),
		i18n.T(locale, "cmd.label_alert_channel", map[string]string{"value": config.AlertChannelID}),
	)

	return &model.CommandResponse{
		ResponseType: model.CommandResponseTypeEphemeral,
		Text:         msg,
	}
}

func (p *Plugin) handleCommandTest(filename, locale string) *model.CommandResponse {
	cfg := p.BuildCheckConfig()
	result := filter.ValidateFile(filename, "", nil, cfg, nil)

	var text string
	if result.Allowed {
		title := i18n.T(locale, "cmd.test_allowed_title")
		desc := i18n.T(locale, "cmd.test_allowed_desc", map[string]string{"filename": filename})
		text = fmt.Sprintf("%s\n%s", title, desc)
	} else {
		title := i18n.T(locale, "cmd.test_blocked_title")
		reason := result.Reason
		if result.ReasonKey != "" {
			reason = i18n.T(locale, result.ReasonKey, result.ReasonArgs)
		}
		text = fmt.Sprintf(
			"%s\n%s\n%s\n%s\n",
			title,
			i18n.T(locale, "cmd.label_filename", map[string]string{"value": filename}),
			i18n.T(locale, "cmd.label_violation", map[string]string{"value": result.Violation}),
			i18n.T(locale, "cmd.label_reason", map[string]string{"value": reason}),
		)
	}

	return &model.CommandResponse{
		ResponseType: model.CommandResponseTypeEphemeral,
		Text:         text,
	}
}

func (p *Plugin) handleCommandHelp(locale string) *model.CommandResponse {
	help := fmt.Sprintf(
		"%s\n%s\n%s\n%s\n",
		i18n.T(locale, "cmd.help_title"),
		i18n.T(locale, "cmd.help_status"),
		i18n.T(locale, "cmd.help_test"),
		i18n.T(locale, "cmd.help_help"),
	)

	return &model.CommandResponse{
		ResponseType: model.CommandResponseTypeEphemeral,
		Text:         help,
	}
}
