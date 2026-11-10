package main

import (
	"bytes"
	"io"
	"path/filepath"

	"github.com/mattermost/mattermost-file-blocker-ng/server/filter"
	"github.com/mattermost/mattermost-file-blocker-ng/server/i18n"
	"github.com/mattermost/mattermost-file-blocker-ng/server/notifier"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

// FileWillBeUploaded is called after a file is uploaded, but before it is committed to storage.
// To reject the upload, return a non-empty string.
// To allow the upload unchanged, return nil, "".
func (p *Plugin) FileWillBeUploaded(
	c *plugin.Context,
	info *model.FileInfo,
	file io.Reader,
	output io.Writer,
) (*model.FileInfo, string) {
	if info == nil {
		return nil, ""
	}

	cfg := p.BuildCheckConfig()
	if !cfg.Enabled {
		return nil, ""
	}

	config := p.getConfiguration()

	// 1. Check System Admin exemption
	if config.AllowSystemAdmins && info.CreatorId != "" {
		user, appErr := p.API.GetUser(info.CreatorId)
		if appErr == nil && user != nil && user.IsInRole(model.SystemAdminRoleId) {
			p.API.LogDebug("User is System Administrator, bypassing file blocker",
				"user_id", info.CreatorId,
				"filename", info.Name,
			)
			return nil, ""
		}
	}

	// 2. Check Channel exemption
	if info.ChannelId != "" {
		exemptChannels := p.GetExemptChannelIDs()
		if _, isExempt := exemptChannels[info.ChannelId]; isExempt {
			p.API.LogDebug("Channel is exempt from file blocker",
				"channel_id", info.ChannelId,
				"filename", info.Name,
			)
			return nil, ""
		}
	}

	// 3. Read file header for deep sniffing and ZIP inspection
	var header []byte
	var zipBuffer []byte

	if file != nil {
		if cfg.InspectZipArchives && (filter.ExtractExtensions(info.Name) != nil && filepath.Ext(info.Name) == ".zip") && info.Size > 0 && info.Size <= 10*1024*1024 {
			// Read up to 10MB in memory for full ZIP central directory inspection
			buf := new(bytes.Buffer)
			_, _ = io.CopyN(buf, file, 10*1024*1024)
			zipBuffer = buf.Bytes()
			if len(zipBuffer) > 512 {
				header = zipBuffer[:512]
			} else {
				header = zipBuffer
			}
		} else {
			headerBuf := make([]byte, 512)
			n, _ := io.ReadFull(file, headerBuf)
			header = headerBuf[:n]
		}
	}

	// Prepare ZIP inspector if archive inspection is enabled
	var zipInspector func(blockedExts map[string]struct{}) (bool, string)
	if len(zipBuffer) > 0 {
		zipInspector = func(blockedExts map[string]struct{}) (bool, string) {
			reader := bytes.NewReader(zipBuffer)
			return filter.InspectZipContent(reader, int64(len(zipBuffer)), blockedExts)
		}
	}

	// 4. Validate file against policies
	result := filter.ValidateFile(info.Name, info.MimeType, header, cfg, zipInspector)
	if result.Allowed {
		return nil, ""
	}

	// 5. Retrieve uploader info and locale
	userLocale := "en"
	username := info.CreatorId
	if info.CreatorId != "" {
		if user, appErr := p.API.GetUser(info.CreatorId); appErr == nil && user != nil {
			if user.Locale != "" {
				userLocale = user.Locale
			}
			if user.Username != "" {
				username = user.Username
			}
		}
	}

	// 6. Localize rejection reason
	localizedReason := result.Reason
	if result.ReasonKey != "" {
		localizedReason = i18n.T(userLocale, result.ReasonKey, result.ReasonArgs)
	}

	// 7. File is rejected: Audit logging
	p.API.LogWarn("File upload blocked by security policy",
		"filename", info.Name,
		"mime_type", info.MimeType,
		"creator_id", info.CreatorId,
		"channel_id", info.ChannelId,
		"violation", result.Violation,
		"reason", localizedReason,
	)

	// 8. Security Alert Notification to configured channel
	if config.AlertChannelID != "" {
		_ = notifier.SendSecurityAlert(
			p.API,
			p.botUserID,
			config.AlertChannelID,
			username,
			info.Name,
			result.Violation,
			localizedReason,
			userLocale,
		)
	}

	// 9. Format user rejection message (falls back to localized default if CustomRejectMessage is empty)
	rejectMsg := FormatRejectMessage(
		config.CustomRejectMessage,
		info.Name,
		filepath.Ext(info.Name),
		localizedReason,
		userLocale,
	)

	return nil, rejectMsg
}
