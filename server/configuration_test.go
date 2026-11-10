package main

import (
	"testing"

	"github.com/mattermost/mattermost-file-blocker-ng/server/filter"
	"github.com/stretchr/testify/assert"
)

func TestFormatRejectMessage(t *testing.T) {
	template := "File {{filename}} (ext: {{extension}}) blocked! Reason: {{reason}}"
	result := FormatRejectMessage(template, "malware.exe", ".exe", "Dangerous executable")
	assert.Equal(t, "File malware.exe (ext: .exe) blocked! Reason: Dangerous executable", result)

	// Fallback when empty with Traditional Chinese
	zhResult := FormatRejectMessage("", "test.bat", ".bat", "Blocked", "zh-TW")
	assert.Contains(t, zhResult, "系統資安政策禁止上傳")

	// Fallback when empty with English
	enResult := FormatRejectMessage("", "test.bat", ".bat", "Blocked", "en")
	assert.Contains(t, enResult, "Uploading this type of file or script is prohibited")
}

func TestBuildCheckConfig(t *testing.T) {
	p := &Plugin{}
	p.setConfiguration(&Configuration{
		EnableBlocker:        true,
		FilterMode:           "blacklist",
		BlockedExtensions:    "exe, bat, sh",
		BlockedMimeTypes:     "application/x-msdownload",
		EnableDeepInspection: true,
		InspectZipArchives:   true,
	})

	cfg := p.BuildCheckConfig()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, filter.ModeBlacklist, cfg.Mode)
	assert.Contains(t, cfg.BlockedExtensions, "exe")
	assert.Contains(t, cfg.BlockedExtensions, "bat")
	assert.Contains(t, cfg.BlockedExtensions, "sh")
	assert.Contains(t, cfg.BlockedMimeTypes, "application/x-msdownload")
	assert.True(t, cfg.EnableDeepInspection)
	assert.True(t, cfg.InspectZipArchives)
}
