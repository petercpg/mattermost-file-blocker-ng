package main

import (
	"testing"

	"github.com/mattermost/mattermost-file-blocker-ng/server/i18n"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/stretchr/testify/assert"
)

func TestExecuteCommand(t *testing.T) {
	p := &Plugin{}
	p.setConfiguration(&Configuration{
		EnableBlocker:     true,
		FilterMode:        "blacklist",
		BlockedExtensions: "exe, bat, sh",
	})

	c := &plugin.Context{}

	// 1. Status command (default English)
	resp, appErr := p.ExecuteCommand(c, &model.CommandArgs{Command: "/fileblocker status"})
	assert.Nil(t, appErr)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Text, "File Blocker NG Status")
	assert.Contains(t, resp.Text, "Enabled")

	// 2. Test command - blocked file
	resp, appErr = p.ExecuteCommand(c, &model.CommandArgs{Command: "/fileblocker test malware.bat"})
	assert.Nil(t, appErr)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Text, "Test Result: Upload Blocked")
	assert.Contains(t, resp.Text, ".bat")

	// 3. Test command - allowed file
	resp, appErr = p.ExecuteCommand(c, &model.CommandArgs{Command: "/fileblocker test document.pdf"})
	assert.Nil(t, appErr)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Text, "Test Result: Upload Allowed")

	// 4. Test command - missing argument
	resp, appErr = p.ExecuteCommand(c, &model.CommandArgs{Command: "/fileblocker test"})
	assert.Nil(t, appErr)
	assert.Contains(t, resp.Text, "Specify a file name to test")

	// 5. Help command
	resp, appErr = p.ExecuteCommand(c, &model.CommandArgs{Command: "/fileblocker help"})
	assert.Nil(t, appErr)
	assert.Contains(t, resp.Text, "File Blocker NG Command Help")

	// 6. Direct localized status test
	zhStatus := p.handleCommandStatus("zh-TW")
	assert.Contains(t, zhStatus.Text, i18n.T("zh-TW", "cmd.status_title"))
	assert.Contains(t, zhStatus.Text, "啟用中")
}
