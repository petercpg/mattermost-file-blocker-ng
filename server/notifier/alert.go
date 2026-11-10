package notifier

import (
	"strings"

	"github.com/mattermost/mattermost-file-blocker-ng/server/i18n"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

// SendSecurityAlert posts a security alert message to the configured channel.
func SendSecurityAlert(api plugin.API, botUserID, channelID, username, filename, violation, reason, locale string) error {
	if channelID == "" {
		return nil
	}

	senderID := botUserID
	if senderID == "" {
		senderID = "system"
	}

	header := i18n.T(locale, "alert.header")
	uploader := i18n.T(locale, "alert.uploader", map[string]string{"user": username})
	fname := i18n.T(locale, "alert.filename", map[string]string{"filename": filename})
	viol := i18n.T(locale, "alert.violation", map[string]string{"violation": violation})
	rsn := i18n.T(locale, "alert.reason", map[string]string{"reason": reason})
	footer := i18n.T(locale, "alert.footer")

	lines := []string{
		header,
		uploader,
		fname,
		viol,
		rsn,
		footer,
	}

	post := &model.Post{
		UserId:    senderID,
		ChannelId: channelID,
		Message:   strings.Join(lines, "\n"),
	}

	if _, err := api.CreatePost(post); err != nil {
		return err
	}

	return nil
}
