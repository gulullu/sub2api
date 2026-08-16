package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAIOAuthCYBAdminAlertIsIndependentAndNonOptional(t *testing.T) {
	info, ok := notificationEmailEventDefinitions[NotificationEmailEventOpenAIOAuthCYBAdminAlert]
	require.True(t, ok)
	require.False(t, info.Optional)
	require.NotEqual(t, NotificationEmailEventCyberPolicyNotice, info.Event)
	require.NotContains(t, info.Placeholders, "api_key_id")

	for _, locale := range notificationEmailLocales {
		template := notificationEmailOfficialTemplates[NotificationEmailEventOpenAIOAuthCYBAdminAlert][locale]
		combined := strings.ToLower(template.Subject + " " + template.HTML)
		require.NotContains(t, combined, "cyb")
		require.NotContains(t, combined, "cyber_policy")
		for _, forbidden := range []string{"api_key_id", "preview", "prompt_signature", "request_body", "account_name", "user_email"} {
			require.NotContains(t, combined, forbidden)
		}
		require.Contains(t, template.Subject, "{{event_id}}")
		require.Contains(t, template.HTML, "{{admin_link}}")
	}
}
