package i18n

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestI18nTranslations(t *testing.T) {
	// 1. English
	enMsg := T("en", "reason.whitelist_extension", map[string]string{"ext": "exe"})
	assert.Equal(t, "The extension .exe is not in the allowlist.", enMsg)

	// 2. Traditional Chinese
	zhTWMsg := T("zh-TW", "reason.whitelist_extension", map[string]string{"ext": "exe"})
	assert.Equal(t, "副檔名 .exe 不在允許清單中", zhTWMsg)

	// 3. Any Chinese locale (e.g. zh, zh-HK, zh-CN) maps directly to Traditional Chinese
	zhFallback := T("zh-CN", "reason.whitelist_extension", map[string]string{"ext": "exe"})
	assert.Equal(t, "副檔名 .exe 不在允許清單中", zhFallback)

	// 4. Default / Fallback from unknown locale (e.g. "fr-FR")
	fallbackMsg := T("fr-FR", "reason.no_extension")
	assert.Equal(t, "The file has no extension. The allowlist policy rejected the upload.", fallbackMsg)

	// 5. Unknown key returns key itself
	unknown := T("en", "non.existent.key")
	assert.Equal(t, "non.existent.key", unknown)
}

func TestKeyParity(t *testing.T) {
	en := translations["en"]
	zhTW := translations["zh-TW"]

	assert.NotEmpty(t, en)
	assert.NotEmpty(t, zhTW)

	for k := range en {
		_, ok := zhTW[k]
		assert.True(t, ok, "key %s in en.json should exist in zh-TW.json", k)
	}

	for k := range zhTW {
		_, ok := en[k]
		assert.True(t, ok, "key %s in zh-TW.json should exist in en.json", k)
	}
}

