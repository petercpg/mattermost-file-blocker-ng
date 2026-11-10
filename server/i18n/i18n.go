package i18n

import (
	"embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed locales/*.json
var localesFS embed.FS

var (
	translations = make(map[string]map[string]string)
	initOnce     sync.Once
)

func init() {
	initOnce.Do(loadTranslations)
}

func loadTranslations() {
	files := []string{"en", "zh-TW"}
	for _, lang := range files {
		data, err := localesFS.ReadFile("locales/" + lang + ".json")
		if err != nil {
			continue
		}

		var m map[string]string
		if err := json.Unmarshal(data, &m); err == nil {
			translations[lang] = m
		}
	}
}

// NormalizeLocale maps client locale strings to supported translation keys.
func NormalizeLocale(locale string) string {
	l := strings.ToLower(strings.TrimSpace(locale))
	l = strings.ReplaceAll(l, "_", "-")

	if strings.HasPrefix(l, "zh") {
		return "zh-TW"
	}
	return "en"
}

// T translates a message key into the requested locale, interpolating placeholders like {{key}}.
func T(locale string, key string, data ...map[string]string) string {
	lang := NormalizeLocale(locale)

	dict, ok := translations[lang]
	if !ok {
		dict = translations["en"]
	}

	val, found := dict[key]
	if !found {
		// Fallback to English
		if enDict, hasEn := translations["en"]; hasEn {
			val, found = enDict[key]
		}
		if !found {
			val = key
		}
	}

	if len(data) > 0 && data[0] != nil {
		for k, v := range data[0] {
			val = strings.ReplaceAll(val, "{{"+k+"}}", v)
		}
	}

	return val
}
