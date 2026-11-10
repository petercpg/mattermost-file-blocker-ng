package filter

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractExtensions(t *testing.T) {
	tests := []struct {
		filename string
		expected []string
	}{
		{"report.pdf", []string{"pdf"}},
		{"FILE.PDF", []string{"pdf"}},
		{"archive.tar.gz", []string{"gz", "tar.gz"}},
		{"malware.pdf.exe", []string{"exe", "pdf.exe"}},
		{"no_ext", nil},
		{"trailing_dot.", nil},
		{"   spaced.doc   ", []string{"doc"}},
	}

	for _, tt := range tests {
		actual := ExtractExtensions(tt.filename)
		assert.Equal(t, tt.expected, actual, "Filename: %s", tt.filename)
	}
}

func TestMatchMimeType(t *testing.T) {
	patterns := []string{
		"application/x-msdownload",
		"video/*",
		"application/x-sh*",
	}

	tests := []struct {
		mime     string
		expected bool
	}{
		{"application/x-msdownload", true},
		{"video/mp4", true},
		{"video/quicktime", true},
		{"application/x-shellscript", true},
		{"image/png", false},
		{"text/plain", false},
	}

	for _, tt := range tests {
		matched, _ := MatchMimeType(tt.mime, patterns)
		assert.Equal(t, tt.expected, matched, "MIME: %s", tt.mime)
	}
}

func TestValidateFile_BlacklistMode(t *testing.T) {
	cfg := CheckConfig{
		Enabled: true,
		Mode:    ModeBlacklist,
		BlockedExtensions: map[string]struct{}{
			"exe": {},
			"bat": {},
			"ps1": {},
			"sh":  {},
		},
		BlockedMimeTypes: []string{"application/x-msdownload"},
	}

	// 1. Allowed safe files
	res := ValidateFile("invoice.pdf", "application/pdf", nil, cfg, nil)
	assert.True(t, res.Allowed)

	res = ValidateFile("picture.png", "image/png", nil, cfg, nil)
	assert.True(t, res.Allowed)

	// 2. Blocked extensions
	res = ValidateFile("setup.exe", "application/octet-stream", nil, cfg, nil)
	assert.False(t, res.Allowed)
	assert.Equal(t, ".exe", res.Violation)

	res = ValidateFile("script.BAT", "text/plain", nil, cfg, nil)
	assert.False(t, res.Allowed)
	assert.Equal(t, ".bat", res.Violation)

	// 3. Double extension evasion attack
	res = ValidateFile("invoice.pdf.exe", "application/octet-stream", nil, cfg, nil)
	assert.False(t, res.Allowed)

	res = ValidateFile("ClickFix_repair.docx.bat", "text/plain", nil, cfg, nil)
	assert.False(t, res.Allowed)

	// 4. Blocked MIME type
	res = ValidateFile("unknown_payload", "application/x-msdownload", nil, cfg, nil)
	assert.False(t, res.Allowed)

	// 5. Content-sniffed MIME: client claims image/png, but content is actually text/html and text/html is blocked
	cfgWithHTML := cfg
	cfgWithHTML.BlockedMimeTypes = []string{"text/html"}
	htmlHeader := []byte("<!DOCTYPE html><html><body>malicious script</body></html>")
	res = ValidateFile("picture.png", "image/png", htmlHeader, cfgWithHTML, nil)
	assert.False(t, res.Allowed)
	assert.Equal(t, "text/html", res.Violation)
}

func TestValidateFile_WhitelistMode(t *testing.T) {
	cfg := CheckConfig{
		Enabled: true,
		Mode:    ModeWhitelist,
		AllowedExtensions: map[string]struct{}{
			"pdf": {},
			"png": {},
			"jpg": {},
		},
	}

	// Allowed
	res := ValidateFile("doc.pdf", "application/pdf", nil, cfg, nil)
	assert.True(t, res.Allowed)

	// Rejected - not in whitelist
	res = ValidateFile("archive.zip", "application/zip", nil, cfg, nil)
	assert.False(t, res.Allowed)

	// Rejected - no extension
	res = ValidateFile("README", "text/plain", nil, cfg, nil)
	assert.False(t, res.Allowed)
}

func TestValidateFile_DeepInspection(t *testing.T) {
	cfg := CheckConfig{
		Enabled:              true,
		Mode:                 ModeBlacklist,
		BlockedExtensions:    map[string]struct{}{"exe": {}, "bat": {}, "sh": {}},
		EnableDeepInspection: true,
	}

	// 1. Disguised Windows EXE renamed as .pdf
	peHeader := []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}
	res := ValidateFile("report.pdf", "application/pdf", peHeader, cfg, nil)
	assert.False(t, res.Allowed)
	assert.Contains(t, res.Reason, "Windows PE Executable")

	// 2. Disguised Linux ELF binary renamed as .txt
	elfHeader := []byte{0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00}
	res = ValidateFile("notes.txt", "text/plain", elfHeader, cfg, nil)
	assert.False(t, res.Allowed)
	assert.Contains(t, res.Reason, "Linux ELF")

	// 3. Shell script with Shebang renamed as .log
	shHeader := []byte("#!/bin/bash\necho 'hello'\n")
	res = ValidateFile("debug.log", "text/plain", shHeader, cfg, nil)
	assert.False(t, res.Allowed)
	assert.Contains(t, res.Reason, "Unix Script")

	// 4. ClickFix / Batch command keywords disguised as .txt
	clickFixHeader := []byte("@echo off\npowershell.exe -w hidden -enc JABzAHIAYwA=\n")
	res = ValidateFile("guide.txt", "text/plain", clickFixHeader, cfg, nil)
	assert.False(t, res.Allowed)
	assert.Contains(t, res.Reason, "ClickFix")

	// 5. Genuine text file - allowed
	safeTextHeader := []byte("This is an official meeting memo from our department.\n")
	res = ValidateFile("memo.txt", "text/plain", safeTextHeader, cfg, nil)
	assert.True(t, res.Allowed)
}

func TestValidateFile_ZipInspection(t *testing.T) {
	cfg := CheckConfig{
		Enabled:            true,
		Mode:               ModeBlacklist,
		BlockedExtensions:  map[string]struct{}{"bat": {}, "exe": {}},
		InspectZipArchives: true,
	}

	// Create a zip with malicious bat file inside
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	w, err := zw.Create("folder/ClickFix.bat")
	require.NoError(t, err)
	_, err = w.Write([]byte("@echo off\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	zipBytes := buf.Bytes()
	inspector := func(blockedExts map[string]struct{}) (bool, string) {
		reader := bytes.NewReader(zipBytes)
		return InspectZipContent(reader, int64(len(zipBytes)), blockedExts)
	}

	res := ValidateFile("archive.zip", "application/zip", zipBytes[:16], cfg, inspector)
	assert.False(t, res.Allowed)
	assert.Contains(t, res.Violation, "ClickFix.bat")
}
