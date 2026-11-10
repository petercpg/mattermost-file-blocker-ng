package filter

import (
	"bytes"
	"strings"
)

// Known Magic Number Signatures
var (
	magicPE    = []byte{0x4D, 0x5A}                         // MZ (DOS/PE executable, DLL, EXE)
	magicELF   = []byte{0x7F, 0x45, 0x4C, 0x46}             // \x7fELF (Linux executable)
	magicMachO = [][]byte{
		{0xFE, 0xED, 0xFA, 0xCE}, // Mach-O 32-bit
		{0xFE, 0xED, 0xFA, 0xCF}, // Mach-O 64-bit
		{0xCE, 0xFA, 0xED, 0xFE}, // Mach-O 32-bit reverse
		{0xCF, 0xFA, 0xED, 0xFE}, // Mach-O 64-bit reverse
		{0xCA, 0xFE, 0xBA, 0xBE}, // Mach-O Universal Binary / Java Class
	}
	magicLNK = []byte{0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00} // Windows Shell Link (.lnk)
)

// ClickFix / Script suspicious keywords in script header
var suspiciousScriptKeywords = []string{
	"@echo off",
	"echo off",
	"powershell",
	"cmd.exe",
	"certutil",
	"invoke-webrequest",
	"downloadstring",
	"mshta",
	"cscript",
	"wscript",
	"start /min",
	"reg add",
}

// SniffExecutableType checks if the given header bytes match executable formats (PE, ELF, Mach-O, LNK).
func SniffExecutableType(header []byte) (isExecutable bool, detectedType string) {
	if len(header) >= 2 && bytes.Equal(header[:2], magicPE) {
		return true, "Windows PE Executable (MZ)"
	}
	if len(header) >= 4 && bytes.Equal(header[:4], magicELF) {
		return true, "Linux ELF Executable"
	}
	for _, m := range magicMachO {
		if len(header) >= len(m) && bytes.Equal(header[:len(m)], m) {
			return true, "Mach-O / Java Class Binary"
		}
	}
	if len(header) >= len(magicLNK) && bytes.Equal(header[:len(magicLNK)], magicLNK) {
		return true, "Windows Shortcut (LNK)"
	}
	return false, ""
}

// SniffScriptType checks if the header content contains Shebang or common ClickFix/Batch script signatures.
func SniffScriptType(header []byte) (isScript bool, detectedType string) {
	trimmed := bytes.TrimSpace(header)
	if len(trimmed) == 0 {
		return false, ""
	}

	// 1. Unix Shebang check (e.g. #!/bin/bash, #!/bin/sh, #!/usr/bin/env)
	if bytes.HasPrefix(trimmed, []byte("#!")) {
		lineEnd := bytes.IndexByte(trimmed, '\n')
		if lineEnd == -1 {
			lineEnd = len(trimmed)
		}
		shebang := string(trimmed[:lineEnd])
		return true, "Unix Script (" + strings.TrimSpace(shebang) + ")"
	}

	// 2. Windows Batch & ClickFix command inspection (case-insensitive)
	lower := strings.ToLower(string(trimmed))
	for _, kw := range suspiciousScriptKeywords {
		if strings.Contains(lower, kw) {
			return true, "Suspicious Script / Command Signature (" + kw + ")"
		}
	}

	return false, ""
}
