package filter

import (
	"net/http"
	"path/filepath"
	"strings"
)

// FilterMode defines filtering strategy: blacklist or whitelist
type FilterMode string

const (
	ModeBlacklist FilterMode = "blacklist"
	ModeWhitelist FilterMode = "whitelist"
)

// CheckConfig holds normalized filtering criteria
type CheckConfig struct {
	Enabled              bool
	Mode                 FilterMode
	BlockedExtensions    map[string]struct{}
	AllowedExtensions    map[string]struct{}
	BlockedMimeTypes     []string
	EnableDeepInspection bool
	InspectZipArchives   bool
}

// CheckResult contains file validation outcome
type CheckResult struct {
	Allowed    bool
	ReasonKey  string
	ReasonArgs map[string]string
	Reason     string
	Violation  string
}

// NormalizeExtension cleans and converts an extension to canonical form (lowercase, no leading dot).
func NormalizeExtension(ext string) string {
	ext = strings.TrimSpace(strings.ToLower(ext))
	ext = strings.TrimPrefix(ext, ".")
	return ext
}

// ExtractExtensions extracts single and multi-level extensions from a filename.
// E.g. "report.pdf.exe" returns ["exe", "pdf.exe"]
func ExtractExtensions(filename string) []string {
	cleanName := filepath.Base(strings.TrimSpace(filename))
	parts := strings.Split(cleanName, ".")
	if len(parts) <= 1 {
		return nil
	}

	exts := make([]string, 0, 2)
	// Last extension: e.g. "exe"
	lastExt := NormalizeExtension(parts[len(parts)-1])
	if lastExt != "" {
		exts = append(exts, lastExt)
	}

	// Double extension if present: e.g. "pdf.exe" or "tar.gz"
	if len(parts) > 2 {
		doubleExt := NormalizeExtension(parts[len(parts)-2] + "." + parts[len(parts)-1])
		if doubleExt != "" {
			exts = append(exts, doubleExt)
		}
	}

	if len(exts) == 0 {
		return nil
	}

	return exts
}

// MatchMimeType checks if an actual MIME type matches any rule in the blocked list.
// Supports wildcards such as "application/x-*" or "video/*".
func MatchMimeType(actualMime string, patterns []string) (bool, string) {
	actual := strings.ToLower(strings.TrimSpace(actualMime))
	if actual == "" {
		return false, ""
	}

	for _, p := range patterns {
		pattern := strings.ToLower(strings.TrimSpace(p))
		if pattern == "" {
			continue
		}

		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(actual, prefix+"/") {
				return true, pattern
			}
		} else if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(actual, prefix) {
				return true, pattern
			}
		} else if actual == pattern {
			return true, pattern
		}
	}

	return false, ""
}

// ValidateFile performs end-to-end inspection of filename, MIME type, and header bytes.
func ValidateFile(
	filename string,
	mimeType string,
	header []byte,
	cfg CheckConfig,
	zipContentInspector func(blockedExts map[string]struct{}) (bool, string),
) CheckResult {
	if !cfg.Enabled {
		return CheckResult{Allowed: true}
	}

	exts := ExtractExtensions(filename)

	// 1. Extension Checks
	if cfg.Mode == ModeWhitelist {
		// Whitelist Mode: File MUST have an extension and that extension MUST be in AllowedExtensions
		if len(exts) == 0 {
			return CheckResult{
				Allowed:    false,
				ReasonKey:  "reason.no_extension",
				Reason:     "檔案無副檔名，白名單安全性政策拒絕上傳",
				Violation:  "no_extension",
			}
		}

		primaryExt := exts[0]
		if _, allowed := cfg.AllowedExtensions[primaryExt]; !allowed {
			return CheckResult{
				Allowed:    false,
				ReasonKey:  "reason.whitelist_extension",
				ReasonArgs: map[string]string{"ext": primaryExt},
				Reason:     "副檔名 ." + primaryExt + " 不在白名單允許清單中",
				Violation:  "." + primaryExt,
			}
		}
	} else {
		// Blacklist Mode: Block if any extension layer matches BlockedExtensions
		for _, ext := range exts {
			if _, blocked := cfg.BlockedExtensions[ext]; blocked {
				return CheckResult{
					Allowed:    false,
					ReasonKey:  "reason.blacklist_extension",
					ReasonArgs: map[string]string{"ext": ext},
					Reason:     "副檔名 ." + ext + " 屬於安全性封鎖清單",
					Violation:  "." + ext,
				}
			}
		}
	}

	// 2. MIME Type Checks (inspects both declared MIME and content-sniffed MIME)
	mimesToCheck := []string{}
	if strings.TrimSpace(mimeType) != "" {
		mimesToCheck = append(mimesToCheck, strings.TrimSpace(mimeType))
	}

	if len(header) > 0 {
		sniffed := http.DetectContentType(header)
		sniffedBase := strings.TrimSpace(strings.Split(sniffed, ";")[0])
		if sniffedBase != "" && sniffedBase != mimeType {
			mimesToCheck = append(mimesToCheck, sniffedBase)
		}
	}

	for _, m := range mimesToCheck {
		if matched, pattern := MatchMimeType(m, cfg.BlockedMimeTypes); matched {
			return CheckResult{
				Allowed:    false,
				ReasonKey:  "reason.blocked_mime",
				ReasonArgs: map[string]string{"mime": m, "pattern": pattern},
				Reason:     "MIME 類型 " + m + " 命中封鎖規則 (" + pattern + ")",
				Violation:  m,
			}
		}
	}

	// 3. Deep Inspection (Magic Bytes & Script Sniffing)
	if cfg.EnableDeepInspection && len(header) > 0 {
		// 3a. Executable binary sniffing
		if isExec, execType := SniffExecutableType(header); isExec {
			// If file header is executable binary:
			// If blacklist blocks exe/dll or whitelist doesn't allow exe, block it!
			_, exeBlocked := cfg.BlockedExtensions["exe"]
			_, dllBlocked := cfg.BlockedExtensions["dll"]
			if cfg.Mode == ModeWhitelist || exeBlocked || dllBlocked {
				return CheckResult{
					Allowed:    false,
					ReasonKey:  "reason.deep_executable",
					ReasonArgs: map[string]string{"detail": execType},
					Reason:     "檔案內容特徵探測為可執行二進位檔 (" + execType + ")，違反安全性原則",
					Violation:  execType,
				}
			}
		}

		// 3b. Script / ClickFix signature sniffing
		if isScript, scriptType := SniffScriptType(header); isScript {
			// Check if scripts/bat/sh are restricted
			_, batBlocked := cfg.BlockedExtensions["bat"]
			_, shBlocked := cfg.BlockedExtensions["sh"]
			_, psBlocked := cfg.BlockedExtensions["ps1"]
			if cfg.Mode == ModeWhitelist || batBlocked || shBlocked || psBlocked {
				return CheckResult{
					Allowed:    false,
					ReasonKey:  "reason.deep_script",
					ReasonArgs: map[string]string{"detail": scriptType},
					Reason:     "檔案內容含有腳本代碼或指令特徵 (" + scriptType + ")，防範 ClickFix 威脅機制已攔截",
					Violation:  scriptType,
				}
			}
		}
	}

	// 4. ZIP Archive Inspection
	if cfg.InspectZipArchives && zipContentInspector != nil && (IsZipArchive(header) || strings.EqualFold(filepath.Ext(filename), ".zip")) {
		if blocked, violatingFile := zipContentInspector(cfg.BlockedExtensions); blocked {
			return CheckResult{
				Allowed:    false,
				ReasonKey:  "reason.zip_restricted",
				ReasonArgs: map[string]string{"file": violatingFile},
				Reason:     "ZIP 壓縮包內含有受封鎖的危險檔案: " + violatingFile,
				Violation:  violatingFile,
			}
		}
	}

	return CheckResult{Allowed: true}
}
