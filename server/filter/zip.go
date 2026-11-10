package filter

import (
	"archive/zip"
	"bytes"
	"io"
)

var zipMagic = []byte{0x50, 0x4B, 0x03, 0x04} // PK\x03\x04

// IsZipArchive checks if the given header matches ZIP format.
func IsZipArchive(header []byte) bool {
	return len(header) >= 4 && bytes.Equal(header[:4], zipMagic)
}

// InspectZipContent checks if the zip reader contains files matching blocked extensions.
// If readerAt is available and size > 0, it inspects all files listed in the ZIP directory.
func InspectZipContent(r io.ReaderAt, size int64, blockedExts map[string]struct{}) (blocked bool, violatingFile string) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return false, ""
	}

	for _, file := range zr.File {
		// Ignore directories
		if file.FileInfo().IsDir() {
			continue
		}

		name := file.Name
		exts := ExtractExtensions(name)
		for _, ext := range exts {
			if _, exists := blockedExts[ext]; exists {
				return true, name
			}
		}
	}

	return false, ""
}
