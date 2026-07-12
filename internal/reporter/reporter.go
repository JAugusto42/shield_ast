package reporter

import (
	"strings"
)

// ExportResults decides whether to start the interactive TUI or save a JSON file.
func ExportResults(targetDir, outputPath string, sastData, scaData, iacData []byte) error {
	// If the user explicitly asks for the TUI, or doesn't provide a .json extension
	if outputPath == "tui" || outputPath == "" || !strings.HasSuffix(outputPath, ".json") {
		return StartTUI(sastData, scaData, iacData)
	}

	// Otherwise, generate the massive JSON envelope
	return GenerateUnifiedJSON(targetDir, outputPath, sastData, scaData, iacData)
}
