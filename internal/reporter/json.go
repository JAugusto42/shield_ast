package reporter

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

// ShieldReport represents the consolidated output of all scanners.
type ShieldReport struct {
	Metadata ReportMetadata  `json:"metadata"`
	SAST     json.RawMessage `json:"sast_opengrep,omitempty"`
	SCA      json.RawMessage `json:"sca_osv,omitempty"`
	IaC      json.RawMessage `json:"iac_trivy,omitempty"`
}

type ReportMetadata struct {
	Timestamp string `json:"timestamp"`
	Target    string `json:"target_directory"`
	Version   string `json:"shield_version"`
}

// GenerateUnifiedJSON builds the struct and writes it to the designated output path
func GenerateUnifiedJSON(targetDir, outputPath string, sastData, scaData, iacData []byte) error {
	report := ShieldReport{
		Metadata: ReportMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Target:    targetDir,
			Version:   "1.0.0",
		},
	}

	// We safely assign the byte slices. The omitempty tag ignores them if empty.
	if len(sastData) > 0 {
		report.SAST = sastData
	}
	if len(scaData) > 0 {
		report.SCA = scaData
	}
	if len(iacData) > 0 {
		report.IaC = iacData
	}

	// MarshalIndent formats the JSON with pretty indentation (2 spaces)
	finalJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	// Resolve absolute path if the output path is relative
	absOutput, err := filepath.Abs(outputPath)
	if err != nil {
		absOutput = outputPath
	}

	// WriteFile writes the payload to disk. 0644 means readable by everyone, writable by owner.
	err = os.WriteFile(absOutput, finalJSON, 0644)
	if err != nil {
		return err
	}

	log.Printf("[Reporter] 📄 Consolidated report saved to: %s", absOutput)
	return nil
}
