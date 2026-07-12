package orchestrator

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"os/exec"

	"github.com/JAugusto42/shield-ast/internal/reporter"
	"github.com/JAugusto42/shield-ast/internal/scanners"
)

// Config holds the CLI arguments passed to the orchestrator
type Config struct {
	TargetDir  string
	OutputPath string
	RunSAST    bool
	RunSCA     bool
	RunIaC     bool
}

func RunScanners(cacheDir string, cfg Config) error {
	opengrepReady := make(chan string)
	osvReady := make(chan string)
	trivyReady := make(chan string)

	// Only trigger downloads/setup if the scanner is enabled
	go func() {
		if !cfg.RunSAST {
			opengrepReady <- ""
			return
		}
		binPath, _ := scanners.SetupOpengrep(cacheDir)
		opengrepReady <- binPath
	}()

	go func() {
		if !cfg.RunSCA {
			osvReady <- ""
			return
		}
		binPath, _ := scanners.SetupOSV(cacheDir)
		osvReady <- binPath
	}()

	go func() {
		if !cfg.RunIaC {
			trivyReady <- ""
			return
		}
		binPath, _ := scanners.SetupTrivy(cacheDir)
		trivyReady <- binPath
	}()

	var sastOutput, scaOutput, iacOutput []byte

	if bin := <-opengrepReady; bin != "" {
		args := []string{"scan", "--json", cfg.TargetDir}
		sastOutput = runScannerAndValidateJSON("Opengrep (SAST)", bin, args)
	}

	if bin := <-osvReady; bin != "" {
		args := []string{"scan", "--format", "json", "-r", cfg.TargetDir}
		scaOutput = runScannerAndValidateJSON("OSV-Scanner (SCA)", bin, args)
	}

	if bin := <-trivyReady; bin != "" {
		args := []string{"config", "--format", "json", cfg.TargetDir}
		iacOutput = runScannerAndValidateJSON("Trivy (IaC)", bin, args)
	}

	log.Println("[Shield AST] Consolidating scan results...")

	err := reporter.ExportResults(cfg.TargetDir, cfg.OutputPath, sastOutput, scaOutput, iacOutput)
	if err != nil {
		log.Printf("[ERROR] Failed to export report: %v", err)
	}

	return nil
}

func runScannerAndValidateJSON(name, binPath string, args []string) []byte {
	log.Printf(">>> Executing %s...", name)

	cmd := exec.Command(binPath, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	if err != nil && os.Getenv("SHIELD_DEBUG") == "true" {
		log.Printf("[DEBUG] %s exited with status: %v", name, err)
	}

	outputData := stdout.Bytes()

	if len(outputData) > 0 && json.Valid(outputData) {
		log.Printf("✅ %s finished. Valid JSON collected.", name)
		return outputData
	}

	log.Printf("⚠️ %s did not output valid JSON.", name)
	if os.Getenv("SHIELD_DEBUG") == "true" {
		log.Printf("[DEBUG] STDERR: %s", stderr.String())
	}

	return nil
}
