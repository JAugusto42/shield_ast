package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/JAugusto42/shield-ast/internal/orchestrator"
)

func main() {
	targetPath := flag.String("path", ".", "Target directory to scan")
	outputPath := flag.String("output", "tui", "Output format ('tui' or path to a '.json' file)")
	debugMode := flag.Bool("debug", false, "Enable debug mode for verbose logging")
	enableSAST := flag.Bool("sast", true, "Enable SAST scanner (Opengrep)")
	enableSCA := flag.Bool("sca", true, "Enable SCA scanner (OSV-Scanner)")
	enableIaC := flag.Bool("iac", true, "Enable IaC scanner (Trivy)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Shield AST - Just-In-Time Security Aggregator\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *debugMode {
		os.Setenv("SHIELD_DEBUG", "true")
		log.Println("[DEBUG] Debug mode enabled via CLI")
	}

	log.Println("[Shield AST] Starting security aggregator...")

	absTargetDir, err := filepath.Abs(*targetPath)
	if err != nil {
		log.Fatalf("[FATAL] Invalid target directory: %v", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("[FATAL] Could not determine user home directory: %v", err)
	}
	cacheDir := filepath.Join(homeDir, ".shield-ast", "bin")

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Fatalf("[FATAL] Failed to create cache directory: %v", err)
	}

	cfg := orchestrator.Config{
		TargetDir:  absTargetDir,
		OutputPath: *outputPath,
		RunSAST:    *enableSAST,
		RunSCA:     *enableSCA,
		RunIaC:     *enableIaC,
	}

	err = orchestrator.RunScanners(cacheDir, cfg)
	if err != nil {
		log.Fatalf("[FATAL] Error during scanner execution: %v", err)
	}

	log.Println("[Shield AST] Scan completed successfully.")
}
