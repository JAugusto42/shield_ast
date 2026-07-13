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
	if len(os.Args) < 2 {
		printGlobalUsage()
		os.Exit(0)
	}

	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)

	targetPathFlag := scanCmd.String("path", ".", "Target directory to scan (can also be passed as a positional argument)")
	outputPath := scanCmd.String("output", "tui", "Output format ('tui' or path to a '.json' file)")
	debugMode := scanCmd.Bool("debug", false, "Enable debug mode for verbose logging")
	enableSAST := scanCmd.Bool("sast", true, "Enable SAST scanner (Opengrep)")
	enableSCA := scanCmd.Bool("sca", true, "Enable SCA scanner (OSV-Scanner)")
	enableIaC := scanCmd.Bool("iac", true, "Enable IaC scanner (Trivy)")
	enableSecrets := scanCmd.Bool("secrets", true, "Enable Secret scanning (TruffleHog)")
	securityGate := scanCmd.Bool("security-gate", false, "Exit with code 1 if any vulnerabilities are found")
	failOn := scanCmd.String("fail-on", "", "Comma-separated severities to break the build (e.g. 'CRITICAL,HIGH,ERROR')")
	disableReachability := scanCmd.Bool("disable-reachability", false, "Do not filter unreachable SCA vulnerabilities (show everything)")

	scanCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: shield scan [options] [directory]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		scanCmd.PrintDefaults()
	}

	switch os.Args[1] {
	case "scan":
		scanCmd.Parse(os.Args[2:])

		targetPath := *targetPathFlag
		if scanCmd.NArg() > 0 {
			targetPath = scanCmd.Arg(0)
		}

		runScan(targetPath, *outputPath, *debugMode, *enableSAST, *enableSCA, *enableIaC, *enableSecrets, *securityGate, *failOn, *disableReachability)

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown subcommand '%s'\n\n", os.Args[1])
		printGlobalUsage()
		os.Exit(1)
	}
}

func printGlobalUsage() {
	fmt.Fprintf(os.Stderr, "Shield AST - Just-In-Time Security Aggregator\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  shield <command> [arguments]\n\n")
	fmt.Fprintf(os.Stderr, "The commands are:\n")
	fmt.Fprintf(os.Stderr, "  scan        Run security scanners against a directory\n\n")
	fmt.Fprintf(os.Stderr, "Use \"shield <command> -h\" for more information about a command.\n")
}

func runScan(targetPath, outputPath string, debugMode, enableSAST, enableSCA, enableIaC, enableSecrets, securityGate bool, failOn string, disableReachability bool) {
	if debugMode {
		os.Setenv("SHIELD_DEBUG", "true")
		log.Println("[DEBUG] Debug mode enabled via CLI")
	}

	if disableReachability {
		os.Setenv("SHIELD_DISABLE_REACHABILITY", "true")
		if debugMode {
			log.Println("[DEBUG] Reachability analysis filter disabled. Showing all vulnerabilities.")
		}
	}

	absTargetDir, err := filepath.Abs(targetPath)
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
		TargetDir:    absTargetDir,
		OutputPath:   outputPath,
		RunSAST:      enableSAST,
		RunSCA:       enableSCA,
		RunIaC:       enableIaC,
		RunSecrets:   enableSecrets,
		SecurityGate: securityGate,
		FailOn:       failOn,
	}

	totalFindings, err := orchestrator.RunScanners(cacheDir, cfg)
	if err != nil {
		log.Fatalf("[FATAL] Error during scanner execution: %v", err)
	}

	isGateActive := securityGate || failOn != ""
	if isGateActive && totalFindings > 0 {
		log.Fatalf("🚨 [SECURITY GATE] Pipeline blocked! %d vulnerabilities found matching criteria.", totalFindings)
	}

	if outputPath != "tui" {
		log.Println("[Shield AST] Scan completed successfully.")
	}
}
