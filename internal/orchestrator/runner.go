package orchestrator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/JAugusto42/shield-ast/internal/reporter"
	"github.com/JAugusto42/shield-ast/internal/scanners"
)

type Config struct {
	TargetDir    string
	OutputPath   string
	RunSAST      bool
	RunSCA       bool
	RunIaC       bool
	RunSecrets   bool // <--- New Property
	SecurityGate bool
	FailOn       string
}

func RunScanners(cacheDir string, cfg Config) (int, error) {
	debug := os.Getenv("SHIELD_DEBUG") == "true"

	opengrepReady := make(chan string)
	osvReady := make(chan string)
	trivyReady := make(chan string)
	trufflehogReady := make(chan string) // <--- Channel for Secrets Scanner

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

	// <--- Setup TruffleHog
	go func() {
		if !cfg.RunSecrets {
			trufflehogReady <- ""
			return
		}
		binPath, _ := scanners.SetupTrufflehog(cacheDir)
		trufflehogReady <- binPath
	}()

	doneSpinner := make(chan bool)
	if !debug {
		go func() {
			spinnerChars := []string{"|", "/", "-", "\\"}
			i := 0
			for {
				select {
				case <-doneSpinner:
					fmt.Print("\r\033[K")
					return
				default:
					fmt.Printf("\r\033[36m%s\033[0m [Shield AST] Executing security engines in parallel...", spinnerChars[i])
					i = (i + 1) % len(spinnerChars)
					time.Sleep(100 * time.Millisecond)
				}
			}
		}()
	} else {
		log.Println("[Shield AST] Executing security engines in parallel...")
	}

	var wg sync.WaitGroup
	var sastOutput, scaOutput, iacOutput, secretsOutput []byte // <--- Added secretsOutput

	wg.Add(1)
	go func() {
		defer wg.Done()
		if bin := <-opengrepReady; bin != "" {
			args := []string{"scan", "--json", cfg.TargetDir}
			sastOutput = runScannerAndValidateJSON("Opengrep (SAST)", bin, args, debug)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if bin := <-osvReady; bin != "" {
			args := []string{"scan", "--format", "json", "-r", cfg.TargetDir}
			scaOutput = runScannerAndValidateJSON("OSV-Scanner (SCA)", bin, args, debug)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if bin := <-trivyReady; bin != "" {
			args := []string{"config", "--format", "json", cfg.TargetDir}
			iacOutput = runScannerAndValidateJSON("Trivy (IaC)", bin, args, debug)
		}
	}()

	// <--- Execute TruffleHog (Secrets)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if bin := <-trufflehogReady; bin != "" {
			// Trufflehog parameters
			// We use `filesystem` instead of `git` to avoid issues with shallow clones and uncommitted files
			// `results=verified,unverified,unknown` gets everything. `json` outputs structured data
			args := []string{"filesystem", "--json", "--results=verified,unverified,unknown", cfg.TargetDir}

			rawOutput := runScannerAndValidateJSON("TruffleHog (Secrets)", bin, args, debug)

			// TruffleHog outputs JSONL (one JSON object per line). We need to wrap it in a JSON array `[...]`
			if len(rawOutput) > 0 {
				lines := strings.Split(strings.TrimSpace(string(rawOutput)), "\n")
				joined := strings.Join(lines, ",")
				secretsOutput = []byte("[" + joined + "]")
			}
		}
	}()

	wg.Wait()

	if !debug {
		doneSpinner <- true
	}

	if debug {
		log.Println("[Shield AST] Consolidating scan results...")
	}

	// Make sure to pass the new `secretsOutput` to the reporter
	err := reporter.ExportResults(cfg.TargetDir, cfg.OutputPath, sastOutput, scaOutput, iacOutput, secretsOutput)
	if err != nil && debug {
		log.Printf("[ERROR] Failed to export report: %v", err)
	}

	totalFindings := countFindings(sastOutput, scaOutput, iacOutput, secretsOutput, cfg.FailOn)

	return totalFindings, nil
}

func countFindings(sastData, scaData, iacData, secretsData []byte, failOn string) int {
	total := 0
	disableReachability := os.Getenv("SHIELD_DISABLE_REACHABILITY") == "true"

	targetSeverities := make(map[string]bool)
	if failOn != "" {
		for _, s := range strings.Split(failOn, ",") {
			targetSeverities[strings.ToUpper(strings.TrimSpace(s))] = true
		}
	}

	checkSeverity := func(sev string) bool {
		if failOn == "" {
			return true
		}
		return targetSeverities[strings.ToUpper(sev)]
	}

	if len(sastData) > 0 {
		var sast struct {
			Results []struct {
				Extra struct {
					Severity string `json:"severity"`
				} `json:"extra"`
			} `json:"results"`
		}
		if json.Unmarshal(sastData, &sast) == nil {
			for _, r := range sast.Results {
				if checkSeverity(r.Extra.Severity) {
					total++
				}
			}
		}
	}

	if len(scaData) > 0 {
		var sca struct {
			Results []struct {
				Packages []struct {
					Groups []struct {
						ExperimentalAnalysis map[string]struct {
							Called bool `json:"called"`
						} `json:"experimental_analysis"`
					} `json:"groups"`
					Vulnerabilities []struct {
						ID string `json:"id"`
					} `json:"vulnerabilities"`
				} `json:"packages"`
			} `json:"results"`
		}
		if json.Unmarshal(scaData, &sca) == nil {
			for _, r := range sca.Results {
				for _, p := range r.Packages {
					reachableMap := make(map[string]bool)
					for _, g := range p.Groups {
						for id, analysis := range g.ExperimentalAnalysis {
							reachableMap[id] = analysis.Called
						}
					}

					for _, v := range p.Vulnerabilities {
						isCalled, hasAnalysis := reachableMap[v.ID]

						if hasAnalysis && !isCalled && !disableReachability {
							continue
						}

						if checkSeverity("HIGH") {
							total++
						}
					}
				}
			}
		}
	}

	if len(iacData) > 0 {
		var iac struct {
			Results []struct {
				Vulnerabilities []struct {
					Severity string `json:"Severity"`
				} `json:"Vulnerabilities"`
			} `json:"Results"`
		}
		if json.Unmarshal(iacData, &iac) == nil {
			for _, r := range iac.Results {
				for _, v := range r.Vulnerabilities {
					if checkSeverity(v.Severity) {
						total++
					}
				}
			}
		}
	}

	// <--- Count TruffleHog Secrets
	// All leaked secrets are considered "CRITICAL"
	if len(secretsData) > 0 && checkSeverity("CRITICAL") {
		// Since we wrapped JSONL into an Array `[{},{}]`, we can parse it as a generic slice
		var secrets []interface{}
		if json.Unmarshal(secretsData, &secrets) == nil {
			total += len(secrets)
		}
	}

	return total
}

func runScannerAndValidateJSON(name, binPath string, args []string, debug bool) []byte {
	cmd := exec.Command(binPath, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	if err != nil && debug {
		log.Printf("[DEBUG] %s exited with status: %v", name, err)
	}

	outputData := stdout.Bytes()

	// Handle TruffleHog JSONL validity check
	if name == "TruffleHog (Secrets)" {
		// If there is ANY output on stdout, assume it's valid lines of JSON
		if len(outputData) > 0 {
			if debug {
				log.Printf("✅ %s finished. JSONL collected.", name)
			}
			return outputData
		}
		return nil
	}

	if len(outputData) > 0 && json.Valid(outputData) {
		if debug {
			log.Printf("✅ %s finished. Valid JSON collected.", name)
		}
		return outputData
	}

	if debug {
		log.Printf("⚠️ %s did not output valid JSON. STDERR: %s", name, stderr.String())
	}

	return nil
}
