package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type Finding struct {
	Scanner      string
	Severity     string
	ID           string
	CWE          string
	File         string
	Line         string
	Title        string
	Description  string
	Reachability string
	Snippet      string
}

// Alteramos a assinatura para receber o secretsData
func StartTUI(sastData, scaData, iacData, secretsData []byte) error {
	var findings []Finding
	disableReachability := os.Getenv("SHIELD_DISABLE_REACHABILITY") == "true"

	// 1. Parse SAST
	if len(sastData) > 0 {
		var sast struct {
			Results []struct {
				CheckID string `json:"check_id"`
				Path    string `json:"path"`
				Start   struct {
					Line int `json:"line"`
				} `json:"start"`
				Extra struct {
					Message  string `json:"message"`
					Severity string `json:"severity"`
					Lines    string `json:"lines"`
					Metadata struct {
						CWE                []string `json:"cwe"`
						VulnerabilityClass []string `json:"vulnerability_class"`
					} `json:"metadata"`
				} `json:"extra"`
			} `json:"results"`
		}
		if err := json.Unmarshal(sastData, &sast); err == nil {
			for _, r := range sast.Results {
				cwe := "N/A"
				if len(r.Extra.Metadata.CWE) > 0 {
					cwe = strings.Split(r.Extra.Metadata.CWE[0], ":")[0]
				}

				title := ""
				if len(r.Extra.Metadata.VulnerabilityClass) > 0 {
					title = r.Extra.Metadata.VulnerabilityClass[0]
				} else {
					parts := strings.Split(r.CheckID, ".")
					title = parts[len(parts)-1]
					title = strings.ReplaceAll(title, "-", " ")
					title = strings.Title(title)
				}

				findings = append(findings, Finding{
					Scanner:      "SAST",
					Severity:     r.Extra.Severity,
					ID:           r.CheckID,
					CWE:          cwe,
					File:         filepath.Base(r.Path),
					Line:         strconv.Itoa(r.Start.Line),
					Title:        title,
					Description:  r.Extra.Message,
					Reachability: "",
					Snippet:      strings.TrimSpace(r.Extra.Lines),
				})
			}
		}
	}

	// 2. Parse SCA
	if len(scaData) > 0 {
		var sca struct {
			Results []struct {
				Source struct {
					Path string `json:"path"`
				} `json:"source"`
				Packages []struct {
					Groups []struct {
						ExperimentalAnalysis map[string]struct {
							Called bool `json:"called"`
						} `json:"experimental_analysis"`
					} `json:"groups"`
					Vulnerabilities []struct {
						ID      string `json:"id"`
						Summary string `json:"summary"`
						Details string `json:"details"`
					} `json:"vulnerabilities"`
				} `json:"packages"`
			} `json:"results"`
		}
		if err := json.Unmarshal(scaData, &sca); err == nil {
			for _, r := range sca.Results {
				for _, pkg := range r.Packages {
					reachableMap := make(map[string]bool)
					for _, g := range pkg.Groups {
						for id, analysis := range g.ExperimentalAnalysis {
							reachableMap[id] = analysis.Called
						}
					}

					for _, v := range pkg.Vulnerabilities {
						isCalled, hasAnalysis := reachableMap[v.ID]
						isReachable := true
						if hasAnalysis {
							isReachable = isCalled
						}

						severityLabel := "HIGH"
						reachabilityMsg := ""

						if !isReachable && !disableReachability {
							severityLabel = "UNREACHABLE"
							reachabilityMsg = "🛡️  This vulnerability is present in your dependency tree, but Reachability Analysis verified that your code never invokes the vulnerable function. It is currently safe to ignore."
						}

						findings = append(findings, Finding{
							Scanner:      "SCA",
							Severity:     severityLabel,
							ID:           v.ID,
							CWE:          "N/A",
							File:         filepath.Base(r.Source.Path),
							Line:         "-",
							Title:        v.Summary,
							Description:  v.Details,
							Reachability: reachabilityMsg,
							Snippet:      "",
						})
					}
				}
			}
		}
	}

	// 3. Parse IaC
	if len(iacData) > 0 {
		var iac struct {
			Results []struct {
				Target          string `json:"Target"`
				Vulnerabilities []struct {
					VulnerabilityID string `json:"VulnerabilityID"`
					Title           string `json:"Title"`
					Description     string `json:"Description"`
					Severity        string `json:"Severity"`
				} `json:"Vulnerabilities"`
			} `json:"Results"`
		}
		if err := json.Unmarshal(iacData, &iac); err == nil {
			for _, r := range iac.Results {
				for _, v := range r.Vulnerabilities {
					findings = append(findings, Finding{
						Scanner:      "IaC",
						Severity:     v.Severity,
						ID:           v.VulnerabilityID,
						CWE:          "N/A",
						File:         filepath.Base(r.Target),
						Line:         "-",
						Title:        v.Title,
						Description:  v.Description,
						Reachability: "",
						Snippet:      "",
					})
				}
			}
		}
	}

	// 4. Parse Secrets (TruffleHog)
	if len(secretsData) > 0 {
		var secrets []struct {
			SourceMetadata struct {
				Data struct {
					Filesystem struct {
						File string `json:"file"`
						Line int    `json:"line"`
					} `json:"Filesystem"`
				} `json:"Data"`
			} `json:"SourceMetadata"`
			DetectorName string `json:"DetectorName"`
			Verified     bool   `json:"Verified"`
			Raw          string `json:"Raw"`
			Redacted     string `json:"Redacted"`
		}
		if err := json.Unmarshal(secretsData, &secrets); err == nil {
			for _, s := range secrets {
				// TruffleHog faz validação ativa da chave
				status := "UNVERIFIED (Potentially inactive)"
				if s.Verified {
					status = "VERIFIED (Active & Exploitable!)"
				}

				desc := fmt.Sprintf("A leaked secret was discovered in your codebase.\n\nDetector: %s\nStatus: %s\nRedacted Format: %s\n\nTake immediate action to rotate this credential if it is verified.",
					s.DetectorName, status, s.Redacted)

				findings = append(findings, Finding{
					Scanner:      "Secrets",
					Severity:     "CRITICAL",
					ID:           fmt.Sprintf("TRUFFLEHOG-%s", strings.ToUpper(s.DetectorName)),
					CWE:          "CWE-798", // Use of Hard-coded Credentials
					File:         filepath.Base(s.SourceMetadata.Data.Filesystem.File),
					Line:         strconv.Itoa(s.SourceMetadata.Data.Filesystem.Line),
					Title:        fmt.Sprintf("Exposed %s Credential", s.DetectorName),
					Description:  desc,
					Reachability: "",
					Snippet:      s.Raw, // Mostramos a chave crua no bloco de snippet
				})
			}
		}
	}

	if len(findings) == 0 {
		fmt.Println("\n✅ No vulnerabilities found by any scanner!")
		return nil
	}

	// === TUI CONSTRUCTION ===
	app := tview.NewApplication()

	list := tview.NewList().ShowSecondaryText(false)

	list.SetMainTextColor(tcell.ColorWhite).
		SetSelectedTextColor(tcell.ColorYellow).
		SetSelectedBackgroundColor(tcell.ColorDarkBlue)

	listTitle := fmt.Sprintf(" 🎯 Findings (%d) - [j/k] to navigate ", len(findings))
	list.SetBorder(true).
		SetTitle(listTitle).
		SetTitleAlign(tview.AlignLeft)

	details := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWordWrap(true)
	details.SetBorder(true).
		SetTitle(" 🔍 Vulnerability Details (q/ESC to quit) ")

	for _, f := range findings {
		severity := f.Severity
		if severity == "" {
			severity = "UNK"
		}

		label := fmt.Sprintf("[%s] %s: %s", severity, f.Scanner, truncate(f.Title, 45))
		list.AddItem(label, "", 0, nil)
	}

	updateDetails := func(index int) {
		f := findings[index]

		reachabilityBlock := ""
		if f.Reachability != "" {
			reachabilityBlock = fmt.Sprintf("\n[yellow]Reachability Analysis:[white]\n%s\n", f.Reachability)
		}

		snippetBlock := ""
		if f.Snippet != "" {
			snippetBlock = fmt.Sprintf("\n[yellow]Code Snippet:[white]\n[gray]%s[white]\n", f.Snippet)
		}

		content := fmt.Sprintf(`
[yellow]Scanner:[white]     %s
[yellow]Severity:[white]    %s
[yellow]ID / CVE:[white]    %s
[yellow]CWE:[white]         %s
[yellow]Location:[white]    %s:%s

[yellow]Title:[white]
%s

[yellow]Description:[white]
%s
%s%s`, f.Scanner, f.Severity, f.ID, f.CWE, f.File, f.Line, f.Title, f.Description, reachabilityBlock, snippetBlock)

		details.SetText(content)
	}

	list.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		updateDetails(index)
	})

	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'j' {
			next := list.GetCurrentItem() + 1
			if next < list.GetItemCount() {
				list.SetCurrentItem(next)
			}
			return nil
		} else if event.Rune() == 'k' {
			prev := list.GetCurrentItem() - 1
			if prev >= 0 {
				list.SetCurrentItem(prev)
			}
			return nil
		}
		return event
	})

	if len(findings) > 0 {
		list.SetCurrentItem(0)
		updateDetails(0)
	}

	flex := tview.NewFlex().
		AddItem(list, 0, 1, true).
		AddItem(details, 0, 2, false)

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape || event.Rune() == 'q' {
			app.Stop()
		}
		return event
	})

	if err := app.SetRoot(flex, true).EnableMouse(true).Run(); err != nil {
		return err
	}

	return nil
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max-3] + "..."
	}
	if s == "" {
		return "-"
	}
	return s
}
