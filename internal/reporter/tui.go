package reporter

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type Finding struct {
	Scanner     string
	Severity    string
	ID          string
	CWE         string
	File        string
	Line        string
	Title       string
	Description string
}

func StartTUI(sastData, scaData, iacData []byte) error {
	var findings []Finding

	// Parse Opengrep (SAST)
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
					Scanner:     "SAST",
					Severity:    r.Extra.Severity,
					ID:          r.CheckID,
					CWE:         cwe,
					File:        filepath.Base(r.Path),
					Line:        strconv.Itoa(r.Start.Line),
					Title:       title,
					Description: r.Extra.Message,
				})
			}
		}
	}

	// Parse OSV (SCA)
	if len(scaData) > 0 {
		var sca struct {
			Results []struct {
				Source struct {
					Path string `json:"path"`
				} `json:"source"`
				Packages []struct {
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
					for _, v := range pkg.Vulnerabilities {
						findings = append(findings, Finding{
							Scanner:     "SCA",
							Severity:    "HIGH",
							ID:          v.ID,
							CWE:         "N/A",
							File:        filepath.Base(r.Source.Path),
							Line:        "-",
							Title:       v.Summary,
							Description: v.Details,
						})
					}
				}
			}
		}
	}

	// Parse Trivy (IaC)
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
						Scanner:     "IaC",
						Severity:    v.Severity,
						ID:          v.VulnerabilityID,
						CWE:         "N/A",
						File:        filepath.Base(r.Target),
						Line:        "-",
						Title:       v.Title,
						Description: v.Description,
					})
				}
			}
		}
	}

	if len(findings) == 0 {
		fmt.Println("\n✅ No vulnerabilities found by any scanner!")
		return nil
	}

	// === TUI CONSTRUCTION ===
	app := tview.NewApplication()

	// Left panel (List)
	list := tview.NewList().ShowSecondaryText(false)

	list.SetMainTextColor(tcell.ColorWhite).
		SetSelectedTextColor(tcell.ColorYellow).
		SetSelectedBackgroundColor(tcell.ColorDarkBlue)

	listTitle := fmt.Sprintf(" 🎯 Findings (%d) - [j/k] to navigate ", len(findings))
	list.SetBorder(true).
		SetTitle(listTitle).
		SetTitleAlign(tview.AlignLeft)

	// Right panel (Details)
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
`, f.Scanner, f.Severity, f.ID, f.CWE, f.File, f.Line, f.Title, f.Description)
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
