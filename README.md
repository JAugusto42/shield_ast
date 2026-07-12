# Shield AST 🛡️

A Just-In-Time (JIT) Application Security Testing aggregator built in Go. 

Shield AST provides a unified, cross-platform CLI to run three major security scanners (Opengrep, OSV-Scanner, and Trivy) without requiring you to install them manually. It automatically downloads the correct binaries for your OS/Architecture, caches them, executes scans in parallel, and presents the results in an interactive terminal interface or a consolidated JSON report.

## 🚀 Features

- **JIT Provisioning:** Zero-install dependency. Downloads scanners on the fly and caches them in `~/.shield-ast/bin`.
- **Interactive TUI:** Explore vulnerabilities in a split-screen terminal interface with Vim keybindings.
- **Unified Reporting:** Aggregates SAST, SCA, and IaC outputs into a single normalized view or a consolidated `.json` file.
- **High Performance:** Downloads and extracts binaries concurrently using Goroutines and Channels.
- **Cross-Platform:** Works seamlessly across Linux, macOS (Intel & Apple Silicon), and Windows.

## 🧰 Engines Included

| Type | Engine | Focus |
|---|---|---|
| **SAST** | [Opengrep](https://github.com/opengrep/opengrep) | Static code analysis and custom rules (Community-driven Semgrep fork). |
| **SCA** | [OSV-Scanner](https://google.github.io/osv-scanner/) | Open Source Vulnerability scanner to find vulnerable dependencies. |
| **IaC** | [Trivy](https://aquasecurity.github.io/trivy/) | Infrastructure as Code misconfiguration scanning (Terraform, Dockerfile, etc). |

## 🛠️ Installation

Ensure you have Go 1.22+ installed. 

```bash
git clone [https://github.com/JAugusto42/shield-ast.git](https://github.com/JAugusto42/shield-ast.git)
cd shield-ast
go build -o shield cmd/shield/main.go

# (Optional) Move to your bin path
sudo mv shield /usr/local/bin/
```

## 💻 Usage

Run the scanner in the current directory with default settings (this will open the Interactive TUI):
```bash
./shield
```

### 🎮 Interactive TUI Controls

When running in default mode (`--output=tui`), Shield AST opens a split-screen terminal UI:
- `j` or `↓` : Move down the list of findings.
- `k` or `↑` : Move up the list of findings.
- `q` or `ESC` : Quit the application.

### ⚙️ CLI Options

Shield AST supports several flags to customize its behavior:

| Flag | Default | Description |
|---|---|---|
| `--path` | `.` | Target directory to scan. |
| `--output` | `tui` | Output format. Use `tui` for the interactive UI, or pass a path ending in `.json` (e.g., `report.json`) to export the raw consolidated data. |
| `--debug` | `false` | Enable verbose logging (downloads, stdout, stderr, cache hits). |
| `--sast` | `true` | Enable or disable the Opengrep SAST scanner. |
| `--sca` | `true` | Enable or disable the OSV-Scanner SCA scanner. |
| `--iac` | `true` | Enable or disable the Trivy IaC scanner. |

**Examples:**

Scan a specific project and save the output to a JSON file for CI/CD integration:
```bash
./shield --path=/var/www/my-project --output=security-audit.json
```

Run only SAST and SCA, disabling IaC, and open the interactive TUI:
```bash
./shield --iac=false
```

Run with verbose debug logs to see download progress and raw execution details:
```bash
./shield --path=. --debug
```

## 🏗️ Project Structure

Shield follows the Standard Go Project Layout:
- `cmd/shield/`: Application entrypoint and CLI flag parsing.
- `internal/downloader/`: Resilient HTTP client with automatic retries, caching, and atomic `.tar.gz` in-memory extraction.
- `internal/scanners/`: Version mapping and OS/Arch translation logic for third-party binaries.
- `internal/orchestrator/`: Concurrency core using Goroutines to manage overlapping I/O bounds and CPU bounds.
- `internal/reporter/`: Unifies disparate JSON schemas and powers the Interactive TUI (tview/tcell) and JSON exporter.

## 📜 License

MIT License. See `LICENSE` for more information. Note that the underlying tools downloaded by Shield AST (Opengrep, OSV-Scanner, and Trivy) are governed by their respective Open Source licenses.
