# Shield AST 🛡️

A Just-In-Time (JIT) Application Security Testing aggregator built in Go.

Shield AST provides a unified, cross-platform CLI to run four major security scanners (Opengrep, OSV-Scanner, Trivy, and TruffleHog) without requiring you to install them manually. It automatically downloads the correct binaries for your OS/Architecture, caches them, executes scans in parallel, and presents the results in an interactive terminal interface or a consolidated JSON report.

## 🚀 Features

- **JIT Provisioning:** Zero-install dependency. Downloads scanners on the fly and caches them in `~/.shield-ast/bin`.
- **4-Pillar Security:** Covers SAST (Code), SCA (Dependencies), IaC (Infrastructure), and Secrets (Credentials).
- **Reachability Analysis:** Automatically filters out vulnerable dependencies that are never invoked by your code, drastically reducing false positives (SCA).
- **Interactive TUI:** Explore vulnerabilities in a split-screen terminal interface with Vim keybindings, Code Snippets, and Reachability Context.
- **CI/CD Ready (Security Gate):** Built-in capability to block automated pipelines (Exit Code 1) with customizable severity thresholds (`--fail-on`).
- **High Performance:** Downloads and executes engines concurrently using real parallelism (Goroutines and WaitGroups) with visual progress feedback.
- **Cross-Platform:** Works seamlessly across Linux, macOS (Intel & Apple Silicon), and Windows.

## 🧰 Engines Included

| Type | Engine | Focus |
|---|---|---|
| **SAST** | [Opengrep](https://github.com/opengrep/opengrep) | Static code analysis and custom rules (Community-driven Semgrep fork). |
| **SCA** | [OSV-Scanner](https://google.github.io/osv-scanner/) | Open Source Vulnerability scanner with Call Graph analysis (Reachability). |
| **IaC** | [Trivy](https://aquasecurity.github.io/trivy/) | Infrastructure as Code misconfiguration scanning (Terraform, Dockerfile, etc). |
| **Secrets** | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Secrets Discovery, Classification, and Validation (Active API verification). |

## 🛠️ Installation

You can install Shield AST by downloading a pre-compiled binary or by building it from source.

### Option A: Pre-compiled Binaries (Recommended)

1. Go to the [Releases page](https://github.com/JAugusto42/shield-ast/releases) and download the latest version (`v1.2.0`) for your operating system and architecture.
2. Extract the downloaded file.
3. Make the binary executable and move it to your system's PATH:

**Linux / macOS:**

```bash
chmod +x shield-OS-ARCH
sudo mv shield-OS-ARCH /usr/local/bin/shield
```

**Windows:**
Move the `shield-windows-amd64.exe` file to a folder of your choice and add that folder to your system's `PATH` Environment Variable.

### Option B: Build from Source

If you have Go 1.22+ installed, you can clone the repository and build it manually:

```bash
git clone <https://github.com/JAugusto42/shield-ast.git>
cd shield-ast
go build -o shield cmd/shield/main.go
```

## Move to your bin path (Linux/macOS)

```bash
sudo mv shield /usr/local/bin/
```

## 💻 Usage

Run the scanner against the current directory using the `scan` subcommand (this will open the Interactive TUI):

```bash
shield scan .
```

To see the global help menu:

```bash
shield
```

To see specific options for the scan command:

```bash
shield scan --help
```

### 🎮 Interactive TUI Controls

When running in default mode (`--output=tui`), Shield AST opens a split-screen terminal UI:

- `j` or `↓` : Move down the list of findings.
- `k` or `↑` : Move up the list of findings.
- `q` or `ESC` : Quit the application.

### ⚙️ Scan Options

The `scan` subcommand supports several flags to customize its behavior:

| Flag | Default | Description |
|---|---|---|
| `--path` | `.` | Target directory to scan (can also be passed as a positional argument). |
| `--output` | `tui` | Output format. Use `tui` for the interactive UI, or pass a path ending in `.json` (e.g., `report.json`) to export the raw consolidated data. |
| `--security-gate` | `false` | Exit with code 1 if *any* vulnerabilities are found (blocks CI/CD pipelines). |
| `--fail-on` | `""` | Comma-separated severities to break the build (e.g., `CRITICAL,HIGH`). |
| `--disable-reachability` | `false` | Disable Call Graph filtering and show all unreachable SCA vulnerabilities. |
| `--debug` | `false` | Enable verbose logging (downloads, stdout, stderr, cache hits). |
| `--sast` | `true` | Enable or disable the Opengrep SAST scanner. |
| `--sca` | `true` | Enable or disable the OSV-Scanner SCA scanner. |
| `--iac` | `true` | Enable or disable the Trivy IaC scanner. |
| `--secrets` | `true` | Enable or disable the TruffleHog Secrets scanner. |

**Examples:**

Scan a specific project and save the output to a JSON file:

```bash
shield scan /var/www/my-project --output=security-audit.json
```

**CI/CD Pipeline Usage (Strict Mode):** Block the pipeline (Exit 1) if *any* vulnerabilities are found, generating a JSON report without launching the interactive TUI:

```bash
shield scan --security-gate --output=report.json .
```

**CI/CD Pipeline Usage (Threshold Mode):** Block the pipeline *only* if `CRITICAL` or `HIGH` vulnerabilities are found. Lower severities are logged but won't break the build:

```bash
shield scan --fail-on="CRITICAL,HIGH" --output=security-audit.json .
```

Run only SAST and Secrets, disabling SCA and IaC, and open the interactive TUI:

```bash
shield scan . --sca=false --iac=false
```

## 🏗️ Project Structure

Shield follows the Standard Go Project Layout:

- `cmd/shield/`: Application entrypoint and CLI flag parsing.
- `internal/downloader/`: Resilient HTTP client with automatic retries, caching, and atomic `.tar.gz` in-memory extraction.
- `internal/scanners/`: Version mapping and OS/Arch translation logic for third-party binaries.
- `internal/orchestrator/`: Concurrency core using Goroutines and WaitGroups to manage overlapping I/O bounds and CPU bounds.
- `internal/reporter/`: Unifies disparate JSON schemas and powers the Interactive TUI (tview/tcell) and JSON exporter.

## 📜 License

MIT License. See `LICENSE` for more information. Note that the underlying tools downloaded by Shield AST (Opengrep, OSV-Scanner, Trivy, and TruffleHog) are governed by their respective Open Source licenses.
