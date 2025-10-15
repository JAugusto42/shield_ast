# Shield AST - Application Security Testing CLI

[![Gem Version](https://badge.fury.io/rb/shield_ast.svg)](https://badge.fury.io/rb/shield_ast)
[![Build Status](https://github.com/JAugusto42/shield_ast/actions/workflows/main.yml/badge.svg)](https://github.com/JAugusto42/shield_ast/actions)
[![Downloads](https://img.shields.io/gem/dt/shield_ast.svg)](https://rubygems.org/gems/shield_ast)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Shield AST** is a powerful command-line tool for **Application Security Testing**, combining multiple open-source scanners into a single workflow. With `ast`, you can run **SAST** (Static Application Security Testing), **SCA** (Software Composition Analysis), and **IaC** (Infrastructure as Code) analysis quickly and automatically, helping you identify and fix vulnerabilities early in the development lifecycle.

---

## 📦 Requirements

- **Ruby** (version 3.0 or later) must be installed on your system.  
  You can check your Ruby version with:
```bash
ruby -v
```
If you don't have Ruby installed, follow the instructions at: [https://www.ruby-lang.org/en/documentation/installation/](https://www.ruby-lang.org/en/documentation/installation/)

---

## 📦 Installation

```bash
# Install the gem
gem install ast
```

---

## 🚀 Usage

```bash
ast [command] [options]
```

### Commands
- **`scan [path]`** – Scans a directory for vulnerabilities. Defaults to the current directory.
- **`report`** – Generates a detailed report from the last scan.
- **`help`** – Displays this help message.

### Options
- **`-s, --sast`** – Run SAST using [Opengrep](https://www.opengrep.dev/).
- **`-c, --sca`** – Run SCA using [OSV Scanner](https://osv.dev).
- **`-i, --iac`** – Run IaC analysis using [Opengrep](https://www.opengrep.dev/) with infrastructure rules.
- **`-o, --output`** – Specify the output format (`json`, `sarif`, `console`).
- **`-h, --help`** – Show this help message.
- **`--version`** – Show the AST version.

---
## ✨ NEW: AI-Powered False Positive Analysis

Shield AST can use the **Google Gemini API** to automatically analyze findings and flag potential false positives, helping you focus on what matters most.

### How to Enable It

To activate this feature, you need a Google AI API key.

### 1. Get Your API Key
First, you'll need a Google Gemini API key to enable AI analysis.

1.  Navigate to **[Google AI Studio](https://aistudio.google.com/app/apikey)**.
2.  Click **"Create API key"** (you may need to sign in with your Google account).
3.  Copy the key once it's generated.

### 2. Configure Your Environment
Next, export the API key as an environment variable in your terminal.

```bash
# Replace with your actual API key
export GEMINI_API_KEY="YOUR_API_KEY_HERE"
````
📌 Tip: This command is temporary and only lasts for the current terminal session.
To make it permanent, add the line above to your shell's configuration file (e.g., ~/.zshrc or ~/.bash_profile).

The tool defaults to the free gemini-2.5-flash model.
If you have access to a more powerful model,
you can specify it by setting the optional GEMINI_MODEL variable:

```bash
export GEMINI_MODEL="gemini-2.5-pro"
```
## 📌 Examples

```bash
# Scan the current directory for all types of vulnerabilities
ast scan

# Run only SAST and SCA on a specific project folder
ast scan /path/to/project --sast --sca

# Generate a report in SARIF format
ast report --output sarif
```

---

## 🛠 How It Works

AST integrates well-known open-source scanners into a single CLI tool:
- **SAST** – [Opengrep](https://www.opengrep.dev/) for static code analysis
- **SCA** – [OSV Scanner](https://osv.dev) for dependency vulnerability scanning
- **IaC** – [Opengrep](https://www.opengrep.dev/) rules for Infrastructure as Code

This unified approach streamlines security testing, enabling developers to catch security issues earlier in the development process.

---

## 📄 License

Distributed under the MIT License. See the [LICENSE](LICENSE) file for details.
