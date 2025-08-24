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
- **`-s, --sast`** – Run SAST using [Semgrep](https://semgrep.dev).
- **`-c, --sca`** – Run SCA using [OSV Scanner](https://osv.dev).
- **`-i, --iac`** – Run IaC analysis using [Semgrep](https://semgrep.dev) with infrastructure rules.
- **`-o, --output`** – Specify the output format (`json`, `sarif`, `console`).
- **`-h, --help`** – Show this help message.
- **`--version`** – Show the AST version.

---

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
- **SAST** – [Semgrep](https://semgrep.dev) for static code analysis
- **SCA** – [OSV Scanner](https://osv.dev) for dependency vulnerability scanning
- **IaC** – [Semgrep](https://semgrep.dev) rules for Infrastructure as Code

This unified approach streamlines security testing, enabling developers to catch security issues earlier in the development process.

---

## 📄 License

Distributed under the MIT License. See the [LICENSE](LICENSE) file for details.
