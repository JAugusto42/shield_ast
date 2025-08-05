# frozen_string_literal: true

require_relative "shield_ast/version"
require_relative "shield_ast/runner"
require 'json' # Necessário para o parser do JSON do Semgrep

# Main module for the Shield AST gem.
module ShieldAst
  class Error < StandardError; end

  # Main class for the Shield AST command-line tool.
  # Handles command-line argument parsing and delegates to the Runner.
  class Main
    def self.call(args)
      options = parse_args(args)
      handle_options(options)
    end

    private_class_method def self.handle_options(options)
      if options[:help]
        show_help
      elsif options[:version]
        puts "Shield AST version #{ShieldAst::VERSION}"
      elsif options[:command] == "scan"
        run_scan(options)
      elsif options[:command] == "report"
        puts "Generating report... (not yet implemented)"
      else
        puts "Invalid command. Use 'ast help' for more information."
        show_help
      end
    end

    private_class_method def self.run_scan(options)
      path = options[:path] || Dir.pwd
      options = apply_default_scanners(options)

      puts "\n-> Starting scan..."
      reports = Runner.run(options, path)
      puts "Scan finished."

      display_reports(reports)
    end

    private_class_method def self.apply_default_scanners(options)
      options.tap do |o|
        if !o[:sast] && !o[:sca] && !o[:iac]
          o[:sast] = true
          o[:sca] = true
          o[:iac] = true
        end
      end
    end

    private_class_method def self.display_reports(reports)
      reports.each do |type, report_data|
        puts "\n--- #{type.to_s.upcase} Report ---"

        if report_data["results"] && !report_data["results"].empty?
          format_report(report_data["results"])
        else
          puts "No vulnerabilities found for #{type.to_s.upcase}."
        end
      end
    end

    private_class_method def self.format_report(results)
      results.each do |result|
        title = result["extra"]["message"].split('.')[0].strip
        description = result["extra"]["message"].gsub("\n", ' ').strip
        severity = result["extra"]["severity"]
        file = result["path"]
        line = result["start"]["line"]

        puts "  - Título: #{title}"
        puts "  - Severidade: #{severity}"
        puts "  - Arquivo: #{file}:#{line}"
        puts "  - Descrição: #{description}"
        puts "  - Informações adicionais:"
        puts "    - Categoria: #{result['extra']['metadata']['category']}"
        puts "    - OWASP: #{result['extra']['metadata']['owasp']&.join(', ')}"
        puts "    - Referências: #{result['extra']['metadata']['references']&.join(', ')}"
        puts "    - Confidence: #{result['extra']['metadata']['confidence']}"
        puts "    - Impact: #{result['extra']['metadata']['impact']}"
        puts "\n"
      end
    end

    # Parses command-line arguments to build an options hash.
    private_class_method def self.parse_args(args)
      options = { command: nil, path: nil, sast: false, sca: false, iac: false, help: false, version: false }

      args.each do |arg|
        case arg
        when "scan" then options[:command] = "scan"
        when "report" then options[:command] = "report"
        when "-s", "--sast" then options[:sast] = true
        when "-c", "--sca" then options[:sca] = true
        when "-i", "--iac" then options[:iac] = true
        when "-h", "--help" then options[:help] = true
        when "--version" then options[:version] = true
        when /^[^-]/ then options[:path] = arg if options[:command] == "scan" && options[:path].nil?
        end
      end
      options
    end

    # Displays the help message for the CLI tool.
    private_class_method def self.show_help
      puts <<~HELP
        ast - A powerful command-line tool for Application Security Testing

        Usage:
          ast [command] [options]

        Commands:
          scan [path]    Scans a directory for vulnerabilities. Defaults to the current directory.
          report         Generates a detailed report from the last scan.
          help           Shows this help message.

        Options:
          -s, --sast       Run Static Application Security Testing (SAST) with Semgrep.
          -c, --sca        Run Software Composition Analysis (SCA) with dep-scan.
          -i, --iac        Run Infrastructure as Code (IaC) analysis with Semgrep.
          -o, --output     Specify the output format (e.g., json, sarif, console).
          -h, --help       Show this help message.
          --version        Show the ast version.

        Examples:
          # Scan the current directory for all types of vulnerabilities
          ast scan

          # Run only SAST and SCA on a specific project folder
          ast scan /path/to/project --sast --sca

          # Generate a report in SARIF format
          ast report --output sarif

        Description:
          ast is an all-in-one command-line tool that automates security testing by
          integrating popular open-source scanners for SAST, SCA, and IaC, helping you
          find and fix vulnerabilities early in the development lifecycle.
      HELP
    end
  end
end
