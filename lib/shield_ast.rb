# frozen_string_literal: true

require_relative "shield_ast/version"
require_relative "shield_ast/runner"

module ShieldAst
  class Error < StandardError; end

  class Main
    def self.call(args)
      options = parse_args(args)

      if options[:help]
        show_help
        return
      end

      if options[:version]
        puts "Shield AST version #{ShieldAst::VERSION}"
        return
      end

      command = options[:command]

      if command == "scan"
        path = options[:path] || Dir.pwd

        if !options[:sast] && !options[:sca] && !options[:iac]
          options[:sast] = true
          options[:sca] = true
          options[:iac] = true
        end

        Runner.run(options, path)
      elsif command == "report"
        puts "Generating report... (not yet implemented)"
      else
        puts "Invalid command. Use 'ast help' for more information."
        show_help
      end
    end

    def self.parse_args(args)
      options = {
        sast: false,
        sca: false,
        iac: false,
        help: false,
        version: false
      }

      args.each do |arg|
        case arg
        when "scan" then options[:command] = "scan"
        when "report" then options[:command] = "report"
        when "-s", "--sast" then options[:sast] = true
        when "-c", "--sca" then options[:sca] = true
        when "-i", "--iac" then options[:iac] = true
        when "-h", "--help" then options[:help] = true
        when "--version" then options[:version] = true
        else
          options[:path] = arg if options[:command] == "scan" && options[:path].nil?
        end
      end
      options
    end

    def self.show_help
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
