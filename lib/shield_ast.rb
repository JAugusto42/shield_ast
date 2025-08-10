# frozen_string_literal: true

require_relative "shield_ast/version"
require_relative "shield_ast/runner"

require "json"

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

      puts "🚀 Starting scan ..."
      start_time = Time.now

      reports = Runner.run(options, path) || {}

      end_time = Time.now
      execution_time = end_time - start_time

      display_reports(reports, execution_time)
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

    private_class_method def self.display_reports(reports, execution_time)
      total_issues = 0

      reports.each do |type, report_data|
        results = report_data["results"] || []
        total_issues += results.length

        next if results.empty?

        puts "\n#{get_scan_icon(type)} #{type.to_s.upcase} (#{results.length} #{results.length == 1 ? "issue" : "issues"})"
        puts "-" * 60

        format_report(results, type)
      end

      puts "\n✅ Scan finished in: #{format_duration(execution_time)}"

      if total_issues.zero?
        puts "✅ No security issues found! Your code looks clean."
      else
        severity_summary = calculate_severity_summary(reports)
        puts "📊 Total: #{total_issues} findings #{severity_summary}"
      end
    end

    private_class_method def self.format_report(results, scan_type)
      results.each_with_index do |result, index|
        if scan_type == :sca && has_sca_format?(result)
          format_sca_result(result)
        else
          format_default_result(result)
        end
        puts "" if index < results.length - 1 # Add spacing between items, but not after last
      end
    end

    # Helper methods for better formatting
    private_class_method def self.get_severity_icon(severity)
      case severity&.upcase
      when "ERROR" then "🔴"
      when "WARNING" then "🟡"
      when "INFO" then "🔵"
      else "⚪"
      end
    end

    private_class_method def self.get_scan_icon(scan_type)
      case scan_type
      when :sast then "🔍"
      when :sca then "📦"
      when :iac then "☁️"
      else "🛡️"
      end
    end

    private_class_method def self.extract_short_description(result)
      description = result["extra"]["message"].gsub("\n", " ").strip
      if description.length > 80
        "#{description[0..80]}..."
      else
        description
      end
    end

    private_class_method def self.calculate_severity_summary(reports)
      error_count = 0
      warning_count = 0
      info_count = 0

      reports.each_value do |report_data|
        (report_data["results"] || []).each do |result|
          severity = result["severity"] || result.dig("extra", "severity")
          case severity&.upcase
          when "ERROR" then error_count += 1
          when "WARNING" then warning_count += 1
          when "INFO" then info_count += 1
          end
        end
      end

      parts = []
      parts << "#{error_count} 🔴" if error_count.positive?
      parts << "#{warning_count} 🟡" if warning_count.positive?
      parts << "#{info_count} 🔵" if info_count.positive?

      "(#{parts.join(", ")})"
    end

    private_class_method def self.format_duration(seconds)
      if seconds < 1
        "#{(seconds * 1000).round}ms"
      elsif seconds < 60
        "#{seconds.round(1)}s"
      else
        minutes = (seconds / 60).floor
        remaining_seconds = (seconds % 60).round
        "#{minutes}m #{remaining_seconds}s"
      end
    end

    private_class_method def self.has_sca_format?(result)
      result.key?("title") && result.key?("description") &&
      result.key?("vulnerable_version") && result.key?("fixed_version")
    end

    private_class_method def self.format_sca_result(result)
      severity_icon = get_severity_icon(result['severity'])
      puts "  #{severity_icon} #{result["title"]} (#{result["vulnerable_version"]} → #{result["fixed_version"]})"
      puts "     📁 #{result["file"]} | #{result["description"][0..80]}#{result["description"].length > 80 ? "..." : ""}"
    end

    private_class_method def self.format_default_result(result)
      severity_icon = get_severity_icon(result["extra"]["severity"])
      title = result["extra"]["message"].split(".")[0].strip
      file_info = "#{File.basename(result["path"])}:#{result["start"]["line"]}"

      puts "  #{severity_icon} #{title}"
      puts "     📁 #{file_info} | #{extract_short_description(result)}"
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
          -c, --sca        Run Software Composition Analysis (SCA) with OSV Scanner.
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
