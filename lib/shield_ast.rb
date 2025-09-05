# lib/shield_ast/main.rb
# frozen_string_literal: true

require_relative "shield_ast/version"
require_relative "shield_ast/runner"
require "json"
require "fileutils"
require "erb"
require "prawn"
require "prawn/table"
require "gemini-ai"

# Main module for the Shield AST gem.
module ShieldAst
  class Error < StandardError; end

  # Main class for the Shield AST command-line tool.
  class Main
    SCAN_DATA_FILE = File.join(Dir.pwd, "reports", "scan_data.json")
    REPORT_JSON_FILE = File.join(Dir.pwd, "reports", "scan_report.json")
    REPORT_PDF_FILE = File.join(Dir.pwd, "reports", "scan_report.pdf")
    PDF_TEMPLATE = File.join(__dir__, "reports", "templates", "pdf_report_template.rb")

    def self.call(args)
      ascii_banner

      unless scanner_exists?("osv-scanner") && scanner_exists?("semgrep")
        puts "\e[31m[!] ERROR:\e[0m Required tools not found."
        puts "    Install: \e[33mosv-scanner\e[0m, \e[33msemgrep\e[0m"
        exit 1
      end

      options = parse_args(args)
      handle_options(options)
    end

    def self.scanner_exists?(scanner)
      system("which #{scanner} > /dev/null 2>&1")
    end

    def self.handle_options(options)
      if options[:help]
        show_help
      elsif options[:version]
        puts "Shield AST version #{ShieldAst::VERSION}"
      elsif options[:command] == "scan"
        run_scan(options)
      elsif options[:command] == "report"
        generate_report(options)
      else
        puts "Invalid command. Use 'ast help' for more information."
        show_help
      end
    end

    def self.run_scan(options)
      path = options[:path] || Dir.pwd
      options = apply_default_scanners(options)

      puts "🚀 Starting scan ..."
      start_time = Time.now

      reports = Runner.run(options, path) || {}

      end_time = Time.now
      execution_time = end_time - start_time

      display_reports(reports, execution_time)
      save_scan_data(reports, execution_time)
    end

    def self.save_scan_data(reports, execution_time)
      normalized_reports = {}
      reports.each do |key, value|
        normalized_reports[key.to_sym] = value.transform_keys(&:to_sym)
      end
      data = {
        reports: normalized_reports,
        execution_time: execution_time,
        generated_at: Time.now.strftime("%Y-%m-%d %H:%M:%S %z")
      }
      FileUtils.mkdir_p(File.dirname(SCAN_DATA_FILE))
      File.write(SCAN_DATA_FILE, JSON.pretty_generate(data))
      puts "Scan data saved to: #{SCAN_DATA_FILE}"
    end

    def self.load_scan_data
      unless File.exist?(SCAN_DATA_FILE)
        puts "Error: Scan data file #{SCAN_DATA_FILE} does not exist."
        return nil
      end

      begin
        JSON.parse(File.read(SCAN_DATA_FILE), symbolize_names: true)
      rescue JSON::ParserError => e
        puts "Error: Invalid scan data in #{SCAN_DATA_FILE}: #{e.message}"
        nil
      end
    end

    def self.generate_report(options)
      scan_data = load_scan_data
      unless scan_data
        puts "No scan data available. Please run 'ast scan' first."
        return
      end

      output_format = options[:output] || "json"
      unless %w[json pdf].include?(output_format)
        puts "Error: Invalid output format '#{output_format}'. Use 'json' or 'pdf'."
        return
      end

      puts "Generating #{output_format.upcase} report..."

      if output_format == "json"
        generate_json_report(scan_data)
      elsif output_format == "pdf"
        generate_pdf_report(scan_data)
      end
    end

    def self.generate_json_report(scan_data)
      FileUtils.mkdir_p(File.dirname(REPORT_JSON_FILE))
      report = {
        generated_at: scan_data[:generated_at],
        scan_duration: format_duration(scan_data[:execution_time]),
        total_issues: calculate_total_issues(scan_data[:reports]),
        severity_summary: calculate_severity_summary(scan_data[:reports]),
        reports: scan_data[:reports]
      }
      File.write(REPORT_JSON_FILE, JSON.pretty_generate(report))
      puts "JSON report generated at: #{REPORT_JSON_FILE}"
    end

    def self.generate_pdf_report(scan_data)
      unless File.exist?(PDF_TEMPLATE)
        puts "Error: PDF template file #{PDF_TEMPLATE} not found."
        return
      end

      FileUtils.mkdir_p(File.dirname(REPORT_PDF_FILE))

      version = ShieldAst::VERSION
      generated_at = scan_data[:generated_at]
      scan_duration = format_duration(scan_data[:execution_time])
      sast_results = normalize_results(sort_by_severity(scan_data[:reports][:sast]&.[](:results) || []))
      sca_results = normalize_results(sort_by_severity(scan_data[:reports][:sca]&.[](:results) || []))
      iac_results = normalize_results(sort_by_severity(scan_data[:reports][:iac]&.[](:results) || []))
      total_issues = calculate_total_issues(scan_data[:reports])
      severity_summary = calculate_severity_summary(scan_data[:reports])
      output_file = REPORT_PDF_FILE

      begin
        template_context = Object.new
        template_context.instance_variable_set(:@version, version)
        template_context.instance_variable_set(:@generated_at, generated_at)
        template_context.instance_variable_set(:@scan_duration, scan_duration)
        template_context.instance_variable_set(:@sast_results, sast_results)
        template_context.instance_variable_set(:@sca_results, sca_results)
        template_context.instance_variable_set(:@iac_results, iac_results)
        template_context.instance_variable_set(:@total_issues, total_issues)
        template_context.instance_variable_set(:@severity_summary, severity_summary)
        template_context.instance_variable_set(:@output_file, output_file)
        template = File.read(PDF_TEMPLATE)
        template_context.instance_eval template, PDF_TEMPLATE
        puts "PDF report generated at: #{REPORT_PDF_FILE}"
      rescue StandardError => e
        puts "Error: Failed to generate PDF: #{e.message}"
        puts "Error: Backtrace: #{e.backtrace.join("\n")}"
      end
    end

    def self.normalize_results(results)
      results.map do |result|
        normalized = result.transform_keys(&:to_sym)
        normalized[:severity] ||= normalized[:extra]&.[](:severity) || normalized[:extra]&.[]("severity") || "INFO"
        normalized[:vulnerable_version] = normalized[:vulnerable_version].to_s if normalized[:vulnerable_version]
        normalized[:fixed_version] = normalized[:fixed_version].to_s if normalized[:fixed_version]
        normalized
      end
    end

    def self.calculate_total_issues(reports)
      sast_count = (reports[:sast]&.[](:results) || reports["sast"]&.[]("results") || []).length
      sca_count = (reports[:sca]&.[](:results) || reports["sca"]&.[]("results") || []).length
      iac_count = (reports[:iac]&.[](:results) || reports["iac"]&.[]("results") || []).length
      sast_count + sca_count + iac_count
    end

    def self.apply_default_scanners(options)
      options.tap do |o|
        if !o[:sast] && !o[:sca] && !o[:iac]
          o[:sast] = true
          o[:sca] = true
          o[:iac] = true
        end
      end
    end

    def self.display_reports(reports, execution_time)
      gemini_enabled = !ENV["GEMINI_API_KEY"].to_s.empty?

      total_issues = flatten_findings(reports).length

      puts "\n✅ Scan finished in: #{format_duration(execution_time)}"

      if total_issues.zero?
        puts "✅ No security issues found! Your code looks clean."
        return
      end

      puts "\nScan Results:"
      if gemini_enabled
        puts "\e[34m🔑 Gemini API key found. False positive analysis enabled (this may slow down the scan).\e[0m"
      end

      reports.each do |scan_type, report_data|
        next unless report_data.is_a?(Hash)

        results = report_data[:results] || report_data["results"] || []
        next if results.empty?

        sorted_results = sort_by_severity(results)

        top_results = sorted_results.first(5)
        remaining_count = sorted_results.length - top_results.length

        puts "\n#{get_scan_icon(scan_type.to_sym)} #{scan_type.to_s.upcase} (#{results.length} #{results.length == 1 ? "issue" : "issues"}#{remaining_count.positive? ? ", showing top 5" : ""})"
        puts "-" * 60

        top_results.each do |result|
          if scan_type.to_sym == :sca && has_sca_format?(result)
            format_sca_result(result)
          else
            fp_indicator = gemini_enabled ? check_for_false_positive(result) : ""
            format_default_result(result, fp_indicator)
          end
          puts ""
        end

        if remaining_count.positive?
          puts "... and #{remaining_count} more #{remaining_count == 1 ? "issue" : "issues"}. See the full report for details."
        end
      end

      puts "\n#{"=" * 60}"
      severity_summary = calculate_severity_summary(reports)
      puts "📊 Total: #{total_issues} findings {error_count: #{severity_summary[:error_count]}, warning_count: #{severity_summary[:warning_count]}, info_count: #{severity_summary[:info_count]}}"
    end

    def self.sort_by_severity(results)
      severity_order = { "ERROR" => 0, "WARNING" => 1, "INFO" => 2 }

      results.sort_by do |result|
        severity = result[:severity] || result["severity"] || result.dig(:extra,
                                                                         :severity) || result.dig("extra",
                                                                                                  "severity") || "INFO"
        severity_order[severity.upcase] || 3
      rescue TypeError
        3
      end
    end

    def self.format_report(results, scan_type)
      results.each_with_index do |result, index|
        if scan_type == :sca && has_sca_format?(result)
          format_sca_result(result)
        else
          format_default_result(result)
        end
        puts "" if index < results.length - 1
      end
    end

    def self.get_severity_icon(severity)
      case severity&.upcase
      when "ERROR" then "🔴"
      when "WARNING" then "🟡"
      when "INFO" then "🔵"
      else "⚪"
      end
    end

    def self.get_scan_icon(scan_type)
      case scan_type
      when :sast then "🔍"
      when :sca then "📦"
      when :iac then "☁️"
      else "🛡️"
      end
    end

    def self.calculate_severity_summary(reports)
      error_count = 0
      warning_count = 0
      info_count = 0

      reports.each_value do |report_data|
        (report_data[:results] || report_data["results"] || []).each do |result|
          severity = result[:severity] || result["severity"] || result.dig(:extra,
                                                                           :severity) || result.dig("extra", "severity")
          case severity&.upcase
          when "ERROR" then error_count += 1
          when "WARNING" then warning_count += 1
          when "INFO" then info_count += 1
          end
        end
      end

      { error_count: error_count, warning_count: warning_count, info_count: info_count }
    end

    def self.format_duration(seconds)
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

    def self.has_sca_format?(result)
      (result.key?(:title) || result.key?("title")) &&
        (result.key?(:description) || result.key?("description")) &&
        (result.key?(:vulnerable_version) || result.key?("vulnerable_version")) &&
        (result.key?(:fixed_version) || result.key?("fixed_version"))
    end

    def self.format_sca_result(result)
      severity_icon = get_severity_icon(result[:severity] || result["severity"])
      puts "  #{severity_icon} #{result[:title] || result["title"]} (#{result[:vulnerable_version] || result["vulnerable_version"]} → #{result[:fixed_version] || result["fixed_version"]})"
      puts "     📁 #{result[:file] || result["file"]} | #{(result[:description] || result["description"] || "")[0..80]}#{(result[:description] || result["description"] || "").length > 80 ? "..." : ""}"
    end

    def self.format_default_result(result, fp_indicator = "")
      severity_icon = get_severity_icon(result[:severity] || result["severity"] || result[:extra]&.[](:severity) || result["extra"]&.[]("severity"))
      message = result[:extra]&.[](:message) || result["extra"]&.[]("message") || "Unknown issue"
      title = message.split(".")[0].strip
      file_info = "#{result[:path] || result["path"] || "N/A"}:#{result[:start]&.[](:line) || result["start"]&.[]("line") || "N/A"}"

      puts "  #{severity_icon} #{title}#{fp_indicator}"
      puts "     📁 #{file_info} | #{(result[:extra]&.[](:message) || result["extra"]&.[]("message") || "No description available")[0..80]}..."
    end

    def self.parse_args(args)
      options = { command: nil, path: nil, sast: false, sca: false, iac: false, help: false, version: false,
                  output: nil }
      args.each_with_index do |arg, index|
        case arg
        when "scan" then options[:command] = "scan"
        when "report" then options[:command] = "report"
        when "-s", "--sast" then options[:sast] = true
        when "-c", "--sca" then options[:sca] = true
        when "-i", "--iac" then options[:iac] = true
        when "-h", "--help" then options[:help] = true
        when "--version" then options[:version] = true
        when "-o", "--output"
          options[:output] = args[index + 1] if index + 1 < args.length
        when /^[^-]/ then options[:path] = arg if options[:command] == "scan" && options[:path].nil?
        end
      end
      options
    end

    def self.flatten_findings(reports)
      findings = []
      reports.each do |scan_type, report_data|
        results = report_data[:results] || report_data["results"] || []

        results.each do |result|
          findings << result.merge(scan_type: scan_type.to_sym)
        end
      end
      sort_by_severity(findings)
    end

    def self.extract_code_snippet(file_path, line_number, context_lines = 10)
      return "Code snippet not available (file not found)." unless File.exist?(file_path)
      return "Code snippet not available (line number not specified)." unless line_number

      lines = File.readlines(file_path)
      start_line = [0, line_number - 1 - context_lines].max
      end_line = [lines.length - 1, line_number - 1 + context_lines].min

      snippet = []
      (start_line..end_line).each do |i|
        line_prefix = i + 1 == line_number ? ">> #{i + 1}: " : "   #{i + 1}: "
        snippet << "#{line_prefix}#{lines[i].chomp}"
      end
      snippet.join("\n")
    rescue StandardError => e
      "Could not read code snippet: #{e.message}"
    end

    def self.check_for_false_positive(finding)
      client = Gemini.new(
        credentials: {
          service: "generative-language-api",
          api_key: ENV["GEMINI_API_KEY"]
        },
        options: { model: "gemini-2.5-pro" }
      )

      file_path = finding["path"]
      line = finding.dig("start", "line")
      message = finding["extra"]["message"] || finding["check_id"] || "N/A"
      code_snippet = extract_code_snippet(file_path, line)

      prompt = <<~PROMPT
        Analyze the following security finding. Based on the code and the description, is it more likely to be a true positive or a false positive?

        **Finding:** #{message}
        **File:** #{file_path || "N/A"}:#{line || "N/A"}

        **Code:**
        ```
        #{code_snippet}
        ```

        Respond with ONLY ONE of the following words: `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `UNCERTAIN`.
      PROMPT

      begin
        request_body = { contents: { role: "user", parts: { text: prompt } } }
        response = client.generate_content(request_body)
        result_text = response.dig("candidates", 0, "content", "parts", 0, "text")&.strip

        return "\e[33m ⚠️ (Possible False Positive)\e[0m" if result_text == "FALSE_POSITIVE"
        return "\e[36m 🛡️ (Verified by AI)\e[0m" if result_text == "TRUE_POSITIVE"
      rescue StandardError => e
        puts "An problem occurred with gemini api: #{e.message}"
      end

      ""
    end

    def self.show_help
      puts <<~HELP
        ast - A powerful command-line tool for Application Security Testing
        Usage:
          ast [command] [options]
        Commands:
          scan [path]    Scans a directory for vulnerabilities. Defaults to the current directory.
          report         Generates a report from the last scan in JSON or PDF format.
          help           Shows this help message.
        Options:
          -s, --sast       Run Static Application Security Testing (SAST) with Semgrep.
          -c, --sca        Run Software Composition Analysis (SCA) with OSV Scanner.
          -i, --iac        Run Infrastructure as Code (IaC) analysis with Semgrep.
          -o, --output     Specify the output format for report (json or pdf, default: json).
          -h, --help       Show this help message.
          --version        Show the ast version.
        Examples:
          ast scan
          ast scan /path/to/project --sast --sca
          ast report --output pdf
        Description:
          ast is an all-in-one command-line tool that automates security testing by
          integrating popular open-source scanners for SAST, SCA, and IaC, helping you
          find and fix vulnerabilities early in the development lifecycle.
      HELP
    end

    def self.ascii_banner
      puts <<~BANNER
        [>>> SHIELD AST <<<]
        powered by open source (semgrep + osv-scanner) \n
      BANNER
    end
  end
end
