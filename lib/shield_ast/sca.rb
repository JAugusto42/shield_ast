# frozen_string_literal: true

require "json"

module ShieldAst
  class SCA
    # Wraps the logic for running SCA scan using Osv Scanner.
    def self.scan(path)
      puts "Scanning path: #{path}" if ENV["DEBUG"]

      if scanner_available?
        puts "OSV Scanner is available" if ENV["DEBUG"]
      else
        puts "OSV Scanner not found in PATH. Please install it first:"
        puts "go install github.com/google/osv-scanner/cmd/osv-scanner@v1"
        return { "results" => [] }
      end

      begin
        cmd = "osv-scanner scan --format json #{path}"
        puts "Executing command: #{cmd}" if ENV["DEBUG"]

        output = `#{cmd} 2>&1`
        exit_code = $CHILD_STATUS.exitstatus

        puts "Exit code: #{exit_code}" if ENV["DEBUG"]
        puts "Output: #{output}" if ENV["DEBUG"]

        case exit_code
        when 0
          { "results" => [] }
        when 1
          { "results" => parse_json_output(output) }
        when 1..126
          puts "OSV Scanner vulnerability error (exit code: #{exit_code})" if ENV["DEBUG"]
          { "results" => parse_json_output(output) }
        when 127
          if output.include?('{"results"')
            puts "OSV Scanner completed with general error but has results" if ENV["DEBUG"]
            { "results" => parse_json_output(output) }
          else
            puts "OSV Scanner general error (exit code: #{exit_code})"
            { "results" => [] }
          end
        when 128
          puts "OSV Scanner found no packages to scan" if ENV["DEBUG"]
          { "results" => [] }
        else
          puts "OSV Scanner non-result error (exit code: #{exit_code})"
          { "results" => [] }
        end
      rescue StandardError => e
        puts "Error running OSV Scanner: #{e.message}"
        { "results" => [] }
      end
    end

    def self.scanner_available?
      result = system("osv-scanner scan --help > /dev/null 2>&1")
      puts "Scanner availability check result: #{result}" if ENV["DEBUG"]
      result
    end

    def self.parse_json_output(output)
      json_start = output.index("{")
      return [] unless json_start

      json_data = JSON.parse(output[json_start..-1])
      convert_to_shield_format(json_data)
    rescue JSON::ParserError
      []
    end

    def self.convert_to_shield_format(osv_data)
      results = []
      scan_results = osv_data["results"] || []

      scan_results.each do |scan_result|
        packages = scan_result["packages"] || []

        packages.each do |package_data|
          vulnerabilities = package_data["vulnerabilities"] || []

          vulnerabilities.each do |vuln|
            results << build_shield_result(vuln, package_data)
          end
        end
      end

      results
    end

    def self.build_shield_result(vuln, package_data)
      package_info = package_data["package"] || {}
      package_name = package_info["name"] || "unknown"
      package_version = package_info["version"] || "unknown"
      ecosystem = package_info["ecosystem"] || "unknown"

      vuln_id = vuln["id"] || "unknown"
      summary = vuln["summary"] || vuln["details"] || "No description available"

      severity = determine_severity(vuln, package_data)
      file_path = determine_file_path(ecosystem)

      fixed_version = extract_fixed_version(vuln)

      {
        "title" => "#{vuln_id}: #{package_name}",
        "severity" => severity,
        "file" => file_path,
        "description" => summary,
        "vulnerable_version" => package_version,
        "fixed_version" => fixed_version,
        "path" => file_path,
        "start" => { "line" => 1 },
        "extra" => {
          "message" => "Vulnerable dependency: #{package_name} (#{package_version}) - #{vuln_id}",
          "severity" => severity,
          "metadata" => {
            "category" => "security",
            "subcategory" => "vulnerable-dependencies",
            "vulnerability_id" => vuln_id,
            "package" => {
              "name" => package_name,
              "ecosystem" => ecosystem,
              "vulnerable_version" => package_version,
              "fixed_version" => fixed_version
            }
          }
        }
      }
    end

    def self.extract_fixed_version(vuln)
      if vuln["affected"].is_a?(Array)
        vuln["affected"].each do |affected|
          if affected["ranges"].is_a?(Array)
            affected["ranges"].each do |range|
              if range["events"].is_a?(Array)
                fixed_event = range["events"].find { |event| event["fixed"] }
                return fixed_event["fixed"] if fixed_event
              end
            end
          end

          if affected["database_specific"] && affected["database_specific"]["last_affected"]
            return "> #{affected["database_specific"]["last_affected"]}"
          end
        end
      end

      if vuln["database_specific"]
        return vuln["database_specific"]["fixed_version"] if vuln["database_specific"]["fixed_version"]
      end

      "Not specified"
    end

    def self.determine_severity(vuln, package_data)
      return map_severity(vuln["database_specific"]["severity"]) if vuln.dig("database_specific", "severity")

      groups = package_data&.dig("groups") || []
      max_severity = groups.first&.dig("max_severity")
      return cvss_to_severity(max_severity.to_f) if max_severity

      "WARNING" # Default severity
    end

    def self.determine_file_path(ecosystem)
      case ecosystem&.downcase
      when "npm", "nodejs" then "package.json"
      when "pip", "pypi" then "requirements.txt"
      when "rubygems" then "Gemfile"
      when "maven" then "pom.xml"
      when "gradle" then "build.gradle"
      when "composer" then "composer.json"
      when "nuget" then "packages.config"
      when "cargo" then "Cargo.toml"
      when "go" then "go.mod"
      else "dependencies"
      end
    end

    def self.map_severity(severity)
      case severity&.to_s&.upcase
      when "CRITICAL", "HIGH" then "ERROR"
      when "MEDIUM", "MODERATE" then "WARNING"
      when "LOW" then "INFO"
      else "WARNING"
      end
    end

    def self.cvss_to_severity(score)
      case score
      when 7.0..10.0 then "ERROR"
      when 4.0..6.9 then "WARNING"
      when 0.1..3.9 then "INFO"
      else "WARNING"
      end
    end
  end
end
