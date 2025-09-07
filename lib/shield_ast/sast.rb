# frozen_string_literal: true

# lib/shield_ast/sast.rb
require "json"
require "open3"

module ShieldAst
  # Wraps the logic for running SAST scan using Semgrep.
  class SAST
    EXCLUDE_PATTERNS = %w[**/spec/ **/test/ **/tests/ **/features/ **/__tests__/ **/vendor/
                          **/node_modules/ **/*_spec.rb **/*_test.rb **/*.spec.js **/*.test.js
                          **/*.spec.ts **/*.test.ts **/*_test.py **/test_*.py **/*_test.go].freeze

    def self.scan(path)
      cmd = build_command(path)
      stdout, stderr, status = Open3.capture3(*cmd)

      if status.success?
        JSON.parse(stdout)
      else
        warn "Semgrep SAST scan failed! Exit Code: #{status.exitstatus}\nError: #{stderr}"
        { "results" => [] }
      end
    rescue JSON::ParserError => e
      warn "Failed to parse Semgrep SAST output: #{e.message}"
      { "results" => [] }
    end

    def self.build_command(path)
      base_cmd = %w[semgrep scan --config p/r2c-ci --config p/secrets --json --disable-version-check]

      EXCLUDE_PATTERNS.each do |pattern|
        base_cmd.push("--exclude", pattern)
      end

      base_cmd.push(path)

      base_cmd
    end
  end
end
