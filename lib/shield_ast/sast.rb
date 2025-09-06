# frozen_string_literal: true

# lib/shield_ast/sast.rb
require "json"
require "open3"

module ShieldAst
  # Wraps the logic for running SAST scan using Semgrep.
  class SAST
    def self.scan(path)
      cmd = [
        "semgrep", "scan", "--config", "p/r2c-ci", "--config", "p/secrets", "--json", "--disable-version-check", path
      ]
      stdout, stderr, status = Open3.capture3(*cmd)

      if status.success?
        JSON.parse(stdout)
      else
        warn "Semgrep SAST scan failed! Error: #{stderr}"
        []
      end
    rescue JSON::ParserError => e
      warn "Failed to parse Semgrep output: #{e.message}"
      []
    end
  end
end
