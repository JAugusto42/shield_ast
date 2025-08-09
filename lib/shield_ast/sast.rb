# frozen_string_literal: true

# lib/shield_ast/sast.rb
require "json"
require "open3"

module ShieldAst
  # Runs SAST analysis using Semgrep.
  class SAST
    def self.scan(path)
      puts "Running SAST scan ..."
      cmd = ["semgrep", "scan", path, "--json", "--disable-version-check"]
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
