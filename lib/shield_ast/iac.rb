# frozen_string_literal: true

require "json"
require "open3"

module ShieldAst
  # Wraps the logic for running Infrastructure as Code (IaC) scans using Opengrep.
  class IaC
    def self.scan(path)
      cmd = [
        "opengrep", "scan",
        "--config", "r/terraform",
        "--config", "r/kubernetes",
        "--config", "r/docker",
        "--config", "r/yaml",
        "--json", "--quiet",
        path
      ]

      stdout, _stderr, status = Open3.capture3(*cmd)

      if status.success? && !stdout.strip.empty?
        begin
          report = JSON.parse(stdout)
          return { "results" => report["results"] || [] }
        rescue JSON::ParserError
          return { "results" => [] }
        end
      end

      { "results" => [] }
    end
  end
end
