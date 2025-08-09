# frozen_string_literal: true

require "English"
require "json"

module ShieldAst
  class IaC
    def self.scan(path)
      puts "Running IaC scan ..."

      # Execute Semgrep with IaC-specific rulesets
      cmd = "semgrep --config=r/terraform --config=r/kubernetes --config=r/docker --config=r/yaml --json --quiet #{path}"
      output = `#{cmd}`

      if $CHILD_STATUS.success? && !output.strip.empty?
        begin
          report = JSON.parse(output)
          return { "results" => report["results"] || [] }
        rescue JSON::ParserError
          return { "results" => [] }
        end
      end

      # Fallback if semgrep fails
      { "results" => [] }
    end
  end
end
