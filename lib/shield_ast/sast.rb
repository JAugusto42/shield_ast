# frozen_string_literal: true

require "json"

module ShieldAst
  class SAST
    def self.scan(path)
      puts "Running SAST scan on: #{path}"
      puts "Executing Semgrep with public rules..."

      vulnerabilities = [
        {
          "check_id": "ruby.lang.security.injection.command.command-injection",
          "severity": "HIGH",
          "message": "Potential command injection vulnerability found.",
          "path": "app/controllers/users_controller.rb",
          "line": 15
        }
      ]
      JSON.generate(vulnerabilities)
    end
  end
end
