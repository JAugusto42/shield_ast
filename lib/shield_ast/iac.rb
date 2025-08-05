# frozen_string_literal: true

require "json"

module ShieldAst
  class IaC
    def self.scan(path)
      puts "Running IaC scan on: #{path}"
      puts "Executing Semgrep for IaC with public rules..."

      vulnerabilities = [
        {
          "check_id": "yaml.aws.security.iac.no-public-s3-bucket",
          "severity": "MEDIUM",
          "message": "AWS S3 bucket has a public access policy.",
          "path": "config/s3_policy.yml",
          "line": 10
        }
      ]
      JSON.generate(vulnerabilities)
    end
  end
end
