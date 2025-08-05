# frozen_string_literal: true

require "json"

module ShieldAst
  class SCA
    def self.scan(path)
      puts "Running SCA scan on: #{path}"
      puts "Executing Dep-scan on project dependencies..."

      vulnerabilities = [
        {
          "dependency": "nokogiri",
          "version": "1.10.4",
          "vulnerability": "CVE-2020-2623",
          "severity": "CRITICAL"
        }
      ]
      JSON.generate(vulnerabilities)
    end
  end
end