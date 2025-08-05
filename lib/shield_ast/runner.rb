# frozen_string_literal: true

require_relative "sast"
require_relative "sca"
require_relative "iac"

module ShieldAst
  class Runner
    def self.run(options, path)
      reports = {}

      if options[:sast]
        puts "\n-> Starting SAST analysis..."
        reports[:sast] = SAST.scan(path)
        puts "SAST analysis finished."
      end

      if options[:sca]
        puts "\n-> Starting SCA analysis..."
        reports[:sca] = SCA.scan(path)
        puts "SCA analysis finished."
      end

      if options[:iac]
        puts "\n-> Starting IaC analysis..."
        reports[:iac] = IaC.scan(path)
        puts "IaC analysis finished."
      end

      reports
    end
  end
end
