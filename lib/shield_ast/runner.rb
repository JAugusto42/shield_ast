# frozen_string_literal: true

require_relative "sast"
require_relative "sca"
require_relative "iac"

require "json"

module ShieldAst
  class Runner
    def self.run(options, path)
      reports = {}

      if options[:sast]
        puts "-> Running SAST scan..."
        reports[:sast] = SAST.scan(path)
      end

      if options[:sca]
        puts "-> Running SCA scan..."
        reports[:sca] = SCA.scan(path)
      end

      if options[:iac]
        puts "-> Running IAC scan..."
        reports[:iac] = IaC.scan(path)
      end

      reports
    end
  end
end
