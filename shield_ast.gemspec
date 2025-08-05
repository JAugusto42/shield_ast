# frozen_string_literal: true

require_relative "lib/shield_ast/version"

Gem::Specification.new do |spec|
  spec.name = "shield_ast"
  spec.version = ShieldAst::VERSION
  spec.authors = ["Jose Augusto"]
  spec.email = ["joseaugusto.881@outlook.com"]

  spec.summary = "A command-line tool for multi-scanner Application Security Testing."
  spec.description = "Shield AST is an all-in-one command-line tool that automates security testing by integrating
                      popular open-source scanners for SAST, SCA, and IaC, helping you find and fix vulnerabilities
                      early in the development lifecycle."
  spec.homepage = "https://github.com/JAugusto42/shield_ast"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore .rspec spec/ .github/ .rubocop.yml])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
end
