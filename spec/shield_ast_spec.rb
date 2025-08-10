# frozen_string_literal: true

RSpec.describe ShieldAst do
  let(:output) { StringIO.new }

  context "when the --help flag is used" do
    it "displays the help message and exits" do
      allow($stdout).to receive(:puts) { |arg| output.puts arg }
      ShieldAst::Main.call(["--help"])
      expect(output.string).to include("ast - A powerful command-line tool for Application Security Testing")
      expect(output.string).to include("Usage:")
    end
  end

  context "when the --version flag is used" do
    it "displays the version number" do
      allow($stdout).to receive(:puts) { |arg| output.puts arg }
      ShieldAst::Main.call(["--version"])
      expect(output.string).to include("Shield AST version #{ShieldAst::VERSION}")
    end
  end

  context "when the scan command is used" do
    let(:runner_spy) { class_spy(ShieldAst::Runner) }

    it "calls the Runner with the correct options" do
      allow(ShieldAst::Runner).to receive(:run)
      ShieldAst::Main.call(%w[scan --sast --sca])
      expect(ShieldAst::Runner).to have_received(:run)
        .with(hash_including(command: "scan", sast: true, sca: true), Dir.pwd)
    end

    it "calls the Runner with a specified path" do
      allow(ShieldAst::Runner).to receive(:run)
      ShieldAst::Main.call(%w[scan /my/project/path])
      expect(ShieldAst::Runner).to have_received(:run)
        .with(hash_including(command: "scan"), "/my/project/path")
    end

    context "when displaying scan results" do
      let(:mock_reports) do
        {
          sast: {
            "results" => [
              {
                "path" => "app/models/user.rb",
                "start" => { "line" => 10 },
                "extra" => {
                  "severity" => "ERROR",
                  "message" => "SQL injection vulnerability detected. User input not sanitized."
                }
              },
              {
                "path" => "app/controllers/admin.rb",
                "start" => { "line" => 25 },
                "extra" => {
                  "severity" => "WARNING",
                  "message" => "Potential XSS vulnerability found."
                }
              },
              {
                "path" => "app/helpers/view.rb",
                "start" => { "line" => 5 },
                "extra" => {
                  "severity" => "ERROR",
                  "message" => "Critical security flaw in authentication."
                }
              },
              {
                "path" => "config/routes.rb",
                "start" => { "line" => 15 },
                "extra" => {
                  "severity" => "INFO",
                  "message" => "Information disclosure possible."
                }
              }
            ]
          }
        }
      end

      before do
        allow(ShieldAst::Runner).to receive(:run).and_return(mock_reports)
        allow($stdout).to receive(:puts) { |arg| output.puts arg }
      end

      it "displays scan results with severity icons" do
        ShieldAst::Main.call(%w[scan])

        expect(output.string).to include("🔍 SAST (4 issues)")
        expect(output.string).to include("🔴") # ERROR severity icon
        expect(output.string).to include("🟡") # WARNING severity icon
        expect(output.string).to include("🔵") # INFO severity icon
      end

      it "sorts results by severity (ERROR first, then WARNING, then INFO)" do
        ShieldAst::Main.call(%w[scan])

        # ERROR results should appear before WARNING and INFO
        error_position = output.string.index("SQL injection vulnerability detected")
        error_position2 = output.string.index("Critical security flaw in authentication")
        warning_position = output.string.index("Potential XSS vulnerability found")
        info_position = output.string.index("Information disclosure possible")

        expect(error_position).to be < warning_position
        expect(error_position2).to be < warning_position
        expect(warning_position).to be < info_position
      end

      context "when there are more than 5 results" do
        let(:many_results) do
          {
            sast: {
              "results" => Array.new(8) do |i|
                {
                  "path" => "file#{i}.rb",
                  "start" => { "line" => i + 1 },
                  "extra" => {
                    "severity" => i < 3 ? "ERROR" : "WARNING",
                    "message" => "Security issue #{i + 1}"
                  }
                }
              end
            }
          }
        end

        before do
          allow(ShieldAst::Runner).to receive(:run).and_return(many_results)
        end

        it "shows only the top 5 most critical results" do
          ShieldAst::Main.call(%w[scan])

          expect(output.string).to include("🔍 SAST (8 issues, showing top 5)")
          expect(output.string).to include("... and 3 more issues")

          # Should show first 5 security issues
          (1..5).each do |i|
            expect(output.string).to include("Security issue #{i}")
          end

          # Should not show the remaining issues
          (6..8).each do |i|
            expect(output.string).not_to include("Security issue #{i}")
          end
        end

        it "suggests using --verbose to see all results" do
          ShieldAst::Main.call(%w[scan])
          expect(output.string).to include("(run with --verbose to see all)")
        end
      end

      context "when there are 5 or fewer results" do
        it "shows all results without 'showing top 5' message" do
          ShieldAst::Main.call(%w[scan])

          expect(output.string).to include("🔍 SAST (4 issues)")
          expect(output.string).not_to include("showing top 5")
          expect(output.string).not_to include("... and")
        end
      end
    end

    context "with SCA results" do
      let(:sca_reports) do
        {
          sca: {
            "results" => [
              {
                "title" => "Critical vulnerability in lodash",
                "severity" => "ERROR",
                "vulnerable_version" => "4.17.15",
                "fixed_version" => "4.17.21",
                "file" => "package.json",
                "description" => "Prototype pollution vulnerability"
              },
              {
                "title" => "Medium severity in express",
                "severity" => "WARNING",
                "vulnerable_version" => "4.16.0",
                "fixed_version" => "4.18.0",
                "file" => "package.json",
                "description" => "DoS vulnerability in query parser"
              }
            ]
          }
        }
      end

      before do
        allow(ShieldAst::Runner).to receive(:run).and_return(sca_reports)
        allow($stdout).to receive(:puts) { |arg| output.puts arg }
      end

      it "displays SCA results with proper formatting" do
        ShieldAst::Main.call(%w[scan])

        expect(output.string).to include("📦 SCA (2 issues)")
        expect(output.string).to include("Critical vulnerability in lodash (4.17.15 → 4.17.21)")
        expect(output.string).to include("Medium severity in express (4.16.0 → 4.18.0)")
      end

      it "sorts SCA results by severity" do
        ShieldAst::Main.call(%w[scan])

        error_position = output.string.index("Critical vulnerability in lodash")
        warning_position = output.string.index("Medium severity in express")

        expect(error_position).to be < warning_position
      end
    end

    context "when no vulnerabilities are found" do
      let(:empty_reports) do
        {
          sast: { "results" => [] },
          sca: { "results" => [] },
          iac: { "results" => [] }
        }
      end

      before do
        allow(ShieldAst::Runner).to receive(:run).and_return(empty_reports)
        allow($stdout).to receive(:puts) { |arg| output.puts arg }
      end

      it "displays a success message" do
        ShieldAst::Main.call(%w[scan])
        expect(output.string).to include("✅ No security issues found! Your code looks clean.")
      end
    end

    context "severity summary" do
      let(:mixed_severity_reports) do
        {
          sast: {
            "results" => [
              {
                "path" => "app/models/user.rb",
                "start" => { "line" => 10 },
                "extra" => {
                  "severity" => "ERROR",
                  "message" => "Critical SQL injection vulnerability"
                }
              },
              {
                "path" => "app/controllers/admin.rb",
                "start" => { "line" => 15 },
                "extra" => {
                  "severity" => "ERROR",
                  "message" => "Authentication bypass detected"
                }
              },
              {
                "path" => "app/helpers/view.rb",
                "start" => { "line" => 8 },
                "extra" => {
                  "severity" => "WARNING",
                  "message" => "Potential XSS vulnerability"
                }
              }
            ]
          },
          sca: {
            "results" => [
              {
                "title" => "Medium vulnerability in express",
                "severity" => "WARNING",
                "vulnerable_version" => "4.16.0",
                "fixed_version" => "4.18.0",
                "file" => "package.json",
                "description" => "DoS vulnerability in query parser"
              },
              {
                "title" => "Low priority issue in lodash",
                "severity" => "INFO",
                "vulnerable_version" => "4.17.15",
                "fixed_version" => "4.17.21",
                "file" => "package.json",
                "description" => "Minor performance issue"
              }
            ]
          }
        }
      end

      before do
        allow(ShieldAst::Runner).to receive(:run).and_return(mixed_severity_reports)
        allow($stdout).to receive(:puts) { |arg| output.puts arg }
      end

      it "displays correct severity counts" do
        ShieldAst::Main.call(%w[scan])
        expect(output.string).to include("📊 Total: 5 findings (2 🔴, 2 🟡, 1 🔵)")
      end
    end
  end

  context "when invalid command is used" do
    before do
      allow($stdout).to receive(:puts) { |arg| output.puts arg }
    end

    it "shows error message and help" do
      ShieldAst::Main.call(%w[invalid_command])
      expect(output.string).to include("Invalid command. Use 'ast help' for more information.")
      expect(output.string).to include("Usage:")
    end
  end
end
