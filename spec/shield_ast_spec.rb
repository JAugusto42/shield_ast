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
  end
end
