# frozen_string_literal: true

RSpec.describe ShieldAst::Runner do
  let(:path) { "/test/path" }

  let(:sast_spy) { class_spy(ShieldAst::SAST) }
  let(:sca_spy) { class_spy(ShieldAst::SCA) }
  let(:iac_spy) { class_spy(ShieldAst::IaC) }

  before do
    allow(sast_spy).to receive(:scan).with(path).and_return("[]")
    allow(sca_spy).to receive(:scan).with(path).and_return("[]")
    allow(iac_spy).to receive(:scan).with(path).and_return("[]")

    stub_const("ShieldAst::SAST", sast_spy)
    stub_const("ShieldAst::SCA", sca_spy)
    stub_const("ShieldAst::IaC", iac_spy)
  end

  context "when all scanners are enabled" do
    let(:options) { { sast: true, sca: true, iac: true } }

    it "calls all scan methods" do
      ShieldAst::Runner.run(options, path)

      expect(sast_spy).to have_received(:scan).with(path).once
      expect(sca_spy).to have_received(:scan).with(path).once
      expect(iac_spy).to have_received(:scan).with(path).once
    end
  end

  context "when only SAST is enabled" do
    let(:options) { { sast: true, sca: false, iac: false } }

    it "only calls the SAST scan method" do
      ShieldAst::Runner.run(options, path)

      expect(sast_spy).to have_received(:scan).with(path).once
      expect(sca_spy).not_to have_received(:scan)
      expect(iac_spy).not_to have_received(:scan)
    end
  end

  context "when only SCA and IaC are enabled" do
    let(:options) { { sast: false, sca: true, iac: true } }

    it "calls only SCA and IaC scan methods" do
      ShieldAst::Runner.run(options, path)

      expect(sast_spy).not_to have_received(:scan)
      expect(sca_spy).to have_received(:scan).with(path).once
      expect(iac_spy).to have_received(:scan).with(path).once
    end
  end
end
