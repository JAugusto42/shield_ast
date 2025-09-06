# frozen_string_literal: true

require "gemini-ai"

module ShieldAst
  class AiAnalyzer
    attr_reader :model_name, :finding

    def initialize(finding)
      @model_name = ENV.fetch("GEMINI_MODEL", "gemini-2.5-flash")
      @finding = finding
    end

    def call
      check_for_false_positive
    end

    private

    def check_for_false_positive
      file_path = finding["path"]
      line = finding.dig("start", "line")
      message = finding.dig("extra", "message") || finding["check_id"] || "N/A"
      code_snippet = extract_code_snippet(file_path, line)
      prompt = prompt(message, code_snippet, file_path, line)

      begin
        request_body = { contents: { role: "user", parts: { text: prompt } } }
        response = client.generate_content(request_body)
        result_text = response.dig("candidates", 0, "content", "parts", 0, "text")&.strip

        return "\e[33m ⚠️ (Possible False Positive)\e[0m" if result_text == "FALSE_POSITIVE"
        return "\e[36m 🛡️ (Verified by AI)\e[0m" if result_text == "TRUE_POSITIVE"
      rescue StandardError
        puts "\e[31m[!] AI analysis failed.\e[0m"
      end

      ""
    end

    def client
      @client ||= Gemini.new(
        credentials: {
          service: "generative-language-api",
          api_key: ENV["GEMINI_API_KEY"]
        },
        options: { model: model_name }
      )
    end

    def prompt(message, code_snippet, file_path, line)
      <<~PROMPT
        Analyze the following security finding. Based on the code and the description, is it more likely to be a true positive or a false positive?

        **Finding:** #{message}
        **File:** #{file_path || "N/A"}:#{line || "N/A"}

        **Code:**
        ```
        #{code_snippet}
        ```

        Respond with ONLY ONE of the following words: `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `UNCERTAIN`.
      PROMPT
    end

    def extract_code_snippet(file_path, line_number, context_lines = 10)
      return "Code snippet not available (file not found)." unless file_path && File.exist?(file_path)
      return "Code snippet not available (line number not specified)." unless line_number

      lines = File.readlines(file_path)
      start_line = [0, line_number - 1 - context_lines].max
      end_line = [lines.length - 1, line_number - 1 + context_lines].min

      snippet = []
      (start_line..end_line).each do |i|
        line_prefix = i + 1 == line_number ? ">> #{i + 1}: " : "   #{i + 1}: "
        snippet << "#{line_prefix}#{lines[i].chomp}"
      end
      snippet.join("\n")
    rescue StandardError => e
      "Could not read code snippet: #{e.message}"
    end
  end
end
