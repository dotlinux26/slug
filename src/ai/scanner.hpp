#pragma once

#include "src/core/types.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <filesystem>

namespace slug::ai {

struct ScanFinding {
    bool has_secret{false};
    int line_number{0};
    std::string reason;
    std::string matched_snippet;
    std::string detector{"Smart Regex Guard"};
};

class AiScanner {
public:
    enum class ProviderType {
        LOCAL_HEURISTIC,
        LOCAL_OLLAMA,
        CLOUD_API
    };

    explicit AiScanner(ProviderType provider = ProviderType::LOCAL_HEURISTIC,
                       std::string endpoint = "http://127.0.0.1:11434",
                       std::string model = "qwen2.5-coder:7b",
                       std::string api_key = "",
                       std::string body_template = "",
                       std::vector<std::pair<std::string, std::string>> headers = {});

    static AiScanner create_for_level(core::FilterLevel level,
                                     core::AiModelProvider ai_provider = core::AiModelProvider::OLLAMA,
                                     const std::filesystem::path& workspace_root = {});

    // Scans file content for sensitive data / leaked secrets according to FilterLevel
    ScanFinding scan_content(const std::string& file_path, std::string_view content, bool deep = false,
                             core::FilterLevel level = core::FilterLevel::LEVEL_3_ENTROPY) const;

    // Actively tests connection and API key validity against the configured AI service
    std::pair<bool, std::string> test_connection() const;

    // Checks if a file path is a code/config file worth scanning
    static bool is_scannable_file(const std::filesystem::path& path);

    ProviderType provider() const { return provider_; }
    const std::string& endpoint() const { return endpoint_; }
    const std::string& model() const { return model_; }
    const std::string& api_key() const { return api_key_; }
    const std::string& body_template() const { return body_template_; }
    const std::vector<std::pair<std::string, std::string>>& headers() const { return headers_; }

private:
    ProviderType provider_;
    std::string endpoint_;
    std::string model_;
    std::string api_key_;
    std::string body_template_;
    std::vector<std::pair<std::string, std::string>> headers_;

    ScanFinding scan_heuristic(const std::string& file_path, std::string_view content, bool deep, bool enable_entropy = true) const;
    ScanFinding scan_ollama(const std::string& file_path, std::string_view content) const;
    ScanFinding scan_cloud(const std::string& file_path, std::string_view content) const;
    ScanFinding scan_gemini(const std::string& file_path, std::string_view content) const;
    ScanFinding scan_anthropic(const std::string& file_path, std::string_view content) const;
    ScanFinding scan_custom(const std::string& file_path, std::string_view content) const;

    mutable bool ollama_alive_{true};
};

} // namespace slug::ai
