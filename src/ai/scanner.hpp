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
                       std::string model = "qwen2.5-coder:7b");

    // Scans file content for sensitive data / leaked secrets
    ScanFinding scan_content(const std::string& file_path, std::string_view content, bool deep = false) const;

    // Checks if a file path is a code/config file worth scanning
    static bool is_scannable_file(const std::filesystem::path& path);

    ProviderType provider() const { return provider_; }
    const std::string& endpoint() const { return endpoint_; }
    const std::string& model() const { return model_; }

private:
    ProviderType provider_;
    std::string endpoint_;
    std::string model_;

    ScanFinding scan_heuristic(const std::string& file_path, std::string_view content, bool deep) const;
    ScanFinding scan_ollama(const std::string& file_path, std::string_view content) const;
    ScanFinding scan_cloud(const std::string& file_path, std::string_view content) const;
};

} // namespace slug::ai
