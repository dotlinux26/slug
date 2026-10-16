#include "src/ai/scanner.hpp"
#include "src/core/utils.hpp"
#include "src/platform/fs.hpp"
#include "third_party/json/json.hpp"
#include <regex>
#include <sstream>
#include <cmath>
#include <map>
#include <cstdio>
#include <cstdlib>

namespace slug::ai {

using json = nlohmann::json;

AiScanner::AiScanner(ProviderType provider, std::string endpoint, std::string model)
    : provider_(provider), endpoint_(std::move(endpoint)), model_(std::move(model)) {}

bool AiScanner::is_scannable_file(const std::filesystem::path& path) {
    std::string fname = path.filename().string();
    std::string ext = path.extension().string();
    for (auto& c : fname) c = static_cast<char>(std::tolower(c));
    for (auto& c : ext) c = static_cast<char>(std::tolower(c));

    // Support .env and variants (.env.local, .env.production, etc.)
    if (fname == ".env" || fname.rfind(".env.", 0) == 0 || ext == ".env") {
        return true;
    }

    static const std::vector<std::string> scannable_exts = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".cpp", ".hpp", ".c", ".h",
        ".go", ".rs", ".java", ".json", ".yaml", ".yml", ".toml",
        ".xml", ".ini", ".conf", ".sh", ".bash", ".zsh", ".rb", ".php"
    };

    for (const auto& e : scannable_exts) {
        if (ext == e) return true;
    }
    return false;
}

// Shannon entropy calculation
static double calculate_entropy(std::string_view s) {
    if (s.empty()) return 0.0;
    std::map<char, int> freq;
    for (char c : s) freq[c]++;

    double entropy = 0.0;
    double len = static_cast<double>(s.size());
    for (const auto& [_, count] : freq) {
        double p = count / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

ScanFinding AiScanner::scan_heuristic(const std::string& file_path, std::string_view content, bool deep) const {
    ScanFinding finding;

    std::string fname = std::filesystem::path(file_path).filename().string();
    for (auto& c : fname) c = static_cast<char>(std::tolower(c));

    // Direct check for environment secret files (.env, .env.local, .env.production, etc.)
    // Exclude documentation or template examples: .env.example, .env.sample, .env.template
    if ((fname == ".env" || fname.rfind(".env.", 0) == 0 || std::filesystem::path(file_path).extension().string() == ".env") &&
        fname != ".env.example" && fname != ".env.sample" && fname != ".env.template") {
        finding.has_secret = true;
        finding.line_number = 1;
        finding.reason = "Environment Secret File (" + fname + ")";
        finding.matched_snippet = content.empty() ? fname : std::string(content.substr(0, std::min(content.size(), (size_t)80)));
        return finding;
    }

    // Pattern definitions
    static const std::vector<std::pair<std::regex, std::string>> rules = {
        {std::regex("-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----"), "Private Key Header"},
        {std::regex("(?:postgres|mysql|mongodb(?:\\+srv)?):\\/\\/[^:]+:([^@]+)@"), "Hardcoded Database Password"},
        {std::regex("(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"), "AWS Access Key ID"},
        {std::regex("gh[pousr]_[0-9a-zA-Z]{36}"), "GitHub Personal Access Token"},
        {std::regex("eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"), "JWT Secret Token"},
        {std::regex("sk_live_[0-9a-zA-Z]{20,}"), "Stripe Live Secret Key"},
        {std::regex("sk_test_[0-9a-zA-Z]{20,}"), "Stripe Test Secret Key"},
        {std::regex("sk-[0-9a-zA-Z]{24,}"), "OpenAI / Cloud Secret Key"},
        {std::regex(R"((?:secret|api_key|apikey|access_token|token|password|passwd|auth|key)\s*[:=]\s*['"]?([A-Za-z0-9_\-+=/]{12,})['"]?)", std::regex::icase), "Hardcoded API Key / Secret String"}
    };

    auto lines = core::Utils::split(content, '\n');
    size_t max_lines = deep ? lines.size() : std::min(lines.size(), (size_t)35);

    for (size_t i = 0; i < max_lines; ++i) {
        const auto& line = lines[i];
        if (line.empty()) continue;

        for (const auto& [rx, desc] : rules) {
            std::smatch match;
            if (std::regex_search(line, match, rx)) {
                finding.has_secret = true;
                finding.line_number = static_cast<int>(i + 1);
                finding.reason = desc;
                finding.matched_snippet = core::Utils::trim(line);
                return finding;
            }
        }

        // Check value in KEY=VALUE or KEY: VALUE for unquoted high-entropy secrets
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) eq_pos = line.find(':');
        if (eq_pos != std::string::npos && eq_pos + 1 < line.size()) {
            std::string val = core::Utils::trim(line.substr(eq_pos + 1));
            while (!val.empty() && (val.front() == '"' || val.front() == '\'')) val = val.substr(1);
            while (!val.empty() && (val.back() == '"' || val.back() == '\'' || val.back() == ';')) val.pop_back();
            if (val.size() >= 20 && calculate_entropy(val) >= 4.0) {
                finding.has_secret = true;
                finding.line_number = static_cast<int>(i + 1);
                finding.reason = "High-entropy Secret Token";
                finding.matched_snippet = val.substr(0, std::min(val.size(), (size_t)8)) + "..." + (val.size() > 4 ? val.substr(val.size() - 4) : "");
                return finding;
            }
        }

        // High entropy token check on individual words
        auto words = core::Utils::split(line, ' ');
        for (const auto& word : words) {
            std::string clean = core::Utils::trim(word);
            while (!clean.empty() && (clean.front() == '"' || clean.front() == '\'' || clean.front() == '=' || clean.front() == ':')) {
                clean = clean.substr(1);
            }
            while (!clean.empty() && (clean.back() == '"' || clean.back() == '\'' || clean.back() == ';' || clean.back() == ',')) {
                clean.pop_back();
            }

            if (clean.size() >= 32 && calculate_entropy(clean) >= 4.5) {
                // High entropy secret detected!
                finding.has_secret = true;
                finding.line_number = static_cast<int>(i + 1);
                finding.reason = "High-entropy Secret Token";
                finding.matched_snippet = clean.substr(0, 8) + "..." + clean.substr(clean.size() - 4);
                return finding;
            }
        }
    }

    return finding;
}


ScanFinding AiScanner::scan_ollama(const std::string& file_path, std::string_view content) const {
    auto h_finding = scan_heuristic(file_path, content, false);
    if (h_finding.has_secret) return h_finding;

    auto lines = core::Utils::split(content, '\n');
    std::string snippet;
    size_t scan_limit = std::min(lines.size(), (size_t)80);
    for (size_t i = 0; i < scan_limit; ++i) {
        snippet += lines[i] + "\n";
    }

    json req_body;
    req_body["model"] = model_.empty() ? "qwen2.5-coder:7b" : model_;
    req_body["prompt"] = "Inspect this code from '" + file_path + "'. Does it contain leaked secrets or credentials? Respond ONLY with JSON: {\"has_secret\": true/false, \"reason\": \"...\", \"line\": 0}.\n\n" + snippet;
    req_body["stream"] = false;

    std::string url = endpoint_ + "/api/generate";
    auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ollama_" + std::to_string(core::Utils::current_timestamp()) + ".json");
    platform::PathUtils::write_text_file_atomic(tmp_payload, req_body.dump());

    std::string curl_cmd = "curl -s -m 5 -X POST \"" + url + "\" -H \"Content-Type: application/json\" -d @" + tmp_payload.string();
    FILE* fp = popen(curl_cmd.c_str(), "r");
    std::string response;
    if (fp) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), fp)) response += buf;
        pclose(fp);
    }
    std::error_code ec;
    std::filesystem::remove(tmp_payload, ec);

    if (!response.empty()) {
        try {
            auto j = json::parse(response);
            std::string text = j.value("response", "");
            size_t b1 = text.find('{');
            size_t b2 = text.rfind('}');
            if (b1 != std::string::npos && b2 != std::string::npos && b2 > b1) {
                auto res_obj = json::parse(text.substr(b1, b2 - b1 + 1));
                if (res_obj.value("has_secret", false)) {
                    ScanFinding finding;
                    finding.has_secret = true;
                    finding.line_number = res_obj.value("line", 1);
                    finding.reason = "Ollama Local Audit: " + res_obj.value("reason", "Secret detected by local model");
                    return finding;
                }
            }
        } catch (...) {}
    }

    return h_finding;
}

ScanFinding AiScanner::scan_cloud(const std::string& file_path, std::string_view content) const {
    const char* api_key_env = std::getenv("SLUG_AI_API_KEY");
    if (!api_key_env) api_key_env = std::getenv("GROQ_API_KEY");
    if (!api_key_env) api_key_env = std::getenv("GEMINI_API_KEY");
    if (!api_key_env) api_key_env = std::getenv("OPENROUTER_API_KEY");
    if (!api_key_env) api_key_env = std::getenv("OPENAI_API_KEY");

    if (!api_key_env || std::string(api_key_env).empty()) {
        return scan_heuristic(file_path, content, false);
    }

    std::string api_key = api_key_env;
    std::string endpoint = endpoint_;
    std::string model = model_;

    if (endpoint == "http://127.0.0.1:11434" || endpoint.empty()) {
        if (api_key.rfind("gsk_", 0) == 0 || std::getenv("GROQ_API_KEY")) {
            endpoint = "https://api.groq.com/openai/v1/chat/completions";
            model = "llama-3.3-70b-versatile";
        } else if (api_key.rfind("sk-or-", 0) == 0 || std::getenv("OPENROUTER_API_KEY")) {
            endpoint = "https://openrouter.ai/api/v1/chat/completions";
            model = "meta-llama/llama-3.2-3b-instruct:free";
        } else if (std::getenv("GEMINI_API_KEY") || api_key.rfind("AIzaSy", 0) == 0) {
            endpoint = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";
            model = "gemini-2.0-flash";
        } else {
            endpoint = "https://api.openai.com/v1/chat/completions";
            model = "gpt-4o-mini";
        }
    }

    const char* custom_endpoint = std::getenv("SLUG_AI_ENDPOINT");
    if (custom_endpoint && *custom_endpoint) endpoint = custom_endpoint;
    const char* custom_model = std::getenv("SLUG_AI_MODEL");
    if (custom_model && *custom_model) model = custom_model;

    // Fast heuristic first
    auto h_finding = scan_heuristic(file_path, content, false);
    if (h_finding.has_secret) return h_finding;

    auto lines = core::Utils::split(content, '\n');
    std::string snippet;
    size_t scan_limit = std::min(lines.size(), (size_t)100);
    for (size_t i = 0; i < scan_limit; ++i) {
        snippet += lines[i] + "\n";
    }

    json req_body;
    req_body["model"] = model;
    req_body["messages"] = json::array({
        {
            {"role", "system"},
            {"content", "You are an automated code security auditor. Detect hardcoded credentials, API keys, passwords, or secrets. Respond ONLY with a valid JSON object in this format: {\"has_secret\": true/false, \"reason\": \"<short description>\", \"line\": <line_number>}."}
        },
        {
            {"role", "user"},
            {"content", "Analyze file: " + file_path + "\n\n" + snippet}
        }
    });
    req_body["temperature"] = 0.0;

    auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ai_req_" + std::to_string(core::Utils::current_timestamp()) + ".json");
    platform::PathUtils::write_text_file_atomic(tmp_payload, req_body.dump());

    std::string curl_cmd = "curl -s -m 8 -X POST \"" + endpoint + "\" "
                           "-H \"Content-Type: application/json\" "
                           "-H \"Authorization: Bearer " + api_key + "\" "
                           "-d @" + tmp_payload.string();

    FILE* fp = popen(curl_cmd.c_str(), "r");
    std::string response;
    if (fp) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), fp)) response += buf;
        pclose(fp);
    }
    std::error_code ec;
    std::filesystem::remove(tmp_payload, ec);

    if (!response.empty()) {
        try {
            auto resp_j = json::parse(response);
            if (resp_j.contains("choices") && resp_j["choices"].is_array() && !resp_j["choices"].empty()) {
                std::string text = resp_j["choices"][0]["message"].value("content", "");
                size_t b1 = text.find('{');
                size_t b2 = text.rfind('}');
                if (b1 != std::string::npos && b2 != std::string::npos && b2 > b1) {
                    auto res_obj = json::parse(text.substr(b1, b2 - b1 + 1));
                    if (res_obj.value("has_secret", false)) {
                        ScanFinding finding;
                        finding.has_secret = true;
                        finding.line_number = res_obj.value("line", 1);
                        finding.reason = "AI Cloud Audit: " + res_obj.value("reason", "Credential detected by LLM");
                        return finding;
                    }
                }
            }
        } catch (...) {}
    }

    return h_finding;
}

ScanFinding AiScanner::scan_content(const std::string& file_path, std::string_view content, bool deep) const {
    if (provider_ == ProviderType::LOCAL_OLLAMA) {
        return scan_ollama(file_path, content);
    }
    if (provider_ == ProviderType::CLOUD_API) {
        return scan_cloud(file_path, content);
    }
    return scan_heuristic(file_path, content, deep);
}

} // namespace slug::ai

