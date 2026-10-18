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

#if defined(_WIN32)
#ifndef popen
#define popen _popen
#endif
#ifndef pclose
#define pclose _pclose
#endif
static const char* NULL_DEV = " 2>nul";
#else
static const char* NULL_DEV = " 2>/dev/null";
#endif

namespace slug::ai {

using json = nlohmann::json;

static bool is_safe_shell_param(const std::string& s) {
    for (char c : s) {
        if (c == '"' || c == '\'' || c == '`' || c == ';' || c == '&' || 
            c == '|' || c == '$' || c == '\n' || c == '\r' || c == '<' || c == '>') {
            return false;
        }
    }
    return true;
}

AiScanner::AiScanner(ProviderType provider, std::string endpoint, std::string model, std::string api_key,
                     std::string body_template, std::vector<std::pair<std::string, std::string>> headers)
    : provider_(provider), endpoint_(std::move(endpoint)), model_(std::move(model)), api_key_(std::move(api_key)),
      body_template_(std::move(body_template)), headers_(std::move(headers)) {}

AiScanner AiScanner::create_for_level(core::FilterLevel level, core::AiModelProvider ai_provider, const std::filesystem::path& workspace_root) {
    if (level == core::FilterLevel::LEVEL_4_AI) {
        std::string prov_str = core::ai_model_to_string(ai_provider);
        std::string endpoint = (ai_provider == core::AiModelProvider::OPENAI) ? "https://api.openai.com/v1/chat/completions" :
                               ((ai_provider == core::AiModelProvider::GEMINI) ? "https://generativelanguage.googleapis.com/v1beta" : "http://127.0.0.1:11434");
        std::string model = (ai_provider == core::AiModelProvider::OPENAI) ? "gpt-4o-mini" :
                            ((ai_provider == core::AiModelProvider::GEMINI) ? "gemini-flash-latest" : "deepseek-r1");
        std::string api_key = "";
        std::string body_template = "";
        std::vector<std::pair<std::string, std::string>> headers;

        if (!workspace_root.empty()) {
            std::filesystem::path ai_file = workspace_root / ".slug" / "ai.json";
            if (std::filesystem::exists(ai_file)) {
                auto content = platform::PathUtils::read_text_file(ai_file);
                if (content && !content->empty()) {
                    try {
                        auto j = json::parse(*content);
                        if (j.contains("ai_provider") && j["ai_provider"].is_string()) prov_str = j["ai_provider"].get<std::string>();
                        if (j.contains("ai_endpoint") && j["ai_endpoint"].is_string()) endpoint = j["ai_endpoint"].get<std::string>();
                        if (j.contains("ai_model") && j["ai_model"].is_string()) model = j["ai_model"].get<std::string>();
                        if (j.contains("ai_api_key") && j["ai_api_key"].is_string()) api_key = j["ai_api_key"].get<std::string>();
                        if (j.contains("body_template")) {
                            if (j["body_template"].is_string()) {
                                body_template = j["body_template"].get<std::string>();
                            } else {
                                body_template = j["body_template"].dump(2);
                            }
                        }
                        if (j.contains("headers") && j["headers"].is_object()) {
                            for (auto& [hk, hv] : j["headers"].items()) {
                                if (hv.is_string()) headers.push_back({hk, hv.get<std::string>()});
                            }
                        }
                    } catch (...) {}
                }
            }
        }

        if (prov_str == "openai" || prov_str == "gemini" || prov_str == "anthropic" || prov_str == "custom" || !body_template.empty()) {
            return AiScanner(ProviderType::CLOUD_API, endpoint, model, api_key, body_template, headers);
        } else {
            return AiScanner(ProviderType::LOCAL_OLLAMA, endpoint, model, api_key, body_template, headers);
        }
    }
    return AiScanner(ProviderType::LOCAL_HEURISTIC);
}

bool AiScanner::is_scannable_file(const std::filesystem::path& path) {
    std::string fname = path.filename().string();
    std::string ext = path.extension().string();
    for (auto& c : fname) c = static_cast<char>(std::tolower(c));
    for (auto& c : ext) c = static_cast<char>(std::tolower(c));

    // Absolute exclusion for binary, compiled, compressed, and media files
    static const std::vector<std::string> binary_exts = {
        ".pyd", ".dll", ".exe", ".bin", ".pak", ".so", ".dylib", ".obj", ".o",
        ".class", ".pyc", ".dat", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
        ".svg", ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz", ".7z", ".iso",
        ".ttf", ".woff", ".woff2", ".wasm", ".pdb", ".lib", ".a", ".node"
    };
    for (const auto& be : binary_exts) {
        if (ext == be) return false;
    }

    // Support .env and variants (.env.local, .env.production, etc.)
    if (fname == ".env" || fname.rfind(".env.", 0) == 0 || ext == ".env") {
        return true;
    }

    static const std::vector<std::string> scannable_exts = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".cpp", ".hpp", ".c", ".h",
        ".go", ".rs", ".java", ".json", ".yaml", ".yml", ".toml",
        ".xml", ".ini", ".conf", ".sh", ".bash", ".zsh", ".rb", ".php",
        ".txt", ".md", ".cfg", ".properties", ".csv", ".log", ".sql",
        ".pem", ".key", ".crt", ".auth", ".token", ".secret", ".cert", ".config", ".cnf"
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

ScanFinding AiScanner::scan_heuristic(const std::string& file_path, std::string_view content, bool deep, bool enable_entropy) const {
    ScanFinding finding;
    finding.detector = "Smart Regex Guard";

    if (!is_scannable_file(file_path)) {
        return finding;
    }

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

        // Check value in KEY=VALUE or KEY: VALUE for unquoted high-entropy secrets (Mức 3 & 4)
        if (enable_entropy) {
            size_t eq_pos = line.find('=');
            if (eq_pos == std::string::npos) {
                size_t c_pos = line.find(':');
                if (c_pos != std::string::npos && c_pos > 0) {
                    std::string key_part = core::Utils::trim(line.substr(0, c_pos));
                    bool is_valid_key = !key_part.empty() && 
                                        key_part.find(' ') == std::string::npos && 
                                        key_part.find('\t') == std::string::npos &&
                                        key_part != "http" && key_part != "https" &&
                                        key_part.front() != '#' && key_part.rfind("//", 0) == std::string::npos;
                    if (is_valid_key) {
                        eq_pos = c_pos;
                    }
                }
            }
            if (eq_pos != std::string::npos && eq_pos + 1 < line.size()) {
                std::string val = core::Utils::trim(line.substr(eq_pos + 1));
                while (!val.empty() && (val.front() == '"' || val.front() == '\'')) val = val.substr(1);
                while (!val.empty() && (val.back() == '"' || val.back() == '\'' || val.back() == ';')) val.pop_back();

                // Only evaluate ASCII token candidates (skip natural language / multi-byte UTF-8)
                bool is_token_candidate = true;
                for (char c : val) {
                    if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) {
                        is_token_candidate = false;
                        break;
                    }
                }
                if (is_token_candidate && val.size() >= 20 && calculate_entropy(val) >= 4.0) {
                    finding.has_secret = true;
                    finding.line_number = static_cast<int>(i + 1);
                    finding.detector = "Shannon Entropy";
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

                // Check that word is ASCII (skip non-ASCII words)
                bool is_ascii_word = true;
                for (char c : clean) {
                    if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) {
                        is_ascii_word = false;
                        break;
                    }
                }

                if (is_ascii_word && clean.size() >= 32 && calculate_entropy(clean) >= 4.5) {
                    // High entropy secret detected!
                    finding.has_secret = true;
                    finding.line_number = static_cast<int>(i + 1);
                    finding.detector = "Shannon Entropy";
                    finding.reason = "High-entropy Secret Token";
                    finding.matched_snippet = clean.substr(0, 8) + "..." + clean.substr(clean.size() - 4);
                    return finding;
                }
            }
        }
    }

    return finding;
}


static std::string execute_http_post(const std::string& url,
                                     const std::filesystem::path& payload_file,
                                     const std::vector<std::pair<std::string, std::string>>& headers,
                                     int timeout_sec) {
    std::string response;

    // 1. Primary Attempt: curl.exe (standard on Windows 10 build 1803+, Windows 11, Linux, macOS)
    std::string headers_cmd = "";
    bool has_content_type = false;
    for (const auto& [name, val] : headers) {
        if (!name.empty()) {
            headers_cmd += "-H \"" + name + ": " + val + "\" ";
            if (name == "Content-Type" || name == "content-type") has_content_type = true;
        }
    }
    if (!has_content_type) {
        headers_cmd = "-H \"Content-Type: application/json\" " + headers_cmd;
    }
    std::string curl_cmd = "curl -s -m " + std::to_string(timeout_sec) + " -X POST \"" + url + "\" "
                         + headers_cmd
                         + "-d @\"" + payload_file.generic_string() + "\"" + NULL_DEV;

    FILE* fp = popen(curl_cmd.c_str(), "r");
    if (fp) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), fp)) response += buf;
        pclose(fp);
    }

#if defined(_WIN32)
    // 2. Windows Fallback via PowerShell + HttpWebRequest
    if (response.empty()) {
        std::string win_path = payload_file.string();
        for (auto& c : win_path) { if (c == '/') c = '\\'; }

        int timeout_ms = timeout_sec * 1000;
        std::string ps_cmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command \""
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            "[System.Net.ServicePointManager]::SecurityProtocol = 3072 -bor 768 -bor 192; "
            "$req = [System.Net.HttpWebRequest]::Create('" + url + "'); "
            "$req.Method = 'POST'; "
            "$req.ContentType = 'application/json; charset=utf-8'; "
            "$req.Timeout = " + std::to_string(timeout_ms) + "; ";
        for (const auto& [name, val] : headers) {
            if (!name.empty() && name != "Content-Type" && name != "content-type") {
                ps_cmd += "$req.Headers.Add('" + name + "', '" + val + "'); ";
            }
        }
        ps_cmd += "$data = [System.IO.File]::ReadAllBytes('" + win_path + "'); "
                  "$req.ContentLength = $data.Length; "
                  "try { "
                  "$st = $req.GetRequestStream(); "
                  "$st.Write($data, 0, $data.Length); "
                  "$st.Close(); "
                  "$resp = $req.GetResponse(); "
                  "$sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8); "
                  "Write-Output $sr.ReadToEnd(); "
                  "$sr.Close(); $resp.Close(); "
                  "} catch [System.Net.WebException] { "
                  "if ($_.Exception.Response) { "
                  "$sr = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream(), [System.Text.Encoding]::UTF8); "
                  "Write-Output $sr.ReadToEnd(); "
                  "$sr.Close(); $_.Exception.Response.Close(); "
                  "} "
                  "} catch { }\"" + NULL_DEV;

        FILE* ps_fp = popen(ps_cmd.c_str(), "r");
        if (ps_fp) {
            char buf[1024];
            while (fgets(buf, sizeof(buf), ps_fp)) response += buf;
            pclose(ps_fp);
        }
    }
#endif

    return response;
}

static std::string execute_http_post(const std::string& url,
                                     const std::filesystem::path& payload_file,
                                     const std::string& header_name,
                                     const std::string& header_val,
                                     int timeout_sec) {
    std::vector<std::pair<std::string, std::string>> hdrs;
    if (!header_name.empty() && !header_val.empty()) {
        hdrs.push_back({header_name, header_val});
    }
    return execute_http_post(url, payload_file, hdrs, timeout_sec);
}

// Universal extractor: handles Gemini, OpenAI, Claude, DeepSeek, Ollama, and arbitrary custom payloads
static std::optional<ScanFinding> try_extract_finding(const json& j) {
    if (j.is_object()) {
        if (j.contains("has_secret") && (j["has_secret"].is_boolean() || j["has_secret"].is_number())) {
            ScanFinding f;
            f.has_secret = j["has_secret"].get<bool>();
            f.line_number = j.value("line", 1);
            f.reason = j.value("reason", "Secret detected by AI model");
            f.detector = "AI Guard";
            return f;
        }
        for (auto it = j.begin(); it != j.end(); ++it) {
            auto res = try_extract_finding(it.value());
            if (res.has_value()) return res;
        }
    } else if (j.is_array()) {
        for (const auto& elem : j) {
            auto res = try_extract_finding(elem);
            if (res.has_value()) return res;
        }
    } else if (j.is_string()) {
        std::string s = j.get<std::string>();
        size_t b1 = s.find('{');
        size_t b2 = s.rfind('}');
        if (b1 != std::string::npos && b2 != std::string::npos && b2 > b1) {
            try {
                auto sub_j = json::parse(s.substr(b1, b2 - b1 + 1));
                auto res = try_extract_finding(sub_j);
                if (res.has_value()) return res;
            } catch (...) {}
        }
    }
    return std::nullopt;
}

ScanFinding AiScanner::scan_ollama(const std::string& file_path, std::string_view content) const {
    auto h_finding = scan_heuristic(file_path, content, false, false);
    if (h_finding.has_secret) return h_finding;
    if (!ollama_alive_) return h_finding;

    auto lines = core::Utils::split(content, '\n');
    std::string snippet;
    size_t scan_limit = std::min(lines.size(), (size_t)80);
    for (size_t i = 0; i < scan_limit; ++i) {
        snippet += lines[i] + "\n";
    }

    std::string model = model_.empty() ? "qwen2.5-coder:7b" : model_;
    std::string prompt = "Inspect this code from '" + file_path + "'. Does it contain leaked secrets or credentials? Respond ONLY with JSON: {\"has_secret\": true/false, \"reason\": \"...\", \"line\": 0}.\n\n" + snippet;

    json req_body;
    req_body["model"] = model;
    req_body["prompt"] = prompt;
    req_body["stream"] = false;

    std::string url = endpoint_ + "/api/generate";
    if (!is_safe_shell_param(url)) return h_finding;

    auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ollama_" + std::to_string(core::Utils::current_timestamp()) + ".json");
    platform::PathUtils::write_text_file_atomic(tmp_payload, req_body.dump());

    std::string response = execute_http_post(url, tmp_payload, "", "", 3);

    std::error_code ec;
    std::filesystem::remove(tmp_payload, ec);

    if (response.empty()) {
        ollama_alive_ = false; // Fast-fail remaining files if Ollama server is not running
        h_finding.detector = "AI Guard (Ollama)";
        h_finding.model = model;
        h_finding.ai_input = prompt;
        h_finding.ai_output = "(Không kết nối được tới máy chủ Ollama)";
        return h_finding;
    }

    try {
        auto j = json::parse(response);
        auto f_opt = try_extract_finding(j);
        if (f_opt.has_value()) {
            f_opt->detector = "AI Guard (" + model + ")";
            f_opt->model = model;
            f_opt->ai_input = prompt;
            f_opt->ai_output = response;
            if (f_opt->has_secret) {
                f_opt->reason = "Ollama Local Audit: " + f_opt->reason;
            } else {
                f_opt->reason = "Clean (Ollama: Không phát hiện rò rỉ mã bí mật)";
            }
            return *f_opt;
        }
    } catch (...) {}

    h_finding.detector = "AI Guard (" + model + ")";
    h_finding.model = model;
    h_finding.ai_input = prompt;
    h_finding.ai_output = response;
    return h_finding;
}

ScanFinding AiScanner::scan_gemini(const std::string& file_path, std::string_view content) const {
    std::string api_key = api_key_;
    if (api_key.empty()) {
        const char* k = std::getenv("GEMINI_API_KEY");
        if (!k) k = std::getenv("SLUG_AI_API_KEY");
        if (k) api_key = k;
    }
    if (api_key.empty()) {
        return scan_heuristic(file_path, content, false, false);
    }

    auto h_finding = scan_heuristic(file_path, content, false, false);
    if (h_finding.has_secret) return h_finding;

    auto lines = core::Utils::split(content, '\n');
    std::string snippet;
    size_t scan_limit = std::min(lines.size(), (size_t)100);
    for (size_t i = 0; i < scan_limit; ++i) {
        snippet += lines[i] + "\n";
    }

    std::string model = model_.empty() ? "gemini-flash-latest" : model_;
    std::string endpoint = endpoint_;
    if (endpoint.empty() || endpoint.find("localhost") != std::string::npos || endpoint.find("127.0.0.1") != std::string::npos) {
        endpoint = "https://generativelanguage.googleapis.com/v1beta";
    }
    while (!endpoint.empty() && endpoint.back() == '/') endpoint.pop_back();

    std::string url;
    if (endpoint.find(":generateContent") != std::string::npos) {
        url = endpoint;
    } else if (endpoint.find("/models/") != std::string::npos) {
        url = endpoint + ":generateContent";
    } else {
        url = endpoint + "/models/" + model + ":generateContent";
    }

    if (!is_safe_shell_param(url) || !is_safe_shell_param(api_key)) return h_finding;

    std::string prompt = "You are an automated code security auditor. Inspect this code from '" + file_path + "'. Does it contain hardcoded credentials, API keys, private keys, or passwords? Respond ONLY with a valid JSON object: {\"has_secret\": true/false, \"reason\": \"<short description>\", \"line\": <line_number>}.\n\n" + snippet;

    json req_body;
    req_body["contents"] = json::array({
        json{
            {"parts", json::array({
                json{{"text", prompt}}
            })}
        }
    });

    auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_gemini_" + std::to_string(core::Utils::current_timestamp()) + ".json");
    platform::PathUtils::write_text_file_atomic(tmp_payload, req_body.dump());

    std::string response = execute_http_post(url, tmp_payload, "x-goog-api-key", api_key, 8);

    std::error_code ec;
    std::filesystem::remove(tmp_payload, ec);

    if (!response.empty()) {
        try {
            auto resp_j = json::parse(response);
            auto f_opt = try_extract_finding(resp_j);
            if (f_opt.has_value()) {
                f_opt->detector = "AI Guard (" + model + ")";
                f_opt->model = model;
                f_opt->ai_input = prompt;
                f_opt->ai_output = response;
                if (f_opt->has_secret) {
                    f_opt->reason = "Gemini AI Audit: " + f_opt->reason;
                } else {
                    f_opt->reason = "Clean (Gemini: Không phát hiện rò rỉ mã bí mật)";
                }
                return *f_opt;
            }
        } catch (...) {}
    }

    h_finding.detector = "AI Guard (" + model + ")";
    h_finding.model = model;
    h_finding.ai_input = prompt;
    h_finding.ai_output = response.empty() ? "(Không nhận được phản hồi từ Gemini API)" : response;
    return h_finding;
}

ScanFinding AiScanner::scan_anthropic(const std::string& file_path, std::string_view content) const {
    std::string api_key = api_key_;
    if (api_key.empty()) {
        const char* k = std::getenv("ANTHROPIC_API_KEY");
        if (!k) k = std::getenv("SLUG_AI_API_KEY");
        if (k) api_key = k;
    }
    if (api_key.empty()) return scan_heuristic(file_path, content, false, false);

    auto h_finding = scan_heuristic(file_path, content, false, false);
    if (h_finding.has_secret) return h_finding;

    auto lines = core::Utils::split(content, '\n');
    std::string snippet;
    size_t scan_limit = std::min(lines.size(), (size_t)100);
    for (size_t i = 0; i < scan_limit; ++i) {
        snippet += lines[i] + "\n";
    }

    std::string model = model_.empty() ? "claude-3-5-haiku-20241022" : model_;
    std::string endpoint = endpoint_.empty() ? "https://api.anthropic.com/v1/messages" : endpoint_;

    std::string prompt = "You are an automated code security auditor. Inspect this code from '" + file_path + "'. Does it contain hardcoded credentials, API keys, private keys, or passwords? Respond ONLY with a valid JSON object: {\"has_secret\": true/false, \"reason\": \"<short description>\", \"line\": <line_number>}.\n\n" + snippet;

    json req_body;
    req_body["model"] = model;
    req_body["max_tokens"] = 1024;
    req_body["messages"] = json::array({
        json{{"role", "user"}, {"content", prompt}}
    });

    auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_anthropic_" + std::to_string(core::Utils::current_timestamp()) + ".json");
    platform::PathUtils::write_text_file_atomic(tmp_payload, req_body.dump());

    std::vector<std::pair<std::string, std::string>> hdrs = {
        {"x-api-key", api_key},
        {"anthropic-version", "2023-06-01"}
    };
    std::string response = execute_http_post(endpoint, tmp_payload, hdrs, 10);

    std::error_code ec;
    std::filesystem::remove(tmp_payload, ec);

    if (!response.empty()) {
        try {
            auto resp_j = json::parse(response);
            auto f_opt = try_extract_finding(resp_j);
            if (f_opt.has_value()) {
                f_opt->detector = "AI Guard (" + model + ")";
                f_opt->model = model;
                f_opt->ai_input = prompt;
                f_opt->ai_output = response;
                if (f_opt->has_secret) {
                    f_opt->reason = "Claude AI Audit: " + f_opt->reason;
                } else {
                    f_opt->reason = "Clean (Claude: Không phát hiện rò rỉ mã bí mật)";
                }
                return *f_opt;
            }
        } catch (...) {}
    }

    h_finding.detector = "AI Guard (" + model + ")";
    h_finding.model = model;
    h_finding.ai_input = prompt;
    h_finding.ai_output = response.empty() ? "(Không nhận được phản hồi từ Claude API)" : response;
    return h_finding;
}

ScanFinding AiScanner::scan_custom(const std::string& file_path, std::string_view content) const {
    auto h_finding = scan_heuristic(file_path, content, false, false);
    if (h_finding.has_secret) return h_finding;

    auto lines = core::Utils::split(content, '\n');
    std::string snippet;
    size_t scan_limit = std::min(lines.size(), (size_t)100);
    for (size_t i = 0; i < scan_limit; ++i) {
        snippet += lines[i] + "\n";
    }

    std::string prompt = "You are an automated code security auditor. Inspect this code from '" + file_path + "'. Does it contain hardcoded credentials, API keys, private keys, or passwords? Respond ONLY with a valid JSON object: {\"has_secret\": true/false, \"reason\": \"<short description>\", \"line\": <line_number>}.\n\n" + snippet;

    // Render body from template
    std::string raw_body = body_template_;
    json prompt_json = prompt;
    std::string prompt_escaped = prompt_json.dump();
    if (prompt_escaped.size() >= 2 && prompt_escaped.front() == '"' && prompt_escaped.back() == '"') {
        prompt_escaped = prompt_escaped.substr(1, prompt_escaped.size() - 2);
    }

    auto replace_all = [](std::string& str, const std::string& from, const std::string& to) {
        size_t start_pos = 0;
        while((start_pos = str.find(from, start_pos)) != std::string::npos) {
            str.replace(start_pos, from.length(), to);
            start_pos += to.length();
        }
    };

    replace_all(raw_body, "{{PROMPT}}", prompt_escaped);
    replace_all(raw_body, "{{MODEL}}", model_);
    replace_all(raw_body, "{{FILE_PATH}}", file_path);
    replace_all(raw_body, "{{API_KEY}}", api_key_);

    std::vector<std::pair<std::string, std::string>> hdrs = headers_;
    for (auto& [hk, hv] : hdrs) {
        replace_all(hv, "{{API_KEY}}", api_key_);
    }

    auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_custom_ai_" + std::to_string(core::Utils::current_timestamp()) + ".json");
    platform::PathUtils::write_text_file_atomic(tmp_payload, raw_body);

    std::string url = endpoint_;
    if (url.find("generativelanguage.googleapis.com") != std::string::npos) {
        while (!url.empty() && url.back() == '/') url.pop_back();
        if (url.find(":generateContent") == std::string::npos) {
            std::string mod = model_.empty() ? "gemini-flash-latest" : model_;
            if (url.find("/models/") == std::string::npos) {
                url = url + "/models/" + mod + ":generateContent";
            } else {
                url = url + ":generateContent";
            }
        }
    }

    std::string response = execute_http_post(url, tmp_payload, hdrs, 10);

    std::error_code ec;
    std::filesystem::remove(tmp_payload, ec);

    std::string custom_model = model_.empty() ? "Custom LLM" : model_;
    if (!response.empty()) {
        try {
            auto resp_j = json::parse(response);
            auto f_opt = try_extract_finding(resp_j);
            if (f_opt.has_value()) {
                f_opt->detector = "AI Guard (" + custom_model + ")";
                f_opt->model = custom_model;
                f_opt->ai_input = raw_body;
                f_opt->ai_output = response;
                if (f_opt->has_secret) {
                    f_opt->reason = "Custom AI Audit: " + f_opt->reason;
                } else {
                    f_opt->reason = "Clean (Custom AI: Không phát hiện rò rỉ mã bí mật)";
                }
                return *f_opt;
            }
        } catch (...) {}
    }

    h_finding.detector = "AI Guard (" + custom_model + ")";
    h_finding.model = custom_model;
    h_finding.ai_input = raw_body;
    h_finding.ai_output = response.empty() ? "(Không nhận được phản hồi từ Custom Endpoint)" : response;
    return h_finding;
}

ScanFinding AiScanner::scan_cloud(const std::string& file_path, std::string_view content) const {
    std::string api_key = api_key_;
    if (api_key.empty()) {
        const char* api_key_env = std::getenv("SLUG_AI_API_KEY");
        if (!api_key_env) api_key_env = std::getenv("GROQ_API_KEY");
        if (!api_key_env) api_key_env = std::getenv("OPENROUTER_API_KEY");
        if (!api_key_env) api_key_env = std::getenv("OPENAI_API_KEY");
        if (api_key_env) api_key = api_key_env;
    }

    if (api_key.empty()) {
        return scan_heuristic(file_path, content, false, false);
    }

    std::string endpoint = endpoint_;
    std::string model = model_;

    if (endpoint == "http://127.0.0.1:11434" || endpoint.empty()) {
        if (api_key.rfind("gsk_", 0) == 0 || std::getenv("GROQ_API_KEY")) {
            endpoint = "https://api.groq.com/openai/v1/chat/completions";
            model = "llama-3.3-70b-versatile";
        } else if (api_key.rfind("sk-or-", 0) == 0 || std::getenv("OPENROUTER_API_KEY")) {
            endpoint = "https://openrouter.ai/api/v1/chat/completions";
            model = "meta-llama/llama-3.2-3b-instruct:free";
        } else {
            endpoint = "https://api.openai.com/v1/chat/completions";
            model = "gpt-4o-mini";
        }
    }

    const char* custom_endpoint = std::getenv("SLUG_AI_ENDPOINT");
    if (custom_endpoint && *custom_endpoint) endpoint = custom_endpoint;
    const char* custom_model = std::getenv("SLUG_AI_MODEL");
    if (custom_model && *custom_model) model = custom_model;

    // Fast heuristic first without entropy preemption
    auto h_finding = scan_heuristic(file_path, content, false, false);
    if (h_finding.has_secret) return h_finding;

    auto lines = core::Utils::split(content, '\n');
    std::string snippet;
    size_t scan_limit = std::min(lines.size(), (size_t)100);
    for (size_t i = 0; i < scan_limit; ++i) {
        snippet += lines[i] + "\n";
    }

    std::string prompt_text = "Analyze file: " + file_path + "\n\n" + snippet;
    json req_body;
    req_body["model"] = model;
    req_body["messages"] = json::array({
        {
            {"role", "system"},
            {"content", "You are an automated code security auditor. Detect hardcoded credentials, API keys, passwords, or secrets. Respond ONLY with a valid JSON object in this format: {\"has_secret\": true/false, \"reason\": \"<short description>\", \"line\": <line_number>}."}
        },
        {
            {"role", "user"},
            {"content", prompt_text}
        }
    });
    req_body["temperature"] = 0.0;

    if (!is_safe_shell_param(endpoint) || !is_safe_shell_param(api_key)) return h_finding;

    auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ai_req_" + std::to_string(core::Utils::current_timestamp()) + ".json");
    platform::PathUtils::write_text_file_atomic(tmp_payload, req_body.dump());

    std::string response = execute_http_post(endpoint, tmp_payload, "Authorization", "Bearer " + api_key, 8);

    std::error_code ec;
    std::filesystem::remove(tmp_payload, ec);

    if (!response.empty()) {
        try {
            auto resp_j = json::parse(response);
            auto f_opt = try_extract_finding(resp_j);
            if (f_opt.has_value()) {
                f_opt->detector = "AI Guard (" + model + ")";
                f_opt->model = model;
                f_opt->ai_input = prompt_text;
                f_opt->ai_output = response;
                if (f_opt->has_secret) {
                    f_opt->reason = "Cloud AI Audit: " + f_opt->reason;
                } else {
                    f_opt->reason = "Clean (Cloud AI: Không phát hiện rò rỉ mã bí mật)";
                }
                return *f_opt;
            }
        } catch (...) {}
    }

    h_finding.detector = "AI Guard (" + model + ")";
    h_finding.model = model;
    h_finding.ai_input = prompt_text;
    h_finding.ai_output = response.empty() ? "(Không nhận được phản hồi từ Cloud Endpoint)" : response;
    return h_finding;
}

ScanFinding AiScanner::scan_content(const std::string& file_path, std::string_view content, bool deep, core::FilterLevel level) const {
    if (level == core::FilterLevel::LEVEL_0_RAW || level == core::FilterLevel::LEVEL_1_RULES) {
        // Mức 0 & Mức 1: Hoàn toàn không quét nội dung!
        ScanFinding safe;
        safe.has_secret = false;
        return safe;
    }
    if (!is_scannable_file(file_path)) {
        ScanFinding safe;
        safe.has_secret = false;
        return safe;
    }
    if (level == core::FilterLevel::LEVEL_2_REGEX) {
        // Mức 2: Regex Secret Guard (Tắt tính entropy)
        return scan_heuristic(file_path, content, deep, false);
    }
    if (level == core::FilterLevel::LEVEL_3_ENTROPY) {
        // Mức 3: Shannon Entropy trên file văn bản/mã nguồn
        return scan_heuristic(file_path, content, deep, true);
    }
    // Mức 4: AI Model Scan
    if (provider_ == ProviderType::LOCAL_OLLAMA) {
        return scan_ollama(file_path, content);
    }
    if (provider_ == ProviderType::CLOUD_API) {
        if (endpoint_.find("generativelanguage.googleapis.com") != std::string::npos ||
            api_key_.rfind("AIzaSy", 0) == 0 ||
            model_.find("gemini") != std::string::npos) {
            return scan_gemini(file_path, content);
        }
        if (endpoint_.find("api.anthropic.com") != std::string::npos ||
            model_.find("claude") != std::string::npos ||
            api_key_.rfind("sk-ant-", 0) == 0) {
            return scan_anthropic(file_path, content);
        }
        if (!body_template_.empty()) {
            return scan_custom(file_path, content);
        }
        return scan_cloud(file_path, content);
    }
    return scan_heuristic(file_path, content, deep, true);
}

std::pair<bool, std::string> AiScanner::test_connection() const {
    auto res = test_connection_detailed();
    return {res.success, res.message};
}

ConnectionTestResult AiScanner::test_connection_detailed() const {
    ConnectionTestResult result;
    auto start_t = std::chrono::steady_clock::now();

    if (provider_ == ProviderType::LOCAL_HEURISTIC) {
        result.success = true;
        result.message = "Bộ lọc nội bộ (Local Heuristic / Regex) hoạt động bình thường mà không cần kết nối mạng.";
        result.endpoint = "internal://regex-engine";
        result.model = "builtin-regex-entropy";
        result.request_payload = "N/A (Chạy trực tiếp trên CPU bộ nhớ trong)";
        result.response_payload = "N/A (Không có kết nối mạng)";
        result.duration_ms = 0;
        return result;
    }

    if (provider_ == ProviderType::LOCAL_OLLAMA) {
        std::string url = endpoint_ + "/api/tags";
        result.endpoint = url;
        result.model = model_.empty() ? "ollama-model" : model_;
        result.request_payload = "{}";

        auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ping_" + std::to_string(core::Utils::current_timestamp()) + ".json");
        platform::PathUtils::write_text_file_atomic(tmp_payload, "{}");
        std::string resp = execute_http_post(url, tmp_payload, "", "", 4);
        std::error_code ec;
        std::filesystem::remove(tmp_payload, ec);

        auto end_t = std::chrono::steady_clock::now();
        result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_t - start_t).count();
        result.response_payload = resp;

        if (resp.empty()) {
            result.success = false;
            result.message = "Không thể kết nối tới máy chủ Ollama tại '" + endpoint_ + "'. Hãy đảm bảo Ollama đã được khởi động.";
            return result;
        }
        try {
            auto j = json::parse(resp);
            if (j.contains("models")) {
                result.success = true;
                result.message = "Kết nối Ollama thành công! Máy chủ đang hoạt động tại " + endpoint_ + ".";
                return result;
            }
        } catch (...) {}
        result.success = true;
        result.message = "Kết nối Ollama thành công!";
        return result;
    }

    if (provider_ == ProviderType::CLOUD_API) {
        // 1. Google Gemini API
        if (endpoint_.find("generativelanguage.googleapis.com") != std::string::npos ||
            api_key_.rfind("AIzaSy", 0) == 0 ||
            model_.find("gemini") != std::string::npos) {
            
            std::string api_key = api_key_;
            if (api_key.empty()) {
                const char* k = std::getenv("GEMINI_API_KEY");
                if (k) api_key = k;
            }
            if (api_key.empty()) {
                result.success = false;
                result.message = "Thiếu API Key cho Google Gemini. Vui lòng nhập khóa bắt đầu bằng 'AIzaSy...'.";
                result.endpoint = endpoint_;
                result.model = model_;
                return result;
            }

            std::string model = model_.empty() ? "gemini-flash-latest" : model_;
            std::string endpoint = endpoint_.empty() ? "https://generativelanguage.googleapis.com/v1beta" : endpoint_;
            while (!endpoint.empty() && endpoint.back() == '/') endpoint.pop_back();

            std::string url;
            if (endpoint.find(":generateContent") != std::string::npos) {
                url = endpoint;
            } else if (endpoint.find("/models/") != std::string::npos) {
                url = endpoint + ":generateContent";
            } else {
                url = endpoint + "/models/" + model + ":generateContent";
            }

            result.endpoint = url;
            result.model = model;

            json req_body;
            req_body["contents"] = json::array({
                json{{"parts", json::array({json{{"text", "ping"}}})}}
            });
            result.request_payload = req_body.dump(2);

            auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ping_gemini_" + std::to_string(core::Utils::current_timestamp()) + ".json");
            platform::PathUtils::write_text_file_atomic(tmp_payload, req_body.dump());
            std::string resp = execute_http_post(url, tmp_payload, "x-goog-api-key", api_key, 6);
            std::error_code ec;
            std::filesystem::remove(tmp_payload, ec);

            auto end_t = std::chrono::steady_clock::now();
            result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_t - start_t).count();
            result.response_payload = resp;

            if (resp.empty()) {
                result.success = false;
                result.message = "Không nhận được phản hồi từ Google Gemini API. Vui lòng kiểm tra kết nối mạng và URL endpoint.";
                return result;
            }
            try {
                auto j = json::parse(resp);
                if (j.contains("error")) {
                    std::string msg = j["error"].value("message", "Lỗi không xác định từ Gemini API");
                    result.success = false;
                    result.message = "Google Gemini API trả về lỗi: " + msg;
                    return result;
                }
                if (j.contains("candidates")) {
                    result.success = true;
                    result.message = "Kết nối Google Gemini API thành công! Mô hình [" + model + "] phản hồi bình thường.";
                    return result;
                }
            } catch (...) {}
            result.success = true;
            result.message = "Kết nối Google Gemini API thành công!";
            return result;
        }

        // 2. Anthropic Claude API
        if (endpoint_.find("api.anthropic.com") != std::string::npos ||
            model_.find("claude") != std::string::npos ||
            api_key_.rfind("sk-ant-", 0) == 0) {
            
            std::string api_key = api_key_;
            if (api_key.empty()) {
                result.success = false;
                result.message = "Thiếu API Key cho Anthropic Claude. Vui lòng nhập khóa 'sk-ant-...'.";
                result.endpoint = endpoint_;
                result.model = model_;
                return result;
            }
            
            std::string model = model_.empty() ? "claude-3-5-haiku-20241022" : model_;
            std::string endpoint = endpoint_.empty() ? "https://api.anthropic.com/v1/messages" : endpoint_;

            result.endpoint = endpoint;
            result.model = model;

            json req_body;
            req_body["model"] = model;
            req_body["max_tokens"] = 10;
            req_body["messages"] = json::array({json{{"role", "user"}, {"content", "hi"}}});
            result.request_payload = req_body.dump(2);

            auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ping_claude_" + std::to_string(core::Utils::current_timestamp()) + ".json");
            platform::PathUtils::write_text_file_atomic(tmp_payload, req_body.dump());
            std::vector<std::pair<std::string, std::string>> hdrs = {
                {"x-api-key", api_key},
                {"anthropic-version", "2023-06-01"}
            };
            std::string resp = execute_http_post(endpoint, tmp_payload, hdrs, 6);
            std::error_code ec;
            std::filesystem::remove(tmp_payload, ec);

            auto end_t = std::chrono::steady_clock::now();
            result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_t - start_t).count();
            result.response_payload = resp;

            if (resp.empty()) {
                result.success = false;
                result.message = "Không nhận được phản hồi từ Anthropic Claude API.";
                return result;
            }
            try {
                auto j = json::parse(resp);
                if (j.contains("error")) {
                    std::string msg = j["error"].value("message", "Lỗi Claude API");
                    result.success = false;
                    result.message = "Claude API trả về lỗi: " + msg;
                    return result;
                }
                if (j.contains("content")) {
                    result.success = true;
                    result.message = "Kết nối Claude API thành công! Mô hình [" + model + "] hoạt động bình thường.";
                    return result;
                }
            } catch (...) {}
            result.success = true;
            result.message = "Kết nối Anthropic Claude API thành công!";
            return result;
        }

        // 3. OpenAI / Custom Cloud API
        std::string ep = endpoint_.empty() ? "https://api.openai.com/v1/chat/completions" : endpoint_;
        std::string model = model_.empty() ? "gpt-4o-mini" : model_;
        result.endpoint = ep;
        result.model = model;

        json req_body;
        req_body["model"] = model;
        req_body["messages"] = json::array({json{{"role", "user"}, {"content", "hi"}}});
        req_body["max_tokens"] = 10;
        result.request_payload = req_body.dump(2);

        auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ping_cloud_" + std::to_string(core::Utils::current_timestamp()) + ".json");
        platform::PathUtils::write_text_file_atomic(tmp_payload, req_body.dump());
        std::string auth_hdr = "Bearer " + api_key_;
        std::string resp = execute_http_post(ep, tmp_payload, "Authorization", auth_hdr, 6);
        std::error_code ec;
        std::filesystem::remove(tmp_payload, ec);

        auto end_t = std::chrono::steady_clock::now();
        result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_t - start_t).count();
        result.response_payload = resp;

        if (resp.empty()) {
            result.success = false;
            result.message = "Không nhận được phản hồi từ dịch vụ AI tại '" + ep + "'.";
            return result;
        }
        try {
            auto j = json::parse(resp);
            if (j.contains("error")) {
                std::string msg = j["error"].value("message", "Lỗi API");
                result.success = false;
                result.message = "Dịch vụ AI trả về lỗi: " + msg;
                return result;
            }
            if (j.contains("choices")) {
                result.success = true;
                result.message = "Kết nối dịch vụ AI thành công! Mô hình [" + model + "] phản hồi bình thường.";
                return result;
            }
        } catch (...) {}
        result.success = true;
        result.message = "Dịch vụ AI đã phản hồi kết nối!";
        return result;
    }

    result.success = true;
    result.message = "Dịch vụ sẵn sàng.";
    return result;
}

} // namespace slug::ai

