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
#include <thread>
#include <chrono>
#include <atomic>

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

static std::atomic<bool> g_scan_cancelled{false};

void AiScanner::request_cancellation() {
    g_scan_cancelled.store(true);
}

void AiScanner::reset_cancellation() {
    g_scan_cancelled.store(false);
}

bool AiScanner::is_cancelled() {
    return g_scan_cancelled.load();
}

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

bool AiScanner::is_binary_content(std::string_view content) {
    if (content.empty()) return false;
    size_t check_len = std::min(content.size(), (size_t)4096);
    size_t non_text = 0;
    for (size_t i = 0; i < check_len; ++i) {
        unsigned char c = static_cast<unsigned char>(content[i]);
        if (c == 0) return true; // Null byte indicates binary content
        if (c < 7 || (c > 13 && c < 32)) {
            non_text++;
        }
    }
    return (non_text * 100 / check_len) > 20;
}

std::string AiScanner::sanitize_utf8(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    size_t i = 0;
    while (i < input.size()) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c == 0) {
            out += ' ';
            i++;
        } else if (c < 0x80) {
            out += static_cast<char>(c);
            i++;
        } else if ((c >> 5) == 0x06) { // 2-byte sequence
            if (i + 1 < input.size() && (static_cast<unsigned char>(input[i+1]) >> 6) == 0x02) {
                out += input[i];
                out += input[i+1];
                i += 2;
            } else {
                out += '?';
                i++;
            }
        } else if ((c >> 4) == 0x0E) { // 3-byte sequence
            if (i + 2 < input.size() && 
                (static_cast<unsigned char>(input[i+1]) >> 6) == 0x02 &&
                (static_cast<unsigned char>(input[i+2]) >> 6) == 0x02) {
                out += input[i];
                out += input[i+1];
                out += input[i+2];
                i += 3;
            } else {
                out += '?';
                i++;
            }
        } else if ((c >> 3) == 0x1E) { // 4-byte sequence
            if (i + 3 < input.size() &&
                (static_cast<unsigned char>(input[i+1]) >> 6) == 0x02 &&
                (static_cast<unsigned char>(input[i+2]) >> 6) == 0x02 &&
                (static_cast<unsigned char>(input[i+3]) >> 6) == 0x02) {
                out += input[i];
                out += input[i+1];
                out += input[i+2];
                out += input[i+3];
                i += 4;
            } else {
                out += '?';
                i++;
            }
        } else {
            out += '?';
            i++;
        }
    }
    return out;
}

static std::string safe_dump_json(const json& j, int indent = -1) {
    try {
        return j.dump(indent, ' ', false, json::error_handler_t::replace);
    } catch (...) {
        return "{}";
    }
}

bool AiScanner::is_scannable_file(const std::filesystem::path& path) {
    std::string fname = path.filename().string();
    std::string ext = path.extension().string();
    for (auto& c : fname) c = static_cast<char>(std::tolower(c));
    for (auto& c : ext) c = static_cast<char>(std::tolower(c));

    // Absolute exclusion for binary, compiled, compressed, database, and encrypted files
    static const std::vector<std::string> binary_exts = {
        ".pyd", ".dll", ".exe", ".bin", ".pak", ".so", ".dylib", ".obj", ".o",
        ".class", ".pyc", ".dat", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
        ".svg", ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz", ".7z", ".iso",
        ".ttf", ".woff", ".woff2", ".wasm", ".pdb", ".lib", ".a", ".node",
        ".pqc", ".vault", ".enc", ".sealed", ".sig", ".db", ".sqlite", ".sqlite3"
    };
    for (const auto& be : binary_exts) {
        if (ext == be) return false;
    }

    // Encrypted files or Slug env containers (.env.pqc, .env.vault) are NOT plaintext code/secrets
    if (fname.ends_with(".pqc") || fname.ends_with(".vault") || fname.ends_with(".enc") || fname.ends_with(".sealed") ||
        ext == ".pqc" || ext == ".vault" || ext == ".enc" || ext == ".sealed") {
        return false;
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
    // Exclude sealed/encrypted files: .env.pqc, .env.vault, .env.enc, .env.sealed
    if ((fname == ".env" || fname.rfind(".env.", 0) == 0 || std::filesystem::path(file_path).extension().string() == ".env") &&
        fname != ".env.example" && fname != ".env.sample" && fname != ".env.template" &&
        !fname.ends_with(".pqc") && !fname.ends_with(".vault") && !fname.ends_with(".enc") && !fname.ends_with(".sealed")) {
        finding.has_secret = true;
        finding.status = ScanStatus::SECRET_FOUND;
        finding.line_number = 1;
        finding.reason = "Environment Secret File (" + fname + ")";
        finding.matched_snippet = content.empty() ? fname : sanitize_utf8(content.substr(0, std::min(content.size(), (size_t)80)));
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
                finding.status = ScanStatus::SECRET_FOUND;
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

                // Skip template expressions, f-strings, function calls, spaces
                bool is_token_candidate = true;
                if (val.find('{') != std::string::npos || val.find('}') != std::string::npos ||
                    val.find('(') != std::string::npos || val.find(')') != std::string::npos ||
                    val.find(' ') != std::string::npos || val.rfind("f\"", 0) == 0 || val.rfind("f'", 0) == 0) {
                    is_token_candidate = false;
                }

                // Only evaluate ASCII token candidates (skip natural language / multi-byte UTF-8)
                for (char c : val) {
                    if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) {
                        is_token_candidate = false;
                        break;
                    }
                }
                if (is_token_candidate && val.size() >= 24 && calculate_entropy(val) >= 4.8) {
                    finding.has_secret = true;
                    finding.status = ScanStatus::SECRET_FOUND;
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

                bool is_ascii_word = true;
                if (clean.find('{') != std::string::npos || clean.find('}') != std::string::npos ||
                    clean.find('(') != std::string::npos || clean.find(')') != std::string::npos ||
                    clean.rfind("f\"", 0) == 0 || clean.rfind("f'", 0) == 0) {
                    is_ascii_word = false;
                }

                for (char c : clean) {
                    if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) {
                        is_ascii_word = false;
                        break;
                    }
                }

                if (is_ascii_word && clean.size() >= 32 && calculate_entropy(clean) >= 5.0) {
                    // High entropy secret detected!
                    finding.has_secret = true;
                    finding.status = ScanStatus::SECRET_FOUND;
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
struct HttpResponse {
    int status_code{0};
    std::string body;
    std::string error_message;
    bool is_timeout{false};
    int retry_after_sec{0};
};

static int extract_retry_delay(const std::string& body, int default_delay) {
    int delay = default_delay;
    try {
        auto j = json::parse(body);
        if (j.contains("error")) {
            auto& err = j["error"];
            if (err.contains("details") && err["details"].is_array()) {
                for (const auto& item : err["details"]) {
                    if (item.contains("retryDelay") && item["retryDelay"].is_string()) {
                        std::string rd = item["retryDelay"].get<std::string>();
                        double sec = std::atof(rd.c_str());
                        if (sec > 0) delay = std::max(delay, static_cast<int>(std::ceil(sec)));
                    }
                }
            }
            if (err.contains("message") && err["message"].is_string()) {
                std::string msg = err["message"].get<std::string>();
                static const std::regex re_retry(R"(retry in ([0-9]+(?:\.[0-9]+)?)s)", std::regex::icase);
                std::smatch m;
                if (std::regex_search(msg, m, re_retry)) {
                    double sec = std::atof(m[1].str().c_str());
                    if (sec > 0) delay = std::max(delay, static_cast<int>(std::ceil(sec)));
                }
            }
        }
    } catch (...) {}
    return delay;
}

static HttpResponse execute_http_post_single(const std::string& url,
                                             const std::filesystem::path& payload_file,
                                             const std::vector<std::pair<std::string, std::string>>& headers,
                                             int timeout_sec) {
    HttpResponse resp;
    if (AiScanner::is_cancelled()) {
        resp.status_code = -1;
        resp.error_message = "Cancelled by user";
        return resp;
    }

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

    auto tmp_hdr = std::filesystem::temp_directory_path() / ("slug_hdr_" + std::to_string(core::Utils::current_timestamp()) + "_" + std::to_string(rand()) + ".txt");

    std::string curl_cmd = "curl -s -S -m " + std::to_string(timeout_sec) + " -X POST \"" + url + "\" "
                         + headers_cmd
                         + "-D \"" + tmp_hdr.generic_string() + "\" "
                         + "-d @\"" + payload_file.generic_string() + "\" "
                         + "-w \"\\n__SLUG_STATUS__:%{http_code}\"" + NULL_DEV;

    std::string raw_out;
    FILE* fp = popen(curl_cmd.c_str(), "r");
    if (fp) {
        char buf[2048];
        while (fgets(buf, sizeof(buf), fp)) {
            raw_out += buf;
            if (AiScanner::is_cancelled()) break;
        }
        pclose(fp);
    }

    size_t status_pos = raw_out.rfind("\n__SLUG_STATUS__:");
    if (status_pos != std::string::npos) {
        std::string code_str = raw_out.substr(status_pos + 17);
        while (!code_str.empty() && (code_str.back() == '\r' || code_str.back() == '\n' || code_str.back() == ' ')) code_str.pop_back();
        try {
            resp.status_code = std::stoi(code_str);
        } catch (...) {
            resp.status_code = 0;
        }
        resp.body = raw_out.substr(0, status_pos);
    } else {
        resp.body = raw_out;
        resp.status_code = 0;
    }

    if (resp.status_code == 0) {
        resp.is_timeout = true;
        resp.error_message = "Không nhận được phản hồi kết nối (Timeout hoặc lỗi mạng)";
    }

    if (std::filesystem::exists(tmp_hdr)) {
        auto hdr_content = platform::PathUtils::read_text_file(tmp_hdr);
        if (hdr_content) {
            auto h_lines = core::Utils::split(*hdr_content, '\n');
            for (const auto& hl : h_lines) {
                if (hl.rfind("Retry-After:", 0) == 0 || hl.rfind("retry-after:", 0) == 0) {
                    std::string val = hl.substr(12);
                    while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(val.begin());
                    while (!val.empty() && (val.back() == '\r' || val.back() == '\n' || val.back() == ' ')) val.pop_back();
                    try {
                        resp.retry_after_sec = std::stoi(val);
                    } catch (...) {}
                }
            }
        }
        std::error_code ec;
        std::filesystem::remove(tmp_hdr, ec);
    }

    if (!resp.body.empty()) {
        resp.retry_after_sec = extract_retry_delay(resp.body, resp.retry_after_sec);
    }

    return resp;
}

static HttpResponse execute_http_post_with_retry(
    const std::string& url,
    const std::filesystem::path& payload_file,
    const std::vector<std::pair<std::string, std::string>>& headers,
    int timeout_sec,
    int max_retries = 2) {
    
    HttpResponse resp;
    for (int attempt = 0; attempt <= max_retries; ++attempt) {
        if (AiScanner::is_cancelled()) {
            resp.status_code = -1;
            resp.error_message = "Cancelled by user";
            return resp;
        }
        resp = execute_http_post_single(url, payload_file, headers, timeout_sec);
        if (AiScanner::is_cancelled()) {
            resp.status_code = -1;
            resp.error_message = "Cancelled by user";
            return resp;
        }

        bool is_retryable = (resp.status_code == 429 || resp.status_code == 503 || resp.status_code == 504 ||
                             resp.status_code == 502 || resp.status_code == 500 || (resp.status_code == 0 && resp.is_timeout));

        if (!is_retryable || attempt == max_retries) {
            break;
        }

        int wait_sec = (resp.retry_after_sec > 0) ? resp.retry_after_sec : ((1 << attempt) * 2);
        wait_sec = std::clamp(wait_sec, 1, 10);

        for (int step = 0; step < wait_sec * 10; ++step) {
            if (AiScanner::is_cancelled()) {
                resp.status_code = -1;
                resp.error_message = "Cancelled by user";
                return resp;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    return resp;
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

static ScanFinding classify_ai_result(
    const ScanFinding& h_finding,
    const HttpResponse& resp,
    const std::string& model,
    const std::string& prompt,
    const std::string& provider_name) {
    
    ScanFinding finding = h_finding;
    finding.detector = "AI Guard (" + model + ")";
    finding.model = model;
    finding.ai_input = AiScanner::sanitize_utf8(prompt);
    finding.ai_output = AiScanner::sanitize_utf8(resp.body.empty() ? ("(Không có phản hồi từ " + provider_name + ")") : resp.body);
    finding.matched_snippet = AiScanner::sanitize_utf8(finding.matched_snippet);
    finding.http_status = resp.status_code;
    finding.retry_after_sec = resp.retry_after_sec;

    // RULE 1: If cancellation requested
    if (resp.status_code == -1 || AiScanner::is_cancelled()) {
        finding.status = ScanStatus::CANCELLED;
        finding.reason = "⏹️ Đã dừng quét bởi người dùng";
        return finding;
    }

    // RULE 2: If Heuristic already detected a secret, SECRET_FOUND is ALWAYS preserved!
    if (h_finding.has_secret) {
        finding.has_secret = true;
        finding.status = ScanStatus::SECRET_FOUND;
        if (resp.status_code == 429) {
            finding.reason = h_finding.reason + " [Lưu ý: " + provider_name + " Rate Limit 429]";
        } else if (resp.status_code >= 500) {
            finding.reason = h_finding.reason + " [Lưu ý: " + provider_name + " lỗi server " + std::to_string(resp.status_code) + "]";
        } else if (resp.status_code == 0 || resp.is_timeout) {
            finding.reason = h_finding.reason + " [Lưu ý: " + provider_name + " Timeout]";
        }
        return finding;
    }

    // Heuristic was clean (has_secret == false). Now evaluate AI response:
    if (resp.status_code == 429) {
        finding.status = ScanStatus::RATE_LIMITED;
        finding.has_secret = false;
        std::string delay_str = (resp.retry_after_sec > 0) ? (" (Cần chờ " + std::to_string(resp.retry_after_sec) + "s)") : "";
        finding.reason = "⚠️ " + provider_name + " Rate Limit (429 - Hết hạn ngạch)" + delay_str;
        return finding;
    }
    if (resp.status_code == 503 || resp.status_code == 529) {
        finding.status = ScanStatus::API_ERROR;
        finding.has_secret = false;
        finding.reason = "⚠️ " + provider_name + " Quá Tải (" + std::to_string(resp.status_code) + " - Máy chủ tạm thời bận)";
        return finding;
    }
    if (resp.status_code == 401 || resp.status_code == 403) {
        finding.status = ScanStatus::API_ERROR;
        finding.has_secret = false;
        finding.reason = "❌ " + provider_name + " Lỗi Xác Thực (" + std::to_string(resp.status_code) + " - API Key sai hoặc hết hạn)";
        return finding;
    }
    if (resp.status_code >= 400 && resp.status_code < 500) {
        finding.status = ScanStatus::API_ERROR;
        finding.has_secret = false;
        finding.reason = "❌ " + provider_name + " Lỗi Yêu Cầu (" + std::to_string(resp.status_code) + ")";
        return finding;
    }
    if (resp.status_code >= 500) {
        finding.status = ScanStatus::API_ERROR;
        finding.has_secret = false;
        finding.reason = "❌ " + provider_name + " Lỗi Máy Chủ (" + std::to_string(resp.status_code) + ")";
        return finding;
    }
    if (resp.status_code == 0 || resp.is_timeout || resp.body.empty()) {
        finding.status = ScanStatus::TIMEOUT;
        finding.has_secret = false;
        finding.reason = "⏱️ Timeout (Quá thời gian chờ phản hồi mạng từ " + provider_name + ")";
        return finding;
    }

    // Parse JSON
    try {
        auto j = json::parse(resp.body);
        if (j.contains("error")) {
            auto& err = j["error"];
            std::string err_msg = err.is_string() ? err.get<std::string>() : err.value("message", "Lỗi API");
            int err_code = err.is_object() ? err.value("code", 0) : 0;
            std::string err_status = err.is_object() ? err.value("status", "") : "";
            
            if (err_code == 429 || err_status == "RESOURCE_EXHAUSTED") {
                finding.status = ScanStatus::RATE_LIMITED;
                finding.reason = "⚠️ " + provider_name + " Rate Limit (429 - Hết hạn ngạch)";
            } else if (err_code == 503 || err_status == "UNAVAILABLE") {
                finding.status = ScanStatus::API_ERROR;
                finding.reason = "⚠️ " + provider_name + " Quá Tải (503 - Máy chủ bận)";
            } else {
                finding.status = ScanStatus::API_ERROR;
                finding.reason = "❌ " + provider_name + " Lỗi: " + err_msg;
            }
            finding.has_secret = false;
            return finding;
        }

        auto f_opt = try_extract_finding(j);
        if (f_opt.has_value()) {
            finding.has_secret = f_opt->has_secret;
            finding.line_number = f_opt->line_number;
            finding.matched_snippet = f_opt->matched_snippet;
            if (f_opt->has_secret) {
                finding.status = ScanStatus::SECRET_FOUND;
                finding.reason = provider_name + " AI Audit: " + f_opt->reason;
            } else {
                finding.status = ScanStatus::CLEAN;
                finding.reason = "Clean (" + provider_name + ": Không phát hiện rò rỉ mã bí mật)";
            }
            return finding;
        }
    } catch (...) {}

    finding.status = ScanStatus::HEURISTIC_ONLY;
    finding.has_secret = false;
    finding.reason = "Heuristic Clean (" + provider_name + " phản hồi nhưng định dạng không đúng chuẩn)";
    return finding;
}

ScanFinding AiScanner::scan_ollama(const std::string& file_path, std::string_view content) const {
    auto h_finding = scan_heuristic(file_path, content, false, false);
    if (!ollama_alive_) {
        if (h_finding.has_secret) {
            h_finding.status = ScanStatus::SECRET_FOUND;
            return h_finding;
        }
        ScanFinding f = h_finding;
        f.status = ScanStatus::API_ERROR;
        f.detector = "AI Guard (Ollama)";
        f.model = model_.empty() ? "qwen2.5-coder:7b" : model_;
        f.reason = "⚠️ Ollama không khả dụng (Máy chủ chưa khởi động)";
        return f;
    }

    auto lines = core::Utils::split(content, '\n');
    std::string snippet;
    size_t scan_limit = std::min(lines.size(), (size_t)80);
    for (size_t i = 0; i < scan_limit; ++i) snippet += lines[i] + "\n";

    std::string safe_snippet = sanitize_utf8(snippet);
    std::string model = model_.empty() ? "qwen2.5-coder:7b" : model_;
    std::string prompt = "Inspect this code from '" + file_path + "'. Does it contain leaked secrets or credentials? Respond ONLY with JSON: {\"has_secret\": true/false, \"reason\": \"...\", \"line\": 0}.\n\n" + safe_snippet;

    json req_body;
    try {
        req_body["model"] = model;
        req_body["prompt"] = prompt;
        req_body["stream"] = false;
    } catch (const std::exception& e) {
        ScanFinding f = h_finding;
        f.status = ScanStatus::API_ERROR;
        f.reason = "Lỗi chuẩn bị dữ liệu Ollama: " + std::string(e.what());
        return f;
    }

    std::string url = endpoint_ + "/api/generate";
    if (!is_safe_shell_param(url)) return h_finding;

    auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ollama_" + std::to_string(core::Utils::current_timestamp()) + "_" + std::to_string(rand()) + ".json");
    platform::PathUtils::write_text_file_atomic(tmp_payload, safe_dump_json(req_body));

    std::vector<std::pair<std::string, std::string>> hdrs = headers_;
    auto resp = execute_http_post_with_retry(url, tmp_payload, hdrs, 5, 1);

    std::error_code ec;
    std::filesystem::remove(tmp_payload, ec);

    if (resp.status_code == 0 || resp.is_timeout) {
        ollama_alive_ = false;
    }
    return classify_ai_result(h_finding, resp, model, prompt, "Ollama");
}

ScanFinding AiScanner::scan_gemini(const std::string& file_path, std::string_view content) const {
    std::string api_key = api_key_;
    if (api_key.empty()) {
        const char* k = std::getenv("GEMINI_API_KEY");
        if (!k) k = std::getenv("SLUG_AI_API_KEY");
        if (k) api_key = k;
    }

    auto h_finding = scan_heuristic(file_path, content, false, false);
    if (api_key.empty()) {
        if (h_finding.has_secret) {
            h_finding.status = ScanStatus::SECRET_FOUND;
            return h_finding;
        }
        ScanFinding f = h_finding;
        f.status = ScanStatus::API_ERROR;
        f.detector = "AI Guard (Google Gemini)";
        f.reason = "❌ Thiếu API Key cho Google Gemini (Chưa cấu hình API Key)";
        return f;
    }

    auto lines = core::Utils::split(content, '\n');
    std::string snippet;
    size_t scan_limit = std::min(lines.size(), (size_t)100);
    for (size_t i = 0; i < scan_limit; ++i) snippet += lines[i] + "\n";

    std::string safe_snippet = sanitize_utf8(snippet);
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

    std::string prompt = "You are an automated code security auditor. Inspect this code from '" + file_path + "'. Does it contain hardcoded credentials, API keys, private keys, or passwords? Respond ONLY with a valid JSON object: {\"has_secret\": true/false, \"reason\": \"<short description>\", \"line\": <line_number>}.\n\n" + safe_snippet;

    json req_body;
    try {
        req_body["contents"] = json::array({
            json{
                {"parts", json::array({
                    json{{"text", prompt}}
                })}
            }
        });
    } catch (const std::exception& e) {
        ScanFinding f = h_finding;
        f.status = ScanStatus::API_ERROR;
        f.reason = "Lỗi chuẩn bị dữ liệu Gemini: " + std::string(e.what());
        return f;
    }

    auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_gemini_" + std::to_string(core::Utils::current_timestamp()) + "_" + std::to_string(rand()) + ".json");
    platform::PathUtils::write_text_file_atomic(tmp_payload, safe_dump_json(req_body));

    std::vector<std::pair<std::string, std::string>> hdrs = {
        {"x-goog-api-key", api_key}
    };
    for (const auto& [hk, hv] : headers_) {
        if (hk != "x-goog-api-key") hdrs.push_back({hk, hv});
    }

    auto resp = execute_http_post_with_retry(url, tmp_payload, hdrs, 8, 2);

    std::error_code ec;
    std::filesystem::remove(tmp_payload, ec);

    return classify_ai_result(h_finding, resp, model, prompt, "Google Gemini");
}

ScanFinding AiScanner::scan_anthropic(const std::string& file_path, std::string_view content) const {
    std::string api_key = api_key_;
    if (api_key.empty()) {
        const char* k = std::getenv("ANTHROPIC_API_KEY");
        if (!k) k = std::getenv("SLUG_AI_API_KEY");
        if (k) api_key = k;
    }

    auto h_finding = scan_heuristic(file_path, content, false, false);
    if (api_key.empty()) {
        if (h_finding.has_secret) {
            h_finding.status = ScanStatus::SECRET_FOUND;
            return h_finding;
        }
        ScanFinding f = h_finding;
        f.status = ScanStatus::API_ERROR;
        f.detector = "AI Guard (Anthropic Claude)";
        f.reason = "❌ Thiếu API Key cho Anthropic Claude";
        return f;
    }

    auto lines = core::Utils::split(content, '\n');
    std::string snippet;
    size_t scan_limit = std::min(lines.size(), (size_t)100);
    for (size_t i = 0; i < scan_limit; ++i) snippet += lines[i] + "\n";

    std::string safe_snippet = sanitize_utf8(snippet);
    std::string model = model_.empty() ? "claude-3-5-haiku-20241022" : model_;
    std::string endpoint = endpoint_.empty() ? "https://api.anthropic.com/v1/messages" : endpoint_;

    std::string prompt = "You are an automated code security auditor. Inspect this code from '" + file_path + "'. Does it contain hardcoded credentials, API keys, private keys, or passwords? Respond ONLY with a valid JSON object: {\"has_secret\": true/false, \"reason\": \"<short description>\", \"line\": <line_number>}.\n\n" + safe_snippet;

    json req_body;
    try {
        req_body["model"] = model;
        req_body["max_tokens"] = 1024;
        req_body["messages"] = json::array({
            json{{"role", "user"}, {"content", prompt}}
        });
    } catch (const std::exception& e) {
        ScanFinding f = h_finding;
        f.status = ScanStatus::API_ERROR;
        f.reason = "Lỗi chuẩn bị dữ liệu Claude: " + std::string(e.what());
        return f;
    }

    auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_anthropic_" + std::to_string(core::Utils::current_timestamp()) + "_" + std::to_string(rand()) + ".json");
    platform::PathUtils::write_text_file_atomic(tmp_payload, safe_dump_json(req_body));

    std::vector<std::pair<std::string, std::string>> hdrs = {
        {"x-api-key", api_key},
        {"anthropic-version", "2023-06-01"}
    };
    for (const auto& [hk, hv] : headers_) {
        if (hk != "x-api-key" && hk != "anthropic-version") hdrs.push_back({hk, hv});
    }

    auto resp = execute_http_post_with_retry(endpoint, tmp_payload, hdrs, 10, 2);

    std::error_code ec;
    std::filesystem::remove(tmp_payload, ec);

    return classify_ai_result(h_finding, resp, model, prompt, "Anthropic Claude");
}

ScanFinding AiScanner::scan_custom(const std::string& file_path, std::string_view content) const {
    auto h_finding = scan_heuristic(file_path, content, false, false);

    auto lines = core::Utils::split(content, '\n');
    std::string snippet;
    size_t scan_limit = std::min(lines.size(), (size_t)100);
    for (size_t i = 0; i < scan_limit; ++i) snippet += lines[i] + "\n";

    std::string safe_snippet = sanitize_utf8(snippet);
    std::string prompt = "You are an automated code security auditor. Inspect this code from '" + file_path + "'. Does it contain hardcoded credentials, API keys, private keys, or passwords? Respond ONLY with a valid JSON object: {\"has_secret\": true/false, \"reason\": \"<short description>\", \"line\": <line_number>}.\n\n" + safe_snippet;

    std::string raw_body = body_template_;
    json prompt_json = prompt;
    std::string prompt_escaped = safe_dump_json(prompt_json);
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

    auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_custom_ai_" + std::to_string(core::Utils::current_timestamp()) + "_" + std::to_string(rand()) + ".json");
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

    auto resp = execute_http_post_with_retry(url, tmp_payload, hdrs, 10, 2);

    std::error_code ec;
    std::filesystem::remove(tmp_payload, ec);

    std::string custom_model = model_.empty() ? "Custom LLM" : model_;
    return classify_ai_result(h_finding, resp, custom_model, raw_body, "Custom AI");
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

    auto h_finding = scan_heuristic(file_path, content, false, false);
    if (api_key.empty()) {
        if (h_finding.has_secret) {
            h_finding.status = ScanStatus::SECRET_FOUND;
            return h_finding;
        }
        ScanFinding f = h_finding;
        f.status = ScanStatus::API_ERROR;
        f.detector = "AI Guard (Cloud API)";
        f.reason = "❌ Thiếu API Key cho Cloud LLM (OpenAI / Groq / OpenRouter)";
        return f;
    }

    std::string endpoint = endpoint_;
    std::string model = model_;
    std::string prov_name = "Cloud AI";

    if (endpoint == "http://127.0.0.1:11434" || endpoint.empty()) {
        if (api_key.rfind("gsk_", 0) == 0 || std::getenv("GROQ_API_KEY")) {
            endpoint = "https://api.groq.com/openai/v1/chat/completions";
            model = "llama-3.3-70b-versatile";
            prov_name = "Groq";
        } else if (api_key.rfind("sk-or-", 0) == 0 || std::getenv("OPENROUTER_API_KEY")) {
            endpoint = "https://openrouter.ai/api/v1/chat/completions";
            model = "meta-llama/llama-3.2-3b-instruct:free";
            prov_name = "OpenRouter";
        } else {
            endpoint = "https://api.openai.com/v1/chat/completions";
            model = "gpt-4o-mini";
            prov_name = "OpenAI";
        }
    } else {
        if (endpoint.find("groq") != std::string::npos) prov_name = "Groq";
        else if (endpoint.find("openrouter") != std::string::npos) prov_name = "OpenRouter";
        else if (endpoint.find("openai") != std::string::npos) prov_name = "OpenAI";
    }

    auto lines = core::Utils::split(content, '\n');
    std::string snippet;
    size_t scan_limit = std::min(lines.size(), (size_t)100);
    for (size_t i = 0; i < scan_limit; ++i) snippet += lines[i] + "\n";

    std::string safe_snippet = sanitize_utf8(snippet);
    std::string prompt_text = "Analyze file: " + file_path + "\n\n" + safe_snippet;
    json req_body;
    try {
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
    } catch (const std::exception& e) {
        ScanFinding f = h_finding;
        f.status = ScanStatus::API_ERROR;
        f.reason = "Lỗi chuẩn bị dữ liệu Cloud AI: " + std::string(e.what());
        return f;
    }

    if (!is_safe_shell_param(endpoint) || !is_safe_shell_param(api_key)) return h_finding;

    auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ai_req_" + std::to_string(core::Utils::current_timestamp()) + "_" + std::to_string(rand()) + ".json");
    platform::PathUtils::write_text_file_atomic(tmp_payload, safe_dump_json(req_body));

    std::vector<std::pair<std::string, std::string>> hdrs = {
        {"Authorization", "Bearer " + api_key}
    };
    for (const auto& [hk, hv] : headers_) {
        if (hk != "Authorization") hdrs.push_back({hk, hv});
    }

    auto resp = execute_http_post_with_retry(endpoint, tmp_payload, hdrs, 8, 2);

    std::error_code ec;
    std::filesystem::remove(tmp_payload, ec);

    return classify_ai_result(h_finding, resp, model, prompt_text, prov_name);
}

ScanFinding AiScanner::scan_content(const std::string& file_path, std::string_view content, bool deep, core::FilterLevel level) const {
    if (is_cancelled()) {
        ScanFinding cancelled;
        cancelled.status = ScanStatus::CANCELLED;
        cancelled.reason = "⏹️ Đã dừng quét bởi người dùng";
        return cancelled;
    }
    if (level == core::FilterLevel::LEVEL_0_RAW || level == core::FilterLevel::LEVEL_1_RULES) {
        ScanFinding safe;
        safe.status = ScanStatus::CLEAN;
        safe.has_secret = false;
        return safe;
    }
    if (!is_scannable_file(file_path)) {
        ScanFinding safe;
        safe.status = ScanStatus::CLEAN;
        safe.has_secret = false;
        safe.reason = "Tệp nhị phân hoặc đã được mã hóa an toàn (bỏ qua)";
        return safe;
    }
    if (is_binary_content(content)) {
        ScanFinding safe;
        safe.status = ScanStatus::CLEAN;
        safe.has_secret = false;
        safe.reason = "Tệp định dạng nhị phân (bỏ qua quét AI)";
        return safe;
    }
    if (level == core::FilterLevel::LEVEL_2_REGEX) {
        return scan_heuristic(file_path, content, deep, false);
    }
    if (level == core::FilterLevel::LEVEL_3_ENTROPY) {
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

        auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ping_" + std::to_string(core::Utils::current_timestamp()) + "_" + std::to_string(rand()) + ".json");
        platform::PathUtils::write_text_file_atomic(tmp_payload, "{}");
        auto resp = execute_http_post_single(url, tmp_payload, {}, 4);
        std::error_code ec;
        std::filesystem::remove(tmp_payload, ec);

        auto end_t = std::chrono::steady_clock::now();
        result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_t - start_t).count();
        result.response_payload = resp.body;
        result.http_status = resp.status_code;

        if (resp.status_code == 0 || resp.body.empty()) {
            result.success = false;
            result.message = "Không thể kết nối tới máy chủ Ollama tại '" + endpoint_ + "'. Hãy đảm bảo Ollama đã được khởi động.";
            return result;
        }
        try {
            auto j = json::parse(resp.body);
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
            result.request_payload = safe_dump_json(req_body, 2);

            auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ping_gemini_" + std::to_string(core::Utils::current_timestamp()) + "_" + std::to_string(rand()) + ".json");
            platform::PathUtils::write_text_file_atomic(tmp_payload, safe_dump_json(req_body));
            std::vector<std::pair<std::string, std::string>> hdrs = {
                {"x-goog-api-key", api_key}
            };
            auto resp = execute_http_post_single(url, tmp_payload, hdrs, 6);
            std::error_code ec;
            std::filesystem::remove(tmp_payload, ec);

            auto end_t = std::chrono::steady_clock::now();
            result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_t - start_t).count();
            result.response_payload = resp.body;
            result.http_status = resp.status_code;
            result.retry_after_sec = resp.retry_after_sec;

            if (resp.status_code == 429) {
                result.success = false;
                result.message = "Google Gemini Rate Limit (429): Quá hạn mức gọi API" + (resp.retry_after_sec > 0 ? " (Vui lòng chờ " + std::to_string(resp.retry_after_sec) + "s)" : "") + ".";
                return result;
            }
            if (resp.status_code == 503) {
                result.success = false;
                result.message = "Google Gemini Quá Tải (503): Máy chủ Google đang chịu tải cao, vui lòng thử lại sau.";
                return result;
            }
            if (resp.status_code == 400 || resp.status_code == 403) {
                result.success = false;
                result.message = "Google Gemini Lỗi Xác Thực (" + std::to_string(resp.status_code) + "): Kiểm tra lại API Key hoặc quyền truy cập model.";
                return result;
            }
            if (resp.status_code == 0 || resp.body.empty()) {
                result.success = false;
                result.message = "Không nhận được phản hồi từ Google Gemini API. Vui lòng kiểm tra kết nối mạng và URL endpoint.";
                return result;
            }

            try {
                auto j = json::parse(resp.body);
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
                const char* k = std::getenv("ANTHROPIC_API_KEY");
                if (k) api_key = k;
            }
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
            result.request_payload = safe_dump_json(req_body, 2);

            auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ping_claude_" + std::to_string(core::Utils::current_timestamp()) + "_" + std::to_string(rand()) + ".json");
            platform::PathUtils::write_text_file_atomic(tmp_payload, safe_dump_json(req_body));
            std::vector<std::pair<std::string, std::string>> hdrs = {
                {"x-api-key", api_key},
                {"anthropic-version", "2023-06-01"}
            };
            auto resp = execute_http_post_single(endpoint, tmp_payload, hdrs, 6);
            std::error_code ec;
            std::filesystem::remove(tmp_payload, ec);

            auto end_t = std::chrono::steady_clock::now();
            result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_t - start_t).count();
            result.response_payload = resp.body;
            result.http_status = resp.status_code;
            result.retry_after_sec = resp.retry_after_sec;

            if (resp.status_code == 429) {
                result.success = false;
                result.message = "Anthropic Claude Rate Limit (429): Quá hạn mức gọi API.";
                return result;
            }
            if (resp.status_code == 0 || resp.body.empty()) {
                result.success = false;
                result.message = "Không nhận được phản hồi từ Anthropic Claude API.";
                return result;
            }
            try {
                auto j = json::parse(resp.body);
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
        result.request_payload = safe_dump_json(req_body, 2);

        auto tmp_payload = std::filesystem::temp_directory_path() / ("slug_ping_cloud_" + std::to_string(core::Utils::current_timestamp()) + "_" + std::to_string(rand()) + ".json");
        platform::PathUtils::write_text_file_atomic(tmp_payload, safe_dump_json(req_body));
        std::vector<std::pair<std::string, std::string>> hdrs = {
            {"Authorization", "Bearer " + api_key_}
        };
        for (const auto& [hk, hv] : headers_) {
            if (hk != "Authorization") hdrs.push_back({hk, hv});
        }
        auto resp = execute_http_post_single(ep, tmp_payload, hdrs, 6);
        std::error_code ec;
        std::filesystem::remove(tmp_payload, ec);

        auto end_t = std::chrono::steady_clock::now();
        result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_t - start_t).count();
        result.response_payload = resp.body;
        result.http_status = resp.status_code;
        result.retry_after_sec = resp.retry_after_sec;

        if (resp.status_code == 429) {
            result.success = false;
            result.message = "Dịch vụ AI báo Rate Limit (429): Quá hạn ngạch gọi API.";
            return result;
        }
        if (resp.status_code == 0 || resp.body.empty()) {
            result.success = false;
            result.message = "Không nhận được phản hồi từ dịch vụ AI tại '" + ep + "'.";
            return result;
        }
        try {
            auto j = json::parse(resp.body);
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
