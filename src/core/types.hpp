#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <chrono>

namespace slug::core {

enum class SuiteID : uint8_t {
    SUITE_1_CLASSICAL = 0x01, // SHA-256 + Ed25519 + X25519 + XChaCha20-Poly1305
    SUITE_2_MODERN    = 0x02, // BLAKE3  + Ed25519 + X25519 + XChaCha20-Poly1305
    SUITE_3_PURE_PQC  = 0x03  // BLAKE3  + ML-DSA-65 + ML-KEM-768 + XChaCha20-Poly1305
};

inline std::string suite_to_string(SuiteID s) {
    switch (s) {
        case SuiteID::SUITE_1_CLASSICAL: return "Suite 1: Classical (SHA-256/Ed25519/X25519/XChaCha)";
        case SuiteID::SUITE_2_MODERN:    return "Suite 2: Modern (BLAKE3/Ed25519/X25519/XChaCha)";
        case SuiteID::SUITE_3_PURE_PQC:  return "Suite 3: PurePQC (BLAKE3/ML-DSA-65/ML-KEM-768/XChaCha)";
    }
    return "Unknown Suite";
}

inline std::string suite_to_short_name(SuiteID s) {
    switch (s) {
        case SuiteID::SUITE_1_CLASSICAL: return "classical";
        case SuiteID::SUITE_2_MODERN:    return "modern";
        case SuiteID::SUITE_3_PURE_PQC:  return "pqc";
    }
    return "unknown";
}

inline constexpr SuiteID kDefaultSuite = SuiteID::SUITE_2_MODERN;

inline SuiteID suite_from_string(std::string_view name) {
    if (name == "1" || name == "classical" || name == "sec1" || name == "sec 1" || name == "SUITE_1_CLASSICAL" || name == "SUITE_1_CLASSICAL_FAST") return SuiteID::SUITE_1_CLASSICAL;
    if (name == "2" || name == "modern" || name == "sec2" || name == "sec 2" || name == "SUITE_2_MODERN" || name == "SUITE_2_MODERN_HIGH_SPEED" || name == "SUITE_2_MODERN_HYBRID") return SuiteID::SUITE_2_MODERN;
    if (name == "3" || name == "pqc" || name == "pure-pqc" || name == "sec3" || name == "sec 3" || name == "SUITE_3_PURE_PQC") return SuiteID::SUITE_3_PURE_PQC;
    return SuiteID::SUITE_2_MODERN; // Default is Suite 2 (Modern High-Speed: BLAKE3 + Ed25519 + X25519 + XChaCha20)
}

enum class Role : uint8_t {
    READ_ONLY  = 0x01, // 'r'
    WRITE_ONLY = 0x02, // 'w'
    READ_WRITE = 0x03  // 'rw'
};

inline std::string role_to_string(Role r) {
    switch (r) {
        case Role::READ_ONLY:  return "r";
        case Role::WRITE_ONLY: return "w";
        case Role::READ_WRITE: return "rw";
    }
    return "r";
}

inline Role role_from_string(std::string_view r) {
    if (r == "w") return Role::WRITE_ONLY;
    if (r == "rw") return Role::READ_WRITE;
    return Role::READ_ONLY;
}

enum class AuditStatus : uint8_t {
    UNKNOWN              = 0,
    CLEAN                = 1,
    AI_FLAGGED           = 2,
    STALE                = 3,
    USER_ALLOWED         = 4,
    RULE_BLOCKED         = 5,
    SMART_FILTER_FLAGGED = 6
};

inline std::string audit_status_to_string(AuditStatus s) {
    switch (s) {
        case AuditStatus::UNKNOWN:              return "UNKNOWN";
        case AuditStatus::CLEAN:                return "CLEAN";
        case AuditStatus::AI_FLAGGED:           return "AI_FLAGGED";
        case AuditStatus::SMART_FILTER_FLAGGED: return "SMART_FILTER_FLAGGED";
        case AuditStatus::STALE:                return "STALE";
        case AuditStatus::USER_ALLOWED:         return "USER_ALLOWED";
        case AuditStatus::RULE_BLOCKED:         return "RULE_BLOCKED";
    }
    return "UNKNOWN";
}

inline AuditStatus audit_status_from_string(std::string_view s) {
    if (s == "CLEAN") return AuditStatus::CLEAN;
    if (s == "AI_FLAGGED") return AuditStatus::AI_FLAGGED;
    if (s == "SMART_FILTER_FLAGGED") return AuditStatus::SMART_FILTER_FLAGGED;
    if (s == "STALE") return AuditStatus::STALE;
    if (s == "USER_ALLOWED") return AuditStatus::USER_ALLOWED;
    if (s == "RULE_BLOCKED") return AuditStatus::RULE_BLOCKED;
    return AuditStatus::UNKNOWN;
}

enum class FilterMode : uint8_t {
    PROTECTED       = 0, // Default: respect .gitignore & rules.conf
    INCLUDE_IGNORED = 1, // Ignore .gitignore (shares build/, node_modules/ if allowed by rules)
    NONE            = 2  // Raw/No-filter: shares files without gitignore (never bypasses .slug/.git or anti-traversal)
};

inline std::string filter_mode_to_string(FilterMode m) {
    switch (m) {
        case FilterMode::PROTECTED:       return "protected";
        case FilterMode::INCLUDE_IGNORED: return "include-ignored";
        case FilterMode::NONE:            return "none";
    }
    return "protected";
}

inline FilterMode filter_mode_from_string(std::string_view s) {
    if (s == "none" || s == "raw" || s == "no-filter" || s == "off") return FilterMode::NONE;
    if (s == "include-ignored" || s == "all" || s == "ignored") return FilterMode::INCLUDE_IGNORED;
    return FilterMode::PROTECTED;
}

// 5 Cấp độ lọc bảo mật dữ liệu (Cumulative Security Filter Levels)
enum class FilterLevel : uint8_t {
    LEVEL_0_RAW     = 0, // Mức 0: Không lọc / Chia sẻ tất cả (Tắt Rules, .gitignore, AI - Chỉ bảo vệ nội bộ .slug/)
    LEVEL_1_RULES   = 1, // Mức 1: Rules & Gitignore (Chỉ lọc .gitignore & rules.conf, không quét nội dung)
    LEVEL_2_REGEX   = 2, // Mức 2: Regex Secret Guard (Mức 1 + Quét mẫu định danh Private Key, AWS, GitHub, JWT, DB URL, .env) [Mặc định]
    LEVEL_3_ENTROPY = 3, // Mức 3: Shannon Entropy (Mức 2 + Đo entropy trên file mã nguồn, bỏ qua 100% binary/ảnh) [Khuyên Dùng]
    LEVEL_4_AI      = 4  // Mức 4: AI Model Scan (Mức 3 + Phân tích ngữ cảnh sâu bằng mô hình AI)
};

inline std::string filter_level_to_string(FilterLevel lvl) {
    switch (lvl) {
        case FilterLevel::LEVEL_0_RAW:     return "level0";
        case FilterLevel::LEVEL_1_RULES:   return "level1";
        case FilterLevel::LEVEL_2_REGEX:   return "level2";
        case FilterLevel::LEVEL_3_ENTROPY: return "level3";
        case FilterLevel::LEVEL_4_AI:      return "level4";
    }
    return "level2";
}

inline FilterLevel filter_level_from_string(std::string_view s) {
    if (s == "0" || s == "level0" || s == "raw" || s == "none" || s == "all") return FilterLevel::LEVEL_0_RAW;
    if (s == "1" || s == "level1" || s == "rules") return FilterLevel::LEVEL_1_RULES;
    if (s == "2" || s == "level2" || s == "regex") return FilterLevel::LEVEL_2_REGEX;
    if (s == "3" || s == "level3" || s == "entropy") return FilterLevel::LEVEL_3_ENTROPY;
    if (s == "4" || s == "level4" || s == "ai") return FilterLevel::LEVEL_4_AI;
    return FilterLevel::LEVEL_2_REGEX;
}

// Mô hình AI áp dụng cho Mức 4 (AI Model Provider for Level 4)
enum class AiModelProvider : uint8_t {
    OLLAMA = 0, // Ollama Local (DeepSeek-R1 / CodeLlama - Offline an toàn)
    OPENAI = 1, // OpenAI Cloud (GPT-4o / GPT-4o-mini)
    GEMINI = 2  // Google Gemini Cloud (Gemini 2.5 Flash)
};

inline std::string ai_model_to_string(AiModelProvider p) {
    switch (p) {
        case AiModelProvider::OLLAMA: return "ollama";
        case AiModelProvider::OPENAI: return "openai";
        case AiModelProvider::GEMINI: return "gemini";
    }
    return "ollama";
}

inline AiModelProvider ai_model_from_string(std::string_view s) {
    if (s == "openai" || s == "gpt" || s == "gpt-4o") return AiModelProvider::OPENAI;
    if (s == "gemini" || s == "google" || s == "gemini-2.5-flash") return AiModelProvider::GEMINI;
    return AiModelProvider::OLLAMA;
}

// Chế độ chia sẻ và kiểm toán bảo mật (Scan Policy)
enum class ScanPolicy : uint8_t {
    INSTANT = 0, // Mặc định: Chia sẻ ngay, cho phép tải trong khi quét nền, file FLAGGED bị chặn
    SECURE  = 1  // Nghiêm ngặt: Chia sẻ ngay, nhưng chỉ cho tải file đã xác minh CLEAN hoặc WHITELISTED
};

inline std::string scan_policy_to_string(ScanPolicy p) {
    switch (p) {
        case ScanPolicy::INSTANT: return "instant";
        case ScanPolicy::SECURE:  return "secure";
    }
    return "instant";
}

inline ScanPolicy scan_policy_from_string(std::string_view s) {
    if (s == "secure" || s == "strict" || s == "safe" || s == "sec") return ScanPolicy::SECURE;
    return ScanPolicy::INSTANT;
}

constexpr uint16_t kDefaultPort = 9443;
constexpr size_t kDefaultChunkSize = 64 * 1024; // 64 KiB logic chunk
constexpr size_t kXChaCha20Poly1305NonceSize = 24;
constexpr size_t kXChaCha20Poly1305TagSize = 16;
constexpr size_t kKeySize = 32;

} // namespace slug::core
