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

inline constexpr SuiteID kDefaultSuite = SuiteID::SUITE_1_CLASSICAL;

inline SuiteID suite_from_string(std::string_view name) {
    if (name == "1" || name == "classical" || name == "sec1" || name == "sec 1") return SuiteID::SUITE_1_CLASSICAL;
    if (name == "2" || name == "modern" || name == "sec2" || name == "sec 2") return SuiteID::SUITE_2_MODERN;
    if (name == "3" || name == "pqc" || name == "pure-pqc" || name == "sec3" || name == "sec 3") return SuiteID::SUITE_3_PURE_PQC;
    return SuiteID::SUITE_1_CLASSICAL; // Default is Suite 1 (Classical Fast)
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
    PROTECTED       = 0, // Default: .gitignore + rules.conf + secret detection + quarantine
    INCLUDE_IGNORED = 1, // Ignore .gitignore (shares build/, node_modules/), but still enforces rules.conf & secret/AI quarantine
    NONE            = 2  // Raw/No-filter: shares all files without gitignore or content quarantine (except internal .slug/.git metadata & anti-traversal)
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

constexpr uint16_t kDefaultPort = 9443;
constexpr size_t kDefaultChunkSize = 64 * 1024; // 64 KiB logic chunk
constexpr size_t kXChaCha20Poly1305NonceSize = 24;
constexpr size_t kXChaCha20Poly1305TagSize = 16;
constexpr size_t kKeySize = 32;

} // namespace slug::core
