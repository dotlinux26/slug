#pragma once

#include "src/core/types.hpp"
#include "src/policy/filter.hpp"
#include "src/ai/stateful_audit.hpp"
#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <span>
#include <memory>

namespace slug::core {

enum class VfsStatus {
    OK,
    ACCESS_DENIED,
    PATH_TRAVERSAL,
    NOT_FOUND,
    FILTERED,
    IS_DIRECTORY,
    NOT_DIRECTORY,
    IO_ERROR
};

inline std::string vfs_status_to_string(VfsStatus s) {
    switch (s) {
        case VfsStatus::OK: return "OK";
        case VfsStatus::ACCESS_DENIED: return "Access Denied";
        case VfsStatus::PATH_TRAVERSAL: return "Path Traversal Rejected";
        case VfsStatus::NOT_FOUND: return "Not Found";
        case VfsStatus::FILTERED: return "Filtered by Policy / AI Guard";
        case VfsStatus::IS_DIRECTORY: return "Target is a directory";
        case VfsStatus::NOT_DIRECTORY: return "Target is not a directory";
        case VfsStatus::IO_ERROR: return "I/O Error";
    }
    return "Unknown Error";
}

struct VfsEntry {
    std::string name;
    std::string virtual_path; // e.g. "/src/main.cpp"
    bool is_dir{false};
    uint64_t size{0};
    std::string blake3_hash;
};

struct VfsResolveResult {
    VfsStatus status{VfsStatus::OK};
    std::filesystem::path real_path;
    std::string virtual_path;
    std::string error_message;

    bool is_ok() const { return status == VfsStatus::OK; }
};

class SlugVFS {
public:
    explicit SlugVFS(std::filesystem::path server_root_path,
                     bool enable_ai = false,
                     FilterMode filter_mode = FilterMode::PROTECTED);

    const std::filesystem::path& server_root() const { return server_root_; }

    FilterMode filter_mode() const { return filter_mode_; }
    void set_filter_mode(FilterMode mode) { filter_mode_ = mode; }

    // Converts any input path (e.g. "src/main.cpp", "/src/main.cpp", "\\src\\main.cpp")
    // to a standardized virtual path starting with "/"
    static std::string normalize_virtual_path(std::string_view input);

    // Resolves and jails a virtual path inside server_root_, checking RBAC role and directory traversal
    VfsResolveResult resolve_and_jail(std::string_view virtual_path, Role role, bool write_intent = false) const;

    // Lists directory safely, applying policy filters and RBAC
    std::pair<VfsStatus, std::vector<VfsEntry>> list_directory(std::string_view virtual_dir, Role role) const;

    // Reads binary content of a jailed file
    std::pair<VfsStatus, std::vector<uint8_t>> read_file(std::string_view virtual_path, Role role) const;

    // Writes binary content to a jailed file
    VfsStatus write_file(std::string_view virtual_path, std::span<const uint8_t> data, Role role, bool overwrite = true);

    policy::PolicyEngine& policy_engine() { return policy_engine_; }
    const policy::PolicyEngine& policy_engine() const { return policy_engine_; }

private:
    std::filesystem::path server_root_;
    bool enable_ai_{false};
    FilterMode filter_mode_{FilterMode::PROTECTED};
    policy::PolicyEngine policy_engine_;
    std::unique_ptr<ai::StatefulAuditIndex> audit_index_;
};

} // namespace slug::core
