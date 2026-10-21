#include "src/core/vfs.hpp"
#include "src/platform/fs.hpp"
#include "src/crypto/blake3_wrapper.hpp"
#include "src/ai/scanner.hpp"
#include "src/core/utils.hpp"
#include <algorithm>
#include <fstream>

namespace slug::core {

namespace fs = std::filesystem;

SlugVFS::SlugVFS(fs::path server_root_path, bool enable_ai, FilterMode filter_mode)
    : enable_ai_(enable_ai),
      filter_mode_(filter_mode),
      policy_engine_(server_root_path, server_root_path / ".slug" / "rules.conf") {
    std::error_code ec;
    server_root_ = fs::canonical(server_root_path, ec);
    if (ec) {
        server_root_ = fs::absolute(server_root_path).lexically_normal();
    }
    if (enable_ai_) {
        fs::path idx_path = server_root_ / ".slug" / "index.db";
        audit_index_ = std::make_unique<ai::StatefulAuditIndex>(idx_path);
    }
}

std::string SlugVFS::normalize_virtual_path(std::string_view input) {
    std::string s(input);
    // Replace backslashes
    std::replace(s.begin(), s.end(), '\\', '/');

    // Strip whitespace
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(0, 1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();

    if (s.empty() || s == ".") return "/";

    // Deduplicate slashes
    std::string clean;
    clean.reserve(s.size() + 1);
    bool prev_slash = false;
    for (char c : s) {
        if (c == '/') {
            if (!prev_slash) {
                clean.push_back('/');
                prev_slash = true;
            }
        } else {
            clean.push_back(c);
            prev_slash = false;
        }
    }

    if (clean.empty() || clean.front() != '/') {
        clean.insert(clean.begin(), '/');
    }
    if (clean.size() > 1 && clean.back() == '/') {
        clean.pop_back();
    }
    return clean;
}

VfsResolveResult SlugVFS::resolve_and_jail(std::string_view virtual_path, Role role, bool write_intent) const {
    VfsResolveResult res;
    res.virtual_path = normalize_virtual_path(virtual_path);

    // 1. RBAC enforcement
    if (role == Role::WRITE_ONLY && !write_intent) {
        res.status = VfsStatus::ACCESS_DENIED;
        res.error_message = "Permission Denied: Write-Only role cannot read or list workspace files.";
        return res;
    }
    if (role == Role::READ_ONLY && write_intent) {
        res.status = VfsStatus::ACCESS_DENIED;
        res.error_message = "Permission Denied: Read-Only role cannot modify or write workspace files.";
        return res;
    }

    // 2. Anti-Traversal check on virtual path components
    std::string rel = (res.virtual_path == "/") ? "" : res.virtual_path.substr(1);
    fs::path test_p = platform::PathUtils::u8_to_path(rel);
    for (const auto& part : test_p) {
        if (part == ".." || part == "") {
            res.status = VfsStatus::PATH_TRAVERSAL;
            res.error_message = "Path traversal attempted (" + std::string(virtual_path) + ")";
            return res;
        }
    }

    // 3. Prevent direct tampering with internal .slug configuration
    if (!rel.empty() && (rel == ".slug" || rel.rfind(".slug/", 0) == 0)) {
        res.status = VfsStatus::ACCESS_DENIED;
        res.error_message = "Access to internal workspace metadata directory is protected.";
        return res;
    }

    // 4. Resolve path against ServerRootPath safely
    fs::path canonical_target;
    if (rel.empty()) {
        canonical_target = server_root_;
    } else {
        auto safe_p = platform::PathUtils::resolve_safe_path(server_root_, rel);
        if (!safe_p) {
            res.status = VfsStatus::PATH_TRAVERSAL;
            res.error_message = "Resolved path escaped workspace root jail.";
            return res;
        }
        canonical_target = *safe_p;
    }

    // 5. Policy filter & AI check
    if (!rel.empty() && filter_mode_ != FilterMode::NONE) {
        std::error_code ec;
        bool is_dir = fs::is_directory(canonical_target, ec);
        bool ignore_gi = (filter_mode_ == FilterMode::INCLUDE_IGNORED);
        auto dec = policy_engine_.evaluate(rel, is_dir, {}, ignore_gi);
        if (!dec.is_allowed) {
            res.status = VfsStatus::FILTERED;
            res.error_message = "File filtered by rule: " + dec.reason;
            return res;
        }
        if (enable_ai_ && audit_index_) {
            if (audit_index_->is_flagged(rel)) {
                res.status = VfsStatus::FILTERED;
                res.error_message = "File blocked by AI Secret Guard";
                return res;
            }
        }
    }

    res.real_path = canonical_target;
    res.status = VfsStatus::OK;
    return res;
}

std::pair<VfsStatus, std::vector<VfsEntry>> SlugVFS::list_directory(std::string_view virtual_dir, Role role) const {
    auto resolved = resolve_and_jail(virtual_dir, role, false);
    if (!resolved.is_ok()) {
        return {resolved.status, {}};
    }

    std::error_code ec;
    if (!fs::exists(resolved.real_path, ec) || !fs::is_directory(resolved.real_path, ec)) {
        return {VfsStatus::NOT_DIRECTORY, {}};
    }

    std::vector<VfsEntry> entries;
    for (const auto& item : fs::directory_iterator(resolved.real_path, ec)) {
        std::string fname = platform::PathUtils::path_to_u8(item.path().filename());
        if (fname == ".slug" || fname == ".git") continue;

        fs::path rel_p = fs::relative(item.path(), server_root_, ec);
        std::string proto_rel = platform::PathUtils::to_protocol_path(rel_p);
        std::string vpath = "/" + proto_rel;
        bool is_dir = item.is_directory(ec);

        bool is_blocked = false;
        std::string block_reason;

        // Filter evaluation
        if (filter_mode_ != FilterMode::NONE) {
            bool ignore_gi = (filter_mode_ == FilterMode::INCLUDE_IGNORED);
            auto dec = policy_engine_.evaluate(proto_rel, is_dir, {}, ignore_gi);
            if (!dec.is_allowed) {
                is_blocked = true;
                block_reason = dec.reason.empty() ? "Filtered by rule / gitignore" : dec.reason;
            } else if (enable_ai_ && audit_index_ && !is_dir) {
                if (audit_index_->is_flagged(proto_rel)) {
                    is_blocked = true;
                    block_reason = "Flagged by AI Secret Guard";
                }
            }
        }

        VfsEntry e;
        e.name = fname;
        e.virtual_path = vpath;
        e.is_dir = is_dir;
        e.size = is_dir ? 0 : item.file_size(ec);
        e.is_blocked = is_blocked;
        e.block_reason = std::move(block_reason);

        if (!is_dir && !e.is_blocked && e.size > 0 && e.size < 64 * 1024 * 1024) {
            auto data = platform::PathUtils::read_binary_file(item.path());
            if (data) {
                e.blake3_hash = crypto::Blake3::hash_hex(*data);
            }
        }
        entries.push_back(std::move(e));
    }

    std::sort(entries.begin(), entries.end(), [](const VfsEntry& a, const VfsEntry& b) {
        if (a.is_dir != b.is_dir) return a.is_dir > b.is_dir;
        return a.name < b.name;
    });

    return {VfsStatus::OK, entries};
}

std::pair<VfsStatus, std::vector<uint8_t>> SlugVFS::read_file(std::string_view virtual_path, Role role) const {
    auto resolved = resolve_and_jail(virtual_path, role, false);
    if (!resolved.is_ok()) {
        return {resolved.status, {}};
    }

    std::error_code ec;
    if (!fs::exists(resolved.real_path, ec)) {
        return {VfsStatus::NOT_FOUND, {}};
    }
    if (fs::is_directory(resolved.real_path, ec)) {
        return {VfsStatus::IS_DIRECTORY, {}};
    }

    auto data = platform::PathUtils::read_binary_file(resolved.real_path);
    if (!data) {
        return {VfsStatus::IO_ERROR, {}};
    }

    // Evaluate content-level rules on read file data
    if (filter_mode_ != FilterMode::NONE) {
        std::string proto = (resolved.virtual_path == "/") ? "" : resolved.virtual_path.substr(1);
        if (enable_ai_ && audit_index_) {
            if (audit_index_->is_flagged(proto)) {
                return {VfsStatus::FILTERED, {}};
            }
        }
        // Only evaluate content text rules on scannable text/code files (never on binary DLL, EXE, etc.)
        std::string_view text_view;
        if (ai::AiScanner::is_scannable_file(resolved.real_path)) {
            text_view = std::string_view(reinterpret_cast<const char*>(data->data()), data->size());
        }
        bool ignore_gi = (filter_mode_ == FilterMode::INCLUDE_IGNORED);
        auto dec = policy_engine_.evaluate(proto, false, text_view, ignore_gi);
        if (!dec.is_allowed) {
            return {VfsStatus::FILTERED, {}};
        }
    }

    return {VfsStatus::OK, std::move(*data)};
}

VfsStatus SlugVFS::write_file(std::string_view virtual_path, std::span<const uint8_t> data, Role role, bool overwrite) {
    auto resolved = resolve_and_jail(virtual_path, role, true);
    if (!resolved.is_ok()) {
        return resolved.status;
    }

    std::error_code ec;
    if (!overwrite && fs::exists(resolved.real_path, ec)) {
        return VfsStatus::ACCESS_DENIED;
    }

    // Evaluate content-level rules and AI Secret Guard on incoming file data
    if (filter_mode_ != FilterMode::NONE) {
        std::string_view text_view;
        if (ai::AiScanner::is_scannable_file(resolved.real_path)) {
            text_view = std::string_view(reinterpret_cast<const char*>(data.data()), data.size());
        }
        bool ignore_gi = (filter_mode_ == FilterMode::INCLUDE_IGNORED);
        std::string proto = (resolved.virtual_path == "/") ? "" : resolved.virtual_path.substr(1);
        auto dec = policy_engine_.evaluate(proto, false, text_view, ignore_gi);
        if (!dec.is_allowed) {
            return VfsStatus::FILTERED;
        }

        if (enable_ai_ && ai::AiScanner::is_scannable_file(resolved.real_path)) {
            ai::AiScanner scanner;
            std::string text(data.begin(), data.end());
            auto finding = scanner.scan_content(proto, text, false);
            if (finding.has_secret) {
                if (audit_index_) {
                    ai::AuditIndexEntry idx_entry;
                    idx_entry.file_path = proto;
                    idx_entry.blake3_hash = crypto::Blake3::hash_hex(data);
                    idx_entry.scanned_at = core::Utils::current_timestamp();
                    idx_entry.status = (finding.detector == "AI Guard") ? core::AuditStatus::AI_FLAGGED : core::AuditStatus::SMART_FILTER_FLAGGED;
                    idx_entry.line_number = finding.line_number;
                    idx_entry.reason = finding.reason;
                    audit_index_->update_entry(idx_entry);
                }
                return VfsStatus::FILTERED;
            }
        }
    }

    platform::PathUtils::ensure_directory(resolved.real_path.parent_path());
    std::vector<uint8_t> copy(data.begin(), data.end());
    if (!platform::PathUtils::write_binary_file_atomic(resolved.real_path, copy)) {
        return VfsStatus::IO_ERROR;
    }
    return VfsStatus::OK;
}

} // namespace slug::core
