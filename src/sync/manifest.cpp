#include "src/sync/manifest.hpp"
#include "src/policy/filter.hpp"
#include "src/ai/stateful_audit.hpp"
#include "src/ai/scanner.hpp"
#include "src/crypto/blake3_wrapper.hpp"
#include "src/core/utils.hpp"
#include "src/platform/fs.hpp"
#include "third_party/json/json.hpp"
#include <algorithm>
#include <iostream>
#include <unordered_map>
#include <mutex>

namespace slug::sync {

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {
struct CachedFileState {
    uint64_t mtime{0};
    uint64_t size{0};
    std::string hash;
    std::vector<ChunkInfo> chunks;
};
static std::mutex g_state_cache_mtx;
static std::unordered_map<std::string, CachedFileState> g_state_cache;
}

void WorkspaceManifest::compute_root_hash() {
    std::string aggregate;
    // Sort files by relative_path to ensure canonical ordering
    std::vector<ManifestFileEntry> sorted_files = files;
    std::sort(sorted_files.begin(), sorted_files.end(), [](const auto& a, const auto& b) {
        return a.relative_path < b.relative_path;
    });

    for (const auto& f : sorted_files) {
        aggregate += f.relative_path + ":" + f.file_blake3_hash + "\n";
    }
    root_hash = crypto::Blake3::hash_hex(aggregate);
}

std::string WorkspaceManifest::to_json() const {
    json j;
    j["protocol_version"] = protocol_version;
    j["suite_id"] = suite_id;
    j["epoch"] = epoch;
    j["timestamp"] = timestamp;
    j["root_hash"] = root_hash;

    j["files"] = json::array();
    for (const auto& f : files) {
        json item;
        item["relative_path"] = f.relative_path;
        item["size"] = f.size;
        item["mtime"] = f.mtime;
        item["file_blake3_hash"] = f.file_blake3_hash;

        json chunks_arr = json::array();
        for (const auto& c : f.chunks) {
            json chunk_item;
            chunk_item["index"] = c.index;
            chunk_item["offset"] = c.offset;
            chunk_item["size"] = c.size;
            chunk_item["blake3_hash"] = c.blake3_hash;
            chunks_arr.push_back(chunk_item);
        }
        item["chunks"] = chunks_arr;
        j["files"].push_back(item);
    }

    j["skipped"] = json::array();
    for (const auto& s : skipped) {
        json item;
        item["relative_path"] = s.relative_path;
        item["reason"] = s.reason;
        item["status"] = s.status;
        j["skipped"].push_back(item);
    }

    return j.dump(2);
}

std::optional<WorkspaceManifest> WorkspaceManifest::from_json(const std::string& json_str) {
    try {
        auto j = json::parse(json_str);
        WorkspaceManifest m;
        m.protocol_version = j.value("protocol_version", 1U);
        m.suite_id = j.value("suite_id", static_cast<uint8_t>(3));
        m.epoch = j.value("epoch", 1ULL);
        m.timestamp = j.value("timestamp", 0ULL);
        m.root_hash = j.value("root_hash", "");

        if (j.contains("files") && j["files"].is_array()) {
            for (const auto& f : j["files"]) {
                ManifestFileEntry fe;
                fe.relative_path = f.value("relative_path", "");
                fe.size = f.value("size", 0ULL);
                fe.mtime = f.value("mtime", 0ULL);
                fe.file_blake3_hash = f.value("file_blake3_hash", "");
                if (f.contains("chunks") && f["chunks"].is_array()) {
                    for (const auto& c : f["chunks"]) {
                        ChunkInfo ci;
                        ci.index = c.value("index", 0U);
                        ci.offset = c.value("offset", 0ULL);
                        ci.size = c.value("size", 0U);
                        ci.blake3_hash = c.value("blake3_hash", "");
                        fe.chunks.push_back(ci);
                    }
                }
                m.files.push_back(fe);
            }
        }

        if (j.contains("skipped") && j["skipped"].is_array()) {
            for (const auto& s : j["skipped"]) {
                ManifestSkippedEntry se;
                se.relative_path = s.value("relative_path", "");
                se.reason = s.value("reason", "");
                se.status = s.value("status", "");
                m.skipped.push_back(se);
            }
        }
        return m;
    } catch (...) {
        return std::nullopt;
    }
}

WorkspaceManifest ManifestBuilder::build(
    const fs::path& workspace_root,
    uint64_t epoch,
    uint8_t suite_id,
    bool enable_ai,
    core::FilterMode filter_mode) {

    WorkspaceManifest manifest;
    manifest.epoch = epoch;
    manifest.suite_id = suite_id;
    manifest.timestamp = core::Utils::current_timestamp();

    fs::path rules_file = workspace_root / ".slug" / "rules.conf";
    fs::path index_file = workspace_root / ".slug" / "index.db";

    policy::PolicyEngine policy_engine(workspace_root, rules_file);
    ai::StatefulAuditIndex audit_index(index_file);
    ai::AiScanner scanner;

    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(workspace_root, fs::directory_options::skip_permission_denied, ec), end = fs::recursive_directory_iterator();
         it != end; ++it) {
        if (ec) { ec.clear(); continue; }

        fs::path p = it->path();
        fs::path rel = p.lexically_relative(workspace_root);
        std::string filename = p.filename().string();
        std::string lower = filename;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (it->is_directory(ec)) {
            if (lower == ".git" || lower == ".slug" || lower == "node_modules" ||
                lower == "_internal" || lower == "venv" || lower == ".venv" || lower == "env" ||
                lower == "__pycache__" || lower == "site-packages" || lower == "vendor" ||
                lower == "build" || lower == "build_win" || lower == "target" || lower == "dist" ||
                lower == "out" || lower == "bin" || lower == "obj" ||
                lower == ".idea" || lower == ".vscode" ||
                platform::PathUtils::is_internal_slug_path(rel)) {
                it.disable_recursion_pending();
            }
            continue;
        }

        if (!it->is_regular_file(ec)) continue;

        std::string proto_path = platform::PathUtils::to_protocol_path(rel);
        const auto& entry = *it;

        // Mandatory isolation: .slug and .git metadata are strictly protected ALWAYS
        if (platform::PathUtils::is_internal_slug_path(rel)) {
            manifest.skipped.push_back({proto_path, "Internal Slug or Git metadata is strictly protected", "MANDATORY_INTERNAL"});
            continue;
        }

        // Step 1: Policy evaluation (Rules + Gitignore)
        if (filter_mode != core::FilterMode::NONE) {
            bool ignore_gi = (filter_mode == core::FilterMode::INCLUDE_IGNORED);
            auto decision = policy_engine.evaluate(rel, false, {}, ignore_gi);
            if (!decision.is_allowed) {
                manifest.skipped.push_back({proto_path, decision.reason, "RULE_OR_GITIGNORE_BLOCKED"});
                continue;
            }
        }

        // Fast metadata check: avoid reading disk if file is unchanged
        uint64_t cur_sz = 0;
        try { cur_sz = fs::file_size(entry.path(), ec); } catch (...) {}
        uint64_t cur_mtime = 0;
        try { cur_mtime = static_cast<uint64_t>(fs::last_write_time(entry.path(), ec).time_since_epoch().count()); } catch (...) {}

        std::string current_hash;
        std::vector<ChunkInfo> cached_chunks;
        bool cache_hit = false;
        {
            std::lock_guard<std::mutex> lk(g_state_cache_mtx);
            auto it_c = g_state_cache.find(proto_path);
            if (it_c != g_state_cache.end() && it_c->second.mtime == cur_mtime && it_c->second.size == cur_sz && !it_c->second.hash.empty()) {
                current_hash = it_c->second.hash;
                cached_chunks = it_c->second.chunks;
                cache_hit = true;
            }
        }

        std::optional<std::vector<uint8_t>> file_data;
        if (!cache_hit) {
            file_data = platform::PathUtils::read_binary_file(entry.path());
            if (!file_data) {
                manifest.skipped.push_back({proto_path, "Failed to read file", "IO_ERROR"});
                continue;
            }
            current_hash = crypto::Blake3::hash_hex(*file_data);
        }

        // Step 2: Stateful AI & Smart Filter Audit evaluation (only active when enable_ai is true and filter_mode != NONE)
        if (enable_ai && filter_mode != core::FilterMode::NONE) {
            core::AuditStatus cached_status = audit_index.check_cached_status(proto_path, current_hash);

            if (cached_status == core::AuditStatus::AI_FLAGGED) {
                auto e = audit_index.get_entry(proto_path);
                std::string r = e ? e->reason : "AI Guard Flagged";
                manifest.skipped.push_back({proto_path, r, "AI_FLAGGED"});
                continue;
            }

            if (cached_status == core::AuditStatus::SMART_FILTER_FLAGGED) {
                auto e = audit_index.get_entry(proto_path);
                std::string r = e ? e->reason : "Smart Regex Flagged";
                manifest.skipped.push_back({proto_path, r, "SMART_FILTER_FLAGGED"});
                continue;
            }

            if (cached_status == core::AuditStatus::RULE_BLOCKED) {
                auto e = audit_index.get_entry(proto_path);
                std::string r = e ? e->reason : "Chặn thủ công (Manual Guard)";
                manifest.skipped.push_back({proto_path, r, "MANUAL_BLOCKED"});
                continue;
            }

            if (cached_status == core::AuditStatus::USER_ALLOWED) {
                // Whitelisted by user override - Always permitted!
            } else if (cached_status == core::AuditStatus::UNKNOWN || cached_status == core::AuditStatus::STALE) {
                if (!file_data) {
                    file_data = platform::PathUtils::read_binary_file(entry.path());
                }
                if (file_data && ai::AiScanner::is_scannable_file(entry.path())) {
                    std::string text(file_data->begin(), file_data->end());
                    auto finding = scanner.scan_content(proto_path, text, false);

                    ai::AuditIndexEntry idx_entry;
                    idx_entry.file_path = proto_path;
                    idx_entry.blake3_hash = current_hash;
                    idx_entry.scanned_at = core::Utils::current_timestamp();

                    if (finding.has_secret) {
                        bool is_ai = (finding.detector == "AI Guard");
                        idx_entry.status = is_ai ? core::AuditStatus::AI_FLAGGED : core::AuditStatus::SMART_FILTER_FLAGGED;
                        idx_entry.line_number = finding.line_number;
                        idx_entry.reason = finding.reason;
                        audit_index.update_entry(idx_entry);

                        std::string tag = is_ai ? "AI_FLAGGED" : "SMART_FILTER_FLAGGED";
                        manifest.skipped.push_back({proto_path, finding.reason + " (Line " + std::to_string(finding.line_number) + ")", tag});
                        continue;
                    } else {
                        idx_entry.status = core::AuditStatus::CLEAN;
                        idx_entry.reason = "Clean";
                        audit_index.update_entry(idx_entry);
                    }
                }
            }
        }

        // File is allowed: chunk it (or use cached chunks) and add to manifest
        ManifestFileEntry fe;
        fe.relative_path = proto_path;
        fe.size = cur_sz;
        fe.mtime = cur_mtime;
        fe.file_blake3_hash = current_hash;
        if (cache_hit && !cached_chunks.empty()) {
            fe.chunks = std::move(cached_chunks);
        } else {
            if (!file_data) {
                file_data = platform::PathUtils::read_binary_file(entry.path());
            }
            if (file_data) {
                fe.chunks = Chunker::chunk_buffer(*file_data);
                std::lock_guard<std::mutex> lk(g_state_cache_mtx);
                g_state_cache[proto_path] = {cur_mtime, cur_sz, current_hash, fe.chunks};
            }
        }

        manifest.files.push_back(std::move(fe));
    }

    manifest.compute_root_hash();
    return manifest;
}

} // namespace slug::sync
