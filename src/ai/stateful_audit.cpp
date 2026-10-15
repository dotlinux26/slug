#include "src/ai/stateful_audit.hpp"
#include "src/core/utils.hpp"
#include "src/platform/fs.hpp"
#include "third_party/json/json.hpp"

namespace slug::ai {

using json = nlohmann::json;

StatefulAuditIndex::StatefulAuditIndex(std::filesystem::path index_file)
    : index_file_(std::move(index_file)) {
    if (!index_file_.empty()) {
        load();
    }
}

bool StatefulAuditIndex::load() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();

    if (index_file_.empty() || !std::filesystem::exists(index_file_)) {
        return false;
    }

    auto content = platform::PathUtils::read_text_file(index_file_);
    if (!content) return false;

    try {
        auto j = json::parse(*content);
        if (j.contains("entries") && j["entries"].is_array()) {
            for (const auto& item : j["entries"]) {
                AuditIndexEntry e;
                e.file_path = item.value("file_path", "");
                e.blake3_hash = item.value("blake3_hash", "");
                e.status = core::audit_status_from_string(item.value("status", "UNKNOWN"));
                e.line_number = item.value("line_number", 0);
                e.reason = item.value("reason", "");
                e.scanned_at = item.value("scanned_at", 0ULL);
                e.decision_actor = item.value("decision_actor", "");
                e.decision_reason = item.value("decision_reason", "");

                if (!e.file_path.empty()) {
                    entries_[e.file_path] = e;
                }
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool StatefulAuditIndex::save() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index_file_.empty()) return false;

    json j;
    j["entries"] = json::array();
    for (const auto& [_, e] : entries_) {
        json item;
        item["file_path"] = e.file_path;
        item["blake3_hash"] = e.blake3_hash;
        item["status"] = core::audit_status_to_string(e.status);
        item["line_number"] = e.line_number;
        item["reason"] = e.reason;
        item["scanned_at"] = e.scanned_at;
        item["decision_actor"] = e.decision_actor;
        item["decision_reason"] = e.decision_reason;
        j["entries"].push_back(item);
    }

    return platform::PathUtils::write_text_file_atomic(index_file_, j.dump(2));
}

core::AuditStatus StatefulAuditIndex::check_cached_status(const std::string& file_path, const std::string& current_blake3_hash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(file_path);
    if (it == entries_.end()) {
        return core::AuditStatus::UNKNOWN;
    }

    const auto& entry = it->second;
    if (entry.blake3_hash == current_blake3_hash) {
        // Zero-Cost Cache Hit: Hash is unchanged!
        return entry.status;
    }

    // Content has changed! State is STALE and requires recheck!
    return core::AuditStatus::STALE;
}

void StatefulAuditIndex::update_entry(const AuditIndexEntry& entry) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_[entry.file_path] = entry;
    }
    save();
}

bool StatefulAuditIndex::allow_file(const std::string& file_path, const std::string& reason, const std::string& actor) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = entries_.find(file_path);
        if (it != entries_.end()) {
            it->second.status = core::AuditStatus::USER_ALLOWED;
            it->second.decision_actor = actor;
            it->second.decision_reason = reason;
        } else {
            AuditIndexEntry e;
            e.file_path = file_path;
            e.status = core::AuditStatus::USER_ALLOWED;
            e.decision_actor = actor;
            e.decision_reason = reason;
            e.scanned_at = core::Utils::current_timestamp();
            entries_[file_path] = e;
        }
    }
    return save();
}

bool StatefulAuditIndex::remove_entry(const std::string& file_path) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = entries_.find(file_path);
        if (it == entries_.end()) return false;
        entries_.erase(it);
    }
    return save();
}

std::optional<AuditIndexEntry> StatefulAuditIndex::get_entry(const std::string& file_path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(file_path);
    if (it != entries_.end()) return it->second;
    return std::nullopt;
}

bool StatefulAuditIndex::is_flagged(const std::string& file_path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(file_path);
    if (it == entries_.end()) return false;
    return (it->second.status == core::AuditStatus::AI_FLAGGED || it->second.status == core::AuditStatus::RULE_BLOCKED);
}

std::vector<AuditIndexEntry> StatefulAuditIndex::list_flagged_or_all(bool only_flagged) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AuditIndexEntry> res;
    for (const auto& [_, e] : entries_) {
        if (!only_flagged || e.status == core::AuditStatus::AI_FLAGGED || e.status == core::AuditStatus::STALE) {
            res.push_back(e);
        }
    }
    return res;
}

} // namespace slug::ai
