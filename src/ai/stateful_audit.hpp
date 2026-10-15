#pragma once

#include "src/core/types.hpp"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <filesystem>
#include <optional>

namespace slug::ai {

struct AuditIndexEntry {
    std::string file_path;
    std::string blake3_hash;
    core::AuditStatus status{core::AuditStatus::UNKNOWN};
    int line_number{0};
    std::string reason;
    uint64_t scanned_at{0};
    std::string decision_actor;
    std::string decision_reason;
};

class StatefulAuditIndex {
public:
    explicit StatefulAuditIndex(std::filesystem::path index_file = {});

    bool load();
    bool save() const;

    // Checks current hash against index
    // Returns cached status if hash matches, or STALE/UNKNOWN if hash changed
    core::AuditStatus check_cached_status(const std::string& file_path, const std::string& current_blake3_hash) const;

    void update_entry(const AuditIndexEntry& entry);
    bool allow_file(const std::string& file_path, const std::string& reason, const std::string& actor = "user");
    bool remove_entry(const std::string& file_path);

    std::optional<AuditIndexEntry> get_entry(const std::string& file_path) const;
    bool is_flagged(const std::string& file_path) const;
    std::vector<AuditIndexEntry> list_flagged_or_all(bool only_flagged = false) const;

private:
    std::filesystem::path index_file_;
    mutable std::mutex mutex_;
    std::map<std::string, AuditIndexEntry> entries_;
};

} // namespace slug::ai
