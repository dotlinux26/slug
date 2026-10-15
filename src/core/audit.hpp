#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <filesystem>

namespace slug::core {

struct AuditEvent {
    uint64_t timestamp{0};
    std::string actor;
    std::string action;
    std::string path;
    std::string reason;
    bool success{true};
};

class AuditLogger {
public:
    explicit AuditLogger(std::filesystem::path log_path = {});

    void log(const std::string& actor, const std::string& action,
             const std::string& path, const std::string& reason, bool success = true);

    std::vector<AuditEvent> read_recent_events(size_t limit = 50) const;

private:
    std::filesystem::path log_path_;
    mutable std::mutex mutex_;
};

} // namespace slug::core
