#include "src/core/audit.hpp"
#include "src/core/utils.hpp"
#include "src/platform/fs.hpp"
#include "third_party/json/json.hpp"
#include <fstream>

namespace slug::core {

using json = nlohmann::json;

AuditLogger::AuditLogger(std::filesystem::path log_path)
    : log_path_(std::move(log_path)) {}

void AuditLogger::log(const std::string& actor, const std::string& action,
                      const std::string& path, const std::string& reason, bool success) {
    if (log_path_.empty()) return;

    std::lock_guard<std::mutex> lock(mutex_);
    platform::PathUtils::ensure_directory(log_path_.parent_path());

    json entry;
    entry["timestamp"] = Utils::current_timestamp();
    entry["actor"] = actor;
    entry["action"] = action;
    entry["path"] = path;
    entry["reason"] = reason;
    entry["success"] = success;

    std::ofstream out(log_path_, std::ios::app);
    if (out.is_open()) {
        out << entry.dump() << "\n";
    }
}

std::vector<AuditEvent> AuditLogger::read_recent_events(size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AuditEvent> events;
    if (log_path_.empty() || !std::filesystem::exists(log_path_)) {
        return events;
    }

    std::ifstream in(log_path_);
    if (!in.is_open()) return events;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        try {
            auto j = json::parse(line);
            AuditEvent ev;
            ev.timestamp = j.value("timestamp", 0ULL);
            ev.actor = j.value("actor", "");
            ev.action = j.value("action", "");
            ev.path = j.value("path", "");
            ev.reason = j.value("reason", "");
            ev.success = j.value("success", true);
            events.push_back(ev);
        } catch (...) {}
    }

    if (events.size() > limit) {
        events.erase(events.begin(), events.begin() + (events.size() - limit));
    }
    return events;
}

} // namespace slug::core
