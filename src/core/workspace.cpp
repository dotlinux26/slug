#include "src/core/workspace.hpp"
#include "src/platform/fs.hpp"
#include "src/core/utils.hpp"
#include "src/sync/manifest.hpp"
#include "third_party/json/json.hpp"
#include <iostream>
#include <cstdlib>

#if defined(SLUG_PLATFORM_POSIX)
#include <signal.h>
#endif

namespace slug::core {

namespace fs = std::filesystem;
using json = nlohmann::json;

WorkspaceManager& WorkspaceManager::instance() {
    static WorkspaceManager mgr;
    return mgr;
}

fs::path WorkspaceManager::registry_file_path() {
    const char* home = std::getenv("HOME");
    if (!home) home = std::getenv("USERPROFILE");
    if (home) {
        fs::path p = fs::path(home) / ".slug" / "registry.json";
        platform::PathUtils::ensure_directory(p.parent_path());
        return p;
    }
    return fs::temp_directory_path() / ".slug_registry.json";
}

static std::vector<WorkspaceInfo> load_registry_unlocked(const fs::path& p) {
    if (!fs::exists(p)) return {};

    auto text = platform::PathUtils::read_text_file(p);
    if (!text) return {};

    std::vector<WorkspaceInfo> list;
    try {
        auto j = json::parse(*text);
        if (j.is_array()) {
            for (const auto& item : j) {
                WorkspaceInfo wi;
                wi.port = item.value("port", static_cast<uint16_t>(0));
                wi.path = fs::path(item.value("path", ""));
                wi.suite = suite_from_string(item.value("suite", "3"));
                wi.ai_enabled = item.value("ai_enabled", false);
                wi.ttl_seconds = item.value("ttl_seconds", 86400ULL);
                wi.pid = item.value("pid", 0U);
                list.push_back(wi);
            }
        }
    } catch (...) {}
    return list;
}

std::vector<WorkspaceInfo> WorkspaceManager::load_registry() {
    fs::path p = registry_file_path();
    FileLockGuard lock(p.string());
    return load_registry_unlocked(p);
}

void WorkspaceManager::update_registry(const WorkspaceInfo& info, bool remove) {
    fs::path p = registry_file_path();
    FileLockGuard lock(p.string());
    auto list = load_registry_unlocked(p);
    std::vector<WorkspaceInfo> updated;

    for (const auto& item : list) {
        if (item.port != info.port) {
            updated.push_back(item);
        }
    }
    if (!remove) {
        updated.push_back(info);
    }

    json j = json::array();
    for (const auto& item : updated) {
        json obj;
        obj["port"] = item.port;
        obj["path"] = item.path.string();
        obj["suite"] = suite_to_short_name(item.suite);
        obj["ai_enabled"] = item.ai_enabled;
        obj["ttl_seconds"] = item.ttl_seconds;
        obj["pid"] = item.pid;
        j.push_back(obj);
    }

    platform::PathUtils::write_text_file_atomic(registry_file_path(), j.dump(2));
}

bool WorkspaceManager::add_workspace(const fs::path& folder_path,
                                    uint16_t port,
                                    SuiteID suite,
                                    uint64_t ttl_seconds,
                                    bool enable_ai) {

    std::error_code ec;
    fs::path canonical_path = fs::canonical(folder_path, ec);
    if (ec) {
        canonical_path = fs::absolute(folder_path).lexically_normal();
    }
    if (!fs::exists(canonical_path) || !fs::is_directory(canonical_path)) {
        std::cerr << "Error: Target folder does not exist or is not a directory: " << folder_path << std::endl;
        return false;
    }

    // Initialize .slug/ workspace directory
    fs::path slug_dir = canonical_path / ".slug";
    platform::PathUtils::ensure_directory(slug_dir);

    // Default rules.conf
    fs::path rules_file = slug_dir / "rules.conf";
    if (!fs::exists(rules_file)) {
        std::string def_rules =
            "# Default Slug Rules (.slug/rules.conf)\n"
            "<rule id=\"r_env\" action=\"block\" type=\"path\">.env</rule>\n"
            "# <rule id=\"r_pem\" action=\"block\" type=\"ext\">.key,.pem,.sqlite</rule>\n"
            "# <rule id=\"r_pvt\" action=\"block\" type=\"content\">BEGIN PRIVATE KEY</rule>\n"
            "<rule id=\"r_env_sample\" action=\"allow\" type=\"path\">./.env.example</rule>\n";
        platform::PathUtils::write_text_file_atomic(rules_file, def_rules);
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (instances_.find(port) != instances_.end()) {
        std::cerr << "Error: Workspace already running on port " << port << std::endl;
        return false;
    }

    auto ctrl = std::make_shared<net::ControlServer>(canonical_path, port, suite, ttl_seconds, enable_ai);
    if (!ctrl->start()) {
        std::cerr << "Error: Failed to bind server to port " << port << std::endl;
        return false;
    }

    // Start embedded Web GUI multiplexed on the control port
    auto web = std::make_unique<net::WebServer>(*ctrl, ctrl->port());
    ctrl->set_web_server(web.get());
    web->start();

    if (enable_ai) {
        // Initial scan on startup to populate index.db and detect flagged secrets immediately
        sync::ManifestBuilder::build(canonical_path, 1, static_cast<uint8_t>(suite), true);
    }

    WorkspaceInfo wi;
    wi.port = ctrl->port();
    wi.path = canonical_path;
    wi.suite = suite;
    wi.ai_enabled = enable_ai;
    wi.ttl_seconds = ttl_seconds;
#if defined(SLUG_PLATFORM_POSIX)
    wi.pid = static_cast<uint32_t>(getpid());
#elif defined(SLUG_PLATFORM_WINDOWS)
    wi.pid = static_cast<uint32_t>(GetCurrentProcessId());
#endif
    wi.totp_code = ctrl->totp_manager().generate_code();
    wi.totp_remaining = ctrl->totp_manager().remaining_seconds();

    update_registry(wi, false);

    instances_[ctrl->port()] = {ctrl, std::move(web)};
    return true;
}

bool WorkspaceManager::stop_workspace(uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = instances_.find(port);
    if (it != instances_.end()) {
        it->second.control_server->stop();
        it->second.web_server->stop();
        instances_.erase(it);

        WorkspaceInfo wi;
        wi.port = port;
        update_registry(wi, true);
        return true;
    }

    // If not in this process, check registry to see if a background PID is running
    auto list = load_registry();
    for (const auto& item : list) {
        if (item.port == port) {
#if defined(SLUG_PLATFORM_POSIX)
            if (item.pid > 0) {
                kill(static_cast<pid_t>(item.pid), SIGTERM);
            }
#elif defined(SLUG_PLATFORM_WINDOWS)
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, item.pid);
            if (h) {
                TerminateProcess(h, 0);
                CloseHandle(h);
            }
#endif
            update_registry(item, true);
            return true;
        }
    }
    return false;
}

std::vector<WorkspaceInfo> WorkspaceManager::list_active_workspaces() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<WorkspaceInfo> result;

    // Collect from running in-memory instances
    for (const auto& [port, inst] : instances_) {
        WorkspaceInfo wi;
        wi.port = port;
        wi.path = inst.control_server->workspace_root();
        wi.suite = inst.control_server->suite_id();
        wi.totp_code = inst.control_server->totp_manager().generate_code();
        wi.totp_remaining = inst.control_server->totp_manager().remaining_seconds();
#if defined(SLUG_PLATFORM_POSIX)
        wi.pid = static_cast<uint32_t>(getpid());
#elif defined(SLUG_PLATFORM_WINDOWS)
        wi.pid = static_cast<uint32_t>(GetCurrentProcessId());
#endif
        result.push_back(wi);
    }

    if (!result.empty()) return result;

    // Otherwise, return registry list
    return load_registry();
}

std::shared_ptr<net::ControlServer> WorkspaceManager::get_server(uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = instances_.find(port);
    if (it != instances_.end()) {
        return it->second.control_server;
    }
    return nullptr;
}

} // namespace slug::core
