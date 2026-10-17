#include "src/platform/platform.hpp"
#include "src/core/workspace.hpp"
#include "src/platform/fs.hpp"
#include "src/platform/process.hpp"
#include "src/core/utils.hpp"
#include "src/sync/manifest.hpp"
#include "third_party/json/json.hpp"
#include <iostream>
#include <cstdlib>

#if defined(SLUG_PLATFORM_POSIX)
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

namespace slug::core {

namespace fs = std::filesystem;
using json = nlohmann::json;

WorkspaceManager& WorkspaceManager::instance() {
    static WorkspaceManager mgr;
    return mgr;
}

fs::path WorkspaceManager::registry_file_path() {
    fs::path base = platform::PathUtils::get_user_home();
    fs::path p = base / ".slug" / "registry.json";
    platform::PathUtils::ensure_directory(p.parent_path());
    return p;
}

static std::vector<WorkspaceInfo> load_registry_unlocked(const fs::path& p, bool auto_prune_dead = true) {
    if (!fs::exists(p)) return {};

    auto text = platform::PathUtils::read_text_file(p);
    if (!text) return {};

    std::vector<WorkspaceInfo> list;
    bool has_dead = false;
    try {
        auto j = json::parse(*text);
        if (j.is_array()) {
            for (const auto& item : j) {
                WorkspaceInfo wi;
                wi.port = item.value("port", static_cast<uint16_t>(0));
                wi.path = fs::path(item.value("path", ""));
                wi.suite = suite_from_string(item.value("suite", "3"));
                wi.ai_enabled = item.value("ai_enabled", false);
                wi.filter_mode = filter_mode_from_string(item.value("filter_mode", "protected"));
                wi.ttl_seconds = item.value("ttl_seconds", 86400ULL);
                wi.pid = item.value("pid", 0U);

                if (auto_prune_dead && wi.pid > 0 && !platform::ProcessUtils::is_process_alive(wi.pid)) {
                    has_dead = true;
                    continue; // Skip dead process
                }

                list.push_back(wi);
            }
        }
    } catch (...) {}

    if (auto_prune_dead && has_dead) {
        json j = json::array();
        for (const auto& item : list) {
            json obj;
            obj["port"] = item.port;
            obj["path"] = item.path.string();
            obj["suite"] = suite_to_short_name(item.suite);
            obj["ai_enabled"] = item.ai_enabled;
            obj["filter_mode"] = filter_mode_to_string(item.filter_mode);
            obj["ttl_seconds"] = item.ttl_seconds;
            obj["pid"] = item.pid;
            j.push_back(obj);
        }
        platform::PathUtils::write_text_file_atomic(p, j.dump(2));
    }

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
        obj["filter_mode"] = filter_mode_to_string(item.filter_mode);
        obj["ttl_seconds"] = item.ttl_seconds;
        obj["pid"] = item.pid;
        j.push_back(obj);
    }

    platform::PathUtils::write_text_file_atomic(registry_file_path(), j.dump(2));
}

static bool is_port_available(uint16_t port) {
#if defined(SLUG_PLATFORM_WINDOWS)
    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    int res = ::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    ::closesocket(sock);
    return (res == 0);
#else
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    int res = ::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    ::close(sock);
    return (res == 0);
#endif
}

uint16_t WorkspaceManager::find_available_port(uint16_t starting_port) {
    if (starting_port < 1024) starting_port = 9443;
    auto reg = load_registry();

    for (uint32_t p = starting_port; p <= 65535; ++p) {
        uint16_t candidate = static_cast<uint16_t>(p);
        // 1. Check in-memory instances_
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (instances_.find(candidate) != instances_.end()) {
                continue;
            }
        }
        // 2. Check registry for active background process
        bool in_use = false;
        for (const auto& r : reg) {
            if (r.port == candidate && r.pid > 0 && platform::ProcessUtils::is_process_alive(r.pid)) {
                in_use = true;
                break;
            }
        }
        if (in_use) continue;

        // 3. Test binding OS TCP socket
        if (is_port_available(candidate)) {
            return candidate;
        }
    }
    return starting_port;
}

bool WorkspaceManager::add_workspace(const fs::path& folder_path,
                                    uint16_t port,
                                    SuiteID suite,
                                    uint64_t ttl_seconds,
                                    bool enable_ai,
                                    FilterMode filter_mode,
                                    uint16_t* actual_port) {

    std::error_code ec;
    fs::path canonical_path = fs::canonical(folder_path, ec);
    if (ec) {
        canonical_path = fs::absolute(folder_path).lexically_normal();
    }
    // Automatically create directory if user specified a non-existent folder
    if (!fs::exists(canonical_path)) {
        fs::create_directories(canonical_path, ec);
    }
    if (!fs::exists(canonical_path) || !fs::is_directory(canonical_path)) {
        std::cerr << "Error: Target folder does not exist and could not be created: " << folder_path << std::endl;
        return false;
    }

    // STRICT CHECK: Reject duplicate hosting of the same directory!
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        for (const auto& [p, inst] : instances_) {
            if (inst.control_server) {
                std::error_code eq_ec;
                if (fs::equivalent(inst.control_server->workspace_root(), canonical_path, eq_ec)) {
                    std::cerr << "Error: Workspace folder is already being hosted on port " << p << std::endl;
                    if (actual_port) *actual_port = p;
                    return false;
                }
            }
        }
        auto reg_list = load_registry();
        for (const auto& w : reg_list) {
            std::error_code eq_ec;
            if (fs::equivalent(w.path, canonical_path, eq_ec)) {
                if (!is_port_available(w.port)) {
                    std::cerr << "Error: Workspace folder is already being hosted on port " << w.port << std::endl;
                    if (actual_port) *actual_port = w.port;
                    return false;
                }
            }
        }
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
    // Auto-search next available port if port is occupied
    uint16_t target_port = (port >= 1024) ? port : 9443;
    std::shared_ptr<net::ControlServer> ctrl;

    int attempts = 100;
    while (attempts-- > 0) {
        if (instances_.find(target_port) == instances_.end()) {
            ctrl = std::make_shared<net::ControlServer>(canonical_path, target_port, suite, ttl_seconds, enable_ai, filter_mode);
            if (ctrl->start()) {
                break; // Successfully bound and started!
            }
            ctrl.reset();
        }
        // Collision: search next available port
        target_port = find_available_port(target_port + 1);
    }

    if (!ctrl) {
        std::cerr << "Error: Failed to bind server to any available port starting from " << port << std::endl;
        return false;
    }

    if (actual_port) {
        *actual_port = ctrl->port();
    }

    // Start embedded Web GUI multiplexed on the control port
    auto web = std::make_unique<net::WebServer>(*ctrl, ctrl->port());
    ctrl->set_web_server(web.get());
    web->start();

    if (enable_ai && filter_mode != FilterMode::NONE) {
        // Initial scan on startup to populate index.db and detect flagged secrets immediately
        sync::ManifestBuilder::build(canonical_path, 1, static_cast<uint8_t>(suite), true, filter_mode);
    }

    WorkspaceInfo wi;
    wi.port = ctrl->port();
    wi.path = canonical_path;
    wi.suite = suite;
    wi.ai_enabled = enable_ai;
    wi.filter_mode = filter_mode;
    wi.ttl_seconds = ttl_seconds;
#if defined(SLUG_PLATFORM_POSIX)
    wi.pid = static_cast<uint32_t>(getpid());
#elif defined(SLUG_PLATFORM_WINDOWS)
    wi.pid = static_cast<uint32_t>(GetCurrentProcessId());
#endif
    wi.totp_code = ctrl->totp_manager().generate_code();
    wi.totp_remaining = ctrl->totp_manager().remaining_seconds();

    update_registry(wi, false);

    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        instances_[ctrl->port()] = {ctrl, std::move(web)};
    }
    return true;
}

bool WorkspaceManager::stop_workspace(uint16_t port) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
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
    std::lock_guard<std::recursive_mutex> lock(mutex_);
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
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = instances_.find(port);
    if (it != instances_.end()) {
        return it->second.control_server;
    }
    return nullptr;
}

} // namespace slug::core
