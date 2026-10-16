#pragma once

#include "src/core/types.hpp"
#include "src/net/control_server.hpp"
#include "src/net/web_server.hpp"
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <map>
#include <mutex>

namespace slug::core {

struct WorkspaceInfo {
    uint16_t port{0};
    std::filesystem::path path;
    SuiteID suite{SuiteID::SUITE_2_MODERN};
    bool ai_enabled{false};
    FilterMode filter_mode{FilterMode::PROTECTED};
    uint64_t ttl_seconds{86400};
    uint32_t pid{0};
    std::string totp_code;
    uint32_t totp_remaining{0};
};

class WorkspaceManager {
public:
    static WorkspaceManager& instance();

    // Initializes or adds a workspace server (auto-picks free port if busy)
    bool add_workspace(const std::filesystem::path& folder_path,
                       uint16_t port = kDefaultPort,
                       SuiteID suite = SuiteID::SUITE_2_MODERN,
                       uint64_t ttl_seconds = 86400,
                       bool enable_ai = false,
                       FilterMode filter_mode = FilterMode::PROTECTED,
                       uint16_t* actual_port = nullptr);

    // Automatically finds the next available, free TCP port starting from starting_port
    uint16_t find_available_port(uint16_t starting_port = 9443);

    // Stops a workspace on a given port
    bool stop_workspace(uint16_t port);

    // Lists active workspaces
    std::vector<WorkspaceInfo> list_active_workspaces();

    // Finds server by port
    std::shared_ptr<net::ControlServer> get_server(uint16_t port);

    // Save/load workspace registry for status across executions
    static std::filesystem::path registry_file_path();
    static std::vector<WorkspaceInfo> load_registry();
    static void update_registry(const WorkspaceInfo& info, bool remove = false);

private:
    WorkspaceManager() = default;
    std::mutex mutex_;
    struct RunningInstance {
        std::shared_ptr<net::ControlServer> control_server;
        std::unique_ptr<net::WebServer> web_server;
    };
    std::map<uint16_t, RunningInstance> instances_;
};

} // namespace slug::core
