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
    SuiteID suite{SuiteID::SUITE_3_PURE_PQC};
    bool ai_enabled{false};
    uint64_t ttl_seconds{86400};
    uint32_t pid{0};
    std::string totp_code;
    uint32_t totp_remaining{0};
};

class WorkspaceManager {
public:
    static WorkspaceManager& instance();

    // Initializes or adds a workspace server
    bool add_workspace(const std::filesystem::path& folder_path,
                       uint16_t port = kDefaultPort,
                       SuiteID suite = SuiteID::SUITE_3_PURE_PQC,
                       uint64_t ttl_seconds = 86400,
                       bool enable_ai = false);

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
