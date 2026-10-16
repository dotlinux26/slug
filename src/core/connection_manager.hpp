#pragma once

#include "src/core/types.hpp"
#include <string>
#include <vector>
#include <optional>
#include <filesystem>

namespace slug::core {

struct ConnectionInfo {
    std::string id;
    std::string host;
    uint16_t port{kDefaultPort};
    std::string workspace;
    std::string identity;
    Role role{Role::READ_ONLY};
    std::string ticket;
    uint64_t created_at{0};
    uint64_t expires_at{0};
    SuiteID suite{SuiteID::SUITE_1_CLASSICAL};
    uint64_t last_active{0};

    bool is_expired() const;
};

class ConnectionManager {
public:
    static ConnectionManager& instance();

    void save_connection(const ConnectionInfo& conn);
    void add_connection(const ConnectionInfo& conn) { save_connection(conn); }
    std::vector<ConnectionInfo> list_connections(bool prune_expired = true);
    size_t prune_expired_connections();
    static bool ping_connection(const ConnectionInfo& c, int timeout_ms = 400);
    size_t prune_dead_connections(int timeout_ms = 400);
    std::optional<ConnectionInfo> get_connection(const std::string& id);
    void remove_connection(const std::string& id);

    void set_active_connection(const std::string& id);
    std::string get_active_connection();
    std::optional<ConnectionInfo> resolve_connection(const std::string& explicit_id = "");

    static std::filesystem::path connections_file_path();
    static std::filesystem::path active_context_file_path();

private:
    ConnectionManager() = default;
};

} // namespace slug::core
