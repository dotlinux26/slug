#include "src/core/connection_manager.hpp"
#include "src/core/utils.hpp"
#include "src/platform/fs.hpp"
#include "src/platform/socket.hpp"
#include "third_party/json/json.hpp"
#include <fstream>

namespace slug::core {

using json = nlohmann::json;
namespace fs = std::filesystem;

bool ConnectionInfo::is_expired() const {
    if (expires_at == 0) return false;
    return Utils::current_timestamp() > expires_at;
}

ConnectionManager& ConnectionManager::instance() {
    static ConnectionManager inst;
    return inst;
}

fs::path ConnectionManager::connections_file_path() {
    const char* home = std::getenv("HOME");
    if (!home) home = std::getenv("USERPROFILE");
    fs::path base = home ? fs::path(home) : fs::temp_directory_path();
    fs::path p = base / ".slug" / "connections.json";
    platform::PathUtils::ensure_directory(p.parent_path());
    return p;
}

fs::path ConnectionManager::active_context_file_path() {
    const char* home = std::getenv("HOME");
    if (!home) home = std::getenv("USERPROFILE");
    fs::path base = home ? fs::path(home) : fs::temp_directory_path();
    fs::path p = base / ".slug" / "active_context.txt";
    platform::PathUtils::ensure_directory(p.parent_path());
    return p;
}

static std::vector<ConnectionInfo> list_connections_unlocked(const fs::path& p) {
    if (!fs::exists(p)) return {};

    auto text_opt = platform::PathUtils::read_text_file(p);
    if (!text_opt) return {};
    const std::string& text = *text_opt;

    std::vector<ConnectionInfo> out;
    try {
        auto j = json::parse(text);
        if (j.is_array()) {
            for (const auto& obj : j) {
                ConnectionInfo c;
                c.id = obj.value("id", "");
                c.host = obj.value("host", "127.0.0.1");
                c.port = obj.value("port", static_cast<uint16_t>(9443));
                c.workspace = obj.value("workspace", "");
                c.identity = obj.value("identity", "");
                c.role = role_from_string(obj.value("role", "r"));
                c.ticket = obj.value("ticket", "");
                c.created_at = obj.value("created_at", 0ULL);
                c.expires_at = obj.value("expires_at", 0ULL);
                c.suite = suite_from_string(obj.value("suite", "classical"));
                c.last_active = obj.value("last_active", c.created_at);
                out.push_back(c);
            }
        }
    } catch (...) {}

    return out;
}

static void write_connections_unlocked(const fs::path& p, const std::vector<ConnectionInfo>& list) {
    json arr = json::array();
    for (const auto& c : list) {
        json obj;
        obj["id"] = c.id;
        obj["host"] = c.host;
        obj["port"] = c.port;
        obj["workspace"] = c.workspace;
        obj["identity"] = c.identity;
        obj["role"] = role_to_string(c.role);
        obj["ticket"] = c.ticket;
        obj["created_at"] = c.created_at;
        obj["expires_at"] = c.expires_at;
        obj["suite"] = suite_to_short_name(c.suite);
        obj["last_active"] = c.last_active;
        arr.push_back(obj);
    }
    platform::PathUtils::write_text_file_atomic(p, arr.dump(2));
}

static size_t prune_expired_connections_unlocked(const fs::path& p) {
    auto list = list_connections_unlocked(p);
    std::vector<ConnectionInfo> kept;
    size_t pruned = 0;
    std::string active_id = ConnectionManager::instance().get_active_connection();
    bool active_pruned = false;

    for (const auto& c : list) {
        if (c.is_expired()) {
            pruned++;
            if (c.id == active_id) active_pruned = true;
        } else {
            kept.push_back(c);
        }
    }

    if (pruned > 0) {
        write_connections_unlocked(p, kept);
        if (active_pruned) {
            ConnectionManager::instance().set_active_connection(!kept.empty() ? kept.front().id : "");
        }
    }
    return pruned;
}

void ConnectionManager::save_connection(const ConnectionInfo& conn) {
    fs::path p = connections_file_path();
    FileLockGuard lock(p.string());
    auto list = list_connections_unlocked(p);
    std::vector<ConnectionInfo> updated;
    for (const auto& item : list) {
        if (item.id != conn.id) {
            if (!item.is_expired()) {
                updated.push_back(item);
            }
        }
    }
    updated.push_back(conn);
    write_connections_unlocked(p, updated);
}

size_t ConnectionManager::prune_expired_connections() {
    fs::path p = connections_file_path();
    FileLockGuard lock(p.string());
    return prune_expired_connections_unlocked(p);
}

bool ConnectionManager::ping_connection(const ConnectionInfo& c, int timeout_ms) {
    platform::TcpSocket sock;
    return sock.connect(c.host, c.port, timeout_ms);
}

size_t ConnectionManager::prune_dead_connections(int timeout_ms) {
    fs::path p = connections_file_path();
    FileLockGuard lock(p.string());
    prune_expired_connections_unlocked(p);
    auto list = list_connections_unlocked(p);
    std::vector<ConnectionInfo> kept;
    size_t pruned = 0;
    std::string active_id = get_active_connection();
    bool active_pruned = false;

    for (const auto& c : list) {
        if (!ping_connection(c, timeout_ms)) {
            pruned++;
            if (c.id == active_id) active_pruned = true;
        } else {
            kept.push_back(c);
        }
    }

    if (pruned > 0) {
        write_connections_unlocked(p, kept);
        if (active_pruned) {
            set_active_connection(!kept.empty() ? kept.front().id : "");
        }
    }
    return pruned;
}

std::vector<ConnectionInfo> ConnectionManager::list_connections(bool prune_expired) {
    fs::path p = connections_file_path();
    FileLockGuard lock(p.string());
    if (prune_expired) {
        prune_expired_connections_unlocked(p);
    }
    return list_connections_unlocked(p);
}

std::optional<ConnectionInfo> ConnectionManager::get_connection(const std::string& id) {
    auto list = list_connections();
    for (const auto& c : list) {
        if (c.id == id) {
            return c;
        }
    }
    return std::nullopt;
}

void ConnectionManager::remove_connection(const std::string& id) {
    fs::path p = connections_file_path();
    FileLockGuard lock(p.string());
    auto list = list_connections_unlocked(p);
    std::vector<ConnectionInfo> kept;
    for (const auto& c : list) {
        if (c.id != id) {
            kept.push_back(c);
        }
    }
    write_connections_unlocked(p, kept);
    if (get_active_connection() == id) {
        set_active_connection(!kept.empty() ? kept.front().id : "");
    }
}

void ConnectionManager::set_active_connection(const std::string& id) {
    platform::PathUtils::write_text_file_atomic(active_context_file_path(), id);
}

std::string ConnectionManager::get_active_connection() {
    auto id_opt = platform::PathUtils::read_text_file(active_context_file_path());
    if (id_opt) {
        std::string id = *id_opt;
        while (!id.empty() && (id.back() == '\n' || id.back() == '\r' || id.back() == ' ')) id.pop_back();
        return id;
    }
    return "";
}

std::optional<ConnectionInfo> ConnectionManager::resolve_connection(const std::string& explicit_id) {
    if (!explicit_id.empty()) {
        return get_connection(explicit_id);
    }
    std::string active_id = get_active_connection();
    if (!active_id.empty()) {
        auto c = get_connection(active_id);
        if (c && !c->is_expired()) return c;
    }
    auto list = list_connections();
    for (const auto& c : list) {
        if (!c.is_expired()) return c;
    }
    return std::nullopt;
}

} // namespace slug::core
