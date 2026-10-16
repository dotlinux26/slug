#pragma once

#include "src/platform/socket.hpp"
#include "src/net/control_server.hpp"
#include "src/core/types.hpp"
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <functional>

namespace slug::net {

struct WebSession {
    std::string token;
    std::string identity;
    core::Role role{core::Role::READ_ONLY};
    uint64_t expires_at{0};
    std::string ticket;
};

struct HttpRequest {
    std::string method;
    std::string uri;
    std::string path;
    std::string query;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string session_token;
};

class WebServer {
public:
    WebServer(ControlServer& control_server, uint16_t web_port);
    ~WebServer();

    bool start();
    void stop();

    uint16_t port() const { return port_; }
    bool is_running() const { return running_; }

    void handle_http_request(platform::TcpSocket& client, std::span<const uint8_t, 4> initial_bytes);
    std::vector<uint8_t> handle_tunneled_http(const std::string& raw_request, uint32_t session_id);

    std::optional<WebSession> validate_session(const std::string& token);
    std::string create_session(const std::string& identity, core::Role role, uint64_t ttl_sec = 86400, const std::string& ticket = "");
    void destroy_session(const std::string& token);
    void revoke_session_by_ticket(const std::string& ticket);

private:
    ControlServer& control_server_;
    uint16_t port_;
    std::atomic<bool> running_{false};
    platform::TcpListener listener_;
    std::unique_ptr<std::thread> worker_thread_;

    std::map<std::string, WebSession> sessions_;
    std::mutex session_mutex_;

    void run_accept_loop();
    void handle_http_client(platform::TcpSocket client);
    void dispatch_http(platform::TcpSocket& client, const HttpRequest& req);
    void dispatch_http_core(const HttpRequest& req, std::function<void(const std::string&)> send_raw, const std::string& peer_ip, uint32_t tunneled_session_id);

    std::string render_login_page(const std::string& error_msg = "", const std::string& redirect_target = "/drop");
    std::string render_directory_listing(const std::string& rel_subpath, const WebSession& session);
    std::string render_admin_dashboard(const WebSession& session);
};

} // namespace slug::net
