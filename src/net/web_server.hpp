#pragma once

#include "src/platform/socket.hpp"
#include "src/net/control_server.hpp"
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <filesystem>

namespace slug::net {

class WebServer {
public:
    WebServer(ControlServer& control_server, uint16_t web_port);
    ~WebServer();

    bool start();
    void stop();

    uint16_t port() const { return port_; }
    bool is_running() const { return running_; }

    void handle_http_request(platform::TcpSocket& client, std::span<const uint8_t, 4> initial_bytes);

private:
    ControlServer& control_server_;
    uint16_t port_;
    std::atomic<bool> running_{false};
    platform::TcpListener listener_;
    std::unique_ptr<std::thread> worker_thread_;

    void run_accept_loop();
    void handle_http_client(platform::TcpSocket client);
    void dispatch_http(platform::TcpSocket& client, const std::string& req_str);

    std::string render_directory_listing(const std::string& rel_subpath = "");
    std::string render_admin_dashboard();
};

} // namespace slug::net
