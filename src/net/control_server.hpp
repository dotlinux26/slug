#pragma once

#include "src/platform/socket.hpp"
#include "src/core/types.hpp"
#include "src/core/acl.hpp"
#include "src/core/audit.hpp"
#include "src/crypto/crypto_suite.hpp"
#include "src/crypto/totp.hpp"
#include "src/sync/manifest.hpp"
#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <filesystem>
#include <map>
#include <mutex>

namespace slug::net {

struct SessionState {
    uint32_t session_id{0};
    core::Role role{core::Role::READ_ONLY};
    uint64_t expires_at{0};
    std::array<uint8_t, 32> session_key{};
    std::string identity;
    std::string web_ticket;

    bool has_permission(core::Role required) const {
        if (role == core::Role::READ_WRITE) return true;
        return role == required;
    }
};

class ControlServer {
public:
    ControlServer(std::filesystem::path workspace_root,
                  uint16_t port = core::kDefaultPort,
                  core::SuiteID suite_id = core::SuiteID::SUITE_3_PURE_PQC,
                  uint64_t cert_ttl = 86400,
                  bool enable_ai = false);
    ~ControlServer();

    bool start();
    void stop();

    uint16_t port() const { return port_; }
    core::SuiteID suite_id() const { return suite_id_; }
    const std::filesystem::path& workspace_root() const { return workspace_root_; }
    crypto::TotpManager& totp_manager() { return totp_manager_; }
    core::AclManager& acl_manager() { return acl_manager_; }
    core::AuditLogger& audit_logger() { return audit_logger_; }
    bool is_running() const { return running_; }
    bool ai_enabled() const { return enable_ai_; }
    uint64_t cert_ttl() const { return cert_ttl_; }

    std::optional<SessionState> get_session(uint32_t session_id) const;
    std::optional<SessionState> find_session_by_ticket(const std::string& ticket) const;
    std::string create_host_admin_ticket(uint64_t ttl_sec = 14400);

    void set_web_server(class WebServer* ws) { web_server_ = ws; }

private:
    std::filesystem::path workspace_root_;
    uint16_t port_;
    core::SuiteID suite_id_;
    uint64_t cert_ttl_;
    bool enable_ai_;
    class WebServer* web_server_{nullptr};

    std::atomic<bool> running_{false};
    platform::TcpListener listener_;
    std::unique_ptr<std::thread> worker_thread_;

    std::unique_ptr<crypto::ICryptoSuite> suite_;
    crypto::TotpManager totp_manager_;
    core::AclManager acl_manager_;
    core::AuditLogger audit_logger_;
    crypto::KemKeyPair server_kem_;
    crypto::SigKeyPair server_sig_;

    mutable std::mutex session_mutex_;
    std::map<uint32_t, SessionState> sessions_;
    uint32_t next_session_id_{1000};

    void run_accept_loop();
    void handle_client(platform::TcpSocket client);
};

} // namespace slug::net
