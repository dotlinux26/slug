#pragma once

#include "src/platform/socket.hpp"
#include "src/core/types.hpp"
#include "src/core/utils.hpp"
#include "src/core/acl.hpp"
#include "src/core/audit.hpp"
#include "src/crypto/crypto_suite.hpp"
#include "src/crypto/totp.hpp"
#include "src/sync/manifest.hpp"
#include "src/core/vfs.hpp"
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
    std::string auth_type{"Unknown"};     // "TOTP", "Account", "Ticket", "Host Admin"
    std::string remote_endpoint{"-"};     // "ip:port" or "127.0.0.1 (local)"
    uint64_t created_at{0};
    uint64_t last_active_at{0};
    bool is_revoked{false};

    bool is_active(uint64_t now) const {
        if (is_revoked) return false;
        if (expires_at == 0) return true;
        return now < expires_at;
    }

    bool has_permission(core::Role required) const {
        if (is_revoked) return false;
        if (role == core::Role::READ_WRITE) return true;
        return role == required;
    }
};

class ControlServer {
public:
    ControlServer(std::filesystem::path workspace_root,
                  uint16_t port = core::kDefaultPort,
                  core::SuiteID suite_id = core::SuiteID::SUITE_1_CLASSICAL,
                  uint64_t cert_ttl = 86400,
                  bool enable_ai = false,
                  core::FilterMode filter_mode = core::FilterMode::PROTECTED,
                  core::FilterLevel filter_level = core::FilterLevel::LEVEL_2_REGEX,
                  core::AiModelProvider ai_provider = core::AiModelProvider::OLLAMA,
                  uint32_t totp_step = 60,
                  uint64_t workspace_ttl = 86400);
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
    core::FilterMode filter_mode() const { return filter_mode_; }
    core::FilterLevel filter_level() const { return filter_level_; }
    core::AiModelProvider ai_provider() const { return ai_provider_; }
    void set_filter_level(core::FilterLevel lvl) {
        filter_level_ = lvl;
        enable_ai_ = (lvl == core::FilterLevel::LEVEL_4_AI);
        invalidate_manifest_cache();
    }
    void set_ai_provider(core::AiModelProvider p) {
        ai_provider_ = p;
        invalidate_manifest_cache();
    }
    uint64_t cert_ttl() const { return cert_ttl_; }
    uint64_t workspace_ttl() const { return workspace_ttl_; }
    uint64_t started_at() const { return started_at_; }
    uint32_t totp_step() const { return totp_step_; }

    bool is_workspace_expired(uint64_t now = 0) const {
        if (workspace_ttl_ == 0) return false;
        if (now == 0) now = core::Utils::current_timestamp();
        return now >= (started_at_ + workspace_ttl_);
    }

    uint64_t remaining_workspace_ttl(uint64_t now = 0) const {
        if (workspace_ttl_ == 0) return 0;
        if (now == 0) now = core::Utils::current_timestamp();
        uint64_t exp = started_at_ + workspace_ttl_;
        return (now < exp) ? (exp - now) : 0;
    }

    std::optional<SessionState> get_session(uint32_t session_id) const;
    std::optional<SessionState> find_session_by_ticket(const std::string& ticket) const;
    std::string create_host_admin_ticket(uint64_t ttl_sec = 14400);
    std::vector<SessionState> list_sessions() const;
    bool revoke_session(uint32_t session_id);
    void revoke_sessions_by_identity(const std::string& identity);
    void touch_session(uint32_t session_id);

    core::SlugVFS& vfs() { return vfs_; }
    const core::SlugVFS& vfs() const { return vfs_; }

    void set_web_server(class WebServer* ws) { web_server_ = ws; }

    sync::WorkspaceManifest get_or_build_manifest();
    std::string get_or_build_manifest_json();
    void invalidate_manifest_cache();

private:
    std::filesystem::path workspace_root_;
    uint16_t port_;
    core::SuiteID suite_id_;
    uint64_t cert_ttl_;
    bool enable_ai_;
    core::FilterLevel filter_level_{core::FilterLevel::LEVEL_2_REGEX};
    core::AiModelProvider ai_provider_{core::AiModelProvider::OLLAMA};
    uint32_t totp_step_{60};
    uint64_t workspace_ttl_{86400};
    uint64_t started_at_{0};
    class WebServer* web_server_{nullptr};

    std::atomic<bool> running_{false};
    platform::TcpListener listener_;
    std::unique_ptr<std::thread> worker_thread_;

    std::unique_ptr<crypto::ICryptoSuite> suite_;
    core::FilterMode filter_mode_{core::FilterMode::PROTECTED};
    crypto::TotpManager totp_manager_;
    core::AclManager acl_manager_;
    core::AuditLogger audit_logger_;
    crypto::KemKeyPair server_kem_;
    crypto::SigKeyPair server_sig_;
    core::SlugVFS vfs_;

    mutable std::mutex session_mutex_;
    std::map<uint32_t, SessionState> sessions_;
    uint32_t next_session_id_{1000};

    mutable std::mutex manifest_mutex_;
    std::string cached_manifest_json_;
    std::optional<sync::WorkspaceManifest> cached_manifest_;
    uint64_t manifest_cached_at_{0};
    bool manifest_dirty_{true};

    void run_accept_loop();
    void handle_client(platform::TcpSocket client);
};

} // namespace slug::net
