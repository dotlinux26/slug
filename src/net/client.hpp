#pragma once

#include "src/platform/socket.hpp"
#include "src/core/types.hpp"
#include "src/crypto/crypto_suite.hpp"
#include "src/sync/manifest.hpp"
#include "src/sync/delta.hpp"
#include "src/net/aead_frame.hpp"
#include "third_party/json/json.hpp"
#include <functional>
#include <string>
#include <vector>
#include <filesystem>
#include <memory>
#include <optional>

namespace slug::net {

struct ClientAuthResult {
    bool success{false};
    uint32_t session_id{0};
    core::Role role{core::Role::READ_ONLY};
    uint64_t ttl{0};
    std::string web_ticket;
    std::string workspace_name;
    std::string message;
};

class SlugClient {
public:
    SlugClient();
    SlugClient(const std::string& host, uint16_t port, core::SuiteID suite_id = core::SuiteID::SUITE_1_CLASSICAL);
    ~SlugClient();

    // Connects to server, performs handshake and negotiates suite
    bool connect(const std::string& host, uint16_t port, int timeout_ms = 5000);
    void disconnect();
    bool is_connected() const { return socket_.is_valid() && is_encrypted_; }

    // Authenticate via single-use 8-digit TOTP
    ClientAuthResult authenticate_totp(const std::string& totp_code);

    // Authenticate via username / password / requested role
    ClientAuthResult authenticate_user(const std::string& username, const std::string& password, const std::string& role = "");
    bool authenticate_user(const std::string& username, const std::string& password, uint64_t ttl, bool save = false);

    // Authenticate via session ticket / certificate
    ClientAuthResult authenticate_ticket(const std::string& ticket);
    bool authenticate_token(const std::string& token_or_ticket, uint64_t ttl = 86400, bool save = false);

    // Fetches remote workspace manifest
    std::optional<sync::WorkspaceManifest> fetch_manifest();

    // Downloads a single specified file into local_dest
    bool get_file(const std::string& remote_path,
                  const std::filesystem::path& local_dest,
                  std::function<void(const std::string& msg)> log_callback = nullptr);

    // Performs incremental delta pull into local_dir
    bool pull(const std::filesystem::path& local_target_dir,
              const sync::DeltaSyncOptions& options,
              std::function<void(const std::string& msg)> log_callback = nullptr,
              const std::optional<sync::WorkspaceManifest>& cached_manifest = std::nullopt);

    // Pushes local file to remote workspace
    bool push(const std::filesystem::path& local_file,
              const std::string& remote_dest,
              std::function<void(const std::string& msg)> log_callback = nullptr);

    // Tunnels raw HTTP request over Post-Quantum AEAD frame channel
    std::vector<uint8_t> tunnel_http(const std::string& raw_http_request);

    core::SuiteID negotiated_suite() const { return suite_id_; }
    const std::string& negotiated_suite_name() const { return suite_name_; }
    uint32_t session_id() const { return session_id_; }
    core::Role role() const { return role_; }
    const std::string& last_error() const { return last_error_; }
    const std::string& get_last_error() const { return last_error_; }
    const std::string& session_ticket() const { return session_ticket_; }
    uint64_t session_ttl() const { return session_ttl_; }
    uint64_t expires_at() const { return expires_at_; }
    const std::string& workspace_name() const { return workspace_name_; }
    const std::string& identity() const { return identity_; }
    const std::string& auth_type() const { return auth_type_; }

private:
    platform::TcpSocket socket_;
    std::string last_error_;
    std::string session_ticket_;
    uint64_t session_ttl_{0};
    uint64_t expires_at_{0};
    std::string workspace_name_;
    std::string identity_;
    std::string auth_type_;
    core::SuiteID suite_id_{core::SuiteID::SUITE_1_CLASSICAL};
    std::string suite_name_;
    std::unique_ptr<crypto::ICryptoSuite> suite_;
    uint32_t session_id_{0};
    core::Role role_{core::Role::READ_ONLY};

    bool is_encrypted_{false};
    SessionKeys session_keys_;
    uint64_t tx_seq_{1};
    AntiReplaySlidingWindow s2c_window_;

    bool send_packet(const std::string& json_str);
    std::optional<std::string> recv_packet(int timeout_ms = 10000);

    bool send_json(const nlohmann::json& j);
    std::optional<nlohmann::json> recv_json(int timeout_ms = 10000);

    std::optional<std::vector<uint8_t>> fetch_chunk(const std::string& rel_path, uint32_t chunk_idx);
};

} // namespace slug::net
