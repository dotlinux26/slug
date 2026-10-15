#include "src/net/control_server.hpp"
#include "src/net/web_server.hpp"
#include "src/net/protocol.hpp"
#include "src/platform/fs.hpp"
#include "src/core/utils.hpp"
#include "third_party/json/json.hpp"
#include <iostream>

namespace slug::net {

using json = nlohmann::json;

ControlServer::ControlServer(std::filesystem::path workspace_root,
                             uint16_t port,
                             core::SuiteID suite_id,
                             uint64_t cert_ttl,
                             bool enable_ai)
    : workspace_root_(std::move(workspace_root)),
      port_(port),
      suite_id_(suite_id),
      cert_ttl_(cert_ttl),
      enable_ai_(enable_ai),
      acl_manager_(workspace_root_ / ".slug" / "acl.db"),
      audit_logger_(workspace_root_ / ".slug" / "audit.log") {

    suite_ = crypto::ICryptoSuite::create(suite_id_);
    server_kem_ = suite_->generate_kem_keypair();
    server_sig_ = suite_->generate_sig_keypair();
}

ControlServer::~ControlServer() {
    stop();
}

bool ControlServer::start() {
    if (running_) return true;

    if (!listener_.bind_and_listen("0.0.0.0", port_)) {
        return false;
    }
    port_ = listener_.bound_port();

    running_ = true;
    worker_thread_ = std::make_unique<std::thread>(&ControlServer::run_accept_loop, this);
    audit_logger_.log("system", "SERVER_START", workspace_root_.string(),
                      "Server started on port " + std::to_string(port_) + " with " + suite_->name());
    return true;
}

void ControlServer::stop() {
    if (!running_) return;
    running_ = false;
    listener_.close();
    if (worker_thread_ && worker_thread_->joinable()) {
        worker_thread_->join();
    }
    audit_logger_.log("system", "SERVER_STOP", workspace_root_.string(), "Server stopped");
}

std::optional<SessionState> ControlServer::get_session(uint32_t session_id) const {
    std::lock_guard<std::mutex> lock(session_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        if (core::Utils::current_timestamp() < it->second.expires_at) {
            return it->second;
        }
    }
    return std::nullopt;
}

void ControlServer::run_accept_loop() {
    while (running_) {
        auto client_opt = listener_.accept(500);
        if (client_opt) {
            std::thread([this, sock = std::move(*client_opt)]() mutable {
                handle_client(std::move(sock));
            }).detach();
        }
    }
}

// Framing helper: send framed JSON message
static bool send_msg(platform::TcpSocket& sock, const json& j) {
    std::string s = j.dump();
    uint32_t len = static_cast<uint32_t>(s.size());
    uint8_t hdr[4];
    hdr[0] = static_cast<uint8_t>((len >> 24) & 0xFF);
    hdr[1] = static_cast<uint8_t>((len >> 16) & 0xFF);
    hdr[2] = static_cast<uint8_t>((len >> 8) & 0xFF);
    hdr[3] = static_cast<uint8_t>(len & 0xFF);

    if (!sock.send_all(std::span<const uint8_t>(hdr, 4))) return false;
    return sock.send_all(s);
}


void ControlServer::handle_client(platform::TcpSocket client) {
    uint32_t cur_session_id = 0;

    while (running_ && client.is_valid()) {
        uint8_t hdr[4];
        if (!client.receive_exact(std::span<uint8_t>(hdr, 4), 10000)) {
            break;
        }

        // Check if incoming connection is an HTTP request
        bool is_http = (hdr[0] == 'G' && hdr[1] == 'E' && hdr[2] == 'T' && hdr[3] == ' ') ||
                       (hdr[0] == 'H' && hdr[1] == 'E' && hdr[2] == 'A' && hdr[3] == 'D') ||
                       (hdr[0] == 'P' && hdr[1] == 'O' && hdr[2] == 'S' && hdr[3] == 'T');

        if (is_http) {
            if (web_server_) {
                web_server_->handle_http_request(client, std::span<const uint8_t, 4>(hdr, 4));
            }
            break;
        }

        uint32_t len = (static_cast<uint32_t>(hdr[0]) << 24) |
                       (static_cast<uint32_t>(hdr[1]) << 16) |
                       (static_cast<uint32_t>(hdr[2]) << 8) |
                        static_cast<uint32_t>(hdr[3]);

        if (len > 50 * 1024 * 1024) break;

        std::vector<uint8_t> body(len);
        if (!client.receive_exact(std::span<uint8_t>(body), 10000)) {
            break;
        }

        json req;
        try {
            std::string s(body.begin(), body.end());
            req = json::parse(s);
        } catch (...) {
            break;
        }

        std::string type = req.value("type", "");

        if (type == "client_hello") {
            // Handshake & Suite negotiation
            json resp;
            resp["type"] = "server_hello";
            resp["suite_id"] = static_cast<uint8_t>(suite_id_);
            resp["suite_name"] = suite_->name();
            resp["server_kem_pub"] = core::Utils::to_hex(server_kem_.public_key);
            resp["server_sig_pub"] = core::Utils::to_hex(server_sig_.public_key);
            resp["server_salt"] = core::Utils::to_hex(core::Utils::random_bytes(16));
            if (!send_msg(client, resp)) break;

        } else if (type == "auth_totp") {
            std::string code = req.value("code", "");
            bool ok = totp_manager_.verify_and_burn(code);

            json resp;
            if (ok) {
                uint32_t sid = 0;
                {
                    std::lock_guard<std::mutex> lock(session_mutex_);
                    sid = next_session_id_++;
                    SessionState ss;
                    ss.session_id = sid;
                    ss.role = core::Role::READ_WRITE;
                    ss.expires_at = core::Utils::current_timestamp() + cert_ttl_;
                    ss.identity = "totp_client_" + client.peer_endpoint().ip;
                    sessions_[sid] = ss;
                }
                cur_session_id = sid;
                resp["status"] = "ok";
                resp["session_id"] = sid;
                resp["role"] = "rw";
                resp["ttl"] = cert_ttl_;
                resp["message"] = "Authenticated via TOTP (token burned)";
                audit_logger_.log(client.peer_endpoint().ip, "AUTH_TOTP_SUCCESS", "", "TOTP verified and burned");
            } else {
                resp["status"] = "error";
                resp["message"] = "Invalid or already burned TOTP token";
                audit_logger_.log(client.peer_endpoint().ip, "AUTH_TOTP_FAIL", "", "Invalid/burned TOTP: " + code, false);
            }
            if (!send_msg(client, resp)) break;

        } else if (type == "auth_user") {
            std::string u = req.value("username", "");
            std::string p = req.value("password", "");
            std::string r_str = req.value("role", "r");
            core::Role req_role = core::role_from_string(r_str);

            bool ok = acl_manager_.authenticate(u, p, req_role);
            json resp;
            if (ok) {
                auto acc_opt = acl_manager_.get_user(u);
                uint64_t ttl = (acc_opt && acc_opt->expires_at > 0)
                               ? (acc_opt->expires_at - core::Utils::current_timestamp())
                               : cert_ttl_;

                uint32_t sid = 0;
                {
                    std::lock_guard<std::mutex> lock(session_mutex_);
                    sid = next_session_id_++;
                    SessionState ss;
                    ss.session_id = sid;
                    ss.role = acc_opt ? acc_opt->role : core::Role::READ_ONLY;
                    ss.expires_at = core::Utils::current_timestamp() + ttl;
                    ss.identity = u;
                    sessions_[sid] = ss;
                }
                cur_session_id = sid;
                resp["status"] = "ok";
                resp["session_id"] = sid;
                resp["role"] = core::role_to_string(sessions_[sid].role);
                resp["ttl"] = ttl;
                resp["message"] = "Authenticated via account " + u;
                audit_logger_.log(u, "AUTH_USER_SUCCESS", "", "Account logged in with role " + core::role_to_string(sessions_[sid].role));
            } else {
                resp["status"] = "error";
                resp["message"] = "Authentication failed (invalid credentials, role mismatch, or expired account)";
                audit_logger_.log(u.empty() ? client.peer_endpoint().ip : u, "AUTH_USER_FAIL", "", "Invalid credentials or expired", false);
            }
            if (!send_msg(client, resp)) break;

        } else if (type == "get_manifest") {
            auto sess = get_session(cur_session_id);
            if (!sess) {
                json err;
                err["status"] = "error";
                err["message"] = "Unauthorized / expired session";
                send_msg(client, err);
                break;
            }

            auto manifest = sync::ManifestBuilder::build(workspace_root_, 1, static_cast<uint8_t>(suite_id_), enable_ai_);
            json resp;
            resp["status"] = "ok";
            resp["manifest"] = json::parse(manifest.to_json());
            if (!send_msg(client, resp)) break;

        } else if (type == "get_chunk") {
            auto sess = get_session(cur_session_id);
            if (!sess) {
                json err;
                err["status"] = "error";
                err["message"] = "Unauthorized session";
                send_msg(client, err);
                break;
            }

            std::string rel_path = req.value("path", "");
            uint32_t chunk_idx = req.value("chunk_index", 0U);

            auto safe_path = platform::PathUtils::resolve_safe_path(workspace_root_, rel_path);
            if (!safe_path) {
                json err;
                err["status"] = "error";
                err["message"] = "Path traversal denied";
                audit_logger_.log(sess->identity, "TRAVERSAL_BLOCKED", rel_path, "Attempted directory escape", false);
                send_msg(client, err);
                continue;
            }

            auto file_data = platform::PathUtils::read_binary_file(*safe_path);
            if (!file_data) {
                json err;
                err["status"] = "error";
                err["message"] = "File not found";
                send_msg(client, err);
                continue;
            }

            auto chunks = sync::Chunker::chunk_buffer(*file_data);
            if (chunk_idx >= chunks.size()) {
                json err;
                err["status"] = "error";
                err["message"] = "Invalid chunk index";
                send_msg(client, err);
                continue;
            }

            const auto& ci = chunks[chunk_idx];
            std::span<const uint8_t> chunk_bytes(file_data->data() + ci.offset, ci.size);

            json resp;
            resp["status"] = "ok";
            resp["path"] = rel_path;
            resp["chunk_index"] = chunk_idx;
            resp["data_b64"] = core::Utils::to_base64(chunk_bytes);
            resp["blake3_hash"] = ci.blake3_hash;
            if (!send_msg(client, resp)) break;

        } else if (type == "push_file") {
            auto sess = get_session(cur_session_id);
            if (!sess || !sess->has_permission(core::Role::WRITE_ONLY)) {
                json err;
                err["status"] = "error";
                err["message"] = "Write permission denied (requires w or rw role)";
                audit_logger_.log(sess ? sess->identity : client.peer_endpoint().ip,
                                  "PUSH_DENIED", req.value("path", ""), "Insufficient role permission", false);
                send_msg(client, err);
                continue;
            }

            std::string dest_path = req.value("path", "");
            std::string b64_data = req.value("data_b64", "");
            auto data = core::Utils::from_base64(b64_data);

            auto safe_path = platform::PathUtils::resolve_safe_path(workspace_root_, dest_path);
            if (!safe_path) {
                json err;
                err["status"] = "error";
                err["message"] = "Path traversal denied";
                audit_logger_.log(sess->identity, "TRAVERSAL_BLOCKED", dest_path, "Path escape attempted on push", false);
                send_msg(client, err);
                continue;
            }

            bool written = platform::PathUtils::write_binary_file_atomic(*safe_path, data);
            json resp;
            if (written) {
                resp["status"] = "ok";
                resp["message"] = "File uploaded successfully";
                audit_logger_.log(sess->identity, "FILE_UPLOAD", dest_path, "Uploaded " + core::Utils::format_size(data.size()));
            } else {
                resp["status"] = "error";
                resp["message"] = "Failed to write file";
            }
            if (!send_msg(client, resp)) break;

        } else {
            json err;
            err["status"] = "error";
            err["message"] = "Unknown command type: " + type;
            send_msg(client, err);
        }
    }
}

} // namespace slug::net
