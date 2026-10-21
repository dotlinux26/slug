#include "src/net/control_server.hpp"
#include "src/net/web_server.hpp"
#include "src/net/protocol.hpp"
#include "src/net/aead_frame.hpp"
#include "src/ai/scanner.hpp"
#include "src/platform/fs.hpp"
#include "src/core/utils.hpp"
#include "third_party/json/json.hpp"
#include <iostream>
#include <fstream>

namespace slug::net {


using json = nlohmann::json;

ControlServer::ControlServer(std::filesystem::path workspace_root,
                             uint16_t port,
                             core::SuiteID suite_id,
                             uint64_t cert_ttl,
                             bool enable_ai,
                             core::FilterMode filter_mode,
                             core::FilterLevel filter_level,
                             core::AiModelProvider ai_provider,
                             uint32_t totp_step,
                             uint64_t workspace_ttl)
    : workspace_root_(std::move(workspace_root)),
      port_(port),
      suite_id_(suite_id),
      cert_ttl_(cert_ttl),
      enable_ai_(enable_ai),
      filter_mode_(filter_mode),
      filter_level_(filter_level),
      ai_provider_(ai_provider),
      totp_step_(totp_step > 0 ? totp_step : 60),
      workspace_ttl_(workspace_ttl),
      started_at_(core::Utils::current_timestamp()),
      totp_manager_(std::vector<uint8_t>{}, totp_step > 0 ? totp_step : 60),
      acl_manager_(workspace_root_ / ".slug" / "acl.db"),
      audit_logger_(workspace_root_ / ".slug" / "audit.log"),
      vfs_(workspace_root_, enable_ai_, filter_mode_) {

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
                      "Server started on port " + std::to_string(port_) + " with " + suite_->name() +
                      " (filter_mode=" + core::filter_mode_to_string(filter_mode_) + ")");
    if (filter_mode_ == core::FilterMode::NONE) {
        audit_logger_.log("host_admin", "HOST_SHARE_UNFILTERED", "",
                          "Workspace started with --filter-mode none (Content filtering disabled)", true);
    }
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
        if (!it->second.is_revoked) {
            if (it->second.expires_at == 0 || core::Utils::current_timestamp() < it->second.expires_at) {
                return it->second;
            }
        }
    }
    return std::nullopt;
}

std::optional<SessionState> ControlServer::find_session_by_ticket(const std::string& ticket) const {
    if (ticket.empty()) return std::nullopt;
    std::lock_guard<std::mutex> lock(session_mutex_);
    for (const auto& [id, s] : sessions_) {
        if (s.web_ticket == ticket) {
            if (!s.is_revoked) {
                if (s.expires_at == 0 || core::Utils::current_timestamp() < s.expires_at) {
                    return s;
                }
            }
        }
    }
    return std::nullopt;
}

std::string ControlServer::create_host_admin_ticket(uint64_t ttl_sec) {
    std::lock_guard<std::mutex> lock(session_mutex_);
    uint64_t now = core::Utils::current_timestamp();

    // Prune expired sessions to prevent unbounded memory growth
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (it->second.expires_at > 0 && it->second.expires_at < now) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }

    // Reuse existing active host_admin session to avoid accumulating duplicate admin sessions
    for (auto& [sid, ss] : sessions_) {
        if (ss.identity == "host_admin" && !ss.is_revoked && (ss.expires_at == 0 || ss.expires_at > now)) {
            ss.last_active_at = now;
            if (ttl_sec > 0) ss.expires_at = now + ttl_sec;
            return ss.web_ticket;
        }
    }

    uint32_t sid = next_session_id_++;
    std::string ticket = core::Utils::to_hex(core::Utils::random_bytes(24));
    SessionState ss;
    ss.session_id = sid;
    ss.role = core::Role::READ_WRITE;
    ss.expires_at = (ttl_sec == 0) ? 0 : (now + ttl_sec);
    ss.identity = "host_admin";
    ss.web_ticket = ticket;
    ss.auth_type = "Host Admin";
    ss.remote_endpoint = "127.0.0.1 (local)";
    ss.created_at = now;
    ss.last_active_at = now;
    ss.is_revoked = false;
    sessions_[sid] = ss;
    return ticket;
}

std::vector<SessionState> ControlServer::list_sessions() const {
    std::lock_guard<std::mutex> lock(session_mutex_);
    std::vector<SessionState> result;
    for (const auto& [id, s] : sessions_) {
        if (s.identity == "host_admin" || s.auth_type == "Host Admin") continue;
        result.push_back(s);
    }
    std::sort(result.begin(), result.end(), [](const SessionState& a, const SessionState& b) {
        return a.created_at > b.created_at;
    });
    return result;
}

bool ControlServer::revoke_session(uint32_t session_id) {
    std::string ticket_to_revoke;
    std::string ident;
    std::string auth_t;
    {
        std::lock_guard<std::mutex> lock(session_mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) return false;
        if (it->second.is_revoked) return true;
        it->second.is_revoked = true;
        ticket_to_revoke = it->second.web_ticket;
        ident = it->second.identity;
        auth_t = it->second.auth_type;
    }
    if (web_server_) {
        if (!ticket_to_revoke.empty()) {
            web_server_->revoke_session_by_ticket(ticket_to_revoke);
        }
        web_server_->revoke_sessions_by_identity(ident);
    }
    audit_logger_.log("host_admin", "SESSION_REVOKED", "session_" + std::to_string(session_id),
                      "Revoked " + auth_t + " session for " + ident);
    return true;
}

void ControlServer::revoke_sessions_by_identity(const std::string& identity) {
    if (identity.empty()) return;
    std::vector<uint32_t> sids;
    {
        std::lock_guard<std::mutex> lock(session_mutex_);
        for (auto& [id, s] : sessions_) {
            if (s.identity == identity && !s.is_revoked) {
                s.is_revoked = true;
                sids.push_back(id);
            }
        }
    }
    if (web_server_) {
        web_server_->revoke_sessions_by_identity(identity);
    }
    for (auto sid : sids) {
        audit_logger_.log("host_admin", "SESSION_REVOKED", "session_" + std::to_string(sid),
                          "Revoked session for user " + identity);
    }
}

void ControlServer::touch_session(uint32_t session_id) {
    if (session_id == 0) return;
    std::lock_guard<std::mutex> lock(session_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        if (!it->second.is_revoked) {
            it->second.last_active_at = core::Utils::current_timestamp();
        }
    }
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
    bool is_encrypted = false;
    SessionKeys session_keys;
    uint64_t server_tx_seq = 1;
    AntiReplaySlidingWindow c2s_window;
    std::vector<uint8_t> client_random;
    std::vector<uint8_t> server_random;

    auto send_packet = [&](const json& j) -> bool {
        if (is_encrypted) {
            std::string s = j.dump();
            std::span<const uint8_t> bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
            return AeadFrameChannel::send_frame(client, session_keys.session_key, session_keys.server_to_client_salt, server_tx_seq++, bytes);
        } else {
            return send_msg(client, j);
        }
    };

    while (running_ && client.is_valid()) {
        json req;
        if (is_encrypted) {
            auto dec = AeadFrameChannel::recv_frame(client, session_keys.session_key, session_keys.client_to_server_salt, c2s_window, 60000);
            if (!dec) break;
            try {
                std::string s(dec->begin(), dec->end());
                req = json::parse(s);
            } catch (...) {
                break;
            }
        } else {
            uint8_t hdr[4];
            if (!client.receive_exact(std::span<uint8_t>(hdr, 4), 60000)) {
                break;
            }

            // Check if incoming connection is an HTTP request (Web Server GUI / API)
            bool is_http = (hdr[0] == 'G' && hdr[1] == 'E' && hdr[2] == 'T' && hdr[3] == ' ') ||
                           (hdr[0] == 'H' && hdr[1] == 'E' && hdr[2] == 'A' && hdr[3] == ' ') ||
                           (hdr[0] == 'P' && hdr[1] == 'O' && hdr[2] == 'S' && hdr[3] == 'T');

            if (is_http) {
                if (web_server_) {
                    web_server_->handle_http_request(client, std::span<const uint8_t, 4>(hdr, 4));
                }
                break;
            }

            uint32_t len = (static_cast<uint32_t>(hdr[0]) << 24) |
                           (static_cast<uint32_t>(hdr[1]) << 16) |
                           (static_cast<uint32_t>(hdr[2]) << 8)  |
                            static_cast<uint32_t>(hdr[3]);

            if (len > 50 * 1024 * 1024) break;

            std::vector<uint8_t> body(len);
            if (!client.receive_exact(std::span<uint8_t>(body), 10000)) {
                break;
            }

            try {
                std::string s(body.begin(), body.end());
                req = json::parse(s);
            } catch (...) {
                break;
            }
        }

        std::string type = req.value("type", "");

        if (type == "client_hello") {
            client_random = core::Utils::from_hex(req.value("client_random", ""));
            server_random = core::Utils::random_bytes(32);

            json resp;
            resp["type"] = "server_hello";
            resp["suite_id"] = static_cast<uint8_t>(suite_id_);
            resp["suite_name"] = suite_->name();
            resp["server_random"] = core::Utils::to_hex(server_random);
            resp["server_kem_pub"] = core::Utils::to_hex(server_kem_.public_key);
            resp["server_sig_pub"] = core::Utils::to_hex(server_sig_.public_key);
            auto sig = suite_->sign(server_kem_.public_key, server_sig_.private_key);
            if (sig) {
                resp["server_sig"] = core::Utils::to_hex(*sig);
            }
            if (!send_packet(resp)) break;

        } else if (type == "kem_exchange") {
            auto ct = core::Utils::from_hex(req.value("ciphertext", ""));
            auto ss = suite_->decapsulate(ct, server_kem_.private_key);
            json resp;
            if (ss) {
                session_keys = SessionKeys::derive(*ss, client_random, server_random);
                resp["type"] = "kem_ok";
                resp["status"] = "ok";
                if (!send_packet(resp)) break;
                is_encrypted = true;
                server_tx_seq = 1;
            } else {
                resp["type"] = "kem_ok";
                resp["status"] = "error";
                send_packet(resp);
                break;
            }

        } else if (type == "auth_totp") {
            std::string code = req.value("code", "");
            auto role_opt = totp_manager_.verify_and_burn_role(code);

            json resp;
            if (role_opt.has_value()) {
                core::Role granted_role = *role_opt;
                uint32_t sid = 0;
                std::string ticket = core::Utils::to_hex(core::Utils::random_bytes(24));
                uint64_t now = core::Utils::current_timestamp();
                {
                    std::lock_guard<std::mutex> lock(session_mutex_);
                    sid = next_session_id_++;
                    SessionState ss;
                    ss.session_id = sid;
                    ss.role = granted_role;
                    ss.expires_at = (cert_ttl_ == 0) ? 0 : (now + cert_ttl_);
                    ss.identity = "totp_client_" + client.peer_endpoint().ip;
                    ss.web_ticket = ticket;
                    ss.auth_type = "TOTP";
                    ss.remote_endpoint = client.peer_endpoint().ip + ":" + std::to_string(client.peer_endpoint().port);
                    ss.created_at = now;
                    ss.last_active_at = now;
                    ss.is_revoked = false;
                    sessions_[sid] = ss;
                }
                cur_session_id = sid;
                resp["status"] = "ok";
                resp["session_id"] = sid;
                resp["role"] = core::role_to_string(granted_role);
                resp["ttl"] = cert_ttl_;
                resp["web_ticket"] = ticket;
                resp["workspace"] = workspace_root_.filename().string();
                resp["message"] = "Authenticated via TOTP (" + core::role_to_string(granted_role) + " role, token burned)";
                audit_logger_.log(client.peer_endpoint().ip, "AUTH_TOTP_SUCCESS", "", "TOTP verified (" + core::role_to_string(granted_role) + ") and burned");
            } else {
                resp["status"] = "error";
                resp["message"] = "Invalid or already burned TOTP token";
                audit_logger_.log(client.peer_endpoint().ip, "AUTH_TOTP_FAIL", "", "Invalid/burned TOTP: " + code, false);
            }
            if (!send_packet(resp)) break;

        } else if (type == "auth_user") {
            std::string u = req.value("username", "");
            std::string p = req.value("password", "");
            std::string r_str = req.value("role", "");
            std::optional<core::Role> req_role = std::nullopt;
            if (!r_str.empty() && r_str != "any" && r_str != "*") {
                req_role = core::role_from_string(r_str);
            }

            bool ok = acl_manager_.authenticate(u, p, req_role);
            json resp;
            if (ok) {
                auto acc_opt = acl_manager_.get_user(u);
                uint64_t now = core::Utils::current_timestamp();
                uint64_t ttl = 0;
                if (acc_opt && acc_opt->expires_at > 0) {
                    uint64_t rem = (acc_opt->expires_at > now) ? (acc_opt->expires_at - now) : 0;
                    ttl = (cert_ttl_ > 0) ? std::min(cert_ttl_, rem) : rem;
                } else {
                    ttl = cert_ttl_;
                }

                uint32_t sid = 0;
                std::string ticket = core::Utils::to_hex(core::Utils::random_bytes(24));
                {
                    std::lock_guard<std::mutex> lock(session_mutex_);
                    sid = next_session_id_++;
                    SessionState ss;
                    ss.session_id = sid;
                    ss.role = acc_opt ? acc_opt->role : core::Role::READ_ONLY;
                    ss.expires_at = (ttl == 0) ? 0 : (now + ttl);
                    ss.identity = u;
                    ss.web_ticket = ticket;
                    ss.auth_type = "Account";
                    ss.remote_endpoint = client.peer_endpoint().ip + ":" + std::to_string(client.peer_endpoint().port);
                    ss.created_at = now;
                    ss.last_active_at = now;
                    ss.is_revoked = false;
                    sessions_[sid] = ss;
                }
                cur_session_id = sid;
                resp["status"] = "ok";
                resp["session_id"] = sid;
                resp["role"] = core::role_to_string(sessions_[sid].role);
                resp["ttl"] = ttl;
                resp["web_ticket"] = ticket;
                resp["workspace"] = workspace_root_.filename().string();
                resp["message"] = "Authenticated via account " + u;
                audit_logger_.log(u, "AUTH_USER_SUCCESS", "", "Account logged in with role " + core::role_to_string(sessions_[sid].role));
            } else {
                resp["status"] = "error";
                resp["message"] = "Authentication failed (invalid credentials, role mismatch, or expired account)";
                audit_logger_.log(u.empty() ? client.peer_endpoint().ip : u, "AUTH_USER_FAIL", "", "Invalid credentials or expired", false);
            }
            if (!send_packet(resp)) break;

        } else if (type == "auth_ticket") {
            std::string ticket = req.value("ticket", "");
            auto sess_opt = find_session_by_ticket(ticket);
            json resp;
            if (sess_opt) {
                cur_session_id = sess_opt->session_id;
                {
                    std::lock_guard<std::mutex> lock(session_mutex_);
                    auto it = sessions_.find(cur_session_id);
                    if (it != sessions_.end()) {
                        it->second.last_active_at = core::Utils::current_timestamp();
                        it->second.remote_endpoint = client.peer_endpoint().ip + ":" + std::to_string(client.peer_endpoint().port);
                    }
                }
                resp["status"] = "ok";
                resp["session_id"] = sess_opt->session_id;
                resp["role"] = core::role_to_string(sess_opt->role);
                resp["ttl"] = (sess_opt->expires_at == 0) ? 0 : ((sess_opt->expires_at > core::Utils::current_timestamp()) ? (sess_opt->expires_at - core::Utils::current_timestamp()) : 0);
                resp["workspace"] = workspace_root_.filename().string();
                resp["message"] = "Authenticated via certificate ticket";
                audit_logger_.log(sess_opt->identity, "AUTH_TICKET_SUCCESS", "", "Ticket authenticated");
            } else {
                resp["status"] = "error";
                resp["message"] = "Invalid or expired session ticket";
                audit_logger_.log(client.peer_endpoint().ip, "AUTH_TICKET_FAIL", "", "Invalid ticket", false);
            }
            if (!send_packet(resp)) break;

        } else if (type == "get_manifest") {
            touch_session(cur_session_id);
            auto sess = get_session(cur_session_id);
            if (!sess) {
                json err;
                err["status"] = "error";
                err["message"] = "Unauthorized / expired session";
                send_packet(err);
                break;
            }

            std::string manifest_str = get_or_build_manifest_json();
            json resp;
            resp["status"] = "ok";
            resp["manifest"] = json::parse(manifest_str);
            if (!send_packet(resp)) break;

        } else if (type == "get_chunk") {
            touch_session(cur_session_id);
            auto sess = get_session(cur_session_id);
            if (!sess) {
                json err;
                err["status"] = "error";
                err["message"] = "Unauthorized session";
                send_packet(err);
                break;
            }

            std::string rel_path = req.value("path", "");
            uint32_t chunk_idx = req.value("chunk_index", 0U);

            // High-speed chunk server: check cache to avoid disk re-read and re-chunking
            std::vector<uint8_t> local_loaded_buf;
            std::span<const uint8_t> file_span;
            bool found_in_cache = false;
            {
                std::lock_guard<std::mutex> lk(chunk_cache_mutex_);
                auto it = chunk_file_cache_.find(rel_path);
                if (it != chunk_file_cache_.end()) {
                    found_in_cache = true;
                    file_span = it->second.data;
                    it->second.last_accessed = core::Utils::current_timestamp();
                }
            }

            if (!found_in_cache) {
                auto [vfs_st, file_data] = vfs_.read_file(rel_path, sess->role);
                if (vfs_st != core::VfsStatus::OK) {
                    json err;
                    err["status"] = "error";
                    err["message"] = core::vfs_status_to_string(vfs_st);
                    audit_logger_.log(sess->identity, "VFS_ACCESS_BLOCKED", rel_path, err["message"], false);
                    send_packet(err);
                    continue;
                }
                local_loaded_buf = std::move(file_data);
                file_span = local_loaded_buf;

                // Cache active file to serve all subsequent chunks without disk I/O
                if (local_loaded_buf.size() <= 100 * 1024 * 1024) {
                    std::lock_guard<std::mutex> lk(chunk_cache_mutex_);
                    if (chunk_file_cache_.size() >= 8) {
                        auto oldest = chunk_file_cache_.begin();
                        for (auto it = chunk_file_cache_.begin(); it != chunk_file_cache_.end(); ++it) {
                            if (it->second.last_accessed < oldest->second.last_accessed) {
                                oldest = it;
                            }
                        }
                        chunk_file_cache_.erase(oldest);
                    }
                    chunk_file_cache_[rel_path] = CachedChunkFile{rel_path, std::move(local_loaded_buf), core::Utils::current_timestamp()};
                    file_span = chunk_file_cache_[rel_path].data;
                }
            }

            uint64_t offset = static_cast<uint64_t>(chunk_idx) * sync::Chunker::kDefaultChunkSize;
            if (offset >= file_span.size() && !(offset == 0 && file_span.empty())) {
                json err;
                err["status"] = "error";
                err["message"] = "Invalid chunk index";
                send_packet(err);
                continue;
            }

            size_t chunk_len = (file_span.empty() || offset >= file_span.size()) ? 0 : std::min(static_cast<uint64_t>(sync::Chunker::kDefaultChunkSize), file_span.size() - offset);
            std::span<const uint8_t> chunk_bytes = file_span.empty() ? std::span<const uint8_t>{} : std::span<const uint8_t>(file_span.data() + offset, chunk_len);

            json resp;
            resp["status"] = "ok";
            resp["path"] = rel_path;
            resp["chunk_index"] = chunk_idx;
            resp["data_b64"] = core::Utils::to_base64(chunk_bytes);
            resp["blake3_hash"] = crypto::Blake3::hash_hex(chunk_bytes);
            if (!send_packet(resp)) break;

        } else if (type == "push_file") {
            touch_session(cur_session_id);
            auto sess = get_session(cur_session_id);
            if (!sess || !sess->has_permission(core::Role::WRITE_ONLY)) {
                json err;
                err["status"] = "error";
                err["message"] = "Write permission denied (requires w or rw role)";
                audit_logger_.log(sess ? sess->identity : client.peer_endpoint().ip,
                                  "PUSH_DENIED", req.value("path", ""), "Insufficient role permission", false);
                send_packet(err);
                continue;
            }

            std::string dest_path = req.value("path", "");
            std::string b64_data = req.value("data_b64", "");
            auto data = core::Utils::from_base64(b64_data);

            // AI Secret Guard inspection
            if (enable_ai_) {
                ai::AiScanner scanner;
                std::string text(data.begin(), data.end());
                auto finding = scanner.scan_content(dest_path, text);
                if (finding.has_secret) {
                    json err;
                    err["status"] = "error";
                    err["message"] = "AI Guard: Sensitive secret detected (" + finding.reason + "). Upload rejected.";
                    audit_logger_.log(sess->identity, "AI_REJECT", dest_path, finding.reason, false);
                    send_packet(err);
                    continue;
                }
            }

            auto vfs_st = vfs_.write_file(dest_path, data, sess->role);
            if (vfs_st != core::VfsStatus::OK) {
                json err;
                err["status"] = "error";
                err["message"] = "VFS error: " + core::vfs_status_to_string(vfs_st);
                send_packet(err);
                continue;
            }

            audit_logger_.log(sess->identity, "FILE_UPLOAD", dest_path, "Uploaded " + core::Utils::format_size(data.size()));
            invalidate_manifest_cache();
            json resp;
            resp["status"] = "ok";
            resp["path"] = dest_path;
            resp["bytes"] = data.size();
            if (!send_packet(resp)) break;

        } else if (type == "start_stream_pull") {
            touch_session(cur_session_id);
            auto sess = get_session(cur_session_id);
            if (!sess || !sess->has_permission(core::Role::READ_ONLY)) {
                json err;
                err["status"] = "error";
                err["message"] = "Unauthorized / expired session (read permission required)";
                audit_logger_.log(sess ? sess->identity : client.peer_endpoint().ip,
                                  "STREAM_PULL_DENIED", req.value("path", ""), "Permission denied", false);
                send_packet(err);
                continue;
            }

            std::string rel_path = req.value("path", "");
            uint32_t transfer_id = req.value("transfer_id", 1U);

            auto vres = vfs_.resolve_and_jail(rel_path, sess->role, false);
            if (!vres.is_ok()) {
                json err;
                err["status"] = "error";
                err["message"] = vres.error_message.empty() ? core::vfs_status_to_string(vres.status) : vres.error_message;
                audit_logger_.log(sess->identity, "VFS_ACCESS_BLOCKED", rel_path, err["message"], false);
                send_packet(err);
                continue;
            }

            std::error_code ec_sz;
            if (!std::filesystem::exists(vres.real_path, ec_sz) || std::filesystem::is_directory(vres.real_path, ec_sz)) {
                json err;
                err["status"] = "error";
                err["message"] = "Target file not found or is a directory";
                send_packet(err);
                continue;
            }

            uint64_t file_size = std::filesystem::file_size(vres.real_path, ec_sz);

            // Fetch or compute BLAKE3 hash
            std::string file_hash;
            {
                std::lock_guard<std::mutex> lk(manifest_mutex_);
                if (cached_manifest_) {
                    for (const auto& f : cached_manifest_->files) {
                        if (f.relative_path == rel_path) {
                            file_hash = f.file_blake3_hash;
                            break;
                        }
                    }
                }
            }
            if (file_hash.empty()) {
                auto h_opt = crypto::Blake3::hash_file(vres.real_path);
                if (h_opt) file_hash = *h_opt;
            }

            json resp;
            resp["status"] = "ok";
            resp["transfer_id"] = transfer_id;
            resp["file_size"] = file_size;
            resp["blake3_hash"] = file_hash;
            if (!send_packet(resp)) break;

            // Parse optional range requests (for delta sync)
            struct Range { uint64_t offset; uint64_t length; };
            std::vector<Range> ranges;
            if (req.contains("ranges") && req["ranges"].is_array() && !req["ranges"].empty()) {
                for (const auto& rj : req["ranges"]) {
                    uint64_t ro = rj.value("offset", 0ULL);
                    uint64_t rl = rj.value("length", 0ULL);
                    if (rl > 0 && ro < file_size) {
                        if (ro + rl > file_size) rl = file_size - ro;
                        ranges.push_back({ro, rl});
                    }
                }
            }
            if (ranges.empty()) {
                ranges.push_back({0ULL, file_size});
            }

            // Stream binary data frames directly from disk over AEAD
            std::ifstream src(vres.real_path, std::ios::binary);
            if (!src.is_open()) {
                StreamDataFrameHeader abort_hdr{};
                abort_hdr.magic = 0x53;
                abort_hdr.frame_type = static_cast<uint8_t>(StreamFrameType::ABORT);
                abort_hdr.transfer_id = transfer_id;
                std::span<const uint8_t> pt(reinterpret_cast<const uint8_t*>(&abort_hdr), sizeof(abort_hdr));
                AeadFrameChannel::send_frame(client, session_keys.session_key, session_keys.server_to_client_salt, server_tx_seq++, pt);
                continue;
            }

            bool stream_ok = true;
            uint64_t total_payload_sent = 0;
            std::vector<uint8_t> frame_buf(sizeof(StreamDataFrameHeader) + kStreamPayloadChunkSize);

            for (const auto& rng : ranges) {
                if (!stream_ok) break;
                src.seekg(static_cast<std::streamoff>(rng.offset), std::ios::beg);
                uint64_t range_bytes_sent = 0;

                while (range_bytes_sent < rng.length && stream_ok) {
                    size_t to_read = static_cast<size_t>(std::min<uint64_t>(kStreamPayloadChunkSize, rng.length - range_bytes_sent));
                    src.read(reinterpret_cast<char*>(frame_buf.data() + sizeof(StreamDataFrameHeader)), to_read);
                    std::streamsize actual = src.gcount();
                    if (actual <= 0) break;

                    StreamDataFrameHeader* phdr = reinterpret_cast<StreamDataFrameHeader*>(frame_buf.data());
                    phdr->magic = 0x53;
                    phdr->frame_type = static_cast<uint8_t>(StreamFrameType::DATA);
                    phdr->reserved = 0;
                    phdr->transfer_id = transfer_id;
                    phdr->offset = rng.offset + range_bytes_sent;
                    phdr->payload_len = static_cast<uint32_t>(actual);

                    std::span<const uint8_t> frame_span(frame_buf.data(), sizeof(StreamDataFrameHeader) + actual);
                    if (!AeadFrameChannel::send_frame(client, session_keys.session_key, session_keys.server_to_client_salt, server_tx_seq++, frame_span)) {
                        stream_ok = false;
                        break;
                    }
                    range_bytes_sent += actual;
                    total_payload_sent += actual;
                }
            }

            if (stream_ok) {
                // Send END_OF_STREAM frame carrying the full-file BLAKE3 hash
                std::vector<uint8_t> eos_buf(sizeof(StreamDataFrameHeader) + file_hash.size());
                StreamDataFrameHeader* peos = reinterpret_cast<StreamDataFrameHeader*>(eos_buf.data());
                peos->magic = 0x53;
                peos->frame_type = static_cast<uint8_t>(StreamFrameType::END_OF_STREAM);
                peos->reserved = 0;
                peos->transfer_id = transfer_id;
                peos->offset = file_size;
                peos->payload_len = static_cast<uint32_t>(file_hash.size());
                std::memcpy(eos_buf.data() + sizeof(StreamDataFrameHeader), file_hash.data(), file_hash.size());

                AeadFrameChannel::send_frame(client, session_keys.session_key, session_keys.server_to_client_salt, server_tx_seq++, eos_buf);
                audit_logger_.log(sess->identity, "STREAM_PULL", rel_path, "Streamed " + core::Utils::format_size(total_payload_sent));
            } else {
                break;
            }

        } else if (type == "start_stream_push") {
            touch_session(cur_session_id);
            auto sess = get_session(cur_session_id);
            if (!sess || !sess->has_permission(core::Role::WRITE_ONLY)) {
                json err;
                err["status"] = "error";
                err["message"] = "Write permission denied (requires w or rw role)";
                audit_logger_.log(sess ? sess->identity : client.peer_endpoint().ip,
                                  "PUSH_DENIED", req.value("path", ""), "Insufficient role permission", false);
                send_packet(err);
                continue;
            }

            std::string dest_path = req.value("path", "");
            uint32_t transfer_id = req.value("transfer_id", 1U);
            std::string expected_blake3_hash = req.value("blake3_hash", "");

            auto vres = vfs_.resolve_and_jail(dest_path, sess->role, true);
            if (!vres.is_ok()) {
                json err;
                err["status"] = "error";
                err["message"] = vres.error_message.empty() ? core::vfs_status_to_string(vres.status) : vres.error_message;
                audit_logger_.log(sess->identity, "PUSH_REJECTED", dest_path, err["message"], false);
                send_packet(err);
                continue;
            }

            // Create temp upload file in parent directory
            std::error_code ec_dir;
            std::filesystem::create_directories(vres.real_path.parent_path(), ec_dir);
            std::filesystem::path temp_upload_path = vres.real_path;
            temp_upload_path += ".slug_upload_tmp." + std::to_string(transfer_id);

            std::ofstream dst(temp_upload_path, std::ios::binary | std::ios::trunc);
            if (!dst.is_open()) {
                json err;
                err["status"] = "error";
                err["message"] = "Failed to open temporary destination file for writing";
                send_packet(err);
                continue;
            }

            json resp;
            resp["status"] = "ok";
            resp["transfer_id"] = transfer_id;
            if (!send_packet(resp)) {
                dst.close();
                std::filesystem::remove(temp_upload_path, ec_dir);
                break;
            }

            // Streaming receive loop
            crypto::Blake3Hasher hasher;
            uint64_t total_written = 0;
            bool upload_success = false;
            std::string error_msg;

            while (true) {
                auto dec = AeadFrameChannel::recv_frame(client, session_keys.session_key, session_keys.client_to_server_salt, c2s_window, 60000);
                if (!dec) {
                    error_msg = "Connection timeout or decryption error during streaming upload";
                    break;
                }
                if (dec->size() < sizeof(StreamDataFrameHeader)) {
                    error_msg = "Malformed stream frame header";
                    break;
                }

                StreamDataFrameHeader hdr;
                std::memcpy(&hdr, dec->data(), sizeof(StreamDataFrameHeader));
                if (hdr.magic != 0x53 || hdr.transfer_id != transfer_id) {
                    error_msg = "Stream frame header magic or transfer_id mismatch";
                    break;
                }

                if (hdr.frame_type == static_cast<uint8_t>(StreamFrameType::ABORT)) {
                    error_msg = "Upload aborted by client";
                    break;
                }

                if (hdr.frame_type == static_cast<uint8_t>(StreamFrameType::DATA)) {
                    if (dec->size() < sizeof(StreamDataFrameHeader) + hdr.payload_len) {
                        error_msg = "Truncated payload in stream data frame";
                        break;
                    }
                    const uint8_t* payload = dec->data() + sizeof(StreamDataFrameHeader);
                    dst.seekp(static_cast<std::streamoff>(hdr.offset), std::ios::beg);
                    dst.write(reinterpret_cast<const char*>(payload), hdr.payload_len);
                    hasher.update(payload, hdr.payload_len);
                    total_written += hdr.payload_len;
                } else if (hdr.frame_type == static_cast<uint8_t>(StreamFrameType::END_OF_STREAM)) {
                    dst.flush();
                    dst.close();

                    std::string computed_hash = crypto::Blake3::hash_file(temp_upload_path).value_or("");
                    if (!expected_blake3_hash.empty() && computed_hash != expected_blake3_hash) {
                        error_msg = "Integrity verification failed (BLAKE3 mismatch)";
                        break;
                    }

                    // AI Secret Guard inspection for text files if enabled
                    if (enable_ai_ && total_written < 10ULL * 1024 * 1024) {
                        ai::AiScanner scanner;
                        std::ifstream check_ifs(temp_upload_path, std::ios::binary);
                        std::string text_sample((std::istreambuf_iterator<char>(check_ifs)), std::istreambuf_iterator<char>());
                        auto finding = scanner.scan_content(dest_path, text_sample);
                        if (finding.has_secret) {
                            error_msg = "AI Guard: Sensitive secret detected (" + finding.reason + "). Upload rejected.";
                            audit_logger_.log(sess->identity, "AI_REJECT", dest_path, finding.reason, false);
                            break;
                        }
                    }

                    // Commit atomically: rename temp file to real destination
                    std::error_code ec_rename;
                    std::filesystem::rename(temp_upload_path, vres.real_path, ec_rename);
                    if (ec_rename) {
                        std::filesystem::copy_file(temp_upload_path, vres.real_path, std::filesystem::copy_options::overwrite_existing, ec_rename);
                        std::filesystem::remove(temp_upload_path, ec_rename);
                    }
                    upload_success = true;
                    break;
                }
            }

            if (dst.is_open()) {
                dst.close();
            }

            if (!upload_success) {
                std::filesystem::remove(temp_upload_path, ec_dir);
                json err;
                err["status"] = "error";
                err["message"] = error_msg.empty() ? "Streaming upload failed" : error_msg;
                send_packet(err);
            } else {
                invalidate_manifest_cache();
                json ok_resp;
                ok_resp["status"] = "ok";
                ok_resp["path"] = dest_path;
                ok_resp["bytes"] = total_written;
                audit_logger_.log(sess->identity, "FILE_UPLOAD", dest_path, "Stream uploaded " + core::Utils::format_size(total_written));
                if (!send_packet(ok_resp)) break;
            }

        } else if (type == "http_tunnel") {
            auto sess = get_session(cur_session_id);
            if (!sess) {
                json err_resp;
                err_resp["status"] = "error";
                err_resp["message"] = "Session revoked or expired";
                std::string err_html = "<html><head><title>401 Session Revoked</title></head><body style='font-family:sans-serif; text-align:center; padding:40px; background:#0d1117; color:#f85149;'><h1>401 Unauthorized</h1><p>Phiên làm việc đã bị Quản Trị Viên (Host Admin) thu hồi (Session Revoked).</p></body></html>";
                std::string http_err = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " +
                                       std::to_string(err_html.size()) + "\r\nConnection: close\r\nSet-Cookie: slug_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n\r\n" + err_html;
                err_resp["raw_resp_b64"] = core::Utils::to_base64(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(http_err.data()), http_err.size()));
                send_packet(err_resp);
                break;
            }
            touch_session(cur_session_id);
            std::string raw_b64 = req.value("raw_req_b64", "");
            auto raw_bytes = core::Utils::from_base64(raw_b64);
            std::string raw_req(raw_bytes.begin(), raw_bytes.end());

            std::vector<uint8_t> resp_bytes;
            if (web_server_) {
                resp_bytes = web_server_->handle_tunneled_http(raw_req, cur_session_id);
            } else {
                std::string err = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
                resp_bytes.assign(err.begin(), err.end());
            }

            json resp;
            resp["status"] = "ok";
            resp["raw_resp_b64"] = core::Utils::to_base64(resp_bytes);
            if (!send_packet(resp)) break;

        } else {
            json err;
            err["status"] = "error";
            err["message"] = "Unknown command type: " + type;
            send_packet(err);
        }
    }
}

sync::WorkspaceManifest ControlServer::get_or_build_manifest() {
    std::lock_guard<std::mutex> lock(manifest_mutex_);
    uint64_t now = core::Utils::current_timestamp();
    // Cache for at most 2 seconds (instead of 300s) so host filesystem changes are reflected immediately
    if (!manifest_dirty_ && cached_manifest_.has_value() && (now - manifest_cached_at_ < 2)) {
        return *cached_manifest_;
    }

    auto manifest = sync::ManifestBuilder::build(workspace_root_, 1, static_cast<uint8_t>(suite_id_), enable_ai_, filter_mode_, filter_level_, ai_provider_);
    cached_manifest_ = manifest;
    cached_manifest_json_ = manifest.to_json();
    manifest_cached_at_ = now;
    manifest_dirty_ = false;
    return manifest;
}

std::string ControlServer::get_or_build_manifest_json() {
    std::lock_guard<std::mutex> lock(manifest_mutex_);
    uint64_t now = core::Utils::current_timestamp();
    if (!manifest_dirty_ && !cached_manifest_json_.empty() && (now - manifest_cached_at_ < 5)) {
        return cached_manifest_json_;
    }

    auto manifest = sync::ManifestBuilder::build(workspace_root_, 1, static_cast<uint8_t>(suite_id_), enable_ai_, filter_mode_, filter_level_, ai_provider_);
    cached_manifest_ = manifest;
    cached_manifest_json_ = manifest.to_json();
    manifest_cached_at_ = now;
    manifest_dirty_ = false;
    return cached_manifest_json_;
}

void ControlServer::invalidate_manifest_cache() {
    std::lock_guard<std::mutex> lock(manifest_mutex_);
    manifest_dirty_ = true;
    cached_manifest_.reset();
    cached_manifest_json_.clear();
    vfs_.reload_policy();
}

} // namespace slug::net
