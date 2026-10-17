#include "src/net/web_server.hpp"
#include "src/net/web_assets.hpp"
#include "src/platform/fs.hpp"
#include "src/core/utils.hpp"
#include "src/sync/manifest.hpp"
#include "src/bench/benchmark.hpp"
#include "src/ai/scanner.hpp"
#include "src/ai/stateful_audit.hpp"
#include "src/policy/rules.hpp"
#include "third_party/json/json.hpp"
#include <sstream>
#include <iostream>
#include <algorithm>
#include <set>
#include <iomanip>

namespace slug::net {

using json = nlohmann::json;
namespace fs = std::filesystem;

WebServer::WebServer(ControlServer& control_server, uint16_t web_port)
    : control_server_(control_server), port_(web_port) {}

WebServer::~WebServer() {
    stop();
}

bool WebServer::start() {
    if (running_) return true;

    if (port_ == control_server_.port()) {
        running_ = true;
        return true;
    }

    if (!listener_.bind_and_listen("0.0.0.0", port_)) {
        return false;
    }
    port_ = listener_.bound_port();

    running_ = true;
    worker_thread_ = std::make_unique<std::thread>(&WebServer::run_accept_loop, this);
    return true;
}

void WebServer::stop() {
    if (!running_) return;
    running_ = false;
    listener_.close();
    if (worker_thread_ && worker_thread_->joinable()) {
        worker_thread_->join();
    }
}

void WebServer::run_accept_loop() {
    while (running_) {
        auto client_opt = listener_.accept(500);
        if (client_opt) {
            std::thread([this, sock = std::move(*client_opt)]() mutable {
                handle_http_client(std::move(sock));
            }).detach();
        }
    }
}

static std::string url_decode(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            int value;
            std::istringstream is(in.substr(i + 1, 2));
            if (is >> std::hex >> value) {
                out += static_cast<char>(value);
                i += 2;
            } else {
                out += in[i];
            }
        } else if (in[i] == '+') {
            out += ' ';
        } else {
            out += in[i];
        }
    }
    return out;
}

static std::string get_query_param(const std::string& query, const std::string& key) {
    std::string search = key + "=";
    size_t pos = query.find(search);
    if (pos == std::string::npos) return "";
    size_t val_start = pos + search.size();
    size_t val_end = query.find('&', val_start);
    std::string val = (val_end == std::string::npos) ? query.substr(val_start) : query.substr(val_start, val_end - val_start);
    return url_decode(val);
}

static uint32_t calculate_crc32(std::span<const uint8_t> data) {
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320u : 0u);
        }
    }
    return ~crc;
}

static std::vector<uint8_t> build_zip_archive(const std::vector<std::pair<std::string, std::vector<uint8_t>>>& files) {
    std::vector<uint8_t> zip;
    struct ZipMeta {
        std::string filename;
        uint32_t crc{0};
        uint32_t size{0};
        uint32_t local_hdr_offset{0};
    };
    std::vector<ZipMeta> meta_list;

    for (const auto& [fname, data] : files) {
        ZipMeta m;
        std::string clean_fn = fname;
        std::replace(clean_fn.begin(), clean_fn.end(), '\\', '/');
        while (!clean_fn.empty() && clean_fn.front() == '/') clean_fn.erase(0, 1);
        fs::path p_test(clean_fn);
        std::string safe_fn;
        for (const auto& comp : p_test) {
            std::string c_str = comp.string();
            if (c_str == ".." || c_str == "." || c_str.empty()) continue;
            if (!safe_fn.empty()) safe_fn += "/";
            safe_fn += c_str;
        }
        m.filename = safe_fn.empty() ? "file" : safe_fn;
        m.crc = calculate_crc32(data);
        m.size = static_cast<uint32_t>(data.size());
        m.local_hdr_offset = static_cast<uint32_t>(zip.size());

        uint8_t lh[30] = {0};
        lh[0] = 0x50; lh[1] = 0x4b; lh[2] = 0x03; lh[3] = 0x04; // PK\x03\x04
        lh[4] = 20; lh[5] = 0; // version 2.0
        lh[14] = static_cast<uint8_t>(m.crc & 0xFF);
        lh[15] = static_cast<uint8_t>((m.crc >> 8) & 0xFF);
        lh[16] = static_cast<uint8_t>((m.crc >> 16) & 0xFF);
        lh[17] = static_cast<uint8_t>((m.crc >> 24) & 0xFF);

        lh[18] = static_cast<uint8_t>(m.size & 0xFF);
        lh[19] = static_cast<uint8_t>((m.size >> 8) & 0xFF);
        lh[20] = static_cast<uint8_t>((m.size >> 16) & 0xFF);
        lh[21] = static_cast<uint8_t>((m.size >> 24) & 0xFF);

        lh[22] = lh[18]; lh[23] = lh[19]; lh[24] = lh[20]; lh[25] = lh[21]; // uncompressed = compressed (store mode)

        uint16_t fn_len = static_cast<uint16_t>(m.filename.size());
        lh[26] = static_cast<uint8_t>(fn_len & 0xFF);
        lh[27] = static_cast<uint8_t>((fn_len >> 8) & 0xFF);

        zip.insert(zip.end(), lh, lh + 30);
        zip.insert(zip.end(), m.filename.begin(), m.filename.end());
        zip.insert(zip.end(), data.begin(), data.end());

        meta_list.push_back(m);
    }

    uint32_t cd_offset = static_cast<uint32_t>(zip.size());
    for (const auto& m : meta_list) {
        uint8_t cdh[46] = {0};
        cdh[0] = 0x50; cdh[1] = 0x4b; cdh[2] = 0x01; cdh[3] = 0x02; // PK\x01\x02
        cdh[4] = 20; cdh[5] = 0;
        cdh[6] = 20; cdh[7] = 0;
        cdh[16] = static_cast<uint8_t>(m.crc & 0xFF);
        cdh[17] = static_cast<uint8_t>((m.crc >> 8) & 0xFF);
        cdh[18] = static_cast<uint8_t>((m.crc >> 16) & 0xFF);
        cdh[19] = static_cast<uint8_t>((m.crc >> 24) & 0xFF);

        cdh[20] = static_cast<uint8_t>(m.size & 0xFF);
        cdh[21] = static_cast<uint8_t>((m.size >> 8) & 0xFF);
        cdh[22] = static_cast<uint8_t>((m.size >> 16) & 0xFF);
        cdh[23] = static_cast<uint8_t>((m.size >> 24) & 0xFF);

        cdh[24] = cdh[20]; cdh[25] = cdh[21]; cdh[26] = cdh[22]; cdh[27] = cdh[23];

        uint16_t fn_len = static_cast<uint16_t>(m.filename.size());
        cdh[28] = static_cast<uint8_t>(fn_len & 0xFF);
        cdh[29] = static_cast<uint8_t>((fn_len >> 8) & 0xFF);

        cdh[42] = static_cast<uint8_t>(m.local_hdr_offset & 0xFF);
        cdh[43] = static_cast<uint8_t>((m.local_hdr_offset >> 8) & 0xFF);
        cdh[44] = static_cast<uint8_t>((m.local_hdr_offset >> 16) & 0xFF);
        cdh[45] = static_cast<uint8_t>((m.local_hdr_offset >> 24) & 0xFF);

        zip.insert(zip.end(), cdh, cdh + 46);
        zip.insert(zip.end(), m.filename.begin(), m.filename.end());
    }

    uint32_t cd_size = static_cast<uint32_t>(zip.size() - cd_offset);
    uint16_t total_entries = static_cast<uint16_t>(meta_list.size());

    uint8_t eocd[22] = {0};
    eocd[0] = 0x50; eocd[1] = 0x4b; eocd[2] = 0x05; eocd[3] = 0x06; // PK\x05\x06
    eocd[8] = static_cast<uint8_t>(total_entries & 0xFF);
    eocd[9] = static_cast<uint8_t>((total_entries >> 8) & 0xFF);
    eocd[10] = eocd[8]; eocd[11] = eocd[9];
    eocd[12] = static_cast<uint8_t>(cd_size & 0xFF);
    eocd[13] = static_cast<uint8_t>((cd_size >> 8) & 0xFF);
    eocd[14] = static_cast<uint8_t>((cd_size >> 16) & 0xFF);
    eocd[15] = static_cast<uint8_t>((cd_size >> 24) & 0xFF);
    eocd[16] = static_cast<uint8_t>(cd_offset & 0xFF);
    eocd[17] = static_cast<uint8_t>((cd_offset >> 8) & 0xFF);
    eocd[18] = static_cast<uint8_t>((cd_offset >> 16) & 0xFF);
    eocd[19] = static_cast<uint8_t>((cd_offset >> 24) & 0xFF);

    zip.insert(zip.end(), eocd, eocd + 22);
    return zip;
}

std::optional<WebSession> WebServer::validate_session(const std::string& token) {
    if (token.empty()) return std::nullopt;
    std::lock_guard<std::mutex> lock(session_mutex_);
    auto it = sessions_.find(token);
    if (it == sessions_.end()) return std::nullopt;
    uint64_t now = core::Utils::current_timestamp();
    if (it->second.expires_at > 0 && it->second.expires_at < now) {
        sessions_.erase(it);
        return std::nullopt;
    }
    if (!it->second.ticket.empty()) {
        auto cs = control_server_.find_session_by_ticket(it->second.ticket);
        if (!cs) {
            sessions_.erase(it);
            return std::nullopt;
        }
        control_server_.touch_session(cs->session_id);
    }
    return it->second;
}

std::string WebServer::create_session(const std::string& identity, core::Role role, uint64_t ttl_sec, const std::string& ticket) {
    std::string token = core::Utils::to_hex(core::Utils::random_bytes(24));
    WebSession s;
    s.token = token;
    s.identity = identity;
    s.role = role;
    s.expires_at = (ttl_sec == 0) ? 0 : core::Utils::current_timestamp() + ttl_sec;
    s.ticket = ticket;
    std::lock_guard<std::mutex> lock(session_mutex_);
    sessions_[token] = s;
    return token;
}

void WebServer::destroy_session(const std::string& token) {
    std::lock_guard<std::mutex> lock(session_mutex_);
    sessions_.erase(token);
}

void WebServer::revoke_session_by_ticket(const std::string& ticket) {
    if (ticket.empty()) return;
    std::lock_guard<std::mutex> lock(session_mutex_);
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (it->second.ticket == ticket) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string WebServer::render_directory_listing(const std::string& rel_subpath, const WebSession& session) {
    auto manifest = control_server_.get_or_build_manifest();
    return WebAssets::render_directory_listing(
        control_server_.workspace_root(),
        control_server_.port(),
        control_server_.suite_id(),
        rel_subpath,
        session.identity,
        session.role,
        manifest
    );
}

std::string WebServer::render_admin_dashboard(const WebSession& session) {
    auto users = control_server_.acl_manager().list_users();
    auto events = control_server_.audit_logger().read_recent_events(25);
    auto bench_rep = bench::BenchmarkEngine::get_latest_report();

    fs::path rules_file = control_server_.workspace_root() / ".slug" / "rules.conf";
    policy::RulesManager rules_mgr(rules_file);
    const auto& rules = rules_mgr.rules();

    fs::path idx_file = control_server_.workspace_root() / ".slug" / "index.db";
    ai::StatefulAuditIndex audit_idx(idx_file);
    auto audit_entries = audit_idx.list_flagged_or_all(false);

    auto client_sessions = control_server_.list_sessions();

    return WebAssets::render_admin_dashboard(
        control_server_.workspace_root(),
        control_server_.port(),
        control_server_.suite_id(),
        control_server_.ai_enabled(),
        session.identity,
        users,
        events,
        bench_rep,
        rules,
        audit_entries,
        client_sessions
    );
}

void WebServer::dispatch_http(platform::TcpSocket& client, const HttpRequest& req) {
    auto send_raw = [&](const std::string& res) {
        client.send_all(res);
    };
    dispatch_http_core(req, send_raw, client.peer_endpoint().ip, 0);
}

void WebServer::dispatch_http_core(const HttpRequest& req, std::function<void(const std::string&)> send_raw, const std::string& peer_ip, uint32_t tunneled_session_id) {
    std::string method = req.method;
    std::string path = req.path;

    // Check for ticket query param to authenticate session automatically
    std::string ticket = get_query_param(req.query, "ticket");
    std::string session_cookie = req.session_token;
    std::string new_session_token = "";

    std::optional<WebSession> current_session = validate_session(session_cookie);

    if (!current_session && tunneled_session_id > 0) {
        auto cs = control_server_.get_session(tunneled_session_id);
        if (cs && !cs->is_revoked) {
            WebSession ws;
            ws.token = "tunneled_" + std::to_string(tunneled_session_id);
            ws.identity = cs->identity;
            ws.role = cs->role;
            ws.expires_at = cs->expires_at;
            ws.ticket = cs->web_ticket;
            current_session = ws;
        }
    }

    if (!current_session && !ticket.empty()) {
        auto sess_opt = control_server_.find_session_by_ticket(ticket);
        if (sess_opt) {
            new_session_token = create_session(sess_opt->identity, sess_opt->role, 14400, ticket);
            current_session = validate_session(new_session_token);
        }
    }

    auto send_resp = [&](int status_code, const std::string& status_text, const std::string& ctype, const std::string& body, const std::string& extra_headers = "") {
        std::string res = "HTTP/1.1 " + std::to_string(status_code) + " " + status_text + "\r\n" +
                          "Content-Type: " + ctype + "\r\n" +
                          "Content-Length: " + std::to_string(body.size()) + "\r\n" +
                          "Connection: close\r\n";
        if (!new_session_token.empty()) {
            res += "Set-Cookie: slug_session=" + new_session_token + "; Path=/; HttpOnly; SameSite=Strict\r\n";
        }
        if (!extra_headers.empty()) {
            res += extra_headers;
        }
        res += "\r\n" + body;
        send_raw(res);
    };

    // Logout endpoint
    if (path == "/logout") {
        if (!session_cookie.empty()) {
            destroy_session(session_cookie);
        }
        std::string body = WebAssets::render_forbidden_page("You have been logged out of the workspace session.");
        send_resp(200, "OK", "text/html; charset=utf-8", body, "Set-Cookie: slug_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n");
        return;
    }

    // Local loopback status query for host CLI (slug status, slug totp, slug web)
    bool is_localhost = (peer_ip == "127.0.0.1" || peer_ip == "::1" || tunneled_session_id > 0);
    if (path == "/api/status" && is_localhost) {
        json j;
        j["port"] = control_server_.port();
        j["suite"] = core::suite_to_string(control_server_.suite_id());
        j["workspace"] = control_server_.workspace_root().string();
        j["workspace_name"] = control_server_.workspace_root().filename().string();
        j["totp_r"] = control_server_.totp_manager().generate_code(core::Role::READ_ONLY);
        j["totp_w"] = control_server_.totp_manager().generate_code(core::Role::WRITE_ONLY);
        j["totp_rw"] = control_server_.totp_manager().generate_code(core::Role::READ_WRITE);
        j["totp"] = j["totp_rw"];
        j["totp_remaining_sec"] = control_server_.totp_manager().remaining_seconds();
        j["totp_step_sec"] = slug::crypto::TotpManager::kStepSeconds;
        j["admin_ticket"] = control_server_.create_host_admin_ticket();
        j["ai_enabled"] = control_server_.ai_enabled();
        j["ttl_seconds"] = control_server_.cert_ttl();

        json s_arr = json::array();
        uint64_t now_ts = core::Utils::current_timestamp();
        for (const auto& s : control_server_.list_sessions()) {
            if (s.identity == "host_admin" || s.auth_type == "Host Admin") continue;
            json item;
            item["session_id"] = s.session_id;
            item["id"] = std::to_string(s.session_id);
            item["identity"] = s.identity;
            item["name"] = s.identity;
            item["auth_type"] = s.auth_type;
            item["role"] = core::role_to_string(s.role);
            item["authType"] = s.auth_type + " [" + core::role_to_string(s.role) + "]";
            item["remote_endpoint"] = s.remote_endpoint;
            item["ip"] = s.remote_endpoint;
            item["suite"] = core::suite_to_string(control_server_.suite_id());
            item["created_at"] = s.created_at;
            item["connectedAt"] = core::Utils::format_timestamp(s.created_at);
            item["last_active_at"] = s.last_active_at;
            item["expires_at"] = s.expires_at;
            item["transferred"] = "Active (Live)";
            item["remaining_sec"] = (s.expires_at > now_ts) ? (s.expires_at - now_ts) : 0;
            item["is_revoked"] = s.is_revoked;
            item["is_expired"] = (s.expires_at > 0 && s.expires_at <= now_ts);
            item["is_active"] = s.is_active(now_ts);
            item["status"] = s.is_revoked ? "REVOKED" : ((s.expires_at > 0 && s.expires_at <= now_ts) ? "EXPIRED" : "ACTIVE");
            s_arr.push_back(item);
        }
        j["sessions"] = s_arr;

        send_resp(200, "OK", "application/json", j.dump(2));
        return;
    }

    // STRICT GATEKEEPER: If not authenticated and not localhost loopback, reject immediately!
    if (!current_session && !is_localhost) {
        std::string body = WebAssets::render_forbidden_page("Mutual Post-Quantum Certificate / Session Ticket Required.");
        send_resp(403, "Forbidden", "text/html; charset=utf-8", body);
        return;
    }

    // If accessing from localhost loopback without an explicit ticket, treat as local host_admin
    if (!current_session && is_localhost) {
        WebSession local_admin_session;
        local_admin_session.identity = "host_admin";
        local_admin_session.role = core::Role::READ_WRITE;
        local_admin_session.token = "local_admin";
        local_admin_session.expires_at = 0;
        current_session = local_admin_session;
    }

    // Authenticated endpoints:
    if (path == "/" || path == "/drop") {
        std::string rel_dir = get_query_param(req.query, "dir");
        std::string body = render_directory_listing(rel_dir, *current_session);
        send_resp(200, "OK", "text/html; charset=utf-8", body);
        return;
    }

    if (path == "/admin") {
        if (current_session->identity != "host_admin") {
            std::string body = WebAssets::render_forbidden_page("Permission Denied: Admin dashboard is restricted strictly to the workspace host administrator.");
            send_resp(403, "Forbidden", "text/html; charset=utf-8", body);
            return;
        }
        std::string body = render_admin_dashboard(*current_session);
        send_resp(200, "OK", "text/html; charset=utf-8", body);
        return;
    }

    if (path == "/api/status") {
        json j;
        j["port"] = control_server_.port();
        j["suite"] = core::suite_to_string(control_server_.suite_id());
        j["workspace"] = control_server_.workspace_root().string();
        j["role"] = core::role_to_string(current_session->role);
        j["identity"] = current_session->identity;
        send_resp(200, "OK", "application/json", j.dump(2));
        return;
    }

    if (path == "/api/bench/run") {
        if (current_session->identity != "host_admin") {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\",\"message\":\"Admin privilege required\"}");
            return;
        }
        auto rep = bench::BenchmarkEngine::run_all(true);
        send_resp(200, "OK", "application/json", rep.to_json().dump(2));
        return;
    }

    if (path == "/api/admin/sessions") {
        if (current_session->identity != "host_admin" && !is_localhost) {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        auto sessions = control_server_.list_sessions();
        uint64_t now_ts = core::Utils::current_timestamp();
        json arr = json::array();
        for (const auto& s : sessions) {
            json item;
            item["session_id"] = s.session_id;
            item["identity"] = s.identity;
            item["auth_type"] = s.auth_type;
            item["role"] = core::role_to_string(s.role);
            item["remote_endpoint"] = s.remote_endpoint;
            item["created_at"] = s.created_at;
            item["last_active_at"] = s.last_active_at;
            item["expires_at"] = s.expires_at;
            item["remaining_sec"] = (s.expires_at > now_ts) ? (s.expires_at - now_ts) : 0;
            item["is_revoked"] = s.is_revoked;
            item["is_expired"] = (s.expires_at > 0 && s.expires_at <= now_ts);
            item["is_active"] = s.is_active(now_ts);
            item["status"] = s.is_revoked ? "REVOKED" : ((s.expires_at > 0 && s.expires_at <= now_ts) ? "EXPIRED" : "ACTIVE");
            arr.push_back(item);
        }
        send_resp(200, "OK", "application/json", arr.dump(2));
        return;
    }

    if (path == "/api/admin/sessions/revoke" && method == "POST") {
        if (current_session->identity != "host_admin" && !is_localhost) {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        try {
            auto j = json::parse(req.body);
            uint32_t sid = j.value("session_id", 0U);
            if (sid == 0) {
                send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"session_id required\"}");
                return;
            }
            bool ok = control_server_.revoke_session(sid);
            if (ok) {
                send_resp(200, "OK", "application/json", "{\"status\":\"ok\",\"message\":\"Session revoked\"}");
            } else {
                send_resp(404, "Not Found", "application/json", "{\"status\":\"error\",\"message\":\"Session not found\"}");
            }
        } catch (...) {
            send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Invalid JSON body\"}");
        }
        return;
    }

    if (path == "/api/admin/users") {
        if (current_session->identity != "host_admin") {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        auto users = control_server_.acl_manager().list_users();
        uint64_t now = core::Utils::current_timestamp();
        json arr = json::array();
        for (const auto& u : users) {
            json item;
            item["username"] = u.username;
            item["role"] = core::role_to_string(u.role);
            item["created_at"] = u.created_at;
            item["expires_at"] = u.expires_at;
            item["is_expired"] = u.is_expired(now);
            item["remaining_sec"] = (u.expires_at > now) ? (u.expires_at - now) : 0;
            arr.push_back(item);
        }
        send_resp(200, "OK", "application/json", arr.dump(2));
        return;
    }

    if (path == "/api/admin/users/add" && method == "POST") {
        if (current_session->identity != "host_admin") {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        try {
            auto j = json::parse(req.body);
            std::string u = j.value("username", "");
            std::string p = j.value("password", "");
            std::string r_str = j.value("role", "r");
            uint64_t ttl = j.value("ttl_sec", 86400ULL);
            if (u.empty() || p.empty()) {
                send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Username and password required\"}");
                return;
            }
            core::Role role = core::role_from_string(r_str);
            bool ok = control_server_.acl_manager().add_user(u, p, role, ttl);
            if (ok) {
                control_server_.audit_logger().log(current_session->identity, "USER_ADD", u, "Created user role=" + r_str);
                send_resp(200, "OK", "application/json", "{\"status\":\"ok\",\"message\":\"User created successfully\"}");
            } else {
                send_resp(500, "Error", "application/json", "{\"status\":\"error\",\"message\":\"Failed to add user\"}");
            }
        } catch (...) {
            send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Invalid JSON body\"}");
        }
        return;
    }

    if (path == "/api/admin/users/update" && method == "POST") {
        if (current_session->identity != "host_admin") {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        try {
            auto j = json::parse(req.body);
            std::string u = j.value("username", "");
            std::string p = j.value("password", "");
            std::optional<core::Role> role = std::nullopt;
            if (j.contains("role") && !j["role"].get<std::string>().empty()) {
                role = core::role_from_string(j["role"].get<std::string>());
            }
            std::optional<uint64_t> ttl = std::nullopt;
            if (j.contains("ttl_sec")) {
                int64_t raw_ttl = j["ttl_sec"].get<int64_t>();
                if (raw_ttl >= 0) {
                    ttl = static_cast<uint64_t>(raw_ttl);
                }
            }
            if (u.empty()) {
                send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Username required\"}");
                return;
            }
            bool ok = control_server_.acl_manager().update_user(u, p, role, ttl);
            if (ok) {
                control_server_.audit_logger().log(current_session->identity, "USER_UPDATE", u, "Updated user settings");
                send_resp(200, "OK", "application/json", "{\"status\":\"ok\",\"message\":\"User updated successfully\"}");
            } else {
                send_resp(404, "Not Found", "application/json", "{\"status\":\"error\",\"message\":\"User not found\"}");
            }
        } catch (...) {
            send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Invalid JSON body\"}");
        }
        return;
    }

    if (path == "/api/admin/users/delete" && method == "POST") {
        if (current_session->identity != "host_admin") {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        try {
            auto j = json::parse(req.body);
            std::string u = j.value("username", "");
            if (u.empty()) {
                send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Username required\"}");
                return;
            }
            bool ok = control_server_.acl_manager().remove_user(u);
            if (ok) {
                control_server_.audit_logger().log(current_session->identity, "USER_DELETE", u, "Removed user");
                send_resp(200, "OK", "application/json", "{\"status\":\"ok\",\"message\":\"User removed successfully\"}");
            } else {
                send_resp(404, "Not Found", "application/json", "{\"status\":\"error\",\"message\":\"User not found\"}");
            }
        } catch (...) {
            send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Invalid JSON body\"}");
        }
        return;
    }

    // Security Rules Endpoints
    if (path == "/api/admin/rules") {
        if (current_session->identity != "host_admin") {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        fs::path rules_file = control_server_.workspace_root() / ".slug" / "rules.conf";
        policy::RulesManager mgr(rules_file);
        json arr = json::array();
        for (const auto& r : mgr.rules()) {
            json item;
            item["id"] = r.id;
            item["action"] = (r.action == policy::RuleAction::ALLOW) ? "ALLOW" : "BLOCK";
            std::string t_str;
            switch (r.type) {
                case policy::RuleType::PATH: t_str = "path"; break;
                case policy::RuleType::EXT: t_str = "ext"; break;
                case policy::RuleType::CONTENT: t_str = "content"; break;
                case policy::RuleType::REGEX: t_str = "regex"; break;
            }
            item["type"] = t_str;
            item["value"] = r.value;
            arr.push_back(item);
        }
        send_resp(200, "OK", "application/json", arr.dump(2));
        return;
    }

    if (path == "/api/admin/rules/add" && method == "POST") {
        if (current_session->identity != "host_admin") {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        try {
            auto j = json::parse(req.body);
            std::string id = j.value("id", "");
            std::string act_str = j.value("action", "block");
            std::string type_str = j.value("type", "path");
            std::string val = j.value("value", "");
            if (val.empty()) {
                send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Pattern or value required\"}");
                return;
            }
            policy::RuleAction act = (act_str == "allow") ? policy::RuleAction::ALLOW : policy::RuleAction::BLOCK;
            policy::RuleType type = policy::RuleType::PATH;
            if (type_str == "ext") type = policy::RuleType::EXT;
            else if (type_str == "content") type = policy::RuleType::CONTENT;
            else if (type_str == "regex") type = policy::RuleType::REGEX;

            fs::path rules_file = control_server_.workspace_root() / ".slug" / "rules.conf";
            policy::RulesManager mgr(rules_file);
            if (mgr.add_rule(id, act, type, val)) {
                control_server_.audit_logger().log(current_session->identity, "RULE_ADD", val, "Added " + act_str + " rule");
                send_resp(200, "OK", "application/json", "{\"status\":\"ok\",\"message\":\"Rule added successfully\"}");
            } else {
                send_resp(500, "Error", "application/json", "{\"status\":\"error\",\"message\":\"Failed to save rule\"}");
            }
        } catch (...) {
            send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Invalid JSON body\"}");
        }
        return;
    }

    if (path == "/api/admin/rules/delete" && method == "POST") {
        if (current_session->identity != "host_admin") {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        try {
            auto j = json::parse(req.body);
            std::string id = j.value("id", "");
            if (id.empty()) {
                send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Rule ID required\"}");
                return;
            }
            fs::path rules_file = control_server_.workspace_root() / ".slug" / "rules.conf";
            policy::RulesManager mgr(rules_file);
            if (mgr.remove_rule(id)) {
                control_server_.audit_logger().log(current_session->identity, "RULE_DELETE", id, "Removed rule");
                send_resp(200, "OK", "application/json", "{\"status\":\"ok\",\"message\":\"Rule removed successfully\"}");
            } else {
                send_resp(404, "Not Found", "application/json", "{\"status\":\"error\",\"message\":\"Rule not found\"}");
            }
        } catch (...) {
            send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Invalid JSON body\"}");
        }
        return;
    }

    // AI Guard Audit Endpoints
    if (path == "/api/admin/audit") {
        if (current_session->identity != "host_admin") {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        fs::path idx_file = control_server_.workspace_root() / ".slug" / "index.db";
        ai::StatefulAuditIndex audit_idx(idx_file);
        auto list = audit_idx.list_flagged_or_all(false);
        json arr = json::array();
        for (const auto& e : list) {
            json item;
            item["file_path"] = e.file_path;
            item["status"] = core::audit_status_to_string(e.status);
            item["line_number"] = e.line_number;
            item["reason"] = e.reason;
            item["scanned_at"] = e.scanned_at;
            item["decision_actor"] = e.decision_actor;
            item["decision_reason"] = e.decision_reason;
            arr.push_back(item);
        }
        send_resp(200, "OK", "application/json", arr.dump(2));
        return;
    }

    if (path == "/api/admin/audit/allow" && method == "POST") {
        if (current_session->identity != "host_admin") {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        try {
            auto j = json::parse(req.body);
            std::string p = j.value("path", "");
            std::string reason = j.value("reason", "Verified false positive");
            if (p.empty()) {
                send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"File path required\"}");
                return;
            }
            fs::path idx_file = control_server_.workspace_root() / ".slug" / "index.db";
            ai::StatefulAuditIndex audit_idx(idx_file);
            if (audit_idx.allow_file(p, reason, current_session->identity)) {
                control_server_.audit_logger().log(current_session->identity, "AUDIT_ALLOW", p, "Whitelisted false positive: " + reason);
                control_server_.invalidate_manifest_cache();
                send_resp(200, "OK", "application/json", "{\"status\":\"ok\",\"message\":\"File whitelisted successfully\"}");
            } else {
                send_resp(500, "Error", "application/json", "{\"status\":\"error\",\"message\":\"Failed to update audit index\"}");
            }
        } catch (...) {
            send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Invalid JSON body\"}");
        }
        return;
    }

    if (path == "/api/admin/audit/allow-all" && method == "POST") {
        if (current_session->identity != "host_admin") {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        fs::path idx_file = control_server_.workspace_root() / ".slug" / "index.db";
        ai::StatefulAuditIndex audit_idx(idx_file);
        auto flagged = audit_idx.list_flagged_or_all(true);
        int count = 0;
        for (const auto& item : flagged) {
            if (audit_idx.allow_file(item.file_path, "Admin batch whitelist", current_session->identity)) {
                count++;
            }
        }
        control_server_.audit_logger().log(current_session->identity, "AUDIT_ALLOW_ALL", "all", "Whitelisted " + std::to_string(count) + " files");
        control_server_.invalidate_manifest_cache();
        send_resp(200, "OK", "application/json", "{\"status\":\"ok\",\"count\":" + std::to_string(count) + "}");
        return;
    }

    if (path == "/download") {
        std::string rel_path = get_query_param(req.query, "path");
        auto [vfs_st, data] = control_server_.vfs().read_file(rel_path, current_session->role);
        if (vfs_st == core::VfsStatus::ACCESS_DENIED) {
            send_resp(403, "Forbidden", "text/plain", "Permission Denied: Your role cannot read this file.");
            return;
        }
        if (vfs_st == core::VfsStatus::PATH_TRAVERSAL) {
            send_resp(403, "Forbidden", "text/plain", "403 Forbidden: Traversal Denied.");
            return;
        }
        if (vfs_st == core::VfsStatus::FILTERED) {
            send_resp(403, "Forbidden", "text/plain", "403 Forbidden: File shielded by Policy or AI Secret Guard.");
            return;
        }
        if (vfs_st != core::VfsStatus::OK) {
            send_resp(404, "Not Found", "text/plain", "404 Not Found.");
            return;
        }
        std::string fname = fs::path(rel_path).filename().string();
        for (char& c : fname) {
            if (c == '\r' || c == '\n' || c == '"' || c == '\\') c = '_';
        }
        std::string extra = "Content-Disposition: attachment; filename=\"" + fname + "\"\r\n";
        std::string body(reinterpret_cast<const char*>(data.data()), data.size());
        send_resp(200, "OK", "application/octet-stream", body, extra);
        return;
    }

    if (path == "/download-folder") {
        std::string rel_dir = get_query_param(req.query, "dir");
        if (current_session->role == core::Role::WRITE_ONLY) {
            send_resp(403, "Forbidden", "text/plain", "Permission Denied: Write-only role cannot download files.");
            return;
        }

        std::string manifest_str = control_server_.get_or_build_manifest_json();
        auto m_opt = sync::WorkspaceManifest::from_json(manifest_str);
        if (!m_opt) {
            send_resp(500, "Internal Server Error", "text/plain", "Failed to retrieve manifest for folder download.");
            return;
        }

        std::string norm_dir = rel_dir;
        std::replace(norm_dir.begin(), norm_dir.end(), '\\', '/');
        while (!norm_dir.empty() && norm_dir.front() == '/') norm_dir.erase(0, 1);
        while (!norm_dir.empty() && norm_dir.back() == '/') norm_dir.pop_back();

        std::string prefix = norm_dir.empty() ? "" : (norm_dir + "/");
        std::vector<std::pair<std::string, std::vector<uint8_t>>> files_to_zip;

        for (const auto& f : m_opt->files) {
            if (prefix.empty() || f.relative_path.rfind(prefix, 0) == 0 || f.relative_path == norm_dir) {
                auto [vfs_st, file_data] = control_server_.vfs().read_file(f.relative_path, current_session->role);
                if (vfs_st == core::VfsStatus::OK) {
                    std::string in_zip_path = f.relative_path;
                    if (!prefix.empty() && in_zip_path.rfind(prefix, 0) == 0) {
                        in_zip_path = in_zip_path.substr(prefix.size());
                    }
                    files_to_zip.push_back({in_zip_path, std::move(file_data)});
                }
            }
        }

        auto zip_bytes = build_zip_archive(files_to_zip);
        std::string zip_name = norm_dir.empty() ? control_server_.workspace_root().filename().string() : fs::path(norm_dir).filename().string();
        if (zip_name.empty()) zip_name = "workspace";
        for (char& c : zip_name) {
            if (c == '\r' || c == '\n' || c == '"' || c == '\\') c = '_';
        }

        std::string extra = "Content-Disposition: attachment; filename=\"" + zip_name + ".zip\"\r\n";
        std::string body(reinterpret_cast<const char*>(zip_bytes.data()), zip_bytes.size());
        send_resp(200, "OK", "application/zip", body, extra);
        return;
    }

    if (path == "/api/upload") {
        std::string rel_dir = get_query_param(req.query, "dir");
        std::string file_name = get_query_param(req.query, "name");
        if (file_name.empty()) {
            send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Missing filename.\"}");
            return;
        }
        file_name = fs::path(file_name).filename().string();
        std::string target_rel = rel_dir.empty() ? file_name : (rel_dir + "/" + file_name);

        std::vector<uint8_t> bytes(req.body.begin(), req.body.end());
        core::VfsStatus vfs_st = control_server_.vfs().write_file(target_rel, bytes, current_session->role, true);

        if (vfs_st == core::VfsStatus::ACCESS_DENIED) {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\",\"message\":\"Read-only role cannot upload.\"}");
            return;
        }
        if (vfs_st == core::VfsStatus::PATH_TRAVERSAL) {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"error\",\"message\":\"Directory traversal rejected.\"}");
            return;
        }
        if (vfs_st == core::VfsStatus::FILTERED) {
            control_server_.audit_logger().log(current_session->identity, "AI_UPLOAD_BLOCKED", target_rel, "Blocked by Policy or AI Secret Guard", false);
            send_resp(400, "Bad Request", "application/json", "{\"status\":\"blocked\",\"message\":\"Upload blocked by Policy or AI Secret Guard!\"}");
            return;
        }
        if (vfs_st != core::VfsStatus::OK) {
            send_resp(500, "Internal Server Error", "application/json", "{\"status\":\"error\",\"message\":\"Failed to save file: " + core::vfs_status_to_string(vfs_st) + "\"}");
            return;
        }

        control_server_.audit_logger().log(current_session->identity, "WEB_UPLOAD", target_rel, "File uploaded successfully (" + std::to_string(bytes.size()) + " bytes)");
        control_server_.invalidate_manifest_cache();
        send_resp(200, "OK", "application/json", "{\"status\":\"ok\",\"filename\":\"" + file_name + "\"}");
        return;
    }

    send_resp(404, "Not Found", "text/plain", "404 Not Found");
}

static bool parse_http_raw(platform::TcpSocket& client, HttpRequest& req, const uint8_t* init4 = nullptr) {
    std::vector<uint8_t> data;
    if (init4) {
        data.insert(data.end(), init4, init4 + 4);
    }

    size_t header_end = std::string::npos;
    std::vector<uint8_t> chunk(8192);
    while (data.size() < 64 * 1024) {
        std::string s(reinterpret_cast<const char*>(data.data()), data.size());
        header_end = s.find("\r\n\r\n");
        if (header_end != std::string::npos) break;
        int n = client.receive(chunk, 3000);
        if (n <= 0) break;
        data.insert(data.end(), chunk.begin(), chunk.begin() + n);
    }
    if (header_end == std::string::npos) return false;

    std::string header_str(reinterpret_cast<const char*>(data.data()), header_end);
    std::istringstream h_stream(header_str);
    std::string line;
    if (!std::getline(h_stream, line)) return false;

    std::istringstream req_line(line);
    req_line >> req.method >> req.uri;
    size_t qmark = req.uri.find('?');
    if (qmark != std::string::npos) {
        req.path = req.uri.substr(0, qmark);
        req.query = req.uri.substr(qmark + 1);
    } else {
        req.path = req.uri;
        req.query = "";
    }

    size_t content_length = 0;
    while (std::getline(h_stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 1);
            while (!val.empty() && val.front() == ' ') val.erase(0, 1);
            std::string lower_k = key;
            std::transform(lower_k.begin(), lower_k.end(), lower_k.begin(), ::tolower);
            req.headers[lower_k] = val;
            if (lower_k == "content-length") {
                try { content_length = std::stoull(val); } catch (...) {}
            } else if (lower_k == "cookie") {
                size_t pos = val.find("slug_session=");
                if (pos != std::string::npos) {
                    size_t vstart = pos + 13;
                    size_t vend = val.find(';', vstart);
                    req.session_token = (vend == std::string::npos) ? val.substr(vstart) : val.substr(vstart, vend - vstart);
                    while (!req.session_token.empty() && req.session_token.front() == ' ') req.session_token.erase(0, 1);
                }
            }
        }
    }

    size_t total_expected = header_end + 4 + content_length;
    if (content_length > 100 * 1024 * 1024) return false;

    while (data.size() < total_expected) {
        size_t needed = total_expected - data.size();
        size_t to_read = std::min(needed, chunk.size());
        int n = client.receive(std::span<uint8_t>(chunk.data(), to_read), 5000);
        if (n <= 0) break;
        data.insert(data.end(), chunk.begin(), chunk.begin() + n);
    }

    if (data.size() > header_end + 4) {
        req.body.assign(reinterpret_cast<const char*>(data.data() + header_end + 4), data.size() - (header_end + 4));
    }
    return true;
}

void WebServer::handle_http_client(platform::TcpSocket client) {
    HttpRequest req;
    if (parse_http_raw(client, req, nullptr)) {
        dispatch_http(client, req);
    }
}

void WebServer::handle_http_request(platform::TcpSocket& client, std::span<const uint8_t, 4> initial_bytes) {
    HttpRequest req;
    if (parse_http_raw(client, req, initial_bytes.data())) {
        dispatch_http(client, req);
    }
}

static bool parse_http_from_string(const std::string& raw, HttpRequest& req) {
    size_t header_end = raw.find("\r\n\r\n");
    if (header_end == std::string::npos) return false;

    std::string header_str = raw.substr(0, header_end);
    std::istringstream h_stream(header_str);
    std::string line;
    if (!std::getline(h_stream, line)) return false;

    std::istringstream req_line(line);
    req_line >> req.method >> req.uri;
    size_t qmark = req.uri.find('?');
    if (qmark != std::string::npos) {
        req.path = req.uri.substr(0, qmark);
        req.query = req.uri.substr(qmark + 1);
    } else {
        req.path = req.uri;
        req.query = "";
    }

    size_t content_length = 0;
    while (std::getline(h_stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 1);
            while (!val.empty() && val.front() == ' ') val.erase(0, 1);
            std::string lower_k = key;
            std::transform(lower_k.begin(), lower_k.end(), lower_k.begin(), ::tolower);
            req.headers[lower_k] = val;
            if (lower_k == "content-length") {
                try { content_length = std::stoull(val); } catch (...) {}
            } else if (lower_k == "cookie") {
                size_t pos = val.find("slug_session=");
                if (pos != std::string::npos) {
                    size_t vstart = pos + 13;
                    size_t vend = val.find(';', vstart);
                    req.session_token = (vend == std::string::npos) ? val.substr(vstart) : val.substr(vstart, vend - vstart);
                    while (!req.session_token.empty() && req.session_token.front() == ' ') req.session_token.erase(0, 1);
                }
            }
        }
    }

    if (raw.size() > header_end + 4) {
        req.body = raw.substr(header_end + 4);
    }
    return true;
}

std::vector<uint8_t> WebServer::handle_tunneled_http(const std::string& raw_request, uint32_t session_id) {
    HttpRequest req;
    if (!parse_http_from_string(raw_request, req)) {
        std::string err = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        return std::vector<uint8_t>(err.begin(), err.end());
    }

    std::vector<uint8_t> response_buffer;
    auto send_raw = [&](const std::string& res) {
        response_buffer.insert(response_buffer.end(), res.begin(), res.end());
    };

    dispatch_http_core(req, send_raw, "127.0.0.1", session_id);
    return response_buffer;
}

} // namespace slug::net
