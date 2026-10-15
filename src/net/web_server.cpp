#include "src/net/web_server.hpp"
#include "src/platform/fs.hpp"
#include "src/core/utils.hpp"
#include "src/sync/manifest.hpp"
#include "src/bench/benchmark.hpp"
#include "third_party/json/json.hpp"
#include <sstream>
#include <iostream>

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

    // When port is identical to ControlServer, HTTP multiplexing is handled by ControlServer
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

std::string WebServer::render_directory_listing(const std::string& /*rel_subpath*/) {
    auto manifest = sync::ManifestBuilder::build(control_server_.workspace_root(), 1, static_cast<uint8_t>(control_server_.suite_id()), false);
    std::string totp_code = control_server_.totp_manager().generate_code();
    uint32_t rem_sec = control_server_.totp_manager().remaining_seconds();

    std::ostringstream h;
    h << "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
      << "<title>Slug - slug://drop</title><style>"
      << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; }"
      << ".container { max-width: 900px; margin: 0 auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }"
      << "h1 { color: #58a6ff; margin-top: 0; display: flex; align-items: center; justify-content: space-between; font-size: 22px; }"
      << ".badge { background: #238636; color: #fff; padding: 4px 10px; border-radius: 20px; font-size: 13px; font-weight: normal; }"
      << ".pqc-badge { background: #8957e5; color: #fff; padding: 4px 10px; border-radius: 20px; font-size: 13px; margin-left: 8px; }"
      << ".info-box { background: #21262d; border-left: 4px solid #58a6ff; padding: 12px 16px; margin: 16px 0; border-radius: 4px; font-size: 14px; }"
      << "table { width: 100%; border-collapse: collapse; margin-top: 20px; }"
      << "th, td { text-align: left; padding: 12px; border-bottom: 1px solid #30363d; font-size: 14px; }"
      << "th { background: #21262d; color: #8b949e; }"
      << "a { color: #58a6ff; text-decoration: none; }"
      << "a:hover { text-decoration: underline; }"
      << ".btn { background: #238636; color: #fff; padding: 6px 14px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 500; display: inline-block; }"
      << ".btn:hover { background: #2ea043; text-decoration: none; }"
      << ".skipped { color: #8b949e; font-style: italic; font-size: 12px; }"
      << ".footer { margin-top: 24px; font-size: 12px; color: #8b949e; text-align: center; border-top: 1px solid #30363d; padding-top: 16px; }"
      << "</style></head><body><div class='container'>"
      << "<h1>Slug Workspace Drop <span><span class='badge'>Port " << control_server_.port() << "</span>"
      << "<span class='pqc-badge'>" << core::suite_to_string(control_server_.suite_id()) << "</span></span></h1>"
      << "<div class='info-box'>"
      << "<strong>TOTP Key:</strong> <span style='font-family:monospace; font-size:18px; color:#58a6ff; font-weight:bold;'>" << totp_code << "</span>"
      << " (Rotates in " << rem_sec << "s) | <strong>Workspace:</strong> " << control_server_.workspace_root().filename().string()
      << " | <a href='/admin' style='color:#a371f7; font-weight:bold;'>Open Admin Dashboard &rarr;</a>"
      << "</div>"
      << "<table><thead><tr><th>File Path</th><th>Size</th><th>BLAKE3 Fingerprint</th><th>Action</th></tr></thead><tbody>";

    for (const auto& f : manifest.files) {
        h << "<tr><td><strong>" << f.relative_path << "</strong></td>"
          << "<td>" << core::Utils::format_size(f.size) << "</td>"
          << "<td style='font-family:monospace; font-size:12px; color:#8b949e;'>" << f.file_blake3_hash.substr(0, 16) << "...</td>"
          << "<td><a class='btn' href='/download?path=" << f.relative_path << "'>Download</a></td></tr>";
    }

    if (manifest.files.empty()) {
        h << "<tr><td colspan='4' style='text-align:center; color:#8b949e;'>No accessible files available in this workspace.</td></tr>";
    }

    h << "</tbody></table>";

    if (!manifest.skipped.empty()) {
        h << "<h3 style='margin-top: 32px; color: #e3b341;'>Shielded / Skipped Items (" << manifest.skipped.size() << ")</h3>"
          << "<p style='font-size: 13px; color: #8b949e;'>Files automatically filtered by .gitignore, security rules, or AI Guard:</p><ul>";
        for (const auto& s : manifest.skipped) {
            h << "<li class='skipped'><strong>" << s.relative_path << "</strong> &mdash; " << s.reason << "</li>";
        }
        h << "</ul>";
    }

    h << "<div class='footer'>Slug &bull; Post-Quantum P2P Workspace Sharing & Dev Shield &bull; Apache-2.0</div></div></body></html>";
    return h.str();
}

std::string WebServer::render_admin_dashboard() {
    auto users = control_server_.acl_manager().list_users();
    auto events = control_server_.audit_logger().read_recent_events(20);
    std::string totp = control_server_.totp_manager().generate_code();
    auto bench_rep = bench::BenchmarkEngine::get_latest_report();

    // Extract metrics for dashboard
    double blake3_speed = 0.0, sha256_speed = 0.0;
    for (const auto& h : bench_rep.hashes) {
        if (h.algorithm.find("BLAKE3") != std::string::npos) blake3_speed = h.throughput_mb_sec;
        if (h.algorithm.find("SHA-256") != std::string::npos) sha256_speed = h.throughput_mb_sec;
    }

    double pqc_kem_decap = 0.0, classical_kem_decap = 0.0;
    double pqc_sig_verify = 0.0, classical_sig_verify = 0.0;
    double cipher_speed = 0.0;

    for (const auto& c : bench_rep.crypto_suites) {
        if (c.suite_id == core::SuiteID::SUITE_3_PURE_PQC) {
            pqc_kem_decap = c.kem_decap_us;
            pqc_sig_verify = c.sig_verify_us;
            cipher_speed = c.cipher_encrypt_mb_sec;
        } else if (c.suite_id == core::SuiteID::SUITE_1_CLASSICAL) {
            classical_kem_decap = c.kem_decap_us;
            classical_sig_verify = c.sig_verify_us;
        }
    }

    std::ostringstream h;
    h << "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>Slug Admin &amp; Benchmark Dashboard</title><style>"
      << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; }"
      << ".container { max-width: 980px; margin: 0 auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }"
      << "h1 { color: #58a6ff; font-size: 22px; margin-top: 0; display:flex; justify-content:space-between; align-items:center; }"
      << ".grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 20px 0; }"
      << ".card { background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 16px; }"
      << ".card h3 { margin-top: 0; font-size: 15px; color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom: 8px; display:flex; justify-content:space-between; align-items:center; }"
      << ".metric-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 12px 0; }"
      << ".metric-box { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; text-align: center; }"
      << ".metric-val { font-size: 20px; font-weight: bold; color: #58a6ff; margin-top: 4px; }"
      << ".metric-lbl { font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; }"
      << ".bar-track { background: #0d1117; border-radius: 4px; height: 12px; width: 100%; margin: 6px 0; overflow: hidden; display: flex; }"
      << ".bar-fill { height: 100%; background: #238636; border-radius: 4px; }"
      << ".bar-pqc { background: #8957e5; }"
      << "table { width: 100%; border-collapse: collapse; font-size: 13px; }"
      << "th, td { text-align: left; padding: 8px; border-bottom: 1px solid #30363d; }"
      << "th { color: #8b949e; }"
      << ".btn { background: #238636; color: #fff; padding: 6px 14px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 500; border: none; cursor: pointer; }"
      << ".btn:hover { background: #2ea043; }"
      << ".btn:disabled { background: #30363d; color: #8b949e; cursor: not-allowed; }"
      << ".log-entry { font-family: monospace; font-size: 12px; margin: 4px 0; color: #8b949e; }"
      << "</style><script>"
      << "function runLiveBenchmark() {"
      << "  const btn = document.getElementById('bench-btn');"
      << "  const status = document.getElementById('bench-status');"
      << "  btn.disabled = true;"
      << "  status.innerText = 'Measuring crypto suites, BLAKE3, AI Guard, & chunker...';"
      << "  fetch('/api/bench/run')"
      << "    .then(r => r.json())"
      << "    .then(data => { status.innerText = 'Updated successfully!'; setTimeout(() => location.reload(), 500); })"
      << "    .catch(e => { status.innerText = 'Error: ' + e; btn.disabled = false; });"
      << "}"
      << "</script></head><body><div class='container'>"
      << "<h1><span>Slug Admin &amp; Metrics Dashboard</span> <a href='/' style='color:#58a6ff; font-size:14px; text-decoration:none;'>&larr; Back to Drop</a></h1>"

      // Workspace Overview & Users
      << "<div class='grid'>"
      << "<div class='card'><h3>Active Server Workspace</h3>"
      << "<p><strong>Port:</strong> " << control_server_.port() << "</p>"
      << "<p><strong>Suite:</strong> <span style='color:#a371f7; font-weight:bold;'>" << core::suite_to_string(control_server_.suite_id()) << "</span></p>"
      << "<p><strong>Path:</strong> " << control_server_.workspace_root().string() << "</p>"
      << "<p><strong>TOTP Seed Token:</strong> <span style='font-family:monospace; color:#58a6ff; font-size:16px; font-weight:bold;'>" << totp << "</span></p>"
      << "</div>"
      << "<div class='card'><h3>User Accounts &amp; Ephemeral Roles</h3>"
      << "<table><thead><tr><th>User</th><th>Role</th><th>Status/TTL</th></tr></thead><tbody>";

    for (const auto& u : users) {
        h << "<tr><td>" << u.username << "</td><td>" << core::role_to_string(u.role) << "</td><td>"
          << (u.is_expired() ? "<span style='color:#f85149'>Expired</span>" : "<span style='color:#3fb950'>Active</span>")
          << "</td></tr>";
    }
    if (users.empty()) {
        h << "<tr><td colspan='3' style='color:#8b949e;'>No separate users (Default TOTP access)</td></tr>";
    }
    h << "</tbody></table></div></div>"

      // Benchmark & Performance Card
      << "<div class='card' style='margin-bottom: 16px;'>"
      << "<h3><span>Performance &amp; Cryptographic Benchmark</span>"
      << "<span><span id='bench-status' style='font-size:12px; color:#8b949e; margin-right:8px;'></span>"
      << "<button id='bench-btn' class='btn' onclick='runLiveBenchmark()'>Run Real-Time Benchmark</button></span></h3>"
      << "<div class='metric-grid'>"
      << "<div class='metric-box'><div class='metric-lbl'>BLAKE3 Throughput</div><div class='metric-val' style='color:#3fb950;'>" << static_cast<int>(blake3_speed) << " MB/s</div></div>"
      << "<div class='metric-box'><div class='metric-lbl'>ML-KEM-768 Decap</div><div class='metric-val' style='color:#a371f7;'>" << static_cast<int>(pqc_kem_decap) << " &mu;s</div></div>"
      << "<div class='metric-box'><div class='metric-lbl'>ML-DSA-65 Verify</div><div class='metric-val' style='color:#a371f7;'>" << static_cast<int>(pqc_sig_verify) << " &mu;s</div></div>"
      << "<div class='metric-box'><div class='metric-lbl'>XChaCha20 Cipher</div><div class='metric-val'>" << static_cast<int>(cipher_speed) << " MB/s</div></div>"
      << "<div class='metric-box'><div class='metric-lbl'>AI Guard Scan Rate</div><div class='metric-val' style='color:#e3b341;'>" << static_cast<int>(bench_rep.ai.lines_per_sec) << " L/s</div></div>"
      << "<div class='metric-box'><div class='metric-lbl'>Index Cache Hit</div><div class='metric-val' style='color:#3fb950;'>" << std::fixed << std::setprecision(2) << bench_rep.ai.cache_hit_lookup_us << " &mu;s</div></div>"
      << "</div>"

      // Visual Comparison Bars
      << "<div style='font-size:12px; color:#8b949e; margin-top:12px;'>"
      << "<div style='display:flex; justify-content:space-between;'><span>Hash Engine: BLAKE3 (" << static_cast<int>(blake3_speed) << " MB/s) vs SHA-256 (" << static_cast<int>(sha256_speed) << " MB/s)</span>"
      << "<span style='color:#3fb950;'><strong>" << (sha256_speed > 0 ? std::to_string(static_cast<int>(blake3_speed / sha256_speed)) : "3") << "x Faster</strong></span></div>"
      << "<div class='bar-track'><div class='bar-fill' style='width: " << std::min(100.0, (blake3_speed / (blake3_speed + sha256_speed + 0.1)) * 100.0) << "%;'></div></div>"

      << "<div style='display:flex; justify-content:space-between; margin-top:8px;'><span>KEM Decapsulation: Suite 3 PurePQC (" << static_cast<int>(pqc_kem_decap) << " &mu;s) vs Classical X25519 (" << static_cast<int>(classical_kem_decap) << " &mu;s)</span>"
      << "<span style='color:#a371f7;'><strong>Post-Quantum FIPS 203</strong></span></div>"
      << "<div class='bar-track'><div class='bar-fill bar-pqc' style='width: 100%;'></div></div>"

      << "<div style='display:flex; justify-content:space-between; margin-top:8px;'><span>Signature Verification: Suite 3 ML-DSA-65 (" << static_cast<int>(pqc_sig_verify) << " &mu;s) vs Classical Ed25519 (" << static_cast<int>(classical_sig_verify) << " &mu;s)</span>"
      << "<span style='color:#a371f7;'><strong>Post-Quantum FIPS 204</strong></span></div>"
      << "<div class='bar-track'><div class='bar-fill bar-pqc' style='width: 100%;'></div></div>"
      << "</div>"
      << "</div>"

      // Audit Log Card
      << "<div class='card'><h3>Recent Security Audit Activity (.slug/audit.log)</h3>";
    for (const auto& e : events) {
        h << "<div class='log-entry'>[" << e.action << "] " << e.actor << " &bull; " << e.path << " &bull; " << e.reason << "</div>";
    }
    if (events.empty()) {
        h << "<div class='log-entry'>No audit events recorded yet.</div>";
    }
    h << "</div></div></body></html>";
    return h.str();
}

void WebServer::dispatch_http(platform::TcpSocket& client, const std::string& req_str) {
    std::istringstream iss(req_str);
    std::string method, uri, http_ver;
    iss >> method >> uri >> http_ver;

    if (method != "GET" && method != "HEAD") {
        std::string res = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n";
        client.send_all(res);
        return;
    }

    if (uri == "/" || uri == "/drop") {
        std::string body = render_directory_listing();
        std::string res = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " +
                          std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        client.send_all(res);
        return;
    }

    if (uri == "/admin") {
        std::string body = render_admin_dashboard();
        std::string res = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " +
                          std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        client.send_all(res);
        return;
    }

    if (uri == "/api/status") {
        json j;
        j["port"] = control_server_.port();
        j["suite"] = core::suite_to_string(control_server_.suite_id());
        j["workspace"] = control_server_.workspace_root().string();
        j["totp"] = control_server_.totp_manager().generate_code();
        std::string body = j.dump(2);
        std::string res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                          std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        client.send_all(res);
        return;
    }

    if (uri == "/api/bench") {
        auto rep = bench::BenchmarkEngine::get_latest_report();
        std::string body = rep.to_json().dump(2);
        std::string res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                          std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        client.send_all(res);
        return;
    }

    if (uri == "/api/bench/run") {
        auto rep = bench::BenchmarkEngine::run_all(true);
        std::string body = rep.to_json().dump(2);
        std::string res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                          std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        client.send_all(res);
        return;
    }

    if (uri.rfind("/download?path=", 0) == 0) {
        std::string rel_path = url_decode(uri.substr(15));
        auto safe = platform::PathUtils::resolve_safe_path(control_server_.workspace_root(), rel_path);
        if (!safe) {
            std::string body = "403 Forbidden: Traversal Denied";
            std::string res = "HTTP/1.1 403 Forbidden\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
            client.send_all(res);
            return;
        }

        auto data = platform::PathUtils::read_binary_file(*safe);
        if (!data) {
            std::string body = "404 Not Found";
            std::string res = "HTTP/1.1 404 Not Found\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
            client.send_all(res);
            return;
        }

        std::string header = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"" +
                             safe->filename().string() + "\"\r\nContent-Length: " +
                             std::to_string(data->size()) + "\r\nConnection: close\r\n\r\n";
        client.send_all(header);
        client.send_all(*data);
        return;
    }

    std::string body = "404 Not Found";
    std::string res = "HTTP/1.1 404 Not Found\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    client.send_all(res);
}

void WebServer::handle_http_client(platform::TcpSocket client) {
    std::vector<uint8_t> req_buf(8192);
    int r = client.receive(req_buf, 3000);
    if (r <= 0) return;
    dispatch_http(client, std::string(req_buf.begin(), req_buf.begin() + r));
}

void WebServer::handle_http_request(platform::TcpSocket& client, std::span<const uint8_t, 4> initial_bytes) {
    std::vector<uint8_t> req_buf(8192);
    std::memcpy(req_buf.data(), initial_bytes.data(), 4);
    int r = client.receive(std::span<uint8_t>(req_buf.data() + 4, req_buf.size() - 4), 3000);
    int total = 4 + (r > 0 ? r : 0);
    dispatch_http(client, std::string(req_buf.begin(), req_buf.begin() + total));
}

} // namespace slug::net
