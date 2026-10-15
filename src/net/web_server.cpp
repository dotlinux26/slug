#include "src/net/web_server.hpp"
#include "src/platform/fs.hpp"
#include "src/core/utils.hpp"
#include "src/sync/manifest.hpp"
#include "src/bench/benchmark.hpp"
#include "src/ai/scanner.hpp"
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
    return it->second;
}

std::string WebServer::create_session(const std::string& identity, core::Role role, uint64_t ttl_sec) {
    std::string token = core::Utils::to_hex(core::Utils::random_bytes(24));
    WebSession s;
    s.token = token;
    s.identity = identity;
    s.role = role;
    s.expires_at = (ttl_sec == 0) ? 0 : core::Utils::current_timestamp() + ttl_sec;
    std::lock_guard<std::mutex> lock(session_mutex_);
    sessions_[token] = s;
    return token;
}

void WebServer::destroy_session(const std::string& token) {
    std::lock_guard<std::mutex> lock(session_mutex_);
    sessions_.erase(token);
}

static std::string render_forbidden_page(const std::string& reason) {
    std::ostringstream h;
    h << "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
      << "<title>403 Forbidden - Slug PQC Gateway</title><style>"
      << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0a0d12; color: #c9d1d9; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; }"
      << ".card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; max-width: 540px; width: 100%; padding: 32px; box-shadow: 0 12px 32px rgba(0,0,0,0.6); }"
      << "h1 { color: #f85149; font-size: 20px; margin-top: 0; display: flex; align-items: center; gap: 8px; }"
      << ".badge { background: #da3633; color: #fff; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }"
      << ".msg { font-size: 14px; line-height: 1.6; color: #8b949e; margin: 16px 0; }"
      << ".cli-box { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 14px; margin-top: 20px; font-family: monospace; font-size: 13px; color: #58a6ff; line-height: 1.5; }"
      << ".footer { margin-top: 24px; font-size: 12px; color: #484f58; text-align: center; border-top: 1px solid #21262d; padding-top: 14px; }"
      << "</style></head><body><div class='card'>"
      << "<h1><span>Access Denied</span> <span class='badge'>PQC Shield</span></h1>"
      << "<div class='msg'>" << reason << "</div>"
      << "<div class='msg'>Anonymous or unauthenticated web access to this Slug workspace is strictly prohibited. You must authenticate through the Slug CLI to negotiate a Post-Quantum session certificate.</div>"
      << "<div class='cli-box'>"
      << "<span style='color:#8b949e;'># Step 1: Connect via Slug CLI</span><br>"
      << "slug connect -i &lt;host_ip&gt; -p &lt;port&gt; -o &lt;totp_code&gt; -w<br><br>"
      << "<span style='color:#8b949e;'># Step 2: Or open an active saved connection</span><br>"
      << "slug connect list<br>"
      << "slug connect &lt;connection_id&gt; -w"
      << "</div>"
      << "<div class='footer'>Slug &bull; Post-Quantum Cryptographic Isolation &bull; Apache-2.0</div>"
      << "</div></body></html>";
    return h.str();
}

std::string WebServer::render_directory_listing(const std::string& rel_subpath, const WebSession& session) {
    auto manifest = sync::ManifestBuilder::build(control_server_.workspace_root(), 1, static_cast<uint8_t>(control_server_.suite_id()), false);

    // Normalize rel_subpath (strip leading/trailing slashes)
    std::string norm_sub = rel_subpath;
    while (!norm_sub.empty() && norm_sub.front() == '/') norm_sub.erase(0, 1);
    while (!norm_sub.empty() && norm_sub.back() == '/') norm_sub.pop_back();

    // Determine subfolders and files at this level
    struct DirEntry {
        bool is_dir;
        std::string name;
        std::string full_rel_path;
        uint64_t size;
        std::string blake3;
    };
    std::vector<DirEntry> entries;
    std::set<std::string> seen_dirs;

    for (const auto& f : manifest.files) {
        std::string p = f.relative_path;
        if (norm_sub.empty()) {
            size_t slash = p.find('/');
            if (slash != std::string::npos) {
                std::string dname = p.substr(0, slash);
                if (seen_dirs.insert(dname).second) {
                    entries.push_back({true, dname, dname, 0, ""});
                }
            } else {
                entries.push_back({false, p, p, f.size, f.file_blake3_hash});
            }
        } else {
            if (p.rfind(norm_sub + "/", 0) == 0) {
                std::string remainder = p.substr(norm_sub.size() + 1);
                size_t slash = remainder.find('/');
                if (slash != std::string::npos) {
                    std::string dname = remainder.substr(0, slash);
                    if (seen_dirs.insert(dname).second) {
                        entries.push_back({true, dname, norm_sub + "/" + dname, 0, ""});
                    }
                } else {
                    entries.push_back({false, remainder, p, f.size, f.file_blake3_hash});
                }
            }
        }
    }

    // Sort entries: directories first, then files
    std::sort(entries.begin(), entries.end(), [](const DirEntry& a, const DirEntry& b) {
        if (a.is_dir != b.is_dir) return a.is_dir > b.is_dir;
        return a.name < b.name;
    });

    // Compute parent directory
    std::string parent_dir = "";
    if (!norm_sub.empty()) {
        size_t last_slash = norm_sub.find_last_of('/');
        if (last_slash != std::string::npos) {
            parent_dir = norm_sub.substr(0, last_slash);
        }
    }

    std::ostringstream h;
    h << "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
      << "<title>Slug - " << control_server_.workspace_root().filename().string() << " / " << (norm_sub.empty() ? "root" : norm_sub) << "</title><style>"
      << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; }"
      << ".container { max-width: 980px; margin: 0 auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }"
      << ".top-bar { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #30363d; padding-bottom: 16px; margin-bottom: 16px; }"
      << "h1 { color: #58a6ff; font-size: 20px; margin: 0; display: flex; align-items: center; gap: 8px; }"
      << ".badge { background: #238636; color: #fff; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 500; }"
      << ".pqc-badge { background: #8957e5; color: #fff; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 500; }"
      << ".user-badge { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 4px 10px; border-radius: 6px; font-size: 12px; display: inline-flex; align-items: center; gap: 6px; }"
      << ".role-tag { background: #1f6feb; color: #fff; padding: 1px 6px; border-radius: 4px; font-size: 10px; text-transform: uppercase; font-weight: bold; }"
      << ".nav-bar { display: flex; align-items: center; justify-content: space-between; background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 10px 16px; margin-bottom: 16px; flex-wrap: wrap; gap: 10px; }"
      << ".breadcrumb { font-size: 14px; font-family: monospace; display: flex; align-items: center; gap: 4px; }"
      << ".breadcrumb a { color: #58a6ff; text-decoration: none; }"
      << ".breadcrumb a:hover { text-decoration: underline; }"
      << ".actions { display: flex; align-items: center; gap: 8px; }"
      << ".btn { background: #238636; color: #fff; padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 500; border: none; cursor: pointer; display: inline-flex; align-items: center; gap: 6px; }"
      << ".btn:hover { background: #2ea043; }"
      << ".btn-sec { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 500; display: inline-flex; align-items: center; gap: 6px; }"
      << ".btn-sec:hover { background: #30363d; }"
      << "table { width: 100%; border-collapse: collapse; margin-top: 8px; }"
      << "th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #21262d; font-size: 13px; }"
      << "th { background: #161b22; color: #8b949e; border-bottom: 2px solid #30363d; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }"
      << "tr.item-row:hover { background: #21262d; }"
      << "a.entry-name { color: #58a6ff; text-decoration: none; font-weight: 500; display: inline-flex; align-items: center; gap: 6px; }"
      << "a.entry-name:hover { text-decoration: underline; }"
      << ".dropzone-active { border: 2px dashed #58a6ff !important; background: rgba(88, 166, 255, 0.05) !important; }"
      << ".context-menu { position: absolute; background: #21262d; border: 1px solid #30363d; border-radius: 6px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); padding: 4px 0; z-index: 1000; min-width: 160px; display: none; }"
      << ".context-menu a { display: block; padding: 8px 16px; color: #c9d1d9; text-decoration: none; font-size: 13px; }"
      << ".context-menu a:hover { background: #30363d; color: #58a6ff; }"
      << "#upload-toast { position: fixed; bottom: 20px; right: 20px; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px 18px; box-shadow: 0 8px 24px rgba(0,0,0,0.6); font-size: 13px; z-index: 9999; display: none; }"
      << ".footer { margin-top: 24px; font-size: 12px; color: #8b949e; text-align: center; border-top: 1px solid #30363d; padding-top: 16px; }"
      << "</style><script>"
      << "const currentDir = '" << norm_sub << "';"
      << "const canWrite = " << (session.role != core::Role::READ_ONLY ? "true" : "false") << ";"

      << "function triggerUpload() {"
      << "  if (!canWrite) { alert('Permission Denied: Your role is read-only.'); return; }"
      << "  document.getElementById('hidden-file-input').click();"
      << "}"

      << "function uploadFiles(files) {"
      << "  if (!canWrite) { alert('Permission Denied: Your role is read-only.'); return; }"
      << "  if (!files || files.length === 0) return;"
      << "  const toast = document.getElementById('upload-toast');"
      << "  toast.style.display = 'block';"
      << "  toast.innerHTML = 'Uploading ' + files.length + ' file(s)...';"

      << "  let completed = 0;"
      << "  Array.from(files).forEach(file => {"
      << "    const url = '/api/upload?dir=' + encodeURIComponent(currentDir) + '&name=' + encodeURIComponent(file.name);"
      << "    fetch(url, { method: 'POST', body: file })"
      << "      .then(r => r.json())"
      << "      .then(res => {"
      << "        completed++;"
      << "        if (res.status === 'blocked') {"
      << "          alert('Upload Blocked by AI Secret Guard:\\n' + res.message);"
      << "        }"
      << "        if (completed === files.length) {"
      << "          toast.innerHTML = 'Upload finished!';"
      << "          setTimeout(() => location.reload(), 600);"
      << "        }"
      << "      })"
      << "      .catch(err => {"
      << "        alert('Upload failed: ' + err);"
      << "        toast.style.display = 'none';"
      << "      });"
      << "  });"
      << "}"

      // Drag and drop handlers
      << "window.addEventListener('dragover', e => { e.preventDefault(); document.getElementById('drop-container').classList.add('dropzone-active'); });"
      << "window.addEventListener('dragleave', e => { if (e.clientX <= 0 || e.clientY <= 0) document.getElementById('drop-container').classList.remove('dropzone-active'); });"
      << "window.addEventListener('drop', e => {"
      << "  e.preventDefault();"
      << "  document.getElementById('drop-container').classList.remove('dropzone-active');"
      << "  if (e.dataTransfer && e.dataTransfer.files) uploadFiles(e.dataTransfer.files);"
      << "});"

      // Context menu
      << "let activeContextPath = '';"
      << "function showContext(e, path) {"
      << "  e.preventDefault();"
      << "  activeContextPath = path;"
      << "  const menu = document.getElementById('context-menu');"
      << "  menu.style.display = 'block';"
      << "  menu.style.left = e.pageX + 'px';"
      << "  menu.style.top = e.pageY + 'px';"
      << "}"
      << "window.addEventListener('click', () => { document.getElementById('context-menu').style.display = 'none'; });"
      << "function ctxDownload() { if (activeContextPath) location.href = '/download?path=' + encodeURIComponent(activeContextPath); }"
      << "function ctxCopy() { if (activeContextPath) { navigator.clipboard.writeText(activeContextPath); alert('Copied path: ' + activeContextPath); } }"
      << "</script></head><body>"
      << "<div class='container' id='drop-container'>"

      // Top bar
      << "<div class='top-bar'>"
      << "<h1><span>Slug Workspace Dropbox</span> <span class='badge'>Port " << control_server_.port() << "</span>"
      << "<span class='pqc-badge'>" << core::suite_to_string(control_server_.suite_id()) << "</span></h1>"
      << "<div style='display:flex; align-items:center; gap:12px;'>"
      << "<div class='user-badge'><span>👤</span> " << session.identity << " <span class='role-tag'>" << core::role_to_string(session.role) << "</span></div>"
      << (session.role == core::Role::READ_WRITE ? "<a class='btn-sec' href='/admin'>Admin Dashboard</a>" : "")
      << "<a class='btn-sec' href='/logout' style='color:#f85149;'>Logout</a>"
      << "</div>"
      << "</div>"

      // Navigation Bar & Breadcrumb
      << "<div class='nav-bar'>"
      << "<div class='breadcrumb'>"
      << "<span>📁 </span><a href='/drop'>[root]</a>";

    if (!norm_sub.empty()) {
        std::stringstream ss(norm_sub);
        std::string segment, accumulated;
        while (std::getline(ss, segment, '/')) {
            if (segment.empty()) continue;
            accumulated += (accumulated.empty() ? "" : "/") + segment;
            h << " / <a href='/drop?dir=" << accumulated << "'>" << segment << "</a>";
        }
    }
    h << "</div>"
      << "<div class='actions'>"
      << "<input type='file' id='hidden-file-input' multiple style='display:none;' onchange='uploadFiles(this.files)'>"
      << (session.role != core::Role::READ_ONLY ? "<button class='btn' onclick='triggerUpload()'>+ Upload File</button>" : "<span style='font-size:12px; color:#8b949e;'>Read-Only Mode</span>")
      << "</div>"
      << "</div>";

    if (session.role == core::Role::WRITE_ONLY) {
        h << "<div style='background:#161b22; border:2px dashed #30363d; border-radius:8px; padding:48px 20px; text-align:center; margin-top:20px;'>"
          << "<div style='font-size:42px; margin-bottom:12px;'>📥</div>"
          << "<h2 style='color:#58a6ff; margin:0 0 8px 0; font-size:18px;'>Blind Drop Inbox (Write-Only Mode)</h2>"
          << "<p style='color:#8b949e; margin:0 0 20px 0; font-size:13px;'>You have write-only permission to deposit files into this workspace.<br>Existing workspace files are strictly shielded and hidden.</p>"
          << "<button class='btn' onclick='triggerUpload()' style='font-size:14px; padding:8px 20px;'>+ Select & Upload Files</button>"
          << "<p style='color:#6e7681; margin:16px 0 0 0; font-size:12px;'>Or drag and drop files anywhere into this window</p>"
          << "</div>";
    } else {
        // File list table
        h << "<table><thead><tr><th>Name</th><th>Size</th><th>BLAKE3 Hash</th><th>Action</th></tr></thead><tbody>";

        if (!norm_sub.empty()) {
            h << "<tr class='item-row'><td colspan='4'>"
              << "<a class='entry-name' href='/drop" << (parent_dir.empty() ? "" : "?dir=" + parent_dir) << "'>📁 .. (Parent Directory)</a>"
              << "</td></tr>";
        }

        for (const auto& entry : entries) {
            if (entry.is_dir) {
                h << "<tr class='item-row'>"
                  << "<td><a class='entry-name' href='/drop?dir=" << entry.full_rel_path << "'>📁 " << entry.name << "/</a></td>"
                  << "<td style='color:#8b949e;'>DIR</td>"
                  << "<td style='color:#8b949e;'>-</td>"
                  << "<td><a class='btn-sec' style='padding:2px 8px; font-size:11px;' href='/drop?dir=" << entry.full_rel_path << "'>Open</a></td>"
                  << "</tr>";
            } else {
                h << "<tr class='item-row' oncontextmenu=\"showContext(event, '" << entry.full_rel_path << "')\">"
                  << "<td><a class='entry-name' href='/download?path=" << entry.full_rel_path << "'>📄 " << entry.name << "</a></td>"
                  << "<td>" << core::Utils::format_size(entry.size) << "</td>"
                  << "<td style='font-family:monospace; font-size:11px; color:#8b949e;'>" << entry.blake3.substr(0, 16) << "...</td>"
                  << "<td><a class='btn-sec' style='padding:2px 8px; font-size:11px;' href='/download?path=" << entry.full_rel_path << "'>Download</a></td>"
                  << "</tr>";
            }
        }

        if (entries.empty() && norm_sub.empty()) {
            h << "<tr><td colspan='4' style='text-align:center; color:#8b949e; padding:24px;'>No files currently shared in this workspace. Drag and drop files here to upload.</td></tr>";
        }

        h << "</tbody></table>";
    }

    // Collapsible Skipped Items box
    if (!manifest.skipped.empty()) {
        h << "<details style='margin-top:24px; background:#161b22; border:1px solid #30363d; border-radius:6px; padding:12px;'>"
          << "<summary style='cursor:pointer; color:#e3b341; font-weight:600; font-size:13px;'>"
          << "Shielded / Skipped Items (" << manifest.skipped.size() << " files) &mdash; Click to view filter log"
          << "</summary>"
          << "<div style='max-height:140px; overflow-y:auto; margin-top:10px; font-family:monospace; font-size:12px; color:#8b949e; background:#0d1117; padding:8px 12px; border-radius:4px; line-height:1.6;'>";
        for (const auto& s : manifest.skipped) {
            h << "<div>[SKIPPED] " << s.relative_path << " &mdash; " << s.reason << "</div>";
        }
        h << "</div></details>";
    }

    // Context menu & Toast
    h << "<div id='context-menu' class='context-menu'>"
      << "<a href='javascript:void(0)' onclick='ctxDownload()'>⬇ Download File</a>"
      << "<a href='javascript:void(0)' onclick='ctxCopy()'>📋 Copy Relative Path</a>"
      << "</div>"
      << "<div id='upload-toast'></div>"
      << "<div class='footer'>Slug &bull; Post-Quantum P2P Workspace Sharing & Dev Shield &bull; Apache-2.0</div>"
      << "</div></body></html>";

    return h.str();
}

std::string WebServer::render_admin_dashboard(const WebSession& session) {
    auto users = control_server_.acl_manager().list_users();
    auto events = control_server_.audit_logger().read_recent_events(25);
    auto bench_rep = bench::BenchmarkEngine::get_latest_report();

    double blake3_speed = 0.0, sha256_speed = 0.0;
    for (const auto& h_item : bench_rep.hashes) {
        if (h_item.algorithm.find("BLAKE3") != std::string::npos) blake3_speed = h_item.throughput_mb_sec;
        if (h_item.algorithm.find("SHA-256") != std::string::npos) sha256_speed = h_item.throughput_mb_sec;
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
    h << "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
      << "<title>Slug Admin &amp; Benchmark Dashboard</title><style>"
      << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; }"
      << ".container { max-width: 980px; margin: 0 auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }"
      << ".top-bar { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #30363d; padding-bottom: 16px; margin-bottom: 20px; }"
      << "h1 { color: #58a6ff; font-size: 20px; margin: 0; }"
      << ".grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 20px 0; }"
      << ".card { background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 16px; }"
      << ".card h3 { margin-top: 0; font-size: 14px; color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom: 8px; display:flex; justify-content:space-between; align-items:center; }"
      << ".metric-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 12px 0; }"
      << ".metric-box { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; text-align: center; }"
      << ".metric-val { font-size: 20px; font-weight: bold; color: #58a6ff; margin-top: 4px; transition: all 0.3s ease; }"
      << ".metric-lbl { font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; }"
      << ".bar-track { background: #0d1117; border-radius: 4px; height: 12px; width: 100%; margin: 6px 0; overflow: hidden; display: flex; }"
      << ".bar-fill { height: 100%; background: #238636; border-radius: 4px; transition: width 0.4s ease; }"
      << ".bar-pqc { background: #8957e5; }"
      << "table { width: 100%; border-collapse: collapse; font-size: 13px; }"
      << "th, td { text-align: left; padding: 8px; border-bottom: 1px solid #30363d; }"
      << "th { color: #8b949e; }"
      << ".btn { background: #238636; color: #fff; padding: 6px 14px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 500; border: none; cursor: pointer; }"
      << ".btn:hover { background: #2ea043; }"
      << ".btn:disabled { background: #30363d; color: #8b949e; cursor: not-allowed; }"
      << ".btn-sec { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 500; }"
      << ".btn-sec:hover { background: #30363d; }"
      << ".log-entry { font-family: monospace; font-size: 12px; margin: 4px 0; color: #8b949e; }"
      << "</style><script>"
      << "function runLiveBenchmark() {"
      << "  const btn = document.getElementById('bench-btn');"
      << "  const status = document.getElementById('bench-status');"
      << "  btn.disabled = true;"
      << "  btn.innerText = 'Measuring live...';"
      << "  status.innerText = 'Running benchmark suite...';"
      << "  fetch('/api/bench/run')"
      << "    .then(r => r.json())"
      << "    .then(rep => {"
      << "      let b3 = 0, sha = 0, kem = 0, sig = 0, ciph = 0;"
      << "      if (rep.hashes) {"
      << "        rep.hashes.forEach(h => {"
      << "          if (h.algorithm.indexOf('BLAKE3') !== -1) b3 = Math.round(h.throughput_mb_sec);"
      << "          if (h.algorithm.indexOf('SHA-256') !== -1) sha = Math.round(h.throughput_mb_sec);"
      << "        });"
      << "      }"
      << "      if (rep.crypto_suites) {"
      << "        rep.crypto_suites.forEach(c => {"
      << "          if (c.suite_id === 3) {"
      << "            kem = Math.round(c.kem_decap_us);"
      << "            sig = Math.round(c.sig_verify_us);"
      << "            ciph = Math.round(c.cipher_encrypt_mb_sec);"
      << "          }"
      << "        });"
      << "      }"
      << "      document.getElementById('m-blake3').innerText = b3 + ' MB/s';"
      << "      document.getElementById('m-kem').innerText = kem + ' µs';"
      << "      document.getElementById('m-sig').innerText = sig + ' µs';"
      << "      document.getElementById('m-cipher').innerText = ciph + ' MB/s';"
      << "      if (rep.ai) {"
      << "        document.getElementById('m-ai').innerText = Math.round(rep.ai.lines_per_sec) + ' L/s';"
      << "        document.getElementById('m-cache').innerText = Number(rep.ai.cache_hit_lookup_us).toFixed(2) + ' µs';"
      << "      }"
      << "      btn.disabled = false;"
      << "      btn.innerText = 'Run Real-Time Benchmark';"
      << "      status.innerText = '✓ Updated at ' + new Date().toLocaleTimeString();"
      << "      status.style.color = '#3fb950';"
      << "    })"
      << "    .catch(e => {"
      << "      status.innerText = 'Error: ' + e;"
      << "      status.style.color = '#f85149';"
      << "      btn.disabled = false;"
      << "      btn.innerText = 'Run Real-Time Benchmark';"
      << "    });"
      << "}"
      << "</script></head><body><div class='container'>"
      << "<div class='top-bar'>"
      << "<h1>Slug Admin &amp; Metrics Dashboard</h1>"
      << "<div style='display:flex; align-items:center; gap:12px;'>"
      << "<span style='font-size:13px; color:#8b949e;'>Operator: <strong style='color:#c9d1d9;'>" << session.identity << "</strong></span>"
      << "<a class='btn-sec' href='/drop'>&larr; Back to Dropbox</a>"
      << "<a class='btn-sec' href='/logout' style='color:#f85149;'>Logout</a>"
      << "</div>"
      << "</div>"

      // Overview grid
      << "<div class='grid'>"
      << "<div class='card'><h3>Active Server Workspace</h3>"
      << "<p><strong>Port:</strong> " << control_server_.port() << "</p>"
      << "<p><strong>Suite:</strong> <span style='color:#a371f7; font-weight:bold;'>" << core::suite_to_string(control_server_.suite_id()) << "</span></p>"
      << "<p><strong>Path:</strong> " << control_server_.workspace_root().string() << "</p>"
      << "<p><strong>AI Secret Shield:</strong> " << (control_server_.ai_enabled() ? "<span style='color:#3fb950;'>ACTIVE</span>" : "OFF") << "</p>"
      << "</div>"

      << "<div class='card'><h3>User Accounts &amp; Ephemeral Roles</h3>"
      << "<table><thead><tr><th>User</th><th>Role</th><th>Status/TTL</th></tr></thead><tbody>";

    for (const auto& u : users) {
        h << "<tr><td>" << u.username << "</td><td>" << core::role_to_string(u.role) << "</td><td>"
          << (u.is_expired() ? "<span style='color:#f85149'>Expired</span>" : "<span style='color:#3fb950'>Active</span>")
          << "</td></tr>";
    }
    if (users.empty()) {
        h << "<tr><td colspan='3' style='color:#8b949e;'>No separate user accounts configured</td></tr>";
    }
    h << "</tbody></table></div></div>"

      // Real-time benchmark card
      << "<div class='card' style='margin-bottom: 16px;'>"
      << "<h3><span>Performance &amp; Cryptographic Benchmark</span>"
      << "<span><span id='bench-status' style='font-size:12px; margin-right:8px;'></span>"
      << "<button id='bench-btn' class='btn' onclick='runLiveBenchmark()'>Run Real-Time Benchmark</button></span></h3>"
      << "<div class='metric-grid'>"
      << "<div class='metric-box'><div class='metric-lbl'>BLAKE3 Throughput</div><div id='m-blake3' class='metric-val' style='color:#3fb950;'>" << static_cast<int>(blake3_speed) << " MB/s</div></div>"
      << "<div class='metric-box'><div class='metric-lbl'>ML-KEM-768 Decap</div><div id='m-kem' class='metric-val' style='color:#a371f7;'>" << static_cast<int>(pqc_kem_decap) << " &mu;s</div></div>"
      << "<div class='metric-box'><div class='metric-lbl'>ML-DSA-65 Verify</div><div id='m-sig' class='metric-val' style='color:#a371f7;'>" << static_cast<int>(pqc_sig_verify) << " &mu;s</div></div>"
      << "<div class='metric-box'><div class='metric-lbl'>XChaCha20 Cipher</div><div id='m-cipher' class='metric-val'>" << static_cast<int>(cipher_speed) << " MB/s</div></div>"
      << "<div class='metric-box'><div class='metric-lbl'>AI Guard Scan Rate</div><div id='m-ai' class='metric-val' style='color:#e3b341;'>" << static_cast<int>(bench_rep.ai.lines_per_sec) << " L/s</div></div>"
      << "<div class='metric-box'><div class='metric-lbl'>Index Cache Hit</div><div id='m-cache' class='metric-val' style='color:#3fb950;'>" << std::fixed << std::setprecision(2) << bench_rep.ai.cache_hit_lookup_us << " &mu;s</div></div>"
      << "</div>"

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

      // Audit log card
      << "<div class='card'><h3>Recent Security Audit Activity (.slug/audit.log)</h3>"
      << "<div style='max-height:160px; overflow-y:auto; padding:6px;'>";
    for (const auto& e : events) {
        h << "<div class='log-entry'>[" << e.action << "] " << e.actor << " &bull; " << e.path << " &bull; " << e.reason << "</div>";
    }
    if (events.empty()) {
        h << "<div class='log-entry'>No audit events recorded yet.</div>";
    }
    h << "</div></div></div></body></html>";
    return h.str();
}

void WebServer::dispatch_http(platform::TcpSocket& client, const HttpRequest& req) {
    std::string method = req.method;
    std::string path = req.path;

    // Check for ticket query param to authenticate session automatically
    std::string ticket = get_query_param(req.query, "ticket");
    std::string session_cookie = req.session_token;
    std::string new_session_token = "";

    std::optional<WebSession> current_session = validate_session(session_cookie);

    if (!current_session && !ticket.empty()) {
        auto sess_opt = control_server_.find_session_by_ticket(ticket);
        if (sess_opt) {
            new_session_token = create_session(sess_opt->identity, sess_opt->role, 14400);
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
        client.send_all(res);
    };

    // Logout endpoint
    if (path == "/logout") {
        if (!session_cookie.empty()) {
            destroy_session(session_cookie);
        }
        std::string body = render_forbidden_page("You have been logged out of the workspace session.");
        send_resp(200, "OK", "text/html; charset=utf-8", body, "Set-Cookie: slug_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n");
        return;
    }

    // Local loopback status query for host CLI (slug status, slug totp, slug web)
    bool is_localhost = (client.peer_endpoint().ip == "127.0.0.1" || client.peer_endpoint().ip == "::1");
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
        j["admin_ticket"] = control_server_.create_host_admin_ticket();
        send_resp(200, "OK", "application/json", j.dump(2));
        return;
    }

    // STRICT GATEKEEPER: If not authenticated, reject immediately!
    if (!current_session) {
        std::string body = render_forbidden_page("Mutual Post-Quantum Certificate / Session Ticket Required.");
        send_resp(403, "Forbidden", "text/html; charset=utf-8", body);
        return;
    }

    // Authenticated endpoints:
    if (path == "/" || path == "/drop") {
        std::string rel_dir = get_query_param(req.query, "dir");
        std::string body = render_directory_listing(rel_dir, *current_session);
        send_resp(200, "OK", "text/html; charset=utf-8", body);
        return;
    }

    if (path == "/admin") {
        if (current_session->role != core::Role::READ_WRITE) {
            std::string body = render_forbidden_page("Permission Denied: Admin dashboard requires Read-Write role.");
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
        if (current_session->role != core::Role::READ_WRITE) {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\"}");
            return;
        }
        auto rep = bench::BenchmarkEngine::run_all(true);
        send_resp(200, "OK", "application/json", rep.to_json().dump(2));
        return;
    }

    if (path == "/download") {
        if (current_session->role == core::Role::WRITE_ONLY) {
            send_resp(403, "Forbidden", "text/plain", "Permission Denied: Write-only role cannot download files.");
            return;
        }
        std::string rel_path = get_query_param(req.query, "path");
        auto safe = platform::PathUtils::resolve_safe_path(control_server_.workspace_root(), rel_path);
        if (!safe) {
            send_resp(403, "Forbidden", "text/plain", "403 Forbidden: Traversal Denied");
            return;
        }
        auto data = platform::PathUtils::read_binary_file(*safe);
        if (!data) {
            send_resp(404, "Not Found", "text/plain", "404 Not Found");
            return;
        }
        std::string extra = "Content-Disposition: attachment; filename=\"" + safe->filename().string() + "\"\r\n";
        std::string body(reinterpret_cast<const char*>(data->data()), data->size());
        send_resp(200, "OK", "application/octet-stream", body, extra);
        return;
    }

    if (path == "/api/upload") {
        if (current_session->role == core::Role::READ_ONLY) {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"forbidden\",\"message\":\"Read-only role cannot upload.\"}");
            return;
        }
        std::string rel_dir = get_query_param(req.query, "dir");
        std::string file_name = get_query_param(req.query, "name");
        if (file_name.empty()) {
            send_resp(400, "Bad Request", "application/json", "{\"status\":\"error\",\"message\":\"Missing filename.\"}");
            return;
        }

        // Sanitize file_name to prevent directory traversal
        file_name = fs::path(file_name).filename().string();
        std::string target_rel = rel_dir.empty() ? file_name : (rel_dir + "/" + file_name);

        auto safe = platform::PathUtils::resolve_safe_path(control_server_.workspace_root(), target_rel);
        if (!safe) {
            send_resp(403, "Forbidden", "application/json", "{\"status\":\"error\",\"message\":\"Directory traversal rejected.\"}");
            return;
        }

        // AI Secret Scanner inspection
        if (control_server_.ai_enabled()) {
            ai::AiScanner scanner;
            auto finding = scanner.scan_content(file_name, req.body);
            if (finding.has_secret) {
                control_server_.audit_logger().log(current_session->identity, "AI_UPLOAD_BLOCKED", target_rel, "Secret detected: " + finding.reason, false);
                send_resp(400, "Bad Request", "application/json", "{\"status\":\"blocked\",\"message\":\"AI Guard detected sensitive secret (" + finding.reason + ")! Upload blocked.\"}");
                return;
            }
        }

        platform::PathUtils::ensure_directory(safe->parent_path());
        std::vector<uint8_t> bytes(req.body.begin(), req.body.end());
        if (!platform::PathUtils::write_binary_file_atomic(*safe, bytes)) {
            send_resp(500, "Internal Server Error", "application/json", "{\"status\":\"error\",\"message\":\"Failed to save file.\"}");
            return;
        }

        control_server_.audit_logger().log(current_session->identity, "WEB_UPLOAD", target_rel, "File uploaded successfully (" + std::to_string(bytes.size()) + " bytes)");
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

    // Read headers until \r\n\r\n
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

    // Body
    size_t total_expected = header_end + 4 + content_length;
    if (content_length > 100 * 1024 * 1024) return false; // 100MB max upload

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

} // namespace slug::net
