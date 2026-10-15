#pragma once

#include "src/core/types.hpp"
#include "src/core/acl.hpp"
#include "src/core/audit.hpp"
#include "src/core/utils.hpp"
#include "src/sync/manifest.hpp"
#include "src/bench/benchmark.hpp"
#include "src/policy/rules.hpp"
#include "src/ai/stateful_audit.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>

namespace slug::net {

struct WebSession; // forward declaration

class WebAssets {
public:
    static std::string render_forbidden_page(const std::string& reason) {
        std::ostringstream h;
        h << "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
          << "<title>403 Forbidden - Slug PQC Gateway</title><style>"
          << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; }"
          << ".card { background: #161b22; border: 1px solid #30363d; border-radius: 2px; max-width: 540px; width: 100%; padding: 32px; box-shadow: 0 12px 32px rgba(0,0,0,0.6); }"
          << "h1 { color: #f85149; font-size: 20px; margin-top: 0; display: flex; align-items: center; gap: 8px; }"
          << ".badge { background: #da3633; color: #fff; padding: 2px 8px; border-radius: 2px; font-size: 11px; font-weight: bold; text-transform: uppercase; }"
          << ".msg { font-size: 14px; line-height: 1.6; color: #8b949e; margin: 16px 0; }"
          << ".cli-box { background: #0d1117; border: 1px solid #30363d; border-radius: 2px; padding: 14px; margin-top: 20px; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 13px; color: #58a6ff; line-height: 1.5; }"
          << ".footer { margin-top: 24px; font-size: 12px; color: #484f58; text-align: center; border-top: 1px solid #21262d; padding-top: 14px; }"
          << "</style></head><body><div class='card'>"
          << "<h1><span>Access Denied</span> <span class='badge'>PQC Shield</span></h1>"
          << "<div class='msg'>" << reason << "</div>"
          << "<div class='msg'>Anonymous or unauthenticated web access to this Slug workspace is strictly prohibited. You must authenticate through the Slug CLI to negotiate a Post-Quantum session certificate.</div>"
          << "<div class='cli-box'>"
          << "<span style='color:#8b949e;'># Step 1: Connect via Slug CLI</span><br>"
          << "slug connect -i &lt;host_ip&gt; -p &lt;port&gt; -o &lt;totp_code&gt; -w<br><br>"
          << "<span style='color:#8b949e;'># Step 2: Or open an active saved connection</span><br>"
          << "slug conn list<br>"
          << "slug conn &lt;connection_id&gt; -w"
          << "</div>"
          << "<div class='footer'>Slug &bull; Post-Quantum Cryptographic Isolation &bull; Apache-2.0</div>"
          << "</div></body></html>";
        return h.str();
    }

    static std::string render_directory_listing(
        const std::filesystem::path& workspace_root,
        uint16_t port,
        core::SuiteID suite_id,
        const std::string& rel_subpath,
        const std::string& identity,
        core::Role role)
    {
        auto manifest = sync::ManifestBuilder::build(workspace_root, 1, static_cast<uint8_t>(suite_id), false);

        std::string norm_sub = rel_subpath;
        while (!norm_sub.empty() && norm_sub.front() == '/') norm_sub.erase(0, 1);
        while (!norm_sub.empty() && norm_sub.back() == '/') norm_sub.pop_back();

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

        std::sort(entries.begin(), entries.end(), [](const DirEntry& a, const DirEntry& b) {
            if (a.is_dir != b.is_dir) return a.is_dir > b.is_dir;
            return a.name < b.name;
        });

        std::string parent_dir = "";
        if (!norm_sub.empty()) {
            size_t last_slash = norm_sub.find_last_of('/');
            if (last_slash != std::string::npos) {
                parent_dir = norm_sub.substr(0, last_slash);
            }
        }

        std::ostringstream h;
        h << "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
          << "<title>Slug - " << workspace_root.filename().string() << " / " << (norm_sub.empty() ? "root" : norm_sub) << "</title><style>"
          << ":root { --bg-canvas: #0d1117; --bg-surface: #161b22; --bg-surface-hover: #21262d; --border-primary: #30363d; --border-focus: #58a6ff; --radius-sharp: 2px; --text-main: #f0f6fc; --text-muted: #8b949e; --text-accent: #58a6ff; --success: #238636; --warning: #d29922; --danger: #f85149; }"
          << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg-canvas); color: var(--text-main); margin: 0; padding: 24px; }"
          << ".container { max-width: 980px; margin: 0 auto; background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }"
          << ".top-bar { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border-primary); padding-bottom: 16px; margin-bottom: 16px; }"
          << "h1 { color: var(--text-accent); font-size: 20px; margin: 0; display: flex; align-items: center; gap: 8px; font-family: 'JetBrains Mono', monospace; }"
          << ".badge { background: var(--success); color: #fff; padding: 2px 8px; border-radius: var(--radius-sharp); font-size: 11px; font-weight: 500; font-family: 'JetBrains Mono', monospace; }"
          << ".pqc-badge { background: #8957e5; color: #fff; padding: 2px 8px; border-radius: var(--radius-sharp); font-size: 11px; font-weight: 500; font-family: 'JetBrains Mono', monospace; }"
          << ".user-badge { background: var(--bg-surface-hover); border: 1px solid var(--border-primary); color: var(--text-main); padding: 4px 10px; border-radius: var(--radius-sharp); font-size: 12px; display: inline-flex; align-items: center; gap: 6px; font-family: 'JetBrains Mono', monospace; }"
          << ".role-tag { background: #1f6feb; color: #fff; padding: 1px 6px; border-radius: var(--radius-sharp); font-size: 10px; text-transform: uppercase; font-weight: bold; font-family: 'JetBrains Mono', monospace; }"
          << ".nav-bar { display: flex; align-items: center; justify-content: space-between; background: var(--bg-surface-hover); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 10px 16px; margin-bottom: 16px; flex-wrap: wrap; gap: 10px; }"
          << ".breadcrumb { font-size: 14px; font-family: 'JetBrains Mono', monospace; display: flex; align-items: center; gap: 4px; }"
          << ".breadcrumb a { color: var(--text-accent); text-decoration: none; }"
          << ".breadcrumb a:hover { text-decoration: underline; }"
          << ".actions { display: flex; align-items: center; gap: 8px; }"
          << ".btn { background: var(--success); color: #fff; padding: 6px 12px; border-radius: var(--radius-sharp); text-decoration: none; font-size: 13px; font-weight: 500; border: none; cursor: pointer; display: inline-flex; align-items: center; gap: 6px; font-family: 'JetBrains Mono', monospace; }"
          << ".btn:hover { background: #2ea043; }"
          << ".btn-sec { background: var(--bg-surface-hover); border: 1px solid var(--border-primary); color: var(--text-main); padding: 6px 12px; border-radius: var(--radius-sharp); text-decoration: none; font-size: 13px; font-weight: 500; display: inline-flex; align-items: center; gap: 6px; font-family: 'JetBrains Mono', monospace; }"
          << ".btn-sec:hover { background: var(--border-primary); }"
          << "table { width: 100%; border-collapse: collapse; margin-top: 8px; font-family: 'JetBrains Mono', monospace; }"
          << "th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--bg-surface-hover); font-size: 13px; }"
          << "th { background: var(--bg-surface); color: var(--text-muted); border-bottom: 2px solid var(--border-primary); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }"
          << "tr.item-row:hover { background: var(--bg-surface-hover); }"
          << "a.entry-name { color: var(--text-accent); text-decoration: none; font-weight: 500; display: inline-flex; align-items: center; gap: 6px; }"
          << "a.entry-name:hover { text-decoration: underline; }"
          << ".dropzone-active { border: 2px dashed var(--border-focus) !important; background: rgba(88, 166, 255, 0.05) !important; }"
          << ".context-menu { position: absolute; background: var(--bg-surface-hover); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); box-shadow: 0 8px 24px rgba(0,0,0,0.5); padding: 4px 0; z-index: 1000; min-width: 160px; display: none; }"
          << ".context-menu a { display: block; padding: 8px 16px; color: var(--text-main); text-decoration: none; font-size: 13px; font-family: 'JetBrains Mono', monospace; }"
          << ".context-menu a:hover { background: var(--border-primary); color: var(--text-accent); }"
          << "#upload-toast { position: fixed; bottom: 20px; right: 20px; background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 12px 18px; box-shadow: 0 8px 24px rgba(0,0,0,0.6); font-size: 13px; font-family: 'JetBrains Mono', monospace; z-index: 9999; display: none; }"
          << ".footer { margin-top: 24px; font-size: 12px; color: var(--text-muted); text-align: center; border-top: 1px solid var(--border-primary); padding-top: 16px; font-family: 'JetBrains Mono', monospace; }"
          << "</style><script>"
          << "const currentDir = '" << norm_sub << "';"
          << "const canWrite = " << (role != core::Role::READ_ONLY ? "true" : "false") << ";"
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
          << "window.addEventListener('dragover', e => { e.preventDefault(); document.getElementById('drop-container').classList.add('dropzone-active'); });"
          << "window.addEventListener('dragleave', e => { if (e.clientX <= 0 || e.clientY <= 0) document.getElementById('drop-container').classList.remove('dropzone-active'); });"
          << "window.addEventListener('drop', e => {"
          << "  e.preventDefault();"
          << "  document.getElementById('drop-container').classList.remove('dropzone-active');"
          << "  if (e.dataTransfer && e.dataTransfer.files) uploadFiles(e.dataTransfer.files);"
          << "});"
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
          << "<div class='top-bar'>"
          << "<h1><span>Slug Workspace Dropbox</span> <span class='badge'>Port " << port << "</span>"
          << "<span class='pqc-badge'>" << core::suite_to_string(suite_id) << "</span></h1>"
          << "<div style='display:flex; align-items:center; gap:12px;'>"
          << "<div class='user-badge'><span>👤</span> " << identity << " <span class='role-tag'>" << core::role_to_string(role) << "</span></div>"
          << (identity == "host_admin" ? "<a class='btn-sec' href='/admin'>Admin Dashboard</a>" : "")
          << "<a class='btn-sec' href='/logout' style='color:#f85149;'>Logout</a>"
          << "</div>"
          << "</div>"
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
          << (role != core::Role::READ_ONLY ? "<button class='btn' onclick='triggerUpload()'>+ Upload File</button>" : "<span style='font-size:12px; color:#8b949e;'>Read-Only Mode</span>")
          << "</div>"
          << "</div>";

        if (role == core::Role::WRITE_ONLY) {
            h << "<div style='background:#161b22; border:2px dashed #30363d; border-radius:2px; padding:48px 20px; text-align:center; margin-top:20px; font-family:\"JetBrains Mono\", monospace;'>"
              << "<div style='font-size:42px; margin-bottom:12px;'>📥</div>"
              << "<h2 style='color:#58a6ff; margin:0 0 8px 0; font-size:18px;'>Blind Drop Inbox (Write-Only Mode)</h2>"
              << "<p style='color:#8b949e; margin:0 0 20px 0; font-size:13px;'>You have write-only permission to deposit files into this workspace.<br>Existing workspace files are strictly shielded and hidden.</p>"
              << "<button class='btn' onclick='triggerUpload()' style='font-size:14px; padding:8px 20px;'>+ Select & Upload Files</button>"
              << "<p style='color:#6e7681; margin:16px 0 0 0; font-size:12px;'>Or drag and drop files anywhere into this window</p>"
              << "</div>";
        } else {
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

        if (!manifest.skipped.empty()) {
            h << "<details style='margin-top:24px; background:#161b22; border:1px solid #30363d; border-radius:2px; padding:12px; font-family:\"JetBrains Mono\", monospace;'>"
              << "<summary style='cursor:pointer; color:#e3b341; font-weight:600; font-size:13px;'>"
              << "Shielded / Skipped Items (" << manifest.skipped.size() << " files) &mdash; Click to view filter log"
              << "</summary>"
              << "<div style='max-height:140px; overflow-y:auto; margin-top:10px; font-family:\"JetBrains Mono\", monospace; font-size:12px; color:#8b949e; background:#0d1117; padding:8px 12px; border-radius:2px; line-height:1.6;'>";
            for (const auto& s : manifest.skipped) {
                h << "<div>[SKIPPED] " << s.relative_path << " &mdash; " << s.reason << "</div>";
            }
            h << "</div></details>";
        }

        h << "<div id='context-menu' class='context-menu'>"
          << "<a href='javascript:void(0)' onclick='ctxDownload()'>⬇ Download File</a>"
          << "<a href='javascript:void(0)' onclick='ctxCopy()'>📋 Copy Relative Path</a>"
          << "</div>"
          << "<div id='upload-toast'></div>"
          << "<div class='footer'>Slug &bull; Post-Quantum P2P Workspace Sharing & Dev Shield &bull; Apache-2.0</div>"
          << "</div></body></html>";

        return h.str();
    }

    static std::string render_admin_dashboard(
        const std::filesystem::path& workspace_root,
        uint16_t port,
        core::SuiteID suite_id,
        bool ai_enabled,
        const std::string& identity,
        const std::vector<core::UserAccount>& users,
        const std::vector<core::AuditEvent>& events,
        const bench::FullBenchmarkReport& bench_rep,
        const std::vector<policy::SlugRule>& rules,
        const std::vector<ai::AuditIndexEntry>& audit_entries)
    {
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
          << "<title>Slug Admin Dashboard</title><style>"
          << ":root { --bg-canvas: #0d1117; --bg-surface: #161b22; --bg-surface-hover: #21262d; --border-primary: #30363d; --border-focus: #58a6ff; --radius-sharp: 2px; --text-main: #f0f6fc; --text-muted: #8b949e; --text-accent: #58a6ff; --success: #238636; --warning: #d29922; --danger: #f85149; }"
          << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg-canvas); color: var(--text-main); margin: 0; padding: 24px; }"
          << ".container { max-width: 1040px; margin: 0 auto; background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }"
          << ".top-bar { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border-primary); padding-bottom: 16px; margin-bottom: 20px; }"
          << "h1 { color: var(--text-accent); font-size: 20px; margin: 0; font-family: 'JetBrains Mono', monospace; }"
          << ".grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 20px 0; }"
          << ".card { background: var(--bg-surface-hover); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 16px; }"
          << ".card h3 { margin-top: 0; font-size: 14px; color: var(--text-muted); border-bottom: 1px solid var(--border-primary); padding-bottom: 8px; display:flex; justify-content:space-between; align-items:center; font-family: 'JetBrains Mono', monospace; }"
          << ".metric-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 12px 0; }"
          << ".metric-box { background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 12px; text-align: center; font-family: 'JetBrains Mono', monospace; }"
          << ".metric-val { font-size: 20px; font-weight: bold; color: var(--text-accent); margin-top: 4px; transition: all 0.3s ease; }"
          << ".metric-lbl { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }"
          << ".bar-track { background: var(--bg-canvas); border-radius: var(--radius-sharp); height: 12px; width: 100%; margin: 6px 0; overflow: hidden; display: flex; }"
          << ".bar-fill { height: 100%; background: var(--success); border-radius: var(--radius-sharp); transition: width 0.4s ease; }"
          << ".bar-pqc { background: #8957e5; }"
          << "table { width: 100%; border-collapse: collapse; font-size: 13px; font-family: 'JetBrains Mono', monospace; }"
          << "th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border-primary); }"
          << "th { color: var(--text-muted); }"
          << ".btn { background: var(--success); color: #fff; padding: 6px 14px; border-radius: var(--radius-sharp); text-decoration: none; font-size: 13px; font-weight: 500; border: none; cursor: pointer; font-family: 'JetBrains Mono', monospace; }"
          << ".btn:hover { background: #2ea043; }"
          << ".btn-sec { background: var(--bg-surface-hover); border: 1px solid var(--border-primary); color: var(--text-main); padding: 6px 12px; border-radius: var(--radius-sharp); text-decoration: none; font-size: 13px; font-weight: 500; font-family: 'JetBrains Mono', monospace; }"
          << ".btn-sec:hover { background: var(--border-primary); }"
          << ".btn-danger { background: var(--danger); color: #fff; padding: 4px 8px; border-radius: var(--radius-sharp); font-size: 11px; border: none; cursor: pointer; font-family: 'JetBrains Mono', monospace; }"
          << ".btn-danger:hover { background: #f85149; }"
          << ".btn-sm { padding: 4px 10px; font-size: 12px; }"
          << ".role-tag { background: #1f6feb; color: #fff; padding: 1px 6px; border-radius: var(--radius-sharp); font-size: 10px; text-transform: uppercase; font-weight: bold; font-family: 'JetBrains Mono', monospace; }"
          << ".input-text { background: var(--bg-canvas); border: 1px solid var(--border-primary); color: var(--text-main); padding: 6px 10px; border-radius: var(--radius-sharp); font-size: 13px; width: 100%; box-sizing: border-box; font-family: 'JetBrains Mono', monospace; }"
          << ".input-select { background: var(--bg-canvas); border: 1px solid var(--border-primary); color: var(--text-main); padding: 6px 10px; border-radius: var(--radius-sharp); font-size: 13px; width: 100%; box-sizing: border-box; font-family: 'JetBrains Mono', monospace; }"
          << ".modal { display: none; position: fixed; z-index: 10000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); align-items: center; justify-content: center; }"
          << ".modal-content { background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 20px; width: 400px; box-shadow: 0 8px 24px rgba(0,0,0,0.8); }"
          << ".form-group { margin-bottom: 12px; }"
          << ".form-group label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 4px; font-family: 'JetBrains Mono', monospace; }"
          << ".log-entry { font-family: 'JetBrains Mono', monospace; font-size: 12px; margin: 4px 0; color: var(--text-muted); }"
          << "</style><script>"
          << "let isBenchmarking = false;"
          << "function runLiveBenchmark() {"
          << "  if (isBenchmarking) return;"
          << "  isBenchmarking = true;"
          << "  const status = document.getElementById('bench-status');"
          << "  if (status) status.innerHTML = '<span style=\"color:#58a6ff;\">● Live Telemetry (Syncing...)</span>';"
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
          << "      const mb3 = document.getElementById('m-blake3'); if (mb3) mb3.innerText = b3 + ' MB/s';"
          << "      const mkem = document.getElementById('m-kem'); if (mkem) mkem.innerText = kem + ' µs';"
          << "      const msig = document.getElementById('m-sig'); if (msig) msig.innerText = sig + ' µs';"
          << "      const mciph = document.getElementById('m-cipher'); if (mciph) mciph.innerText = ciph + ' MB/s';"
          << "      if (rep.ai) {"
          << "        const mai = document.getElementById('m-ai'); if (mai) mai.innerText = Math.round(rep.ai.lines_per_sec) + ' L/s';"
          << "        const mcache = document.getElementById('m-cache'); if (mcache) mcache.innerText = Number(rep.ai.cache_hit_lookup_us).toFixed(2) + ' µs';"
          << "      }"
          << "      if (status) status.innerHTML = '<span style=\"color:#3fb950;\">● Live Telemetry (' + new Date().toLocaleTimeString() + ')</span>';"
          << "      isBenchmarking = false;"
          << "    })"
          << "    .catch(e => {"
          << "      if (status) status.innerHTML = '<span style=\"color:#f85149;\">Telemetry Error</span>';"
          << "      isBenchmarking = false;"
          << "    });"
          << "}"
          << "function formatSec(s, exp) {"
          << "  if (exp === 0) return 'Permanent (∞)';"
          << "  if (s <= 0) return 'Expired';"
          << "  if (s >= 86400) return Math.floor(s/86400) + 'd ' + Math.floor((s%86400)/3600) + 'h';"
          << "  if (s >= 3600) return Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';"
          << "  return s + 's';"
          << "}"
          << "function reloadUsers() {"
          << "  fetch('/api/admin/users')"
          << "    .then(r => r.json())"
          << "    .then(users => {"
          << "      const tbody = document.getElementById('users-tbody');"
          << "      if (!tbody) return;"
          << "      if (!users || users.length === 0) {"
          << "        tbody.innerHTML = '<tr><td colspan=\"4\" style=\"color:#8b949e;\">No user accounts configured</td></tr>';"
          << "        return;"
          << "      }"
          << "      let html = '';"
          << "      users.forEach(u => {"
          << "        let status = (u.expires_at === 0) ? '<span style=\"color:#3fb950;\">Permanent (∞)</span>' :"
          << "                     (u.is_expired ? '<span style=\"color:#f85149;\">Expired</span>' : '<span style=\"color:#3fb950;\">Active (' + formatSec(u.remaining_sec, u.expires_at) + ')</span>');"
          << "        let roleBadge = '<span class=\"role-tag\">' + u.role + '</span>';"
          << "        html += '<tr><td><strong>' + u.username + '</strong></td><td>' + roleBadge + '</td><td>' + status + '</td>'"
          << "             + '<td><button class=\"btn-sec btn-sm\" onclick=\"openEditModal(\\'' + u.username + '\\', \\'' + u.role + '\\')\">Edit</button> '"
          << "             + '<button class=\"btn-danger btn-sm\" onclick=\"deleteUser(\\'' + u.username + '\\')\">Delete</button></td></tr>';"
          << "      });"
          << "      tbody.innerHTML = html;"
          << "    });"
          << "}"
          << "function openAddModal() { document.getElementById('modal-add-user').style.display = 'flex'; }"
          << "function closeAddModal() { document.getElementById('modal-add-user').style.display = 'none'; }"
          << "function submitAddUser(e) {"
          << "  e.preventDefault();"
          << "  const u = document.getElementById('add-u').value.trim();"
          << "  const p = document.getElementById('add-p').value;"
          << "  const r = document.getElementById('add-r').value;"
          << "  const ttl = parseInt(document.getElementById('add-ttl').value);"
          << "  if (!u || !p) { alert('Username and Password required'); return; }"
          << "  fetch('/api/admin/users/add', {"
          << "    method: 'POST',"
          << "    headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ username: u, password: p, role: r, ttl_sec: ttl })"
          << "  }).then(r => r.json()).then(res => {"
          << "    if (res.status === 'ok') {"
          << "      closeAddModal();"
          << "      document.getElementById('add-u').value = '';"
          << "      document.getElementById('add-p').value = '';"
          << "      reloadUsers();"
          << "    } else {"
          << "      alert(res.message || 'Failed to add user');"
          << "    }"
          << "  });"
          << "}"
          << "function openEditModal(username, currentRole) {"
          << "  document.getElementById('edit-u').value = username;"
          << "  document.getElementById('edit-u-display').innerText = username;"
          << "  document.getElementById('edit-p').value = '';"
          << "  document.getElementById('edit-r').value = currentRole;"
          << "  document.getElementById('modal-edit-user').style.display = 'flex';"
          << "}"
          << "function closeEditModal() { document.getElementById('modal-edit-user').style.display = 'none'; }"
          << "function submitEditUser(e) {"
          << "  e.preventDefault();"
          << "  const u = document.getElementById('edit-u').value;"
          << "  const p = document.getElementById('edit-p').value;"
          << "  const r = document.getElementById('edit-r').value;"
          << "  const ttl = parseInt(document.getElementById('edit-ttl').value);"
          << "  const payload = { username: u, role: r };"
          << "  if (p) payload.password = p;"
          << "  if (ttl >= 0) payload.ttl_sec = ttl;"
          << "  fetch('/api/admin/users/update', {"
          << "    method: 'POST',"
          << "    headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify(payload)"
          << "  }).then(r => r.json()).then(res => {"
          << "    if (res.status === 'ok') {"
          << "      closeEditModal();"
          << "      reloadUsers();"
          << "    } else {"
          << "      alert(res.message || 'Failed to update user');"
          << "    }"
          << "  });"
          << "}"
          << "function deleteUser(username) {"
          << "  if (!confirm('Are you sure you want to delete user ' + username + '?')) return;"
          << "  fetch('/api/admin/users/delete', {"
          << "    method: 'POST',"
          << "    headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ username: username })"
          << "  }).then(r => r.json()).then(res => {"
          << "    if (res.status === 'ok') {"
          << "      reloadUsers();"
          << "    } else {"
          << "      alert(res.message || 'Failed to delete user');"
          << "    }"
          << "  });"
          << "}"
          << "function reloadRules() {"
          << "  fetch('/api/admin/rules')"
          << "    .then(r => r.json())"
          << "    .then(rules => {"
          << "      const tbody = document.getElementById('rules-tbody');"
          << "      if (!tbody) return;"
          << "      if (!rules || rules.length === 0) {"
          << "        tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:#8b949e;\">No custom rules configured</td></tr>';"
          << "        return;"
          << "      }"
          << "      let html = '';"
          << "      rules.forEach(r => {"
          << "        let actBadge = (r.action === 'ALLOW') ? '<span style=\"color:#3fb950; font-weight:bold;\">ALLOW</span>' : '<span style=\"color:#f85149; font-weight:bold;\">BLOCK</span>';"
          << "        html += '<tr><td><code>' + r.id + '</code></td><td>' + actBadge + '</td><td><code>' + r.type + '</code></td><td><code>' + r.value + '</code></td>'"
          << "             + '<td><button class=\"btn-danger btn-sm\" onclick=\"deleteRule(\\'' + r.id + '\\')\">Delete</button></td></tr>';"
          << "      });"
          << "      tbody.innerHTML = html;"
          << "    });"
          << "}"
          << "function openAddRuleModal() { document.getElementById('modal-add-rule').style.display = 'flex'; }"
          << "function closeAddRuleModal() { document.getElementById('modal-add-rule').style.display = 'none'; }"
          << "function submitAddRule(e) {"
          << "  e.preventDefault();"
          << "  const id = document.getElementById('rule-id').value.trim();"
          << "  const act = document.getElementById('rule-action').value;"
          << "  const type = document.getElementById('rule-type').value;"
          << "  const val = document.getElementById('rule-val').value.trim();"
          << "  if (!val) { alert('Pattern/Value is required'); return; }"
          << "  fetch('/api/admin/rules/add', {"
          << "    method: 'POST',"
          << "    headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ id: id, action: act, type: type, value: val })"
          << "  }).then(r => r.json()).then(res => {"
          << "    if (res.status === 'ok') {"
          << "      closeAddRuleModal();"
          << "      document.getElementById('rule-id').value = '';"
          << "      document.getElementById('rule-val').value = '';"
          << "      reloadRules();"
          << "    } else {"
          << "      alert(res.message || 'Failed to add rule');"
          << "    }"
          << "  });"
          << "}"
          << "function deleteRule(ruleId) {"
          << "  if (!confirm('Are you sure you want to delete rule ' + ruleId + '?')) return;"
          << "  fetch('/api/admin/rules/delete', {"
          << "    method: 'POST',"
          << "    headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ id: ruleId })"
          << "  }).then(r => r.json()).then(res => {"
          << "    if (res.status === 'ok') {"
          << "      reloadRules();"
          << "    } else {"
          << "      alert(res.message || 'Failed to delete rule');"
          << "    }"
          << "  });"
          << "}"
          << "function reloadAudit() {"
          << "  fetch('/api/admin/audit')"
          << "    .then(r => r.json())"
          << "    .then(entries => {"
          << "      const tbody = document.getElementById('audit-tbody');"
          << "      if (!tbody) return;"
          << "      if (!entries || entries.length === 0) {"
          << "        tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:#8b949e;\">No quarantined or flagged files</td></tr>';"
          << "        return;"
          << "      }"
          << "      let html = '';"
          << "      entries.forEach(e => {"
          << "        let stColor = (e.status === 'CLEAN' || e.status === 'MANUAL_ALLOWED') ? '#3fb950' : '#f85149';"
          << "        html += '<tr><td><code>' + e.file_path + '</code></td><td><span style=\"color:' + stColor + '; font-weight:bold;\">' + e.status + '</span></td>'"
          << "             + '<td>' + (e.line_number > 0 ? 'L' + e.line_number : '-') + '</td><td>' + e.reason + '</td>'"
          << "             + '<td>' + (e.status.indexOf('ALLOWED') === -1 ? '<button class=\"btn btn-sm\" onclick=\"allowAuditFile(\\'' + e.file_path + '\\')\">Whitelist</button>' : '<span style=\"color:#8b949e;\">Whitelisted</span>') + '</td></tr>';"
          << "      });"
          << "      tbody.innerHTML = html;"
          << "    });"
          << "}"
          << "function allowAuditFile(filePath) {"
          << "  const reason = prompt('Reason for whitelisting false positive for:\\n' + filePath, 'Verified safe false positive');"
          << "  if (!reason) return;"
          << "  fetch('/api/admin/audit/allow', {"
          << "    method: 'POST',"
          << "    headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ path: filePath, reason: reason })"
          << "  }).then(r => r.json()).then(res => {"
          << "    if (res.status === 'ok') {"
          << "      reloadAudit();"
          << "    } else {"
          << "      alert(res.message || 'Failed to allow file');"
          << "    }"
          << "  });"
          << "}"
          << "window.addEventListener('DOMContentLoaded', () => {"
          << "  runLiveBenchmark();"
          << "  setInterval(runLiveBenchmark, 3500);"
          << "});"
          << "</script></head><body><div class='container'>"
          << "<div class='top-bar'>"
          << "<h1>Slug Workspace Admin &amp; Security Shield</h1>"
          << "<div style='display:flex; align-items:center; gap:12px;'>"
          << "<span style='font-size:13px; color:#8b949e;'>Operator: <strong style='color:#c9d1d9;'>" << identity << "</strong></span>"
          << "<a class='btn-sec' href='/drop'>&larr; Back to Dropbox</a>"
          << "<a class='btn-sec' href='/logout' style='color:#f85149;'>Logout</a>"
          << "</div>"
          << "</div>"

          // Overview grid
          << "<div class='grid'>"
          << "<div class='card'><h3>Active Server Workspace</h3>"
          << "<p><strong>Port:</strong> " << port << "</p>"
          << "<p><strong>Suite:</strong> <span style='color:#a371f7; font-weight:bold;'>" << core::suite_to_string(suite_id) << "</span></p>"
          << "<p><strong>Path:</strong> " << workspace_root.string() << "</p>"
          << "<p><strong>AI Secret Shield:</strong> " << (ai_enabled ? "<span style='color:#3fb950;'>ACTIVE</span>" : "OFF") << "</p>"
          << "</div>"

          << "<div class='card'><h3><span>User Accounts &amp; Ephemeral Roles</span><button class='btn btn-sm' onclick='openAddModal()'>+ Create Account</button></h3>"
          << "<table><thead><tr><th>User</th><th>Role</th><th>Status/TTL</th><th>Actions</th></tr></thead><tbody id='users-tbody'>";

        uint64_t now = core::Utils::current_timestamp();
        for (const auto& u : users) {
            std::string status = (u.expires_at == 0) ? "<span style='color:#3fb950;'>Permanent (∞)</span>" :
                                 (u.is_expired(now) ? "<span style='color:#f85149'>Expired</span>" :
                                 ("<span style='color:#3fb950'>Active (" + core::Utils::format_ttl((u.expires_at > now) ? (u.expires_at - now) : 0) + ")</span>"));
            h << "<tr><td><strong>" << u.username << "</strong></td><td><span class='role-tag'>" << core::role_to_string(u.role) << "</span></td><td>"
              << status
              << "</td><td><button class='btn-sec btn-sm' onclick=\"openEditModal('" << u.username << "', '" << core::role_to_string(u.role) << "')\">Edit</button> "
              << "<button class='btn-danger btn-sm' onclick=\"deleteUser('" << u.username << "')\">Delete</button></td></tr>";
        }
        if (users.empty()) {
            h << "<tr><td colspan='4' style='color:#8b949e;'>No separate user accounts configured</td></tr>";
        }
        h << "</tbody></table></div></div>"

          // Real-time benchmark card
          << "<div class='card' style='margin-bottom: 16px;'>"
          << "<h3><span>Performance &amp; Cryptographic Benchmark</span>"
          << "<span id='bench-status' style='font-size:12px;'></span></h3>"
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

          // Security Rules & AI Guard Quarantine Section
          << "<div class='grid'>"
          << "<div class='card'><h3><span>Security Filter Rules (.slug/rules.conf)</span><button class='btn btn-sm' onclick='openAddRuleModal()'>+ Add Rule</button></h3>"
          << "<table><thead><tr><th>ID</th><th>Action</th><th>Type</th><th>Pattern</th><th>Action</th></tr></thead><tbody id='rules-tbody'>";

        for (const auto& r : rules) {
            std::string t_str;
            switch (r.type) {
                case policy::RuleType::PATH: t_str = "path"; break;
                case policy::RuleType::EXT: t_str = "ext"; break;
                case policy::RuleType::CONTENT: t_str = "content"; break;
                case policy::RuleType::REGEX: t_str = "regex"; break;
            }
            std::string act = (r.action == policy::RuleAction::ALLOW) ? "<span style='color:#3fb950; font-weight:bold;'>ALLOW</span>" : "<span style='color:#f85149; font-weight:bold;'>BLOCK</span>";
            h << "<tr><td><code>" << r.id << "</code></td><td>" << act << "</td><td><code>" << t_str << "</code></td><td><code>" << r.value << "</code></td>"
              << "<td><button class='btn-danger btn-sm' onclick=\"deleteRule('" << r.id << "')\">Delete</button></td></tr>";
        }
        if (rules.empty()) {
            h << "<tr><td colspan='5' style='color:#8b949e;'>No custom rules configured</td></tr>";
        }
        h << "</tbody></table></div>"

          << "<div class='card'><h3><span>AI Guard Quarantined Files (.slug/index.db)</span></h3>"
          << "<table><thead><tr><th>File</th><th>Status</th><th>Line</th><th>AI Reason</th><th>Action</th></tr></thead><tbody id='audit-tbody'>";

        for (const auto& ae : audit_entries) {
            std::string st_str = core::audit_status_to_string(ae.status);
            std::string st_color = (ae.status == core::AuditStatus::CLEAN || ae.status == core::AuditStatus::USER_ALLOWED) ? "#3fb950" : "#f85149";
            h << "<tr><td><code>" << ae.file_path << "</code></td><td><span style='color:" << st_color << "; font-weight:bold;'>" << st_str << "</span></td>"
              << "<td>" << (ae.line_number > 0 ? ("L" + std::to_string(ae.line_number)) : "-") << "</td><td>" << ae.reason << "</td>"
              << "<td>" << (ae.status != core::AuditStatus::USER_ALLOWED ? ("<button class='btn btn-sm' onclick=\"allowAuditFile('" + ae.file_path + "')\">Whitelist</button>") : "<span style='color:#8b949e;'>Whitelisted</span>") << "</td></tr>";
        }
        if (audit_entries.empty()) {
            h << "<tr><td colspan='5' style='color:#8b949e;'>No quarantined or flagged files</td></tr>";
        }
        h << "</tbody></table></div></div>"

          // Audit log card
          << "<div class='card' style='margin-bottom: 16px;'><h3>Recent Security Audit Activity (.slug/audit.log)</h3>"
          << "<div style='max-height:160px; overflow-y:auto; padding:6px;'>";
        for (const auto& e : events) {
            h << "<div class='log-entry'>[" << e.action << "] " << e.actor << " &bull; " << e.path << " &bull; " << e.reason << "</div>";
        }
        if (events.empty()) {
            h << "<div class='log-entry'>No audit events recorded yet.</div>";
        }
        h << "</div></div>"

          // Modals for Add & Edit User
          << "<div id='modal-add-user' class='modal'>"
          << "<div class='modal-content'>"
          << "<h3 style='margin-top:0; color:#58a6ff;'>Create Ephemeral User Account</h3>"
          << "<form onsubmit='submitAddUser(event)'>"
          << "<div class='form-group'><label>Username</label><input type='text' id='add-u' class='input-text' placeholder='e.g. dev_guest' required></div>"
          << "<div class='form-group'><label>Password</label><input type='password' id='add-p' class='input-text' placeholder='Strong password' required></div>"
          << "<div class='form-group'><label>Permission Role</label>"
          << "<select id='add-r' class='input-select'>"
          << "<option value='r'>[r] Read-Only (Pull / View files only)</option>"
          << "<option value='rw' selected>[rw] Read-Write (Full Sync &amp; Drop)</option>"
          << "<option value='w'>[w] Write-Only (Blind Drop only)</option>"
          << "</select></div>"
          << "<div class='form-group'><label>Session TTL</label>"
          << "<select id='add-ttl' class='input-select'>"
          << "<option value='3600'>1 Hour (1h)</option>"
          << "<option value='14400'>4 Hours (4h)</option>"
          << "<option value='86400' selected>24 Hours (1d)</option>"
          << "<option value='604800'>7 Days (7d)</option>"
          << "<option value='0'>Permanent (∞ no expiry)</option>"
          << "</select></div>"
          << "<div style='display:flex; justify-content:flex-end; gap:8px; margin-top:16px;'>"
          << "<button type='button' class='btn-sec' onclick='closeAddModal()'>Cancel</button>"
          << "<button type='submit' class='btn'>Create User</button>"
          << "</div></form></div></div>"

          << "<div id='modal-edit-user' class='modal'>"
          << "<div class='modal-content'>"
          << "<h3 style='margin-top:0; color:#58a6ff;'>Edit User Account: <span id='edit-u-display' style='color:#fff;'></span></h3>"
          << "<form onsubmit='submitEditUser(event)'>"
          << "<input type='hidden' id='edit-u'>"
          << "<div class='form-group'><label>New Password (leave blank to keep unchanged)</label><input type='password' id='edit-p' class='input-text' placeholder='New password'></div>"
          << "<div class='form-group'><label>Permission Role</label>"
          << "<select id='edit-r' class='input-select'>"
          << "<option value='r'>[r] Read-Only (Pull / View files only)</option>"
          << "<option value='rw'>[rw] Read-Write (Full Sync &amp; Drop)</option>"
          << "<option value='w'>[w] Write-Only (Blind Drop only)</option>"
          << "</select></div>"
          << "<div class='form-group'><label>Update TTL</label>"
          << "<select id='edit-ttl' class='input-select'>"
          << "<option value='-1'>Keep existing expiration</option>"
          << "<option value='3600'>1 Hour (1h)</option>"
          << "<option value='14400'>4 Hours (4h)</option>"
          << "<option value='86400'>24 Hours (1d)</option>"
          << "<option value='604800'>7 Days (7d)</option>"
          << "<option value='0'>Permanent (∞ no expiry)</option>"
          << "</select></div>"
          << "<div style='display:flex; justify-content:flex-end; gap:8px; margin-top:16px;'>"
          << "<button type='button' class='btn-sec' onclick='closeEditModal()'>Cancel</button>"
          << "<button type='submit' class='btn'>Save Changes</button>"
          << "</div></form></div></div>"

          // Modal for Add Rule
          << "<div id='modal-add-rule' class='modal'>"
          << "<div class='modal-content'>"
          << "<h3 style='margin-top:0; color:#58a6ff;'>Add Security Filter Rule</h3>"
          << "<form onsubmit='submitAddRule(event)'>"
          << "<div class='form-group'><label>Rule ID (Optional)</label><input type='text' id='rule-id' class='input-text' placeholder='e.g. block_certs'></div>"
          << "<div class='form-group'><label>Action</label>"
          << "<select id='rule-action' class='input-select'>"
          << "<option value='block' selected>BLOCK</option>"
          << "<option value='allow'>ALLOW</option>"
          << "</select></div>"
          << "<div class='form-group'><label>Rule Type</label>"
          << "<select id='rule-type' class='input-select'>"
          << "<option value='path' selected>Path (exact/prefix glob)</option>"
          << "<option value='ext'>Extension (.key, .pem)</option>"
          << "<option value='content'>Content contains</option>"
          << "<option value='regex'>Regex pattern</option>"
          << "</select></div>"
          << "<div class='form-group'><label>Pattern / Value</label><input type='text' id='rule-val' class='input-text' placeholder='e.g. *.pem or /private/*' required></div>"
          << "<div style='display:flex; justify-content:flex-end; gap:8px; margin-top:16px;'>"
          << "<button type='button' class='btn-sec' onclick='closeAddRuleModal()'>Cancel</button>"
          << "<button type='submit' class='btn'>Add Rule</button>"
          << "</div></form></div></div>"

          << "<div class='footer'>Slug &bull; Post-Quantum P2P Workspace Sharing & Dev Shield &bull; Apache-2.0</div>"
          << "</div></body></html>";

        return h.str();
    }
};

} // namespace slug::net
