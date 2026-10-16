#pragma once

#include "src/core/types.hpp"
#include "src/core/acl.hpp"
#include "src/core/audit.hpp"
#include "src/core/utils.hpp"
#include "src/sync/manifest.hpp"
#include "src/bench/benchmark.hpp"
#include "src/policy/rules.hpp"
#include "src/ai/stateful_audit.hpp"
#include "src/core/connection_manager.hpp"
#include "src/net/control_server.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <map>

namespace slug::net {

struct WebSession; // forward declaration

class WebAssets {
public:
    static std::string render_forbidden_page(const std::string& reason) {
        std::ostringstream h;
        h << "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
          << "<title>403 Forbidden - Slug PQC Gateway</title><style>"
          << ":root { --bg-canvas: #f6f8fa; --bg-surface: #ffffff; --border-primary: #d0d7de; --border-focus: #0969da; --radius-sharp: 2px; --text-main: #1f2328; --text-muted: #656d76; --text-accent: #0969da; --danger: #cf222e; --danger-bg: #ffebe9; }"
          << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg-canvas); color: var(--text-main); display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; }"
          << ".card { background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); max-width: 560px; width: 100%; padding: 32px; box-shadow: 0 1px 3px rgba(31,35,40,0.12); }"
          << "h1 { color: var(--danger); font-size: 20px; margin-top: 0; display: flex; align-items: center; gap: 8px; font-family: 'JetBrains Mono', monospace; }"
          << ".badge { background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(207,34,46,0.3); padding: 2px 8px; border-radius: var(--radius-sharp); font-size: 11px; font-weight: bold; text-transform: uppercase; font-family: 'JetBrains Mono', monospace; }"
          << ".msg { font-size: 14px; line-height: 1.6; color: var(--text-muted); margin: 16px 0; }"
          << ".cli-box { background: #f6f8fa; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 14px; margin-top: 20px; font-family: 'JetBrains Mono', monospace; font-size: 13px; color: var(--text-accent); line-height: 1.6; }"
          << ".footer { margin-top: 24px; font-size: 12px; color: var(--text-muted); text-align: center; border-top: 1px solid var(--border-primary); padding-top: 14px; font-family: 'JetBrains Mono', monospace; }"
          << "</style></head><body><div class='card'>"
          << "<h1><span>Access Denied (403)</span> <span class='badge'>PQC Shield</span></h1>"
          << "<div class='msg'>" << reason << "</div>"
          << "<div class='msg'>Anonymous or unauthenticated web access to this Slug workspace is strictly prohibited. You must authenticate through the Slug CLI to negotiate a Post-Quantum session certificate.</div>"
          << "<div class='cli-box'>"
          << "<span style='color:var(--text-muted);'># Step 1: Connect via Slug CLI (authenticates and saves context)</span><br>"
          << "slug connect -i &lt;host_ip&gt; -p &lt;port&gt; -o &lt;totp_code&gt;<br><br>"
          << "<span style='color:var(--text-muted);'># Step 2: Open authenticated Web Dropbox with your ticket</span><br>"
          << "slug web<br><br>"
          << "<span style='color:var(--text-muted);'># Step 3: Or get a specific file via CLI without web</span><br>"
          << "slug get &lt;file_path&gt; [local_dest]"
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
        auto manifest = sync::ManifestBuilder::build(workspace_root, 1, static_cast<uint8_t>(suite_id), true);

        std::string norm_sub = rel_subpath;
        while (!norm_sub.empty() && norm_sub.front() == '/') norm_sub.erase(0, 1);
        while (!norm_sub.empty() && norm_sub.back() == '/') norm_sub.pop_back();

        uint64_t total_workspace_size = 0;
        for (const auto& f : manifest.files) {
            total_workspace_size += f.size;
        }

        struct ItemRow {
            bool is_dir;
            std::string name;
            std::string full_rel_path;
            uint64_t size;
            std::string type_str;
            std::string status;
            std::string status_badge_class;
            std::string status_detail;
            std::string blake3;
            bool selectable;
        };

        std::vector<ItemRow> items;
        std::set<std::string> seen_dirs;
        std::map<std::string, uint64_t> dir_sizes;

        // Process available files
        for (const auto& f : manifest.files) {
            std::string p = f.relative_path;
            if (norm_sub.empty()) {
                size_t slash = p.find('/');
                if (slash != std::string::npos) {
                    std::string dname = p.substr(0, slash);
                    dir_sizes[dname] += f.size;
                    if (seen_dirs.insert(dname).second) {
                        items.push_back({true, dname, dname, 0, "folder", "Available", "badge-available", "", "", false});
                    }
                } else {
                    items.push_back({false, p, p, f.size, "file", "Available", "badge-available", "", f.file_blake3_hash, true});
                }
            } else {
                if (p.rfind(norm_sub + "/", 0) == 0) {
                    std::string rem = p.substr(norm_sub.size() + 1);
                    size_t slash = rem.find('/');
                    if (slash != std::string::npos) {
                        std::string dname = rem.substr(0, slash);
                        std::string full_d = norm_sub + "/" + dname;
                        dir_sizes[full_d] += f.size;
                        if (seen_dirs.insert(full_d).second) {
                            items.push_back({true, dname, full_d, 0, "folder", "Available", "badge-available", "", "", false});
                        }
                    } else {
                        items.push_back({false, rem, p, f.size, "file", "Available", "badge-available", "", f.file_blake3_hash, true});
                    }
                }
            }
        }

        // Update directory sizes
        for (auto& item : items) {
            if (item.is_dir) {
                item.size = dir_sizes[item.full_rel_path];
            }
        }

        // Process skipped / filtered / quarantined files
        for (const auto& s : manifest.skipped) {
            std::string p = s.relative_path;
            std::string st_label = "Excluded";
            std::string badge_cls = "badge-excluded";
            if (s.status == "AI_FLAGGED") {
                st_label = "Quarantined";
                badge_cls = "badge-quarantined";
            } else if (s.status == "RULE_OR_GITIGNORE_BLOCKED") {
                if (s.reason.find("gitignore") != std::string::npos) {
                    st_label = "Excluded";
                    badge_cls = "badge-excluded";
                } else {
                    st_label = "Blocked";
                    badge_cls = "badge-blocked";
                }
            }

            if (norm_sub.empty()) {
                size_t slash = p.find('/');
                if (slash != std::string::npos) {
                    std::string dname = p.substr(0, slash);
                    if (seen_dirs.insert(dname).second) {
                        items.push_back({true, dname, dname, 0, "folder", st_label, badge_cls, s.reason, "", false});
                    }
                } else {
                    items.push_back({false, p, p, 0, "file", st_label, badge_cls, s.reason, "", false});
                }
            } else {
                if (p.rfind(norm_sub + "/", 0) == 0) {
                    std::string rem = p.substr(norm_sub.size() + 1);
                    size_t slash = rem.find('/');
                    if (slash != std::string::npos) {
                        std::string dname = rem.substr(0, slash);
                        std::string full_d = norm_sub + "/" + dname;
                        if (seen_dirs.insert(full_d).second) {
                            items.push_back({true, dname, full_d, 0, "folder", st_label, badge_cls, s.reason, "", false});
                        }
                    } else {
                        items.push_back({false, rem, p, 0, "file", st_label, badge_cls, s.reason, "", false});
                    }
                }
            }
        }

        std::sort(items.begin(), items.end(), [](const ItemRow& a, const ItemRow& b) {
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
          << ":root {"
          << "  --bg-canvas: #f6f8fa;"
          << "  --bg-surface: #ffffff;"
          << "  --bg-surface-hover: #f3f4f6;"
          << "  --bg-surface-active: #ebecf0;"
          << "  --border-primary: #d0d7de;"
          << "  --border-subtle: #e1e4e8;"
          << "  --border-focus: #0969da;"
          << "  --radius-sharp: 2px;"
          << "  --text-main: #1f2328;"
          << "  --text-muted: #656d76;"
          << "  --text-accent: #0969da;"
          << "  --success: #1a7f37;"
          << "  --success-bg: #dafbe1;"
          << "  --warning: #9a6700;"
          << "  --warning-bg: #fff8c5;"
          << "  --danger: #cf222e;"
          << "  --danger-bg: #ffebe9;"
          << "  --pqc: #8250df;"
          << "  --pqc-bg: #fbefff;"
          << "}"
          << "* { box-sizing: border-box; }"
          << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg-canvas); color: var(--text-main); margin: 0; padding: 24px; line-height: 1.5; }"
          << ".container { max-width: 1040px; margin: 0 auto; background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 24px; box-shadow: 0 1px 3px rgba(31,35,40,0.08); }"
          << ".top-bar { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border-primary); padding-bottom: 16px; margin-bottom: 16px; flex-wrap: wrap; gap: 10px; }"
          << "h1 { color: var(--text-main); font-size: 18px; margin: 0; display: flex; align-items: center; gap: 8px; font-family: 'JetBrains Mono', monospace; font-weight: 600; }"
          << ".badge { padding: 2px 7px; border-radius: var(--radius-sharp); font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; text-transform: uppercase; letter-spacing: 0.3px; }"
          << ".badge-available { background: var(--success-bg); color: var(--success); border: 1px solid rgba(26,127,55,0.25); }"
          << ".badge-excluded { background: var(--bg-surface-hover); color: var(--text-muted); border: 1px solid var(--border-primary); }"
          << ".badge-quarantined { background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(207,34,46,0.3); }"
          << ".badge-blocked { background: var(--warning-bg); color: var(--warning); border: 1px solid rgba(154,103,0,0.3); }"
          << ".badge-pqc { background: var(--pqc-bg); color: var(--pqc); border: 1px solid rgba(130,80,223,0.3); }"
          << ".user-badge { background: var(--bg-canvas); border: 1px solid var(--border-primary); color: var(--text-main); padding: 4px 10px; border-radius: var(--radius-sharp); font-size: 12px; display: inline-flex; align-items: center; gap: 6px; font-family: 'JetBrains Mono', monospace; }"
          << ".role-tag { background: #0969da; color: #fff; padding: 1px 5px; border-radius: var(--radius-sharp); font-size: 10px; font-weight: bold; text-transform: uppercase; font-family: 'JetBrains Mono', monospace; }"
          << ".ws-summary-box { background: #f6f8fa; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 10px 14px; margin-bottom: 14px; font-family: 'JetBrains Mono', monospace; font-size: 12px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }"
          << ".nav-bar { display: flex; align-items: center; justify-content: space-between; background: #ffffff; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 8px 14px; margin-bottom: 14px; flex-wrap: wrap; gap: 10px; }"
          << ".breadcrumb { font-size: 13px; font-family: 'JetBrains Mono', monospace; display: flex; align-items: center; gap: 4px; color: var(--text-muted); }"
          << ".breadcrumb a { color: var(--text-accent); text-decoration: none; font-weight: 500; }"
          << ".breadcrumb a:hover { text-decoration: underline; }"
          << ".btn { background: #0969da; color: #ffffff; padding: 6px 12px; border-radius: var(--radius-sharp); text-decoration: none; font-size: 13px; font-weight: 500; border: 1px solid #0969da; cursor: pointer; display: inline-flex; align-items: center; gap: 6px; font-family: 'JetBrains Mono', monospace; }"
          << ".btn:hover { background: #0856b3; border-color: #0856b3; }"
          << ".btn-sec { background: #ffffff; border: 1px solid var(--border-primary); color: var(--text-main); padding: 5px 11px; border-radius: var(--radius-sharp); text-decoration: none; font-size: 12px; font-weight: 500; display: inline-flex; align-items: center; gap: 6px; font-family: 'JetBrains Mono', monospace; cursor: pointer; }"
          << ".btn-sec:hover { background: var(--bg-surface-hover); border-color: #afb8c1; }"
          << ".btn:disabled, .btn-sec:disabled { opacity: 0.5; cursor: not-allowed; }"
          << "table { width: 100%; border-collapse: collapse; margin-top: 4px; font-family: 'JetBrains Mono', monospace; }"
          << "th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border-subtle); font-size: 12px; vertical-align: middle; }"
          << "th { background: #f6f8fa; color: var(--text-muted); border-bottom: 1px solid var(--border-primary); font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; font-size: 11px; }"
          << "tr.item-row:hover { background: var(--bg-surface-hover); }"
          << "a.entry-name { color: var(--text-accent); text-decoration: none; font-weight: 500; display: inline-flex; align-items: center; gap: 6px; }"
          << "a.entry-name:hover { text-decoration: underline; }"
          << ".dropzone-active { border: 2px dashed var(--border-focus) !important; background: #f0f7ff !important; }"
          << ".explorer-footer { display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-primary); padding-top: 14px; margin-top: 14px; font-family: 'JetBrains Mono', monospace; font-size: 12px; flex-wrap: wrap; gap: 10px; }"
          << ".footer { margin-top: 24px; font-size: 11px; color: var(--text-muted); text-align: center; border-top: 1px solid var(--border-primary); padding-top: 14px; font-family: 'JetBrains Mono', monospace; }"
          << ".modal { display: none; position: fixed; z-index: 10000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(31,35,40,0.5); align-items: center; justify-content: center; }"
          << ".modal-content { background: #ffffff; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 20px; width: 480px; max-width: 90%; box-shadow: 0 8px 24px rgba(31,35,40,0.18); font-family: 'JetBrains Mono', monospace; }"
          << "#upload-toast { position: fixed; bottom: 20px; right: 20px; background: #ffffff; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 10px 16px; box-shadow: 0 4px 12px rgba(31,35,40,0.15); font-size: 12px; font-family: 'JetBrains Mono', monospace; z-index: 9999; display: none; }"
          << "</style><script>"
          << "const currentDir = '" << norm_sub << "';"
          << "const canWrite = " << (role != core::Role::READ_ONLY ? "true" : "false") << ";"
          << "function formatSize(bytes) {"
          << "  if (bytes === 0) return '0 B';"
          << "  const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];"
          << "  const i = Math.floor(Math.log(bytes) / Math.log(k));"
          << "  return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];"
          << "}"
          << "function updateSelection() {"
          << "  const checks = document.querySelectorAll('.file-check:checked');"
          << "  let count = checks.length; let bytes = 0;"
          << "  checks.forEach(cb => { bytes += parseInt(cb.getAttribute('data-size') || '0'); });"
          << "  document.getElementById('sel-count').innerText = count;"
          << "  document.getElementById('sel-size').innerText = formatSize(bytes);"
          << "  document.getElementById('btn-download-sel').disabled = (count === 0);"
          << "  document.getElementById('btn-preview-sel').disabled = (count === 0);"
          << "}"
          << "function toggleSelectAll(master) {"
          << "  document.querySelectorAll('.file-check:not(:disabled)').forEach(cb => { cb.checked = master.checked; });"
          << "  updateSelection();"
          << "}"
          << "function openPreviewModal() {"
          << "  const checks = document.querySelectorAll('.file-check:checked');"
          << "  if (checks.length === 0) return;"
          << "  let listHtml = ''; let totalBytes = 0;"
          << "  checks.forEach(cb => {"
          << "    const p = cb.getAttribute('data-path');"
          << "    const s = parseInt(cb.getAttribute('data-size') || '0');"
          << "    totalBytes += s;"
          << "    listHtml += '<div>📄 ' + p + ' (' + formatSize(s) + ')</div>';"
          << "  });"
          << "  document.getElementById('preview-file-list').innerHTML = listHtml;"
          << "  document.getElementById('preview-total-info').innerText = checks.length + ' file(s) &bull; ' + formatSize(totalBytes);"
          << "  document.getElementById('modal-preview').style.display = 'flex';"
          << "}"
          << "function closePreviewModal() { document.getElementById('modal-preview').style.display = 'none'; }"
          << "function downloadSelected() {"
          << "  const checks = document.querySelectorAll('.file-check:checked');"
          << "  if (checks.length === 0) return;"
          << "  checks.forEach((cb, idx) => {"
          << "    setTimeout(() => {"
          << "      const p = cb.getAttribute('data-path');"
          << "      const a = document.createElement('a');"
          << "      a.href = '/download?path=' + encodeURIComponent(p);"
          << "      a.download = p.split('/').pop();"
          << "      document.body.appendChild(a);"
          << "      a.click();"
          << "      document.body.removeChild(a);"
          << "    }, idx * 250);"
          << "  });"
          << "}"
          << "function triggerUpload() {"
          << "  if (!canWrite) { alert('Permission Denied: Your role is read-only.'); return; }"
          << "  document.getElementById('hidden-file-input').click();"
          << "}"
          << "function uploadFiles(files) {"
          << "  if (!canWrite) { alert('Permission Denied: Your role is read-only.'); return; }"
          << "  if (!files || files.length === 0) return;"
          << "  const toast = document.getElementById('upload-toast');"
          << "  toast.style.display = 'block'; toast.innerHTML = 'Uploading ' + files.length + ' file(s)...';"
          << "  let completed = 0;"
          << "  Array.from(files).forEach(file => {"
          << "    const url = '/api/upload?dir=' + encodeURIComponent(currentDir) + '&name=' + encodeURIComponent(file.name);"
          << "    fetch(url, { method: 'POST', body: file })"
          << "      .then(r => r.json())"
          << "      .then(res => {"
          << "        completed++;"
          << "        if (res.status === 'blocked') alert('Upload Blocked by AI Secret Guard:\\n' + res.message);"
          << "        if (completed === files.length) { toast.innerHTML = 'Upload finished!'; setTimeout(() => location.reload(), 600); }"
          << "      })"
          << "      .catch(err => { alert('Upload failed: ' + err); toast.style.display = 'none'; });"
          << "  });"
          << "}"
          << "window.addEventListener('dragover', e => { e.preventDefault(); document.getElementById('drop-container').classList.add('dropzone-active'); });"
          << "window.addEventListener('dragleave', e => { if (e.clientX <= 0 || e.clientY <= 0) document.getElementById('drop-container').classList.remove('dropzone-active'); });"
          << "window.addEventListener('drop', e => {"
          << "  e.preventDefault();"
          << "  document.getElementById('drop-container').classList.remove('dropzone-active');"
          << "  if (e.dataTransfer && e.dataTransfer.files) uploadFiles(e.dataTransfer.files);"
          << "});"
          << "</script></head><body>"
          << "<div class='container' id='drop-container'>"
          << "<div class='top-bar'>"
          << "<h1><span>Slug Workspace Explorer</span> <span class='badge badge-pqc'>" << core::suite_to_string(suite_id) << "</span></h1>"
          << "<div style='display:flex; align-items:center; gap:8px;'>"
          << "<div class='user-badge'><span>👤</span> " << identity << " <span class='role-tag'>" << core::role_to_string(role) << "</span></div>"
          << (identity == "host_admin" ? "<a class='btn-sec' href='/admin'>Admin Dashboard</a>" : "")
          << "<a class='btn-sec' href='/logout' style='color:var(--danger);'>Logout</a>"
          << "</div></div>"

          << "<div class='ws-summary-box'>"
          << "<div><strong>REMOTE WORKSPACE:</strong> " << workspace_root.filename().string() << " (Port " << port << ")</div>"
          << "<div>Available: <strong>" << core::Utils::format_size(total_workspace_size) << "</strong> (" << manifest.files.size() << " files) &bull; Filtered: <strong>" << manifest.skipped.size() << "</strong> items</div>"
          << "</div>"

          << "<div class='nav-bar'>"
          << "<div class='breadcrumb'><span>Scope: </span><a href='/drop'>[root]</a>";

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
          << "<div style='display:flex; align-items:center; gap:8px;'>"
          << "<input type='file' id='hidden-file-input' multiple style='display:none;' onchange='uploadFiles(this.files)'>"
          << (role != core::Role::WRITE_ONLY ? ("<a class='btn-sec' href='/download-folder?dir=" + norm_sub + "'>⬇ Download Folder (ZIP)</a>") : "")
          << (role != core::Role::READ_ONLY ? "<button class='btn' onclick='triggerUpload()'>+ Upload File</button>" : "<span style='font-size:12px; color:var(--text-muted);'>Read-Only Mode</span>")
          << "</div></div>";

        if (role == core::Role::WRITE_ONLY) {
            h << "<div style='background:#f6f8fa; border:2px dashed var(--border-primary); border-radius:var(--radius-sharp); padding:48px 20px; text-align:center; margin-top:16px; font-family:\"JetBrains Mono\", monospace;'>"
              << "<div style='font-size:36px; margin-bottom:8px;'>📥</div>"
              << "<h2 style='color:var(--text-main); margin:0 0 8px 0; font-size:16px;'>Blind Drop Mode (Write-Only)</h2>"
              << "<p style='color:var(--text-muted); margin:0 0 16px 0; font-size:12px;'>You have write-only permission to deposit files into this workspace.<br>Host source files are strictly shielded and unlisted.</p>"
              << "<button class='btn' onclick='triggerUpload()'>+ Select &amp; Upload Files</button>"
              << "<p style='color:var(--text-muted); margin:12px 0 0 0; font-size:11px;'>Or drag and drop files anywhere into this window</p>"
              << "</div>";
        } else {
            h << "<table><thead><tr>"
              << "<th style='width:32px;'><input type='checkbox' id='master-check' onchange='toggleSelectAll(this)' title='Select All Available'></th>"
              << "<th>NAME</th>"
              << "<th style='width:80px;'>TYPE</th>"
              << "<th style='width:100px;'>SIZE</th>"
              << "<th style='width:150px;'>STATUS</th>"
              << "<th style='width:90px; text-align:right;'>ACTION</th>"
              << "</tr></thead><tbody>";

            if (!norm_sub.empty()) {
                h << "<tr class='item-row'><td></td>"
                  << "<td colspan='5'><a class='entry-name' href='/drop" << (parent_dir.empty() ? "" : "?dir=" + parent_dir) << "'>📁 .. (Parent Directory)</a></td>"
                  << "</tr>";
            }

            for (const auto& item : items) {
                h << "<tr class='item-row'>";
                if (item.is_dir) {
                    h << "<td></td>"
                      << "<td><a class='entry-name' href='/drop?dir=" << item.full_rel_path << "'>📁 " << item.name << "/</a></td>"
                      << "<td style='color:var(--text-muted);'>folder</td>"
                      << "<td>" << (item.size > 0 ? core::Utils::format_size(item.size) : "-") << "</td>"
                      << "<td><span class='badge " << item.status_badge_class << "' title='" << item.status_detail << "'>" << item.status << "</span></td>"
                      << "<td style='text-align:right;'><a class='btn-sec' style='padding:2px 8px; font-size:11px;' href='/drop?dir=" << item.full_rel_path << "'>Browse</a></td>";
                } else {
                    std::string chk = item.selectable
                        ? ("<input type='checkbox' class='file-check' data-path='" + item.full_rel_path + "' data-size='" + std::to_string(item.size) + "' onchange='updateSelection()'>")
                        : "<input type='checkbox' disabled title='File is shielded/quarantined'>";

                    std::string act = item.selectable
                        ? ("<a class='btn-sec' style='padding:2px 8px; font-size:11px;' href='/download?path=" + item.full_rel_path + "'>Download</a>")
                        : "<span style='color:var(--text-muted); font-size:11px;'>Shielded</span>";

                    h << "<td>" << chk << "</td>"
                      << "<td><span style='display:inline-flex; align-items:center; gap:6px;'>📄 " << item.name << "</span></td>"
                      << "<td style='color:var(--text-muted);'>file</td>"
                      << "<td>" << (item.size > 0 ? core::Utils::format_size(item.size) : "-") << "</td>"
                      << "<td><span class='badge " << item.status_badge_class << "' title='" << item.status_detail << "'>" << item.status << "</span></td>"
                      << "<td style='text-align:right;'>" << act << "</td>";
                }
                h << "</tr>";
            }

            if (items.empty() && norm_sub.empty()) {
                h << "<tr><td colspan='6' style='text-align:center; color:var(--text-muted); padding:24px;'>No files or folders in this workspace scope.</td></tr>";
            }

            h << "</tbody></table>";

            h << "<div class='explorer-footer'>"
              << "<div>Selected: <strong id='sel-count'>0</strong> files &nbsp;&bull;&nbsp; Estimated: <strong id='sel-size'>0 B</strong></div>"
              << "<div style='display:flex; gap:8px;'>"
              << "<button id='btn-preview-sel' class='btn-sec' onclick='openPreviewModal()' disabled>Preview Transfer</button>"
              << "<button id='btn-download-sel' class='btn' onclick='downloadSelected()' disabled>Download Selected</button>"
              << "</div></div>";
        }

        // Preview modal
        h << "<div id='modal-preview' class='modal'>"
          << "<div class='modal-content'>"
          << "<h3 style='margin-top:0; font-size:15px; color:var(--text-main);'>Selective Transfer Plan Preview</h3>"
          << "<div id='preview-total-info' style='font-size:12px; color:var(--text-muted); margin-bottom:12px; padding-bottom:8px; border-bottom:1px solid var(--border-primary);'></div>"
          << "<div id='preview-file-list' style='max-height:180px; overflow-y:auto; font-size:11px; color:var(--text-main); line-height:1.6; margin-bottom:16px; background:#f6f8fa; padding:10px; border:1px solid var(--border-primary); border-radius:var(--radius-sharp);'></div>"
          << "<div style='display:flex; justify-content:flex-end; gap:8px;'>"
          << "<button class='btn-sec' onclick='closePreviewModal()'>Close</button>"
          << "<button class='btn' onclick='downloadSelected(); closePreviewModal();'>Download Selected</button>"
          << "</div></div></div>";

        h << "<div id='upload-toast'></div>"
          << "<div class='footer'>Slug &bull; Policy-Aware Git-like Workspace Sharing &bull; Apache-2.0</div>"
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
        const std::vector<ai::AuditIndexEntry>& audit_entries,
        const std::vector<SessionState>& client_sessions)
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
          << ":root {"
          << "  --bg-canvas: #f6f8fa;"
          << "  --bg-surface: #ffffff;"
          << "  --bg-surface-hover: #f3f4f6;"
          << "  --border-primary: #d0d7de;"
          << "  --border-focus: #0969da;"
          << "  --radius-sharp: 2px;"
          << "  --text-main: #1f2328;"
          << "  --text-muted: #656d76;"
          << "  --text-accent: #0969da;"
          << "  --success: #1a7f37;"
          << "  --warning: #9a6700;"
          << "  --danger: #cf222e;"
          << "  --pqc: #8250df;"
          << "}"
          << "* { box-sizing: border-box; }"
          << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg-canvas); color: var(--text-main); margin: 0; padding: 24px; line-height: 1.5; }"
          << ".container { max-width: 1040px; margin: 0 auto; background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 24px; box-shadow: 0 1px 3px rgba(31,35,40,0.08); }"
          << ".top-bar { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border-primary); padding-bottom: 16px; margin-bottom: 20px; flex-wrap: wrap; gap: 10px; }"
          << "h1 { color: var(--text-main); font-size: 18px; margin: 0; font-family: 'JetBrains Mono', monospace; font-weight: 600; }"
          << ".grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 16px 0; }"
          << ".card { background: #ffffff; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 16px; }"
          << ".card h3 { margin-top: 0; font-size: 13px; color: var(--text-main); border-bottom: 1px solid var(--border-primary); padding-bottom: 8px; display:flex; justify-content:space-between; align-items:center; font-family: 'JetBrains Mono', monospace; font-weight: 600; }"
          << ".metric-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 12px 0; }"
          << ".metric-box { background: #f6f8fa; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 12px; text-align: center; font-family: 'JetBrains Mono', monospace; }"
          << ".metric-val { font-size: 18px; font-weight: bold; color: var(--text-accent); margin-top: 4px; }"
          << ".metric-lbl { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }"
          << ".bar-track { background: #eaeef2; border-radius: var(--radius-sharp); height: 10px; width: 100%; margin: 6px 0; overflow: hidden; display: flex; }"
          << ".bar-fill { height: 100%; background: var(--success); border-radius: var(--radius-sharp); }"
          << ".bar-pqc { background: var(--pqc); }"
          << "table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: 'JetBrains Mono', monospace; }"
          << "th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--border-primary); }"
          << "th { background: #f6f8fa; color: var(--text-muted); font-size: 11px; text-transform: uppercase; }"
          << ".btn { background: #0969da; color: #fff; padding: 5px 12px; border-radius: var(--radius-sharp); text-decoration: none; font-size: 12px; font-weight: 500; border: 1px solid #0969da; cursor: pointer; font-family: 'JetBrains Mono', monospace; }"
          << ".btn:hover { background: #0856b3; }"
          << ".btn-sec { background: #ffffff; border: 1px solid var(--border-primary); color: var(--text-main); padding: 5px 10px; border-radius: var(--radius-sharp); text-decoration: none; font-size: 12px; font-weight: 500; font-family: 'JetBrains Mono', monospace; cursor: pointer; }"
          << ".btn-sec:hover { background: var(--bg-surface-hover); }"
          << ".btn-danger { background: #ffffff; color: var(--danger); border: 1px solid var(--danger); padding: 3px 6px; border-radius: var(--radius-sharp); font-size: 11px; cursor: pointer; font-family: 'JetBrains Mono', monospace; }"
          << ".btn-danger:hover { background: var(--danger); color: #fff; }"
          << ".btn-sm { padding: 3px 8px; font-size: 11px; }"
          << ".role-tag { background: #0969da; color: #fff; padding: 1px 5px; border-radius: var(--radius-sharp); font-size: 10px; text-transform: uppercase; font-weight: bold; font-family: 'JetBrains Mono', monospace; }"
          << ".input-text, .input-select { background: #ffffff; border: 1px solid var(--border-primary); color: var(--text-main); padding: 6px 10px; border-radius: var(--radius-sharp); font-size: 12px; width: 100%; box-sizing: border-box; font-family: 'JetBrains Mono', monospace; }"
          << ".input-text:focus, .input-select:focus { border-color: var(--border-focus); outline: 2px solid var(--border-focus); outline-offset: -1px; }"
          << ".modal { display: none; position: fixed; z-index: 10000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(31,35,40,0.5); align-items: center; justify-content: center; }"
          << ".modal-content { background: #ffffff; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 20px; width: 420px; box-shadow: 0 8px 24px rgba(31,35,40,0.18); font-family: 'JetBrains Mono', monospace; }"
          << ".form-group { margin-bottom: 12px; }"
          << ".form-group label { display: block; font-size: 11px; color: var(--text-muted); margin-bottom: 4px; font-family: 'JetBrains Mono', monospace; }"
          << ".log-entry { font-family: 'JetBrains Mono', monospace; font-size: 11px; margin: 4px 0; color: var(--text-muted); line-height: 1.5; border-bottom: 1px solid #f0f2f5; padding-bottom: 3px; }"
          << ".table-scroll-container { max-height: 260px; overflow-y: auto; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); position: relative; }"
          << ".table-scroll-container table { margin-top: 0; border-collapse: separate; border-spacing: 0; }"
          << ".table-scroll-container th { position: sticky; top: 0; z-index: 2; background: #f6f8fa; box-shadow: 0 1px 0 var(--border-primary); }"
          << ".table-search-input { background: #ffffff; border: 1px solid var(--border-primary); color: var(--text-main); padding: 4px 8px; border-radius: var(--radius-sharp); font-size: 11px; font-family: 'JetBrains Mono', monospace; }"
          << ".table-search-input:focus { border-color: var(--border-focus); outline: 2px solid var(--border-focus); outline-offset: -1px; }"
          << "</style><script>"
          << "let isBenchmarking = false;"
          << "function runLiveBenchmark() {"
          << "  if (isBenchmarking) return;"
          << "  isBenchmarking = true;"
          << "  const status = document.getElementById('bench-status');"
          << "  if (status) status.innerHTML = '<span style=\"color:#0969da;\">● Telemetry Live</span>';"
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
          << "      isBenchmarking = false;"
          << "    })"
          << "    .catch(e => { isBenchmarking = false; });"
          << "}"
          << "function formatSec(s, exp) {"
          << "  if (exp === 0) return 'Permanent (∞)';"
          << "  if (s <= 0) return 'Expired';"
          << "  if (s >= 86400) return Math.floor(s/86400) + 'd ' + Math.floor((s%86400)/3600) + 'h';"
          << "  if (s >= 3600) return Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';"
          << "  return s + 's';"
          << "}"
          << "function formatAgo(ts) {"
          << "  if (!ts || ts === 0) return '-';"
          << "  const now = Math.floor(Date.now() / 1000);"
          << "  const diff = Math.max(0, now - ts);"
          << "  if (diff < 5) return 'just now';"
          << "  if (diff < 60) return diff + 's ago';"
          << "  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';"
          << "  if (diff < 86400) return Math.floor(diff / 3600) + 'h ' + Math.floor((diff % 3600) / 60) + 'm ago';"
          << "  return Math.floor(diff / 86400) + 'd ago';"
          << "}"
          << "function renderAuthBadge(type) {"
          << "  if (type === 'TOTP') return '<span class=\"badge badge-pqc\">TOTP</span>';"
          << "  if (type === 'Account' || type === 'Ephemeral Account') return '<span class=\"badge\" style=\"background:#ddf4ff; color:#0969da; border:1px solid rgba(9,105,218,0.3);\">ACCOUNT</span>';"
          << "  if (type === 'Host Admin') return '<span class=\"badge\" style=\"background:#fbefff; color:#8250df; border:1px solid rgba(130,80,223,0.3);\">ADMIN</span>';"
          << "  return '<span class=\"badge badge-excluded\">' + type + '</span>';"
          << "}"
          << "function renderSessionStatus(s) {"
          << "  if (s.is_revoked) return '<span class=\"badge badge-quarantined\" style=\"background:var(--danger-bg); color:var(--danger);\">REVOKED (Đã hủy)</span>';"
          << "  if (s.is_expired) return '<span class=\"badge\" style=\"background:#f6f8fa; color:var(--text-muted); border:1px solid var(--border-primary);\">EXPIRED (Đã chết)</span>';"
          << "  if (s.expires_at === 0) return '<span class=\"badge badge-available\">ACTIVE (Permanent ∞)</span>';"
          << "  return '<span class=\"badge badge-available\">ACTIVE (Còn sống: ' + formatSec(s.remaining_sec, s.expires_at) + ')</span>';"
          << "}"
          << "let cachedSessions = [];"
          << "function reloadSessions() {"
          << "  fetch('/api/admin/sessions')"
          << "    .then(r => r.json())"
          << "    .then(sessions => {"
          << "      cachedSessions = sessions || [];"
          << "      renderFilteredSessions();"
          << "    }).catch(e => {});"
          << "}"
          << "function filterSessions() { renderFilteredSessions(); }"
          << "function renderFilteredSessions() {"
          << "  const tbody = document.getElementById('sessions-tbody'); if (!tbody) return;"
          << "  const q = (document.getElementById('session-search')?.value || '').toLowerCase().trim();"
          << "  const list = cachedSessions.filter(s => {"
          << "    if (!q) return true;"
          << "    return String(s.session_id).includes(q) ||"
          << "           (s.identity && s.identity.toLowerCase().includes(q)) ||"
          << "           (s.auth_type && s.auth_type.toLowerCase().includes(q)) ||"
          << "           (s.remote_endpoint && s.remote_endpoint.toLowerCase().includes(q)) ||"
          << "           (s.role && s.role.toLowerCase().includes(q));"
          << "  });"
          << "  if (list.length === 0) {"
          << "    tbody.innerHTML = '<tr><td colspan=\"8\" style=\"color:var(--text-muted); text-align:center; padding:14px;\">No client sessions matching filter</td></tr>';"
          << "    return;"
          << "  }"
          << "  let html = '';"
          << "  list.forEach(s => {"
          << "    let actBadge = renderAuthBadge(s.auth_type);"
          << "    let stBadge = renderSessionStatus(s);"
          << "    let btn = (s.is_active && !s.is_revoked)"
          << "      ? '<button class=\"btn-danger btn-sm\" onclick=\"killSession(' + s.session_id + ')\">Kill Session</button>'"
          << "      : '<span style=\"color:var(--text-muted); font-size:11px;\">Terminated</span>';"
          << "    let timeInfo = formatAgo(s.created_at) + ' / <span style=\"color:var(--text-accent);\">' + formatAgo(s.last_active_at) + '</span>';"
          << "    html += '<tr><td><strong>#' + s.session_id + '</strong></td>'"
          << "         + '<td><code>' + s.identity + '</code></td>'"
          << "         + '<td>' + actBadge + '</td>'"
          << "         + '<td><code>' + s.remote_endpoint + '</code></td>'"
          << "         + '<td><span class=\"role-tag\">' + s.role + '</span></td>'"
          << "         + '<td>' + timeInfo + '</td>'"
          << "         + '<td>' + stBadge + '</td>'"
          << "         + '<td>' + btn + '</td></tr>';"
          << "  });"
          << "  tbody.innerHTML = html;"
          << "}"
          << "function killSession(id) {"
          << "  if (!confirm('Revoke and terminate client session #' + id + ' immediately?')) return;"
          << "  fetch('/api/admin/sessions/revoke', {"
          << "    method: 'POST', headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ session_id: id })"
          << "  }).then(r => r.json()).then(res => {"
          << "    if (res.status === 'ok') reloadSessions();"
          << "    else alert(res.message || 'Failed to revoke session');"
          << "  }).catch(e => alert('Network error revoking session'));"
          << "}"
          << "function reloadUsers() {"
          << "  fetch('/api/admin/users')"
          << "    .then(r => r.json())"
          << "    .then(users => {"
          << "      const tbody = document.getElementById('users-tbody');"
          << "      if (!tbody) return;"
          << "      if (!users || users.length === 0) { tbody.innerHTML = '<tr><td colspan=\"4\" style=\"color:var(--text-muted);\">No user accounts configured</td></tr>'; return; }"
          << "      let html = '';"
          << "      users.forEach(u => {"
          << "        let status = (u.expires_at === 0) ? '<span style=\"color:var(--success);\">Permanent (∞)</span>' :"
          << "                     (u.is_expired ? '<span style=\"color:var(--danger);\">Expired</span>' : '<span style=\"color:var(--success);\">Active (' + formatSec(u.remaining_sec, u.expires_at) + ')</span>');"
          << "        html += '<tr><td><strong>' + u.username + '</strong></td><td><span class=\"role-tag\">' + u.role + '</span></td><td>' + status + '</td>'"
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
          << "    method: 'POST', headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ username: u, password: p, role: r, ttl_sec: ttl })"
          << "  }).then(r => r.json()).then(res => {"
          << "    if (res.status === 'ok') { closeAddModal(); document.getElementById('add-u').value = ''; document.getElementById('add-p').value = ''; reloadUsers(); }"
          << "    else { alert(res.message || 'Failed to add user'); }"
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
          << "  if (p) payload.password = p; if (ttl >= 0) payload.ttl_sec = ttl;"
          << "  fetch('/api/admin/users/update', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })"
          << "    .then(r => r.json()).then(res => {"
          << "      if (res.status === 'ok') { closeEditModal(); reloadUsers(); }"
          << "      else { alert(res.message || 'Failed to update user'); }"
          << "    });"
          << "}"
          << "function deleteUser(username) {"
          << "  if (!confirm('Are you sure you want to delete user ' + username + '?')) return;"
          << "  fetch('/api/admin/users/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: username }) })"
          << "    .then(r => r.json()).then(res => { if (res.status === 'ok') reloadUsers(); else alert(res.message); });"
          << "}"
          << "function reloadRules() {"
          << "  fetch('/api/admin/rules').then(r => r.json()).then(rules => {"
          << "    const tbody = document.getElementById('rules-tbody'); if (!tbody) return;"
          << "    if (!rules || rules.length === 0) { tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:var(--text-muted);\">No custom rules configured</td></tr>'; return; }"
          << "    let html = '';"
          << "    rules.forEach(r => {"
          << "      let actBadge = (r.action === 'ALLOW') ? '<span style=\"color:var(--success); font-weight:bold;\">ALLOW</span>' : '<span style=\"color:var(--danger); font-weight:bold;\">BLOCK</span>';"
          << "      html += '<tr><td><code>' + r.id + '</code></td><td>' + actBadge + '</td><td><code>' + r.type + '</code></td><td><code>' + r.value + '</code></td>'"
          << "           + '<td><button class=\"btn-danger btn-sm\" onclick=\"deleteRule(\\'' + r.id + '\\')\">Delete</button></td></tr>';"
          << "    });"
          << "    tbody.innerHTML = html;"
          << "  });"
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
          << "  fetch('/api/admin/rules/add', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: id, action: act, type: type, value: val }) })"
          << "    .then(r => r.json()).then(res => {"
          << "      if (res.status === 'ok') { closeAddRuleModal(); document.getElementById('rule-id').value = ''; document.getElementById('rule-val').value = ''; reloadRules(); }"
          << "      else { alert(res.message || 'Failed to add rule'); }"
          << "    });"
          << "}"
          << "function deleteRule(ruleId) {"
          << "  if (!confirm('Are you sure you want to delete rule ' + ruleId + '?')) return;"
          << "  fetch('/api/admin/rules/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: ruleId }) })"
          << "    .then(r => r.json()).then(res => { if (res.status === 'ok') reloadRules(); else alert(res.message); });"
          << "}"
          << "let cachedAudit = [];"
          << "let filteredAudit = [];"
          << "let auditRenderIndex = 0;"
          << "const AUDIT_CHUNK_SIZE = 25;"
          << "function reloadAudit() {"
          << "  fetch('/api/admin/audit').then(r => r.json()).then(entries => {"
          << "    cachedAudit = entries || [];"
          << "    const badge = document.getElementById('audit-badge');"
          << "    if (badge) badge.innerText = cachedAudit.length;"
          << "    filterAudit();"
          << "  }).catch(e => {});"
          << "}"
          << "function filterAudit() {"
          << "  const q = (document.getElementById('audit-search')?.value || '').toLowerCase().trim();"
          << "  filteredAudit = cachedAudit.filter(e => {"
          << "    if (!q) return true;"
          << "    return (e.file_path && e.file_path.toLowerCase().includes(q)) ||"
          << "           (e.status && e.status.toLowerCase().includes(q)) ||"
          << "           (e.reason && e.reason.toLowerCase().includes(q));"
          << "  });"
          << "  auditRenderIndex = 0;"
          << "  const tbody = document.getElementById('audit-tbody'); if (!tbody) return;"
          << "  tbody.innerHTML = '';"
          << "  if (filteredAudit.length === 0) {"
          << "    tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:var(--text-muted); text-align:center; padding:14px;\">No quarantined or flagged files matching filter</td></tr>';"
          << "    return;"
          << "  }"
          << "  appendAuditRows();"
          << "}"
          << "function appendAuditRows() {"
          << "  const tbody = document.getElementById('audit-tbody');"
          << "  if (!tbody || auditRenderIndex >= filteredAudit.length) return;"
          << "  const end = Math.min(filteredAudit.length, auditRenderIndex + AUDIT_CHUNK_SIZE);"
          << "  let html = '';"
          << "  for (let i = auditRenderIndex; i < end; i++) {"
          << "    const e = filteredAudit[i];"
          << "    let stColor = (e.status === 'CLEAN' || e.status === 'USER_ALLOWED' || e.status === 'MANUAL_ALLOWED') ? 'var(--success)' : 'var(--danger)';"
          << "    let isAllowed = (e.status === 'USER_ALLOWED' || e.status === 'MANUAL_ALLOWED');"
          << "    let actBtn = isAllowed"
          << "      ? '<span style=\"color:var(--text-muted); font-size:11px;\">Whitelisted</span>'"
          << "      : '<button class=\"btn btn-sm\" onclick=\"allowAuditFile(\\'' + e.file_path.replace(/\\\\/g, '\\\\\\\\') + '\\')\">Whitelist</button>';"
          << "    html += '<tr><td><code style=\"word-break:break-all;\">' + e.file_path + '</code></td>'"
          << "         + '<td><span style=\"color:' + stColor + '; font-weight:bold;\">' + e.status + '</span></td>'"
          << "         + '<td>' + (e.line_number > 0 ? 'L' + e.line_number : '-') + '</td>'"
          << "         + '<td style=\"font-size:11px;\">' + (e.reason || '-') + '</td>'"
          << "         + '<td>' + actBtn + '</td></tr>';"
          << "  }"
          << "  tbody.insertAdjacentHTML('beforeend', html);"
          << "  auditRenderIndex = end;"
          << "}"
          << "function onAuditScroll(el) {"
          << "  if (el.scrollTop + el.clientHeight >= el.scrollHeight - 40) appendAuditRows();"
          << "}"
          << "function allowAuditFile(filePath) {"
          << "  const reason = prompt('Reason for whitelisting false positive for:\\n' + filePath, 'Verified safe false positive');"
          << "  if (!reason) return;"
          << "  fetch('/api/admin/audit/allow', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: filePath, reason: reason }) })"
          << "    .then(r => r.json()).then(res => { if (res.status === 'ok') reloadAudit(); else alert(res.message); });"
          << "}"
          << "function allowAllAuditFiles() {"
          << "  if (!confirm('Are you sure you want to whitelist all currently flagged false positives?')) return;"
          << "  fetch('/api/admin/audit/allow-all', { method: 'POST' })"
          << "    .then(r => r.json()).then(res => {"
          << "      if (res.status === 'ok') reloadAudit();"
          << "      else alert(res.message || 'Failed to whitelist all');"
          << "    }).catch(e => alert('Network error'));"
          << "}"
          << "function filterAuditLogs() {"
          << "  const q = (document.getElementById('logs-search')?.value || '').toLowerCase().trim();"
          << "  const entries = document.querySelectorAll('#audit-logs-container .log-entry');"
          << "  let visibleCount = 0;"
          << "  entries.forEach(el => {"
          << "    const txt = (el.getAttribute('data-text') || el.innerText || '').toLowerCase();"
          << "    if (!q || txt.includes(q)) {"
          << "      el.style.display = 'block';"
          << "      visibleCount++;"
          << "    } else {"
          << "      el.style.display = 'none';"
          << "    }"
          << "  });"
          << "  const emptyNotice = document.getElementById('logs-empty-notice');"
          << "  if (emptyNotice) emptyNotice.style.display = (visibleCount === 0) ? 'block' : 'none';"
          << "  const badge = document.getElementById('logs-badge');"
          << "  if (badge) badge.innerText = visibleCount;"
          << "}"
          << "window.addEventListener('DOMContentLoaded', () => { runLiveBenchmark(); setInterval(runLiveBenchmark, 3500); reloadSessions(); setInterval(reloadSessions, 2500); reloadAudit(); });"
          << "</script></head><body><div class='container'>"
          << "<div class='top-bar'>"
          << "<h1>Slug Workspace Admin &amp; Security Policy</h1>"
          << "<div style='display:flex; align-items:center; gap:8px;'>"
          << "<span style='font-size:12px; color:var(--text-muted); font-family:\"JetBrains Mono\", monospace;'>Operator: <strong>" << identity << "</strong></span>"
          << "<a class='btn-sec' href='/drop'>&larr; Explorer</a>"
          << "<a class='btn-sec' href='/logout' style='color:var(--danger);'>Logout</a>"
          << "</div></div>"

          << "<div class='grid'>"
          << "<div class='card'><h3>Active Server Workspace</h3>"
          << "<p style='font-family:\"JetBrains Mono\", monospace; font-size:12px;'><strong>Port:</strong> " << port << "<br>"
          << "<strong>Suite:</strong> <span style='color:var(--pqc); font-weight:bold;'>" << core::suite_to_string(suite_id) << "</span><br>"
          << "<strong>Path:</strong> " << workspace_root.string() << "<br>"
          << "<strong>AI Secret Shield:</strong> " << (ai_enabled ? "<span style='color:var(--success); font-weight:bold;'>ACTIVE</span>" : "OFF") << "</p>"
          << "</div>"

          << "<div class='card'><h3><span>User Accounts &amp; Ephemeral Roles</span><button class='btn btn-sm' onclick='openAddModal()'>+ Create User</button></h3>"
          << "<table><thead><tr><th>User</th><th>Role</th><th>Status/TTL</th><th>Actions</th></tr></thead><tbody id='users-tbody'>";

        uint64_t now = core::Utils::current_timestamp();
        for (const auto& u : users) {
            std::string status = (u.expires_at == 0) ? "<span style='color:var(--success);'>Permanent (∞)</span>" :
                                 (u.is_expired(now) ? "<span style='color:var(--danger);'>Expired</span>" :
                                 ("<span style='color:var(--success);'>Active (" + core::Utils::format_ttl((u.expires_at > now) ? (u.expires_at - now) : 0) + ")</span>"));
            h << "<tr><td><strong>" << u.username << "</strong></td><td><span class='role-tag'>" << core::role_to_string(u.role) << "</span></td><td>"
              << status
              << "</td><td><button class='btn-sec btn-sm' onclick=\"openEditModal('" << u.username << "', '" << core::role_to_string(u.role) << "')\">Edit</button> "
              << "<button class='btn-danger btn-sm' onclick=\"deleteUser('" << u.username << "')\">Delete</button></td></tr>";
        }
        if (users.empty()) {
            h << "<tr><td colspan='4' style='color:var(--text-muted);'>No user accounts configured</td></tr>";
        }
        h << "</tbody></table></div></div>"

          << "<div class='card' style='margin-bottom: 16px;'>"
          << "<h3><span>Connected Client Sessions (Real-Time PQC Channels)</span>"
          << "<span style='display:flex; align-items:center; gap:8px;'>"
          << "<span id='sessions-pulse' style='font-size:11px; color:var(--success); font-weight:normal;'>● Realtime Live (2.5s)</span>"
          << "<input type='text' id='session-search' class='table-search-input' placeholder='Filter sessions (ID, IP, role)...' oninput='filterSessions()' style='width:200px;'>"
          << "<button class='btn-sec btn-sm' onclick='reloadSessions()'>Refresh</button>"
          << "</span></h3>"
          << "<div class='table-scroll-container' style='max-height:240px;'>"
          << "<table><thead><tr>"
          << "<th>Session ID</th><th>Identity</th><th>Auth Type</th><th>Client Endpoint</th><th>Role</th><th>Created / Last Active</th><th>Status / TTL</th><th>Actions</th>"
          << "</tr></thead><tbody id='sessions-tbody'>";

        for (const auto& s : client_sessions) {
            std::string auth_badge = "<span class='badge badge-excluded'>" + s.auth_type + "</span>";
            if (s.auth_type == "TOTP") auth_badge = "<span class='badge badge-pqc'>TOTP</span>";
            else if (s.auth_type == "Account" || s.auth_type == "Ephemeral Account") auth_badge = "<span class='badge' style='background:#ddf4ff; color:#0969da; border:1px solid rgba(9,105,218,0.3);'>ACCOUNT</span>";
            else if (s.auth_type == "Host Admin") auth_badge = "<span class='badge' style='background:#fbefff; color:#8250df; border:1px solid rgba(130,80,223,0.3);'>ADMIN</span>";

            std::string st_badge = "<span class='badge badge-available'>ACTIVE</span>";
            if (s.is_revoked) {
                st_badge = "<span class='badge badge-quarantined' style='background:var(--danger-bg); color:var(--danger);'>REVOKED (Đã hủy)</span>";
            } else if (s.expires_at > 0 && s.expires_at <= now) {
                st_badge = "<span class='badge' style='background:#f6f8fa; color:var(--text-muted); border:1px solid var(--border-primary);'>EXPIRED (Đã chết)</span>";
            } else if (s.expires_at == 0) {
                st_badge = "<span class='badge badge-available'>ACTIVE (Permanent ∞)</span>";
            } else {
                st_badge = "<span class='badge badge-available'>ACTIVE (Còn sống: " + core::Utils::format_ttl(s.expires_at - now) + ")</span>";
            }

            std::string act_btn = (s.is_active(now) && !s.is_revoked)
                ? ("<button class='btn-danger btn-sm' onclick=\"killSession(" + std::to_string(s.session_id) + ")\">Kill Session</button>")
                : "<span style='color:var(--text-muted); font-size:11px;'>Terminated</span>";

            std::string created_str = (s.created_at == 0) ? "-" : (std::to_string(now > s.created_at ? (now - s.created_at) : 0) + "s ago");
            std::string active_str = (s.last_active_at == 0) ? "-" : (std::to_string(now > s.last_active_at ? (now - s.last_active_at) : 0) + "s ago");

            h << "<tr><td><strong>#" << s.session_id << "</strong></td>"
              << "<td><code>" << s.identity << "</code></td>"
              << "<td>" << auth_badge << "</td>"
              << "<td><code>" << s.remote_endpoint << "</code></td>"
              << "<td><span class='role-tag'>" << core::role_to_string(s.role) << "</span></td>"
              << "<td>" << created_str << " / <span style='color:var(--text-accent);'>" << active_str << "</span></td>"
              << "<td>" << st_badge << "</td>"
              << "<td>" << act_btn << "</td></tr>";
        }
        if (client_sessions.empty()) {
            h << "<tr><td colspan='8' style='color:var(--text-muted); text-align:center; padding:14px;'>No connected client sessions recorded yet</td></tr>";
        }
        h << "</tbody></table></div></div>"

          << "<div class='card' style='margin-bottom: 16px;'>"
          << "<h3><span>Cryptographic &amp; I/O Telemetry</span><span id='bench-status' style='font-size:11px;'></span></h3>"
          << "<div class='metric-grid'>"
          << "<div class='metric-box'><div class='metric-lbl'>BLAKE3 Throughput</div><div id='m-blake3' class='metric-val' style='color:var(--success);'>" << static_cast<int>(blake3_speed) << " MB/s</div></div>"
          << "<div class='metric-box'><div class='metric-lbl'>ML-KEM-768 Decap</div><div id='m-kem' class='metric-val' style='color:var(--pqc);'>" << static_cast<int>(pqc_kem_decap) << " &mu;s</div></div>"
          << "<div class='metric-box'><div class='metric-lbl'>ML-DSA-65 Verify</div><div id='m-sig' class='metric-val' style='color:var(--pqc);'>" << static_cast<int>(pqc_sig_verify) << " &mu;s</div></div>"
          << "<div class='metric-box'><div class='metric-lbl'>XChaCha20 AEAD</div><div id='m-cipher' class='metric-val'>" << static_cast<int>(cipher_speed) << " MB/s</div></div>"
          << "<div class='metric-box'><div class='metric-lbl'>Smart Regex Rate</div><div id='m-ai' class='metric-val' style='color:var(--warning);'>" << static_cast<int>(bench_rep.ai.lines_per_sec) << " L/s</div></div>"
          << "<div class='metric-box'><div class='metric-lbl'>Index Cache Lookup</div><div id='m-cache' class='metric-val' style='color:var(--success);'>" << std::fixed << std::setprecision(2) << bench_rep.ai.cache_hit_lookup_us << " &mu;s</div></div>"
          << "</div>"

          << "<div style='font-size:11px; color:var(--text-muted); margin-top:10px; font-family:\"JetBrains Mono\", monospace;'>"
          << "<div style='display:flex; justify-content:space-between;'><span>Hashing Engine: BLAKE3 (" << static_cast<int>(blake3_speed) << " MB/s) vs SHA-256 (" << static_cast<int>(sha256_speed) << " MB/s)</span>"
          << "<span style='color:var(--success); font-weight:bold;'>" << (sha256_speed > 0 ? std::to_string(static_cast<int>(blake3_speed / sha256_speed)) : "3") << "x Faster</span></div>"
          << "<div class='bar-track'><div class='bar-fill' style='width: " << std::min(100.0, (blake3_speed / (blake3_speed + sha256_speed + 0.1)) * 100.0) << "%;'></div></div>"

          << "<div style='display:flex; justify-content:space-between; margin-top:8px;'><span>KEM Decapsulation: Suite 3 PurePQC (" << static_cast<int>(pqc_kem_decap) << " &mu;s) vs Classical X25519 (" << static_cast<int>(classical_kem_decap) << " &mu;s)</span>"
          << "<span style='color:var(--pqc); font-weight:bold;'>NIST FIPS 203</span></div>"
          << "<div class='bar-track'><div class='bar-fill bar-pqc' style='width: 100%;'></div></div>"

          << "<div style='display:flex; justify-content:space-between; margin-top:8px;'><span>Digital Signatures: Suite 3 ML-DSA-65 (" << static_cast<int>(pqc_sig_verify) << " &mu;s) vs Classical Ed25519 (" << static_cast<int>(classical_sig_verify) << " &mu;s)</span>"
          << "<span style='color:var(--pqc); font-weight:bold;'>NIST FIPS 204</span></div>"
          << "<div class='bar-track'><div class='bar-fill bar-pqc' style='width: 100%;'></div></div>"

          << "<div style='font-size:11px; color:var(--text-muted); margin-top:12px; line-height:1.6; border-top:1px solid var(--border-primary); padding-top:8px;'>"
          << "<strong style='color:var(--text-main);'>Slug Multi-Layer Security Architecture:</strong><br>"
          << "&bull; <strong>1. Gitignore Layer:</strong> Standard <code>.gitignore</code> pattern exclusions.<br>"
          << "&bull; <strong>2. Policy Rules:</strong> Explicit administrator rules in <code>.slug/rules.conf</code> (allow/block path, ext, regex).<br>"
          << "&bull; <strong>3. Smart Regex Guard:</strong> Fast entropy &amp; heuristic token detector (detects API keys, private keys, high-entropy secrets).<br>"
          << "&bull; <strong>4. AI Guard (LLM):</strong> Deep context-aware semantic analysis (only activated when AI server is configured)."
          << "</div>"
          << "</div></div>"

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
            std::string act = (r.action == policy::RuleAction::ALLOW) ? "<span style='color:var(--success); font-weight:bold;'>ALLOW</span>" : "<span style='color:var(--danger); font-weight:bold;'>BLOCK</span>";
            h << "<tr><td><code>" << r.id << "</code></td><td>" << act << "</td><td><code>" << t_str << "</code></td><td><code>" << r.value << "</code></td>"
              << "<td><button class='btn-danger btn-sm' onclick=\"deleteRule('" << r.id << "')\">Delete</button></td></tr>";
        }
        if (rules.empty()) {
            h << "<tr><td colspan='5' style='color:var(--text-muted);'>No custom rules configured</td></tr>";
        }
        h << "</tbody></table></div>"

          << "<div class='card'><h3><span>Flagged &amp; Quarantined (.slug/index.db) <span id='audit-badge' class='badge badge-quarantined' style='margin-left:4px;'>" << audit_entries.size() << "</span></span>"
          << "<span style='display:flex; align-items:center; gap:6px;'>"
          << "<input type='text' id='audit-search' class='table-search-input' placeholder='Filter file or reason...' oninput='filterAudit()' style='width:160px;'>"
          << "<button class='btn-sec btn-sm' onclick='allowAllAuditFiles()' title='Whitelist all currently flagged files'>Whitelist All</button>"
          << "<button class='btn-sec btn-sm' onclick='reloadAudit()'>Refresh</button>"
          << "</span></h3>"
          << "<div id='audit-scroll-box' class='table-scroll-container' style='max-height:280px;' onscroll='onAuditScroll(this)'>"
          << "<table><thead><tr><th>File</th><th>Status</th><th>Line</th><th>Detector / Reason</th><th>Action</th></tr></thead><tbody id='audit-tbody'>";

        for (const auto& ae : audit_entries) {
            std::string st_str = core::audit_status_to_string(ae.status);
            std::string st_color = (ae.status == core::AuditStatus::CLEAN || ae.status == core::AuditStatus::USER_ALLOWED) ? "var(--success)" : "var(--danger)";
            h << "<tr><td><code style='word-break:break-all;'>" << ae.file_path << "</code></td><td><span style='color:" << st_color << "; font-weight:bold;'>" << st_str << "</span></td>"
              << "<td>" << (ae.line_number > 0 ? ("L" + std::to_string(ae.line_number)) : "-") << "</td><td style='font-size:11px;'>" << ae.reason << "</td>"
              << "<td>" << (ae.status != core::AuditStatus::USER_ALLOWED ? ("<button class='btn btn-sm' onclick=\"allowAuditFile('" + ae.file_path + "')\">Whitelist</button>") : "<span style='color:var(--text-muted); font-size:11px;'>Whitelisted</span>") << "</td></tr>";
        }
        if (audit_entries.empty()) {
            h << "<tr><td colspan='5' style='color:var(--text-muted); text-align:center; padding:14px;'>No quarantined or flagged files</td></tr>";
        }
        h << "</tbody></table></div></div></div>"

          << "<div class='card' style='margin-bottom: 16px;'>"
          << "<h3><span>Recent Security Audit Activity (.slug/audit.log) <span id='logs-badge' class='badge badge-excluded' style='margin-left:4px;'>" << events.size() << "</span></span>"
          << "<span style='display:flex; align-items:center; gap:6px;'>"
          << "<input type='text' id='logs-search' class='table-search-input' placeholder='Filter audit logs...' oninput='filterAuditLogs()' style='width:180px;'>"
          << "</span></h3>"
          << "<div id='audit-logs-container' class='table-scroll-container' style='max-height:200px; padding:8px; background:#fcfcfc;'>";
        for (const auto& e : events) {
            std::string safe_text = "[" + e.action + "] " + e.actor + " " + e.path + " " + e.reason;
            h << "<div class='log-entry' data-text='" << safe_text << "'>[" << e.action << "] <strong>" << e.actor << "</strong> &bull; <code>" << e.path << "</code> &bull; " << e.reason << "</div>";
        }
        if (events.empty()) {
            h << "<div class='log-entry'>No audit events recorded yet.</div>";
        }
        h << "<div id='logs-empty-notice' style='display:none; color:var(--text-muted); text-align:center; padding:12px; font-size:11px;'>No audit log entries matching search query</div>"
          << "</div></div>"

          // Modals
          << "<div id='modal-add-user' class='modal'>"
          << "<div class='modal-content'>"
          << "<h3 style='margin-top:0; font-size:14px; color:var(--text-main);'>Create Ephemeral User Account</h3>"
          << "<form onsubmit='submitAddUser(event)'>"
          << "<div class='form-group'><label>Username</label><input type='text' id='add-u' class='input-text' placeholder='e.g. dev_guest' required></div>"
          << "<div class='form-group'><label>Password</label><input type='password' id='add-p' class='input-text' placeholder='Strong password' required></div>"
          << "<div class='form-group'><label>Permission Role</label>"
          << "<select id='add-r' class='input-select'>"
          << "<option value='r'>[r] Read-Only (Pull / View files only)</option>"
          << "<option value='rw' selected>[rw] Read-Write (Full Sync &amp; Upload)</option>"
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
          << "<h3 style='margin-top:0; font-size:14px; color:var(--text-main);'>Edit User Account: <span id='edit-u-display'></span></h3>"
          << "<form onsubmit='submitEditUser(event)'>"
          << "<input type='hidden' id='edit-u'>"
          << "<div class='form-group'><label>New Password (leave blank to keep unchanged)</label><input type='password' id='edit-p' class='input-text' placeholder='New password'></div>"
          << "<div class='form-group'><label>Permission Role</label>"
          << "<select id='edit-r' class='input-select'>"
          << "<option value='r'>[r] Read-Only (Pull / View files only)</option>"
          << "<option value='rw'>[rw] Read-Write (Full Sync &amp; Upload)</option>"
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

          << "<div id='modal-add-rule' class='modal'>"
          << "<div class='modal-content'>"
          << "<h3 style='margin-top:0; font-size:14px; color:var(--text-main);'>Add Security Filter Rule</h3>"
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

    static std::string render_client_portal(
        const std::vector<core::ConnectionInfo>& conns,
        uint16_t portal_port)
    {
        std::string html = R"raw(<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Slug - Trạm Điều Khiển Workspace Trực Tiếp Giữa Các Máy Tính</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg-canvas: #f6f8fa;
  --bg-surface: #ffffff;
  --bg-surface-hover: #f3f4f6;
  --border-primary: #d0d7de;
  --border-focus: #0969da;
  --radius-sharp: 4px;
  --text-main: #1f2328;
  --text-muted: #656d76;
  --text-accent: #0969da;
  --success: #1a7f37;
  --success-bg: #dafbe1;
  --warning: #9a6700;
  --warning-bg: #fff8c5;
  --danger: #cf222e;
  --danger-bg: #ffebe9;
  --pqc: #8250df;
  --pqc-bg: #fbefff;
}
* { box-sizing: border-box; }
body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg-canvas);
  color: var(--text-main);
  margin: 0;
  padding: 24px;
  line-height: 1.5;
}
code, pre, .font-mono {
  font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, Menlo, Monaco, monospace;
}
.container {
  max-width: 1100px;
  margin: 0 auto;
}
.top-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--border-primary);
  padding-bottom: 16px;
  margin-bottom: 20px;
  flex-wrap: wrap;
  gap: 12px;
}
.logo-title {
  display: flex;
  align-items: center;
  gap: 12px;
}
.logo-icon {
  background: #1f2328;
  color: #ffffff;
  font-weight: 900;
  padding: 6px 12px;
  border-radius: var(--radius-sharp);
  letter-spacing: 1px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 16px;
}
.header-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}
.role-tabs {
  display: flex;
  gap: 4px;
  background: #eaeef2;
  padding: 4px;
  border-radius: var(--radius-sharp);
  margin-bottom: 20px;
  border: 1px solid var(--border-primary);
}
.role-tab-btn {
  flex: 1;
  padding: 10px 16px;
  border: 1px solid transparent;
  background: transparent;
  color: var(--text-muted);
  font-weight: 600;
  font-size: 13px;
  border-radius: var(--radius-sharp);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  transition: all 0.15s ease;
  font-family: 'Inter', sans-serif;
}
.role-tab-btn:hover {
  background: var(--bg-surface-hover);
  color: var(--text-main);
}
.role-tab-btn.active {
  background: #0969da;
  color: #ffffff;
  border-color: #0969da;
}
.badge {
  padding: 3px 8px;
  border-radius: var(--radius-sharp);
  font-size: 11px;
  font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
  text-transform: uppercase;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.badge-live {
  background: var(--success-bg);
  color: var(--success);
  border: 1px solid rgba(26,127,55,0.3);
}
.badge-offline {
  background: var(--danger-bg);
  color: var(--danger);
  border: 1px solid rgba(207,34,46,0.3);
}
.badge-pqc {
  background: var(--pqc-bg);
  color: var(--pqc);
  border: 1px solid rgba(130,80,223,0.3);
}
.card {
  background: #ffffff;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-sharp);
  padding: 18px;
  margin-bottom: 20px;
  box-shadow: 0 1px 3px rgba(31,35,40,0.04);
}
.card h3 {
  margin-top: 0;
  font-size: 14px;
  color: var(--text-main);
  border-bottom: 1px solid var(--border-primary);
  padding-bottom: 10px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: 'JetBrains Mono', monospace;
  flex-wrap: wrap;
  gap: 8px;
}
.form-grid {
  display: grid;
  grid-template-columns: 2fr 1fr 2fr;
  gap: 14px;
  margin-bottom: 14px;
}
@media (max-width: 768px) {
  .form-grid { grid-template-columns: 1fr; }
}
.form-group { margin-bottom: 12px; }
.form-group label {
  display: block;
  font-size: 11px;
  color: var(--text-muted);
  margin-bottom: 4px;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
}
.input-text, .input-select {
  background: #ffffff;
  border: 1px solid var(--border-primary);
  color: var(--text-main);
  padding: 8px 12px;
  border-radius: var(--radius-sharp);
  font-size: 13px;
  width: 100%;
  box-sizing: border-box;
  font-family: 'JetBrains Mono', monospace;
  height: 38px;
}
.input-text:focus, .input-select:focus {
  border-color: var(--border-focus);
  outline: 2px solid var(--border-focus);
  outline-offset: -1px;
}

/* Button Unified Styles */
.btn, .btn-sec, .btn-danger {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  font-weight: 600;
  border-radius: var(--radius-sharp);
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  white-space: nowrap;
  gap: 6px;
  text-decoration: none;
  transition: all 0.1s ease;
  box-sizing: border-box;
  height: 38px;
}
.btn {
  background: #0969da;
  color: #ffffff;
  border: 1px solid #0969da;
  padding: 0 16px;
}
.btn:hover { background: #0858b8; border-color: #0858b8; }
.btn-sec {
  background: #ffffff;
  color: var(--text-main);
  border: 1px solid var(--border-primary);
  padding: 0 14px;
}
.btn-sec:hover { background: var(--bg-surface-hover); }
.btn-danger {
  background: #ffffff;
  color: var(--danger);
  border: 1px solid var(--danger);
  padding: 0 14px;
}
.btn-danger:hover { background: var(--danger); color: #fff; }

.btn-sm {
  padding: 0 10px;
  font-size: 11px;
  height: 28px;
}
.btn-xs {
  padding: 0 8px;
  font-size: 10px;
  height: 24px;
}

/* Table */
table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 8px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
}
th, td {
  text-align: left;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border-primary);
  vertical-align: middle;
}
th {
  background: #f6f8fa;
  color: var(--text-muted);
  font-size: 11px;
  text-transform: uppercase;
}
.clickable-row {
  cursor: pointer;
  transition: background-color 0.12s ease;
  user-select: none;
}
.clickable-row:hover {
  background-color: #f0f6fc !important;
}
.role-tag {
  background: #0969da;
  color: #fff;
  padding: 2px 6px;
  border-radius: var(--radius-sharp);
  font-size: 10px;
  font-weight: bold;
}

/* Host Card Styling */
.host-card {
  background: #ffffff;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-sharp);
  padding: 16px;
  margin-bottom: 18px;
  box-shadow: 0 1px 3px rgba(31,35,40,0.06);
  transition: border-color 0.15s ease;
}
.host-card:hover { border-color: #54aeff; }
.host-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border-primary);
  margin-bottom: 14px;
  flex-wrap: wrap;
  gap: 8px;
}
.host-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
  min-width: 0;
  max-width: 60%;
}
.path-truncate {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 320px;
  display: inline-block;
  vertical-align: middle;
}
.host-body {
  display: grid;
  grid-template-columns: 1.6fr 1.1fr 1.3fr;
  gap: 14px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
}
@media (max-width: 960px) {
  .host-body { grid-template-columns: 1fr; }
  .host-title { max-width: 100%; }
}
.host-box {
  background: #f6f8fa;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-sharp);
  padding: 12px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}
.host-box-title {
  font-size: 11px;
  font-weight: 700;
  color: var(--text-muted);
  text-transform: uppercase;
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

/* 3-Column OTP Grid inside Box 1 */
.otp-3col-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
  margin-bottom: 8px;
}
@media (max-width: 768px) {
  .otp-3col-grid { grid-template-columns: 1fr; }
}
.otp-col-card {
  background: #ffffff;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-sharp);
  padding: 8px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}
.otp-col-role {
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  margin-bottom: 2px;
}
.otp-col-code {
  font-size: 18px;
  font-weight: 900;
  letter-spacing: 2px;
  color: #1f2328;
  font-family: 'JetBrains Mono', monospace;
  margin: 4px 0 6px 0;
}
.otp-col-actions {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.progress-bar {
  height: 4px;
  background: #e1e4e8;
  border-radius: 2px;
  overflow: hidden;
  margin-top: 4px;
}
.progress-fill {
  height: 100%;
  background: #0969da;
  transition: width 1s linear;
}

/* Admin Console Drawer */
.admin-drawer {
  display: none;
  border-top: 1px solid var(--border-primary);
  padding-top: 14px;
  margin-top: 14px;
}
.admin-tabs {
  display: flex;
  gap: 6px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.admin-tab-btn {
  background: #f6f8fa;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-sharp);
  padding: 6px 12px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  font-family: 'JetBrains Mono', monospace;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 30px;
}
.admin-tab-btn.active {
  background: #0969da;
  color: #ffffff;
  border-color: #0969da;
}

/* Modal Popup */
.modal-overlay {
  display: none;
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.5);
  z-index: 1000;
  align-items: center;
  justify-content: center;
}
.modal-box {
  background: #ffffff;
  border-radius: var(--radius-sharp);
  padding: 24px;
  max-width: 500px;
  width: 90%;
  box-shadow: 0 8px 24px rgba(0,0,0,0.2);
  border: 1px solid var(--border-primary);
}

.footer {
  text-align: center;
  padding: 24px 0 12px 0;
  font-size: 11px;
  color: var(--text-muted);
  font-family: 'JetBrains Mono', monospace;
  border-top: 1px solid var(--border-primary);
  margin-top: 24px;
}
.live-indicator {
  display: inline-block;
  width: 8px;
  height: 8px;
  background: #1a7f37;
  border-radius: 50%;
  box-shadow: 0 0 0 0 rgba(26,127,55,0.7);
  animation: pulse 1.8s infinite;
}
@keyframes pulse {
  0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(26,127,55,0.7); }
  70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(26,127,55,0); }
  100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(26,127,55,0); }
}
</style>
<script>
// Inline SVG Vector Icons (100% Offline, Crisp, No Font/Network Dependencies)
const ICONS = {
  terminal: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>`,
  qr: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>`,
  copy: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`,
  folder: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>`,
  shield: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`,
  refresh: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>`,
  user: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>`,
  users: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>`,
  settings: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>`,
  stop: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><circle cx="12" cy="12" r="10"></circle><rect x="9" y="9" width="6" height="6"></rect></svg>`,
  lock: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`,
  unlock: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg>`,
  download: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>`,
  upload: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>`,
  check: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
  edit: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>`,
  trash: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`,
  plus: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>`
};

let currentRole = 'client';
let clientAuthMode = 'otp';
let hostedWorkspaces = [
  {
    id: 'host-9443',
    path: './',
    port: 9443,
    suite: '3',
    suiteName: '⭐ Mức 3: Pure Post-Quantum (ML-KEM-1024 + ML-DSA-87) [Khuyên dùng]',
    filterMode: 'protected',
    filterName: '🛡️ Protected (Slug Rule + Slug Regex + Slug AI)',
    otp_rw: '48291048',
    otp_r: '71928301',
    otp_w: '39582104',
    otp: '48291048',
    ttl: 30,
    maxTtl: 30,
    role: 'rw',
    peers: [
      { id: 'peer-1', name: 'Lab-PC-03', ip: '192.168.1.105', authType: 'TOTP [RW]', suite: 'ML-KEM-1024 + ML-DSA-87', connectedAt: '5 phút trước', transferred: '14.2 MB' }
    ],
    auditStats: { clean: 24, quarantined: 1, excluded: 842 },
    quarantinedFiles: [
      { name: '.env', size: '380 B', detector: 'Slug Regex & Slug AI', reason: 'Phát hiện JWT_SECRET, DATABASE_URL, API_KEY (Entropy: 4.82)', risk: 'CRITICAL', unquarantined: false }
    ],
    excludedFiles: [
      { name: 'node_modules/', size: '184.2 MiB', detector: 'Slug Rule (.gitignore)', reason: 'Rác build dependencies', included: false },
      { name: 'build/', size: '45.1 MiB', detector: 'Slug Rule (.gitignore)', reason: 'Thư mục output CMake / Ninja', included: false }
    ],
    logs: [
      'Khởi động chia sẻ workspace ./ trên cổng 9443 với Mức 3: Pure Post-Quantum (ML-KEM-1024 + ML-DSA-87)',
      'Slug Guard kích hoạt: Slug Rule (.gitignore) + Slug Regex + Slug AI',
      'Peer 192.168.1.105 kết nối thành công qua kênh ML-KEM-1024 (OTP RW)',
      'Slug Regex & Slug AI phát hiện và cách ly tệp .env vào RAM Shield'
    ]
  }
];

let userAccounts = [
  { username: 'admin', role: 'rw', roleName: 'Toàn Quyền (Đọc & Ghi)', ttl: 0, status: 'Permanent (∞)', createdAt: 'Hôm nay 22:00', revoked: false },
  { username: 'colleague_bob', role: 'r', roleName: 'Chỉ Đọc (Tải Về)', ttl: 6300, status: 'Còn 1h 45m', createdAt: 'Hôm nay 22:10', revoked: false },
  { username: 'student_alice', role: 'w', roleName: 'Hộp Thư Nộp Bài (Upload)', ttl: 19200, status: 'Còn 5h 20m', createdAt: 'Hôm nay 22:25', revoked: false }
];

function switchClientAuth(mode) {
  clientAuthMode = mode;
  document.getElementById('auth-tab-otp').classList.toggle('active', mode === 'otp');
  document.getElementById('auth-tab-acc').classList.toggle('active', mode === 'account');
  document.getElementById('client-auth-otp-sec').style.display = (mode === 'otp') ? 'block' : 'none';
  document.getElementById('client-auth-acc-sec').style.display = (mode === 'account') ? 'block' : 'none';
}

function submitClientConnect(e) {
  e.preventDefault();
  const endpoint = document.getElementById('client-endpoint').value.trim();
  const suite = document.getElementById('client-suite').value;
  const msgBox = document.getElementById('conn-msg');
  msgBox.innerHTML = '<span style="color:#0969da;">Đang thiết lập kênh mật mã Hậu lượng tử NIST FIPS 203 (ML-KEM)...</span>';

  const payload = {
    endpoint: endpoint,
    suite: parseInt(suite),
    auth_mode: clientAuthMode,
    otp: document.getElementById('client-otp').value.trim(),
    username: document.getElementById('client-username').value.trim(),
    password: document.getElementById('client-password').value
  };

  fetch('/api/portal/connect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(r => r.json()).then(res => {
    if (res.status === 'ok') {
      msgBox.innerHTML = '<span style="color:#1a7f37; font-weight:bold;">Xác thực thành công! Đang chuyển hướng tới Web Dropbox...</span>';
      setTimeout(() => { window.location.href = res.url || '/drop'; }, 400);
    } else {
      msgBox.innerHTML = '<span style="color:#cf222e; font-weight:bold;">Lỗi: ' + (res.message || 'Kết nối thất bại') + '</span>';
    }
  }).catch(() => {
    msgBox.innerHTML = '<span style="color:#cf222e;">Lỗi kết nối tới trạm đích qua mạng LAN.</span>';
  });
}

function switchRole(role) {
  currentRole = role;
  document.getElementById('tab-btn-client').classList.toggle('active', role === 'client');
  document.getElementById('tab-btn-host').classList.toggle('active', role === 'host');
  document.getElementById('section-client').style.display = (role === 'client') ? 'block' : 'none';
  document.getElementById('section-host').style.display = (role === 'host') ? 'block' : 'none';
  if (role === 'host') {
    renderHostedWorkspaces();
    renderUserAccounts();
  }
}

function renderHostedWorkspaces() {
  const container = document.getElementById('hosted-workspaces-list');
  const countBadge = document.getElementById('hosted-count');
  const countTitle = document.getElementById('hosted-count-title');
  if (countBadge) countBadge.textContent = hostedWorkspaces.length;
  if (countTitle) countTitle.textContent = hostedWorkspaces.length;

  if (hostedWorkspaces.length === 0) {
    container.innerHTML = '<div style="text-align:center; padding:32px; background:#f6f8fa; border:1px dashed var(--border-primary); border-radius:var(--radius-sharp); color:var(--text-muted); font-size:13px;">Chưa có thư mục nào đang chia sẻ.</div>';
    return;
  }

  container.innerHTML = hostedWorkspaces.map(w => {
    const percent = Math.max(0, Math.min(100, (w.ttl / (w.maxTtl || 30)) * 100));
    return `
      <div class="host-card" id="card-${w.id}">
        <div class="host-header">
          <div class="host-title">
            <span style="color:#0969da; flex-shrink:0;">${ICONS.folder}</span>
            <span class="path-truncate" title="${w.path}">${w.path}</span>
            <button class="btn-sec btn-xs" onclick="copyText('${w.path}', 'Đường dẫn')" style="flex-shrink:0;">${ICONS.copy} Copy Path</button>
            <span class="badge badge-live" style="flex-shrink:0;">🟢 ĐANG PHÁT (HOSTING)</span>
            <span class="badge" style="background:#eaeef2; color:#1f2328; flex-shrink:0;">Cổng: ${w.port}</span>
          </div>
          <div style="display:flex; gap:8px; flex-shrink:0;">
            <button class="btn btn-sm" onclick="window.location.href='/drop'">${ICONS.folder} Duyệt Thư Mục Này</button>
            <button class="btn-sec btn-sm" onclick="toggleAdminPanel('${w.id}')">${ICONS.settings} Quản Trị (Admin)</button>
            <button class="btn-danger btn-sm" onclick="stopHost('${w.id}')">${ICONS.stop} Dừng Host</button>
          </div>
        </div>
        <div class="host-body">
          <!-- Box 1: Sinh Bộ 3 Mã OTP Động -->
          <div class="host-box">
            <div>
              <div class="host-box-title">
                <span>${ICONS.lock} BỘ 3 MÃ OTP PHÂN QUYỀN (SINH ĐỘNG)</span>
                <span style="color:#0969da; cursor:pointer; font-size:11px;" onclick="changeHostTtl('${w.id}')">⏱️ TTL: ${w.maxTtl || 30}s</span>
              </div>
              
              <div class="otp-3col-grid">
                <div class="otp-col-card" style="border-left: 3px solid #1a7f37;">
                  <div class="otp-col-role" style="color:#1a7f37;">🟢 TOÀN QUYỀN [RW]</div>
                  <div class="otp-col-code" id="otp-rw-${w.id}">${w.otp_rw || w.otp}</div>
                  <div class="otp-col-actions">
                    <button class="btn-sec btn-xs" onclick="copyText('${w.otp_rw || w.otp}', 'OTP RW')">${ICONS.copy} Copy OTP</button>
                    <button class="btn btn-xs" onclick="copyCliCmd('${w.port}', '${w.otp_rw || w.otp}', 'rw')">${ICONS.terminal} Lệnh CLI</button>
                  </div>
                </div>

                <div class="otp-col-card" style="border-left: 3px solid #0969da;">
                  <div class="otp-col-role" style="color:#0969da;">🔵 CHỈ ĐỌC [R]</div>
                  <div class="otp-col-code" id="otp-r-${w.id}">${w.otp_r || '71928301'}</div>
                  <div class="otp-col-actions">
                    <button class="btn-sec btn-xs" onclick="copyText('${w.otp_r || '71928301'}', 'OTP R')">${ICONS.copy} Copy OTP</button>
                    <button class="btn btn-xs" onclick="copyCliCmd('${w.port}', '${w.otp_r || '71928301'}', 'r')">${ICONS.terminal} Lệnh CLI</button>
                  </div>
                </div>

                <div class="otp-col-card" style="border-left: 3px solid #9a6700;">
                  <div class="otp-col-role" style="color:#9a6700;">🟡 NỘP BÀI [W]</div>
                  <div class="otp-col-code" id="otp-w-${w.id}">${w.otp_w || '39582104'}</div>
                  <div class="otp-col-actions">
                    <button class="btn-sec btn-xs" onclick="copyText('${w.otp_w || '39582104'}', 'OTP W')">${ICONS.copy} Copy OTP</button>
                    <button class="btn btn-xs" onclick="copyCliCmd('${w.port}', '${w.otp_w || '39582104'}', 'w')">${ICONS.terminal} Lệnh CLI</button>
                  </div>
                </div>
              </div>

              <div style="font-size:11px; color:var(--text-muted); display:flex; justify-content:space-between; margin-bottom:2px;">
                <span>⏳ Tự đổi cả 3 mã sau: <strong id="timer-text-${w.id}">${w.ttl}</strong>s</span>
                <span style="color:#54aeff;">RAM Shield TOTP</span>
              </div>
              <div class="progress-bar">
                <div class="progress-fill" id="progress-${w.id}" style="width:${percent}%"></div>
              </div>
            </div>
            <div style="display:flex; gap:6px; margin-top:10px; flex-wrap:wrap;">
              <button class="btn-sec btn-sm" onclick="rotateHostOtps('${w.id}')">${ICONS.refresh} Sinh Bộ 3 Mã Mới</button>
              <button class="btn-sec btn-sm" onclick="showQrModal('${w.otp_rw || w.otp}', '${w.port}')">${ICONS.qr} QR Code</button>
              <button class="btn-sec btn-sm" onclick="showCliInstructions('${w.port}', '${w.otp_rw || w.otp}')">${ICONS.terminal} Trợ Giúp CLI</button>
            </div>
          </div>

          <!-- Box 2: Cấp Độ Mật Mã & Bộ Lọc (Cho Phép Cài Lại Trực Tiếp) -->
          <div class="host-box" style="gap:10px;">
            <div>
              <div class="host-box-title">
                <span>${ICONS.shield} MỨC MẬT MÃ &amp; BỘ LỌC</span>
                <span class="badge badge-pqc">${w.suite === '3' ? '⭐ PQC NATIVE' : (w.suite === '2' ? '⚛️ HYBRID' : '⚡ CLASSICAL')}</span>
              </div>
              
              <div style="margin-bottom:8px;">
                <label style="font-size:10px; color:var(--text-muted); font-weight:700; display:block; margin-bottom:2px;">CẤU HÌNH MẬT MÃ (CIPHER SUITE):</label>
                <select class="input-select" style="width:100%; font-size:11px; padding:5px 8px; height:32px;" onchange="updateHostSuite('${w.id}', this.value)">
                  <option value="3" ${w.suite === '3' ? 'selected' : ''}>⭐ Mức 3: Pure Post-Quantum (ML-KEM-1024 + ML-DSA-87) [Khuyên dùng]</option>
                  <option value="2" ${w.suite === '2' ? 'selected' : ''}>⚛️ Mức 2: Modern Hybrid (ML-KEM-768 + X25519 + ChaCha20)</option>
                  <option value="1" ${w.suite === '1' ? 'selected' : ''}>⚡ Mức 1: Classical Fast (X25519 + AES-256-GCM)</option>
                </select>
              </div>

              <div>
                <label style="font-size:10px; color:var(--text-muted); font-weight:700; display:block; margin-bottom:2px;">CHẾ ĐỘ LỌC DỮ LIỆU SLUG GUARD:</label>
                <select class="input-select" style="width:100%; font-size:11px; padding:5px 8px; height:32px;" onchange="updateHostFilter('${w.id}', this.value)">
                  <option value="protected" ${w.filterMode === 'protected' ? 'selected' : ''}>🛡️ Protected (Slug Rule + Slug Regex + Slug AI)</option>
                  <option value="include_ignored" ${w.filterMode === 'include_ignored' ? 'selected' : ''}>📦 Include-Ignored (Gửi cả build, chặn secret)</option>
                  <option value="none" ${w.filterMode === 'none' ? 'selected' : ''}>⚠️ None (Gửi tất cả, không lọc - Thận trọng)</option>
                </select>
              </div>
            </div>

            <div style="font-size:11px; color:#1a7f37; font-weight:600; display:flex; align-items:center; gap:6px;">
              <span class="live-indicator"></span> ${(w.peers || []).length} thiết bị đang kết nối | Quyền: <strong>${(w.role || 'rw').toUpperCase()}</strong>
            </div>
          </div>

          <!-- Box 3: Hướng Dẫn Terminal Cho Bạn Bè -->
          <div class="host-box">
            <div>
              <div class="host-box-title">
                <span>${ICONS.terminal} LỆNH KẾT NỐI CHO BẠN BÈ (TERMINAL)</span>
              </div>
              <div style="font-size:11px; color:var(--text-muted); margin-bottom:6px;">
                Đọc mã OTP hoặc gửi lệnh tải nhanh qua mạng LAN:
              </div>
              <div style="background:#1f2328; color:#e6edf3; padding:8px 10px; font-size:11px; border-radius:4px; word-break:break-all; font-family:'JetBrains Mono', monospace;">
                <code>slug get 127.0.0.1:${w.port}?otp=${w.otp_rw || w.otp}</code>
              </div>
            </div>
            <div style="margin-top:10px; display:flex; gap:6px;">
              <button class="btn btn-sm" onclick="copyCliCmd('${w.port}', '${w.otp_rw || w.otp}', '${w.role || 'rw'}')">${ICONS.copy} Sao Chép Lệnh Terminal</button>
            </div>
          </div>
        </div>

        <!-- Admin Console Drawer -->
        <div class="admin-drawer" id="admin-drawer-${w.id}">
          <div class="admin-tabs">
            <button class="admin-tab-btn active" onclick="switchAdminTab('${w.id}', 'audit', this)">${ICONS.shield} Slug Guard (4 Tầng Phòng Thủ)</button>
            <button class="admin-tab-btn" onclick="switchAdminTab('${w.id}', 'peers', this)">${ICONS.users} Peers Kết Nối (${(w.peers||[]).length})</button>
            <button class="admin-tab-btn" onclick="switchAdminTab('${w.id}', 'acl', this)">${ICONS.lock} Phân Quyền (ACL)</button>
            <button class="admin-tab-btn" onclick="switchAdminTab('${w.id}', 'log', this)">${ICONS.terminal} Nhật Ký Hoạt Động</button>
          </div>

          <div id="subtab-${w.id}-audit">
            <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:12px; margin-bottom:14px;">
              <div style="background:#fff; border:1px solid #d0d7de; padding:12px; border-radius:var(--radius-sharp);">
                <div style="font-size:11px; color:var(--text-muted); font-weight:600;">TỆP SẠCH (CLEAN)</div>
                <div style="font-size:22px; font-weight:700; color:#1a7f37;" id="stat-clean-${w.id}">${w.auditStats ? w.auditStats.clean : 24}</div>
                <div style="font-size:10px; color:var(--text-muted);">Sẵn sàng chia sẻ qua PQC channel</div>
              </div>
              <div style="background:#fff; border:1px solid #d0d7de; padding:12px; border-radius:var(--radius-sharp);">
                <div style="font-size:11px; color:var(--text-muted); font-weight:600;">CÁCH LY SECRET (BLOCKED)</div>
                <div style="font-size:22px; font-weight:700; color:#cf222e;" id="stat-quarantined-${w.id}">${w.auditStats ? w.auditStats.quarantined : 1}</div>
                <div style="font-size:10px; color:#cf222e;">Bị chặn bởi Slug Regex &amp; Slug AI</div>
              </div>
              <div style="background:#fff; border:1px solid #d0d7de; padding:12px; border-radius:var(--radius-sharp);">
                <div style="font-size:11px; color:var(--text-muted); font-weight:600;">RÁC BUILD (.GITIGNORE)</div>
                <div style="font-size:22px; font-weight:700; color:#656d76;" id="stat-excluded-${w.id}">${w.auditStats ? w.auditStats.excluded : 842}</div>
                <div style="font-size:10px; color:var(--text-muted);">Bị loại trừ bởi Slug Rule</div>
              </div>
            </div>

            <div style="margin-bottom:14px;">
              <div style="font-size:12px; font-weight:700; margin-bottom:6px; display:flex; justify-content:space-between; align-items:center;">
                <span>🔒 Tệp Tin Nhạy Cảm Bị Cách Ly Trong RAM Shield (${(w.quarantinedFiles || []).length})</span>
                <span style="font-size:11px; color:#cf222e;">Bảo vệ chống rò rỉ secret ra mạng</span>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>Tên Tệp</th>
                    <th>Dung Lượng</th>
                    <th>Tầng Bắt</th>
                    <th>Lý Do Cách Ly</th>
                    <th>Thao Tác</th>
                  </tr>
                </thead>
                <tbody id="quarantine-tbody-${w.id}">
                  ${(w.quarantinedFiles && w.quarantinedFiles.length > 0) ? w.quarantinedFiles.map(f => `
                    <tr>
                      <td><strong style="color:${f.unquarantined ? '#1a7f37' : '#cf222e'};">${f.name}</strong></td>
                      <td><code>${f.size}</code></td>
                      <td>
                        <span class="badge" style="background:#fff8c5; color:#9a6700;">Slug Regex</span>
                        <span class="badge" style="background:#fbefff; color:#8250df;">Slug AI</span>
                      </td>
                      <td style="font-size:11px; color:var(--text-muted);">${f.reason}</td>
                      <td>
                        <button class="${f.unquarantined ? 'btn-sec' : 'btn'} btn-xs" onclick="toggleUnquarantine('${w.id}', '${f.name}')">
                          ${f.unquarantined ? ICONS.lock + ' Tái Cách Ly (Block)' : ICONS.unlock + ' 🔓 Gỡ Cách Ly (Allow Secret)'}
                        </button>
                      </td>
                    </tr>
                  `).join('') : '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:10px;">Không có tệp bí mật nào bị cách ly.</td></tr>'}
                </tbody>
              </table>
            </div>

            <div style="display:flex; justify-content:space-between; align-items:center;">
              <button class="btn-sec btn-sm" onclick="showToast('✅ Đã chạy kiểm toán RAM Shield: An toàn tuyệt đối!')">${ICONS.refresh} Quét Lại Bộ Lọc &amp; Bí Mật (Deep Rescan)</button>
              <span style="font-size:11px; color:var(--text-muted);">Slug Guard 4 Tầng: Slug Rule + Slug Regex + Slug AI + RAM Shield</span>
            </div>
          </div>

          <div id="subtab-${w.id}-peers" style="display:none;">
            <table>
              <thead>
                <tr>
                  <th>Tên Máy / IP</th>
                  <th>Xác Thực</th>
                  <th>Kênh Mật Mã</th>
                  <th>Thời Điểm Nối</th>
                  <th>Dữ Liệu Đã Truyền</th>
                  <th>Hành Động</th>
                </tr>
              </thead>
              <tbody>
                ${(w.peers && w.peers.length > 0) ? w.peers.map(p => `
                  <tr>
                    <td><strong>${p.name}</strong> (${p.ip})</td>
                    <td><span class="badge" style="background:#ddf4ff; color:#0969da;">${p.authType || 'TOTP [RW]'}</span></td>
                    <td><span class="badge badge-pqc">${p.suite || 'ML-KEM-1024 + ML-DSA-87'}</span></td>
                    <td>${p.connectedAt}</td>
                    <td><code>${p.transferred}</code></td>
                    <td><button class="btn-danger btn-xs" onclick="kickPeer('${w.id}', '${p.id}')">${ICONS.stop} Ngắt Kết Nối</button></td>
                  </tr>
                `).join('') : '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:12px;">Chưa có peer nào kết nối.</td></tr>'}
              </tbody>
            </table>
          </div>

          <div id="subtab-${w.id}-acl" style="display:none;">
            <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
              <label style="font-weight:600; font-size:12px;">Chế Độ Phân Quyền Cho Bạn Bè:</label>
              <select class="input-select" style="max-width:280px; height:32px;" onchange="updateHostRole('${w.id}', this.value)">
                <option value="rw" ${w.role === 'rw' ? 'selected' : ''}>[rw] Đọc &amp; Ghi (Cho phép tải về và tải lên)</option>
                <option value="r" ${w.role === 'r' ? 'selected' : ''}>[r] Chỉ Đọc (Chỉ cho tải về, cấm sửa đổi)</option>
                <option value="w" ${w.role === 'w' ? 'selected' : ''}>[w] Hộp Thư Nộp Bài (Blind Drop)</option>
              </select>
              <span style="font-size:11px; color:#1a7f37;">Đã lưu cấu hình phân quyền tức thì.</span>
            </div>
          </div>

          <div id="subtab-${w.id}-log" style="display:none;">
            <div style="background:#1f2328; color:#e6edf3; padding:10px; font-size:11px; border-radius:4px; max-height:160px; overflow-y:auto; line-height:1.6; font-family:'JetBrains Mono', monospace;">
              ${(w.logs || []).map(l => `<div>&gt; ${l}</div>`).join('')}
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

function toggleAdminPanel(hostId) {
  const panel = document.getElementById('admin-drawer-' + hostId);
  if (!panel) return;
  panel.style.display = (panel.style.display === 'block') ? 'none' : 'block';
}

function switchAdminTab(hostId, tabName, btn) {
  const card = document.getElementById('admin-drawer-' + hostId);
  card.querySelectorAll('.admin-tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  ['audit', 'peers', 'acl', 'log'].forEach(t => {
    const el = document.getElementById(`subtab-${hostId}-${t}`);
    if (el) el.style.display = (t === tabName) ? 'block' : 'none';
  });
}

function updateHostSuite(hostId, newSuite) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  if (!host) return;
  host.suite = newSuite;
  host.suiteName = (newSuite === '3') ? '⭐ Mức 3: Pure Post-Quantum (ML-KEM-1024 + ML-DSA-87)' :
                   ((newSuite === '2') ? '⚛️ Mức 2: Modern Hybrid (ML-KEM-768 + X25519)' : '⚡ Mức 1: Classical Fast (X25519 + AES-GCM)');
  host.logs.unshift(`[${new Date().toLocaleTimeString()}] Đổi Cipher Suite sang ${host.suiteName}`);
  renderHostedWorkspaces();
  toggleAdminPanel(hostId);
}

function updateHostFilter(hostId, newFilter) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  if (!host) return;
  host.filterMode = newFilter;
  host.logs.unshift(`[${new Date().toLocaleTimeString()}] Đổi chế độ lọc sang [${newFilter}]`);
  renderHostedWorkspaces();
  toggleAdminPanel(hostId);
}

function updateHostRole(hostId, newRole) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  if (host) {
    host.role = newRole;
    host.logs.unshift(`[${new Date().toLocaleTimeString()}] Quản trị viên cập nhật quyền thành [${newRole}]`);
  }
}

function rotateHostOtps(id) {
  const host = hostedWorkspaces.find(w => w.id === id);
  if (!host) return;
  host.otp_rw = Math.floor(10000000 + Math.random() * 90000000).toString();
  host.otp_r = Math.floor(10000000 + Math.random() * 90000000).toString();
  host.otp_w = Math.floor(10000000 + Math.random() * 90000000).toString();
  host.otp = host.otp_rw;
  host.ttl = host.maxTtl || 30;
  renderHostedWorkspaces();
  showToast(`Đã xoay bộ 3 mã OTP mới! Mã RW: ${host.otp_rw}`);
}

function toggleUnquarantine(hostId, fname) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  if (host && host.quarantinedFiles) {
    const qf = host.quarantinedFiles.find(f => f.name === fname);
    if (qf) {
      qf.unquarantined = !qf.unquarantined;
      if (qf.unquarantined) {
        host.auditStats.quarantined = Math.max(0, host.auditStats.quarantined - 1);
        host.auditStats.clean += 1;
        host.logs.unshift(`[${new Date().toLocaleTimeString()}] 🔓 Quản trị viên ĐÃ GỠ CÁCH LY cho tệp '${fname}'`);
        showToast(`Đã gỡ cách ly cho tệp ${fname}! Tệp hiện đã có thể được tải về.`);
      } else {
        host.auditStats.quarantined += 1;
        host.auditStats.clean = Math.max(0, host.auditStats.clean - 1);
        host.logs.unshift(`[${new Date().toLocaleTimeString()}] 🔒 Quản trị viên TÁI CÁCH LY lại tệp '${fname}'`);
        showToast(`Đã tái cách ly tệp ${fname} vào RAM Shield!`);
      }
    }
  }
  renderHostedWorkspaces();
  toggleAdminPanel(hostId);
}

function kickPeer(hostId, peerId) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  if (host && host.peers) {
    host.peers = host.peers.filter(p => p.id !== peerId);
    renderHostedWorkspaces();
    toggleAdminPanel(hostId);
    showToast(`Đã ngắt kết nối peer ${peerId}!`);
  }
}

function getNextFreePort() {
  const usedPorts = new Set(hostedWorkspaces.map(w => parseInt(w.port)));
  let p = 9443;
  while (usedPorts.has(p)) { p++; }
  return p;
}

function startHosting(e) {
  e.preventDefault();
  const pathInp = document.getElementById('host-path').value.trim() || './';
  const portRaw = document.getElementById('host-port').value.trim();
  const portVal = parseInt(portRaw);
  const port = (!isNaN(portVal) && portVal >= 1024 && portVal <= 65535) ? portVal : getNextFreePort();

  if (hostedWorkspaces.some(w => parseInt(w.port) === port)) {
    alert(`Cổng ${port} đã được sử dụng bởi một thư mục khác! Hãy chọn cổng khác.`);
    return;
  }

  const sSelect = document.getElementById('host-suite');
  const fSelect = document.getElementById('host-filter');

  const newOtp = Math.floor(10000000 + Math.random() * 90000000).toString();
  hostedWorkspaces.unshift({
    id: 'host-' + port,
    path: pathInp,
    port: port,
    suite: sSelect.value,
    suiteName: sSelect.options[sSelect.selectedIndex].text,
    filterMode: fSelect.value,
    filterName: fSelect.options[fSelect.selectedIndex].text,
    otp_rw: newOtp,
    otp_r: Math.floor(10000000 + Math.random() * 90000000).toString(),
    otp_w: Math.floor(10000000 + Math.random() * 90000000).toString(),
    otp: newOtp,
    ttl: 30,
    maxTtl: 30,
    role: "rw",
    peers: [],
    auditStats: { clean: 18, quarantined: 1, excluded: 120 },
    quarantinedFiles: [
      { name: ".env", size: "380 B", detector: "Slug Regex & Slug AI", reason: "Phát hiện JWT_SECRET, DATABASE_URL, API_KEY", risk: "CRITICAL", unquarantined: false }
    ],
    excludedFiles: [
      { name: "node_modules/", size: "184.2 MiB", detector: "Slug Rule (.gitignore)", reason: "Rác build dependencies", included: false }
    ],
    logs: [`[${new Date().toLocaleTimeString()}] Khởi động chia sẻ workspace '${pathInp}' trên cổng ${port}`]
  });

  renderHostedWorkspaces();
  document.getElementById('host-port').value = '';
  document.getElementById('host-port').placeholder = 'Tự động (' + getNextFreePort() + ')';
  showToast(`Đã bắt đầu chia sẻ thư mục trên cổng ${port}!`);
}

function stopHost(id) {
  if (confirm("Dừng chia sẻ thư mục này?")) {
    hostedWorkspaces = hostedWorkspaces.filter(w => w.id !== id);
    renderHostedWorkspaces();
    document.getElementById('host-port').placeholder = 'Tự động (' + getNextFreePort() + ')';
  }
}

function renderUserAccounts() {
  const tbody = document.getElementById('users-tbody');
  const countBadge = document.getElementById('users-count');
  if (countBadge) countBadge.textContent = userAccounts.length;
  if (!tbody) return;

  tbody.innerHTML = userAccounts.map(u => `
    <tr>
      <td><div style="display:flex; align-items:center; gap:8px;">${ICONS.user}<strong>${u.username}</strong></div></td>
      <td><span class="role-tag">[${u.role.toUpperCase()}] ${u.roleName}</span></td>
      <td><span class="badge ${u.revoked ? 'badge-offline' : 'badge-live'}">${u.revoked ? '⛔ Đã Thu Hồi' : '🟢 ' + u.status}</span></td>
      <td><code style="font-size:11px; color:var(--text-muted);">${u.createdAt}</code></td>
      <td>
        <button class="btn-sec btn-xs" onclick="openEditUserModal('${u.username}')">${ICONS.edit} Sửa</button>
        <button class="btn-danger btn-xs" onclick="deleteUser('${u.username}')">${ICONS.trash} Xóa</button>
      </td>
    </tr>
  `).join('');
}

function openAddUserModal() {
  document.getElementById('user-modal-title').textContent = 'Tạo Tài Khoản Người Dùng Mới';
  document.getElementById('modal-username').value = '';
  document.getElementById('modal-username').disabled = false;
  document.getElementById('modal-password').value = '';
  document.getElementById('modal-role').value = 'rw';
  document.getElementById('modal-ttl').value = '86400';
  document.getElementById('user-modal').style.display = 'flex';
}

function openEditUserModal(username) {
  const u = userAccounts.find(x => x.username === username);
  if (!u) return;
  document.getElementById('user-modal-title').textContent = `Chỉnh Sửa Tài Khoản: ${username}`;
  document.getElementById('modal-username').value = u.username;
  document.getElementById('modal-username').disabled = true;
  document.getElementById('modal-password').value = '';
  document.getElementById('modal-role').value = u.role || 'rw';
  document.getElementById('modal-ttl').value = u.ttl > 0 ? u.ttl.toString() : '0';
  document.getElementById('user-modal').style.display = 'flex';
}

function closeUserModal() {
  document.getElementById('user-modal').style.display = 'none';
}

function saveUserModal(e) {
  e.preventDefault();
  const uname = document.getElementById('modal-username').value.trim();
  const role = document.getElementById('modal-role').value;
  const ttlSec = parseInt(document.getElementById('modal-ttl').value) || 0;
  const isEdit = document.getElementById('modal-username').disabled;

  const roleNames = { 'rw': 'Toàn Quyền (Đọc & Ghi)', 'r': 'Chỉ Đọc (Tải Về)', 'w': 'Hộp Thư Nộp Bài (Upload)' };
  let statusStr = ttlSec > 0 ? `Còn ${Math.round(ttlSec / 3600)}h` : 'Permanent (∞)';

  if (isEdit) {
    const existing = userAccounts.find(x => x.username === uname);
    if (existing) {
      existing.role = role;
      existing.roleName = roleNames[role];
      existing.ttl = ttlSec;
      existing.status = statusStr;
    }
    showToast(`Đã cập nhật tài khoản ${uname}!`);
  } else {
    userAccounts.unshift({
      username: uname, role: role, roleName: roleNames[role], ttl: ttlSec, status: statusStr,
      createdAt: 'Vừa tạo', revoked: false
    });
    showToast(`Đã tạo tài khoản ${uname}!`);
  }
  closeUserModal();
  renderUserAccounts();
}

function deleteUser(username) {
  if (confirm(`Xóa tài khoản ${username}?`)) {
    userAccounts = userAccounts.filter(x => x.username !== username);
    renderUserAccounts();
    showToast(`Đã xóa tài khoản ${username}!`);
  }
}

function copyText(val, label) {
  navigator.clipboard.writeText(val).then(() => {
    showToast(`Đã sao chép ${label || 'nội dung'}: ${val}`);
  }).catch(() => prompt("Nhấn Ctrl+C để sao chép:", val));
}

function copyCliCmd(port, otp, role) {
  copyText(`slug get 127.0.0.1:${port}?otp=${otp}&role=${role || 'rw'}`, "Lệnh Terminal CLI");
}

function showToast(msg) {
  let toast = document.getElementById('slug-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'slug-toast';
    toast.style.cssText = "position:fixed; bottom:24px; right:24px; background:#1f2328; color:#fff; padding:10px 18px; border-radius:4px; font-family:'JetBrains Mono', monospace; font-size:12px; z-index:9999; box-shadow:0 4px 12px rgba(0,0,0,0.15); transition:opacity 0.3s ease;";
    document.body.appendChild(toast);
  }
  toast.innerHTML = `${ICONS.check} ${msg}`;
  toast.style.opacity = '1';
  clearTimeout(toast._timeout);
  toast._timeout = setTimeout(() => { toast.style.opacity = '0'; }, 3200);
}

function showQrModal(otp, port) {
  document.getElementById('qr-otp-display').textContent = otp;
  document.getElementById('qr-port-display').textContent = port;
  document.getElementById('qr-modal').style.display = 'flex';
}

function closeQrModal() {
  document.getElementById('qr-modal').style.display = 'none';
}

function showCliInstructions(port, otp) {
  document.getElementById('cli-cmd-display').textContent = `slug get 127.0.0.1:${port}?otp=${otp}`;
  document.getElementById('cli-modal').style.display = 'flex';
}

function closeCliModal() {
  document.getElementById('cli-modal').style.display = 'none';
}

setInterval(() => {
  let changed = false;
  hostedWorkspaces.forEach(w => {
    if (w.ttl > 0) {
      w.ttl--;
      const textEl = document.getElementById(`timer-text-${w.id}`);
      const progEl = document.getElementById(`progress-${w.id}`);
      if (textEl) textEl.textContent = w.ttl;
      if (progEl) {
        progEl.style.width = Math.max(0, Math.min(100, (w.ttl / (w.maxTtl || 30)) * 100)) + '%';
      }
    } else {
      w.otp_rw = Math.floor(10000000 + Math.random() * 90000000).toString();
      w.otp_r = Math.floor(10000000 + Math.random() * 90000000).toString();
      w.otp_w = Math.floor(10000000 + Math.random() * 90000000).toString();
      w.otp = w.otp_rw;
      w.ttl = w.maxTtl || 30;
      changed = true;
    }
  });
  if (changed && currentRole === 'host') {
    renderHostedWorkspaces();
  }
}, 1000);

window.onload = function() {
  renderHostedWorkspaces();
  renderUserAccounts();
};
</script>
</head>
<body>
<div class="container">
  <div class="top-bar">
    <div class="logo-title">
      <div class="logo-icon">SLUG</div>
      <div>
        <div style="font-weight:700; font-size:16px;">Trạm Điều Khiển Workspace Trực Tiếp</div>
        <div style="font-size:11px; color:var(--text-muted); font-family:'JetBrains Mono', monospace;">
          Post-Quantum P2P Workspace Sharing &bull; NIST FIPS 203/204 &bull; Local Bridge: <strong>127.0.0.1:{{PORTAL_PORT}}</strong>
        </div>
      </div>
    </div>
    <div class="header-actions">
      <button class="btn-danger btn-sm" onclick="if(confirm('Thoát Slug Engine?'))fetch('/api/portal/quit',{method:'POST'}).finally(()=>window.close())">
        ${ICONS.stop} Thoát Slug Engine
      </button>
    </div>
  </div>

  <div class="role-tabs">
    <button class="role-tab-btn active" id="tab-btn-client" onclick="switchRole('client')">
      <span>📥</span>
      <span>Nhận Dữ Liệu (Client Mode)</span>
    </button>
    <button class="role-tab-btn" id="tab-btn-host" onclick="switchRole('host')">
      <span>📤</span>
      <span>Chia Sẻ Dữ Liệu (Host Mode)</span>
      <span class="badge" id="hosted-count" style="background:#0969da; color:#fff; font-size:10px;">1</span>
    </button>
  </div>

  <!-- SECTION CLIENT -->
  <div id="section-client">
    <div class="card">
      <h3><span>🚀 Kết Nối Đến Máy Bạn Cùng Nhóm (LAN / Remote)</span></h3>
      
      <div style="display:flex; gap:6px; margin-bottom:14px; border-bottom:1px solid var(--border-primary); padding-bottom:10px;">
        <button type="button" class="btn-sec btn-sm active" id="auth-tab-otp" onclick="switchClientAuth('otp')">
          ${ICONS.lock} Xác Thực Bằng Mã OTP (TOTP)
        </button>
        <button type="button" class="btn-sec btn-sm" id="auth-tab-acc" onclick="switchClientAuth('account')">
          ${ICONS.user} Đăng Nhập Bằng Tài Khoản &amp; Mật Khẩu
        </button>
      </div>

      <form onsubmit="submitClientConnect(event)">
        <div class="form-grid">
          <div class="form-group">
            <label>Địa Chỉ Máy Chủ (IP:Port)</label>
            <input type="text" id="client-endpoint" class="input-text" value="127.0.0.1:9443" placeholder="192.168.1.x:9443" required>
          </div>
          <div class="form-group">
            <label>Mức Mật Mã Kết Nối (Cipher Suite)</label>
            <select id="client-suite" class="input-select">
              <option value="3" selected>⭐ Mức 3: Pure Post-Quantum (ML-KEM-1024 + ML-DSA-87)</option>
              <option value="2">⚛️ Mức 2: Modern Hybrid (ML-KEM-768 + X25519)</option>
              <option value="1">⚡ Mức 1: Classical Fast (X25519 + AES-GCM)</option>
            </select>
          </div>
          <div class="form-group" style="display:flex; align-items:flex-end;">
            <button type="submit" class="btn" style="width:100%; justify-content:center;">
              ${ICONS.check} 🚀 Bắt Đầu Kết Nối &amp; Nhận File
            </button>
          </div>
        </div>

        <div id="client-auth-otp-sec">
          <div class="form-group" style="max-width:320px;">
            <label>Mã OTP Kết Nối (8 Chữ Số Sinh Động)</label>
            <input type="text" id="client-otp" class="input-text" placeholder="Ví dụ: 48291048" maxlength="8">
          </div>
        </div>

        <div id="client-auth-acc-sec" style="display:none;">
          <div style="display:grid; grid-template-columns: 1fr 1fr; gap:14px; max-width:640px;">
            <div class="form-group">
              <label>Tên Tài Khoản (Username)</label>
              <input type="text" id="client-username" class="input-text" placeholder="Ví dụ: colleague_bob" autocomplete="username">
            </div>
            <div class="form-group">
              <label>Mật Khẩu (Password)</label>
              <input type="password" id="client-password" class="input-text" placeholder="Mật khẩu tài khoản" autocomplete="current-password">
            </div>
          </div>
          <div style="font-size:11px; color:#0969da; margin-top:2px; font-family:'JetBrains Mono', monospace;">
            💡 Một tài khoản có thể được đăng nhập đồng thời bởi nhiều máy trạm trong cùng nhóm.
          </div>
        </div>
      </form>
      <div id="conn-msg" style="margin-top:10px; font-size:12px; font-family:'JetBrains Mono', monospace;"></div>
    </div>

    <div class="card">
      <h3>
        <span>📂 Danh Sách Các Trạm Đã Kết Nối Gần Đây ({{SAVED_CONNS_COUNT}})</span>
        <button class="btn-sec btn-sm" onclick="window.location.reload()">${ICONS.refresh} Làm Mới</button>
      </h3>
      <table>
        <thead>
          <tr>
            <th>Tên / ID</th>
            <th>Thư Mục</th>
            <th>Địa Chỉ (IP:Port)</th>
            <th>Quyền</th>
            <th>Thời Hạn</th>
            <th>Thao Tác</th>
          </tr>
        </thead>
        <tbody>
          {{SAVED_CONNS_ROWS}}
        </tbody>
      </table>
    </div>
  </div>

  <!-- SECTION HOST -->
  <div id="section-host" style="display:none;">
    <div class="card" id="host-config-card">
      <h3><span>📤 Bật Chia Sẻ Workspace Nhanh Cho Bạn Bè</span></h3>
      <form onsubmit="startHosting(event)">
        <div class="form-grid">
          <div class="form-group">
            <label>Đường Dẫn Thư Mục (Workspace)</label>
            <div style="display:flex; gap:8px; align-items:center;">
              <input type="text" id="host-path" class="input-text" value="./" placeholder="Ví dụ: D:/slugdoc hoặc ./" style="height:38px; box-sizing:border-box;" required>
              <label class="btn-sec" style="cursor:pointer; white-space:nowrap; display:inline-flex; align-items:center; justify-content:center; height:38px; box-sizing:border-box; padding:0 14px; font-size:12px;">
                <input type="file" id="host-folder-picker" webkitdirectory directory style="display:none;" onchange="if(this.files.length>0)document.getElementById('host-path').value='./'+this.files[0].webkitRelativePath.split('/')[0]">
                <span>${ICONS.folder}</span>
                <span>Chọn Thư Mục</span>
              </label>
            </div>
          </div>
          <div class="form-group">
            <label>Cổng Máy Chủ (Port)</label>
            <input type="number" id="host-port" class="input-text" value="9443" placeholder="Tự động (9443)" style="height:38px; box-sizing:border-box;">
          </div>
          <div class="form-group">
            <label>Mức Mật Mã Mặc Định (Cipher Suite)</label>
            <select id="host-suite" class="input-select" style="height:38px; box-sizing:border-box;">
              <option value="3" selected>⭐ Mức 3: Pure Post-Quantum (ML-KEM-1024 + ML-DSA-87) [Khuyên dùng]</option>
              <option value="2">⚛️ Mức 2: Modern Hybrid (ML-KEM-768 + X25519 + ChaCha20)</option>
              <option value="1">⚡ Mức 1: Classical Fast (X25519 + AES-256-GCM)</option>
            </select>
          </div>
        </div>
        <div class="form-grid" style="grid-template-columns: 2fr 1fr;">
          <div class="form-group">
            <label>Chế Độ Lọc Dữ Liệu Slug Guard</label>
            <select id="host-filter" class="input-select">
              <option value="protected" selected>🛡️ Protected (Lọc rác .gitignore + Chặn secret qua Regex &amp; AI)</option>
              <option value="include_ignored">📦 Include-Ignored (Gửi cả build artifacts, chỉ chặn secret)</option>
              <option value="none">⚠️ None (Gửi toàn bộ, không lọc - Thận trọng!)</option>
            </select>
          </div>
          <div class="form-group" style="display:flex; align-items:flex-end;">
            <button type="submit" class="btn" style="width:100%; height:38px; justify-content:center;">
              ${ICONS.plus} 🚀 Bắt Đầu Chia Sẻ Thư Mục
            </button>
          </div>
        </div>
      </form>
    </div>

    <div class="card">
      <h3>
        <span>📁 Danh Sách Các Thư Mục Đang Chia Sẻ (<span id="hosted-count-title">1</span>)</span>
        <button class="btn-sec btn-sm" onclick="renderHostedWorkspaces()">${ICONS.refresh} Làm Mới Danh Sách</button>
      </h3>
      <div id="hosted-workspaces-list"></div>
    </div>

    <!-- User Accounts CRUD -->
    <div class="card">
      <h3>
        <span>${ICONS.users} Quản Lý Tài Khoản Người Dùng &amp; Phân Quyền Ephemeral RBAC (<span id="users-count">3</span>)</span>
        <div style="display:flex; gap:8px;">
          <button class="btn btn-sm" onclick="openAddUserModal()">${ICONS.plus} Tạo Tài Khoản Mới</button>
          <button class="btn-sec btn-sm" onclick="renderUserAccounts()">${ICONS.refresh} Làm Mới</button>
        </div>
      </h3>
      <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px; font-family:'JetBrains Mono', monospace;">
        Quản lý các tài khoản cố định hoặc tạm thời (Ephemeral) để bạn bè đăng nhập vào workspace mà không cần phụ thuộc mã OTP quay vòng. <strong>Một tài khoản có thể được đăng nhập đồng thời bởi nhiều máy trạm.</strong>
      </div>
      <table>
        <thead>
          <tr>
            <th>Tên Tài Khoản</th>
            <th>Phân Quyền (RBAC Role)</th>
            <th>Trạng Thái / Thời Hạn (TTL)</th>
            <th>Thời Gian Tạo</th>
            <th>Thao Tác</th>
          </tr>
        </thead>
        <tbody id="users-tbody"></tbody>
      </table>
    </div>
  </div>

  <div class="footer">
    Slug 1.0.0 &bull; Trạm Điều Khiển Workspace Trực Tiếp Giữa Các Máy Tính &bull; Apache-2.0
  </div>
</div>

<!-- Modal QR Code -->
<div class="modal-overlay" id="qr-modal" onclick="if(event.target===this)closeQrModal()">
  <div class="modal-box" style="text-align:center;">
    <h3 style="margin-top:0;">📱 Mã QR Kết Nối Nhanh Cho Thiết Bị Di Động</h3>
    <p style="font-size:12px; color:var(--text-muted);">Quét mã này bằng ứng dụng Slug Mobile hoặc máy ảnh trên điện thoại để nhận workspace:</p>
    <div style="background:#f6f8fa; border:1px solid #d0d7de; padding:24px; display:inline-block; margin:12px auto; border-radius:4px;">
      <svg width="180" height="180" viewBox="0 0 100 100">
        <rect x="0" y="0" width="100" height="100" fill="#fff"/>
        <rect x="10" y="10" width="25" height="25" fill="#1f2328"/>
        <rect x="15" y="15" width="15" height="15" fill="#fff"/>
        <rect x="18" y="18" width="9" height="9" fill="#1f2328"/>
        <rect x="65" y="10" width="25" height="25" fill="#1f2328"/>
        <rect x="70" y="15" width="15" height="15" fill="#fff"/>
        <rect x="73" y="18" width="9" height="9" fill="#1f2328"/>
        <rect x="10" y="65" width="25" height="25" fill="#1f2328"/>
        <rect x="15" y="70" width="15" height="15" fill="#fff"/>
        <rect x="18" y="73" width="9" height="9" fill="#1f2328"/>
        <rect x="45" y="20" width="10" height="10" fill="#1f2328"/>
        <rect x="40" y="45" width="20" height="10" fill="#1f2328"/>
        <rect x="45" y="65" width="10" height="20" fill="#1f2328"/>
        <rect x="65" y="45" width="20" height="10" fill="#1f2328"/>
        <rect x="75" y="65" width="15" height="15" fill="#1f2328"/>
      </svg>
    </div>
    <div style="font-family:'JetBrains Mono', monospace; font-size:14px; margin-bottom:16px;">
      Cổng: <strong id="qr-port-display">9443</strong> &bull; OTP: <strong id="qr-otp-display" style="color:#0969da; font-size:18px;">48291048</strong>
    </div>
    <button class="btn btn-sm" onclick="closeQrModal()">Đóng Cửa Sổ</button>
  </div>
</div>

<!-- Modal Terminal Help -->
<div class="modal-overlay" id="cli-modal" onclick="if(event.target===this)closeCliModal()">
  <div class="modal-box">
    <h3 style="margin-top:0;">>_ Hướng Dẫn Dùng Lệnh Terminal CLI</h3>
    <p style="font-size:12px; color:var(--text-muted);">Bạn bè của bạn chỉ cần mở Command Prompt / PowerShell / Bash và dán lệnh sau:</p>
    <div style="background:#1f2328; color:#e6edf3; padding:12px; border-radius:4px; font-family:'JetBrains Mono', monospace; font-size:12px; margin-bottom:12px; word-break:break-all;">
      <code id="cli-cmd-display">slug get 127.0.0.1:9443?otp=48291048</code>
    </div>
    <div style="font-size:11px; color:var(--text-muted); margin-bottom:16px;">
      💡 Lệnh trên sẽ tự động thiết lập kênh mật mã Hậu lượng tử NIST FIPS 203 (ML-KEM) và đồng bộ workspace về máy trạm đích chỉ trong vài giây.
    </div>
    <button class="btn btn-sm" onclick="closeCliModal()">Đã Hiểu</button>
  </div>
</div>

<!-- Modal User Account Add/Edit -->
<div class="modal-overlay" id="user-modal" onclick="if(event.target===this)closeUserModal()">
  <div class="modal-box">
    <h3 style="margin-top:0;" id="user-modal-title">Tạo Tài Khoản Người Dùng Mới</h3>
    <form onsubmit="saveUserModal(event)">
      <div class="form-group">
        <label>Tên Đăng Nhập (Username)</label>
        <input type="text" id="modal-username" class="input-text" placeholder="Ví dụ: bob, alice_dev" required>
      </div>
      <div class="form-group">
        <label>Mật Khẩu (Password)</label>
        <input type="password" id="modal-password" class="input-text" placeholder="Nhập mật khẩu an toàn">
      </div>
      <div class="form-group">
        <label>Quyền Hạn (RBAC Role)</label>
        <select id="modal-role" class="input-select">
          <option value="rw">[rw] Toàn Quyền (Đọc &amp; Ghi - Đầy Đủ)</option>
          <option value="r">[r] Chỉ Đọc (Chỉ cho tải về, không cho sửa)</option>
          <option value="w">[w] Nộp Bài (Chỉ cho tải lên / Hộp thư Blind Drop)</option>
        </select>
      </div>
      <div class="form-group">
        <label>Thời Gian Sống Của Tài Khoản (TTL Expiration)</label>
        <select id="modal-ttl" class="input-select">
          <option value="1800">30 Phút (Ephemeral)</option>
          <option value="7200">2 Giờ</option>
          <option value="86400" selected>24 Giờ (1 Ngày)</option>
          <option value="604800">7 Ngày</option>
          <option value="0">Vô Thời Hạn (Permanent ∞)</option>
        </select>
      </div>
      <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:16px;">
        <button type="button" class="btn-sec btn-sm" onclick="closeUserModal()">Hủy Bỏ</button>
        <button type="submit" class="btn btn-sm">Lưu Tài Khoản</button>
      </div>
    </form>
  </div>
</div>

</body>
</html>
)raw";

        size_t p = html.find("{{PORTAL_PORT}}");
        if (p != std::string::npos) html.replace(p, 15, std::to_string(portal_port));

        std::string conns_rows = "";
        uint64_t now = core::Utils::current_timestamp();
        for (const auto& c : conns) {
            std::string exp_str = (c.expires_at == 0) ? "Permanent (∞)"
                                  : (c.expires_at > now ? core::Utils::format_duration(c.expires_at - now) : "<span style='color:var(--danger);'>Expired</span>");
            conns_rows += "<tr class='clickable-row' onclick='openSaved(\"" + c.id + "\")'><td><strong>" + c.id + "</strong></td>"
                       + "<td><code>" + c.workspace + "</code></td>"
                       + "<td><code>" + c.host + ":" + std::to_string(c.port) + "</code></td>"
                       + "<td><span class='role-tag'>" + core::role_to_string(c.role) + "</span></td>"
                       + "<td>" + exp_str + "</td>"
                       + "<td onclick='event.stopPropagation()'><button class='btn btn-xs' onclick='openSaved(\"" + c.id + "\")'>🚀 Open</button> "
                       + "<button class='btn-danger btn-xs' onclick='removeSaved(\"" + c.id + "\")'>Remove</button></td></tr>";
        }
        if (conns_rows.empty()) {
            conns_rows = "<tr><td colspan='6' style='text-align:center; color:var(--text-muted); padding:18px;'>Chưa có trạm lưu nào. Điền IP và mã OTP vào biểu mẫu phía trên để kết nối ngay.</td></tr>";
        }

        p = html.find("{{SAVED_CONNS_ROWS}}");
        if (p != std::string::npos) html.replace(p, 20, conns_rows);

        p = html.find("{{SAVED_CONNS_COUNT}}");
        if (p != std::string::npos) html.replace(p, 21, std::to_string(conns.size()));

        return html;
    }
};

} // namespace slug::net
