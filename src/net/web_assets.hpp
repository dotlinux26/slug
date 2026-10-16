#pragma once

#include "src/core/types.hpp"
#include "src/core/acl.hpp"
#include "src/core/audit.hpp"
#include "src/core/utils.hpp"
#include "src/sync/manifest.hpp"
#include "src/bench/benchmark.hpp"
#include "src/policy/rules.hpp"
#include "src/ai/stateful_audit.hpp"
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
          << "<div>"
          << "<input type='file' id='hidden-file-input' multiple style='display:none;' onchange='uploadFiles(this.files)'>"
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
          << ".log-entry { font-family: 'JetBrains Mono', monospace; font-size: 11px; margin: 4px 0; color: var(--text-muted); }"
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
          << "function reloadSessions() {"
          << "  fetch('/api/admin/sessions')"
          << "    .then(r => r.json())"
          << "    .then(sessions => {"
          << "      const tbody = document.getElementById('sessions-tbody');"
          << "      if (!tbody) return;"
          << "      if (!sessions || sessions.length === 0) {"
          << "        tbody.innerHTML = '<tr><td colspan=\"8\" style=\"color:var(--text-muted); text-align:center; padding:14px;\">No connected client sessions recorded yet</td></tr>';"
          << "        return;"
          << "      }"
          << "      let html = '';"
          << "      sessions.forEach(s => {"
          << "        let actBadge = renderAuthBadge(s.auth_type);"
          << "        let stBadge = renderSessionStatus(s);"
          << "        let btn = (s.is_active && !s.is_revoked)"
          << "          ? '<button class=\"btn-danger btn-sm\" onclick=\"killSession(' + s.session_id + ')\">Kill Session</button>'"
          << "          : '<span style=\"color:var(--text-muted); font-size:11px;\">Terminated</span>';"
          << "        let timeInfo = formatAgo(s.created_at) + ' / <span style=\"color:var(--text-accent);\">' + formatAgo(s.last_active_at) + '</span>';"
          << "        html += '<tr><td><strong>#' + s.session_id + '</strong></td>'"
          << "             + '<td><code>' + s.identity + '</code></td>'"
          << "             + '<td>' + actBadge + '</td>'"
          << "             + '<td><code>' + s.remote_endpoint + '</code></td>'"
          << "             + '<td><span class=\"role-tag\">' + s.role + '</span></td>'"
          << "             + '<td>' + timeInfo + '</td>'"
          << "             + '<td>' + stBadge + '</td>'"
          << "             + '<td>' + btn + '</td></tr>';"
          << "      });"
          << "      tbody.innerHTML = html;"
          << "    }).catch(e => {});"
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
          << "function reloadAudit() {"
          << "  fetch('/api/admin/audit').then(r => r.json()).then(entries => {"
          << "    const tbody = document.getElementById('audit-tbody'); if (!tbody) return;"
          << "    if (!entries || entries.length === 0) { tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:var(--text-muted);\">No quarantined or flagged files</td></tr>'; return; }"
          << "    let html = '';"
          << "    entries.forEach(e => {"
          << "      let stColor = (e.status === 'CLEAN' || e.status === 'MANUAL_ALLOWED') ? 'var(--success)' : 'var(--danger)';"
          << "      html += '<tr><td><code>' + e.file_path + '</code></td><td><span style=\"color:' + stColor + '; font-weight:bold;\">' + e.status + '</span></td>'"
          << "           + '<td>' + (e.line_number > 0 ? 'L' + e.line_number : '-') + '</td><td>' + e.reason + '</td>'"
          << "           + '<td>' + (e.status.indexOf('ALLOWED') === -1 ? '<button class=\"btn btn-sm\" onclick=\"allowAuditFile(\\'' + e.file_path + '\\')\">Whitelist</button>' : '<span style=\"color:var(--text-muted);\">Whitelisted</span>') + '</td></tr>';"
          << "    });"
          << "    tbody.innerHTML = html;"
          << "  });"
          << "}"
          << "function allowAuditFile(filePath) {"
          << "  const reason = prompt('Reason for whitelisting false positive for:\\n' + filePath, 'Verified safe false positive');"
          << "  if (!reason) return;"
          << "  fetch('/api/admin/audit/allow', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: filePath, reason: reason }) })"
          << "    .then(r => r.json()).then(res => { if (res.status === 'ok') reloadAudit(); else alert(res.message); });"
          << "}"
          << "window.addEventListener('DOMContentLoaded', () => { runLiveBenchmark(); setInterval(runLiveBenchmark, 3500); reloadSessions(); setInterval(reloadSessions, 2500); });"
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
          << "<button class='btn-sec btn-sm' onclick='reloadSessions()'>Refresh</button>"
          << "</span></h3>"
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
        h << "</tbody></table></div>"

          << "<div class='card' style='margin-bottom: 16px;'>"
          << "<h3><span>Cryptographic &amp; I/O Telemetry</span><span id='bench-status' style='font-size:11px;'></span></h3>"
          << "<div class='metric-grid'>"
          << "<div class='metric-box'><div class='metric-lbl'>BLAKE3 Throughput</div><div id='m-blake3' class='metric-val' style='color:var(--success);'>" << static_cast<int>(blake3_speed) << " MB/s</div></div>"
          << "<div class='metric-box'><div class='metric-lbl'>ML-KEM-768 Decap</div><div id='m-kem' class='metric-val' style='color:var(--pqc);'>" << static_cast<int>(pqc_kem_decap) << " &mu;s</div></div>"
          << "<div class='metric-box'><div class='metric-lbl'>ML-DSA-65 Verify</div><div id='m-sig' class='metric-val' style='color:var(--pqc);'>" << static_cast<int>(pqc_sig_verify) << " &mu;s</div></div>"
          << "<div class='metric-box'><div class='metric-lbl'>XChaCha20 AEAD</div><div id='m-cipher' class='metric-val'>" << static_cast<int>(cipher_speed) << " MB/s</div></div>"
          << "<div class='metric-box'><div class='metric-lbl'>AI Guard Rate</div><div id='m-ai' class='metric-val' style='color:var(--warning);'>" << static_cast<int>(bench_rep.ai.lines_per_sec) << " L/s</div></div>"
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

          << "<div class='card'><h3><span>AI Guard Quarantined Files (.slug/index.db)</span></h3>"
          << "<table><thead><tr><th>File</th><th>Status</th><th>Line</th><th>AI Reason</th><th>Action</th></tr></thead><tbody id='audit-tbody'>";

        for (const auto& ae : audit_entries) {
            std::string st_str = core::audit_status_to_string(ae.status);
            std::string st_color = (ae.status == core::AuditStatus::CLEAN || ae.status == core::AuditStatus::USER_ALLOWED) ? "var(--success)" : "var(--danger)";
            h << "<tr><td><code>" << ae.file_path << "</code></td><td><span style='color:" << st_color << "; font-weight:bold;'>" << st_str << "</span></td>"
              << "<td>" << (ae.line_number > 0 ? ("L" + std::to_string(ae.line_number)) : "-") << "</td><td>" << ae.reason << "</td>"
              << "<td>" << (ae.status != core::AuditStatus::USER_ALLOWED ? ("<button class='btn btn-sm' onclick=\"allowAuditFile('" + ae.file_path + "')\">Whitelist</button>") : "<span style='color:var(--text-muted);'>Whitelisted</span>") << "</td></tr>";
        }
        if (audit_entries.empty()) {
            h << "<tr><td colspan='5' style='color:var(--text-muted);'>No quarantined or flagged files</td></tr>";
        }
        h << "</tbody></table></div></div>"

          << "<div class='card' style='margin-bottom: 16px;'><h3>Recent Security Audit Activity (.slug/audit.log)</h3>"
          << "<div style='max-height:140px; overflow-y:auto; padding:4px;'>";
        for (const auto& e : events) {
            h << "<div class='log-entry'>[" << e.action << "] " << e.actor << " &bull; " << e.path << " &bull; " << e.reason << "</div>";
        }
        if (events.empty()) {
            h << "<div class='log-entry'>No audit events recorded yet.</div>";
        }
        h << "</div></div>"

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
};

} // namespace slug::net
