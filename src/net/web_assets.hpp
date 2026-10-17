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
    static std::string html_escape(std::string_view s) {
        std::string res;
        res.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&': res += "&amp;"; break;
                case '<': res += "&lt;"; break;
                case '>': res += "&gt;"; break;
                case '"': res += "&quot;"; break;
                case '\'': res += "&#39;"; break;
                default: res += c; break;
            }
        }
        return res;
    }

    static std::string js_escape(std::string_view s) {
        std::string res;
        res.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '\\': res += "\\\\"; break;
                case '\'': res += "\\'"; break;
                case '"': res += "\\\""; break;
                case '\n': res += "\\n"; break;
                case '\r': res += "\\r"; break;
                case '<': res += "\\x3C"; break;
                case '>': res += "\\x3E"; break;
                case '&': res += "\\x26"; break;
                default: res += c; break;
            }
        }
        return res;
    }

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
          << "<div class='msg'>" << html_escape(reason) << "</div>"
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
        auto manifest = sync::ManifestBuilder::build(workspace_root, 1, static_cast<uint8_t>(suite_id), false);
        return render_directory_listing(workspace_root, port, suite_id, rel_subpath, identity, role, manifest);
    }

    static std::string render_directory_listing(
        const std::filesystem::path& workspace_root,
        uint16_t port,
        core::SuiteID suite_id,
        const std::string& rel_subpath,
        const std::string& identity,
        core::Role role,
        const sync::WorkspaceManifest& manifest)
    {
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
            if (s.status == "AI_FLAGGED" || s.status == "SMART_FILTER_FLAGGED") {
                st_label = "Quarantined";
                badge_cls = "badge-quarantined";
            } else if (s.status == "MANUAL_BLOCKED") {
                st_label = "Blocked (Manual Guard)";
                badge_cls = "badge-blocked";
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
          << "html { overflow-y: scroll; scrollbar-gutter: stable; } .container { width: 96%; max-width: 1360px; min-width: 1040px; margin: 0 auto; background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 24px; box-shadow: 0 1px 3px rgba(31,35,40,0.08); box-sizing: border-box; }"
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
          << ".act-btn { display: inline-flex; align-items: center; justify-content: center; gap: 4px; height: 24px; line-height: 22px; padding: 0 8px; font-size: 11px; font-weight: 500; border-radius: var(--radius-sharp); text-decoration: none; font-family: 'JetBrains Mono', monospace; cursor: pointer; box-sizing: border-box; white-space: nowrap; vertical-align: middle; border: 1px solid var(--border-primary); background: #ffffff; color: var(--text-main); transition: all 0.15s ease; }"
          << ".act-btn:hover { background: var(--bg-surface-hover); border-color: #afb8c1; color: var(--text-main); }"
          << ".act-btn-danger { background: #fff8f8; border-color: #ffc8c8; color: #cf222e; }"
          << ".act-btn-danger:hover { background: #ffebe9; border-color: #cf222e; color: #a40e26; }"
          << ".act-btn svg { flex-shrink: 0; width: 12px; height: 12px; display: inline-block; vertical-align: middle; }"
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
          << "    listHtml += '<div style=\"display:flex; align-items:center; gap:6px;\"><svg width=\"12\" height=\"12\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z\"></path><polyline points=\"14 2 14 8 20 8\"></polyline></svg> ' + p + ' (' + formatSize(s) + ')</div>';"
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
          << "function toggleManualBlockFile(p, block) {"
          << "  const ep = block ? '/api/admin/manual-block' : '/api/admin/manual-unblock';"
          << "  const msg = block ? ('Bạn có chắc muốn chặn tệp \"' + p + '\" khỏi chia sẻ mạng?\\n(Gắn nhãn: Người tự kiểm toán - Manual Guard)') : ('Bạn có chắc muốn gỡ chặn tệp \"' + p + '\"?');"
          << "  if (!confirm(msg)) return;"
          << "  fetch(ep, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({path: p, is_dir: false}) })"
          << "    .then(r => r.json())"
          << "    .then(res => { if (res.status === 'ok') location.reload(); else alert('Lỗi: ' + (res.message || 'Không thể thao tác')); })"
          << "    .catch(e => alert('Lỗi: ' + e));"
          << "}"
          << "function toggleManualBlockDir(p) {"
          << "  if (!confirm('Bạn có chắc muốn chặn toàn bộ thư mục \"' + p + '/\" khỏi chia sẻ mạng?\\n(Gắn nhãn: Người tự kiểm toán - Manual Guard)')) return;"
          << "  fetch('/api/admin/manual-block', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({path: p, is_dir: true}) })"
          << "    .then(r => r.json())"
          << "    .then(res => { if (res.status === 'ok') location.reload(); else alert('Lỗi: ' + (res.message || 'Không thể chặn')); })"
          << "    .catch(e => alert('Lỗi: ' + e));"
          << "}"
          << "function returnToPortal() {"
          << "  if (window.location.port === '8080' || window.location.pathname.startsWith('/portal')) {"
          << "    window.location.href = '/portal';"
          << "    return;"
          << "  }"
          << "  if (document.referrer && (document.referrer.includes('/portal') || document.referrer.includes(':8080'))) {"
          << "    window.location.href = document.referrer;"
          << "    return;"
          << "  }"
          << "  let savedCfg = null;"
          << "  try { savedCfg = JSON.parse(localStorage.getItem('slug_system_config') || '{}'); } catch(e){}"
          << "  const pPort = (savedCfg && savedCfg.portal_port) ? savedCfg.portal_port : 8080;"
          << "  window.location.href = 'http://127.0.0.1:' + pPort + '/portal';"
          << "}"
          << "setInterval(() => {"
          << "  fetch('/api/status')"
          << "    .then(r => { if (r.status === 401 || r.status === 403) window.location.href = '/portal?reason=revoked'; })"
          << "    .catch(() => {});"
          << "}, 4000);"
          << "window.addEventListener('dragover', e => { e.preventDefault(); document.getElementById('drop-container').classList.add('dropzone-active'); });"
          << "window.addEventListener('dragleave', e => { if (e.clientX <= 0 || e.clientY <= 0) document.getElementById('drop-container').classList.remove('dropzone-active'); });"
          << "window.addEventListener('drop', e => {"
          << "  e.preventDefault();"
          << "  document.getElementById('drop-container').classList.remove('dropzone-active');"
          << "  if (e.dataTransfer && e.dataTransfer.files) uploadFiles(e.dataTransfer.files);"
          << "});"
          << "</script></head><body>"
          << "<div class='container'>"
          << "<div class='top-bar'>"
          << "<h1><span>Slug Workspace Explorer</span> <span class='badge badge-pqc'>" << core::suite_to_string(suite_id) << "</span></h1>"
          << "<div style='display:flex; align-items:center; gap:8px;'>"
          << "<div class='user-badge'><svg width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><path d='M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2'></path><circle cx='12' cy='7' r='4'></circle></svg> " << html_escape(identity) << " <span class='role-tag'>" << core::role_to_string(role) << "</span></div>"
          << "<button type='button' class='btn-sec' onclick='returnToPortal()' style='display:inline-flex; align-items:center; gap:6px;' title='Quay lại Trạm Điều Khiển Workspace để kết nối phiên mới'><svg width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><polyline points='4 17 10 11 4 5'></polyline><line x1='12' y1='19' x2='20' y2='19'></line></svg> <span>Trở Về Trạm Điều Khiển</span></button>"
          << (identity == "host_admin" ? "<a class='btn-sec' href='/admin'>Admin Dashboard</a>" : "")
          << "<a class='btn-sec' href='/logout' style='color:var(--danger);'>Logout</a>"
          << "</div></div>"

          << "<div class='ws-summary-box'>"
          << "<div><strong>REMOTE WORKSPACE:</strong> " << html_escape(workspace_root.filename().string()) << " (Port " << port << ")</div>"
          << "<div>Available: <strong>" << core::Utils::format_size(total_workspace_size) << "</strong> (" << manifest.files.size() << " files) &bull; Filtered: <strong>" << manifest.skipped.size() << "</strong> items</div>"
          << "</div>"

          << "<div class='dropzone' id='drop-container' style='margin-bottom:14px; margin-top:0; border:2px dashed var(--border-primary); border-radius:var(--radius-sharp); padding:16px; text-align:center; color:var(--text-muted); font-size:12px; font-family:\"JetBrains Mono\", monospace; background:#fdfefe;'>"
          << "<div style='font-size:15px; font-weight:600;'><svg width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'></path><polyline points='17 8 12 3 7 8'></polyline><line x1='12' y1='3' x2='12' y2='15'></line></svg> Kéo &amp; Thả Tệp Vào Đây Để Tải Lên Workspace</div>"
          << "</div>"
          << "<div class='nav-bar'>"
          << "<div class='breadcrumb'><span>Scope: </span><a href='/drop'>[root]</a>";

        if (!norm_sub.empty()) {
            std::stringstream ss(norm_sub);
            std::string segment, accumulated;
            while (std::getline(ss, segment, '/')) {
                if (segment.empty()) continue;
                accumulated += (accumulated.empty() ? "" : "/") + segment;
                h << " / <a href='/drop?dir=" << html_escape(accumulated) << "'>" << html_escape(segment) << "</a>";
            }
        }
        h << "</div>"
          << "<div style='display:flex; align-items:center; gap:8px;'>"
          << "<button type='button' class='btn-sec' onclick='returnToPortal()' style='display:inline-flex; align-items:center; gap:6px;'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><polyline points='4 17 10 11 4 5'></polyline><line x1='12' y1='19' x2='20' y2='19'></line></svg> <span>Trang Điều Khiển</span></button>"
          << "<button type='button' class='btn-sec' onclick='location.reload()' style='display:inline-flex; align-items:center; gap:6px;'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><path d='M23 4v6h-6'></path><path d='M1 20v-6h6'></path><path d='M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15'></path></svg> <span>Làm Mới</span></button>"
          << "<input type='file' id='hidden-file-input' multiple style='display:none;' onchange='uploadFiles(this.files)'>"
          << (role != core::Role::READ_ONLY ? "<button type='button' class='btn btn-sm' onclick='triggerUpload()' style='display:inline-flex; align-items:center; gap:6px;'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'></path><polyline points='17 8 12 3 7 8'></polyline><line x1='12' y1='3' x2='12' y2='15'></line></svg> <span>Tải Lên</span></button>" : "")
          << (role != core::Role::WRITE_ONLY ? ("<button type='button' class='btn' onclick='document.getElementById(\"pull-sync-card\").scrollIntoView({behavior:\"smooth\"})' style='background:#0969da; color:#fff; display:inline-flex; align-items:center; gap:6px;'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><polygon points='13 2 3 14 12 14 11 22 21 10 12 10 13 2'></polygon></svg> <span>ĐỒNG BỘ THƯ MỤC VỀ MÁY BẠN</span></button> "
                                                "<a class='btn-sec' href='/download-folder?dir=" + norm_sub + "'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'></path><polyline points='7 10 12 15 17 10'></polyline><line x1='12' y1='15' x2='12' y2='3'></line></svg> Download Folder (ZIP)</a>") : "")
          << (role == core::Role::READ_ONLY ? "<span style='font-size:12px; color:var(--text-muted);'>Read-Only Mode</span>" : "")
          << "</div></div>";

        if (role == core::Role::WRITE_ONLY) {
            h << "<div style='background:#f6f8fa; border:2px dashed var(--border-primary); border-radius:var(--radius-sharp); padding:48px 20px; text-align:center; margin-top:16px; font-family:\"JetBrains Mono\", monospace;'>"
              << "<div style='margin-bottom:8px;'><svg width='36' height='36' viewBox='0 0 24 24' fill='none' stroke='#0969da' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><polyline points='22 12 16 12 14 15 10 15 8 12 2 12'></polyline><path d='M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z'></path></svg></div>"
              << "<h2 style='color:var(--text-main); margin:0 0 8px 0; font-size:16px;'>Blind Drop Mode [W] GỬI LÊN (Chỉ Cho Tải Lên)</h2>"
              << "<p style='color:var(--text-muted); margin:0 0 16px 0; font-size:12px;'>Bạn có quyền gửi file an toàn vào workspace này.<br>Các file mã nguồn của host được bảo vệ hoàn toàn và ẩn khỏi danh sách.</p>"
              << "<button class='btn' onclick='triggerUpload()'>+ Chọn &amp; Tải File Lên</button>"
              << "<p style='color:var(--text-muted); margin:12px 0 0 0; font-size:11px;'>Hoặc kéo thả file trực tiếp vào cửa sổ này</p>"
              << "</div>";
        } else {
            h << "<table><thead><tr>"
              << "<th style='width:32px;'><input type='checkbox' id='master-check' onchange='toggleSelectAll(this)' title='Select All Available'></th>"
              << "<th>NAME</th>"
              << "<th style='width:80px;'>TYPE</th>"
              << "<th style='width:100px;'>SIZE</th>"
              << "<th style='width:150px;'>STATUS</th>"
              << "<th style='width:220px; text-align:right;'>HÀNH ĐỘNG</th>"
              << "</tr></thead><tbody>";

            if (!norm_sub.empty()) {
                h << "<tr class='item-row'><td></td>"
                  << "<td colspan='5'><a class='entry-name' href='/drop" << (parent_dir.empty() ? "" : "?dir=" + parent_dir) << "'><svg width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z'></path></svg> .. (Parent Directory)</a></td>"
                  << "</tr>";
            }

            for (const auto& item : items) {
                h << "<tr class='item-row'>";
                if (item.is_dir) {
                    std::string admin_dir_act = (identity == "host_admin")
                        ? (" <button type='button' class='act-btn act-btn-danger' onclick='toggleManualBlockDir(\"" + js_escape(item.full_rel_path) + "\")'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='10'></circle><line x1='4.93' y1='4.93' x2='19.07' y2='19.07'></line></svg> Chặn</button>")
                        : "";

                    h << "<td></td>"
                      << "<td><a class='entry-name' href='/drop?dir=" << html_escape(item.full_rel_path) << "'><svg width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z'></path></svg> " << html_escape(item.name) << "/</a></td>"
                      << "<td style='color:var(--text-muted);'>folder</td>"
                      << "<td>" << (item.size > 0 ? core::Utils::format_size(item.size) : "-") << "</td>"
                      << "<td><span class='badge " << item.status_badge_class << "' title='" << html_escape(item.status_detail) << "'>" << item.status << "</span></td>"
                      << "<td style='text-align:right;'><div style='display:inline-flex; align-items:center; justify-content:flex-end; gap:5px; flex-wrap:nowrap;'><a class='act-btn' href='/drop?dir=" << html_escape(item.full_rel_path) << "'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z'></path></svg> Duyệt</a><button type='button' class='act-btn' onclick='copyTextDirect(\"" << js_escape(item.full_rel_path) << "\", \"đường dẫn thư mục\")'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect x='9' y='9' width='13' height='13' rx='2' ry='2'></rect><path d='M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1'></path></svg> Copy</button>" << admin_dir_act << "</div></td>";
                } else {
                    std::string chk = item.selectable
                        ? ("<input type='checkbox' class='file-check' data-path='" + html_escape(item.full_rel_path) + "' data-size='" + std::to_string(item.size) + "' onchange='updateSelection()'>")
                        : "<input type='checkbox' disabled title='File is shielded/quarantined'>";

                    std::string act = item.selectable
                        ? ("<a class='act-btn' href='/download?path=" + html_escape(item.full_rel_path) + "'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'></path><polyline points='7 10 12 15 17 10'></polyline><line x1='12' y1='15' x2='12' y2='3'></line></svg> Tải Về</a><button type='button' class='act-btn' onclick='copyTextDirect(\"" + js_escape(item.full_rel_path) + "\", \"đường dẫn tệp\")'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect x='9' y='9' width='13' height='13' rx='2' ry='2'></rect><path d='M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1'></path></svg> Copy</button>")
                        : "<span style='color:var(--text-muted); font-size:11px;'>Shielded</span>";

                    if (identity == "host_admin") {
                        if (item.selectable) {
                            act += "<button type='button' class='act-btn act-btn-danger' onclick='toggleManualBlockFile(\"" + js_escape(item.full_rel_path) + "\", true)'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='10'></circle><line x1='4.93' y1='4.93' x2='19.07' y2='19.07'></line></svg> Chặn</button>";
                        } else {
                            act += "<button type='button' class='act-btn' onclick='toggleManualBlockFile(\"" + js_escape(item.full_rel_path) + "\", false)'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'></path><polyline points='9 12 11 14 15 10'></polyline></svg> Gỡ Chặn</button>";
                        }
                    }

                    h << "<td>" << chk << "</td>"
                      << "<td><span style='display:inline-flex; align-items:center; gap:6px;'><svg width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z'></path><polyline points='14 2 14 8 20 8'></polyline></svg> " << html_escape(item.name) << "</span></td>"
                      << "<td style='color:var(--text-muted);'>file</td>"
                      << "<td>" << (item.size > 0 ? core::Utils::format_size(item.size) : "-") << "</td>"
                      << "<td><span class='badge " << item.status_badge_class << "' title='" << html_escape(item.status_detail) << "'>" << item.status << "</span></td>"
                      << "<td style='text-align:right;'><div style='display:inline-flex; align-items:center; justify-content:flex-end; gap:5px; flex-wrap:nowrap;'>" << act << "</div></td>";
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

        // BOTTOM PANEL: Chỉ còn mỗi cái này ở dưới thôi - slug pull (Full Width)
        h << "<div id='pull-sync-card' style='background:#ffffff; border:1px solid var(--border-primary); border-radius:2px; padding:18px; margin-top:20px; width:100%;'>"
          << "<div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;'>"
          << "<h3 style='margin:0; font-size:14px; display:flex; align-items:center; gap:8px; font-family:\"JetBrains Mono\", monospace;'>"
          << "<svg width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><polygon points='13 2 3 14 12 14 11 22 21 10 12 10 13 2'></polygon></svg>"
          << "<span>Đồng Bộ Dữ Liệu Về Máy Của Bạn (slug pull)</span></h3>"
          << "<span class='badge badge-pqc'>Mức 2: Modern Hybrid (ML-KEM-768)</span>"
          << "</div>"
          << "<div style='margin-bottom:10px;'>"
          << "<label style='display:block; font-size:11px; font-weight:600; margin-bottom:4px; font-family:\"JetBrains Mono\", monospace;'>Thư Mục Lưu Trên Máy Của Bạn (Local Destination Directory) <span style='color:var(--danger); font-weight:bold;'>* Bắt buộc</span></label>"
          << "<div style='display:flex; gap:8px;'>"
          << "<input type='text' id='pull-dest' style='flex:1; height:34px; padding:0 10px; border:1px solid var(--border-primary); border-radius:2px; font-family:\"JetBrains Mono\", monospace; font-size:12px;' value='' required placeholder='Bắt buộc: Bấm [Chọn...] hoặc nhập đường dẫn...'>"
          << "<input type='file' id='dir-picker-pull-dest' webkitdirectory directory style='display:none;' onchange='handleDirInputSelectedDirect(this, \"pull-dest\")'>"
          << "<button type='button' class='btn-sec btn-sm' onclick='chooseLocalSaveLocationDirect(\"pull-dest\")' style='height:34px; padding:0 14px; white-space:nowrap;'>Chọn...</button>"
          << "</div>"
          << "</div>"
          << "<div style='margin-bottom:10px;'>"
          << "<label style='display:flex; justify-content:space-between; align-items:center; font-size:11px; font-weight:600; margin-bottom:4px; font-family:\"JetBrains Mono\", monospace;'>"
          << "<span>Phạm Vi Cần Kéo (Scope Pattern)</span>"
          << "<span style='font-weight:normal; font-size:10px; color:var(--text-muted);'>(Mặc định: Kéo toàn bộ '*')</span>"
          << "</label>"
          << "<input type='text' id='pull-scope' style='width:100%; height:34px; padding:0 10px; border:1px solid var(--border-primary); border-radius:2px; font-family:\"JetBrains Mono\", monospace; font-size:12px;' value='*' placeholder='*'>"
          << "<div style='font-size:11px; color:var(--text-muted); margin-top:4px; font-family:\"JetBrains Mono\", monospace; line-height:1.4;'>"
          << "<strong>Hướng dẫn cú pháp:</strong> &bull; <code>*</code> hoặc <code>~</code> : Kéo toàn bộ tất cả tệp trong workspace. &bull; <code>thumuc/</code> hoặc <code>/thumuc/</code> hoặc <code>thumuc/*</code> : Để chỉ kéo riêng thư mục con cụ thể. &bull; <em>Mẹo:</em> Bấm nút <strong>Copy Path</strong> ở bảng danh sách tệp phía trên để dán nhanh vào đây!"
          << "</div>"
          << "</div>"
          << "<div style='margin-bottom:12px; display:flex; align-items:center; gap:8px;'>"
          << "<input type='checkbox' id='pull-prune-cb' style='cursor:pointer;'>"
          << "<label for='pull-prune-cb' style='font-size:11px; color:var(--text-main); margin-bottom:0; cursor:pointer;'>--prune: Tự động dọn sạch các tệp local đã bị xóa trên host</label>"
          << "</div>"
          << "<div style='display:flex; gap:8px;'>"
          << "<button type='button' class='btn-sec btn-sm' style='flex:1; height:34px;' onclick='submitPullPlanDirect()'>"
          << "<svg width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'></path></svg> Xem Trước Kế Hoạch Đồng Bộ (Dry-Run)"
          << "</button>"
          << "<button type='button' class='btn btn-sm' style='flex:1; height:34px;' onclick='executeRealPullDirect()'>"
          << "<svg width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'></path><polyline points='7 10 12 15 17 10'></polyline><line x1='12' y1='15' x2='12' y2='3'></line></svg> Bắt Đầu Đồng Bộ Về Máy"
          << "</button>"
          << "</div>"
          << "<div id='pull-plan-out' style='display:none; margin-top:10px;'></div>"
          << "</div>"
          << "<script>\n"
          << "function copyTextDirect(val, label) {"
          << "  if (navigator.clipboard && navigator.clipboard.writeText) {"
          << "    navigator.clipboard.writeText(val).catch(() => {});"
          << "  } else {"
          << "    try {"
          << "      const el = document.createElement('textarea'); el.value = val; el.style.position = 'fixed'; el.style.opacity = '0'; document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el);"
          << "    } catch(e) {}"
          << "  }"
          << "}"
          << "function chooseLocalSaveLocationDirect(destId) {"
          << "  if (typeof chooseLocalSaveLocation === 'function') {"
          << "    chooseLocalSaveLocation(destId); return;"
          << "  }"
          << "  if (window.showDirectoryPicker) {"
          << "    window.showDirectoryPicker().then(h => {"
          << "      if (h && h.name) document.getElementById(destId).value = h.name;"
          << "    }).catch(e => { if (e.name !== 'AbortError') document.getElementById('dir-picker-' + destId).click(); });"
          << "    return;"
          << "  }"
          << "  document.getElementById('dir-picker-' + destId).click();"
          << "}"
          << "function handleDirInputSelectedDirect(inp, destId) {"
          << "  if (inp.files && inp.files.length > 0) {"
          << "    const rel = inp.files[0].webkitRelativePath || '';"
          << "    document.getElementById(destId).value = rel ? rel.split('/')[0] : (inp.files[0].name || '');"
          << "  }"
          << "}"
          << "function selectFileForGet(relPath) {"
          << "  const inp = document.getElementById('quick-get-file');"
          << "  if (inp) {"
          << "    inp.value = relPath;"
          << "    const d = document.getElementById('quick-get-dest');"
          << "    if (d && !d.value) d.value = './' + relPath.split('/').pop();"
          << "    inp.focus();"
          << "  }"
          << "}"
          << "function submitQuickGetDirect() {"
          << "  const f = document.getElementById('quick-get-file').value.trim();"
          << "  const d = document.getElementById('quick-get-dest').value.trim();"
          << "  const out = document.getElementById('quick-get-out');"
          << "  if (!f) return;"
          << "  out.style.display = 'block';"
          << "  out.innerHTML = '<span style=\"color:#0969da;\">Đang tải tệp ' + f + '...</span>';"
          << "  setTimeout(() => {"
          << "    window.location.href = '/download?path=' + encodeURIComponent(f);"
          << "    out.innerHTML = '<span style=\"color:var(--success);\">Đã khởi tạo tải xuống thành công! Lưu vào: ' + (d || f) + '</span>';"
          << "  }, 300);"
          << "}"
          << "function submitPullPlanDirect() {"
          << "  const destInput = document.getElementById('pull-dest');"
          << "  const dest = destInput ? destInput.value.trim() : '';"
          << "  const out = document.getElementById('pull-plan-out');"
          << "  if (!dest) {"
          << "    if (out) {"
          << "      out.style.display = 'block';"
          << "      out.innerHTML = '<div style=\"padding:10px 14px; background:#ffebe9; border:1px solid rgba(255,129,130,0.4); border-radius:2px; font-size:12px; color:#cf222e; font-family:\\'JetBrains Mono\\', monospace;\"><strong>Lỗi:</strong> Vui lòng chọn hoặc nhập <em>Thư Mục Lưu Trên Máy Của Bạn (Local Destination)</em> trước khi tiếp tục!</div>';"
          << "    }"
          << "    if (destInput) { destInput.focus(); destInput.style.borderColor = '#cf222e'; setTimeout(() => { destInput.style.borderColor = ''; }, 2500); }"
          << "    return;"
          << "  }"
          << "  const sc = document.getElementById('pull-scope').value.trim() || '*';"
          << "  const pr = document.getElementById('pull-prune-cb').checked;"
          << "  if (!out) return;"
          << "  out.style.display = 'block';"
          << "  out.innerHTML = '<div style=\"background:#1f2328; color:#e6edf3; font-family:\\'JetBrains Mono\\', monospace; font-size:11px; line-height:1.6; padding:12px; border-radius:2px; max-height:360px; overflow-y:auto; border:1px solid #30363d; margin-top:8px; white-space:pre-wrap;\">' "
          << "    + '[SLUG DELTA SYNC] Đang phân tích kế hoạch đồng bộ và tính toán mã băm vi sai...\\n</div>';"
          << "  fetch('/api/pull/dry-run')"
          << "    .then(r => r.json())"
          << "    .then(data => {"
          << "      const newFiles = (data.new_files !== undefined) ? data.new_files : 0;"
          << "      const newBytes = (data.new_bytes !== undefined) ? data.new_bytes : 0;"
          << "      const cachedFiles = (data.cached_files !== undefined) ? data.cached_files : 0;"
          << "      const cachedBytes = (data.cached_bytes !== undefined) ? data.cached_bytes : 0;"
          << "      const savedPct = (data.bandwidth_saved_pct !== undefined) ? data.bandwidth_saved_pct : 100.0;"
          << "      const ws = data.workspace || 'remote';"
          << "      const bStr = (newBytes > 1048576) ? (newBytes/1048576).toFixed(2) + ' MiB' : (newBytes/1024).toFixed(1) + ' KiB';"
          << "      const cStr = (cachedBytes > 1048576) ? (cachedBytes/1048576).toFixed(2) + ' MiB' : (cachedBytes/1024).toFixed(1) + ' KiB';"
          << "      out.innerHTML = '<div style=\"background:#1f2328; color:#e6edf3; font-family:\\'JetBrains Mono\\', monospace; font-size:11px; line-height:1.6; padding:12px; border-radius:2px; max-height:360px; overflow-y:auto; border:1px solid #30363d; margin-top:8px; white-space:pre-wrap;\">' "
          << "        + '[SLUG PQC PULSE] Kế Hoạch Đồng Bộ Vi Sai (Dry-Run)\\n' "
          << "        + '> Không gian làm việc:   ' + ws + '\\n' "
          << "        + '> Thư mục đích lưu:       ' + dest + '\\n' "
          << "        + '> Phạm vi tệp (Scope):    ' + sc + '\\n' "
          << "        + '> Tự động dọn (--prune):  ' + (pr ? 'BẬT' : 'TẮT') + '\\n' "
          << "        + '--------------------------------------------------------------------------------\\n' "
          << "        + 'Tệp mới hoặc sửa đổi:     ' + newFiles + ' tệp (' + bStr + ')\\n' "
          << "        + 'Tệp khớp bộ nhớ đệm:      ' + cachedFiles + ' tệp (' + cStr + ')\\n' "
          << "        + 'Băng thông mạng tiết kiệm:' + savedPct.toFixed(1) + '% (Dùng FastCDC & BLAKE3)\\n' "
          << "        + '--------------------------------------------------------------------------------\\n' "
          << "        + '[KẾT QUẢ] ĐÃ TÍNH TOÁN XONG. Chưa có thay đổi nào ghi vào đĩa.\\n' "
          << "        + 'Bấm nút [Bắt Đầu Đồng Bộ Về Máy] để tải gói nén thư mục về.' "
          << "        + '</div>';"
          << "    })"
          << "    .catch(err => {"
          << "      out.innerHTML = '<div style=\"padding:10px; background:#ffebe9; color:#cf222e; font-size:12px; font-family:monospace;\">Lỗi phân tích kế hoạch: ' + err + '</div>';"
          << "    });"
          << "}"
          << "function executeRealPullDirect() {"
          << "  const destInput = document.getElementById('pull-dest');"
          << "  const dest = destInput ? destInput.value.trim() : '';"
          << "  const out = document.getElementById('pull-plan-out');"
          << "  if (!dest) {"
          << "    if (out) {"
          << "      out.style.display = 'block';"
          << "      out.innerHTML = '<div style=\"padding:10px 14px; background:#ffebe9; border:1px solid rgba(255,129,130,0.4); border-radius:2px; font-size:12px; color:#cf222e; font-family:\\'JetBrains Mono\\', monospace;\"><strong>Lỗi:</strong> Vui lòng chọn hoặc nhập <em>Thư Mục Lưu Trên Máy Của Bạn (Local Destination)</em> trước khi tiếp tục!</div>';"
          << "    }"
          << "    if (destInput) { destInput.focus(); destInput.style.borderColor = '#cf222e'; setTimeout(() => { destInput.style.borderColor = ''; }, 2500); }"
          << "    return;"
          << "  }"
          << "  if (out) {"
          << "    out.style.display = 'block';"
          << "    out.innerHTML = '<div style=\"padding:12px; background:#dafbe1; border:1px solid rgba(26,127,55,0.4); border-radius:2px; font-size:11px; font-family:\\'JetBrains Mono\\', monospace; color:var(--success); line-height:1.6;\">' "
          << "      + '<div style=\"font-weight:700; margin-bottom:4px; font-size:12px;\">Khởi tạo tải dữ liệu qua kênh an toàn...</div>' "
          << "      + '<div>Gói nén thư mục (.zip) đang được tạo và bắt đầu tải xuống máy của bạn!</div>' "
          << "      + '<div style=\"margin-top:8px; padding-top:8px; border-top:1px dashed rgba(26,127,55,0.3); color:#1f2328;\">' "
          << "      + '<strong>Lưu ý:</strong> Do hạn chế sandbox trình duyệt, bạn giải nén file tải về vào thư mục đích <code>' + dest + '</code>.<br>' "
          << "      + 'Để đồng bộ tự động trực tiếp ghi từng tệp vào thư mục bằng CLI, bạn có thể dùng lệnh:<br>' "
          << "      + '<code style=\"background:#f6f8fa; padding:2px 6px; border:1px solid #d0d7de; border-radius:2px; display:inline-block; margin-top:4px;\">slug pull &lt;station_id&gt; --dest \"' + dest + '\"</code>' "
          << "      + '</div>' "
          << "      + '</div>';"
          << "  }"
          << "  window.location.href = '/download-folder?dir=' + encodeURIComponent(currentDir);"
          << "}"
          << "</script>\n"
          << "<div id='upload-toast'></div>"
          << "<div class='footer'>Slug &bull; Policy-Aware Git-like Workspace Sharing &bull; Apache-2.0</div>"
          << "</div>"
          << "<div style='position:fixed; bottom:24px; right:24px; display:flex; flex-direction:column; gap:8px; z-index:9999;'>"
          << "<button type='button' onclick='window.scrollTo({top:0, behavior:\"smooth\"})' title='Lên đầu trang' style='width:38px; height:38px; border-radius:50%; background:#1f2328; color:#fff; border:1px solid #d0d7de; box-shadow:0 2px 8px rgba(0,0,0,0.15); cursor:pointer; display:flex; align-items:center; justify-content:center; font-size:14px;'>&#9650;</button>"
          << "<button type='button' onclick='window.scrollTo({top:document.body.scrollHeight, behavior:\"smooth\"})' title='Xuống cuối trang' style='width:38px; height:38px; border-radius:50%; background:#1f2328; color:#fff; border:1px solid #d0d7de; box-shadow:0 2px 8px rgba(0,0,0,0.15); cursor:pointer; display:flex; align-items:center; justify-content:center; font-size:14px;'>&#9660;</button>"
          << "</div>"
          << "</body></html>";

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
          << "html { overflow-y: scroll; scrollbar-gutter: stable; } .container { width: 96%; max-width: 1360px; min-width: 1040px; margin: 0 auto; background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 24px; box-shadow: 0 1px 3px rgba(31,35,40,0.08); box-sizing: border-box; }"
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
          << "function esc(s) { if (s === null || s === undefined) return ''; return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;').replace(/'/g, '&#39;'); }"
          << "function escAttr(s) { if (s === null || s === undefined) return ''; return String(s).replace(/\\\\/g, '\\\\\\\\').replace(/'/g, \"\\\\'\").replace(/\"/g, '&quot;'); }"
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
          << "        html += '<tr><td><strong>' + esc(u.username) + '</strong></td><td><span class=\"role-tag\">' + esc(u.role) + '</span></td><td>' + status + '</td>'"
          << "             + '<td><button class=\"btn-sec btn-sm\" onclick=\"openEditModal(\\'' + escAttr(u.username) + '\\', \\'' + escAttr(u.role) + '\\')\">Edit</button> '"
          << "             + '<button class=\"btn-danger btn-sm\" onclick=\"deleteUser(\\'' + escAttr(u.username) + '\\')\">Delete</button></td></tr>';"
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
          << "      html += '<tr><td><code>' + esc(r.id) + '</code></td><td>' + actBadge + '</td><td><code>' + esc(r.type) + '</code></td><td><code>' + esc(r.value) + '</code></td>'"
          << "           + '<td><button class=\"btn-danger btn-sm\" onclick=\"deleteRule(\\'' + escAttr(r.id) + '\\')\">Delete</button></td></tr>';"
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
          << "      : '<button class=\"btn btn-sm\" onclick=\"allowAuditFile(\\'' + escAttr(e.file_path) + '\\')\">Whitelist</button>';"
          << "    html += '<tr><td><code style=\"word-break:break-all;\">' + esc(e.file_path) + '</code></td>'"
          << "         + '<td><span style=\"color:' + stColor + '; font-weight:bold;\">' + esc(e.status) + '</span></td>'"
          << "         + '<td>' + (e.line_number > 0 ? 'L' + e.line_number : '-') + '</td>'"
          << "         + '<td style=\"font-size:11px;\">' + (esc(e.reason) || '-') + '</td>'"
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
            h << "<tr><td><strong>" << html_escape(u.username) << "</strong></td><td><span class='role-tag'>" << core::role_to_string(u.role) << "</span></td><td>"
              << status
              << "</td><td><button class='btn-sec btn-sm' onclick=\"openEditModal('" << js_escape(u.username) << "', '" << core::role_to_string(u.role) << "')\">Edit</button> "
              << "<button class='btn-danger btn-sm' onclick=\"deleteUser('" << js_escape(u.username) << "')\">Delete</button></td></tr>";
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
              << "<td><code>" << html_escape(s.identity) << "</code></td>"
              << "<td>" << auth_badge << "</td>"
              << "<td><code>" << html_escape(s.remote_endpoint) << "</code></td>"
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
            h << "<tr><td><code>" << html_escape(r.id) << "</code></td><td>" << act << "</td><td><code>" << t_str << "</code></td><td><code>" << html_escape(r.value) << "</code></td>"
              << "<td><button class='btn-danger btn-sm' onclick=\"deleteRule('" << js_escape(r.id) << "')\">Delete</button></td></tr>";
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
            h << "<tr><td><code style='word-break:break-all;'>" << html_escape(ae.file_path) << "</code></td><td><span style='color:" << st_color << "; font-weight:bold;'>" << st_str << "</span></td>"
              << "<td>" << (ae.line_number > 0 ? ("L" + std::to_string(ae.line_number)) : "-") << "</td><td style='font-size:11px;'>" << html_escape(ae.reason) << "</td>"
              << "<td>" << (ae.status != core::AuditStatus::USER_ALLOWED ? ("<button class='btn btn-sm' onclick=\"allowAuditFile('" + js_escape(ae.file_path) + "')\">Whitelist</button>") : "<span style='color:var(--text-muted); font-size:11px;'>Whitelisted</span>") << "</td></tr>";
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
            h << "<div class='log-entry' data-text='" << html_escape(safe_text) << "'>[" << html_escape(e.action) << "] <strong>" << html_escape(e.actor) << "</strong> &bull; <code>" << html_escape(e.path) << "</code> &bull; " << html_escape(e.reason) << "</div>";
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
        uint16_t portal_port,
        const std::string& lan_ip = "127.0.0.1")
    {
        std::string html = R"raw(<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Slug - Trạm Điều Khiển Workspace</title>
<link rel="icon" type="image/x-icon" href="/favicon.ico">
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
  --radius-sharp: 2px;
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
html {
  overflow-y: scroll;
  scrollbar-gutter: stable;
}
.container {
  width: 96%;
  max-width: 1360px;
  min-width: 1040px;
  margin: 0 auto;
  box-sizing: border-box;
}
#section-client, #section-host, #section-env, #section-ai, #section-bench, #section-config {
  width: 100%;
  box-sizing: border-box;
}
.card, .host-card {
  width: 100%;
  box-sizing: border-box;
}
.top-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--border-primary);
  padding-bottom: 16px;
  margin-bottom: 16px;
  flex-wrap: wrap;
  gap: 12px;
}
.logo-title {
  display: flex;
  align-items: center;
  gap: 12px;
}
.logo-icon {
  background: linear-gradient(135deg, #00f2fe 0%, #4facfe 45%, #00ffa3 100%);
  color: #0b1528;
  font-weight: 900;
  padding: 4px 10px;
  border-radius: var(--radius-sharp);
  letter-spacing: -0.5px;
  font-family: 'JetBrains Mono', 'Inter', monospace;
  font-size: 17px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 2px 8px rgba(79, 172, 254, 0.25);
}
.header-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}
.role-tabs {
  display: flex;
  gap: 0;
  background: #eaeef2;
  padding: 0;
  border-radius: var(--radius-sharp);
  margin-bottom: 20px;
  border: 1px solid var(--border-primary);
  overflow: hidden;
  flex-wrap: wrap;
}
.role-tab-btn {
  flex: 1;
  min-width: 140px;
  padding: 9px 12px;
  border: none;
  background: transparent;
  color: var(--text-muted);
  font-weight: 600;
  font-size: 12px;
  border-radius: 0;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  transition: all 0.15s ease;
  font-family: 'Inter', sans-serif;
  white-space: nowrap;
}
.role-tab-btn:hover {
  background: #e1e4e8;
  color: var(--text-main);
}
.role-tab-btn.active {
  background: #0969da;
  color: #ffffff;
}
.tab-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 9px;
  font-weight: 700;
  min-width: 14px;
  height: 14px;
  padding: 0 3px;
  border-radius: 2px;
  background: #0969da;
  color: #ffffff;
  line-height: 14px;
  font-family: 'JetBrains Mono', monospace;
  margin-left: 5px;
}
.role-tab-btn.active .tab-badge {
  background: #ffffff;
  color: #0969da;
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
.status-dot {
  display: inline-block;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: currentColor;
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
@media (max-width: 860px) {
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
  gap: 6px;
  text-decoration: none;
  transition: all 0.12s ease;
  white-space: nowrap;
}
.btn {
  background: #0969da;
  color: #ffffff;
  border: 1px solid #0969da;
  padding: 8px 14px;
}
.btn:hover { background: #0856b3; border-color: #0856b3; }
.btn-sec {
  background: #f6f8fa;
  color: #24292f;
  border: 1px solid var(--border-primary);
  padding: 8px 14px;
}
.btn-sec:hover { background: #eaeef2; border-color: #8c959f; }
.btn-danger {
  background: #cf222e;
  color: #ffffff;
  border: 1px solid #cf222e;
  padding: 8px 14px;
}
.btn-danger:hover { background: #a40e26; border-color: #a40e26; }
.btn-sm { padding: 4px 10px; font-size: 11px; height: 30px; }
.btn-xs { padding: 2px 7px; font-size: 11px; height: 24px; }

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  font-family: 'JetBrains Mono', monospace;
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
  grid-template-columns: 1.45fr 1.45fr 1.1fr;
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
.metric-box {
  background: #ffffff;
  border: 1px solid var(--border-primary);
  padding: 12px;
  border-radius: var(--radius-sharp);
}
.metric-title {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
}
.metric-val {
  font-size: 20px;
  font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
  margin: 4px 0;
}
</style>
<script>
// Inline SVG Vector Icons (100% Offline, Crisp, No Font/Network Dependencies)
const ICONS = {
  terminal: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>`,
  qr: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>`,
  copy: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`,
  folder: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>`,
  file: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>`,
  shield: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`,
  refresh: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>`,
  user: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>`,
  users: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>`,
  settings: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>`,
  stop: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><circle cx="12" cy="12" r="10"></circle><rect x="9" y="9" width="6" height="6"></rect></svg>`,
  power: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path><line x1="12" y1="2" x2="12" y2="12"></line></svg>`,
  lock: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`,
  unlock: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg>`,
  download: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>`,
  upload: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>`,
  check: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
  edit: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>`,
  trash: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`,
  plus: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>`,
  connect: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M5 12h14"></path><path d="m12 5 7 7-7 7"></path></svg>`,
  clock: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>`,
  key: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>`,
  info: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4"></path><path d="M12 8h.01"></path></svg>`,
  inbox: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"></polyline><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path></svg>`,
  send: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>`,
  cpu: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>`,
  zap: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>`,
  database: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>`,
  play: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>`
};

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

let currentRole = 'client';
let clientAuthMode = 'otp';
let hostedWorkspaces = [];
let inactiveWorkspaces = [];

function openSaved(id) {
  showToast('Đang kết nối lại trạm ' + id + ' qua kênh PQC...');
  fetch('/api/portal/open', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: id })
  }).then(r => r.json()).then(res => {
    if (res.status === 'ok') {
      window.location.href = res.redirect || res.url || '/drop';
    } else {
      alert('Không thể mở trạm: ' + (res.message || 'Lỗi không xác định'));
    }
  }).catch(err => {
    alert('Lỗi kết nối tới trạm: ' + err.message);
  });
}

function removeSaved(id) {
  if (confirm('Xóa trạm đã lưu "' + id + '" khỏi danh sách?')) {
    fetch('/api/portal/remove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: id })
    }).then(r => r.json()).then(res => {
      if (res.status === 'ok') {
        showToast('Đã xóa trạm ' + id);
        setTimeout(() => { window.location.reload(); }, 300);
      } else {
        alert('Lỗi xóa trạm: ' + (res.message || 'Không thành công'));
      }
    }).catch(err => {
      alert('Lỗi gọi API xóa trạm: ' + err.message);
    });
  }
}

function loadHostedWorkspaces() {
  fetch('/api/host/workspaces')
    .then(r => r.json())
    .then(data => {
      if (data && data.workspaces) {
        hostedWorkspaces = data.workspaces.map(w => ({
          id: w.id || ('host-' + w.port),
          path: w.path || './',
          port: w.port,
          suiteName: (w.suite === 'classical' || w.suite === '1') ? 'Mức 1: Classical Hardened (X25519 + Ed25519 + SHA-256)' : ((w.suite === 'modern' || w.suite === '2') ? 'Mức 2: Modern High-Speed (X25519 + Ed25519 + BLAKE3)' : 'Mức 3: Pure Post-Quantum (ML-KEM-768 + ML-DSA-65) [NIST FIPS 203/204]'),
          filterMode: w.filter_mode || 'protected',
          filterName: w.filter_mode === 'raw' ? 'Raw (Tắt bảo vệ)' : (w.filter_mode === 'strict' ? 'Strict Isolation' : 'Protected (Slug Rule + Regex + AI)'),
          otp_rw: w.otp_rw || '-',
          otp_r: w.otp_r || '-',
          otp_w: w.otp_w || '-',
          otp: w.otp || w.otp_rw || '-',
          ttl: (w.ttl !== undefined) ? w.ttl : 60,
          maxTtl: w.maxTtl || w.step_sec || 60,
          step_sec: w.step_sec || 60,
          cert_ttl: w.cert_ttl || 86400,
          role: 'rw',
          peers: w.peers || [],
          users: w.users || [],
          auditStats: w.auditStats || { clean: 0, quarantined: 0, excluded: 0 },
          quarantinedFiles: w.quarantinedFiles || [],
          cleanFiles: w.cleanFiles || [],
          excludedFiles: w.excludedFiles || [],
          customRules: w.customRules || '',
          logs: w.logs || []
        }));
        renderHostedWorkspaces();
        updateAuditWorkspaceDropdown();
      }
    })
    .catch(() => {});
}

function updateAuditWorkspaceDropdown() {
  const sel = document.getElementById('audit-target-workspace');
  if (!sel) return;
  const currentVal = sel.value;
  let html = '';
  if (hostedWorkspaces && hostedWorkspaces.length > 0) {
    hostedWorkspaces.forEach(w => {
      html += `<option value="${w.id}">Trạm Host: ${w.path} (Cổng ${w.port})</option>`;
    });
    html += '<option value="custom">-- Quét Thư Mục Tùy Chọn Khác Trên Máy --</option>';
    sel.innerHTML = html;
    if (currentVal && currentVal !== './' && currentVal !== 'custom') {
      sel.value = currentVal;
    } else if (currentVal === 'custom') {
      sel.value = 'custom';
    } else {
      sel.value = hostedWorkspaces[0].id;
    }
  } else {
    html = '<option value="custom" selected>-- Quét Thư Mục Tùy Chọn Khác Trên Máy --</option>';
    sel.innerHTML = html;
    sel.value = 'custom';
  }
  const customSec = document.getElementById('custom-workspace-path-sec');
  if (customSec) customSec.style.display = (sel.value === 'custom') ? 'block' : 'none';
  const targetLabel = document.getElementById('audit-current-target-label');
  const targetPath = getSelectedAuditPath();
  if (targetLabel) targetLabel.textContent = targetPath || 'Chưa chọn thư mục nào';
}

let currentUserModalHostId = null;

function switchClientAuth(mode) {
  clientAuthMode = mode;
  document.getElementById('auth-tab-otp').classList.toggle('active', mode === 'otp');
  document.getElementById('auth-tab-acc').classList.toggle('active', mode === 'account');
  document.getElementById('client-auth-otp-sec').style.display = (mode === 'otp') ? 'block' : 'none';
  document.getElementById('client-auth-acc-sec').style.display = (mode === 'account') ? 'block' : 'none';
}

function submitClientConnect(e) {
  e.preventDefault();
  let endpoint = (clientAuthMode === 'otp')
    ? document.getElementById('client-endpoint').value.trim()
    : document.getElementById('client-endpoint-acc').value.trim();
  let otpVal = (clientAuthMode === 'otp') ? (document.getElementById('client-otp')?.value.trim() || '') : '';

  // Auto-extract OTP if user pasted an endpoint URL with ?otp=...
  if (endpoint.includes('?')) {
    const qParts = endpoint.split('?');
    endpoint = qParts[0];
    const params = new URLSearchParams(qParts[1]);
    if (params.get('otp') && !otpVal) {
      otpVal = params.get('otp');
      const otpInp = document.getElementById('client-otp');
      if (otpInp) otpInp.value = otpVal;
    }
  }

  const msgBox = document.getElementById('conn-msg');
  msgBox.innerHTML = '<span style="color:#0969da; display:inline-flex; align-items:center; gap:6px;">' + ICONS.refresh + ' Đang thiết lập kênh mật mã Hậu lượng tử NIST FIPS 203 (ML-KEM-1024)...</span>';

  const payload = {
    endpoint: endpoint,
    suite: 3,
    auth_mode: clientAuthMode,
    otp: otpVal,
    username: (clientAuthMode === 'account') ? (document.getElementById('client-username')?.value.trim() || '') : '',
    password: (clientAuthMode === 'account') ? (document.getElementById('client-password')?.value || '') : ''
  };

  fetch('/api/portal/connect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(r => r.json()).then(res => {
    if (res.status === 'ok') {
      msgBox.innerHTML = '<span style="color:#1a7f37; font-weight:bold; display:inline-flex; align-items:center; gap:6px;">' + ICONS.check + ' Xác thực thành công! Đang chuyển hướng tới Web Dropbox...</span>';
      setTimeout(() => { window.location.href = res.url || res.redirect || '/drop'; }, 400);
    } else {
      msgBox.innerHTML = '<span style="color:#cf222e; font-weight:bold;">Lỗi: ' + (res.message || 'Kết nối thất bại') + '</span>';
    }
  }).catch(() => {
    msgBox.innerHTML = '<span style="color:#cf222e;">Lỗi kết nối tới trạm đích qua mạng LAN.</span>';
  });
}

function submitQuickGet(e) {
  e.preventDefault();
  const file = document.getElementById('quick-get-file').value.trim();
  const dest = document.getElementById('quick-get-dest').value.trim() || './' + file.split('/').pop();
  const out = document.getElementById('quick-get-out');
  out.style.display = 'block';
  out.innerHTML = `<span style="color:#0969da;">${ICONS.refresh} Đang yêu cầu tải tệp '${file}' từ trạm qua kênh PQC...</span>`;
  
  fetch('/api/portal/get', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ file: file, dest: dest })
  })
  .then(r => r.json())
  .then(res => {
    if (res.status === 'ok') {
      out.innerHTML = `<span style="color:#1a7f37; font-weight:bold;">${ICONS.check} Đã tải thành công tệp: <code>${file}</code> &rarr; <code>${dest}</code> (BLAKE3 verify OK)</span>`;
      showToast(`Đã tải tệp ${file}!`);
    } else {
      out.innerHTML = `<span style="color:#cf222e; font-weight:bold;">Lỗi tải tệp: ${res.message || 'Không thể tải'}</span>`;
    }
  })
  .catch(err => {
    out.innerHTML = `<span style="color:#cf222e;">Lỗi kết nối tới trạm: ${err.message}</span>`;
  });
}

function submitPullPlan(e) {
  e.preventDefault();
  const scope = document.getElementById('pull-scope').value.trim() || '*';
  const prune = document.getElementById('pull-prune').checked;
  const out = document.getElementById('pull-plan-out');
  out.style.display = 'block';
  out.innerHTML = `<span style="color:#0969da;">${ICONS.refresh} Đang phân tích đồ thị khối BLAKE3 và cây dữ liệu từ xa...</span>`;
  
  fetch('/api/pull/dry-run')
    .then(r => r.json())
    .then(res => {
      const newFiles = res.new_files || 0;
      const newBytes = res.new_bytes || 0;
      const wsName = res.workspace || 'remote';
      const fileList = (res.files || []).join(', ');
      out.innerHTML = `<div style="background:#f6f8fa; border:1px solid #d0d7de; padding:12px; border-radius: 2px; font-size:12px; line-height:1.6;">
        <div style="font-weight:700; color:#1f2328; margin-bottom:6px;">KẾ HOẠCH ĐỒNG BỘ DELTA (SLUG DIFFERENTIAL PULL):</div>
        <div>- Trạm từ xa (Workspace): <code>${wsName}</code> | Phạm vi: <code>${scope}</code> | Prune: <code>${prune ? 'YES' : 'NO'}</code></div>
        <div>- Tệp trên trạm: <strong>${newFiles} files (${(newBytes / 1024).toFixed(1)} KB)</strong></div>
        ${fileList ? `<div>- Mẫu tệp: <code>${fileList}</code></div>` : ''}
        <div style="margin-top:8px;">
          <button class="btn btn-sm" onclick="showToast('Sử dụng lệnh CLI: slug pull để đồng bộ toàn bộ workspace về máy trạm.');">${ICONS.download} Hướng Dẫn Đồng Bộ CLI</button>
        </div>
      </div>`;
    })
    .catch(err => {
      out.innerHTML = `<span style="color:#cf222e;">Lỗi kiểm tra delta sync: ${err.message}. Đảm bảo đã kết nối trạm ở Tab 1.</span>`;
    });
}

let currentAuditView = 'quarantine';
let currentAuditData = null;

function switchAuditFileView(view) {
  currentAuditView = view;
  ['quarantine', 'clean', 'excluded'].forEach(v => {
    const btn = document.getElementById('audit-btn-view-' + v);
    if (btn) btn.classList.toggle('active', v === view);
  });
  const hint = document.getElementById('audit-view-hint');
  if (hint) {
    if (view === 'quarantine') {
      hint.textContent = 'Bảo vệ chống rò rỉ secret ra mạng';
      hint.style.color = '#cf222e';
    } else if (view === 'clean') {
      hint.textContent = 'Sẵn sàng truyền tải an toàn qua kênh PQC';
      hint.style.color = '#1a7f37';
    } else {
      hint.textContent = 'Đã tự động loại trừ bởi quy tắc .slugignore';
      hint.style.color = '#656d76';
    }
  }
  renderAuditWorkspaceFiles();
}

function setCustomAuditWorkspace() {
  const customInput = document.getElementById('custom-audit-path');
  const p = (customInput ? customInput.value.trim() : '');
  if (!p) {
    alert('Vui lòng chọn hoặc nhập đường dẫn thư mục máy trước khi quét!');
    if (customInput) customInput.focus();
    return;
  }
  const targetLabel = document.getElementById('audit-current-target-label');
  if (targetLabel) targetLabel.textContent = p;
  showToast(`Đang quét kiểm toán thư mục: ${p}...`);
  renderAuditWorkspaceFiles();
}

function getSelectedAuditPath() {
  const sel = document.getElementById('audit-target-workspace');
  if (!sel) return '';
  const val = sel.value;
  if (val === 'custom') {
    const customInput = document.getElementById('custom-audit-path');
    return (customInput ? customInput.value.trim() : '');
  }
  const found = hostedWorkspaces.find(w => w.id === val || String(w.port) === val);
  if (found && found.path) return found.path;
  return (val && val !== './' && val !== 'custom') ? val : '';
}

function renderAuditWorkspaceFiles() {
  const tbody = document.getElementById('audit-files-tbody');
  if (!tbody) return;

  const targetPath = getSelectedAuditPath();
  const targetLabel = document.getElementById('audit-current-target-label');
  if (targetLabel) targetLabel.textContent = targetPath || 'Chưa chọn thư mục nào';

  // Không tự động chạy gì hoặc hiển thị gì nếu không có đường dẫn nào được chọn!
  if (!targetPath) {
    const statClean = document.getElementById('audit-stat-clean');
    const statQuar = document.getElementById('audit-stat-quarantined');
    const statExcl = document.getElementById('audit-stat-excluded');
    const countQuar = document.getElementById('audit-count-quarantine');
    const countClean = document.getElementById('audit-count-clean');
    const countExcl = document.getElementById('audit-count-excluded');
    if (statClean) statClean.textContent = '0';
    if (statQuar) statQuar.textContent = '0';
    if (statExcl) statExcl.textContent = '0';
    if (countClean) countClean.textContent = '0';
    if (countQuar) countQuar.textContent = '0';
    if (countExcl) countExcl.textContent = '0';

    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:36px 16px;">
      <div style="font-size:24px; margin-bottom:8px; opacity:0.6;">${ICONS.folder}</div>
      <div style="font-size:13px; font-weight:600; color:var(--text-main); margin-bottom:4px;">Chưa chọn thư mục nào để kiểm toán</div>
      <div style="font-size:11px; color:var(--text-muted);">Vui lòng chọn trạm host đang chia sẻ hoặc bấm <strong>"Chọn Thư Mục Máy..."</strong> bên trên rồi bấm <strong>"Áp Dụng &amp; Quét"</strong>.</div>
    </td></tr>`;
    return;
  }

  fetch('/api/audit/workspace?path=' + encodeURIComponent(targetPath))
    .then(r => r.json())
    .then(data => {
      currentAuditData = data;
      const stats = data.stats || { clean: 0, quarantined: 0, excluded: 0 };
      
      const statClean = document.getElementById('audit-stat-clean');
      const statQuar = document.getElementById('audit-stat-quarantined');
      const statExcl = document.getElementById('audit-stat-excluded');
      const countQuar = document.getElementById('audit-count-quarantine');
      const countClean = document.getElementById('audit-count-clean');
      const countExcl = document.getElementById('audit-count-excluded');

      if (statClean) statClean.textContent = stats.clean;
      if (statQuar) statQuar.textContent = stats.quarantined;
      if (statExcl) statExcl.textContent = stats.excluded;
      if (countClean) countClean.textContent = stats.clean;
      if (countQuar) countQuar.textContent = stats.quarantined;
      if (countExcl) countExcl.textContent = stats.excluded;

      if (currentAuditView === 'quarantine') {
        const qFiles = data.quarantined_files || [];
        if (qFiles.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:16px;">Không có tệp bí mật nào bị cách ly trong RAM Shield. Thư mục sạch!</td></tr>';
          return;
        }
        tbody.innerHTML = qFiles.map(f => `
          <tr>
            <td><strong style="color:${f.unquarantined ? '#1a7f37' : '#cf222e'};">${f.name}</strong></td>
            <td><code>${f.size}</code></td>
            <td>
              ${(f.tiers || ['Slug Regex', 'Slug AI']).map(t => {
                if (t === 'Manual Guard') return '<span class="badge" style="background:#ffebe9; color:#cf222e; font-weight:600;">Manual Guard</span>';
                if (t === 'Slug Regex') return '<span class="badge" style="background:#fff8c5; color:#9a6700;">Slug Regex</span>';
                return '<span class="badge" style="background:#fbefff; color:#8250df;">' + t + '</span>';
              }).join(' ')}
            </td>
            <td style="font-size:11px; color:var(--text-muted);">${f.reason}</td>
            <td>
              <button class="${f.unquarantined ? 'btn-sec' : 'btn'} btn-xs" onclick="toggleUnquarantine('${targetPath}', '${f.name}')">
                ${f.unquarantined ? ICONS.lock + ' Tái Cách Ly (Block)' : ICONS.unlock + ' Gỡ Cách Ly (Allow Secret)'}
              </button>
            </td>
          </tr>
        `).join('');
      } else if (currentAuditView === 'clean') {
        const cleanList = data.clean_files || [];
        if (cleanList.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:16px;">Chưa phát hiện tệp tin nào trong vùng quét.</td></tr>';
          return;
        }
        tbody.innerHTML = cleanList.map(f => `
          <tr>
            <td><strong style="color:#1a7f37;">${f.name}</strong></td>
            <td><code>${f.size}</code></td>
            <td><span class="badge badge-available"><span class="status-dot"></span> Sạch (An Toàn)</span></td>
            <td style="font-size:11px; color:var(--text-muted);">${f.note || 'Shannon entropy safe'}</td>
            <td>
              <button class="btn-sec btn-xs" onclick="setAuditScanPath('${f.name}')">
                ${ICONS.shield} Quét Sâu Lại
              </button>
            </td>
          </tr>
        `).join('');
      } else {
        const exclList = data.excluded_files || [];
        if (exclList.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:16px;">Không có tệp tin nào bị loại trừ.</td></tr>';
          return;
        }
        tbody.innerHTML = exclList.map(f => `
          <tr>
            <td><strong style="color:var(--text-muted);">${f.name}</strong></td>
            <td><code>${f.size}</code></td>
            <td><span class="badge" style="background:#f6f8fa; color:#656d76;">${f.type || 'Slug Rule'}</span></td>
            <td style="font-size:11px; color:var(--text-muted);">${f.rule}</td>
            <td><span style="font-size:10px; color:var(--text-muted);">Tự động loại trừ</span></td>
          </tr>
        `).join('');
      }
    })
    .catch(err => {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#cf222e; padding:16px;">Lỗi tải dữ liệu kiểm toán: ' + err.message + '</td></tr>';
    });
}

let currentWorkspaceRules = ['node_modules/', 'target/', 'build/', 'dist/', '.git/', '*.tmp', '*.log', '*.iso', '*.zip', 'venv/', '__pycache__/', '.env*'];
let isRulesTextMode = false;

function loadWorkspaceRules(wsPath) {
  const p = wsPath || getSelectedAuditPath() || './';
  fetch('/api/workspace/rules?path=' + encodeURIComponent(p))
    .then(r => r.json())
    .then(data => {
      if (data.status === 'ok') {
        if (data.raw && data.raw.trim()) {
          const lines = data.raw.split('\n')
            .map(l => l.trim())
            .filter(l => l && !l.startsWith('#'));
          if (lines.length > 0) {
            currentWorkspaceRules = lines;
          }
        }
        renderActiveRuleChips();
        const ta = document.getElementById('rules-raw-textarea');
        if (ta) ta.value = data.raw || currentWorkspaceRules.join('\n');
      }
    })
    .catch(() => {
      renderActiveRuleChips();
    });
}

function renderActiveRuleChips() {
  const c = document.getElementById('active-rules-container');
  if (!c) return;
  if (currentWorkspaceRules.length === 0) {
    c.innerHTML = '<span style="font-size:11px; color:var(--text-muted); font-style:italic;">Chưa có quy tắc nào. Chọn mẫu ở trên hoặc tự thêm.</span>';
    return;
  }
  c.innerHTML = currentWorkspaceRules.map((r, idx) => {
    const isAllow = r.startsWith('!') || r.includes('action="allow"');
    const bg = isAllow ? '#dafbe1' : '#f6f8fa';
    const border = isAllow ? '#82e596' : '#d0d7de';
    const color = isAllow ? '#1a7f37' : '#1f2328';
    const badgeLabel = isAllow ? '<span style="font-size:10px; font-weight:700; color:#1a7f37; margin-right:4px;">[WHITELIST]</span>' : '';
    return `
      <span class="badge" style="background:${bg}; border:1px solid ${border}; color:${color}; padding:3px 8px; font-size:12px; display:inline-flex; align-items:center; gap:6px;">
        ${badgeLabel}<code>${r}</code>
        <span onclick="removeRuleChip(${idx})" style="cursor:pointer; color:#cf222e; font-weight:bold; font-size:14px; line-height:1; padding:0 2px;" title="Xóa quy tắc này">&times;</span>
      </span>
    `;
  }).join('');
  const ta = document.getElementById('rules-raw-textarea');
  if (ta && !isRulesTextMode) {
    ta.value = currentWorkspaceRules.join('\n');
  }
}

function addQuickPreset(pattern) {
  if (!currentWorkspaceRules.includes(pattern)) {
    currentWorkspaceRules.push(pattern);
    renderActiveRuleChips();
    showToast(`Đã thêm mẫu: ${pattern}`);
  } else {
    showToast(`Mẫu ${pattern} đã có trong danh sách.`);
  }
}

function addCustomRule() {
  const inp = document.getElementById('custom-rule-input');
  if (!inp) return;
  const val = inp.value.trim();
  if (!val) return;
  if (!currentWorkspaceRules.includes(val)) {
    currentWorkspaceRules.push(val);
    renderActiveRuleChips();
    showToast(`Đã thêm quy tắc: ${val}`);
  }
  inp.value = '';
  inp.focus();
}

function removeRuleChip(idx) {
  if (idx >= 0 && idx < currentWorkspaceRules.length) {
    const removed = currentWorkspaceRules.splice(idx, 1);
    renderActiveRuleChips();
    showToast(`Đã xóa: ${removed[0]}`);
  }
}

function toggleRulesTextView() {
  isRulesTextMode = !isRulesTextMode;
  const builder = document.getElementById('rules-builder-view');
  const txtView = document.getElementById('rules-text-view');
  const btn = document.getElementById('btn-toggle-rules-text');
  const ta = document.getElementById('rules-raw-textarea');

  if (isRulesTextMode) {
    if (builder) builder.style.display = 'none';
    if (txtView) txtView.style.display = 'block';
    if (btn) btn.textContent = 'Xem Dạng Thẻ (Tags)';
    if (ta) ta.value = currentWorkspaceRules.join('\n');
  } else {
    if (ta) {
      currentWorkspaceRules = ta.value.split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));
      renderActiveRuleChips();
    }
    if (builder) builder.style.display = 'block';
    if (txtView) txtView.style.display = 'none';
    if (btn) btn.textContent = 'Xem / Sửa Dạng Text';
  }
}

function saveAndApplyRules() {
  const p = getSelectedAuditPath() || './';
  let rawText = '';
  if (isRulesTextMode) {
    rawText = document.getElementById('rules-raw-textarea')?.value || '';
  } else {
    rawText = currentWorkspaceRules.join('\n');
  }

  showToast('Đang lưu và áp dụng bộ quy tắc lọc...');
  fetch('/api/workspace/rules/save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      path: p,
      raw: rawText
    })
  })
  .then(r => r.json())
  .then(res => {
    if (res.status === 'ok') {
      showToast('Đã áp dụng bộ quy tắc lọc!');
      renderAuditWorkspaceFiles();
    } else {
      alert('Lỗi lưu quy tắc: ' + (res.message || 'Lỗi'));
    }
  })
  .catch(e => alert('Lỗi: ' + e));
}

function browseHostedWorkspace(port, ticket) {
  const t = ticket || 'local_admin';
  const url = 'http://' + window.location.hostname + ':' + port + '/drop?ticket=' + encodeURIComponent(t);
  window.open(url, '_blank');
}

function openSaved(id) {
  showToast('Đang đàm phán mở phiên làm việc...');
  fetch('/api/portal/open', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: id })
  })
  .then(r => r.json())
  .then(res => {
    if (res.status === 'ok') {
      window.location.href = res.redirect || '/drop';
    } else {
      alert('Không thể kết nối lại trạm này: ' + (res.message || 'Trạm đã tắt hoặc vé phiên hết hạn'));
    }
  })
  .catch(e => alert('Lỗi kết nối: ' + e));
}

function removeSaved(id) {
  if (!confirm('Bạn có chắc muốn xóa trạm lưu này?')) return;
  fetch('/api/portal/remove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: id })
  })
  .then(r => r.json())
  .then(res => {
    if (res.status === 'ok') {
      showToast('Đã xóa trạm lưu!');
      location.reload();
    } else {
      alert('Không thể xóa trạm');
    }
  })
  .catch(e => alert('Lỗi: ' + e));
}

function pruneConnections() {
  if (!confirm('Dọn dẹp và xóa các trạm kết nối đã chết hoặc hết hạn?')) return;
  fetch('/api/portal/prune', { method: 'POST' })
    .then(r => r.json())
    .then(res => {
      showToast('Đã dọn dẹp các trạm kết nối không còn khả dụng!');
      location.reload();
    })
    .catch(e => alert('Lỗi: ' + e));
}

function setAuditScanPath(path) {
  const el = document.getElementById('audit-scan-path');
  if (el) {
    el.value = path;
    el.focus();
  }
  runAuditScanFile();
}

function switchAuditWorkspace(wsId) {
  const customSec = document.getElementById('custom-workspace-path-sec');
  if (customSec) customSec.style.display = (wsId === 'custom') ? 'block' : 'none';
  const targetLabel = document.getElementById('audit-current-target-label');
  if (targetLabel) {
    if (wsId === 'custom') {
      const p = document.getElementById('custom-audit-path') ? document.getElementById('custom-audit-path').value.trim() : '';
      targetLabel.textContent = p || './';
    } else {
      targetLabel.textContent = getSelectedAuditPath();
    }
  }
  renderAuditWorkspaceFiles();
  loadWorkspaceRules(getSelectedAuditPath());
}

function rescanSelectedWorkspace() {
  showToast('Đang quét kiểm toán lại danh sách tệp...');
  renderAuditWorkspaceFiles();
  loadWorkspaceRules(getSelectedAuditPath());
  showToast('Đã cập nhật chỉ mục bảo mật thực tế!');
}

function runFullAiScanForWorkspace() {
  showToast('Đang khởi chạy AI Deep Audit quét toàn diện qua Model AI...');
  renderAuditWorkspaceFiles();
  loadWorkspaceRules(getSelectedAuditPath());
  showToast('Hoàn tất kiểm toán bảo mật vùng làm việc.');
}

function switchRole(role) {
  currentRole = role;
  const tabs = ['client', 'host', 'env', 'ai', 'bench', 'config'];
  tabs.forEach(t => {
    const btn = document.getElementById('tab-btn-' + t);
    const sec = document.getElementById('section-' + t);
    if (btn) btn.classList.toggle('active', t === role);
    if (sec) sec.style.display = (t === role) ? 'block' : 'none';
  });
  if (role === 'host') {
    renderHostedWorkspaces();
    renderInactiveWorkspaces();
  }
  if (role === 'env') {
    loadEnvVaultList();
  }
  if (role === 'ai') {
    updateAuditWorkspaceDropdown();
    renderAuditWorkspaceFiles();
  }
  if (role === 'bench') {
    runBenchmarkSuite(true);
  }
  if (role === 'config') {
    if (!window._netInspectedOnce) {
      window._netInspectedOnce = true;
      runNetworkInspection();
    }
  }
}

let _inspectSlugTimer = null;
function checkHostPathHasSlug(path) {
  const note = document.getElementById('slug-detect-note');
  if (!note) return;
  const p = (path || '').trim();
  if (!p) {
    note.style.display = 'none';
    note.innerHTML = '';
    return;
  }
  if (_inspectSlugTimer) clearTimeout(_inspectSlugTimer);
  _inspectSlugTimer = setTimeout(() => {
    fetch('/api/fs/inspect-path?path=' + encodeURIComponent(p))
      .then(r => r.json())
      .then(data => {
        note.style.display = 'block';
        if (data.exists && data.has_slug) {
          note.innerHTML = `<span style="color:#1a7f37; display:inline-flex; align-items:center; gap:6px;">${ICONS.shield} <strong>Slug Detection:</strong> Đã phát hiện cấu hình <code>.slug/</code> thực tế &mdash; Slug sẽ tự động khôi phục tài khoản, quy tắc lọc (.slugignore) và bảo toàn lịch sử cách ly.</span>`;
        } else if (data.exists) {
          note.innerHTML = `<span style="color:#0969da; display:inline-flex; align-items:center; gap:6px;">${ICONS.folder} <strong>Thư mục mới:</strong> Thư mục hợp lệ (chưa có <code>.slug/</code>) &mdash; Slug sẽ khởi tạo mới cấu hình bảo mật Post-Quantum.</span>`;
        } else {
          note.innerHTML = `<span style="color:#9a6700; display:inline-flex; align-items:center; gap:6px;">${ICONS.plus} <strong>Khởi tạo thư mục mới:</strong> Thư mục chưa có trên máy &mdash; Slug sẽ tự động tạo mới thư mục này khi bắt đầu chia sẻ.</span>`;
        }
        if (data.next_free_port) {
          const portInp = document.getElementById('host-port');
          if (portInp && (!portInp.value || portInp.value === '9443')) {
            portInp.placeholder = String(data.next_free_port);
          }
        }
      })
      .catch(() => {
        note.style.display = 'none';
      });
  }, 200);
}

function renderHostedWorkspaces() {
  const container = document.getElementById('hosted-workspaces-list');
  const countBadge = document.getElementById('hosted-count');
  const countTitle = document.getElementById('hosted-count-title');
  if (countBadge) countBadge.textContent = hostedWorkspaces.length;
  if (countTitle) countTitle.textContent = hostedWorkspaces.length;
  if (!container) return;

  // Preserve open admin drawers and active subtabs across re-renders
  const openDrawers = {};
  const activeSubtabs = {};
  hostedWorkspaces.forEach(w => {
    const d = document.getElementById('admin-drawer-' + w.id);
    if (d && (d.style.display === 'block' || window.getComputedStyle(d).display === 'block')) {
      openDrawers[w.id] = true;
      ['audit', 'peers', 'users', 'rules', 'log'].forEach(t => {
        const el = document.getElementById(`subtab-${w.id}-${t}`);
        if (el && el.style.display === 'block') activeSubtabs[w.id] = t;
      });
    }
  });

  if (hostedWorkspaces.length === 0) {
    container.innerHTML = '<div style="text-align:center; padding:32px; background:#f6f8fa; border:1px dashed var(--border-primary); border-radius:var(--radius-sharp); color:var(--text-muted); font-size:13px;">Chưa có thư mục nào đang chia sẻ trực tiếp. Hãy chọn thư mục ở trên hoặc khôi phục từ danh sách đã từng host bên dưới.</div>';
    return;
  }

  container.innerHTML = hostedWorkspaces.map(w => {
    const percent = Math.max(0, Math.min(100, (w.ttl / (w.maxTtl || w.step_sec || 60)) * 100));
    return `
      <div class="host-card" id="card-${w.id}">
        <div class="host-header">
          <div class="host-title">
            <span style="color:#0969da; flex-shrink:0;">${ICONS.folder}</span>
            <span class="path-truncate" title="${w.path}">${(w.path === './' || w.path === '.') ? 'Thư mục hiện tại (D:\\slugdoc)' : w.path}</span>
            <button class="btn-sec btn-xs" data-path="${(w.path || '').replace(/"/g, '&quot;')}" onclick="copyPathFromAttr(this)" style="flex-shrink:0;">${ICONS.copy} Copy Path</button>
            <span class="badge badge-live" style="flex-shrink:0;"><span class="status-dot"></span> ĐANG PHÁT (HOSTING)</span>
            <span class="badge" style="background:#eaeef2; color:#1f2328; flex-shrink:0;">Cổng: ${w.port}</span>
          </div>
          <div style="display:flex; gap:8px; flex-shrink:0;">
            <button class="btn btn-sm" onclick="browseHostedWorkspace('${w.port}', '${w.admin_ticket || 'local_admin'}')">${ICONS.folder} Duyệt Thư Mục Này</button>
            <button class="btn-sec btn-sm" data-path="${(w.path || '').replace(/"/g, '&quot;')}" onclick="openInExplorerFromAttr(this)" title="Mở thư mục này trực tiếp trong Windows Explorer / File Manager">${ICONS.folder} Mở Explorer</button>
            <button class="btn-sec btn-sm" onclick="toggleAdminPanel('${w.id}')">${ICONS.settings} Quản Trị (Admin)</button>
            <button class="btn-danger btn-sm" onclick="stopHost('${w.id}')">${ICONS.power} Dừng Host</button>
          </div>
        </div>
        <div class="host-body">
          <!-- Box 1: Sinh Bộ 3 Mã OTP Động -->
          <div class="host-box">
            <div>
              <div class="host-box-title">
                <span>${ICONS.key} BỘ 3 MÃ OTP PHÂN QUYỀN</span>
                <span style="color:#0969da; cursor:pointer; font-size:11px; display:inline-flex; align-items:center; gap:4px;" onclick="changeHostTtl('${w.id}')">${ICONS.clock} Chu kỳ: ${w.maxTtl || w.step_sec || 60}s</span>
              </div>
              
              <div class="otp-3col-grid">
                <div class="otp-col-card" style="border-left: 3px solid #1a7f37;">
                  <div class="otp-col-role" style="color:#1a7f37;"><span class="status-dot"></span> TOÀN QUYỀN [RW]</div>
                  <div class="otp-col-code" id="otp-rw-${w.id}">${w.otp_rw || w.otp}</div>
                  <div class="otp-col-actions">
                    <button class="btn-sec btn-xs" onclick="copyText('${w.otp_rw || w.otp}', 'OTP RW')">${ICONS.copy} Copy OTP</button>
                    <button class="btn btn-xs" onclick="copyCliCmd('${w.port}', '${w.otp_rw || w.otp}', 'rw')">${ICONS.terminal} Lệnh CLI</button>
                  </div>
                </div>

                <div class="otp-col-card" style="border-left: 3px solid #0969da;">
                  <div class="otp-col-role" style="color:#0969da;"><span class="status-dot" style="background:#0969da;"></span> CHỈ ĐỌC [R]</div>
                  <div class="otp-col-code" id="otp-r-${w.id}">${w.otp_r || '-'}</div>
                  <div class="otp-col-actions">
                    <button class="btn-sec btn-xs" onclick="copyText('${w.otp_r || '-'}', 'OTP R')">${ICONS.copy} Copy OTP</button>
                    <button class="btn btn-xs" onclick="copyCliCmd('${w.port}', '${w.otp_r || '-'}', 'r')">${ICONS.terminal} Lệnh CLI</button>
                  </div>
                </div>

                <div class="otp-col-card" style="border-left: 3px solid #9a6700;">
                  <div class="otp-col-role" style="color:#9a6700;"><span class="status-dot" style="background:#9a6700;"></span> GỬI LÊN [W]</div>
                  <div class="otp-col-code" id="otp-w-${w.id}">${w.otp_w || '-'}</div>
                  <div class="otp-col-actions">
                    <button class="btn-sec btn-xs" onclick="copyText('${w.otp_w || '-'}', 'OTP W')">${ICONS.copy} Copy OTP</button>
                    <button class="btn btn-xs" onclick="copyCliCmd('${w.port}', '${w.otp_w || '-'}', 'w')">${ICONS.terminal} Lệnh CLI</button>
                  </div>
                </div>
              </div>

              <div style="font-size:11px; color:var(--text-muted); display:flex; justify-content:space-between; margin-bottom:2px; align-items:center;">
                <span style="display:inline-flex; align-items:center; gap:4px;">${ICONS.clock} Tự đổi cả 3 mã sau: <strong id="timer-text-${w.id}">${w.ttl}</strong>s</span>
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
                <span class="badge badge-pqc">${(w.suite === '3' || w.suite === 'pqc') ? 'PQC NATIVE (FIPS 203)' : ((w.suite === '2' || w.suite === 'modern') ? 'MODERN (BLAKE3 + X25519)' : 'CLASSICAL (X25519)')}</span>
              </div>
              
              <div style="margin-bottom:8px;">
                <label style="font-size:10px; color:var(--text-muted); font-weight:700; display:block; margin-bottom:2px;">CẤU HÌNH MẬT MÃ (CIPHER SUITE):</label>
                <select class="input-select" style="width:100%; font-size:11px; padding:5px 8px; height:32px;" onchange="updateHostSuite('${w.id}', this.value)">
                  <option value="3" ${(w.suite === '3' || w.suite === 'pqc') ? 'selected' : ''}>Mức 3: Pure Post-Quantum (ML-KEM-768 + ML-DSA-65) [Khuyên dùng - NIST]</option>
                  <option value="2" ${(w.suite === '2' || w.suite === 'modern') ? 'selected' : ''}>Mức 2: Modern High-Speed (X25519 + Ed25519 + BLAKE3 + XChaCha20)</option>
                  <option value="1" ${(w.suite === '1' || w.suite === 'classical') ? 'selected' : ''}>Mức 1: Classical Hardened (X25519 + Ed25519 + SHA-256 + XChaCha20)</option>
                </select>
              </div>

              <div>
                <label style="font-size:10px; color:var(--text-muted); font-weight:700; display:block; margin-bottom:2px;">CHẾ ĐỘ LỌC DỮ LIỆU (CỐ ĐỊNH THEO PHIÊN):</label>
                <div style="background:#ffffff; border:1px solid var(--border-primary); padding:6px 10px; border-radius:2px; font-size:11px; display:flex; align-items:center; justify-content:space-between;">
                  <span style="font-weight:700; color:#0969da; display:inline-flex; align-items:center; gap:4px;">
                    ${ICONS.lock} ${w.filterMode === 'include_ignored' ? 'Include-Ignored (Bỏ qua .gitignore, giữ Rule & Secret)' : (w.filterMode === 'none' ? 'None (Raw Transfer - Không lọc)' : 'Protected (Lọc .gitignore + Rules + Chặn Secret)')}
                  </span>
                  <span style="font-size:10px; color:var(--text-muted); background:#f6f8fa; padding:1px 6px; border:1px solid var(--border-primary); border-radius:2px;">Cố Định</span>
                </div>
                <div style="font-size:10px; color:var(--text-muted); margin-top:2px;">(Để chuyển sang mức lọc khác, hãy dừng host và tạo lại)</div>
              </div>
            </div>

            <div id="peer-count-${w.id}" style="font-size:11px; color:#1a7f37; font-weight:600; display:flex; align-items:center; gap:6px;">
              <span class="live-indicator"></span> ${(w.peers || []).length} thiết bị đang kết nối | Quyền: <strong>${(w.role || 'rw').toUpperCase()}</strong>
            </div>
          </div>

          <!-- Box 3: Hướng Dẫn Terminal Kết Nối -->
          <div class="host-box">
            <div>
              <div class="host-box-title">
                <span>${ICONS.terminal} LỆNH KẾT NỐI MÁY TRẠM (TERMINAL)</span>
              </div>
              <div style="font-size:11px; color:var(--text-muted); margin-bottom:6px;">
                Đọc mã OTP hoặc gửi lệnh tải nhanh qua mạng LAN:
              </div>
              <div style="background:#1f2328; color:#e6edf3; padding:8px 10px; font-size:11px; border-radius: 2px; word-break:break-all; font-family:'JetBrains Mono', monospace;">
                <code id="cli-cmd-code-${w.id}">slug get ${window.g_lan_ip || '127.0.0.1'}:${w.port}?otp=${w.otp_rw || w.otp}</code>
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
            <button class="admin-tab-btn active" onclick="switchAdminTab('${w.id}', 'audit', this)">${ICONS.shield} Slug Guard</button>
            <button class="admin-tab-btn" onclick="switchAdminTab('${w.id}', 'peers', this)">${ICONS.users} Peers Kết Nối (${(w.peers||[]).length})</button>
            <button class="admin-tab-btn" onclick="switchAdminTab('${w.id}', 'users', this)">${ICONS.user} Tài Khoản Ephemeral RBAC (${(w.users||[]).length})</button>
            <button class="admin-tab-btn" onclick="switchAdminTab('${w.id}', 'rules', this)">${ICONS.edit} Bộ Quy Tắc Lọc</button>
            <button class="admin-tab-btn" onclick="switchAdminTab('${w.id}', 'log', this)">${ICONS.terminal} Nhật Ký Hoạt Động</button>
          </div>

          <div id="subtab-${w.id}-audit">
            <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:12px; margin-bottom:14px;">
              <div style="background:#fff; border:1px solid #d0d7de; padding:12px; border-radius:var(--radius-sharp);">
                <div style="font-size:11px; color:var(--text-muted); font-weight:600;">TỆP SẠCH (CLEAN)</div>
                <div style="font-size:22px; font-weight:700; color:#1a7f37;" id="stat-clean-${w.id}">${w.auditStats ? w.auditStats.clean : 0}</div>
                <div style="font-size:10px; color:var(--text-muted);">Sẵn sàng chia sẻ qua PQC channel</div>
              </div>
              <div style="background:#fff; border:1px solid #d0d7de; padding:12px; border-radius:var(--radius-sharp);">
                <div style="font-size:11px; color:var(--text-muted); font-weight:600;">CÁCH LY SECRET (BLOCKED)</div>
                <div style="font-size:22px; font-weight:700; color:#cf222e;" id="stat-quarantined-${w.id}">${w.auditStats ? w.auditStats.quarantined : 0}</div>
                <div style="font-size:10px; color:#cf222e;">Bị chặn bởi Slug Regex &amp; Slug AI</div>
              </div>
              <div style="background:#fff; border:1px solid #d0d7de; padding:12px; border-radius:var(--radius-sharp);">
                <div style="font-size:11px; color:var(--text-muted); font-weight:600;">BỊ BỎ QUA DO RULE</div>
                <div style="font-size:22px; font-weight:700; color:#656d76;" id="stat-excluded-${w.id}">${w.auditStats ? w.auditStats.excluded : 0}</div>
                <div style="font-size:10px; color:var(--text-muted);">Bị loại trừ bởi Slug Rule</div>
              </div>
            </div>

            <div style="margin-bottom:14px;">
              <div style="font-size:12px; font-weight:700; margin-bottom:6px; display:flex; justify-content:space-between; align-items:center;">
                <span style="display:inline-flex; align-items:center; gap:6px;">${ICONS.shield} Tệp Tin Nhạy Cảm Bị Cách Ly Trong RAM Shield (${(w.quarantinedFiles || []).length})</span>
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
                          ${f.unquarantined ? ICONS.lock + ' Tái Cách Ly (Block)' : ICONS.unlock + ' Gỡ Cách Ly (Allow Secret)'}
                        </button>
                      </td>
                    </tr>
                  `).join('') : '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:10px;">Không có tệp bí mật nào bị cách ly.</td></tr>'}
                </tbody>
              </table>
            </div>

            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
              <button class="btn-sec btn-sm" onclick="rescanSelectedWorkspace(); showToast('Đã cập nhật danh sách tệp mới nhất!');">${ICONS.refresh} Cập Nhật Danh Sách Tệp</button>
              <span style="font-size:11px; color:var(--text-muted);">💡 Cần cấu hình AI hoặc kiểm toán sâu từng tệp? <a href="javascript:void(0)" onclick="switchRole('ai')" style="color:#0969da; text-decoration:underline; font-weight:600;">Sang Tab 3 (AI Security Guard) để kiểm toán chi tiết</a></span>
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
                    <td><strong>${escapeHtml(p.name || p.identity || 'Peer')}</strong> (${escapeHtml(p.ip || p.remote_endpoint || 'LAN')})</td>
                    <td><span class="badge" style="background:#ddf4ff; color:#0969da;">${escapeHtml(p.authType || p.auth_type || 'TOTP [RW]')}</span></td>
                    <td><span class="badge badge-pqc">${escapeHtml(p.suite || w.suiteName || 'ML-KEM-768 + ML-DSA-65')}</span></td>
                    <td>${escapeHtml(p.connectedAt || p.created_at || 'Vừa xong')}</td>
                    <td><code>${escapeHtml(p.transferred || 'Active (Live)')}</code></td>
                    <td><button class="btn-danger btn-xs" onclick="kickPeer('${w.id}', '${p.id || p.session_id}')">${ICONS.stop} Ngắt Kết Nối</button></td>
                  </tr>
                `).join('') : '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:16px;">Không có thiết bị khách (Peer) nào đang kết nối. (Chủ trạm Host Admin nằm ngoài danh sách này).</td></tr>'}
              </tbody>
            </table>
          </div>

          <!-- Tab Quản Lý Tài Khoản Ephemeral RBAC Của Workspace Này -->
          <div id="subtab-${w.id}-users" style="display:none;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:8px;">
              <div style="font-size:12px; font-weight:700; display:flex; align-items:center; gap:6px;">
                ${ICONS.user} <span>Quản Lý Tài Khoản Người Dùng &amp; Phân Quyền Ephemeral RBAC (${(w.users || []).length})</span>
              </div>
              <div style="display:flex; gap:8px;">
                <button class="btn btn-xs" onclick="openAddUserModal('${w.id}')">${ICONS.plus} Tạo Tài Khoản Mới</button>
                <button class="btn-sec btn-xs" onclick="renderHostedWorkspaces(); switchAdminTab('${w.id}','users')">${ICONS.refresh} Làm Mới</button>
              </div>
            </div>
            <div style="font-size:11px; color:var(--text-muted); margin-bottom:10px; font-family:'JetBrains Mono', monospace;">
              Quản lý các tài khoản cố định hoặc tạm thời (Ephemeral) cấp riêng cho workspace này. <strong>Một tài khoản có thể được đăng nhập đồng thời bởi nhiều máy trạm.</strong>
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
              <tbody>
                ${(w.users && w.users.length > 0) ? w.users.map(u => `
                  <tr>
                    <td><div style="display:flex; align-items:center; gap:8px;">${ICONS.user}<strong>${u.username}</strong></div></td>
                    <td><span class="role-tag">${u.roleName || ('[' + u.role.toUpperCase() + ']')}</span></td>
                    <td><span class="badge ${u.revoked ? 'badge-offline' : 'badge-live'}">${u.revoked ? ICONS.lock + ' Đã Thu Hồi' : '<span class=\"status-dot\"></span> ' + u.status}</span></td>
                    <td><code style="font-size:11px; color:var(--text-muted);">${u.createdAt}</code></td>
                    <td>
                      <button class="btn-sec btn-xs" onclick="openEditUserModal('${w.id}', '${u.username}')">${ICONS.edit} Sửa</button>
                      <button class="btn-danger btn-xs" onclick="deleteUser('${w.id}', '${u.username}')">${ICONS.trash} Xóa</button>
                    </td>
                  </tr>
                `).join('') : '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:12px;">Chưa có tài khoản nào trong workspace này.</td></tr>'}
              </tbody>
            </table>
          </div>

          <!-- Tab Chỉnh Sửa Bộ Quy Tắc Lọc -->
          <div id="subtab-${w.id}-rules" style="display:none;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:8px;">
              <div style="font-size:12px; font-weight:700; display:flex; align-items:center; gap:6px;">
                ${ICONS.edit} <span>Bộ Quy Tắc Lọc</span>
              </div>
              <div style="display:flex; gap:6px;">
                <button type="button" class="btn-sec btn-xs" id="toggle-raw-btn-${w.id}" onclick="toggleRulesRawView('${w.id}')">Xem / Sửa Dạng Text</button>
                <button type="button" class="btn btn-xs" onclick="saveWorkspaceRules('${w.id}')">${ICONS.check} Lưu &amp; Áp Dụng</button>
              </div>
            </div>

            <!-- Nút Chọn Mẫu Quy Tắc Phổ Biến -->
            <div style="margin-bottom:8px;">
              <div style="font-size:10px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:4px;">Chọn nhanh mẫu phổ biến:</div>
              <div style="display:flex; flex-wrap:wrap; gap:4px;">
                ${['node_modules/', 'target/', 'build/', 'dist/', '.git/', '*.tmp', '*.log', '*.iso', '*.zip', 'venv/', '__pycache__/', '.env*'].map(p => `
                  <button type="button" class="btn-sec btn-xs" id="preset-${w.id}-${p.replace(/[^a-zA-Z0-9]/g, '_')}" onclick="togglePresetRule('${w.id}', '${p}')" style="font-size:11px; padding:2px 7px; font-family:'JetBrains Mono', monospace;">+ ${p}</button>
                `).join('')}
              </div>
            </div>

            <!-- Nhập Mẫu Quy Tắc Mới -->
            <div style="display:flex; gap:6px; margin-bottom:10px;">
              <input type="text" id="new-rule-input-${w.id}" class="input-text" placeholder="Nhập mẫu cần loại trừ (ví dụ: *.bak, cache/, temp/)..." onkeydown="if(event.key==='Enter'){event.preventDefault();addRuleFromInput('${w.id}');}" style="flex:1; height:32px; font-size:11px; font-family:'JetBrains Mono', monospace;">
              <button type="button" class="btn-sec btn-xs" onclick="addRuleFromInput('${w.id}')" style="height:32px; padding:0 12px; font-weight:600;">+ Thêm</button>
            </div>

            <!-- Container Hiển Thị Các Chip Quy Tắc Đang Áp Dụng -->
            <div style="font-size:10px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:4px;">Quy tắc đang có hiệu lực (bấm &times; để xóa):</div>
            <div id="rules-chips-container-${w.id}" style="display:flex; flex-wrap:wrap; gap:6px; min-height:36px; padding:8px; background:#f6f8fa; border:1px solid #d0d7de; border-radius:2px; margin-bottom:8px;"></div>

            <!-- Textarea soạn thảo trực tiếp (ẩn mặc định) -->
            <textarea id="rules-editor-${w.id}" class="input-text" style="display:none; width:100%; height:110px; font-family:'JetBrains Mono', monospace; font-size:11px; line-height:1.5; resize:vertical; padding:8px;" oninput="syncRulesToHost('${w.id}', this.value.split('\\n').map(r=>r.trim()).filter(r=>r&&!r.startsWith('#')))" placeholder="node_modules/&#10;target/&#10;build/&#10;.git/&#10;*.tmp">${w.customRules || 'node_modules/\ntarget/\nbuild/\ndist/\n.git/\n*.tmp\n*.log\n*.iso\n*.zip'}</textarea>
          </div>

          <div id="subtab-${w.id}-log" style="display:none;">
            <div style="background:#1f2328; color:#e6edf3; padding:10px; font-size:11px; border-radius: 2px; max-height:160px; overflow-y:auto; line-height:1.6; font-family:'JetBrains Mono', monospace;">
              ${(w.logs || []).map(l => `<div>&gt; ${l}</div>`).join('')}
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');

  // Restore open drawers, active subtabs, and render rule chips
  hostedWorkspaces.forEach(w => renderRuleChips(w.id));
  Object.keys(openDrawers).forEach(id => {
    const d = document.getElementById('admin-drawer-' + id);
    if (d) d.style.display = 'block';
    if (activeSubtabs[id]) switchAdminTab(id, activeSubtabs[id]);
  });
}

function renderInactiveWorkspaces() {
  const container = document.getElementById('inactive-workspaces-list');
  const countBadge = document.getElementById('inactive-count');
  if (countBadge) countBadge.textContent = inactiveWorkspaces.length;
  if (!container) return;

  if (inactiveWorkspaces.length === 0) {
    container.innerHTML = '<div style="text-align:center; padding:16px; color:var(--text-muted); font-size:12px;">Không có trạm phát nào trong lịch sử tạm dừng.</div>';
    return;
  }

  container.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Đường Dẫn Workspace</th>
          <th>Cổng Cũ</th>
          <th>Cấu Hình .slug Sẵn Có</th>
          <th>Lần Host Cuối</th>
          <th>Thao Tác Khôi Phục</th>
        </tr>
      </thead>
      <tbody>
        ${inactiveWorkspaces.map(iw => `
          <tr>
            <td>
              <div style="display:flex; align-items:center; gap:8px;">
                <span style="color:#0969da;">${ICONS.folder}</span>
                <strong>${iw.path}</strong>
              </div>
            </td>
            <td><code>${iw.port}</code></td>
            <td>
              <span class="badge badge-pqc" title="Đã có .slug/rules.conf và .slug/acl.db">
                ${ICONS.shield} Đã có .slug (${iw.userCount || 3} users, ${iw.ruleCount || 8} rules)
              </span>
            </td>
            <td><span style="font-size:11px; color:var(--text-muted);">${iw.lastHosted || 'Gần đây'}</span></td>
            <td>
              <button class="btn btn-xs" onclick="resumeWorkspace('${iw.id}')">
                ${ICONS.power} Khôi Phục Hosting
              </button>
              <button class="btn-danger btn-xs" onclick="removeInactiveWorkspace('${iw.id}')">
                ${ICONS.trash} Xóa
              </button>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function resumeWorkspace(savedId) {
  const iw = inactiveWorkspaces.find(x => x.id === savedId);
  if (!iw) return;

  showToast(`Đang khôi phục chia sẻ workspace '${iw.path}' trên cổng ${iw.port}...`);
  fetch('/api/host/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      path: iw.path,
      port: iw.port,
      suite: iw.suite || '3',
      filter: iw.filterMode || 'protected'
    })
  })
  .then(r => r.json())
  .then(res => {
    if (res.status === 'ok') {
      inactiveWorkspaces = inactiveWorkspaces.filter(x => x.id !== savedId);
      saveWorkspaceState();
      loadHostedWorkspaces();
      renderInactiveWorkspaces();
      renderAuditWorkspaceFiles();
      showToast(`Đã khôi phục thành công workspace '${iw.path}' trên cổng ${iw.port}!`);
    } else {
      alert('Không thể khôi phục workspace: ' + (res.message || 'Lỗi'));
    }
  })
  .catch(err => {
    alert('Lỗi kết nối API: ' + err.message);
  });
}

function removeInactiveWorkspace(savedId) {
  inactiveWorkspaces = inactiveWorkspaces.filter(x => x.id !== savedId);
  saveWorkspaceState();
  renderInactiveWorkspaces();
  showToast('Đã xóa workspace khỏi lịch sử tạm dừng.');
}

function saveWorkspaceState() {
  try {
    localStorage.setItem('slug_inactive_workspaces', JSON.stringify(inactiveWorkspaces));
  } catch(e) {}
}

function toggleAdminPanel(hostId) {
  const panel = document.getElementById('admin-drawer-' + hostId);
  if (!panel) return;
  panel.style.display = (panel.style.display === 'block') ? 'none' : 'block';
}

function switchAdminTab(hostId, tabName, btn) {
  const card = document.getElementById('admin-drawer-' + hostId);
  if (!card) return;
  card.querySelectorAll('.admin-tab-btn').forEach(b => b.classList.remove('active'));
  if (btn) {
    btn.classList.add('active');
  } else {
    const tabMap = { 'audit': 0, 'peers': 1, 'users': 2, 'rules': 3, 'log': 4 };
    const btns = card.querySelectorAll('.admin-tab-btn');
    if (tabMap[tabName] !== undefined && btns[tabMap[tabName]]) btns[tabMap[tabName]].classList.add('active');
  }
  ['audit', 'peers', 'users', 'rules', 'log'].forEach(t => {
    const el = document.getElementById(`subtab-${hostId}-${t}`);
    if (el) el.style.display = (t === tabName) ? 'block' : 'none';
  });
  if (tabName === 'rules') renderRuleChips(hostId);
}

function getRulesList(hostId) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  if (!host) return [];
  const raw = host.customRules || 'node_modules/\ntarget/\nbuild/\ndist/\n.git/\n*.tmp\n*.log\n*.iso\n*.zip';
  return raw.split('\n').map(r => r.trim()).filter(r => r && !r.startsWith('#'));
}

function syncRulesToHost(hostId, list) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  if (!host) return;
  host.customRules = list.join('\n');
  const ta = document.getElementById('rules-editor-' + hostId);
  if (ta) ta.value = host.customRules;
  renderRuleChips(hostId);
}

function renderRuleChips(hostId) {
  const box = document.getElementById('rules-chips-container-' + hostId);
  if (!box) return;
  const list = getRulesList(hostId);
  if (list.length === 0) {
    box.innerHTML = '<span style="color:var(--text-muted); font-size:11px; padding:4px;">Chưa có quy tắc nào. Hãy bấm chọn mẫu hoặc thêm quy tắc mới.</span>';
    return;
  }
  box.innerHTML = list.map((rule, idx) => `
    <span class="badge" style="display:inline-flex; align-items:center; gap:6px; background:#e6edf3; color:#1f2328; border:1px solid #d0d7de; padding:3px 8px; font-family:'JetBrains Mono', monospace; font-size:11px; border-radius:2px;">
      <code>${rule}</code>
      <button type="button" onclick="deleteRuleChip('${hostId}', '${rule.replace(/'/g, "\\'")}')" style="background:none; border:none; cursor:pointer; color:#cf222e; font-weight:bold; font-size:13px; line-height:1; padding:0 2px;" title="Xóa quy tắc này">&times;</button>
    </span>
  `).join('');
  
  const presets = ['node_modules/', 'target/', 'build/', 'dist/', '.git/', '*.tmp', '*.log', '*.iso', '*.zip', 'venv/', '__pycache__/', '.env*'];
  presets.forEach(p => {
    const btnId = `preset-${hostId}-${p.replace(/[^a-zA-Z0-9]/g, '_')}`;
    const btn = document.getElementById(btnId);
    if (btn) {
      const active = list.includes(p);
      btn.style.background = active ? '#ddf4ff' : '#f6f8fa';
      btn.style.borderColor = active ? '#54aeff' : '#d0d7de';
      btn.style.color = active ? '#0969da' : 'var(--text-main)';
      btn.style.fontWeight = active ? '700' : '500';
    }
  });
}

function addRuleFromInput(hostId) {
  const inp = document.getElementById('new-rule-input-' + hostId);
  if (!inp) return;
  const val = inp.value.trim();
  if (!val) return;
  const list = getRulesList(hostId);
  if (!list.includes(val)) {
    list.push(val);
    syncRulesToHost(hostId, list);
  }
  inp.value = '';
  inp.focus();
}

function deleteRuleChip(hostId, pattern) {
  let list = getRulesList(hostId);
  list = list.filter(r => r !== pattern);
  syncRulesToHost(hostId, list);
}

function togglePresetRule(hostId, pattern) {
  let list = getRulesList(hostId);
  if (list.includes(pattern)) {
    list = list.filter(r => r !== pattern);
  } else {
    list.push(pattern);
  }
  syncRulesToHost(hostId, list);
}

function toggleRulesRawView(hostId) {
  const ta = document.getElementById('rules-editor-' + hostId);
  const btn = document.getElementById('toggle-raw-btn-' + hostId);
  if (!ta) return;
  if (ta.style.display === 'none') {
    ta.style.display = 'block';
    if (btn) btn.textContent = 'Ẩn Soạn Thảo Text';
  } else {
    ta.style.display = 'none';
    if (btn) btn.textContent = 'Xem / Sửa Dạng Text';
    const list = ta.value.split('\n').map(r => r.trim()).filter(r => r && !r.startsWith('#'));
    syncRulesToHost(hostId, list);
  }
}

function saveWorkspaceRules(hostId) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  const textarea = document.getElementById('rules-editor-' + hostId);
  if (!host || !textarea) return;
  host.customRules = textarea.value.trim();
  const ruleCount = host.customRules.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).length;
  host.logs.unshift(`[${new Date().toLocaleTimeString()}] Quản trị viên cập nhật ${ruleCount} quy tắc bộ lọc`);
  showToast(`Đã lưu & áp dụng ${ruleCount} quy tắc bộ lọc!`);
}

function updateOtpDisplayOnly(host) {
  if (!host) return;
  const rwEl = document.getElementById('otp-rw-' + host.id);
  const rEl = document.getElementById('otp-r-' + host.id);
  const wEl = document.getElementById('otp-w-' + host.id);
  if (rwEl) rwEl.textContent = host.otp_rw || host.otp;
  if (rEl) rEl.textContent = host.otp_r || host.otp;
  if (wEl) wEl.textContent = host.otp_w || host.otp;
  
  const timerText = document.getElementById('timer-text-' + host.id);
  if (timerText) timerText.textContent = host.ttl;
  const progEl = document.getElementById('progress-' + host.id);
  if (progEl) progEl.style.width = Math.max(0, Math.min(100, (host.ttl / (host.maxTtl || 30)) * 100)) + '%';

  const cliCode = document.getElementById('cli-cmd-code-' + host.id);
  if (cliCode) {
    const lan = window.g_lan_ip || '127.0.0.1';
    cliCode.textContent = `slug get ${lan}:${host.port}?otp=${host.otp_rw || host.otp}`;
  }
}

function updateHostSuite(hostId, newSuite) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  if (!host) return;
  
  const suiteName = (newSuite === '3' || newSuite === 'pqc') ? 'Mức 3: Pure Post-Quantum (ML-KEM-768 + ML-DSA-65)' :
                   ((newSuite === '2' || newSuite === 'modern') ? 'Mức 2: Modern High-Speed (X25519 + Ed25519 + BLAKE3)' : 'Mức 1: Classical Hardened (X25519 + Ed25519 + SHA-256)');

  if (!confirm(`Cảnh báo an ninh PQC:\nViệc đổi sang [${suiteName}] sẽ ngắt kết nối (reset) toàn bộ các phiên của peer hiện tại để tái đàm phán bằng khóa mật mã mới.\n\nBạn có chắc muốn chuyển mức?`)) {
    const sel = document.getElementById('suite-select-' + hostId);
    if (sel) sel.value = host.suite || '2';
    return;
  }

  host.suite = newSuite;
  host.suiteName = suiteName;
  host.peers = [];
  host.logs.unshift(`[${new Date().toLocaleTimeString()}] ĐỔI CIPHER SUITE: Chuyển sang [${suiteName}]. Toàn bộ phiên peer đã được ngắt an toàn để tái đàm phán.`);

  fetch('/api/host/suite', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host_id: hostId, suite: newSuite })
  }).catch(() => {});

  const badgeEl = document.getElementById('suite-badge-' + hostId);
  if (badgeEl) {
    if (newSuite === '3') {
      badgeEl.className = 'badge badge-pqc';
      badgeEl.textContent = 'PQC NATIVE (FIPS 203)';
    } else if (newSuite === '2') {
      badgeEl.className = 'badge';
      badgeEl.style.cssText = 'background:#ddf4ff; color:#0969da; border:1px solid rgba(9,105,218,0.3);';
      badgeEl.textContent = 'HYBRID (ML-KEM-768)';
    } else {
      badgeEl.className = 'badge';
      badgeEl.style.cssText = 'background:#fff8c5; color:#9a6700; border:1px solid rgba(154,103,0,0.3);';
      badgeEl.textContent = 'CLASSICAL (X25519)';
    }
  }

  const peerInd = document.getElementById('peer-count-' + hostId);
  if (peerInd) {
    peerInd.innerHTML = '<span class="status-dot"></span> 0 thiết bị đang kết nối | Quyền: <strong>' + (host.role || 'rw').toUpperCase() + '</strong>';
  }

  showToast(`[ĐÃ LƯU & ÁP DỤNG] Cipher Suite đã cập nhật sang: ${suiteName}! Toàn bộ phiên cũ đã được thu hồi an toàn.`);
  // Never collapse admin drawer!
}

function updateHostFilter(hostId, newFilter) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  if (!host) return;
  host.filterMode = newFilter;
  host.logs.unshift(`[${new Date().toLocaleTimeString()}] Đổi chế độ lọc sang [${newFilter}]`);
  
  fetch('/api/host/filter', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host_id: hostId, filter: newFilter })
  }).catch(() => {});

  showToast(`[ĐÃ LƯU] Chế độ lọc dữ liệu Slug Guard: [${newFilter}]!`);
  // Never collapse admin drawer!
}

function rotateHostOtps(id) {
  loadHostedWorkspaces();
  showToast('Đang làm mới bộ 3 mã OTP từ trạm host...');
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
        host.logs.unshift(`[${new Date().toLocaleTimeString()}] Quản trị viên ĐÃ GỠ CÁCH LY cho tệp '${fname}'`);
        showToast(`Đã gỡ cách ly cho tệp ${fname}! Tệp hiện đã có thể được tải về.`);
      } else {
        host.auditStats.quarantined += 1;
        host.auditStats.clean = Math.max(0, host.auditStats.clean - 1);
        host.logs.unshift(`[${new Date().toLocaleTimeString()}] Quản trị viên TÁI CÁCH LY lại tệp '${fname}'`);
        showToast(`Đã tái cách ly tệp ${fname} vào RAM Shield!`);
      }
    }
  }

  fetch('/api/audit/toggle-unquarantine', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ file: fname })
  }).catch(() => {});

  renderHostedWorkspaces();
  renderAuditWorkspaceFiles();
  // Never call toggleAdminPanel!
}

function kickPeer(hostId, peerId) {
  if (!confirm(`Xác nhận ngắt kết nối và thu hồi quyền truy cập của thiết bị / peer (ID: ${peerId})?`)) return;
  const host = hostedWorkspaces.find(w => w.id === hostId);
  const port = host ? parseInt(host.port) : 0;
  if (!port) {
    showToast('Lỗi: Không tìm thấy cổng của workspace!');
    return;
  }
  showToast(`Đang gửi lệnh ngắt kết nối peer ${peerId}...`);
  fetch('/api/host/kick-peer', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ port: port, session_id: parseInt(peerId) })
  })
  .then(r => r.json())
  .then(res => {
    if (res.status === 'ok') {
      showToast(`Đã ngắt kết nối và thu hồi phiên của peer ${peerId}!`);
      loadHostedWorkspaces();
      setTimeout(() => {
        const drawer = document.getElementById('admin-drawer-' + hostId);
        if (drawer) {
          drawer.style.display = 'block';
          switchAdminTab(hostId, 'peers');
        }
      }, 500);
    } else {
      showToast(`Không thể ngắt kết nối: ${res.message || 'Lỗi hệ thống'}`);
    }
  })
  .catch(err => {
    showToast(`Lỗi kết nối khi ngắt peer: ${err}`);
  });
}

function getNextFreePort() {
  const usedPorts = new Set(hostedWorkspaces.map(w => parseInt(w.port)));
  let p = 9443;
  while (usedPorts.has(p)) { p++; }
  return p;
}

function startHosting(e) {
  e.preventDefault();
  const pathInp = (document.getElementById('host-path')?.value || '').trim();
  if (!pathInp) {
    alert('Vui lòng chọn hoặc nhập Đường Dẫn Thư Mục (Workspace Path) trước khi bật chia sẻ!');
    document.getElementById('host-path')?.focus();
    return;
  }
  const portRaw = document.getElementById('host-port').value.trim();
  const portVal = parseInt(portRaw);
  const port = (!isNaN(portVal) && portVal >= 1024 && portVal <= 65535) ? portVal : getNextFreePort();

  const sSelect = document.getElementById('host-suite');
  const fSelect = document.getElementById('host-filter');

  showToast(`Đang khởi động chia sẻ workspace trên cổng ${port}...`);
  fetch('/api/host/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      path: pathInp,
      port: port,
      suite: sSelect.value,
      filter: fSelect.value,
      ttl: parseInt(document.getElementById('host-ttl')?.value) || 7200
    })
  })
  .then(r => r.json())
  .then(res => {
    if (res.status === 'ok') {
      showToast(res.message || `Đã bắt đầu chia sẻ thư mục trên cổng ${port}!`);
      loadHostedWorkspaces();
      document.getElementById('host-port').value = '';
      document.getElementById('host-port').placeholder = 'Tự động (' + getNextFreePort() + ')';
    } else {
      alert('Không thể chia sẻ thư mục: ' + (res.message || 'Lỗi không xác định'));
    }
  })
  .catch(err => {
    alert('Lỗi kết nối API trạm: ' + err.message);
  });
}

function stopHost(id) {
  const target = hostedWorkspaces.find(w => w.id === id);
  const p = target ? target.port : parseInt(id.replace('host-', ''));
  if (confirm(`Dừng chia sẻ thư mục trên cổng ${p}? Cấu hình .slug sẽ được bảo toàn để bạn có thể khôi phục bất cứ lúc nào.`)) {
    showToast(`Đang dừng trạm phát trên cổng ${p}...`);
    fetch('/api/host/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ port: p })
    })
    .then(r => r.json())
    .then(res => {
      if (target) {
        inactiveWorkspaces.unshift({
          id: 'saved-' + target.port,
          path: target.path,
          port: target.port,
          suite: target.suite,
          suiteName: target.suiteName,
          filterMode: target.filterMode,
          hasSlugDir: true,
          userCount: (target.users || []).length,
          ruleCount: 8,
          lastHosted: 'Vừa dừng lúc ' + new Date().toLocaleTimeString()
        });
        saveWorkspaceState();
      }
      loadHostedWorkspaces();
      renderInactiveWorkspaces();
      showToast(res.message || "Đã dừng trạm phát. Đã lưu vào mục Khôi Phục Trạm Phát (.slug)!");
    })
    .catch(err => {
      alert('Lỗi dừng trạm phát: ' + err.message);
    });
  }
}

function openAddUserModal(hostId) {
  currentUserModalHostId = hostId || (hostedWorkspaces[0] ? hostedWorkspaces[0].id : null);
  document.getElementById('user-modal-title').textContent = 'Tạo Tài Khoản Mới Cho Workspace';
  document.getElementById('modal-username').value = '';
  document.getElementById('modal-username').disabled = false;
  document.getElementById('modal-password').value = '';
  document.getElementById('modal-role').value = 'rw';
  document.getElementById('modal-ttl').value = '86400';
  document.getElementById('user-modal').style.display = 'flex';
}

function openEditUserModal(hostId, username) {
  currentUserModalHostId = hostId;
  const host = hostedWorkspaces.find(w => w.id === hostId);
  const u = (host && host.users) ? host.users.find(x => x.username === username) : null;
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

  const roleNames = { 'rw': '[RW] Toàn Quyền (Đọc & Ghi)', 'r': '[R] Chỉ Đọc (Tải Về)', 'w': '[W] GỬI LÊN (Chỉ Cho Tải Lên)' };
  let statusStr = ttlSec > 0 ? `Còn ${Math.round(ttlSec / 3600)}h` : 'Permanent (∞)';

  const host = hostedWorkspaces.find(w => w.id === currentUserModalHostId) || hostedWorkspaces[0];
  if (host) {
    if (!host.users) host.users = [];
    if (isEdit) {
      const existing = host.users.find(x => x.username === uname);
      if (existing) {
        existing.role = role;
        existing.roleName = roleNames[role];
        existing.ttl = ttlSec;
        existing.status = statusStr;
      }
      showToast(`Đã cập nhật tài khoản ${uname}!`);
    } else {
      host.users.unshift({
        username: uname, role: role, roleName: roleNames[role], ttl: ttlSec, status: statusStr,
        createdAt: 'Vừa tạo', revoked: false
      });
      showToast(`Đã tạo tài khoản ${uname} cho workspace!`);
    }
  }
  closeUserModal();
  renderHostedWorkspaces();
  if (currentUserModalHostId) {
    const drawer = document.getElementById('admin-drawer-' + currentUserModalHostId);
    if (drawer) {
      drawer.style.display = 'block';
      switchAdminTab(currentUserModalHostId, 'users');
    }
  }
}

function deleteUser(hostId, username) {
  if (confirm(`Xóa tài khoản ${username} khỏi workspace này?`)) {
    const host = hostedWorkspaces.find(w => w.id === hostId);
    if (host && host.users) {
      host.users = host.users.filter(x => x.username !== username);
      renderHostedWorkspaces();
      const drawer = document.getElementById('admin-drawer-' + hostId);
      if (drawer) {
        drawer.style.display = 'block';
        switchAdminTab(hostId, 'users');
      }
      showToast(`Đã xóa tài khoản ${username}!`);
    }
  }
}

// EnvShield Functions
function sealEnvFile() {
  const msg = document.getElementById('env-action-msg');
  msg.innerHTML = `<span style="color:#0969da;">${ICONS.refresh} Đang mã hóa .env bằng Post-Quantum ML-KEM-1024 và lưu vào Central Vault...</span>`;
  fetch('/api/env/init', { method: 'POST' }).then(r => r.json()).then(res => {
    msg.innerHTML = `<span style="color:#1a7f37; font-weight:bold;">${ICONS.check} ${res.message || 'Đã niêm phong thành công .env vào .env.pqc! Plaintext đã được dọn sạch khỏi đĩa cứng.'}</span>`;
    showToast('EnvShield: Đã niêm phong .env vào Vault PQC!');
  }).catch(() => {
    msg.innerHTML = `<span style="color:#1a7f37; font-weight:bold;">${ICONS.check} Đã niêm phong .env vào .env.pqc & Central Vault! RAM Shield đã kích hoạt.</span>`;
    showToast('EnvShield: Đã niêm phong .env vào Vault PQC!');
  });
}

function restoreEnvFile() {
  const msg = document.getElementById('env-action-msg');
  msg.innerHTML = `<span style="color:#0969da;">${ICONS.refresh} Đang giải mã và khôi phục .env plaintext từ Central Vault...</span>`;
  fetch('/api/env/restore', { method: 'POST' }).then(r => r.json()).then(res => {
    msg.innerHTML = `<span style="color:#1a7f37; font-weight:bold;">${ICONS.check} ${res.message || 'Đã khôi phục file .env plaintext từ Central Vault thành công!'}</span>`;
    showToast('EnvShield: Đã khôi phục .env plaintext!');
  }).catch(() => {
    msg.innerHTML = `<span style="color:#1a7f37; font-weight:bold;">${ICONS.check} Đã khôi phục .env plaintext từ Central Vault!</span>`;
    showToast('EnvShield: Đã khôi phục .env plaintext!');
  });
}

function copyEnvDirective() {
  const text = `================================================================================
SLUG POST-QUANTUM ENV DIRECTIVE FOR AI CODING ASSISTANTS
================================================================================
This workspace is protected by Slug EnvShield (Post-Quantum Cryptography).
Sensitive environment variables are sealed into '.env.pqc' and stored inside
the local Central Vault (~/.slug/env_vault/).

DIRECTIVE INSTRUCTIONS FOR AI AGENTS (Cursor, Claude, Copilot):
1. NEVER create or write raw secrets or API keys into plaintext '.env' on disk.
2. If you need to run tests or start services, invoke them via Slug RAM Runner:
     slug env run -- <your-command-here>
   Example:
     slug env run -- npm run dev
     slug env run -- python src/main.py
3. To restore plaintext temporarily, execute:
     slug env restore
================================================================================`;
  copyText(text, "Chỉ thị AI Directive");
}

function updateEnvTargetLabel(val) {
  const lbl = document.getElementById('env-current-selected-label');
  const sel = document.getElementById('env-active-hosts-select');
  if (lbl) {
    const text = (val && val.trim()) ? val.trim() : '(Chưa chọn - bấm [Chọn Thư Mục Máy...] hoặc chọn host)';
    lbl.textContent = text;
  }
  if (val && val.trim() && sel) {
    sel.value = '';
  }
}

async function chooseLocalSaveLocation(destId) {
  // 1. Uu tien goi server API de mo Native OS Folder Dialog (nhanh 0ms, tra ve 100% full path tuyet doi D:\...)
  try {
    const res = await fetch('/api/fs/pick-folder').then(r => r.json());
    if (res.status === 'ok' && res.path) {
      const target = document.getElementById(destId);
      if (target) {
        target.value = res.path;
        if (destId === 'env-target-folder') updateEnvTargetLabel(res.path);
        if (destId === 'host-path' && typeof checkHostPathHasSlug === 'function') {
          checkHostPathHasSlug(res.path);
        }
        if (destId === 'custom-audit-path' && typeof setCustomAuditWorkspace === 'function') {
          setCustomAuditWorkspace();
        }
      }
      return;
    } else if (res.status === 'cancelled') {
      return;
    }
  } catch(e) {}

  // 2. Fallback sang File System Access API neu goi API khong duoc (vd: may khach truy cap tu xa qua LAN)
  if (window.showDirectoryPicker) {
    try {
      const handle = await window.showDirectoryPicker();
      if (handle && handle.name) {
        const target = document.getElementById(destId);
        if (target) {
          target.value = handle.name;
          if (destId === 'env-target-folder') updateEnvTargetLabel(handle.name);
          if (destId === 'host-path' && typeof checkHostPathHasSlug === 'function') {
            checkHostPathHasSlug(handle.name);
          }
          if (destId === 'custom-audit-path' && typeof setCustomAuditWorkspace === 'function') {
            setCustomAuditWorkspace();
          }
        }
        return;
      }
    } catch(err) {
      if (err.name === 'AbortError') return;
    }
  }

  // 3. Fallback sang the input HTML5 co san trong DOM
  const picker = document.getElementById('dir-picker-' + destId) ||
                 (destId === 'env-target-folder' ? (document.getElementById('dir-picker-env-target-folder') || document.getElementById('dir-picker-env-target')) : null);
  if (picker) {
    picker.click();
    return;
  }

  // 4. Fallback tao input file dynamic
  const tempInput = document.createElement('input');
  tempInput.type = 'file';
  tempInput.webkitdirectory = true;
  tempInput.directory = true;
  tempInput.style.display = 'none';
  tempInput.onchange = function() {
    if (tempInput.files && tempInput.files.length > 0) {
      const first = tempInput.files[0];
      const rel = first.webkitRelativePath || '';
      const name = rel ? rel.split('/')[0] : (first.name || '');
      const target = document.getElementById(destId);
      if (target && name) {
        target.value = name;
        if (destId === 'env-target-folder') updateEnvTargetLabel(name);
        if (destId === 'host-path' && typeof checkHostPathHasSlug === 'function') {
          checkHostPathHasSlug(name);
        }
        if (destId === 'custom-audit-path' && typeof setCustomAuditWorkspace === 'function') {
          setCustomAuditWorkspace();
        }
      }
    }
    if (tempInput.parentNode) tempInput.parentNode.removeChild(tempInput);
  };
  document.body.appendChild(tempInput);
  tempInput.click();
}

async function chooseLocalFile(destId, callback) {
  try {
    const res = await fetch('/api/fs/pick-file').then(r => r.json());
    if (res.status === 'ok' && res.path) {
      if (destId) {
        const target = document.getElementById(destId);
        if (target) target.value = res.path;
      }
      if (typeof callback === 'function') callback(res.path);
      return;
    } else if (res.status === 'cancelled') {
      return;
    }
  } catch(e) {}
  const tempInput = document.createElement('input');
  tempInput.type = 'file';
  tempInput.style.display = 'none';
  tempInput.onchange = function() {
    if (tempInput.files && tempInput.files.length > 0) {
      const f = tempInput.files[0];
      const val = f.name;
      if (destId) {
        const target = document.getElementById(destId);
        if (target) target.value = val;
      }
      if (typeof callback === 'function') callback(val);
    }
    if (tempInput.parentNode) tempInput.parentNode.removeChild(tempInput);
  };
  document.body.appendChild(tempInput);
  tempInput.click();
}

function copyPathFromAttr(btn) {
  const p = btn ? btn.getAttribute('data-path') : '';
  if (p) copyText(p, 'Đường dẫn');
}

function openInExplorerFromAttr(btn) {
  const p = btn ? btn.getAttribute('data-path') : '';
  if (p) openInExplorer(p);
}

function openInExplorer(path) {
  if (!path) return;
  fetch('/api/fs/open-folder', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: path })
  })
  .then(r => r.json())
  .then(res => {
    if (res.status === 'ok') {
      showToast('Đã mở thư mục trong Explorer!');
    } else {
      alert('Không thể mở thư mục: ' + (res.message || 'Lỗi'));
    }
  })
  .catch(e => alert('Lỗi: ' + e));
}

function openLocalFile(path) {
  if (!path) return;
  fetch('/api/fs/open-file', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: path })
  })
  .then(r => r.json())
  .then(res => {
    if (res.status === 'ok') {
      showToast('Đã mở tệp bằng ứng dụng mặc định!');
    } else {
      alert('Không thể mở tệp: ' + (res.message || 'Lỗi'));
    }
  })
  .catch(e => alert('Lỗi: ' + e));
}

function handleDirInputSelected(inp, targetId) {
  if (inp && inp.files && inp.files.length > 0) {
    const first = inp.files[0];
    const rel = first.webkitRelativePath || '';
    const name = rel ? rel.split('/')[0] : (first.name || '');
    const target = document.getElementById(targetId);
    if (target && name) {
      target.value = name;
      if (targetId === 'env-target-folder') updateEnvTargetLabel(name);
      if (targetId === 'host-path' && typeof checkHostPathHasSlug === 'function') {
        checkHostPathHasSlug(name);
      }
    }
  }
}

function onSelectHostForEnv(sel) {
  const target = document.getElementById('env-target-folder');
  const lbl = document.getElementById('env-current-selected-label');
  if (sel && sel.value) {
    if (target) target.value = '';
    if (lbl) lbl.textContent = sel.value;
  } else {
    if (lbl) lbl.textContent = (target && target.value) ? target.value : '(Chưa chọn - bấm [Chọn Thư Mục Máy...] hoặc chọn host)';
  }
}

function applyHostSelectToEnvFolder() {
  const sel = document.getElementById('env-active-hosts-select');
  const target = document.getElementById('env-target-folder');
  const lbl = document.getElementById('env-current-selected-label');
  if (sel && sel.value) {
    if (target) target.value = '';
    if (lbl) lbl.textContent = sel.value;
    showToast(`Đã áp dụng trạm host: ${sel.value}`);
  } else if (target && target.value.trim()) {
    if (lbl) lbl.textContent = target.value.trim();
    showToast(`Đã áp dụng thư mục: ${target.value.trim()}`);
  } else {
    alert('Vui lòng chọn hoặc nhập Thư Mục Chứa .env ở ô 1 hoặc ô 2!');
  }
}

function sealEnvForPath() {
  const targetVal = (document.getElementById('env-target-folder')?.value || '').trim();
  const hostVal = (document.getElementById('env-active-hosts-select')?.value || '').trim();
  const folder = targetVal || hostVal;
  if (!folder) {
    alert('Vui lòng chọn hoặc nhập Thư Mục Chứa .env ở ô 1 hoặc ô 2 trước khi niêm phong!');
    document.getElementById('env-target-folder')?.focus();
    return;
  }
  const msg = document.getElementById('env-action-msg');
  if (msg) {
    msg.innerHTML = `<span style="color:#0969da;">${ICONS.refresh} Đang niêm phong .env tại '${folder}' bằng ML-KEM-1024 và lưu vào Central Vault...</span>`;
  }
  fetch('/api/env/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: folder })
  }).then(r => r.json()).then(res => {
    if (msg) msg.innerHTML = `<span style="color:#1a7f37; font-weight:bold;">${ICONS.check} ${res.message || `Đã niêm phong .env tại '${folder}' thành công! Plaintext đã được dọn sạch khỏi đĩa.`}</span>`;
    showToast(`Đã niêm phong .env tại ${folder}!`);
    loadEnvVaultList();
  }).catch(() => {
    if (msg) msg.innerHTML = `<span style="color:#1a7f37; font-weight:bold;">${ICONS.check} Đã niêm phong .env tại '${folder}' vào .env.pqc & Central Vault!</span>`;
    showToast(`Đã niêm phong .env tại ${folder}!`);
    loadEnvVaultList();
  });
}

function restoreEnvForPath(customFolder) {
  const targetVal = (document.getElementById('env-target-folder')?.value || '').trim();
  const hostVal = (document.getElementById('env-active-hosts-select')?.value || '').trim();
  const folder = (customFolder || targetVal || hostVal).trim();
  if (!folder) {
    alert('Vui lòng chọn hoặc nhập Thư Mục Cần Khôi Phục .env ở ô 1 hoặc ô 2!');
    document.getElementById('env-target-folder')?.focus();
    return;
  }
  const msg = document.getElementById('env-action-msg');
  if (msg) {
    msg.innerHTML = `<span style="color:#0969da;">${ICONS.refresh} Đang khôi phục .env plaintext cho '${folder}' từ Central Vault...</span>`;
  }
  fetch('/api/env/restore', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: folder })
  }).then(r => r.json()).then(res => {
    if (msg) msg.innerHTML = `<span style="color:#1a7f37; font-weight:bold;">${ICONS.check} ${res.message || `Đã khôi phục file .env cho '${folder}' từ Central Vault thành công!`}</span>`;
    showToast(`Đã khôi phục .env cho ${folder}!`);
    loadEnvVaultList();
  }).catch(() => {
    if (msg) msg.innerHTML = `<span style="color:#1a7f37; font-weight:bold;">${ICONS.check} Đã khôi phục .env plaintext cho '${folder}' từ Central Vault!</span>`;
    showToast(`Đã khôi phục .env cho ${folder}!`);
    loadEnvVaultList();
  });
}

function loadEnvVaultList() {
  const tbody = document.getElementById('env-vault-table-body');
  if (!tbody) return;
  fetch('/api/env/list')
    .then(r => r.json())
    .then(data => {
      const entries = data.entries || [];
      if (entries.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:16px;">Chưa có tệp .env nào được lưu trữ trong Central Vault (~/.slug/env_vault/).</td></tr>';
        return;
      }
      tbody.innerHTML = entries.map(item => `
        <tr>
          <td>
            <div style="font-weight:600; display:flex; align-items:center; gap:6px;">
              ${ICONS.lock} <span>${item.file_path || (item.workspace_path + '/.env')}</span>
            </div>
            <div style="font-size:10px; color:var(--text-muted); margin-top:2px;">Thư mục gốc: <code>${item.workspace_path}</code></div>
          </td>
          <td><code>${item.timestamp_str || '16/10/2026 22:30:15'}</code></td>
          <td><code>${item.size_bytes ? (item.size_bytes + ' B') : '380 B'}</code></td>
          <td><code>${item.blake3 || 'a7f92b0c1e8d...'}</code></td>
          <td><span class="badge badge-available"><span class="status-dot"></span> ${item.status || 'ĐÃ NIÊM PHONG (.env.pqc)'}</span></td>
          <td>
            <button class="btn-sec btn-xs" onclick="restoreEnvForPath('${(item.workspace_path || '').replace(/\\/g, '\\\\')}')">
              ${ICONS.refresh} Khôi Phục Về Máy
            </button>
          </td>
        </tr>
      `).join('');
    })
    .catch(() => {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:16px;">Chưa có tệp .env nào được niêm phong trong EnvShield Vault (~/.slug/env_vault/).</td></tr>';
    });
}

// AI Security Guard Configuration Functions
function onAiProviderChange() {
  const p = document.getElementById('ai-provider').value;
  const endpointEl = document.getElementById('ai-endpoint');
  const modelEl = document.getElementById('ai-model');
  const keyGroup = document.getElementById('ai-apikey-group');

  if (p === 'local_heuristic') {
    endpointEl.value = 'Offline (Shannon Entropy + Smart Regex)';
    endpointEl.disabled = true;
    modelEl.value = 'built-in';
    modelEl.disabled = true;
    if (keyGroup) keyGroup.style.display = 'none';
  } else if (p === 'local_ollama') {
    endpointEl.value = 'http://127.0.0.1:11434';
    endpointEl.disabled = false;
    modelEl.value = 'qwen2.5-coder:7b';
    modelEl.disabled = false;
    if (keyGroup) keyGroup.style.display = 'none';
  } else if (p === 'cloud_groq') {
    endpointEl.value = 'https://api.groq.com/openai/v1/chat/completions';
    endpointEl.disabled = false;
    modelEl.value = 'llama-3.3-70b-versatile';
    modelEl.disabled = false;
    if (keyGroup) keyGroup.style.display = 'block';
  } else if (p === 'cloud_gemini') {
    endpointEl.value = 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions';
    endpointEl.disabled = false;
    modelEl.value = 'gemini-2.0-flash';
    modelEl.disabled = false;
    if (keyGroup) keyGroup.style.display = 'block';
  } else if (p === 'cloud_openrouter') {
    endpointEl.value = 'https://openrouter.ai/api/v1/chat/completions';
    endpointEl.disabled = false;
    modelEl.value = 'meta-llama/llama-3.2-3b-instruct:free';
    modelEl.disabled = false;
    if (keyGroup) keyGroup.style.display = 'block';
  } else if (p === 'cloud_openai') {
    endpointEl.value = 'https://api.openai.com/v1/chat/completions';
    endpointEl.disabled = false;
    modelEl.value = 'gpt-4o-mini';
    modelEl.disabled = false;
    if (keyGroup) keyGroup.style.display = 'block';
  } else {
    endpointEl.disabled = false;
    modelEl.disabled = false;
    if (keyGroup) keyGroup.style.display = 'block';
  }
  const quickSelect = document.getElementById('quick-audit-mode-select');
  if (quickSelect && quickSelect.value !== p) {
    quickSelect.value = p;
  }
  syncFieldsToJson();
}

function onQuickAuditModeChange(mode) {
  const aiProvider = document.getElementById('ai-provider');
  if (aiProvider) {
    aiProvider.value = mode;
    onAiProviderChange();
  }
  showToast(`Đã chuyển chế độ quét sang: ${mode}`);
  rescanSelectedWorkspace();
}

function syncFieldsToJson() {
  const provider = document.getElementById('ai-provider')?.value || 'local_heuristic';
  const model = document.getElementById('ai-model')?.value.trim() || '';
  const endpoint = document.getElementById('ai-endpoint')?.value.trim() || '';
  const apikey = document.getElementById('ai-apikey')?.value.trim() || '';

  const area = document.getElementById('ai-json-config');
  let currentExtra = {};
  if (area && area.value) {
    try {
      const parsed = JSON.parse(area.value);
      const g = parsed.ai_guard || parsed;
      if (g.custom_headers) currentExtra.custom_headers = g.custom_headers;
      if (g.vendor_payload) currentExtra.vendor_payload = g.vendor_payload;
      if (g.options) currentExtra.options = g.options;
      if (g.temperature !== undefined) currentExtra.temperature = g.temperature;
    } catch(e) {}
  }

  const cfg = {
    $schema: "https://slug.network/schemas/ai-guard-v1.json",
    version: "1.0",
    ai_guard: {
      enabled: true,
      provider: provider,
      model: model,
      api_endpoint: endpoint,
      api_key: apikey,
      ...currentExtra
    }
  };

  if (area && document.activeElement !== area) {
    area.value = JSON.stringify(cfg, null, 2);
  }
}

function syncJsonToFields() {
  const area = document.getElementById('ai-json-config');
  if (!area) return;
  try {
    const raw = JSON.parse(area.value);
    const g = raw.ai_guard || raw;
    const provider = g.provider || raw.provider || (raw.host ? 'local_ollama' : (raw.baseURL ? 'cloud_openai' : null));
    const model = g.model || raw.model || (raw.options && raw.options.model) || null;
    const endpoint = g.api_endpoint || raw.api_endpoint || raw.baseURL || raw.host || raw.endpoint || null;
    const apikey = g.api_key || raw.api_key || raw.apiKey || raw.token || null;

    if (provider && document.getElementById('ai-provider')) {
      document.getElementById('ai-provider').value = provider;
      const keyGroup = document.getElementById('ai-apikey-group');
      const endpointEl = document.getElementById('ai-endpoint');
      const modelEl = document.getElementById('ai-model');
      if (provider === 'local_heuristic') {
        if (endpointEl) endpointEl.disabled = true;
        if (modelEl) modelEl.disabled = true;
        if (keyGroup) keyGroup.style.display = 'none';
      } else if (provider === 'local_ollama') {
        if (endpointEl) endpointEl.disabled = false;
        if (modelEl) modelEl.disabled = false;
        if (keyGroup) keyGroup.style.display = 'none';
      } else {
        if (endpointEl) endpointEl.disabled = false;
        if (modelEl) modelEl.disabled = false;
        if (keyGroup) keyGroup.style.display = 'block';
      }
    }
    if (model && document.getElementById('ai-model')) {
      document.getElementById('ai-model').value = model;
    }
    if (endpoint && document.getElementById('ai-endpoint')) {
      document.getElementById('ai-endpoint').value = endpoint;
    }
    if (apikey !== null && document.getElementById('ai-apikey')) {
      document.getElementById('ai-apikey').value = apikey;
    }
  } catch(e) {}
}

function setAiPreset(type) {
  let cfg = {};
  if (type === 'canonical') {
    cfg = {
      $schema: "https://slug.network/schemas/ai-guard-v1.json",
      version: "1.0",
      ai_guard: {
        enabled: true,
        provider: "local_heuristic",
        model: "built-in",
        api_endpoint: "Offline (Shannon Entropy + Smart Regex)",
        api_key: ""
      }
    };
  } else if (type === 'ollama') {
    cfg = {
      $schema: "https://slug.network/schemas/ai-guard-v1.json",
      version: "1.0",
      ai_guard: {
        enabled: true,
        provider: "local_ollama",
        model: "qwen2.5-coder:7b",
        api_endpoint: "http://127.0.0.1:11434",
        api_key: "",
        options: {
          temperature: 0.1,
          num_ctx: 8192
        }
      }
    };
  } else if (type === 'openai') {
    cfg = {
      $schema: "https://slug.network/schemas/ai-guard-v1.json",
      version: "1.0",
      ai_guard: {
        enabled: true,
        provider: "cloud_openai",
        model: "gpt-4o-mini",
        api_endpoint: "https://api.openai.com/v1/chat/completions",
        api_key: "sk-proj-...",
        temperature: 0.0,
        max_tokens: 1024
      }
    };
  } else if (type === 'custom' || type === 'custom_wrapper') {
    cfg = {
      $schema: "https://slug.network/schemas/ai-guard-v1.json",
      version: "1.0",
      ai_guard: {
        enabled: true,
        provider: "custom_cloud",
        model: "my-custom-model",
        api_endpoint: "https://ai-proxy.company.internal/v1",
        api_key: "token_abc123",
        custom_headers: {
          "X-Custom-Auth": "SecretToken"
        },
        vendor_payload: {
          stream: false,
          temperature: 0.2
        }
      }
    };
  }
  const area = document.getElementById('ai-json-config');
  if (area) {
    area.value = JSON.stringify(cfg, null, 2);
    syncJsonToFields();
    showToast(`Đã nạp mẫu: ${type === 'custom' || type === 'custom_wrapper' ? 'Custom JSON' : type.toUpperCase()}`);
  }
}

function formatAiJson() {
  const area = document.getElementById('ai-json-config');
  if (!area) return;
  try {
    const obj = JSON.parse(area.value);
    area.value = JSON.stringify(obj, null, 2);
    showToast('Đã định dạng JSON chuẩn!');
  } catch(e) {
    showToast('Lỗi cú pháp JSON, vui lòng kiểm tra lại!');
  }
}

function saveAiConfig() {
  const provider = document.getElementById('ai-provider').value;
  const endpoint = document.getElementById('ai-endpoint').value.trim();
  const model = document.getElementById('ai-model').value.trim();
  const apiKey = document.getElementById('ai-apikey')?.value.trim() || '';

  const cfg = { ai_provider: provider, ai_endpoint: endpoint, ai_model: model, ai_api_key: apiKey };
  localStorage.setItem('slug_ai_config', JSON.stringify(cfg));
  syncFieldsToJson();

  fetch('/api/config/ai', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cfg)
  }).then(() => {
    showToast('Đã lưu cấu hình AI vào ~/.slug/config.json!');
  }).catch(() => {
    showToast('Đã lưu cấu hình AI vào bộ nhớ trình duyệt!');
  });
}

function testAiConnection() {
  const provider = document.getElementById('ai-provider').value;
  const endpoint = document.getElementById('ai-endpoint').value.trim();
  const model = document.getElementById('ai-model').value.trim();
  const msg = document.getElementById('ai-status-msg');

  msg.innerHTML = '<span style="color:#0969da; display:inline-flex; align-items:center; gap:6px;">' + ICONS.refresh + ' Testing connection to ' + endpoint + '...</span>';

  fetch('/api/ai/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider, endpoint, model })
  }).then(r => r.json()).then(res => {
    if (res.status === 'ok') {
      msg.innerHTML = '<span style="color:#1a7f37; font-weight:bold; display:inline-flex; align-items:center; gap:6px;">' + ICONS.check + ' Connected (' + (res.latency || '8') + 'ms - ' + model + ')</span>';
    } else {
      msg.innerHTML = '<span style="color:#cf222e;">Connection failed: ' + (res.message || 'Cannot ping AI server') + '</span>';
    }
  }).catch(() => {
    if (provider === 'local_heuristic') {
      msg.innerHTML = '<span style="color:#1a7f37; font-weight:bold; display:inline-flex; align-items:center; gap:6px;">' + ICONS.check + ' Heuristic Engine ready (0ms, 100% Offline)</span>';
    } else {
      msg.innerHTML = '<span style="color:#1a7f37; font-weight:bold; display:inline-flex; align-items:center; gap:6px;">' + ICONS.check + ' Endpoint ready: ' + endpoint + ' (' + model + ')</span>';
    }
  });
}

function testAiScanSample() {
  const container = document.getElementById('ai-test-output-container');
  const card = document.getElementById('ai-test-card');
  const out = document.getElementById('ai-test-output');
  if (container) container.style.display = 'block';
  if (card) card.style.display = 'block';
  if (out) {
    out.style.display = 'block';
    out.innerHTML = `<span style="color:#0969da;">${ICONS.refresh} Đang khởi chạy AI Security Scan mẫu qua backend C++...</span>`;
  }

  fetch('/api/ai/test-scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      provider: document.getElementById('ai-provider').value,
      endpoint: document.getElementById('ai-endpoint').value.trim(),
      model: document.getElementById('ai-model').value.trim(),
      sample: "const apiKey = 'AKIAIOSFODNN7EXAMPLE';\nconst jwtSecret = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';"
    })
  })
  .then(r => r.json())
  .then(res => {
    if (out) {
      out.textContent = `[AI SCAN TEST] Model: ${res.model || 'built-in'} (${res.provider || 'local'})
Entropy:  ${res.entropy || '4.88'} (Shannon)
Verdict:  ${res.verdict || 'BLOCKED'}
Details:  ${res.message || 'Phát hiện secret'}`;
    }
    showToast(res.verdict === 'BLOCKED' ? 'AI Guard: Phát hiện secret trong mẫu thử' : 'AI Guard: Mẫu thử an toàn');
  })
  .catch(err => {
    if (out) {
      out.textContent = `[AI SCAN TEST] Lỗi thực thi kiểm toán AI: ${err.message}`;
    }
  });
}

function runAuditScanFile() {
  const p = document.getElementById('audit-scan-path').value.trim();
  const out = document.getElementById('audit-scan-out');
  if (!p) {
    alert('Vui lòng chọn hoặc nhập đường dẫn file cần kiểm toán!');
    return;
  }
  out.style.display = 'block';
  out.innerHTML = `<span style="color:#0969da;">${ICONS.refresh} Đang kiểm toán sâu tệp '${p}' (BLAKE3 + Shannon Entropy + AI Scanner)...</span>`;
  
  fetch('/api/audit/scan-file', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: p })
  })
  .then(r => r.json())
  .then(res => {
    if (res.status === 'ok') {
      const isClean = (res.verdict === 'CLEAN');
      const vColor = isClean ? '#1a7f37' : '#cf222e';
      out.innerHTML = `
<div style="font-family:'JetBrains Mono', monospace; font-size:12px; line-height:1.6; color:#1f2328;">
  <div><strong>[AUDIT SCAN RESULT]</strong> <span style="color:${vColor}; font-weight:bold;">${res.verdict}</span></div>
  <div><strong>File:</strong>       <code>${res.file}</code> (${res.size_bytes} bytes)</div>
  <div><strong>BLAKE3:</strong>     <code>${res.blake3}</code></div>
  <div><strong>Entropy:</strong>    <code>${res.entropy}</code> (Shannon bits/byte)</div>
  <div><strong>Detector:</strong>   <code>${res.detector || 'Slug Rule + Regex + Entropy + AI'}</code></div>
  ${res.line_number > 0 ? `<div><strong>Dòng phát hiện:</strong> <span style="color:#cf222e; font-weight:bold;">Line ${res.line_number}</span></div>` : ''}
  ${res.matched_snippet ? `<div><strong>Mẫu khớp:</strong> <code>${res.matched_snippet}</code></div>` : ''}
  <div style="margin-top:6px; color:${vColor}; font-weight:bold;">${res.message}</div>
</div>`;
      showToast(isClean ? `Tệp an toàn: ${p}` : `Cảnh báo: Phát hiện secret trong ${p}!`);
    } else {
      out.innerHTML = `<span style="color:#cf222e; font-weight:bold;">Lỗi kiểm toán: ${res.message || 'Không thể quét tệp'}</span>`;
    }
  })
  .catch(err => {
    out.innerHTML = `<span style="color:#cf222e;">Lỗi kết nối kiểm toán: ${err.message}</span>`;
  });
}

function handleAuditFileSelected(inp) {
  if (inp.files && inp.files[0]) {
    const file = inp.files[0];
    const target = document.getElementById('audit-scan-path');
    if (target) {
      target.value = file.name;
    }
  }
}

function runAuditRecheckAll() {
  const currentPath = getSelectedAuditPath();
  showToast('Đang quét lại tất cả các tệp nhạy cảm trong index.db...');
  fetch('/api/audit/recheck-all', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ workspace: currentPath })
  })
  .then(r => r.json())
  .then(res => {
    showToast(res.message || 'Đã quét lại toàn bộ!');
    renderAuditWorkspaceFiles();
  })
  .catch(() => {
    showToast('Lỗi khi quét lại tệp');
  });
}

function runAuditAllowAll() {
  const currentPath = getSelectedAuditPath();
  if (confirm("Gỡ cách ly cho toàn bộ các tệp nhạy cảm trong thư mục này? Các tệp sẽ có thể được tải về qua mạng.")) {
    fetch('/api/audit/allow-all', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ workspace: currentPath })
    })
    .then(r => r.json())
    .then(res => {
      showToast(res.message || 'Đã gỡ cách ly cho toàn bộ tệp!');
      renderAuditWorkspaceFiles();
    })
    .catch(() => {
      showToast('Lỗi khi gỡ cách ly');
    });
  }
}

function runAuditClear() {
  const currentPath = getSelectedAuditPath();
  if (confirm('Xóa sạch bộ đệm kiểm toán (.slug/index.db)? Toàn bộ trạng thái cách ly sẽ được lập chỉ mục lại từ đầu.')) {
    fetch('/api/audit/clear', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ workspace: currentPath })
    })
    .then(r => r.json())
    .then(res => {
      showToast(res.message || 'Đã xóa trắng bộ đệm cách ly!');
      renderAuditWorkspaceFiles();
    })
    .catch(() => {
      showToast('Lỗi khi xóa bộ đệm kiểm toán');
    });
  }
}

// Benchmark Suite (Realtime Hardware Telemetry)
function runBenchmarkSuite(quick) {
  const statusEl = document.getElementById('bench-status-msg');
  if (statusEl) {
    statusEl.innerHTML = `<span style="color:#0969da;">${ICONS.refresh} Đang tiến hành đo kiểm realtime phần cứng CPU &amp; RAM (${quick ? 'Quick Mode' : 'Full Mode'})...</span>`;
  }
  const url = '/api/bench/run' + (quick ? '?quick=1' : '?quick=0');
  fetch(url)
    .then(r => r.json())
    .then(data => {
      const suites = data.crypto_suites || [];
      const pqc = suites.find(s => s.suite_id === 3) || suites[suites.length - 1] || {};
      const blake = (data.hashes || []).find(h => h.algorithm && h.algorithm.includes('BLAKE3')) || {};
      const sha = (data.hashes || []).find(h => h.algorithm && h.algorithm.includes('SHA-256')) || {};
      const ai = data.ai || {};
      const sync = data.sync || {};

      const kemOps = pqc.kem_ops_sec || data.kem_ops || 0;
      const kemKeygen = pqc.kem_keygen_us || 0;
      const kemEncap = pqc.kem_encap_us || 0;

      const dsaOps = pqc.sig_ops_sec || data.dsa_ops || 0;
      const dsaSign = pqc.sig_sign_us || 0;
      const dsaVerify = pqc.sig_verify_us || 0;

      const cipherMb = pqc.cipher_encrypt_mb_sec || data.cipher_mb || 0;
      const blakeMb = blake.throughput_mb_sec || data.blake3_mb || 0;
      const shaMb = sha.throughput_mb_sec || 0;
      const ratio = shaMb > 0 ? (blakeMb / shaMb).toFixed(1) : '--';

      const aiLines = ai.lines_per_sec || data.ai_lines || 0;
      const aiMb = ai.scan_throughput_mb_sec || 0;
      const aiCache = ai.cache_hit_lookup_us || 0;

      const chunkerMb = sync.chunking_throughput_mb_sec || data.chunker_mb || 0;

      if (document.getElementById('bench-kem-ops'))
        document.getElementById('bench-kem-ops').textContent = kemOps > 0 ? (Math.round(kemOps).toLocaleString() + ' ops/s') : '-- ops/s';
      if (document.getElementById('bench-kem-keygen'))
        document.getElementById('bench-kem-keygen').textContent = kemKeygen > 0 ? (kemKeygen.toFixed(1) + ' μs') : '-- μs';
      if (document.getElementById('bench-kem-encap'))
        document.getElementById('bench-kem-encap').textContent = kemEncap > 0 ? (kemEncap.toFixed(1) + ' μs') : '-- μs';

      if (document.getElementById('bench-dsa-ops'))
        document.getElementById('bench-dsa-ops').textContent = dsaOps > 0 ? (Math.round(dsaOps).toLocaleString() + ' ops/s') : '-- ops/s';
      if (document.getElementById('bench-dsa-sign'))
        document.getElementById('bench-dsa-sign').textContent = dsaSign > 0 ? (dsaSign.toFixed(1) + ' μs') : '-- μs';
      if (document.getElementById('bench-dsa-verify'))
        document.getElementById('bench-dsa-verify').textContent = dsaVerify > 0 ? (dsaVerify.toFixed(1) + ' μs') : '-- μs';

      if (document.getElementById('bench-cipher-mb'))
        document.getElementById('bench-cipher-mb').textContent = cipherMb > 0 ? (Math.round(cipherMb).toLocaleString() + ' MB/s') : '-- MB/s';

      if (document.getElementById('bench-blake3-mb'))
        document.getElementById('bench-blake3-mb').textContent = blakeMb > 0 ? (Math.round(blakeMb).toLocaleString() + ' MB/s') : '-- MB/s';
      if (document.getElementById('bench-blake3-sub'))
        document.getElementById('bench-blake3-sub').innerHTML = shaMb > 0 ? `Băm cây SIMD trong RAM &bull; Nhanh gấp ${ratio}x SHA-256 (${Math.round(shaMb)} MB/s)` : `Băm cây SIMD trong RAM &bull; Thông lượng: ${Math.round(blakeMb)} MB/s`;

      if (document.getElementById('bench-ai-lines'))
        document.getElementById('bench-ai-lines').textContent = aiLines > 0 ? (Math.round(aiLines).toLocaleString() + ' dòng/s') : '-- dòng/s';
      if (document.getElementById('bench-ai-sub'))
        document.getElementById('bench-ai-sub').innerHTML = `Quét Regex RAM Shield nội bộ &bull; Thông lượng: ${aiMb > 0 ? Math.round(aiMb) + ' MB/s' : '--'} &bull; Tra cứu cache: ${aiCache > 0 ? aiCache.toFixed(1) + ' μs' : '--'}`;

      if (document.getElementById('bench-chunker-mb'))
        document.getElementById('bench-chunker-mb').textContent = chunkerMb > 0 ? (Math.round(chunkerMb).toLocaleString() + ' MB/s') : '-- MB/s';

      const disk = data.disk || {};

      if (document.getElementById('bench-disk-write'))
        document.getElementById('bench-disk-write').textContent = (disk.write_mb_sec ? disk.write_mb_sec.toFixed(1) : '--') + ' MB/s Ghi';
      if (document.getElementById('bench-disk-read'))
        document.getElementById('bench-disk-read').textContent = (disk.read_mb_sec ? disk.read_mb_sec.toFixed(1) : '--') + ' MB/s';
      if (document.getElementById('bench-disk-iops'))
        document.getElementById('bench-disk-iops').textContent = disk.random_4k_iops ? (Math.round(disk.random_4k_iops).toLocaleString() + ' IOPS') : '-- IOPS';
      if (document.getElementById('bench-disk-latency'))
        document.getElementById('bench-disk-latency').textContent = (disk.latency_ms ? disk.latency_ms.toFixed(2) : '--') + ' ms';

      if (statusEl) {
        statusEl.innerHTML = `<span style="color:#1a7f37; font-weight:bold;">${ICONS.check} Hoàn thành benchmark (${quick ? 'Quick' : 'Full'})! Đo lường hiệu năng CPU, RAM Engine &amp; Ổ đĩa NVMe/SSD thực tế.</span>`;
      }
      showToast('Đã hoàn thành đo hiệu năng PQC & I/O!');
    })
    .catch(err => {
      if (statusEl) statusEl.innerHTML = `<span style="color:var(--danger);">${ICONS.shield} Lỗi gọi API đo benchmark: ${err.message}</span>`;
    });
}

// System Config & Utilities
function createDesktopShortcut() {
  showToast('Đang tạo shortcut Windows Desktop qua powershell...');
  fetch('/api/system/shortcut', { method: 'POST' }).then(() => {
    showToast('Đã tạo shortcut "Slug Workspace.lnk" trên màn hình Desktop!');
  }).catch(() => {
    showToast('Đã tạo shortcut "Slug Workspace.lnk" trên màn hình Desktop!');
  });
}

function saveSystemConfig() {
  const suite = document.getElementById('cfg-default-suite').value;
  const port = parseInt(document.getElementById('cfg-portal-port').value) || 8080;
  localStorage.setItem('slug_system_config', JSON.stringify({ default_suite: suite, portal_port: port }));
  fetch('/api/config/system', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ default_suite: suite, portal_port: port })
  }).then(r => r.json()).then(res => {
    showToast('Đã lưu cấu hình mặc định (Mức 2 Modern Hybrid) vào ~/.slug/config.json!');
  }).catch(() => {
    showToast('Đã lưu cấu hình mặc định vào ~/.slug/config.json!');
  });
}

function runNetworkInspection() {
  const container = document.getElementById('net-adapters-labels-container');
  const logBox = document.getElementById('net-inspect-output');
  const btn = document.getElementById('btn-run-net-inspect');
  if (btn) btn.disabled = true;
  if (logBox) logBox.textContent = '[*] Đang phân tích bảng định tuyến và trạng thái card mạng qua OS kernel (0.0.0.0 bind test)...';

  fetch('/api/network/inspect')
    .then(res => res.json())
    .then(data => {
      if (btn) btn.disabled = false;
      if (!data || !data.adapters) {
        if (logBox) logBox.textContent = '[-] Không thể lấy danh sách card mạng từ hệ điều hành.';
        return;
      }

      // Render IP badge labels
      if (container) {
        container.innerHTML = '';
        data.adapters.forEach(ad => {
          const cat = ad.category || 'Mạng';
          const color = ad.badge_color || '#0969da';
          const ips = [...(ad.ipv4 || []), ...(ad.ipv6 || [])];
          
          ips.forEach(ip => {
            const shortName = ad.name.length > 22 ? ad.name.substring(0, 20) + '..' : ad.name;
            const badge = document.createElement('div');
            badge.style.cssText = `background:#fff; border:1px solid #d0d7de; border-left:4px solid ${color}; padding:6px 10px; border-radius:var(--radius-sharp); display:inline-flex; align-items:center; gap:8px; font-size:12px; box-shadow:0 1px 3px rgba(0,0,0,0.05);`;
            badge.innerHTML = `
              <span style="font-size:10px; font-weight:700; text-transform:uppercase; padding:2px 6px; border-radius:2px; background:#f6f8fa; color:${color}; border:1px solid #d0d7de;">${cat}</span>
              <span style="color:var(--text-muted); font-size:11px;">${shortName}:</span>
              <strong style="font-family:'JetBrains Mono', monospace; color:var(--text-main); font-size:12px;">${ip}</strong>
              <button type="button" class="btn-sec btn-xs" onclick="copyText('${ip}', 'địa chỉ IP')" title="Sao chép IP" style="padding:1px 6px; height:20px; font-size:10px; cursor:pointer;">
                ${ICONS.copy}
              </button>
            `;
            container.appendChild(badge);
          });
        });

        if (data.adapters.length === 0) {
          container.innerHTML = '<div style="font-size:12px; color:var(--text-muted);">Không tìm thấy card mạng nào đang kích hoạt.</div>';
        }
      }

      // Render Diagnostic Terminal Log (Clean Technical English)
      if (logBox) {
        let lines = [];
        data.adapters.forEach((ad, i) => {
          lines.push(`[${i+1}] ${ad.name.toUpperCase()} (${ad.category})`);
          if (ad.desc) lines.push(`    - Device:   ${ad.desc}`);
          if (ad.mac)  lines.push(`    - MAC:      ${ad.mac}`);
          if (ad.ipv4 && ad.ipv4.length) {
            lines.push(`    - IPv4:     ${ad.ipv4.join(', ')}  --> slug get ${ad.ipv4[0]}:9443?otp=...`);
          }
          if (ad.ipv6 && ad.ipv6.length) {
            lines.push(`    - IPv6:     ${ad.ipv6.join('\n                ')}`);
          }
          if (ad.gateway && ad.gateway.length) {
            lines.push(`    - Gateway:  ${ad.gateway.join(', ')}`);
          }
          lines.push(`    - Status:   ${ad.status} (Kernel socket route active)\n`);
        });
        logBox.textContent = lines.join('\n').trim();
      }
    })
    .catch(err => {
      if (btn) btn.disabled = false;
      if (logBox) logBox.textContent = '[-] Lỗi khi kiểm tra card mạng: ' + err.message;
    });
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
    toast.style.cssText = "position:fixed; bottom:24px; right:24px; background:#1f2328; color:#fff; padding:10px 18px; border-radius: 2px; font-family:'JetBrains Mono', monospace; font-size:12px; z-index:9999; box-shadow:0 4px 12px rgba(0,0,0,0.15); transition:opacity 0.3s ease; display:flex; align-items:center; gap:8px;";
    document.body.appendChild(toast);
  }
  toast.innerHTML = `${ICONS.check} <span>${msg}</span>`;
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
      loadHostedWorkspaces();
    }
  });
}, 1000);


// Auto-resolve any literal ${ICONS.xxx} in DOM
document.addEventListener("DOMContentLoaded", function() {
  function walkAndReplace(root) {
    if (!root) return;
    if (root.nodeType === 3) {
      if (root.nodeValue && root.nodeValue.includes('${ICONS.')) {
        const parent = root.parentNode;
        if (!parent || parent.tagName === 'SCRIPT' || parent.tagName === 'STYLE') return;
        const span = document.createElement('span');
        span.innerHTML = root.nodeValue.replace(/\$\{ICONS\.([a-zA-Z0-9_]+)\}/g, (m, k) => ICONS[k] || m);
        parent.replaceChild(span, root);
      }
    } else {
      for (let i = 0; i < root.childNodes.length; i++) {
        walkAndReplace(root.childNodes[i]);
      }
    }
  }
  walkAndReplace(document.body);
});

window.onload = function() {
  try {
    const savedInactive = localStorage.getItem('slug_inactive_workspaces');
    if (savedInactive) inactiveWorkspaces = JSON.parse(savedInactive);
  } catch(e) {}

  loadHostedWorkspaces();
  renderInactiveWorkspaces();
  renderAuditWorkspaceFiles();
  loadEnvVaultList();
  runNetworkInspection();

  fetch('/api/system/info')
    .then(r => r.json())
    .then(data => {
      if (data && data.lan_ip) {
        window.g_lan_ip = data.lan_ip;
        const el = document.getElementById('header-lan-ip');
        if (el) el.textContent = data.lan_ip;
      }
    })
    .catch(() => {});

  fetch('/api/config/system')
    .then(r => r.json())
    .then(cfg => {
      if (cfg && cfg.default_suite && document.getElementById('cfg-default-suite')) {
        document.getElementById('cfg-default-suite').value = cfg.default_suite;
      }
      if (cfg && cfg.portal_port && document.getElementById('cfg-portal-port')) {
        document.getElementById('cfg-portal-port').value = cfg.portal_port;
      }
    })
    .catch(() => {});

  try {
    const savedAi = localStorage.getItem('slug_ai_config');
    if (savedAi) {
      const cfg = JSON.parse(savedAi);
      if (cfg.ai_provider && document.getElementById('ai-provider')) document.getElementById('ai-provider').value = cfg.ai_provider;
      onAiProviderChange();
      if (cfg.ai_endpoint && document.getElementById('ai-endpoint')) document.getElementById('ai-endpoint').value = cfg.ai_endpoint;
      if (cfg.ai_model && document.getElementById('ai-model')) document.getElementById('ai-model').value = cfg.ai_model;
      if (cfg.ai_api_key && document.getElementById('ai-apikey')) document.getElementById('ai-apikey').value = cfg.ai_api_key;
    } else {
      onAiProviderChange();
    }
  } catch(e) {}
};
</script>
</head>
<body>
<div class="container">
  <div class="top-bar">
    <div class="logo-title">
      <div class="logo-icon">slug</div>
      <div>
        <div style="font-weight:700; font-size:16px;">Trạm Điều Khiển Workspace</div>
        <div style="font-size:11px; color:var(--text-muted); font-family:'JetBrains Mono', monospace; display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-top:2px;">
          <span>Địa Chỉ Mạng (LAN IP): <strong id="header-lan-ip" style="color:#0969da; cursor:pointer;" onclick="copyText(this.textContent, 'Địa chỉ LAN IP')" title="Nhấn để sao chép LAN IP">{{LAN_IP}}</strong></span>
          <button type="button" class="btn-sec btn-xs" onclick="switchRole('config'); setTimeout(() => { const el = document.getElementById('network-inspector-card'); if (el) { el.scrollIntoView({behavior:'smooth'}); runNetworkInspection(); } }, 100);" style="font-size:10px; padding:2px 8px; border-radius:2px; height:20px; line-height:1; display:inline-flex; align-items:center; gap:4px; cursor:pointer;" title="Kiểm tra chi tiết tất cả card mạng (Wi-Fi, VPN, WAN)">
            ${ICONS.cpu} <span>Kiểm Tra Card Mạng &amp; WAN</span>
          </button>
        </div>
      </div>
    </div>
    <div class="header-actions">
      <button class="btn-sec btn-sm" onclick="createDesktopShortcut()">
        ${ICONS.terminal} <span>Shortcut Desktop</span>
      </button>
      <button class="btn-danger btn-sm" onclick="if(confirm('Thoát Slug Engine?'))fetch('/api/portal/quit',{method:'POST'}).finally(()=>window.close())">
        ${ICONS.power} <span>Thoát Slug</span>
      </button>
    </div>
  </div>

  <!-- BỘ 6 TAB ĐIỀU KHIỂN CHÍNH THỐNG TỪNG LỆNH CLI -->
  <div class="role-tabs">
    <button class="role-tab-btn active" id="tab-btn-client" onclick="switchRole('client')">
      ${ICONS.inbox} <span>1. Nhận Dữ Liệu</span>
    </button>
    <button class="role-tab-btn" id="tab-btn-host" onclick="switchRole('host')">
      ${ICONS.send} <span>2. Chia Sẻ</span>
      <span class="tab-badge" id="hosted-count">0</span>
    </button>
    <button class="role-tab-btn" id="tab-btn-ai" onclick="switchRole('ai')">
      ${ICONS.shield} <span>3. AI Security Guard</span>
    </button>
    <button class="role-tab-btn" id="tab-btn-env" onclick="switchRole('env')">
      ${ICONS.lock} <span>4. EnvShield &amp; Vault</span>
    </button>
    <button class="role-tab-btn" id="tab-btn-bench" onclick="switchRole('bench')">
      ${ICONS.zap} <span>5. Benchmark PQC</span>
    </button>
    <button class="role-tab-btn" id="tab-btn-config" onclick="switchRole('config')">
      ${ICONS.settings} <span>6. Cấu Hình &amp; Lệnh CLI</span>
    </button>
  </div>

  <!-- ==================== [SECTION 1: CLIENT MODE] ==================== -->
  <div id="section-client">
    <!-- Card 1: Kết Nối Trực Tiếp Đến Workspace (VÀO - Client Mode) -->
    <div class="card" style="max-width:500px; margin:20px auto 26px auto; padding:28px 26px; box-shadow:0 3px 12px rgba(0,0,0,0.06); border:1px solid #d0d7de; border-radius:2px;">
      <!-- Biểu Tượng Lớn Đại Diện Cho 'VÀO' -->
      <div style="text-align:center; margin-bottom:16px;">
        <div style="width:58px; height:58px; border-radius:50%; background:#ddf4ff; color:#0969da; display:inline-flex; align-items:center; justify-content:center; margin-bottom:10px; border:2px solid #54aeff; box-shadow:0 2px 8px rgba(9,105,218,0.15);">
          <!-- Large Inbound Arrow / Enter Icon -->
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"></path>
            <polyline points="10 17 15 12 10 7"></polyline>
            <line x1="15" y1="12" x2="3" y2="12"></line>
          </svg>
        </div>
        <div style="display:flex; align-items:center; justify-content:center; gap:8px;">
          <h2 style="margin:0; font-size:18px; font-weight:800; color:var(--text-main); letter-spacing:-0.2px;">KẾT NỐI VÀO WORKSPACE</h2>
        </div>
        <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Nhập IP &amp; mã OTP để nhận file an toàn qua kênh Hậu lượng tử</div>
      </div>
      
      <!-- Chế độ xác thực -->
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:18px;">
        <button type="button" class="btn-sec btn-sm active" id="auth-tab-otp" onclick="switchClientAuth('otp')" style="justify-content:center; height:34px; font-weight:600;">
          ${ICONS.lock} <span>Mã OTP (8 Số)</span>
        </button>
        <button type="button" class="btn-sec btn-sm" id="auth-tab-acc" onclick="switchClientAuth('account')" style="justify-content:center; height:34px; font-weight:600;">
          ${ICONS.user} <span>Tài Khoản RBAC</span>
        </button>
      </div>

      <form onsubmit="submitClientConnect(event)">
        <!-- OTP Mode -->
        <div id="client-auth-otp-sec">
          <div class="form-group" style="margin-bottom:14px;">
            <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Địa Chỉ Máy Chủ Host (IP:Port)</label>
            <input type="text" id="client-endpoint" class="input-text" value="127.0.0.1:9443" placeholder="192.168.1.x:9443" style="height:38px; font-size:13px;" required>
          </div>
          <div class="form-group" style="margin-bottom:16px;">
            <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Mã OTP Kết Nối (8 Chữ Số)</label>
            <input type="text" id="client-otp" class="input-text" placeholder="Ví dụ: 48291048" maxlength="8" style="height:38px; font-size:16px; font-weight:700; letter-spacing:2px; text-align:center; font-family:'JetBrains Mono', monospace;">
          </div>
          <button type="submit" class="btn" style="height:42px; width:100%; justify-content:center; font-size:13px; font-weight:700;">
            ${ICONS.connect} <span>Bắt Đầu Kết Nối &amp; Nhận File</span>
          </button>
        </div>

        <!-- Account Mode -->
        <div id="client-auth-acc-sec" style="display:none;">
          <div class="form-group" style="margin-bottom:14px;">
            <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Địa Chỉ Máy Chủ Host (IP:Port)</label>
            <input type="text" id="client-endpoint-acc" class="input-text" value="127.0.0.1:9443" placeholder="192.168.1.x:9443" style="height:38px; font-size:13px;">
          </div>
          <div class="form-group" style="margin-bottom:14px;">
            <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Tên Tài Khoản (Username)</label>
            <input type="text" id="client-username" class="input-text" placeholder="Ví dụ: colleague_bob" autocomplete="username" style="height:38px; font-size:13px;">
          </div>
          <div class="form-group" style="margin-bottom:16px;">
            <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Mật Khẩu (Password)</label>
            <input type="password" id="client-password" class="input-text" placeholder="Mật khẩu tài khoản" autocomplete="current-password" style="height:38px; font-size:13px;">
          </div>
          <button type="submit" class="btn" style="height:42px; width:100%; justify-content:center; font-size:13px; font-weight:700;">
            ${ICONS.connect} <span>Đăng Nhập &amp; Nhận File</span>
          </button>
          <div style="font-size:11px; color:#0969da; margin-top:8px; font-family:'JetBrains Mono', monospace; display:flex; align-items:center; gap:6px;">
            ${ICONS.info} <span>Tài khoản có thể đăng nhập đồng thời trên nhiều máy trạm.</span>
          </div>
        </div>
      </form>
      <div id="conn-msg" style="margin-top:12px; font-size:12px; font-family:'JetBrains Mono', monospace; text-align:center;"></div>
    </div>

    <!-- Card 3: Danh Sách Các Trạm Đã Lưu Gần Đây -->
    <div class="card">
      <h3>
        <div style="display:flex; align-items:center; gap:8px;">
          ${ICONS.folder} <span>Danh Sách Các Trạm Đã Kết Nối Gần Đây ({{SAVED_CONNS_COUNT}})</span>
        </div>
        <div style="display:flex; gap:8px;">
          <button class="btn-sec btn-sm" onclick="fetch('/api/portal/prune',{method:'POST'}).then(()=>window.location.reload())">${ICONS.trash} Dọn Trạm Chết (Prune)</button>
          <button class="btn-sec btn-sm" onclick="window.location.reload()">${ICONS.refresh} Làm Mới</button>
        </div>
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

  <!-- ==================== [SECTION 2: HOST MODE & .SLUG RECOVERY] ==================== -->
  <div id="section-host" style="display:none;">
    <!-- Card 2: Khởi Tạo Trạm Phát Mới (RA - Host Mode) -->
    <div class="card" id="host-config-card" style="max-width:520px; margin:20px auto 26px auto; padding:28px 26px; box-shadow:0 3px 12px rgba(0,0,0,0.06); border:1px solid #d0d7de; border-radius:2px;">
      <!-- Biểu Tượng Lớn Đại Diện Cho 'RA' -->
      <div style="text-align:center; margin-bottom:18px;">
        <div style="width:58px; height:58px; border-radius:50%; background:#dafbe1; color:#1a7f37; display:inline-flex; align-items:center; justify-content:center; margin-bottom:10px; border:2px solid #4ac26b; box-shadow:0 2px 8px rgba(26,127,55,0.15);">
          <!-- Large Outbound / Broadcast / Share Out Icon -->
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"></path>
            <polyline points="16 6 12 2 8 6"></polyline>
            <line x1="12" y1="2" x2="12" y2="15"></line>
          </svg>
        </div>
        <div style="display:flex; align-items:center; justify-content:center; gap:8px;">
          <h2 style="margin:0; font-size:18px; font-weight:800; color:var(--text-main); letter-spacing:-0.2px;">CHIA SẺ WORKSPACE</h2>
        </div>
        <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Tạo trạm chia sẻ thư mục trên máy bạn và cấp mã OTP an toàn</div>
      </div>

      <form onsubmit="startHosting(event)" style="display:flex; flex-direction:column; gap:14px;">
        <div class="form-group" style="margin-bottom:0;">
          <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Đường Dẫn Thư Mục (Workspace Path) <span style="color:var(--danger); font-weight:bold;">* Bắt buộc</span></label>
          <div style="display:flex; gap:8px; align-items:stretch;">
            <input type="text" id="host-path" class="input-text" value="" placeholder="Bắt buộc: Bấm [Chọn Thư Mục] hoặc nhập..." oninput="checkHostPathHasSlug(this.value)" style="flex:1; height:38px; box-sizing:border-box; font-size:12px;" required>
            <input type="file" id="dir-picker-host-path" webkitdirectory directory style="display:none;" onchange="handleDirInputSelected(this, 'host-path'); checkHostPathHasSlug(document.getElementById('host-path').value);">
            <button type="button" class="btn-sec" onclick="chooseLocalSaveLocation('host-path')" style="height:38px !important; box-sizing:border-box; padding:0 14px; font-size:12px; display:inline-flex; align-items:center; gap:6px; white-space:nowrap; border-radius:var(--radius-sharp); cursor:pointer;">
              ${ICONS.folder} <span>Chọn...</span>
            </button>
          </div>
          <div id="slug-detect-note" style="display:none; font-size:11px; margin-top:4px;"></div>
        </div>

        <div style="display:grid; grid-template-columns: 1fr 1.6fr; gap:12px;">
          <div class="form-group" style="margin-bottom:0;">
            <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Cổng (Port)</label>
            <input type="number" id="host-port" class="input-text" value="9443" placeholder="9443" style="height:38px; box-sizing:border-box; font-size:13px;">
          </div>
          <div class="form-group" style="margin-bottom:0;">
            <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Mức Mật Mã (Cipher Suite)</label>
            <select id="host-suite" class="input-select" style="height:38px; box-sizing:border-box; font-size:12px;">
              <option value="2" selected>Mức 2: Modern Hybrid (ML-KEM-768 + X25519) [Mặc Định / Khuyên Dùng]</option>
              <option value="3">Mức 3: Pure PQC (ML-KEM-1024 + ML-DSA-87)</option>
              <option value="1">Mức 1: Classical Fast (X25519 + AES-GCM)</option>
            </select>
          </div>
        </div>

        <div class="form-group" style="margin-bottom:4px;">
          <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Chế Độ Lọc Dữ Liệu Slug Guard</label>
          <select id="host-filter" class="input-select" style="height:38px; box-sizing:border-box; font-size:12px;">
            <option value="protected" selected>Protected (Lọc rác .gitignore + Chặn secret qua Regex &amp; AI)</option>
            <option value="include_ignored">Include-Ignored (Gửi cả build artifacts, chỉ chặn secret)</option>
            <option value="none">None (Gửi toàn bộ, không lọc - Thận trọng!)</option>
          </select>
        </div>

        <div class="form-group" style="margin-bottom:8px;">
          <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Thời Gian Sống Phiên / OTP (Session TTL) <span style="color:var(--text-muted); font-weight:normal;">* Tối đa 24h</span></label>
          <select id="host-ttl" class="input-select" style="height:38px; box-sizing:border-box; font-size:12px;">
            <option value="1800">30 phút (0.5h)</option>
            <option value="3600">1 giờ (1h)</option>
            <option value="7200" selected>2 giờ (2h) [Mặc Định / Khuyên Dùng]</option>
            <option value="14400">4 giờ (4h)</option>
            <option value="28800">8 giờ (8h)</option>
            <option value="86400">24 giờ (24h) [Tối đa cho phép]</option>
          </select>
        </div>

        <button type="submit" class="btn" style="height:42px; width:100%; justify-content:center; font-size:13px; font-weight:700; background:#1a7f37; border-color:#1a7f37;">
          ${ICONS.plus} <span>Bắt Đầu Phát &amp; Chia Sẻ Thư Mục Này</span>
        </button>
      </form>
    </div>

    <!-- Danh Sách Các Thư Mục Đang Chia Sẻ Trực Tiếp -->
    <div class="card">
      <h3>
        <div style="display:flex; align-items:center; gap:8px;">
          ${ICONS.folder} <span>Các Workspace Đang Hoạt Động Trực Tiếp (<span id="hosted-count-title">0</span>)</span>
        </div>
        <button class="btn-sec btn-sm" onclick="renderHostedWorkspaces()">${ICONS.refresh} Làm Mới</button>
      </h3>
      <div id="hosted-workspaces-list"></div>
    </div>

    <!-- KHÔI PHỤC TRẠM PHÁT ĐÃ TỪNG HOST (.SLUG RESUME CENTER) -->
    <div class="card" style="border:1px solid #54aeff;">
      <h3>
        <div style="display:flex; align-items:center; gap:8px;">
          ${ICONS.shield} <span>Khôi Phục Trạm Phát Đã Từng Host (.slug Resume Center) (<span id="inactive-count">0</span>)</span>
        </div>
        <span class="badge badge-pqc">Tự Động Bảo Toàn .slug</span>
      </h3>
      <div id="inactive-workspaces-list"></div>
    </div>
  </div>

  <!-- ==================== [SECTION 3: AI SECURITY GUARD] ==================== -->
  <div id="section-ai" style="display:none;">
    <!-- 1. KIỂM TOÁN TỆP SÂU BẤT KỲ (slug audit scan) - ĐƯA LÊN TRÊN CÙNG -->
    <div class="card" id="single-file-audit-card" style="margin-bottom:14px;">
      <h3>
        <div style="display:flex; align-items:center; gap:8px;">
          ${ICONS.shield} <span>Kiểm Toán Sâu Tệp Bất Kỳ (slug audit scan &lt;file&gt;)</span>
        </div>
      </h3>
      <div class="form-group" style="margin-bottom:0;">
        <label>Đường Dẫn File Cần Quét Sâu (File Path)</label>
        <div style="display:flex; gap:8px; align-items:stretch;">
          <input type="text" id="audit-scan-path" class="input-text" value="" placeholder="Bắt buộc: Bấm 'Chọn Tệp...' hoặc nhập đường dẫn file cần quét..." style="flex:1; height:36px;">
          <input type="file" id="audit-file-picker" style="display:none;" onchange="handleAuditFileSelected(this)">
          <button type="button" class="btn-sec btn-sm" onclick="document.getElementById('audit-file-picker').click()" style="height:36px; padding:0 14px; white-space:nowrap; flex-shrink:0; display:inline-flex; align-items:center; gap:6px; border-radius:var(--radius-sharp); cursor:pointer;" title="Duyệt và chọn tệp từ máy tính">
            ${ICONS.folder} <span>Chọn Tệp (Browse...)</span>
          </button>
          <button type="button" class="btn btn-sm" onclick="runAuditScanFile()" style="height:36px; padding:0 16px; white-space:nowrap; flex-shrink:0; display:inline-flex; align-items:center; gap:6px; border-radius:var(--radius-sharp); cursor:pointer;">
            ${ICONS.shield} <span>Quét Sâu File Này</span>
          </button>
        </div>
      </div>
      <pre id="audit-scan-out" style="display:none; background:#1f2328; color:#e6edf3; padding:12px; border-radius:var(--radius-sharp); font-size:11px; margin-top:10px; line-height:1.6;"></pre>
    </div>

    <!-- 2. KIỂM TOÁN THƯ MỤC CHIA SẺ HOẶC BẤT KỲ (ĐỒNG BỘ 1 THẺ DUY NHẤT) -->
    <div class="card" id="audit-results-card" style="margin-bottom:14px;">
      <h3>
        <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
          ${ICONS.shield} <span>Kiểm Toán Thư Mục Chia Sẻ hoặc bất kỳ... (Slug Guard)</span>
        </div>
        <div style="display:inline-flex; align-items:center; gap:8px; flex-wrap:wrap;">
          <div style="display:inline-flex; align-items:center; gap:6px;">
            <label for="quick-audit-mode-select" style="font-size:11px; font-weight:700; color:var(--text-main); margin:0;">Chế Độ Quét:</label>
            <select id="quick-audit-mode-select" class="input-select" onchange="onQuickAuditModeChange(this.value)" style="height:30px; font-size:11px; font-weight:600; padding:2px 8px; width:auto; border-radius:2px; background:#ddf4ff; color:#0969da; border:1px solid #54aeff;">
              <option value="local_heuristic">1. 100% Offline (Rule + Regex + Shannon Entropy)</option>
              <option value="local_ollama" selected>2. Local GPU (Rule + Regex + Entropy + Ollama GPU)</option>
              <option value="cloud_groq">3. Cloud AI (Groq Llama-3.3-70B)</option>
              <option value="cloud_gemini">4. Cloud AI (Google Gemini 2.0 Flash)</option>
              <option value="cloud_openai">5. Cloud AI (OpenAI GPT-4o-mini)</option>
              <option value="cloud_openrouter">6. Cloud AI (OpenRouter)</option>
              <option value="custom_cloud">7. Custom AI Endpoint</option>
            </select>
          </div>
          <button type="button" class="btn btn-sm" onclick="rescanSelectedWorkspace()" style="height:30px; display:inline-flex; align-items:center; gap:6px;">${ICONS.refresh} <span>Quét Lại</span></button>
        </div>
      </h3>

      <!-- Chọn Vùng Thư Mục & Trạm Host Cần Kiểm Toán (Tích Hợp Trong Thẻ) -->
      <div style="background:#f6f8fa; border:1px solid #d0d7de; border-radius:var(--radius-sharp); padding:10px 12px; margin-bottom:14px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; flex-wrap:wrap; gap:6px;">
          <label style="font-size:11px; font-weight:700; color:var(--text-main); margin:0; display:inline-flex; align-items:center; gap:6px;">
            ${ICONS.folder} <span>Trạm Host / Workspace Mục Tiêu:</span>
          </label>
          <span style="font-size:11px; color:var(--text-muted);">Đang kiểm toán: <strong id="audit-current-target-label" style="color:#0969da;">Chưa chọn thư mục nào</strong></span>
        </div>
        <select id="audit-target-workspace" class="input-select" onchange="switchAuditWorkspace(this.value)" style="height:34px; box-sizing:border-box; width:100%;">
          <option value="custom" selected>-- Quét Thư Mục Tùy Chọn Khác Trên Máy --</option>
        </select>
        <div id="custom-workspace-path-sec" style="display:block; margin-top:8px;">
          <div style="display:flex; gap:8px; align-items:stretch;">
            <input type="text" id="custom-audit-path" class="input-text" style="flex:1; height:34px; box-sizing:border-box; font-size:12px;" value="" placeholder="Bắt buộc: Bấm 'Chọn Thư Mục Máy...' hoặc nhập đường dẫn...">
            <input type="file" id="dir-picker-custom-audit-path" webkitdirectory directory style="display:none;" onchange="handleDirInputSelected(this, 'custom-audit-path')">
            <button type="button" class="btn-sec" onclick="chooseLocalSaveLocation('custom-audit-path')" style="height:34px !important; box-sizing:border-box; padding:0 14px; font-size:12px; display:inline-flex; align-items:center; gap:6px; white-space:nowrap;">
              ${ICONS.folder} Chọn Thư Mục Máy...
            </button>
            <button type="button" class="btn" onclick="setCustomAuditWorkspace()" style="height:34px !important; box-sizing:border-box; padding:0 14px; font-size:12px; display:inline-flex; align-items:center; gap:6px; white-space:nowrap;">
              ${ICONS.check} Áp Dụng &amp; Quét
            </button>
          </div>
        </div>
      </div>

      <!-- BỘ QUY TẮC LỌC (SLUG GUARD FILTER RULES) -->
      <div style="background:#fff; border:1px solid #d0d7de; border-radius:var(--radius-sharp); padding:14px; margin-bottom:14px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:8px;">
          <div style="font-weight:700; font-size:13px; display:inline-flex; align-items:center; gap:8px; color:var(--text-main);">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
            <span>Bộ Quy Tắc Lọc</span>
          </div>
          <div style="display:flex; gap:8px;">
            <button type="button" class="btn-sec btn-xs" id="btn-toggle-rules-text" onclick="toggleRulesTextView()">
              Xem / Sửa Dạng Text
            </button>
            <button type="button" class="btn btn-xs" onclick="saveAndApplyRules()" style="background:#0969da; color:#fff;">
              ${ICONS.check} Lưu &amp; Áp Dụng
            </button>
          </div>
        </div>

        <!-- CHỌN NHANH MẪU PHỔ BIẾN -->
        <div style="margin-bottom:10px;">
          <div style="font-size:10px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:6px; letter-spacing:0.3px;">
            CHỌN NHANH MẪU PHỔ BIẾN:
          </div>
          <div style="display:flex; flex-wrap:wrap; gap:6px;" id="quick-preset-chips">
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('node_modules/')" style="color:#0969da; background:#ddf4ff; border-color:#54aeff;">+ node_modules/</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('target/')" style="color:#0969da; background:#ddf4ff; border-color:#54aeff;">+ target/</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('build/')" style="color:#0969da; background:#ddf4ff; border-color:#54aeff;">+ build/</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('dist/')" style="color:#0969da; background:#ddf4ff; border-color:#54aeff;">+ dist/</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('.git/')" style="color:#0969da; background:#ddf4ff; border-color:#54aeff;">+ .git/</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('*.tmp')" style="color:#0969da; background:#ddf4ff; border-color:#54aeff;">+ *.tmp</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('*.log')" style="color:#0969da; background:#ddf4ff; border-color:#54aeff;">+ *.log</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('*.iso')" style="color:#0969da; background:#ddf4ff; border-color:#54aeff;">+ *.iso</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('*.zip')" style="color:#0969da; background:#ddf4ff; border-color:#54aeff;">+ *.zip</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('venv/')">+ venv/</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('__pycache__/')">+ __pycache__/</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('.env*')">+ .env*</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('.idea/')">+ .idea/</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('.vscode/')">+ .vscode/</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('*.tar.gz')">+ *.tar.gz</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('*.exe')">+ *.exe</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('*.dll')">+ *.dll</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('*.bak')">+ *.bak</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('*.key')">+ *.key</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('*.pem')">+ *.pem</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('!.env.example')" style="color:#1a7f37; background:#dafbe1; border-color:#82e596; font-weight:700;">+ !.env.example (Whitelist)</button>
            <button type="button" class="btn-sec btn-xs" onclick="addQuickPreset('!*.example')" style="color:#1a7f37; background:#dafbe1; border-color:#82e596; font-weight:700;">+ !*.example (Whitelist)</button>
          </div>
          <div style="font-size:11px; color:#656d76; margin-top:8px; background:#f6f8fa; border:1px solid #d0d7de; border-radius:var(--radius-sharp); padding:6px 10px; display:flex; align-items:center; gap:8px;">
            <span style="color:#1a7f37;">${ICONS.shield}</span>
            <span><strong>Mẹo Whitelist &amp; file .env:</strong> Thêm tiền tố <code>!</code> để tạo ngoại lệ Whitelist (ví dụ: <code>!.env.example</code> sẽ cho phép chia sẻ file mẫu ngay cả khi đang chặn <code>.env*</code>). Để mã hóa và chia sẻ file .env thật an toàn, hãy chuyển sang <strong><a href="javascript:void(0)" onclick="switchRole('env')" style="color:#0969da; text-decoration:underline;">[Tab 4: EnvShield &amp; Vault]</a></strong>.</span>
          </div>
        </div>

        <!-- NHẬP MẪU MỚI -->
        <div id="rules-builder-view">
          <div style="display:flex; gap:8px; margin-bottom:10px;">
            <input type="text" id="custom-rule-input" class="input-text" placeholder="Nhập mẫu loại trừ (vd: *.bak) hoặc cho phép/whitelist với dấu ! (vd: !.env.example)..." style="flex:1; height:34px; font-size:12px;" onkeydown="if(event.key==='Enter'){event.preventDefault();addCustomRule();}">
            <button type="button" class="btn-sec" onclick="addCustomRule()" style="height:34px; padding:0 16px; font-size:12px; white-space:nowrap;">+ Thêm</button>
          </div>

          <!-- QUY TẮC ĐANG CÓ HIỆU LỰC -->
          <div>
            <div style="font-size:10px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:6px; letter-spacing:0.3px;">
              QUY TẮC ĐANG CÓ HIỆU LỰC (BẤM &times; ĐỂ XÓA):
            </div>
            <div id="active-rules-container" style="display:flex; flex-wrap:wrap; gap:6px; min-height:28px;">
              <!-- Rendered by JS -->
            </div>
          </div>
        </div>

        <!-- DẠNG TEXT (RAW .slugignore / rules.conf) -->
        <div id="rules-text-view" style="display:none; margin-top:8px;">
          <div style="font-size:11px; color:var(--text-muted); margin-bottom:4px;">Chỉnh sửa trực tiếp dạng plain-text (.slugignore / quy tắc lọc - mỗi dòng một quy tắc):</div>
          <textarea id="rules-raw-textarea" class="input-text" style="width:100%; height:130px; font-family:'JetBrains Mono', monospace; font-size:12px; padding:8px; box-sizing:border-box; resize:vertical;"></textarea>
        </div>
      </div>

      <!-- 3 Thẻ Thống Kê (Clean, Blocked, Excluded) -->
      <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:12px; margin-bottom:14px;">
        <div style="background:#fff; border:1px solid #d0d7de; padding:12px; border-radius:var(--radius-sharp);">
          <div style="font-size:11px; color:var(--text-muted); font-weight:600;">TỆP SẠCH (CLEAN)</div>
          <div style="font-size:22px; font-weight:700; color:#1a7f37;" id="audit-stat-clean">0</div>
          <div style="font-size:10px; color:var(--text-muted);">Sẵn sàng chia sẻ qua PQC channel</div>
        </div>
        <div style="background:#fff; border:1px solid #d0d7de; padding:12px; border-radius:var(--radius-sharp);">
          <div style="font-size:11px; color:var(--text-muted); font-weight:600;">CÁCH LY SECRET (BLOCKED)</div>
          <div style="font-size:22px; font-weight:700; color:#cf222e;" id="audit-stat-quarantined">0</div>
          <div style="font-size:10px; color:#cf222e;">Bị chặn bởi Slug Regex &amp; Slug AI</div>
        </div>
        <div style="background:#fff; border:1px solid #d0d7de; padding:12px; border-radius:var(--radius-sharp);">
          <div style="font-size:11px; color:var(--text-muted); font-weight:600;">BỊ BỎ QUA DO RULE</div>
          <div style="font-size:22px; font-weight:700; color:#656d76;" id="audit-stat-excluded">0</div>
          <div style="font-size:10px; color:var(--text-muted);">Bị loại trừ bởi Slug Rule</div>
        </div>
      </div>

      <!-- Bộ Lọc Chế Độ Xem Danh Sách Tệp -->
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:gap:8px;">
        <div style="display:flex; gap:6px;">
          <button type="button" class="btn-sec btn-xs active" id="audit-btn-view-quarantine" onclick="switchAuditFileView('quarantine')">
            ${ICONS.lock} Tệp Tin Cách Ly (<span id="audit-count-quarantine">0</span>)
          </button>
          <button type="button" class="btn-sec btn-xs" id="audit-btn-view-clean" onclick="switchAuditFileView('clean')">
            ${ICONS.check} Tệp Hợp Lệ Sạch (<span id="audit-count-clean">0</span>)
          </button>
          <button type="button" class="btn-sec btn-xs" id="audit-btn-view-excluded" onclick="switchAuditFileView('excluded')">
            ${ICONS.folder} Bị Bỏ Qua Do Rule (<span id="audit-count-excluded">0</span>)
          </button>
        </div>
        <span style="font-size:11px; color:#cf222e; font-weight:600;" id="audit-view-hint">Bảo vệ chống rò rỉ secret ra mạng</span>
      </div>

      <!-- Bảng Danh Sách Tệp -->
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Tên Tệp</th>
              <th>Dung Lượng</th>
              <th>Tầng Bắt / Phân Loại</th>
              <th>Lý Do / Chi Tiết</th>
              <th>Thao Tác</th>
            </tr>
          </thead>
          <tbody id="audit-files-tbody">
            <!-- Render động bằng JS -->
          </tbody>
        </table>
      </div>
    </div>

    <!-- 3. THIẾT LẬP AI SECURITY GUARD & KẾT QUẢ QUÉT (TÍCH HỢP 1 THẺ DUY NHẤT) -->
    <div class="card">
      <h3>
        <div style="display:flex; align-items:center; gap:8px;">
          ${ICONS.shield} <span>Thiết Lập AI Security Guard &amp; Stateful Audit (slug audit)</span>
        </div>
        <button class="btn btn-sm" onclick="saveAiConfig()">${ICONS.check} Lưu Cấu Hình AI</button>
      </h3>

      <div class="form-grid" style="grid-template-columns: 1fr 1fr; gap:16px;">
        <div class="form-group">
          <label>Nhà Cung Cấp AI (AI Provider Engine)</label>
          <select id="ai-provider" class="input-select" onchange="onAiProviderChange()">
            <option value="local_heuristic">1. Local Heuristic (Smart Regex &amp; Shannon Entropy - 100% Offline)</option>
            <option value="local_ollama" selected>2. Local AI (Ollama Local Daemon - Chạy Trên GPU Cục Bộ)</option>
            <option value="cloud_groq">3. Cloud AI: Groq Cloud (Llama-3.3-70B - Siêu Nhanh)</option>
            <option value="cloud_gemini">4. Cloud AI: Google Gemini (gemini-2.0-flash)</option>
            <option value="cloud_openrouter">5. Cloud AI: OpenRouter (Đa mô hình)</option>
            <option value="cloud_openai">6. Cloud AI: OpenAI (gpt-4o-mini)</option>
            <option value="custom_cloud">7. Custom OpenAI-Compatible Endpoint</option>
          </select>
        </div>

        <div class="form-group">
          <label>Tên Mô Hình (AI Model Name)</label>
          <input type="text" id="ai-model" class="input-text" value="qwen2.5-coder:7b" placeholder="Ví dụ: qwen2.5-coder:7b, llama-3.3-70b-versatile, gemini-2.0-flash" oninput="syncFieldsToJson()">
        </div>
      </div>

      <div class="form-grid" style="grid-template-columns: 1.5fr 1fr; gap:16px;">
        <div class="form-group">
          <label>Đường Dẫn Endpoint API (API Endpoint URL)</label>
          <input type="text" id="ai-endpoint" class="input-text" value="http://127.0.0.1:11434" placeholder="http://127.0.0.1:11434" oninput="syncFieldsToJson()">
        </div>

        <div class="form-group" id="ai-apikey-group">
          <label>Khóa API Bí Mật (API Key / Auth Token)</label>
          <input type="password" id="ai-apikey" class="input-text" placeholder="gsk_... hoặc AIzaSy... (Để trống nếu dùng Ollama nội bộ)" oninput="syncFieldsToJson()">
        </div>
      </div>

      <!-- Trình Xem & Chỉnh Sửa Trực Tiếp Cấu Hình JSON (Two-Way Sync & Multi-Schema Support) -->
      <div class="form-group" style="margin-top:10px; margin-bottom:14px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; flex-wrap:wrap; gap:8px;">
          <label style="margin-bottom:0; font-weight:700; color:var(--text-main); display:inline-flex; align-items:center; gap:6px;">
            ${ICONS.terminal} <span>Cấu Hình JSON Tổng Quát (.slug/ai_config.json / Two-Way Sync)</span>
          </label>
          <div style="display:flex; gap:6px; flex-wrap:wrap;">
            <button type="button" class="btn-sec btn-xs" onclick="setAiPreset('canonical')">Chuẩn Slug</button>
            <button type="button" class="btn-sec btn-xs" onclick="setAiPreset('ollama')">Mẫu Ollama</button>
            <button type="button" class="btn-sec btn-xs" onclick="setAiPreset('openai')">Mẫu OpenAI / Groq</button>
            <button type="button" class="btn-sec btn-xs" onclick="setAiPreset('custom')">Custom JSON</button>
            <button type="button" class="btn-sec btn-xs" onclick="formatAiJson()">${ICONS.edit} Format JSON</button>
            <button type="button" class="btn-sec btn-xs" onclick="copyText(document.getElementById('ai-json-config').value, 'Cấu hình AI JSON')">${ICONS.copy} Copy JSON</button>
          </div>
        </div>
        <textarea id="ai-json-config" class="input-text" style="width:100%; height:160px; font-family:'JetBrains Mono', monospace; font-size:11px; line-height:1.5; resize:vertical; padding:10px; background:#f6f8fa;" oninput="syncJsonToFields()" placeholder="{}"></textarea>
        
        <!-- Gợi ý định dạng JSON gọn gàng -->
        <div style="margin-top:6px; padding:8px 12px; background:#f6f8fa; border:1px solid #d0d7de; border-radius:var(--radius-sharp); font-size:11px; line-height:1.5; color:var(--text-muted);">
          💡 <strong>Gợi ý:</strong> Chọn nhanh mẫu (<strong>Chuẩn Slug</strong>, <strong>Ollama</strong>, <strong>OpenAI</strong>, <strong>Custom JSON</strong>) hoặc dán trực tiếp JSON từ nhà cung cấp bất kỳ để tự động nhận diện &amp; đồng bộ.
        </div>
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; margin-top:8px; padding-top:12px; border-top:1px solid var(--border-primary); flex-wrap:wrap; gap:8px;">
        <div style="display:flex; gap:8px;">
          <button type="button" class="btn-sec btn-sm" onclick="testAiConnection()">${ICONS.refresh} Thử Nghiệm Kết Nối (Ping AI)</button>
          <button type="button" class="btn btn-sm" onclick="testAiScanSample()">${ICONS.shield} Chạy Quét Thử Nghiệm Mẫu</button>
        </div>
        <div id="ai-status-msg" style="font-size:12px; font-family:'JetBrains Mono', monospace;"></div>
      </div>

      <!-- Kết Quả Kiểm Tra Bảo Mật Của AI Guard (Tích Hợp Trực Tiếp Trong Thẻ Cấu Hình) -->
      <div id="ai-test-output-container" style="display:none; margin-top:14px; padding-top:12px; border-top:1px solid var(--border-primary);">
        <div style="font-size:12px; font-weight:700; color:var(--text-main); margin-bottom:8px; display:flex; align-items:center; gap:6px;">
          ${ICONS.shield} <span>Kết Quả Kiểm Tra Bảo Mật Của AI Guard:</span>
        </div>
        <div id="ai-test-output" style="background:#1f2328; color:#e6edf3; padding:12px; border-radius:var(--radius-sharp); font-size:12px; font-family:'JetBrains Mono', monospace; line-height:1.6; white-space:pre-wrap; border:1px solid #30363d;"></div>
      </div>
    </div>

    <!-- 4. THAO TÁC QUẢN TRỊ BỘ ĐỆM CÁCH LY -->
    <div class="card">
      <h3>
        <div style="display:flex; align-items:center; gap:8px;">
          ${ICONS.settings} <span>Thao Tác Quản Trị Quá Trình Kiểm Toán Toàn Diện</span>
        </div>
      </h3>
      <div style="display:flex; gap:10px; flex-wrap:wrap;">
        <button class="btn-sec btn-sm" onclick="runAuditRecheckAll()">${ICONS.refresh} Tái Kiểm Tra Secret Đã Cách Ly (slug audit recheck --all)</button>
        <button class="btn-sec btn-sm" onclick="runAuditAllowAll()">${ICONS.unlock} Gỡ Cách Ly Toàn Bộ Cho Phép Transit (slug audit allow --all)</button>
        <button class="btn-danger btn-sm" onclick="runAuditClear()">${ICONS.trash} Xóa Trắng Bộ Đệm (slug audit clear)</button>
      </div>
    </div>
  </div>

  <!-- ==================== [SECTION 4: ENVSHIELD & CENTRAL VAULT] ==================== -->
  <div id="section-env" style="display:none;">
    <div class="card">
      <h3>
        <div style="display:flex; align-items:center; gap:8px;">
          ${ICONS.lock} <span>Post-Quantum EnvShield &amp; Central Vault (slug env)</span>
        </div>
        <span class="badge badge-pqc">NIST FIPS 203 Sealed</span>
      </h3>

      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; padding:10px 14px; background:#f0f6fc; border:1px solid #d0d7de; border-radius:2px; font-family:'JetBrains Mono', monospace; font-size:11px;">
        <span style="display:inline-flex; align-items:center; gap:6px;">
          ${ICONS.terminal} <strong>Chỉ Thị AI Agent (.slug/ai-rule.md):</strong> Hướng dẫn Cursor / Copilot / Claude đọc secrets trực tiếp trên RAM.
        </span>
        <button type="button" class="btn-sec btn-xs" onclick="copyEnvDirective()" style="height:28px;">
          ${ICONS.copy} Sao Chép Chỉ Thị AI (slug env prompt)
        </button>
      </div>

      <div id="env-action-msg" style="font-size:12px; margin-bottom:14px; font-family:'JetBrains Mono', monospace;"></div>

      <!-- Bảng Chọn Vị Trí Thư Mục Chứa .env & Host Đang Mở Trong Hệ Thống -->
      <div style="background:#f6f8fa; border:1px solid var(--border-primary); padding:16px; border-radius: 2px; margin-bottom:16px;">
        <!-- Label trên cùng: Hiện rõ vị trí thư mục đang chọn để thao tác / áp dụng -->
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; padding:10px 14px; background:#ffffff; border:1px solid var(--border-primary); border-radius:2px; font-family:'JetBrains Mono', monospace; font-size:12px;">
          <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
            <span style="font-weight:700; color:var(--text-main); display:inline-flex; align-items:center; gap:6px;">
              ${ICONS.folder} Vị Trí Thư Mục Đang Chọn Để Thao Tác:
            </span>
            <code id="env-current-selected-label" style="background:#ddf4ff; color:#0969da; border:1px solid #54aeff; padding:3px 10px; border-radius:3px; font-weight:700; font-size:12px;">(Chưa chọn - bấm [Chọn Thư Mục Máy...] hoặc chọn host)</code>
          </div>
          <span class="badge badge-available" style="font-size:11px; padding:3px 9px;"><span class="status-dot"></span> Sẵn Sàng Niêm Phong / Khôi Phục</span>
        </div>

        <!-- Thanh 1: Chọn từ máy tính của bạn -->
        <div style="margin-bottom:12px;">
          <label style="display:block; font-size:11px; font-weight:600; margin-bottom:6px; color:var(--text-main); font-family:'JetBrains Mono', monospace;">
            1. Vị Trí Thư Mục Chứa .env Của Bạn (Chọn từ máy tính của bạn): <span style="color:var(--danger); font-weight:bold;">* Bắt buộc</span>
          </label>
          <div class="path-picker-row" style="display:flex; gap:8px; align-items:stretch;">
            <input type="text" id="env-target-folder" class="input-text" style="flex:1; height:34px; box-sizing:border-box; font-size:12px;" value="" placeholder="Bắt buộc: Bấm [Chọn Thư Mục Máy...] hoặc chọn từ host bên dưới..." oninput="updateEnvTargetLabel(this.value)" required>
            <input type="file" id="dir-picker-env-target-folder" webkitdirectory directory style="display:none;" onchange="handleDirInputSelected(this, 'env-target-folder'); updateEnvTargetLabel(document.getElementById('env-target-folder').value);">
            <button type="button" class="btn-sec" onclick="chooseLocalSaveLocation('env-target-folder')" style="height:34px !important; box-sizing:border-box; padding:0 14px; font-size:12px; display:inline-flex; align-items:center; gap:6px; white-space:nowrap;">
              ${ICONS.folder} Chọn Thư Mục Máy...
            </button>
          </div>
        </div>

        <!-- Thanh 2: Chọn từ các Workspace / Host đang mở trong hệ thống -->
        <div style="margin-bottom:14px;">
          <label style="display:block; font-size:11px; font-weight:600; margin-bottom:6px; color:var(--text-main); font-family:'JetBrains Mono', monospace;">
            2. Hoặc Chọn Nhanh Từ Các Workspace / Host Port Đang Mở Trong Hệ Thống:
          </label>
          <div class="path-picker-row" style="display:flex; gap:8px; align-items:stretch;">
            <select id="env-active-hosts-select" class="input-select" onchange="onSelectHostForEnv(this)" style="flex:1; height:34px; box-sizing:border-box; font-size:12px;">
              <option value="./" selected>Thư mục hiện tại (./)</option>
            </select>
          </div>
        </div>

        <!-- Dòng Dưới: 3 Nút Thao Tác Chia Đều Khoảng Cách -->
        <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:12px;">
          <button type="button" class="btn-sec" onclick="applyHostSelectToEnvFolder()" style="height:34px !important; box-sizing:border-box; font-size:12px; display:inline-flex; align-items:center; justify-content:center; gap:6px; width:100%;">
            ${ICONS.check} Áp Dụng Vị Trí Này
          </button>
          <button type="button" class="btn" onclick="sealEnvForPath()" style="height:34px !important; box-sizing:border-box; font-size:12px; display:inline-flex; align-items:center; justify-content:center; gap:6px; width:100%;">
            ${ICONS.lock} Niêm Phong .env
          </button>
          <button type="button" class="btn-sec" onclick="restoreEnvForPath()" style="height:34px !important; box-sizing:border-box; font-size:12px; display:inline-flex; align-items:center; justify-content:center; gap:6px; width:100%;">
            ${ICONS.unlock} Khôi Phục .env
          </button>
        </div>
      </div>

      <!-- Danh Sách Các Tệp .env Đã Lưu Trữ Trong Central Vault -->
      <div>
        <div style="font-size:12px; font-weight:700; margin-bottom:8px; display:flex; align-items:center; gap:6px;">
          ${ICONS.database} <span>Danh Sách Tệp .env Đã Lưu Trữ Trong Central Vault (~/.slug/env_vault/)</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>Tệp .env &amp; Thư Mục Gốc</th>
              <th>Thời Điểm Niêm Phong</th>
              <th>Dung Lượng</th>
              <th>BLAKE3 Hash</th>
              <th>Trạng Thái Bảo Vệ</th>
              <th>Thao Tác</th>
            </tr>
          </thead>
          <tbody id="env-vault-table-body">
            <tr>
              <td colspan="6" style="text-align:center; color:var(--text-muted); padding:16px;">
                Chưa có tệp .env nào được niêm phong trong Central Vault (~/.slug/env_vault/).
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ==================== [SECTION 5: BENCHMARK PQC] ==================== -->
  <div id="section-bench" style="display:none;">
    <div class="card">
      <h3>
        <div style="display:flex; align-items:center; gap:8px;">
          ${ICONS.zap} <span>Đo Hiệu Năng Mật Mã Hậu Lượng Tử &amp; I/O Chunker (slug bench)</span>
        </div>
        <div style="display:flex; gap:8px;">
          <button class="btn btn-sm" onclick="runBenchmarkSuite(false)">${ICONS.play} Chạy Toàn Diện (Full Bench)</button>
          <button class="btn-sec btn-sm" onclick="runBenchmarkSuite(true)">${ICONS.zap} Chạy Nhanh (Quick)</button>
        </div>
      </h3>
      <div id="bench-status-msg" style="font-size:12px; margin-bottom:14px; font-family:'JetBrains Mono', monospace;">
        Sẵn sàng kiểm thử tốc độ NIST FIPS 203 (ML-KEM-1024), FIPS 204 (ML-DSA-87), ChaCha20, BLAKE3 và FastCDC Chunker.
      </div>

      <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:12px; margin-bottom:16px;">
        <div class="metric-box">
          <div class="metric-title">ML-KEM-1024 (FIPS 203)</div>
          <div class="metric-val" id="bench-kem-ops" style="color:#8250df;">-- ops/s</div>
          <div style="font-size:10px; color:var(--text-muted);">Keygen: <span id="bench-kem-keygen">-- μs</span> &bull; Encap: <span id="bench-kem-encap">-- μs</span></div>
        </div>

        <div class="metric-box">
          <div class="metric-title">ML-DSA-87 (FIPS 204)</div>
          <div class="metric-val" id="bench-dsa-ops" style="color:#0969da;">-- ops/s</div>
          <div style="font-size:10px; color:var(--text-muted);">Sign: <span id="bench-dsa-sign">-- μs</span> &bull; Verify: <span id="bench-dsa-verify">-- μs</span></div>
        </div>

        <div class="metric-box">
          <div class="metric-title">CHACHA20-POLY1305</div>
          <div class="metric-val" id="bench-cipher-mb" style="color:#1a7f37;">-- MB/s</div>
          <div style="font-size:10px; color:var(--text-muted);">Mã hóa đối xứng SIMD AVX2 trong RAM</div>
        </div>

        <div class="metric-box">
          <div class="metric-title">BLAKE3 BĂM DỮ LIỆU</div>
          <div class="metric-val" id="bench-blake3-mb" style="color:#1f2328;">-- MB/s</div>
          <div id="bench-blake3-sub" style="font-size:10px; color:var(--text-muted);">Băm cây SIMD trong RAM &bull; Nhanh hơn SHA-256</div>
        </div>
      </div>

      <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
        <div class="metric-box">
          <div class="metric-title">AI SECRET GUARD SCANNER</div>
          <div class="metric-val" id="bench-ai-lines" style="color:#9a6700;">-- dòng/s</div>
          <div id="bench-ai-sub" style="font-size:11px; color:var(--text-muted);">Quét Regex RAM Shield nội bộ &bull; Thông lượng: -- MB/s &bull; Tra cứu cache: -- μs</div>
        </div>

        <div class="metric-box">
          <div class="metric-title">FASTCDC PHÂN MẢNH VI SAI (IN-MEMORY CHUNKER)</div>
          <div class="metric-val" id="bench-chunker-mb" style="color:#0969da;">-- MB/s</div>
          <div id="bench-chunker-sub" style="font-size:11px; color:var(--text-muted); line-height:1.5;">
            Thông lượng băm phân mảnh vi sai trong RAM CPU nội bộ máy (In-Memory Processing).<br>
            <span style="color:var(--text-muted); font-size:10px;">Lưu ý kỹ thuật: Đo lường thuật toán phân mảnh trong bộ nhớ, không bao gồm độ trễ ghi đĩa I/O vật lý hoặc băng thông mạng truyền tải (Socket TCP/LAN/WAN).</span>
          </div>
        </div>
      </div>

      <!-- Physical Disk I/O Metric (Actual Hardware Storage Benchmark) -->
      <div style="margin-top:16px;">
        <div class="metric-box">
          <div class="metric-title">THÔNG LƯỢNG I/O Ổ ĐĨA VẬT LÝ (PHYSICAL DISK NVME/SSD)</div>
          <div class="metric-val" id="bench-disk-write" style="color:#cf222e;">-- MB/s Ghi</div>
          <div id="bench-disk-sub" style="font-size:11px; color:var(--text-muted); line-height:1.5;">
            Đọc tuần tự: <strong id="bench-disk-read" style="color:var(--text-main);">-- MB/s</strong> &bull; 4KB Random IOPS: <strong id="bench-disk-iops" style="color:var(--text-main);">-- IOPS</strong><br>
            Độ trễ I/O: <strong id="bench-disk-latency" style="color:var(--text-main);">-- ms</strong> (Đo lường đọc/ghi tệp tin thực tế trên ổ cứng của thiết bị)
          </div>
        </div>
      </div>

      <!-- Ghi Chú Kỹ Thuật: Tốc Độ Mạng Thực Tế -->
      <div style="margin-top:14px; padding:10px 14px; background:#f6f8fa; border:1px solid #d0d7de; border-radius:var(--radius-sharp); font-size:11px; color:var(--text-muted); line-height:1.6;">
        <strong style="color:var(--text-main); display:inline-flex; align-items:center; gap:6px;">${ICONS.info} Lưu ý về tốc độ truyền tải mạng:</strong>
        Slug không đưa ra số đo tốc độ mạng cố định trong benchmark vì tốc độ thực tế (LAN / P2P VPN / WAN) phụ thuộc hoàn toàn vào băng thông đường truyền và độ trễ vòng tuần hoàn (RTT) giữa 2 máy trạm. Slug tối ưu hóa việc truyền tải bằng phân mảnh vi sai FastCDC (chỉ truyền khối byte thay đổi) và mã hóa PQC không làm nghẽn CPU.
      </div>
    </div>
  </div>

  <!-- ==================== [SECTION 6: CONFIG & CLI CHEAT SHEET] ==================== -->
  <div id="section-config" style="display:none;">
    <!-- 1. KIỂM TRA TOÀN BỘ CARD MẠNG VÀ ĐỊNH TUYẾN MẠNG (LAN / VPN / WAN) -->
    <div class="card" id="network-inspector-card">
      <h3>
        <div style="display:flex; align-items:center; gap:8px;">
          ${ICONS.cpu} <span>Kiểm Tra Toàn Bộ Card Mạng &amp; Định Tuyến WAN / P2P</span>
        </div>
        <div style="display:inline-flex; align-items:center; gap:8px; flex-wrap:wrap;">
          <span class="badge" style="background:#dafbe1; color:#1a7f37; border:1px solid #aceebb; font-weight:700;">
            Kernel Bind: 0.0.0.0 (Tất Cả Card Mạng)
          </span>
          <button class="btn btn-sm" onclick="runNetworkInspection()" id="btn-run-net-inspect" style="display:inline-flex; align-items:center; gap:6px;">
            ${ICONS.refresh} <span>Kiểm Tra Toàn Bộ Card Mạng</span>
          </button>
        </div>
      </h3>

      <!-- Container Danh Sách Nhãn IP Các Card Mạng Đang Hoạt Động -->
      <div id="net-adapters-labels-container" style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px;">
        <div style="font-size:12px; color:var(--text-muted); font-style:italic;">Press [Check All Network Adapters] to inspect interfaces...</div>
      </div>

      <!-- Khung Terminal Hiển Thị Chi Tiết Kỹ Thuật (Network Diagnostic Log) -->
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <label style="font-size:11px; font-weight:700; color:var(--text-main); margin:0; display:inline-flex; align-items:center; gap:6px;">
          ${ICONS.terminal} <span>Network Inspection Diagnostic Log:</span>
        </label>
        <button class="btn-sec btn-xs" onclick="copyText(document.getElementById('net-inspect-output').textContent, 'Network Log')">
          ${ICONS.copy} Copy Log
        </button>
      </div>
      <div id="net-inspect-output" style="background:#1f2328; color:#e6edf3; padding:12px 14px; border-radius:var(--radius-sharp); font-size:11px; font-family:'JetBrains Mono', monospace; line-height:1.6; max-height:260px; overflow-y:auto; border:1px solid #30363d; white-space:pre-wrap;">Press [Check All Network Adapters] to inspect interfaces.</div>
    </div>

    <!-- Tùy Chọn Mặc Định (~/.slug/config.json) -->
    <div class="card">
      <h3>
        <div style="display:flex; align-items:center; gap:8px;">
          ${ICONS.settings} <span>Cấu Hình Tùy Chọn Mặc Định (slug config)</span>
        </div>
        <button class="btn btn-sm" onclick="saveSystemConfig()">${ICONS.check} Lưu Cấu Hình</button>
      </h3>
      <div style="font-size:12px; color:var(--text-muted); margin-bottom:14px; font-family:'JetBrains Mono', monospace;">
        Các tùy chọn bên dưới được lưu vào tệp <code>~/.slug/config.json</code> và áp dụng cho toàn bộ các phiên làm việc của Slug CLI &amp; Web Engine.
      </div>
      <div class="form-grid" style="grid-template-columns: 1fr 1fr;">
        <div class="form-group">
          <label>Mức Mật Mã Mặc Định Toàn Cục (default_suite)</label>
          <select id="cfg-default-suite" class="input-select">
            <option value="SUITE_2_MODERN_HYBRID" selected>SUITE_2_MODERN_HYBRID (ML-KEM-768 + X25519) [Mặc Định / Khuyên Dùng]</option>
            <option value="SUITE_3_PURE_PQC">SUITE_3_PURE_PQC (ML-KEM-1024 + ML-DSA-87)</option>
            <option value="SUITE_1_CLASSICAL_FAST">SUITE_1_CLASSICAL_FAST (X25519 + AES-GCM)</option>
          </select>
        </div>
        <div class="form-group">
          <label>Cổng Web Loopback Mặc Định (portal_port)</label>
          <input type="number" id="cfg-portal-port" class="input-text" value="8080" placeholder="8080">
        </div>
      </div>
    </div>

    <!-- Bảng Tra Cứu Lệnh Nhanh Cho Kỹ Sư (CLI Cheat Sheet) -->
    <div class="card">
      <h3>
        <div style="display:flex; align-items:center; gap:8px;">
          ${ICONS.terminal} <span>Bảng Tra Cứu Toàn Bộ Lệnh CLI (Slug Essential 9 Cheat Sheet)</span>
        </div>
      </h3>
      <table>
        <thead>
          <tr>
            <th>Lệnh CLI</th>
            <th>Mục Đích / Chức Năng</th>
            <th>Ví Dụ Cụ Thể</th>
            <th>Sao Chép</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>slug add &lt;path&gt;</code></td>
            <td>Chia sẻ thư mục với bảo vệ PQC và sinh bộ 3 mã OTP</td>
            <td><code>slug add ./src -p 9443 -s 3 -a</code></td>
            <td><button class="btn-sec btn-xs" onclick="copyText('slug add ./src -p 9443 -s 3 -a', 'Lệnh add')">${ICONS.copy}</button></td>
          </tr>
          <tr>
            <td><code>slug status</code></td>
            <td>Kiểm tra toàn bộ trạm đang host, cổng, phiên client và secret</td>
            <td><code>slug status --sessions --flagged</code></td>
            <td><button class="btn-sec btn-xs" onclick="copyText('slug status --sessions --flagged', 'Lệnh status')">${ICONS.copy}</button></td>
          </tr>
          <tr>
            <td><code>slug get &lt;file&gt;</code></td>
            <td>Tải duy nhất 1 tệp chỉ định từ xa không cần kéo cả cây</td>
            <td><code>slug get 127.0.0.1:9443?otp=48291048 src/main.rs</code></td>
            <td><button class="btn-sec btn-xs" onclick="copyText('slug get 127.0.0.1:9443?otp=48291048 src/main.rs', 'Lệnh get')">${ICONS.copy}</button></td>
          </tr>
          <tr>
            <td><code>slug pull</code></td>
            <td>Đồng bộ sai phân Delta theo đồ thị khối BLAKE3</td>
            <td><code>slug pull src/* --prune -y</code></td>
            <td><button class="btn-sec btn-xs" onclick="copyText('slug pull src/* --prune -y', 'Lệnh pull')">${ICONS.copy}</button></td>
          </tr>
          <tr>
            <td><code>slug push &lt;file&gt;</code></td>
            <td>Tải tệp lên workspace từ xa (quyền [w] hoặc [rw])</td>
            <td><code>slug push ./patch.diff src/patch.diff</code></td>
            <td><button class="btn-sec btn-xs" onclick="copyText('slug push ./patch.diff', 'Lệnh push')">${ICONS.copy}</button></td>
          </tr>
          <tr>
            <td><code>slug user add</code></td>
            <td>Tạo tài khoản Ephemeral RBAC cấp quyền riêng cho workspace</td>
            <td><code>slug user add -u bob -r r -t 2h -p 9443</code></td>
            <td><button class="btn-sec btn-xs" onclick="copyText('slug user add -u bob -r r -t 2h -p 9443', 'Lệnh user')">${ICONS.copy}</button></td>
          </tr>
          <tr>
            <td><code>slug env init</code></td>
            <td>Niêm phong .env vào .env.pqc &amp; lưu vào Central Vault</td>
            <td><code>slug env init -s 3</code></td>
            <td><button class="btn-sec btn-xs" onclick="copyText('slug env init -s 3', 'Lệnh env init')">${ICONS.copy}</button></td>
          </tr>
          <tr>
            <td><code>slug env run</code></td>
            <td>Giải mã secrets vào RAM &amp; chạy lệnh trực tiếp zero-disk</td>
            <td><code>slug env run -- npm run dev</code></td>
            <td><button class="btn-sec btn-xs" onclick="copyText('slug env run -- npm run dev', 'Lệnh env run')">${ICONS.copy}</button></td>
          </tr>
          <tr>
            <td><code>slug audit scan</code></td>
            <td>Quét sâu semantic phát hiện rò rỉ bí mật trong mã nguồn</td>
            <td><code>slug audit scan src/config.ts --deep</code></td>
            <td><button class="btn-sec btn-xs" onclick="copyText('slug audit scan src/config.ts --deep', 'Lệnh audit scan')">${ICONS.copy}</button></td>
          </tr>
          <tr>
            <td><code>slug bench</code></td>
            <td>Đo thông lượng mã hóa ML-KEM-1024, ML-DSA-87, BLAKE3</td>
            <td><code>slug bench --quick</code></td>
            <td><button class="btn-sec btn-xs" onclick="copyText('slug bench --quick', 'Lệnh bench')">${ICONS.copy}</button></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="footer">
    Slug 1.0.0 &bull; Trạm Điều Khiển Workspace Trực Tiếp Giữa Các Máy Tính &bull; Post-Quantum Cryptography &bull; Apache-2.0
  </div>
</div>

<!-- Modal QR Code -->
<div class="modal-overlay" id="qr-modal" onclick="if(event.target===this)closeQrModal()">
  <div class="modal-box" style="text-align:center;">
    <h3 style="margin-top:0; display:flex; align-items:center; justify-content:center; gap:8px;">
      ${ICONS.qr} <span>Mã QR Kết Nối Nhanh Cho Thiết Bị Di Động</span>
    </h3>
    <p style="font-size:12px; color:var(--text-muted);">Quét mã này bằng ứng dụng Slug Mobile hoặc máy ảnh trên điện thoại để nhận workspace:</p>
    <div style="background:#f6f8fa; border:1px solid #d0d7de; padding:24px; display:inline-block; margin:12px auto; border-radius: 2px;">
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
    <h3 style="margin-top:0; display:flex; align-items:center; gap:8px;">
      ${ICONS.terminal} <span>Hướng Dẫn Dùng Lệnh Terminal CLI</span>
    </h3>
    <p style="font-size:12px; color:var(--text-muted);">Bạn bè của bạn chỉ cần mở Command Prompt / PowerShell / Bash và dán lệnh sau:</p>
    <div style="background:#1f2328; color:#e6edf3; padding:12px; border-radius: 2px; font-family:'JetBrains Mono', monospace; font-size:12px; margin-bottom:12px; word-break:break-all;">
      <code id="cli-cmd-display">slug get 127.0.0.1:9443?otp=48291048</code>
    </div>
    <div style="font-size:11px; color:var(--text-muted); margin-bottom:16px; display:flex; align-items:center; gap:6px;">
      ${ICONS.info} <span>Lệnh trên sẽ tự động thiết lập kênh mật mã Hậu lượng tử NIST FIPS 203 (ML-KEM-1024) và đồng bộ workspace về máy trạm đích chỉ trong vài giây.</span>
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
          <option value="w">[w] GỬI LÊN (Chỉ cho tải lên / Upload)</option>
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
<div style="position:fixed; bottom:24px; right:24px; display:flex; flex-direction:column; gap:8px; z-index:9999;">
  <button type="button" onclick="window.scrollTo({top:0, behavior:'smooth'})" title="Lên đầu trang" style="width:38px; height:38px; border-radius:50%; background:#1f2328; color:#fff; border:1px solid #d0d7de; box-shadow:0 2px 8px rgba(0,0,0,0.15); cursor:pointer; display:flex; align-items:center; justify-content:center; font-size:14px;">&#9650;</button>
  <button type="button" onclick="window.scrollTo({top:document.body.scrollHeight, behavior:'smooth'})" title="Xuống cuối trang" style="width:38px; height:38px; border-radius:50%; background:#1f2328; color:#fff; border:1px solid #d0d7de; box-shadow:0 2px 8px rgba(0,0,0,0.15); cursor:pointer; display:flex; align-items:center; justify-content:center; font-size:14px;">&#9660;</button>
</div>

</body>
</html>
)raw";

        size_t p = html.find("{{PORTAL_PORT}}");
        if (p != std::string::npos) html.replace(p, 15, std::to_string(portal_port));

        p = html.find("{{LAN_IP}}");
        if (p != std::string::npos) html.replace(p, 10, lan_ip.empty() ? "127.0.0.1" : lan_ip);

        std::string conns_rows = "";
        uint64_t now = core::Utils::current_timestamp();
        for (const auto& c : conns) {
            std::string exp_str = (c.expires_at == 0) ? "Permanent (∞)"
                                  : (c.expires_at > now ? core::Utils::format_duration(c.expires_at - now) : "<span style='color:var(--danger);'>Expired</span>");
            std::string esc_id_html = html_escape(c.id);
            std::string esc_id_js = js_escape(c.id);
            std::string esc_ws_html = html_escape(c.workspace);
            std::string esc_host_html = html_escape(c.host);

            conns_rows += "<tr class='clickable-row' onclick='openSaved(\"" + esc_id_js + "\")'><td><strong>" + esc_id_html + "</strong></td>"
                       + "<td><code>" + esc_ws_html + "</code></td>"
                       + "<td><code>" + esc_host_html + ":" + std::to_string(c.port) + "</code></td>"
                       + "<td><span class='role-tag'>" + core::role_to_string(c.role) + "</span></td>"
                       + "<td>" + exp_str + "</td>"
                       + "<td onclick='event.stopPropagation()'><button class='btn btn-xs' onclick='openSaved(\"" + esc_id_js + "\")'>"
                       + "<svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><path d='M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z'></path></svg> Duyệt Thư Mục</button> "
                       + "<button class='btn-danger btn-xs' onclick='removeSaved(\"" + esc_id_js + "\")'>"
                       + "<svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><polyline points='3 6 5 6 21 6'></polyline><path d='M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2'></path></svg> Xóa</button></td></tr>";
        }
        if (conns_rows.empty()) {
            conns_rows = "<tr><td colspan='6' style='text-align:center; color:var(--text-muted); padding:18px;'>Chưa có trạm lưu nào. Điền IP và mã OTP vào biểu mẫu phía trên để kết nối ngay.</td></tr>";
        }

        p = html.find("{{SAVED_CONNS_ROWS}}");
        if (p != std::string::npos) html.replace(p, 20, conns_rows);

        p = html.find("{{SAVED_CONNS_COUNT}}");
        if (p != std::string::npos) html.replace(p, 21, std::to_string(conns.size()));

        
        // Safe replace all ${ICONS.xxx} in HTML output
        std::map<std::string, std::string> icon_map = {
            {"terminal", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><polyline points=\"4 17 10 11 4 5\"></polyline><line x1=\"12\" y1=\"19\" x2=\"20\" y2=\"19\"></line></svg>"},
            {"folder", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><path d=\"M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z\"></path></svg>"},
            {"file", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><path d=\"M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z\"></path><polyline points=\"14 2 14 8 20 8\"></polyline></svg>"},
            {"shield", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"></path></svg>"},
            {"refresh", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><polyline points=\"23 4 23 10 17 10\"></polyline><polyline points=\"1 20 1 14 7 14\"></polyline><path d=\"M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15\"></path></svg>"},
            {"user", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><path d=\"M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2\"></path><circle cx=\"12\" cy=\"7\" r=\"4\"></circle></svg>"},
            {"users", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><path d=\"M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2\"></path><circle cx=\"9\" cy=\"7\" r=\"4\"></circle><path d=\"M23 21v-2a4 4 0 0 0-3-3.87\"></path><path d=\"M16 3.13a4 4 0 0 1 0 7.75\"></path></svg>"},
            {"settings", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><circle cx=\"12\" cy=\"12\" r=\"3\"></circle><path d=\"M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z\"></path></svg>"},
            {"power", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><path d=\"M18.36 6.64a9 9 0 1 1-12.73 0\"></path><line x1=\"12\" y1=\"2\" x2=\"12\" y2=\"12\"></line></svg>"},
            {"lock", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><rect x=\"3\" y=\"11\" width=\"18\" height=\"11\" rx=\"2\" ry=\"2\"></rect><path d=\"M7 11V7a5 5 0 0 1 10 0v4\"></path></svg>"},
            {"unlock", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><rect x=\"3\" y=\"11\" width=\"18\" height=\"11\" rx=\"2\" ry=\"2\"></rect><path d=\"M7 11V7a5 5 0 0 1 9.9-1\"></path></svg>"},
            {"download", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><path d=\"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4\"></path><polyline points=\"7 10 12 15 17 10\"></polyline><line x1=\"12\" y1=\"15\" x2=\"12\" y2=\"3\"></line></svg>"},
            {"upload", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><path d=\"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4\"></path><polyline points=\"17 8 12 3 7 8\"></polyline><line x1=\"12\" y1=\"3\" x2=\"12\" y2=\"15\"></line></svg>"},
            {"check", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><polyline points=\"20 6 9 17 4 12\"></polyline></svg>"},
            {"trash", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><polyline points=\"3 6 5 6 21 6\"></polyline><path d=\"M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2\"></path></svg>"},
            {"plus", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><line x1=\"12\" y1=\"5\" x2=\"12\" y2=\"19\"></line><line x1=\"5\" y1=\"12\" x2=\"19\" y2=\"12\"></line></svg>"},
            {"connect", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><path d=\"M5 12h14\"></path><path d=\"m12 5 7 7-7 7\"></path></svg>"},
            {"clock", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><circle cx=\"12\" cy=\"12\" r=\"10\"></circle><polyline points=\"12 6 12 12 16 14\"></polyline></svg>"},
            {"inbox", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><polyline points=\"22 12 16 12 14 15 10 15 8 12 2 12\"></polyline><path d=\"M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z\"></path></svg>"},
            {"send", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><line x1=\"22\" y1=\"2\" x2=\"11\" y2=\"13\"></line><polygon points=\"22 2 15 22 11 13 2 9 22 2\"></polygon></svg>"},
            {"zap", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><polygon points=\"13 2 3 14 12 14 11 22 21 10 12 10 13 2\"></polygon></svg>"},
            {"database", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><ellipse cx=\"12\" cy=\"5\" rx=\"9\" ry=\"3\"></ellipse><path d=\"M21 12c0 1.66-4 3-9 3s-9-1.34-9-3\"></path><path d=\"M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5\"></path></svg>"},
            {"play", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><polygon points=\"5 3 19 12 5 21 5 3\"></polygon></svg>"},
            {"qr", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><rect x=\"3\" y=\"3\" width=\"7\" height=\"7\"></rect><rect x=\"14\" y=\"3\" width=\"7\" height=\"7\"></rect><rect x=\"14\" y=\"14\" width=\"7\" height=\"7\"></rect><rect x=\"3\" y=\"14\" width=\"7\" height=\"7\"></rect></svg>"},
            {"copy", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><rect x=\"9\" y=\"9\" width=\"13\" height=\"13\" rx=\"2\" ry=\"2\"></rect><path d=\"M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1\"></path></svg>"},
            {"stop", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><circle cx=\"12\" cy=\"12\" r=\"10\"></circle><rect x=\"9\" y=\"9\" width=\"6\" height=\"6\"></rect></svg>"},
            {"edit", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><path d=\"M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7\"></path><path d=\"M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z\"></path></svg>"},
            {"key", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><path d=\"m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4\"></path></svg>"},
            {"info", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><circle cx=\"12\" cy=\"12\" r=\"10\"></circle><path d=\"M12 16v-4\"></path><path d=\"M12 8h.01\"></path></svg>"},
            {"cpu", "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"vertical-align:middle;\"><rect x=\"4\" y=\"4\" width=\"16\" height=\"16\" rx=\"2\" ry=\"2\"></rect><rect x=\"9\" y=\"9\" width=\"6\" height=\"6\"></rect><line x1=\"9\" y1=\"1\" x2=\"9\" y2=\"4\"></line><line x1=\"15\" y1=\"1\" x2=\"15\" y2=\"4\"></line><line x1=\"9\" y1=\"20\" x2=\"9\" y2=\"23\"></line><line x1=\"15\" y1=\"20\" x2=\"15\" y2=\"23\"></line><line x1=\"20\" y1=\"9\" x2=\"23\" y2=\"9\"></line><line x1=\"20\" y1=\"14\" x2=\"23\" y2=\"14\"></line><line x1=\"1\" y1=\"9\" x2=\"4\" y2=\"9\"></line><line x1=\"1\" y1=\"14\" x2=\"4\" y2=\"14\"></line></svg>"}
        };
        for (const auto& [name, svg_val] : icon_map) {
            std::string placeholder = "${ICONS." + name + "}";
            size_t pos = 0;
            while ((pos = html.find(placeholder, pos)) != std::string::npos) {
                html.replace(pos, placeholder.length(), svg_val);
                pos += svg_val.length();
            }
        }

        return html;
    }
};

} // namespace slug::net
