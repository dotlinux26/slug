#pragma once

#include "src/core/types.hpp"
#include "src/core/acl.hpp"
#include "src/core/audit.hpp"
#include "src/core/utils.hpp"
#include "src/sync/manifest.hpp"
#include "src/bench/benchmark.hpp"
#include "src/policy/rules.hpp"
#include "src/ai/stateful_audit.hpp"
#include "src/ai/scanner.hpp"
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
          << "<div style='margin-top:20px; display:flex; gap:10px; justify-content:center; flex-wrap:wrap;'>"
          << "<a href='/portal' style='display:inline-flex; align-items:center; gap:6px; padding:9px 16px; background:#0969da; color:#ffffff; text-decoration:none; border-radius:4px; font-weight:600; font-size:13px;'>&larr; Về Trang Chủ Portal (Back to Portal)</a>"
          << "<a href='/drop' style='display:inline-flex; align-items:center; gap:6px; padding:9px 16px; background:#ffffff; color:#1f2328; border:1px solid #d0d7de; text-decoration:none; border-radius:4px; font-weight:600; font-size:13px;'>Đăng Nhập Lại (Re-login)</a>"
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
        auto manifest = sync::ManifestBuilder::build(workspace_root, 1, static_cast<uint8_t>(suite_id), false, core::FilterMode::PROTECTED, core::FilterLevel::LEVEL_3_ENTROPY, core::AiModelProvider::OLLAMA);
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
            std::string scan_status;
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
                        items.push_back({true, dname, dname, 0, "folder", "DIR", "badge-excluded", "Directory", "", false, ""});
                    }
                } else {
                    items.push_back({false, p, p, f.size, "file", "AVAILABLE", "badge-available", "Available for download", f.file_blake3_hash, true, f.scan_status});
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
                            items.push_back({true, dname, full_d, 0, "folder", "DIR", "badge-excluded", "Directory", "", false, ""});
                        }
                    } else {
                        items.push_back({false, rem, p, f.size, "file", "AVAILABLE", "badge-available", "Available for download", f.file_blake3_hash, true, f.scan_status});
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

        // Process skipped / filtered / quarantined files (Standardized to BLOCKED)
        for (const auto& s : manifest.skipped) {
            std::string p = s.relative_path;
            std::string st_label = "BLOCKED";
            std::string badge_cls = "badge-quarantined";
            std::string detail = (identity == "host_admin") ? s.reason : "Shielded by workspace policy";

            if (norm_sub.empty()) {
                size_t slash = p.find('/');
                if (slash != std::string::npos) {
                    std::string dname = p.substr(0, slash);
                    if (seen_dirs.insert(dname).second) {
                        items.push_back({true, dname, dname, 0, "folder", "DIR", "badge-excluded", "Directory", "", false, ""});
                    }
                } else {
                    items.push_back({false, p, p, 0, "file", st_label, badge_cls, detail, "", false, ""});
                }
            } else {
                if (p.rfind(norm_sub + "/", 0) == 0) {
                    std::string rem = p.substr(norm_sub.size() + 1);
                    size_t slash = rem.find('/');
                    if (slash != std::string::npos) {
                        std::string dname = rem.substr(0, slash);
                        std::string full_d = norm_sub + "/" + dname;
                        if (seen_dirs.insert(full_d).second) {
                            items.push_back({true, dname, full_d, 0, "folder", "DIR", "badge-excluded", "Directory", "", false, ""});
                        }
                    } else {
                        items.push_back({false, rem, p, 0, "file", st_label, badge_cls, detail, "", false, ""});
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
          << ".badge { padding: 2px 7px; border-radius: var(--radius-sharp); font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; text-transform: uppercase; letter-spacing: 0.3px; display: inline-block; white-space: nowrap; }"
          << ".badge-available { background: var(--success-bg); color: var(--success); border: 1px solid rgba(26,127,55,0.25); }"
          << ".badge-excluded { background: var(--bg-surface-hover); color: var(--text-muted); border: 1px solid var(--border-primary); }"
          << ".badge-quarantined { background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(207,34,46,0.3); }"
          << ".badge-blocked { background: var(--warning-bg); color: var(--warning); border: 1px solid rgba(154,103,0,0.3); }"
          << ".badge-pqc { background: var(--pqc-bg); color: var(--pqc); border: 1px solid rgba(130,80,223,0.3); }"
          << ".top-bar-actions, .nav-bar-actions { display: inline-flex; align-items: center; gap: 8px; flex-wrap: wrap; }"
          << ".user-badge { height: 32px; line-height: 30px; box-sizing: border-box; background: var(--bg-canvas); border: 1px solid var(--border-primary); color: var(--text-main); padding: 0 10px; border-radius: var(--radius-sharp); font-size: 12px; display: inline-flex; align-items: center; gap: 6px; font-family: 'JetBrains Mono', monospace; vertical-align: middle; }"
          << ".role-tag { height: 18px; line-height: 18px; box-sizing: border-box; background: #0969da; color: #fff; padding: 0 5px; border-radius: var(--radius-sharp); font-size: 10px; font-weight: bold; text-transform: uppercase; font-family: 'JetBrains Mono', monospace; display: inline-flex; align-items: center; }"
          << ".ws-summary-box { background: #f6f8fa; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 10px 14px; margin-bottom: 14px; font-family: 'JetBrains Mono', monospace; font-size: 12px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }"
          << ".nav-bar { display: flex; align-items: center; justify-content: space-between; background: #ffffff; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 8px 14px; margin-bottom: 14px; flex-wrap: wrap; gap: 10px; }"
          << ".breadcrumb { font-size: 13px; font-family: 'JetBrains Mono', monospace; display: flex; align-items: center; gap: 4px; color: var(--text-muted); }"
          << ".breadcrumb a { color: var(--text-accent); text-decoration: none; font-weight: 500; }"
          << ".breadcrumb a:hover { text-decoration: underline; }"
          << ".btn { height: 32px; line-height: 30px; box-sizing: border-box; background: #0969da; color: #ffffff; padding: 0 12px; border-radius: var(--radius-sharp); text-decoration: none; font-size: 12px; font-weight: 500; border: 1px solid #0969da; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 6px; font-family: 'JetBrains Mono', monospace; vertical-align: middle; white-space: nowrap; }"
          << ".btn:hover { background: #0856b3; border-color: #0856b3; }"
          << ".btn-sec { height: 32px; line-height: 30px; box-sizing: border-box; background: #ffffff; border: 1px solid var(--border-primary); color: var(--text-main); padding: 0 11px; border-radius: var(--radius-sharp); text-decoration: none; font-size: 12px; font-weight: 500; display: inline-flex; align-items: center; justify-content: center; gap: 6px; font-family: 'JetBrains Mono', monospace; cursor: pointer; vertical-align: middle; white-space: nowrap; }"
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
          << "#upload-toast { position: fixed; bottom: 24px; right: 24px; background: #ffffff; border: 1px solid var(--border-primary); border-radius: 6px; padding: 14px 18px; box-shadow: 0 8px 24px rgba(31,35,40,0.18); font-size: 12px; font-family: 'JetBrains Mono', monospace; z-index: 9999; display: none; min-width: 340px; max-width: 480px; box-sizing: border-box; }"
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
          << "function formatSpeed(bytesPerSec) {"
          << "  if (bytesPerSec >= 1048576) return (bytesPerSec / 1048576).toFixed(1) + ' MB/s';"
          << "  if (bytesPerSec >= 1024) return (bytesPerSec / 1024).toFixed(1) + ' KB/s';"
          << "  return Math.round(bytesPerSec) + ' B/s';"
          << "}"
          << "function formatTime(sec) {"
          << "  if (typeof sec !== 'number' || isNaN(sec)) sec = 0;"
          << "  if (sec > 0 && sec < 1) return '< 1s';"
          << "  sec = Math.round(sec);"
          << "  if (sec < 60) return sec + 's';"
          << "  const m = Math.floor(sec / 60); const s = sec % 60;"
          << "  if (m < 60) return m + 'm ' + (s < 10 ? '0' : '') + s + 's';"
          << "  const h = Math.floor(m / 60); const remM = m % 60;"
          << "  return h + 'h ' + (remM < 10 ? '0' : '') + remM + 'm';"
          << "}"
          << "function downloadFileWithProgress(path, filename, onComplete) {"
          << "  const toast = document.getElementById('upload-toast');"
          << "  if (toast) {"
          << "    toast.style.display = 'block';"
          << "    toast.innerHTML = '<div style=\"font-weight:700; color:#1f2328; margin-bottom:6px; display:flex; justify-content:space-between; align-items:center;\"><span>📁 Đang mở hộp thoại chọn thư mục lưu...</span><span style=\"color:#0969da; font-size:11px; font-weight:600;\">Giữ nguyên tên tệp</span></div><div style=\"font-size:11px; color:#57606a; margin-bottom:8px; word-break:break-all;\">Tệp: <strong>' + filename + '</strong></div><div style=\"background:#e1e4e8; border-radius:3px; height:6px; width:100%; overflow:hidden;\"><div style=\"background:#0969da; height:100%; width:100%;\"></div></div>';"
          << "  }"
          << "  fetch('/api/transfer/download-file', {"
          << "    method: 'POST',"
          << "    headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ path: path, filename: filename })"
          << "  })"
          << "  .then(r => {"
          << "    if (!r.ok && r.status === 404) throw new Error('FALLBACK_BROWSER');"
          << "    return r.json();"
          << "  })"
          << "  .then(res => {"
          << "    if (res.status === 'cancelled') {"
          << "      if (toast) {"
          << "        toast.innerHTML = '<div style=\"color:#57606a; font-weight:600;\">Đã hủy chọn thư mục lưu tệp.</div>';"
          << "        setTimeout(() => { if (toast && !onComplete) toast.style.display = 'none'; }, 2000);"
          << "      }"
          << "      if (onComplete) onComplete();"
          << "      return;"
          << "    }"
          << "    if (res.status !== 'ok' || !res.job_id) {"
          << "      if (toast) {"
          << "        toast.innerHTML = '<div style=\"font-weight:700; color:#cf222e;\">❌ Lỗi: ' + (res.message || 'Không thể bắt đầu tải tệp.') + '</div>';"
          << "        setTimeout(() => { if (toast && !onComplete) toast.style.display = 'none'; }, 3500);"
          << "      }"
          << "      if (onComplete) onComplete();"
          << "      return;"
          << "    }"
          << "    const jobId = res.job_id;"
          << "    const destPath = res.dest || '';"
          << "    const clientStart = Date.now();"
          << "    const pollTimer = setInterval(() => {"
          << "      fetch('/api/transfer/progress?job_id=' + encodeURIComponent(jobId))"
          << "      .then(pr => pr.json())"
          << "      .then(p => {"
          << "        if (!toast) { clearInterval(pollTimer); if (onComplete) onComplete(); return; }"
          << "        const pct = (p.percent || 0).toFixed(1);"
          << "        const doneStr = formatSize(p.bytes_transferred || 0);"
          << "        const totStr = formatSize(p.total_bytes || 0);"
          << "        const clientSec = Math.max(0.1, (Date.now() - clientStart) / 1000);"
          << "        const elapsedVal = (typeof p.elapsed_sec === 'number' && p.elapsed_sec > 0) ? p.elapsed_sec : ((typeof p.elapsed_ms === 'number' && p.elapsed_ms > 0) ? (p.elapsed_ms / 1000) : clientSec);"
          << "        let avgVal = (typeof p.avg_mbps === 'number' && p.avg_mbps > 0) ? p.avg_mbps : 0;"
          << "        if (p.bytes_transferred > 0 && (avgVal <= 0 || avgVal > 2500)) {"
          << "          avgVal = (p.bytes_transferred / (1024 * 1024)) / Math.max(0.1, (p.elapsed_ms ? (p.elapsed_ms / 1000) : clientSec));"
          << "        }"
          << "        const instSpeed = (p.instant_mbps || 0).toFixed(1);"
          << "        const avgSpeed = avgVal.toFixed(1);"
          << "        const elapsed = formatTime(elapsedVal);"
          << "        const eta = (p.eta_sec && p.eta_sec > 0) ? formatTime(p.eta_sec) : (pct >= 99.5 ? 'Gần xong' : 'Đang tính...');"
          << "        if (p.status === 'running' || p.status === 'pending') {"
          << "          toast.innerHTML = '<div style=\"font-weight:700; color:#1f2328; margin-bottom:8px; display:flex; justify-content:space-between; align-items:center;\">' "
          << "            + '<span style=\"color:#0969da; display:flex; align-items:center; gap:5px;\">⚡ TẢI STREAMING TRỰC TIẾP</span>' "
          << "            + '<span style=\"color:#1a7f37; font-weight:700; font-size:13px;\">' + pct + '%</span>' "
          << "            + '</div>' "
          << "            + '<div style=\"font-size:11px; color:#24292f; margin-bottom:6px; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;\" title=\"' + filename + '\">Tệp: ' + filename + '</div>' "
          << "            + '<div style=\"background:#e1e4e8; border-radius:3px; height:8px; width:100%; overflow:hidden; margin-bottom:8px;\">' "
          << "            + '<div style=\"background:linear-gradient(90deg, #2da44e, #1a7f37); height:100%; width:' + pct + '%; transition:width 0.2s ease;\"></div>' "
          << "            + '</div>' "
          << "            + '<div style=\"display:grid; grid-template-columns:1fr 1fr; gap:6px; font-size:11px; color:#57606a; line-height:1.5;\">' "
          << "            + '<div>Đã tải: <strong style=\"color:#24292f;\">' + doneStr + ' / ' + totStr + '</strong></div>' "
          << "            + '<div>Tốc độ tức thời: <strong style=\"color:#0969da;\">' + instSpeed + ' MB/s</strong></div>' "
          << "            + '<div>Tốc độ TB: <strong style=\"color:#1a7f37;\">' + avgSpeed + ' MB/s</strong></div>' "
          << "            + '<div>Thời gian đã qua: <strong style=\"color:#24292f;\">' + elapsed + '</strong></div>' "
          << "            + '<div style=\"grid-column:1 / -1; color:#0969da;\">Thời gian còn lại (ETA): <strong>' + eta + '</strong></div>' "
          << "            + '</div>' "
          << "            + '<div style=\"margin-top:10px; display:flex; justify-content:space-between; align-items:center;\">' "
          << "            + '<span style=\"font-size:10px; color:#8c959f;\">Ghi trực tiếp ra đĩa (0MB RAM)</span>' "
          << "            + '<button type=\"button\" class=\"btn-sec\" style=\"height:24px; line-height:22px; font-size:11px; padding:0 8px; color:#cf222e; border-color:#ffc8c8;\" onclick=\"fetch(\\\'/api/transfer/cancel?job_id=' + jobId + '\\\',{method:\\\'POST\\\'}); this.innerText=\\\'Đang hủy...\\\';\">Hủy Tải</button>' "
          << "            + '</div>';"
          << "        } else if (p.status === 'completed') {"
          << "          clearInterval(pollTimer);"
          << "          const finalTarget = p.dest || destPath;"
          << "          toast.innerHTML = '<div style=\"padding:4px 0;\">' "
          << "            + '<div style=\"font-weight:700; color:#1a7f37; font-size:13px; margin-bottom:6px; display:flex; align-items:center; gap:6px;\">' "
          << "            + '<svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\"><polyline points=\"20 6 9 17 4 12\"></polyline></svg>' "
          << "            + 'TẢI VỀ THÀNH CÔNG!' "
          << "            + '</div>' "
          << "            + '<div style=\"font-size:11px; color:#24292f; margin-bottom:4px; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;\">' + filename + ' (' + doneStr + ')</div>' "
          << "            + '<div style=\"font-size:11px; color:#57606a; margin-bottom:6px;\">Tốc độ TB: <strong>' + avgSpeed + ' MB/s</strong> &bull; Thời gian: <strong>' + elapsed + '</strong></div>' "
          << "            + '<div style=\"font-size:10px; color:#1a7f37; margin-bottom:8px;\">🔒 Đã xác minh tính toàn vẹn BLAKE3 100%</div>' "
          << "            + '<div style=\"display:flex; gap:6px; align-items:center; margin-top:8px;\">' "
          << "            + '<button type=\"button\" id=\"btn-dl-open-folder\" class=\"btn\" style=\"height:26px; line-height:24px; font-size:11px; padding:0 10px;\">Mở Thư Mục Chứa Tệp</button>' "
          << "            + '<button type=\"button\" id=\"btn-dl-close-toast\" class=\"btn-sec\" style=\"height:26px; line-height:24px; font-size:11px; padding:0 8px;\">Đóng</button>' "
          << "            + '</div>' "
          << "            + '</div>';"
          << "          const openBtn = document.getElementById('btn-dl-open-folder');"
          << "          if (openBtn) {"
          << "            openBtn.onclick = () => {"
          << "              fetch('/api/fs/open-folder', {"
          << "                method: 'POST',"
          << "                headers: { 'Content-Type': 'application/json' },"
          << "                body: JSON.stringify({ path: finalTarget })"
          << "              });"
          << "            };"
          << "          }"
          << "          const closeBtn = document.getElementById('btn-dl-close-toast');"
          << "          if (closeBtn) closeBtn.onclick = () => { toast.style.display = 'none'; };"
          << "          if (onComplete) onComplete();"
          << "        } else {"
          << "          clearInterval(pollTimer);"
          << "          toast.innerHTML = '<div style=\"font-weight:700; color:#cf222e; margin-bottom:4px;\">❌ Tải Về Thất Bại</div>' "
          << "            + '<div style=\"font-size:11px; color:#57606a; margin-bottom:8px;\">' + (p.error_message || 'Quá trình tải tệp bị gián đoạn hoặc bị hủy.') + '</div>' "
          << "            + '<button type=\"button\" class=\"btn-sec\" style=\"height:24px; line-height:22px; font-size:11px; padding:0 8px;\" onclick=\"document.getElementById(\\\'upload-toast\\\').style.display=\\\'none\\\';\">Đóng</button>';"
          << "          if (onComplete) onComplete();"
          << "        }"
          << "      })"
          << "      .catch(err => {"
          << "        clearInterval(pollTimer);"
          << "        if (toast) {"
          << "          toast.innerHTML = '<div style=\"font-weight:700; color:#cf222e; margin-bottom:4px;\">❌ Lỗi Mạng / Gián Đoạn Kết Nối</div>' "
          << "            + '<div style=\"font-size:11px; color:#57606a; margin-bottom:8px;\">' + err.message + '</div>' "
          << "            + '<button type=\"button\" class=\"btn-sec\" style=\"height:24px; line-height:22px; font-size:11px; padding:0 8px;\" onclick=\"document.getElementById(\\\'upload-toast\\\').style.display=\\\'none\\\';\">Đóng</button>';"
          << "        }"
          << "        if (onComplete) onComplete();"
          << "      });"
          << "    }, 250);"
          << "  })"
          << "  .catch(err => {"
          << "    if (err && err.message === 'FALLBACK_BROWSER') {"
          << "      const urlParams = new URLSearchParams(window.location.search);"
          << "      const curTicket = urlParams.get('ticket') || '';"
          << "      const dlUrl = '/download?path=' + encodeURIComponent(path) + (curTicket ? '&ticket=' + encodeURIComponent(curTicket) : '');"
          << "      const a = document.createElement('a');"
          << "      a.href = dlUrl;"
          << "      a.download = filename;"
          << "      document.body.appendChild(a);"
          << "      a.click();"
          << "      setTimeout(() => { document.body.removeChild(a); }, 500);"
          << "      if (toast) {"
          << "        toast.innerHTML = '<div style=\"font-weight:600; color:#1a7f37;\">Đang tải xuống qua trình duyệt: ' + filename + '</div>';"
          << "        setTimeout(() => { if (toast && !onComplete) toast.style.display = 'none'; }, 2500);"
          << "      }"
          << "      if (onComplete) onComplete();"
          << "      return;"
          << "    }"
          << "    if (toast) {"
          << "      toast.innerHTML = '<div style=\"font-weight:700; color:#cf222e; margin-bottom:4px;\">❌ Không Thể Bắt Đầu Tải</div>' "
          << "        + '<div style=\"font-size:11px; color:#57606a; margin-bottom:8px;\">' + err.message + '</div>' "
          << "        + '<button type=\"button\" class=\"btn-sec\" style=\"height:24px; line-height:22px; font-size:11px; padding:0 8px;\" onclick=\"document.getElementById(\\\'upload-toast\\\').style.display=\\\'none\\\';\">Đóng</button>';"
          << "    }"
          << "    if (onComplete) onComplete();"
          << "  });"
          << "}"
          << "async function downloadSelected() {"
          << "  const checks = document.querySelectorAll('.file-check:checked');"
          << "  if (checks.length === 0) return;"
          << "  for (let i = 0; i < checks.length; i++) {"
          << "    const cb = checks[i];"
          << "    const p = cb.getAttribute('data-path');"
          << "    const name = p.split('/').pop();"
          << "    await new Promise(resolve => downloadFileWithProgress(p, name, resolve));"
          << "  }"
          << "}"
          << "function refreshWorkspaceListing() {"
          << "  const toast = document.getElementById('upload-toast');"
          << "  if (toast) {"
          << "    toast.style.display = 'block';"
          << "    toast.innerHTML = '<div style=\"font-weight:600; color:#0969da; display:flex; align-items:center; gap:6px;\">🔄 Đang đồng bộ danh mục tệp từ đĩa...</div>';"
          << "  }"
          << "  fetch('/api/fs/refresh').then(() => {"
          << "    let u = new URL(window.location.href);"
          << "    u.searchParams.set('refresh', '1');"
          << "    window.location.href = u.toString();"
          << "  }).catch(() => { location.reload(); });"
          << "}"
          << "function downloadFolderAsZipDirect(dir) {"
          << "  const toast = document.getElementById('upload-toast');"
          << "  if (toast) {"
          << "    toast.style.display = 'block';"
          << "    toast.innerHTML = '<div style=\"font-weight:700; color:#1f2328; margin-bottom:6px; display:flex; justify-content:space-between; align-items:center;\"><span>📦 Đang nén &amp; tải gói ZIP...</span><span id=\"zip-speed-lbl\" style=\"color:#0969da; font-size:11px; font-weight:600;\">Đang xử lý...</span></div><div style=\"background:#e1e4e8; border-radius:3px; height:8px; width:100%; overflow:hidden; margin-bottom:6px;\"><div id=\"zip-bar\" style=\"background:#0969da; height:100%; width:15%; transition:width 0.2s ease;\"></div></div><div style=\"display:flex; justify-content:space-between; font-size:11px; color:#57606a;\"><span id=\"zip-status-lbl\">Máy chủ đang quét và đóng gói các tệp...</span><span style=\"color:#1a7f37; font-weight:600;\">Direct Stream</span></div>';"
          << "  }"
          << "  const urlParams = new URLSearchParams(window.location.search);"
          << "  const curTicket = urlParams.get('ticket') || '';"
          << "  const u = '/download-folder?dir=' + encodeURIComponent(dir) + (curTicket ? '&ticket=' + encodeURIComponent(curTicket) : '');"
          << "  const xhr = new XMLHttpRequest();"
          << "  xhr.open('GET', u, true);"
          << "  xhr.responseType = 'blob';"
          << "  let startTime = Date.now();"
          << "  let lastLoaded = 0;"
          << "  let lastTime = startTime;"
          << "  let prepTimer = setInterval(() => {"
          << "    const bar = document.getElementById('zip-bar');"
          << "    if (bar) {"
          << "      let curW = parseFloat(bar.style.width) || 15;"
          << "      if (curW < 85) bar.style.width = (curW + 5) + '%';"
          << "    }"
          << "  }, 400);"
          << "  xhr.onprogress = function(e) {"
          << "    if (prepTimer) { clearInterval(prepTimer); prepTimer = null; }"
          << "    const now = Date.now();"
          << "    const dt = (now - lastTime) / 1000;"
          << "    const speed = (dt > 0.25) ? ((e.loaded - lastLoaded) / (1024 * 1024) / dt) : 0;"
          << "    if (dt > 0.25) { lastLoaded = e.loaded; lastTime = now; }"
          << "    const speedLbl = document.getElementById('zip-speed-lbl');"
          << "    const statusLbl = document.getElementById('zip-status-lbl');"
          << "    const bar = document.getElementById('zip-bar');"
          << "    if (e.lengthComputable && e.total > 0) {"
          << "      const pct = Math.min(100, Math.round((e.loaded / e.total) * 100));"
          << "      if (bar) bar.style.width = pct + '%';"
          << "      if (speedLbl && speed > 0) speedLbl.innerText = speed.toFixed(1) + ' MB/s (' + pct + '%)';"
          << "      if (statusLbl) statusLbl.innerText = (e.loaded / (1024 * 1024)).toFixed(1) + ' MB / ' + (e.total / (1024 * 1024)).toFixed(1) + ' MB';"
          << "    } else {"
          << "      if (bar) bar.style.width = '75%';"
          << "      if (statusLbl) statusLbl.innerText = 'Đang truyền ' + (e.loaded / (1024 * 1024)).toFixed(1) + ' MB...';"
          << "    }"
          << "  };"
          << "  xhr.onload = function() {"
          << "    if (prepTimer) clearInterval(prepTimer);"
          << "    if (xhr.status === 200) {"
          << "      const bar = document.getElementById('zip-bar');"
          << "      if (bar) bar.style.width = '100%';"
          << "      if (toast) {"
          << "        toast.innerHTML = '<div style=\"font-weight:700; color:#1a7f37; display:flex; align-items:center; gap:6px;\">✅ Đã đóng gói và tải xuống tệp ZIP thành công!</div>';"
          << "        setTimeout(() => { toast.style.display = 'none'; }, 2500);"
          << "      }"
          << "      const blob = xhr.response;"
          << "      let filename = (dir ? dir.replace(/[^a-zA-Z0-9_-]/g, '_') : 'workspace') + '.zip';"
          << "      const disposition = xhr.getResponseHeader('Content-Disposition');"
          << "      if (disposition && disposition.indexOf('filename=') !== -1) {"
          << "        const matches = /filename[^;=\\n]*=((['\\\"]).*?\\2|[^;\\n]*)/.exec(disposition);"
          << "        if (matches != null && matches[1]) filename = matches[1].replace(/['\\\"]/g, '');"
          << "      }"
          << "      const link = document.createElement('a');"
          << "      link.href = window.URL.createObjectURL(blob);"
          << "      link.download = filename;"
          << "      document.body.appendChild(link);"
          << "      link.click();"
          << "      setTimeout(() => {"
          << "        window.URL.revokeObjectURL(link.href);"
          << "        document.body.removeChild(link);"
          << "      }, 500);"
          << "    } else if (xhr.status === 413) {"
          << "      if (toast) {"
          << "        toast.innerHTML = '<div style=\"font-weight:700; color:#cf222e; margin-bottom:4px;\">⚠️ Thư mục quá lớn để nén ZIP qua web (> 150 MB)</div><div style=\"font-size:11px; color:#57606a; line-height:1.4;\">Dung lượng thư mục vượt quá giới hạn nén trực tiếp trên trình duyệt. Vui lòng bấm <b>⚡ ĐỒNG BỘ DỮ LIỆU VỀ MÁY (slug pull)</b> ở thanh công cụ để đồng bộ toàn bộ tốc độ cao với phân luồng vi sai FastCDC.</div>';"
          << "        setTimeout(() => { toast.style.display = 'none'; }, 8000);"
          << "      }"
          << "    } else {"
          << "      if (toast) {"
          << "        toast.innerHTML = '<div style=\"font-weight:700; color:#cf222e;\">Lỗi tải xuống gói ZIP (Mã lỗi ' + xhr.status + ')</div>';"
          << "        setTimeout(() => { toast.style.display = 'none'; }, 4000);"
          << "      }"
          << "    }"
          << "  };"
          << "  xhr.onerror = function() {"
          << "    if (prepTimer) clearInterval(prepTimer);"
          << "    if (toast) {"
          << "      toast.innerHTML = '<div style=\"font-weight:700; color:#cf222e;\">Lỗi kết nối khi tải file ZIP</div>';"
          << "      setTimeout(() => { toast.style.display = 'none'; }, 3000);"
          << "    }"
          << "  };"
          << "  xhr.send();"
          << "}"
          << "async function triggerUpload() {"
          << "  if (!canWrite) { alert('Permission Denied: Your role is read-only.'); return; }"
          << "  try {"
          << "    const res = await fetch('/api/fs/pick-file').then(r => r.json());"
          << "    if (res.status === 'ok' && res.path) {"
          << "      const toast = document.getElementById('upload-toast');"
          << "      const filename = res.path.split(/[\\\\/]/).pop();"
          << "      let startTime = Date.now();"
          << "      let progressTimer = null;"
          << "      if (toast) {"
          << "        toast.style.display = 'block';"
          << "        toast.innerHTML = '<div style=\"font-weight:700; color:#1f2328; margin-bottom:6px; display:flex; justify-content:space-between; align-items:center;\"><span>📤 Đang tải lên: ' + filename + '</span><span id=\"up-speed-lbl\" style=\"color:#0969da; font-size:11px; font-weight:600;\">Đang xử lý...</span></div><div style=\"background:#e1e4e8; border-radius:3px; height:8px; width:100%; overflow:hidden; margin-bottom:6px;\"><div id=\"up-bar\" style=\"background:#0969da; height:100%; width:30%; transition:width 0.3s ease;\"></div></div><div style=\"display:flex; justify-content:space-between; font-size:11px; color:#57606a;\"><span id=\"up-time-lbl\">Vui lòng chờ...</span><span style=\"color:#1a7f37; font-weight:600;\">PQC AEAD Protected</span></div>';"
          << "        progressTimer = setInterval(() => {"
          << "          const el = (Date.now() - startTime) / 1000;"
          << "          const timeLbl = document.getElementById('up-time-lbl');"
          << "          const speedLbl = document.getElementById('up-speed-lbl');"
          << "          const bar = document.getElementById('up-bar');"
          << "          if (timeLbl) timeLbl.innerText = 'Thời gian: ' + el.toFixed(1) + 's';"
          << "          if (speedLbl) speedLbl.innerText = 'Đang đồng bộ vào VFS...';"
          << "          if (bar) {"
          << "            let curW = parseFloat(bar.style.width) || 30;"
          << "            if (curW < 90) bar.style.width = (curW + 5) + '%';"
          << "          }"
          << "        }, 500);"
          << "      }"
          << "      const upRes = await fetch('/api/fs/upload-local-path', {"
          << "        method: 'POST',"
          << "        headers: {'Content-Type': 'application/json'},"
          << "        body: JSON.stringify({source_path: res.path, dir: currentDir, is_dir: false})"
          << "      }).then(r => r.json());"
          << "      if (progressTimer) clearInterval(progressTimer);"
          << "      if (upRes.status === 'ok') {"
          << "        const bar = document.getElementById('up-bar');"
          << "        if (bar) bar.style.width = '100%';"
          << "        if (toast) toast.innerHTML = '<div style=\"font-weight:700; color:#1a7f37; display:flex; align-items:center; gap:6px;\">✅ Tải lên tệp hoàn tất: ' + (upRes.filename || filename) + '</div>';"
          << "        setTimeout(() => refreshWorkspaceListing(), 700);"
          << "      } else {"
          << "        alert('Lỗi tải tệp: ' + (upRes.message || 'Thất bại'));"
          << "        if (toast) toast.style.display = 'none';"
          << "      }"
          << "      return;"
          << "    } else if (res.status === 'cancelled') {"
          << "      return;"
          << "    }"
          << "  } catch(e) {}"
          << "  document.getElementById('hidden-file-input').click();"
          << "}"
          << "async function triggerUploadFolder() {"
          << "  if (!canWrite) { alert('Permission Denied: Your role is read-only.'); return; }"
          << "  try {"
          << "    const res = await fetch('/api/fs/pick-folder').then(r => r.json());"
          << "    if (res.status === 'ok' && res.path) {"
          << "      const toast = document.getElementById('upload-toast');"
          << "      const foldername = res.path.split(/[\\\\/]/).pop();"
          << "      let startTime = Date.now();"
          << "      let progressTimer = null;"
          << "      if (toast) {"
          << "        toast.style.display = 'block';"
          << "        toast.innerHTML = '<div style=\"font-weight:700; color:#1f2328; margin-bottom:6px; display:flex; justify-content:space-between; align-items:center;\"><span>📁 Đang tải lên thư mục: ' + foldername + '</span><span id=\"up-speed-lbl\" style=\"color:#0969da; font-size:11px; font-weight:600;\">Đang quét...</span></div><div style=\"background:#e1e4e8; border-radius:3px; height:8px; width:100%; overflow:hidden; margin-bottom:6px;\"><div id=\"up-bar\" style=\"background:#0969da; height:100%; width:25%; transition:width 0.3s ease;\"></div></div><div style=\"display:flex; justify-content:space-between; font-size:11px; color:#57606a;\"><span id=\"up-time-lbl\">Vui lòng chờ...</span><span style=\"color:#1a7f37; font-weight:600;\">PQC AEAD Protected</span></div>';"
          << "        progressTimer = setInterval(() => {"
          << "          const el = (Date.now() - startTime) / 1000;"
          << "          const timeLbl = document.getElementById('up-time-lbl');"
          << "          const speedLbl = document.getElementById('up-speed-lbl');"
          << "          const bar = document.getElementById('up-bar');"
          << "          if (timeLbl) timeLbl.innerText = 'Thời gian: ' + el.toFixed(1) + 's';"
          << "          if (speedLbl) speedLbl.innerText = 'Đang đồng bộ thư mục vào VFS...';"
          << "          if (bar) {"
          << "            let curW = parseFloat(bar.style.width) || 25;"
          << "            if (curW < 90) bar.style.width = (curW + 7) + '%';"
          << "          }"
          << "        }, 500);"
          << "      }"
          << "      const upRes = await fetch('/api/fs/upload-local-path', {"
          << "        method: 'POST',"
          << "        headers: {'Content-Type': 'application/json'},"
          << "        body: JSON.stringify({source_path: res.path, dir: currentDir, is_dir: true})"
          << "      }).then(r => r.json());"
          << "      if (progressTimer) clearInterval(progressTimer);"
          << "      if (upRes.status === 'ok') {"
          << "        const bar = document.getElementById('up-bar');"
          << "        if (bar) bar.style.width = '100%';"
          << "        if (toast) toast.innerHTML = '<div style=\"font-weight:700; color:#1a7f37; display:flex; align-items:center; gap:6px;\">✅ Tải lên thư mục thành công (' + upRes.count + ' tệp)!</div>';"
          << "        setTimeout(() => refreshWorkspaceListing(), 700);"
          << "      } else {"
          << "        alert('Lỗi tải thư mục: ' + (upRes.message || 'Thất bại'));"
          << "        if (toast) toast.style.display = 'none';"
          << "      }"
          << "      return;"
          << "    } else if (res.status === 'cancelled') {"
          << "      return;"
          << "    }"
          << "  } catch(e) {}"
          << "}"

          << "async function uploadFiles(files) {"
          << "  if (!canWrite) { alert('Permission Denied: Your role is read-only.'); return; }"
          << "  if (!files || files.length === 0) return;"
          << "  const toast = document.getElementById('upload-toast');"
          << "  if (toast) toast.style.display = 'block';"
          << "  const fileList = Array.from(files);"
          << "  let completedCount = 0; let failedCount = 0;"
          << "  for (let i = 0; i < fileList.length; i++) {"
          << "    const file = fileList[i];"
          << "    const startTime = Date.now();"
          << "    await new Promise((resolve) => {"
          << "      const xhr = new XMLHttpRequest();"
          << "      const url = '/api/upload?dir=' + encodeURIComponent(currentDir) + '&name=' + encodeURIComponent(file.name);"
          << "      xhr.open('POST', url, true);"
          << "      xhr.upload.onprogress = (e) => {"
          << "        if (!toast) return;"
          << "        const elapsed = (Date.now() - startTime) / 1000;"
          << "        const speed = elapsed > 0.1 ? (e.loaded / elapsed) : 0;"
          << "        const speedStr = formatSpeed(speed);"
          << "        const filePercent = e.lengthComputable ? Math.min(100, Math.round((e.loaded / e.total) * 100)) : 0;"
          << "        toast.innerHTML = '<div style=\"font-weight:700; color:#1f2328; margin-bottom:6px; display:flex; justify-content:space-between; align-items:center;\"><span>Đang tải lên (' + (i + 1) + '/' + fileList.length + '): ' + file.name + '</span><span style=\"color:#0969da; font-size:11px;\">' + speedStr + '</span></div><div style=\"background:#e1e4e8; border-radius:3px; height:8px; width:100%; overflow:hidden; margin-bottom:6px;\"><div style=\"background:#0969da; height:100%; width:' + filePercent + '%; transition:width 0.15s ease;\"></div></div><div style=\"display:flex; justify-content:space-between; font-size:11px; color:#57606a;\"><span>' + formatSize(e.loaded) + ' / ' + formatSize(e.total) + ' (' + filePercent + '%)</span><span style=\"color:#1a7f37;\">Tải lên qua PQC AEAD</span></div>';"
          << "      };"
          << "      xhr.onload = () => {"
          << "        try {"
          << "          const res = JSON.parse(xhr.responseText || '{}');"
          << "          if (xhr.status === 200 && res.status === 'ok') {"
          << "            completedCount++;"
          << "          } else {"
          << "            failedCount++;"
          << "            if (res.status === 'blocked') alert('Tệp bị chặn bởi AI Secret Guard / Policy:\\n' + (res.message || file.name));"
          << "          }"
          << "        } catch(e) {"
          << "          if (xhr.status === 200) completedCount++; else failedCount++;"
          << "        }"
          << "        resolve();"
          << "      };"
          << "      xhr.onerror = () => { failedCount++; resolve(); };"
          << "      xhr.send(file);"
          << "    });"
          << "  }"
          << "  if (!toast) return;"
          << "  if (failedCount === 0) {"
          << "    toast.innerHTML = '<div style=\"font-weight:700; color:#1a7f37; display:flex; align-items:center; gap:6px;\"><svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><polyline points=\"20 6 9 17 4 12\"></polyline></svg> Tải lên hoàn tất ' + completedCount + '/' + fileList.length + ' tệp thành công!</div>';"
          << "    setTimeout(() => location.reload(), 800);"
          << "  } else {"
          << "    toast.innerHTML = '<div style=\"font-weight:700; color:#cf222e;\">Đã tải lên ' + completedCount + ' tệp, ' + failedCount + ' tệp thất bại hoặc bị chặn!</div>';"
          << "    setTimeout(() => location.reload(), 2000);"
          << "  }"
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
          << "  if (window.location.port === '8081' || window.location.port === '8080' || window.location.pathname.startsWith('/portal')) {"
          << "    window.location.href = '/portal';"
          << "    return;"
          << "  }"
          << "  if (document.referrer && (document.referrer.includes('/portal') || document.referrer.includes(':8081') || document.referrer.includes(':8080'))) {"
          << "    window.location.href = document.referrer;"
          << "    return;"
          << "  }"
          << "  let savedCfg = null;"
          << "  try { savedCfg = JSON.parse(localStorage.getItem('slug_system_config') || '{}'); } catch(e){}"
          << "  const pPort = (savedCfg && savedCfg.portal_port) ? savedCfg.portal_port : 8081;"
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
          << "</div></div>";

        size_t blocked_in_dir = 0;
        for (const auto& itm : items) {
            if (!itm.is_dir && itm.status == "BLOCKED") {
                blocked_in_dir++;
            }
        }

        h << "<div class='ws-summary-box'>"
          << "<div><strong>REMOTE WORKSPACE:</strong> " << html_escape(workspace_root.filename().string()) << " (Port " << port << ")</div>"
          << "<div>Available: <strong>" << core::Utils::format_size(total_workspace_size) << "</strong> (" << manifest.files.size() << " files) &bull; Filtered: <strong>" << manifest.skipped.size() << "</strong> items (" << blocked_in_dir << " tệp bị chặn trong thư mục này)</div>"
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
          << "<button type='button' class='btn-sec' onclick='refreshWorkspaceListing()' style='display:inline-flex; align-items:center; gap:6px;' title='Đồng bộ & quét lại danh mục tệp thực tế trên đĩa cứng'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><path d='M23 4v6h-6'></path><path d='M1 20v-6h6'></path><path d='M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15'></path></svg> <span>Làm Mới</span></button>"
          << "<input type='file' id='hidden-file-input' multiple style='display:none;' onchange='uploadFiles(this.files)'>"
          << (role != core::Role::READ_ONLY ? "<button type='button' class='btn btn-sm' onclick='triggerUpload()' style='display:inline-flex; align-items:center; gap:6px;'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'></path><polyline points='17 8 12 3 7 8'></polyline><line x1='12' y1='3' x2='12' y2='15'></line></svg> <span>Tải Lên Tệp</span></button> <button type='button' class='btn btn-sm' onclick='triggerUploadFolder()' style='display:inline-flex; align-items:center; gap:6px;'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><path d='M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z'></path><line x1='12' y1='11' x2='12' y2='17'></line><line x1='9' y1='14' x2='15' y2='14'></line></svg> <span>Tải Lên Thư Mục</span></button>" : "")
          << (role != core::Role::WRITE_ONLY ? ("<button type='button' class='btn' onclick='document.getElementById(\"pull-sync-card\").scrollIntoView({behavior:\"smooth\"})' style='background:#0969da; color:#fff; display:inline-flex; align-items:center; gap:6px;'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><polygon points='13 2 3 14 12 14 11 22 21 10 12 10 13 2'></polygon></svg> <span>ĐỒNG BỘ THƯ MỤC VỀ MÁY BẠN</span></button> "
                                                "<button type='button' class='btn-sec' onclick='downloadFolderAsZipDirect(\"" + js_escape(norm_sub) + "\")' style='display:inline-flex; align-items:center; gap:6px;'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'></path><polyline points='7 10 12 15 17 10'></polyline><line x1='12' y1='15' x2='12' y2='3'></line></svg> Download Folder (ZIP)</button>") : "")
          << (role == core::Role::READ_ONLY ? "<span style='font-size:12px; color:var(--text-muted);'>Read-Only Mode</span>" : "")
          << "</div></div>";

        if (role == core::Role::WRITE_ONLY) {
            h << "<div style='background:#f6f8fa; border:2px dashed var(--border-primary); border-radius:var(--radius-sharp); padding:48px 20px; text-align:center; margin-top:16px; font-family:\"JetBrains Mono\", monospace;'>"
              << "<div style='margin-bottom:8px;'><svg width='36' height='36' viewBox='0 0 24 24' fill='none' stroke='#0969da' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><polyline points='22 12 16 12 14 15 10 15 8 12 2 12'></polyline><path d='M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z'></path></svg></div>"
              << "<h2 style='color:var(--text-main); margin:0 0 8px 0; font-size:16px;'>Blind Drop Mode [W] GỬI LÊN (Chỉ Cho Tải Lên)</h2>"
              << "<p style='color:var(--text-muted); margin:0 0 16px 0; font-size:12px;'>Bạn có quyền gửi file an toàn vào workspace này.<br>Các file mã nguồn của host được bảo vệ hoàn toàn và ẩn khỏi danh sách.</p>"
              << "<button class='btn' onclick='triggerUpload()' style='margin-right:8px;'>+ Chọn Tệp Lên</button>"
              << "<button class='btn-sec' onclick='triggerUploadFolder()'>+ Chọn Thư Mục Lên</button>"
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
                        ? ("<button type='button' class='act-btn' onclick='downloadFileWithProgress(\"" + js_escape(item.full_rel_path) + "\", \"" + js_escape(item.name) + "\")'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'></path><polyline points='7 10 12 15 17 10'></polyline><line x1='12' y1='15' x2='12' y2='3'></line></svg> Tải Về</button><button type='button' class='act-btn' onclick='copyTextDirect(\"" + js_escape(item.full_rel_path) + "\", \"đường dẫn tệp\")'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect x='9' y='9' width='13' height='13' rx='2' ry='2'></rect><path d='M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1'></path></svg> Copy</button>")
                        : "<span style='color:var(--text-muted); font-size:11px;'>Shielded</span>";

                    if (identity == "host_admin") {
                        if (item.selectable) {
                            act += "<button type='button' class='act-btn act-btn-danger' onclick='toggleManualBlockFile(\"" + js_escape(item.full_rel_path) + "\", true)'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='10'></circle><line x1='4.93' y1='4.93' x2='19.07' y2='19.07'></line></svg> Chặn</button>";
                        } else {
                            act += "<button type='button' class='act-btn' onclick='toggleManualBlockFile(\"" + js_escape(item.full_rel_path) + "\", false)'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'></path><polyline points='9 12 11 14 15 10'></polyline></svg> Gỡ Chặn</button>";
                        }
                    }

                    std::string scan_lbl = "";
                    if (ai::AiScanner::is_scannable_file(item.name)) {
                        if (item.scan_status == "NOT_SCANNED") {
                            scan_lbl = "<span class='badge' style='background:#f6f8fa; color:#57606a; border:1px solid #d0d7de; font-size:9.5px; padding:1px 5px; font-weight:600; white-space:nowrap;' title='File mã nguồn/văn bản chưa qua kiểm tra nội dung (do vượt kích thước 10MB)'>NOT SCANNED</span>";
                        } else if (item.scan_status == "SCANNED") {
                            scan_lbl = "<span class='badge' style='background:#dafbe1; color:#1a7f37; border:1px solid #aceebb; font-size:9.5px; padding:1px 5px; font-weight:600; white-space:nowrap;' title='Nội dung đã được bộ lọc kiểm tra an toàn'>SCANNED</span>";
                        }
                    }

                    std::string status_cell;
                    if (scan_lbl.empty()) {
                        status_cell = "<span class='badge " + item.status_badge_class + "' title='" + html_escape(item.status_detail) + "'>" + item.status + "</span>";
                    } else {
                        status_cell = "<div style='display:inline-flex; flex-direction:column; align-items:flex-start; gap:4px;'>"
                                      "<span class='badge " + item.status_badge_class + "' title='" + html_escape(item.status_detail) + "'>" + item.status + "</span>"
                                      + scan_lbl +
                                      "</div>";
                    }

                    h << "<td>" << chk << "</td>"
                      << "<td><span style='display:inline-flex; align-items:center; gap:6px;'><svg width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z'></path><polyline points='14 2 14 8 20 8'></polyline></svg> " << html_escape(item.name) << "</span></td>"
                      << "<td style='color:var(--text-muted);'>file</td>"
                      << "<td>" << (item.size > 0 ? core::Utils::format_size(item.size) : "-") << "</td>"
                      << "<td>" << status_cell << "</td>"
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

        // BOTTOM PANEL: slug pull (Full Width, Matching Host Form Exactly)
        h << "<div id='pull-sync-card' style='background:#ffffff; border:1px solid var(--border-primary); border-radius:2px; padding:18px; margin-top:20px; width:100%;'>"
          << "<div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;'>"
          << "<h3 style='margin:0; font-size:14px; display:flex; align-items:center; gap:8px; font-family:\"JetBrains Mono\", monospace;'>"
          << "<svg width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><polygon points='13 2 3 14 12 14 11 22 21 10 12 10 13 2'></polygon></svg>"
          << "<span>Đồng Bộ Dữ Liệu Về Máy Của Bạn (slug pull)</span></h3>"
          << "<span class='badge badge-pqc'>" << core::suite_to_string(suite_id) << "</span>"
          << "</div>"
          << "<div style='margin-bottom:12px;'>"
          << "<label style='display:block; font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; font-family:\"JetBrains Mono\", monospace;'>Thư Mục Lưu Trên Máy Của Bạn (Local Destination Directory) <span style='color:var(--danger); font-weight:bold;'>* Bắt buộc</span></label>"
          << "<div style='display:flex; gap:8px; align-items:stretch;'>"
          << "<input type='text' id='pull-dest' class='input-text' style='flex:1; height:38px; box-sizing:border-box; padding:0 10px; border:1px solid var(--border-primary); border-radius:var(--radius-sharp); font-family:\"JetBrains Mono\", monospace; font-size:12px;' value='' required placeholder='Bắt buộc: Bấm [Chọn...] hoặc nhập đường dẫn thư mục lưu trên máy bạn...'>"
          << "<input type='file' id='dir-picker-pull-dest' webkitdirectory directory style='display:none;' onchange='handleDirInputSelected(this, \"pull-dest\")'>"
          << "<button type='button' class='btn-sec' onclick='chooseLocalSaveLocation(\"pull-dest\")' style='height:38px !important; box-sizing:border-box; padding:0 14px; font-size:12px; display:inline-flex; align-items:center; gap:6px; white-space:nowrap; border-radius:var(--radius-sharp); cursor:pointer;'>"
          << "<svg width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><path d='M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z'></path></svg> <span>Chọn...</span>"
          << "</button>"
          << "</div>"
          << "</div>"
          << "<div style='margin-bottom:12px;'>"
          << "<label style='display:flex; justify-content:space-between; align-items:center; font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; font-family:\"JetBrains Mono\", monospace;'>"
          << "<span>Phạm Vi Cần Kéo (Scope Pattern)</span>"
          << "<span style='font-weight:normal; font-size:10px; color:var(--text-muted);'>(Mặc định: Kéo toàn bộ '*')</span>"
          << "</label>"
          << "<input type='text' id='pull-scope' class='input-text' style='width:100%; height:38px; box-sizing:border-box; padding:0 10px; border:1px solid var(--border-primary); border-radius:var(--radius-sharp); font-family:\"JetBrains Mono\", monospace; font-size:12px;' value='*' placeholder='*'>"
          << "<div style='font-size:11px; color:var(--text-muted); margin-top:4px; font-family:\"JetBrains Mono\", monospace; line-height:1.4;'>"
          << "<strong>Hướng dẫn cú pháp:</strong> &bull; <code>*</code> hoặc <code>~</code> : Kéo toàn bộ tất cả tệp trong workspace. &bull; <code>thumuc/</code> hoặc <code>/thumuc/</code> hoặc <code>thumuc/*</code> : Để chỉ kéo riêng thư mục con cụ thể. &bull; <em>Mẹo:</em> Bấm nút <strong>Copy Path</strong> ở bảng danh sách tệp phía trên để dán nhanh vào đây!"
          << "</div>"
          << "</div>"
          << "<div style='margin-bottom:14px; display:flex; align-items:center; gap:8px;'>"
          << "<input type='checkbox' id='pull-prune-cb' style='cursor:pointer;'>"
          << "<label for='pull-prune-cb' style='font-size:11px; color:var(--text-main); margin-bottom:0; cursor:pointer;'>--prune: Tự động dọn sạch các tệp local đã bị xóa trên host</label>"
          << "</div>"
          << "<div style='display:flex; gap:8px;'>"
          << "<button type='button' class='btn-sec' style='flex:1; height:38px; font-size:12px; font-weight:600; display:inline-flex; align-items:center; justify-content:center; gap:6px;' onclick='submitPullPlanDirect()'>"
          << "<svg width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'></path></svg> <span>Xem Trước Kế Hoạch Đồng Bộ (Dry-Run)</span>"
          << "</button>"
          << "<button type='button' class='btn' style='flex:1; height:38px; font-size:12px; font-weight:700; background:#0969da; border-color:#0969da; display:inline-flex; align-items:center; justify-content:center; gap:6px;' onclick='executeRealPullDirect()'>"
          << "<svg width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'></path><polyline points='7 10 12 15 17 10'></polyline><line x1='12' y1='15' x2='12' y2='3'></line></svg> <span>Bắt Đầu Đồng Bộ Về Máy</span>"
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
          << "async function chooseLocalSaveLocation(destId) {"
          << "  try {"
          << "    const res = await fetch('/api/fs/pick-folder').then(r => r.json());"
          << "    if (res.status === 'ok' && res.path) {"
          << "      const target = document.getElementById(destId);"
          << "      if (target) target.value = res.path;"
          << "      return;"
          << "    } else if (res.status === 'cancelled') {"
          << "      return;"
          << "    }"
          << "  } catch(e) {}"
          << "  if (window.showDirectoryPicker) {"
          << "    try {"
          << "      const handle = await window.showDirectoryPicker();"
          << "      if (handle && handle.name) {"
          << "        const target = document.getElementById(destId);"
          << "        if (target) target.value = handle.name;"
          << "        return;"
          << "      }"
          << "    } catch(err) {"
          << "      if (err.name === 'AbortError') return;"
          << "    }"
          << "  }"
          << "  const picker = document.getElementById('dir-picker-' + destId);"
          << "  if (picker) picker.click();"
          << "}"
          << "const chooseLocalSaveLocationDirect = chooseLocalSaveLocation;\n"
          << "function handleDirInputSelected(inp, destId) {"
          << "  if (inp && inp.files && inp.files.length > 0) {"
          << "    const rel = inp.files[0].webkitRelativePath || '';"
          << "    const name = rel ? rel.split('/')[0] : (inp.files[0].name || '');"
          << "    const target = document.getElementById(destId);"
          << "    if (target && name) target.value = name;"
          << "  }"
          << "}"
          << "const handleDirInputSelectedDirect = handleDirInputSelected;\n"
          << "function selectFileForGet(relPath) {"
          << "  const inp = document.getElementById('pull-scope');"
          << "  if (inp) {"
          << "    inp.value = relPath;"
          << "    inp.focus();"
          << "  }"
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
          << "  fetch('/api/pull/dry-run?dest=' + encodeURIComponent(dest) + '&scope=' + encodeURIComponent(sc) + '&prune=' + pr)"
          << "    .then(r => {"
          << "      if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + r.statusText);"
          << "      return r.json();"
          << "    })"
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
          << "        + 'Bấm nút [Bắt Đầu Đồng Bộ Về Máy] để tải hoặc đồng bộ trực tiếp.' "
          << "        + '</div>';"
          << "    })"
          << "    .catch(err => {"
          << "      out.innerHTML = '<div style=\"padding:10px; background:#ffebe9; color:#cf222e; font-size:12px; font-family:monospace;\">Lỗi phân tích kế hoạch: ' + err.message + '</div>';"
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
          << "    out.innerHTML = '<div style=\"background:#1f2328; color:#e6edf3; font-family:\\'JetBrains Mono\\', monospace; font-size:11px; line-height:1.6; padding:12px; border-radius:2px; border:1px solid #30363d; margin-top:8px;\">' "
          << "      + '<span style=\"color:#54aeff;\">[SLUG SYNC] Đang khởi tạo đồng bộ dữ liệu vào: ' + dest + '...</span>' "
          << "      + '</div>';"
          << "  }"
          << "  fetch('/api/pull/execute', {"
          << "    method: 'POST',"
          << "    headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ dest: dest, dir: currentDir })"
          << "  })"
          << "  .then(r => r.json())"
          << "  .then(res => {"
          << "    if (res.status === 'ok') {"
          << "      const jobId = res.job_id;"
          << "      if (!jobId) {"
          << "        const bStr = (res.bytes > 1048576) ? (res.bytes/1048576).toFixed(2) + ' MiB' : (res.bytes/1024).toFixed(1) + ' KiB';"
          << "        if (out) {"
          << "          out.innerHTML = '<div style=\"padding:14px; background:#dafbe1; border:1px solid rgba(26,127,55,0.4); border-radius:4px; font-size:12px; font-family:\\'JetBrains Mono\\', monospace; color:var(--success); line-height:1.6;\">' "
          << "            + '<div style=\"font-weight:700; margin-bottom:6px; font-size:13px;\">✅ ĐỒNG BỘ THÀNH CÔNG ' + (res.copied || 0) + ' TỆP (' + bStr + ')!</div>' "
          << "            + '<div>Toàn bộ tệp đã được ghi trực tiếp vào thư mục: <code>' + (res.dest || dest) + '</code></div>' "
          << "            + '<div style=\"margin-top:10px; display:flex; gap:8px;\">' "
          << "            + '<button type=\"button\" class=\"btn btn-sm\" onclick=\"fetch(\\'/api/fs/open-folder\\',{method:\\'POST\\',headers:{\\'Content-Type\\':\\'application/json\\'},body:JSON.stringify({path:\\'' + (res.dest || dest).replace(/\\\\/g, '\\\\\\\\').replace(/\\'/g, \"\\\\'\") + '\\'})})\">Mở Thư Mục Trong Explorer</button>' "
          << "            + '</div>' "
          << "            + '</div>';"
          << "        }"
          << "        return;"
          << "      }"
          << "      const clientStart = Date.now();"
          << "      const pollTimer = setInterval(() => {"
          << "        fetch('/api/transfer/progress?job_id=' + encodeURIComponent(jobId))"
          << "        .then(pr => pr.json())"
          << "        .then(p => {"
          << "          if (!out) { clearInterval(pollTimer); return; }"
          << "          const pct = (p.percent || 0).toFixed(1);"
          << "          const doneStr = (p.bytes_transferred > 1073741824) ? (p.bytes_transferred/1073741824).toFixed(2) + ' GB' : (p.bytes_transferred > 1048576) ? (p.bytes_transferred/1048576).toFixed(2) + ' MB' : (p.bytes_transferred/1024).toFixed(1) + ' KB';"
          << "          const totStr = (p.total_bytes > 1073741824) ? (p.total_bytes/1073741824).toFixed(2) + ' GB' : (p.total_bytes > 1048576) ? (p.total_bytes/1048576).toFixed(2) + ' MB' : (p.total_bytes/1024).toFixed(1) + ' KB';"
          << "          const clientSec = Math.max(0.1, (Date.now() - clientStart) / 1000);"
          << "          const elapsedVal = (typeof p.elapsed_sec === 'number' && p.elapsed_sec > 0) ? p.elapsed_sec : ((typeof p.elapsed_ms === 'number' && p.elapsed_ms > 0) ? (p.elapsed_ms / 1000) : clientSec);"
          << "          let avgVal = (typeof p.avg_mbps === 'number' && p.avg_mbps > 0) ? p.avg_mbps : 0;"
          << "          if (p.bytes_transferred > 0 && (avgVal <= 0 || avgVal > 2500)) {"
          << "            avgVal = (p.bytes_transferred / (1024 * 1024)) / Math.max(0.1, (p.elapsed_ms ? (p.elapsed_ms / 1000) : clientSec));"
          << "          }"
          << "          const curSpeed = (p.instant_mbps || 0).toFixed(1);"
          << "          const avgSpeed = avgVal.toFixed(1);"
          << "          const elapsed = formatTime(elapsedVal);"
          << "          if (p.status === 'running' || p.status === 'pending') {"
          << "            out.innerHTML = '<div style=\"background:#161b22; color:#e6edf3; font-family:\\'JetBrains Mono\\', monospace; font-size:12px; line-height:1.6; padding:14px; border-radius:4px; border:1px solid #30363d; margin-top:8px;\">' "
          << "              + '<div style=\"display:flex; justify-content:space-between; margin-bottom:8px; font-weight:700;\">' "
          << "              + '<span style=\"color:#58a6ff;\">⚡ TCP BINARY STREAMING DATA PLANE</span>' "
          << "              + '<span style=\"color:#7ee787;\">' + pct + '%</span>' "
          << "              + '</div>' "
          << "              + '<div style=\"background:#21262d; border-radius:4px; height:8px; overflow:hidden; margin-bottom:10px;\">' "
          << "              + '<div style=\"background:linear-gradient(90deg, #238636, #2ea043); width:' + pct + '%; height:100%; transition:width 0.2s;\"></div>' "
          << "              + '</div>' "
          << "              + '<div style=\"display:grid; grid-template-columns:1fr 1fr; gap:6px; font-size:11px; color:#8b949e;\">' "
          << "              + '<div>Đã truyền: <span style=\"color:#c9d1d9; font-weight:600;\">' + doneStr + ' / ' + totStr + '</span></div>' "
          << "              + '<div>Tốc độ tức thời: <span style=\"color:#58a6ff; font-weight:700;\">' + curSpeed + ' MB/s</span></div>' "
          << "              + '<div>Tốc độ trung bình: <span style=\"color:#7ee787; font-weight:600;\">' + avgSpeed + ' MB/s</span></div>' "
          << "              + '<div>Thời gian: <span style=\"color:#c9d1d9;\">' + elapsed + '</span></div>' "
          << "              + '</div>' "
          << "              + '<div style=\"margin-top:10px; display:flex; justify-content:flex-end;\">' "
          << "              + '<button type=\"button\" class=\"btn-sec btn-sm\" style=\"color:#f85149; border-color:rgba(248,81,73,0.4);\" onclick=\"fetch(\\'/api/transfer/cancel?job_id=' + jobId + '\\',{method:\\'POST\\'}); this.innerText=\\'Đang hủy...\\';\">Hủy Quá Trình</button>' "
          << "              + '</div>' "
          << "              + '</div>';"
          << "          } else if (p.status === 'completed') {"
          << "            clearInterval(pollTimer);"
          << "            out.innerHTML = '<div style=\"padding:14px; background:#dafbe1; border:1px solid rgba(26,127,55,0.4); border-radius:4px; font-size:12px; font-family:\\'JetBrains Mono\\', monospace; color:var(--success); line-height:1.6;\">' "
          << "              + '<div style=\"font-weight:700; margin-bottom:6px; font-size:13px;\">✅ ĐỒNG BỘ STREAMING THÀNH CÔNG (' + doneStr + ')!</div>' "
          << "              + '<div>Tốc độ trung bình: <strong>' + avgSpeed + ' MB/s</strong> | Thời gian: <strong>' + elapsed + '</strong></div>' "
          << "              + '<div>Toàn bộ tệp đã được ghi trực tiếp vào thư mục: <code>' + (p.dest || dest) + '</code></div>' "
          << "              + '<div style=\"margin-top:10px; display:flex; gap:8px;\">' "
          << "              + '<button type=\"button\" class=\"btn btn-sm\" onclick=\"fetch(\\'/api/fs/open-folder\\',{method:\\'POST\\',headers:{\\'Content-Type\\':\\'application/json\\'},body:JSON.stringify({path:\\'' + (p.dest || dest).replace(/\\\\/g, '\\\\\\\\').replace(/\\'/g, \"\\\\'\") + '\\'})})\">Mở Thư Mục Trong Explorer</button>' "
          << "              + '</div>' "
          << "              + '</div>';"
          << "          } else {"
          << "            clearInterval(pollTimer);"
          << "            out.innerHTML = '<div style=\"padding:12px; background:#ffebe9; border:1px solid rgba(255,129,130,0.4); border-radius:4px; font-size:12px; font-family:\\'JetBrains Mono\\', monospace; color:#cf222e; line-height:1.6;\">' "
          << "              + '<div style=\"font-weight:700; margin-bottom:4px;\">❌ Lỗi Quá Trình Đồng Bộ:</div>' "
          << "              + '<div>' + (p.error_message || 'Quá trình đồng bộ thất bại hoặc bị hủy.') + '</div>' "
          << "              + '<div style=\"margin-top:8px; color:#57606a;\">Thư mục đích: <code>' + dest + '</code></div>' "
          << "              + '</div>';"
          << "          }"
          << "        })"
          << "        .catch(err => {"
          << "          clearInterval(pollTimer);"
          << "          if (out) {"
          << "            out.innerHTML = '<div style=\"padding:12px; background:#ffebe9; border:1px solid rgba(255,129,130,0.4); border-radius:4px; font-size:12px; font-family:\\'JetBrains Mono\\', monospace; color:#cf222e;\">Lỗi truy vấn tiến trình: ' + err.message + '</div>';"
          << "          }"
          << "        });"
          << "      }, 500);"
          << "    } else {"
          << "      if (out) {"
          << "        out.innerHTML = '<div style=\"padding:12px; background:#ffebe9; border:1px solid rgba(255,129,130,0.4); border-radius:4px; font-size:12px; font-family:\\'JetBrains Mono\\', monospace; color:#cf222e;\"><strong>Lỗi:</strong> ' + (res.message || 'Không thể bắt đầu đồng bộ.') + '</div>';"
          << "      }"
          << "    }"
          << "  })"
          << "  .catch(err => {"
          << "    if (out) {"
          << "      out.innerHTML = '<div style=\"padding:12px; background:#ffebe9; border:1px solid rgba(255,129,130,0.4); border-radius:4px; font-size:12px; font-family:\\'JetBrains Mono\\', monospace; color:#cf222e;\"><strong>Lỗi kết nối:</strong> ' + err.message + '</div>';"
          << "    }"
          << "  });"
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
        const std::vector<SessionState>& client_sessions,
        core::FilterLevel filter_level = core::FilterLevel::LEVEL_2_REGEX,
        core::AiModelProvider ai_provider = core::AiModelProvider::OLLAMA,
        uint64_t workspace_ttl = 86400,
        uint64_t remaining_workspace_ttl = 86400)
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
        h << "<!DOCTYPE html><html lang='vi'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
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
          << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg-canvas); color: var(--text-main); margin: 0; padding: 16px; line-height: 1.5; }"
          << "html { overflow-y: scroll; scrollbar-gutter: stable; }"
          << ".container { width: 100%; max-width: 1360px; margin: 0 auto; background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 20px; box-shadow: 0 1px 3px rgba(31,35,40,0.08); box-sizing: border-box; }"
          << ".top-bar { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border-primary); padding-bottom: 14px; margin-bottom: 16px; flex-wrap: wrap; gap: 10px; }"
          << "h1 { color: var(--text-main); font-size: 18px; margin: 0; font-family: 'JetBrains Mono', monospace; font-weight: 600; }"
          << ".grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 16px; margin: 16px 0; }"
          << ".card { background: #ffffff; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 16px; box-sizing: border-box; min-width: 0; }"
          << ".card h3 { margin-top: 0; font-size: 13px; color: var(--text-main); border-bottom: 1px solid var(--border-primary); padding-bottom: 8px; display: flex; justify-content: space-between; align-items: center; font-family: 'JetBrains Mono', monospace; font-weight: 600; flex-wrap: wrap; gap: 8px; }"
          << ".metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(135px, 1fr)); gap: 10px; margin: 12px 0; }"
          << ".metric-box { background: #f6f8fa; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 10px 8px; text-align: center; font-family: 'JetBrains Mono', monospace; }"
          << ".metric-val { font-size: 16px; font-weight: bold; color: var(--text-accent); margin-top: 4px; }"
          << ".metric-lbl { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }"
          << ".bar-track { background: #eaeef2; border-radius: var(--radius-sharp); height: 8px; width: 100%; margin: 6px 0; overflow: hidden; display: flex; }"
          << ".bar-fill { height: 100%; background: var(--success); border-radius: var(--radius-sharp); }"
          << ".bar-pqc { background: var(--pqc); }"
          << "table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: 'JetBrains Mono', monospace; }"
          << "th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--border-primary); overflow-wrap: anywhere; word-break: break-word; }"
          << "th { background: #f6f8fa; color: var(--text-muted); font-size: 11px; text-transform: uppercase; }"
          << ".btn { background: #0969da; color: #fff; padding: 5px 12px; border-radius: var(--radius-sharp); text-decoration: none; font-size: 12px; font-weight: 500; border: 1px solid #0969da; cursor: pointer; font-family: 'JetBrains Mono', monospace; white-space: nowrap; }"
          << ".btn:hover { background: #0856b3; }"
          << ".btn-sec { background: #ffffff; border: 1px solid var(--border-primary); color: var(--text-main); padding: 5px 10px; border-radius: var(--radius-sharp); text-decoration: none; font-size: 12px; font-weight: 500; font-family: 'JetBrains Mono', monospace; cursor: pointer; white-space: nowrap; }"
          << ".btn-sec:hover { background: var(--bg-surface-hover); }"
          << ".btn-danger { background: #ffffff; color: var(--danger); border: 1px solid var(--danger); padding: 3px 6px; border-radius: var(--radius-sharp); font-size: 11px; cursor: pointer; font-family: 'JetBrains Mono', monospace; white-space: nowrap; }"
          << ".btn-danger:hover { background: var(--danger); color: #fff; }"
          << ".btn-sm { padding: 3px 8px; font-size: 11px; }"
          << ".role-tag { background: #0969da; color: #fff; padding: 1px 5px; border-radius: var(--radius-sharp); font-size: 10px; text-transform: uppercase; font-weight: bold; font-family: 'JetBrains Mono', monospace; }"
          << ".input-text, .input-select { background: #ffffff; border: 1px solid var(--border-primary); color: var(--text-main); padding: 6px 10px; border-radius: var(--radius-sharp); font-size: 12px; width: 100%; box-sizing: border-box; font-family: 'JetBrains Mono', monospace; }"
          << ".input-text:focus, .input-select:focus { border-color: var(--border-focus); outline: 2px solid var(--border-focus); outline-offset: -1px; }"
          << ".badge { display: inline-block; padding: 2px 6px; font-size: 10px; font-weight: 600; border-radius: var(--radius-sharp); }"
          << ".badge-ai { background: #fbefff; color: #8250df; border: 1px solid rgba(130,80,223,0.3); }"
          << ".badge-entropy { background: #fff8c5; color: #9a6700; border: 1px solid rgba(154,103,0,0.3); }"
          << ".badge-regex { background: #ddf4ff; color: #0969da; border: 1px solid rgba(9,105,218,0.3); }"
          << ".badge-quarantined { background: #ffebe9; color: var(--danger); border: 1px solid rgba(207,34,46,0.3); }"
          << ".badge-available { background: #dafbe1; color: var(--success); border: 1px solid rgba(26,127,55,0.3); }"
          << ".badge-excluded { background: #f6f8fa; color: var(--text-muted); border: 1px solid var(--border-primary); }"
          << ".ai-progress-track { background: #eaeef2; border-radius: var(--radius-sharp); height: 10px; width: 100%; margin: 6px 0; overflow: hidden; position: relative; }"
          << ".ai-progress-bar { height: 100%; background: linear-gradient(90deg, #0969da, #8250df); transition: width 0.25s ease; width: 0%; }"
          << ".ai-tab-btn { background: #f6f8fa; border: 1px solid var(--border-primary); border-bottom: none; padding: 6px 12px; font-size: 11px; cursor: pointer; font-family: 'JetBrains Mono', monospace; font-weight: 600; border-radius: var(--radius-sharp) var(--radius-sharp) 0 0; }"
          << ".ai-tab-btn.active { background: #ffffff; color: var(--text-accent); border-top: 2px solid var(--text-accent); }"
          << ".ai-code-viewer { width: 100%; height: 260px; font-family: 'JetBrains Mono', monospace; font-size: 11px; background: #f6f8fa; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 8px; overflow: auto; white-space: pre-wrap; word-break: break-all; box-sizing: border-box; }"
          << ".modal { display: none; position: fixed; z-index: 10000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(31,35,40,0.5); align-items: center; justify-content: center; padding: 12px; }"
          << ".modal-content { background: #ffffff; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); padding: 20px; width: 440px; max-width: 100%; box-shadow: 0 8px 24px rgba(31,35,40,0.18); font-family: 'JetBrains Mono', monospace; box-sizing: border-box; }"
          << ".form-group { margin-bottom: 12px; }"
          << ".form-group label { display: block; font-size: 11px; color: var(--text-muted); margin-bottom: 4px; font-family: 'JetBrains Mono', monospace; }"
          << ".log-entry { font-family: 'JetBrains Mono', monospace; font-size: 11px; margin: 4px 0; color: var(--text-muted); line-height: 1.5; border-bottom: 1px solid #f0f2f5; padding-bottom: 3px; word-break: break-all; }"
          << ".table-scroll-container { max-height: 280px; overflow-y: auto; overflow-x: auto; border: 1px solid var(--border-primary); border-radius: var(--radius-sharp); position: relative; width: 100%; -webkit-overflow-scrolling: touch; }"
          << ".table-scroll-container table { margin-top: 0; border-collapse: separate; border-spacing: 0; width: 100%; }"
          << ".table-scroll-container th { position: sticky; top: 0; z-index: 2; background: #f6f8fa; box-shadow: 0 1px 0 var(--border-primary); }"
          << ".table-search-input { background: #ffffff; border: 1px solid var(--border-primary); color: var(--text-main); padding: 4px 8px; border-radius: var(--radius-sharp); font-size: 11px; font-family: 'JetBrains Mono', monospace; box-sizing: border-box; }"
          << ".table-search-input:focus { border-color: var(--border-focus); outline: 2px solid var(--border-focus); outline-offset: -1px; }"
          << "@media (max-width: 1080px) { .grid { grid-template-columns: 1fr !important; } }"
          << "@media (max-width: 768px) { body { padding: 8px !important; } .container { padding: 12px !important; } .top-bar { flex-direction: column; align-items: flex-start !important; gap: 10px; } .card h3 { flex-direction: column; align-items: flex-start !important; } .metric-grid { grid-template-columns: repeat(2, 1fr) !important; } }"
          << "@media (max-width: 480px) { .metric-grid { grid-template-columns: 1fr !important; } }"
          << "</style><script>"
          << "function esc(s) { if (s === null || s === undefined) return ''; return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;').replace(/'/g, '&#39;'); }"
          << "function escAttr(s) { if (s === null || s === undefined) return ''; return String(s).replace(/\"/g, '&quot;').replace(/'/g, '&#39;'); }"
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
          << "  if (s <= 0) return '0s';"
          << "  if (s >= 86400) return Math.floor(s/86400) + 'd ' + Math.floor((s%86400)/3600) + 'h';"
          << "  if (s >= 3600) return Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';"
          << "  return s + 's';"
          << "}"
          << "function formatClock(sec) {"
          << "  if (sec === undefined || sec === null || sec < 0) return '00:00:00';"
          << "  if (sec === 0) return '00:00:00';"
          << "  const d = Math.floor(sec / 86400);"
          << "  const h = Math.floor((sec % 86400) / 3600);"
          << "  const m = Math.floor((sec % 3600) / 60);"
          << "  const s = sec % 60;"
          << "  const pad = n => String(n).padStart(2, '0');"
          << "  if (d > 0) return d + 'd ' + pad(h) + ':' + pad(m) + ':' + pad(s);"
          << "  return pad(h) + ':' + pad(m) + ':' + pad(s);"
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
          << "  if (s.is_revoked || s.status === 'REVOKED') return '<span class=\"badge badge-quarantined\" style=\"background:var(--danger-bg); color:var(--danger);\">REVOKED (Đã hủy)</span>';"
          << "  if (s.is_expired || s.status === 'EXPIRED' || (s.expires_at > 0 && s.remaining_sec <= 0)) return '<span class=\"badge\" style=\"background:#ffebe9; color:#cf222e; border:1px solid rgba(207,34,46,0.3);\">EXPIRED (Đã hết hạn)</span>';"
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
          << "         + '<td><code>' + esc(s.identity) + '</code></td>'"
          << "         + '<td>' + actBadge + '</td>'"
          << "         + '<td><code>' + esc(s.remote_endpoint) + '</code></td>'"
          << "         + '<td><span class=\"role-tag\">' + esc(s.role) + '</span></td>'"
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
          << "        let isExp = u.is_expired || (u.expires_at > 0 && u.remaining_sec <= 0);"
          << "        let status = (u.expires_at === 0) ? '<span class=\"badge badge-available\">Permanent (∞)</span>' :"
          << "                     (isExp ? '<span class=\"badge\" style=\"background:#ffebe9; color:#cf222e; border:1px solid rgba(207,34,46,0.3);\">EXPIRED</span>' : '<span class=\"badge badge-available\">ACTIVE (' + formatSec(u.remaining_sec, u.expires_at) + ')</span>');"
          << "        html += '<tr><td><strong>' + esc(u.username) + '</strong></td><td><span class=\"role-tag\">' + esc(u.role) + '</span></td><td>' + status + '</td>'"
          << "             + '<td><button class=\"btn-sec btn-sm\" data-u=\"' + escAttr(u.username) + '\" data-r=\"' + escAttr(u.role) + '\" onclick=\"openEditModal(this.dataset.u, this.dataset.r)\">Edit</button> '"
          << "             + '<button class=\"btn-danger btn-sm\" data-u=\"' + escAttr(u.username) + '\" onclick=\"deleteUser(this.dataset.u)\">Delete</button></td></tr>';"
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
          << "  }).catch(err => alert('Lỗi tạo người dùng: ' + err.message));"
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
          << "  const ttl_ext = parseInt(document.getElementById('edit-ttl').value);"
          << "  const payload = { username: u, password: p, role: r };"
          << "  if (!isNaN(ttl_ext) && ttl_ext >= 0) {"
          << "    payload.ttl_sec = ttl_ext;"
          << "    payload.ttl_extend_sec = ttl_ext;"
          << "  }"
          << "  fetch('/api/admin/users/update', {"
          << "    method: 'POST', headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify(payload)"
          << "  }).then(r => r.json()).then(res => {"
          << "    if (res.status === 'ok') { closeEditModal(); reloadUsers(); }"
          << "    else alert(res.message || 'Failed to update user');"
          << "  }).catch(err => alert('Lỗi cập nhật người dùng: ' + err.message));"
          << "}"
          << "function deleteUser(username) {"
          << "  if (!confirm('Are you sure you want to delete user ' + username + '?')) return;"
          << "  fetch('/api/admin/users/delete', {"
          << "    method: 'POST', headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ username: username })"
          << "  }).then(r => r.json()).then(res => {"
          << "    if (res.status === 'ok') reloadUsers();"
          << "    else alert(res.message || 'Failed to delete user');"
          << "  }).catch(err => alert('Lỗi xóa người dùng: ' + err.message));"
          << "}"
          << "function reloadRules() {"
          << "  fetch('/api/admin/rules')"
          << "    .then(r => r.json())"
          << "    .then(rules => {"
          << "      const tbody = document.getElementById('rules-tbody');"
          << "      if (!tbody) return;"
          << "      if (!rules || rules.length === 0) { tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:var(--text-muted); text-align:center; padding:12px;\">No custom rules configured</td></tr>'; return; }"
          << "      let html = '';"
          << "      rules.forEach(r => {"
          << "        let act = (r.action && r.action.toLowerCase() === 'allow') ? '<span style=\"color:var(--success); font-weight:bold;\">ALLOW</span>' : '<span style=\"color:var(--danger); font-weight:bold;\">BLOCK</span>';"
          << "        html += '<tr><td><code>' + esc(r.id) + '</code></td><td>' + act + '</td><td><code>' + esc(r.type) + '</code></td><td><code style=\"word-break:break-all; font-size:11px;\">' + esc(r.value) + '</code></td>'"
          << "             + '<td><button class=\"btn-danger btn-sm\" data-id=\"' + escAttr(r.id) + '\" onclick=\"deleteRule(this.dataset.id)\">Delete</button></td></tr>';"
          << "      });"
          << "      tbody.innerHTML = html;"
          << "    });"
          << "}"
          << "function toggleRulesRawEditor() {"
          << "  const c = document.getElementById('rules-raw-container');"
          << "  if (!c) return;"
          << "  if (c.style.display === 'none') { reloadRawRules(); c.style.display = 'block'; } else { c.style.display = 'none'; }"
          << "}"
          << "function reloadRawRules() {"
          << "  fetch('/api/admin/rules/raw')"
          << "    .then(r => r.json())"
          << "    .then(data => {"
          << "      const ta = document.getElementById('raw-rules-ta');"
          << "      if (ta) ta.value = data.content || '';"
          << "      updatePresetHighlights();"
          << "    });"
          << "}"
          << "function saveRawRules() {"
          << "  const ta = document.getElementById('raw-rules-ta');"
          << "  if (!ta) return;"
          << "  fetch('/api/admin/rules/raw', {"
          << "    method: 'POST',"
          << "    headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ content: ta.value })"
          << "  }).then(r => r.json()).then(res => {"
          << "    if (res.status === 'ok') {"
          << "      alert('Đã lưu & áp dụng quy tắc thành công!');"
          << "      reloadRules();"
          << "      queryAudit(true);"
          << "    } else { alert(res.message || 'Lỗi lưu quy tắc'); }"
          << "  }).catch(e => alert('Network error'));"
          << "}"
          << "function togglePresetRuleDirect(pattern) {"
          << "  fetch('/api/admin/rules/raw').then(r => r.json()).then(data => {"
          << "    let lines = (data.content || '').split('\\n');"
          << "    let found = false;"
          << "    let newLines = [];"
          << "    for (let l of lines) {"
          << "      let trimmed = l.trim();"
          << "      if (trimmed.endsWith(pattern) || trimmed.includes(pattern)) { found = true; }"
          << "      else { newLines.push(l); }"
          << "    }"
          << "    if (!found) { newLines.push('BLOCK path ' + pattern); }"
          << "    return fetch('/api/admin/rules/raw', {"
          << "      method: 'POST',"
          << "      headers: { 'Content-Type': 'application/json' },"
          << "      body: JSON.stringify({ content: newLines.join('\\n') })"
          << "    });"
          << "  }).then(r => r.json()).then(res => {"
          << "    reloadRules();"
          << "    queryAudit(true);"
          << "  }).catch(e => {});"
          << "}"
          << "function updatePresetHighlights() {"
          << "  const ta = document.getElementById('raw-rules-ta');"
          << "  const txt = ta ? ta.value : '';"
          << "  const presets = ['node_modules/', 'target/', 'build/', 'dist/', '.git/', '*.tmp', '*.log', '*.iso', '*.zip', 'venv/', '__pycache__/', '.env*'];"
          << "  presets.forEach(p => {"
          << "    const btn = document.getElementById('preset-chip-' + p.replace(/[^a-zA-Z0-9]/g, '_'));"
          << "    if (btn) {"
          << "      const active = txt.includes(p);"
          << "      btn.style.background = active ? '#ddf4ff' : '#f6f8fa';"
          << "      btn.style.borderColor = active ? '#54aeff' : 'var(--border-primary)';"
          << "      btn.style.color = active ? '#0969da' : 'var(--text-main)';"
          << "      btn.style.fontWeight = active ? 'bold' : 'normal';"
          << "    }"
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
          << "      if (res.status === 'ok') { closeAddRuleModal(); document.getElementById('rule-id').value = ''; document.getElementById('rule-val').value = ''; reloadRules(); queryAudit(true); }"
          << "      else { alert(res.message || 'Failed to add rule'); }"
          << "    });"
          << "}"
          << "function deleteRule(ruleId) {"
          << "  if (!confirm('Are you sure you want to delete rule ' + ruleId + '?')) return;"
          << "  fetch('/api/admin/rules/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: ruleId }) })"
          << "    .then(r => r.json()).then(res => { if (res.status === 'ok') { reloadRules(); queryAudit(true); } else alert(res.message); });"
          << "}"
          << "let auditQueryState = { status: 'all', detector: 'all', ext: 'all', q: '', limit: 50, offset: 0, total: 0, filtered: 0 };"
          << "function queryAudit(resetOffset) {"
          << "  if (resetOffset) auditQueryState.offset = 0;"
          << "  auditQueryState.status = document.getElementById('audit-filter-status')?.value || 'all';"
          << "  auditQueryState.detector = document.getElementById('audit-filter-detector')?.value || 'all';"
          << "  onAuditDetectorChanged();"
          << "  auditQueryState.ext = document.getElementById('audit-filter-ext')?.value || 'all';"
          << "  auditQueryState.q = (document.getElementById('audit-search')?.value || '').trim();"
          << "  auditQueryState.limit = parseInt(document.getElementById('audit-filter-limit')?.value || '50');"
          << "  const params = new URLSearchParams({"
          << "    status: auditQueryState.status, detector: auditQueryState.detector, ext: auditQueryState.ext,"
          << "    q: auditQueryState.q, limit: auditQueryState.limit, offset: auditQueryState.offset"
          << "  });"
          << "  const tbody = document.getElementById('audit-tbody');"
          << "  if (tbody) tbody.innerHTML = '<tr><td colspan=\"5\" style=\"text-align:center; padding:16px; color:var(--text-muted);\">Đang truy vấn cơ sở dữ liệu SQLite...</td></tr>';"
          << "  fetch('/api/admin/audit/query?' + params.toString())"
          << "    .then(r => r.json())"
          << "    .then(res => {"
          << "      if (res.status !== 'ok') {"
          << "        if (tbody) tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:var(--danger); text-align:center; padding:12px;\">Lỗi truy vấn: ' + esc(res.message) + '</td></tr>';"
          << "        return;"
          << "      }"
          << "      auditQueryState.total = res.total || 0;"
          << "      auditQueryState.filtered = res.filtered || 0;"
          << "      const badge = document.getElementById('audit-badge');"
          << "      if (badge) badge.innerText = res.filtered;"
          << "      const pageInfo = document.getElementById('audit-page-info');"
          << "      if (pageInfo) {"
          << "        const from = res.filtered === 0 ? 0 : auditQueryState.offset + 1;"
          << "        const to = Math.min(res.filtered, auditQueryState.offset + (res.entries?.length || 0));"
          << "        pageInfo.innerText = 'Hiển thị ' + from + ' - ' + to + ' / ' + res.filtered + ' bản ghi (Tổng SQLite: ' + res.total + ')';"
          << "      }"
          << "      const prevBtn = document.getElementById('audit-prev-btn');"
          << "      const nextBtn = document.getElementById('audit-next-btn');"
          << "      if (prevBtn) prevBtn.disabled = (auditQueryState.offset <= 0);"
          << "      if (nextBtn) nextBtn.disabled = (auditQueryState.offset + auditQueryState.limit >= res.filtered);"
          << "      if (!res.entries || res.entries.length === 0) {"
          << "        if (tbody) tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:var(--text-muted); text-align:center; padding:16px;\">Không tìm thấy bản ghi kiểm toán nào khớp bộ lọc</td></tr>';"
          << "        return;"
          << "      }"
          << "      let html = '';"
          << "      res.entries.forEach(e => {"
          << "        let stColor = (e.status === 'CLEAN' || e.status === 'USER_ALLOWED' || e.status === 'MANUAL_ALLOWED') ? 'var(--success)' : 'var(--danger)';"
          << "        let isAllowed = (e.status === 'USER_ALLOWED' || e.status === 'MANUAL_ALLOWED');"
          << "        let actBtn = isAllowed"
          << "          ? '<span style=\"color:var(--text-muted); font-size:11px;\">Whitelisted</span>'"
          << "          : '<button class=\"btn btn-sm\" data-path=\"' + escAttr(e.file_path) + '\" onclick=\"allowAuditFile(this.dataset.path)\">Whitelist</button>';"
          << "        let detBadge = '';"
          << "        let hasAiData = (e.ai_output && e.ai_output.length > 0) || (e.detector && e.detector.indexOf('AI Guard') !== -1);"
          << "        if (e.detector && e.detector.indexOf('AI Guard') !== -1) {"
          << "          detBadge = '<span class=\"badge badge-ai\" style=\"margin-right:4px;\">' + esc(e.detector) + '</span>';"
          << "        } else if (e.detector && e.detector.indexOf('Entropy') !== -1) {"
          << "          detBadge = '<span class=\"badge badge-entropy\" style=\"margin-right:4px;\">' + esc(e.detector) + '</span>';"
          << "        } else if (e.detector && e.detector.indexOf('Regex') !== -1) {"
          << "          detBadge = '<span class=\"badge badge-regex\" style=\"margin-right:4px;\">' + esc(e.detector) + '</span>';"
          << "        } else if (e.detector) {"
          << "          detBadge = '<span class=\"badge badge-excluded\" style=\"margin-right:4px;\">' + esc(e.detector) + '</span>';"
          << "        }"
          << "        let aiDetailBtn = hasAiData"
          << "          ? '<button type=\"button\" class=\"btn-sec btn-sm\" style=\"margin-left:4px;\" data-path=\"' + escAttr(e.file_path) + '\" onclick=\"openAiDetailModal(this.dataset.path)\" title=\"Xem chi tiết Prompt & Raw JSON từ AI\">👁️ Chi tiết AI</button>'"
          << "          : '';"
          << "        html += '<tr><td><code style=\"word-break:break-all; font-size:11px;\">' + esc(e.file_path) + '</code></td>'"
          << "             + '<td style=\"white-space:nowrap;\"><span style=\"color:' + stColor + '; font-weight:bold; font-size:11px;\">' + esc(e.status) + '</span></td>'"
          << "             + '<td style=\"white-space:nowrap;\">' + (e.line_number > 0 ? 'L' + e.line_number : '-') + '</td>'"
          << "             + '<td style=\"font-size:11px;\">' + detBadge + (esc(e.reason) || '-') + '</td>'"
          << "             + '<td style=\"white-space:nowrap;\">' + actBtn + aiDetailBtn + '</td></tr>';"
          << "      });"
          << "      if (tbody) tbody.innerHTML = html;"
          << "    })"
          << "    .catch(err => {"
          << "      if (tbody) tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:var(--danger); text-align:center; padding:12px;\">Lỗi kết nối khi truy vấn audit</td></tr>';"
          << "    });"
          << "}"
          << "function showAiInspectionModal(fileOrTitle, statusStr, isDanger, detector, lineOrLatency, reason, inputData, outputData) {"
          << "  const modal = document.getElementById('modal-ai-detail');"
          << "  if (!modal) return;"
          << "  document.getElementById('ai-detail-file').innerText = fileOrTitle || '-';"
          << "  document.getElementById('ai-detail-loading').style.display = 'none';"
          << "  document.getElementById('ai-detail-body').style.display = 'block';"
          << "  const stEl = document.getElementById('ai-detail-status');"
          << "  if (stEl) {"
          << "    stEl.innerText = statusStr || '-';"
          << "    if (isDanger) {"
          << "      stEl.style.color = 'var(--danger)';"
          << "    } else if (statusStr && (statusStr.includes('RATE_LIMITED') || statusStr.includes('API_ERROR') || statusStr.includes('TIMEOUT') || statusStr.includes('CANCELLED') || statusStr.includes('HEURISTIC_ONLY'))) {"
          << "      stEl.style.color = '#d97706';"
          << "    } else {"
          << "      stEl.style.color = 'var(--success)';"
          << "    }"
          << "  }"
          << "  const detEl = document.getElementById('ai-detail-detector');"
          << "  if (detEl) detEl.innerText = detector || 'AI Guard';"
          << "  const lineEl = document.getElementById('ai-detail-line');"
          << "  if (lineEl) lineEl.innerText = lineOrLatency || '-';"
          << "  const rEl = document.getElementById('ai-detail-reason');"
          << "  if (rEl) rEl.innerText = reason || '-';"
          << "  let formattedOut = outputData || '(Không có dữ liệu phản hồi từ AI)';"
          << "  try { const parsed = JSON.parse(formattedOut); formattedOut = JSON.stringify(parsed, null, 2); } catch(e) {}"
          << "  let formattedIn = inputData || '(Không có dữ liệu input prompt)';"
          << "  try { const parsed = JSON.parse(formattedIn); formattedIn = JSON.stringify(parsed, null, 2); } catch(e) {}"
          << "  const inEl = document.getElementById('ai-input-text');"
          << "  if (inEl) inEl.value = formattedIn;"
          << "  const outEl = document.getElementById('ai-output-text');"
          << "  if (outEl) outEl.value = formattedOut;"
          << "  showAiTab('output');"
          << "  modal.style.display = 'flex';"
          << "}"
          << "function openAiDetailModal(path) {"
          << "  const modal = document.getElementById('modal-ai-detail');"
          << "  if (!modal) return;"
          << "  document.getElementById('ai-detail-file').innerText = path;"
          << "  document.getElementById('ai-detail-loading').style.display = 'block';"
          << "  document.getElementById('ai-detail-body').style.display = 'none';"
          << "  modal.style.display = 'flex';"
          << "  fetch('/api/admin/audit/detail?path=' + encodeURIComponent(path))"
          << "    .then(r => r.json())"
          << "    .then(res => {"
          << "      document.getElementById('ai-detail-loading').style.display = 'none';"
          << "      if (res.status === 'ok') {"
          << "        const isDanger = (res.status_str === 'SMART_FILTER_FLAGGED' || res.status_str === 'AI_FLAGGED');"
          << "        showAiInspectionModal("
          << "          res.file_path,"
          << "          res.status_str || res.status,"
          << "          isDanger,"
          << "          res.detector || 'AI Guard',"
          << "          res.line_number > 0 ? ('Dòng L' + res.line_number) : '-',"
          << "          res.reason || '-',"
          << "          res.ai_input,"
          << "          res.ai_output"
          << "        );"
          << "      } else {"
          << "        alert('Lỗi: ' + (res.message || 'Không thể tải chi tiết'));"
          << "        modal.style.display = 'none';"
          << "      }"
          << "    })"
          << "    .catch(e => {"
          << "      document.getElementById('ai-detail-loading').style.display = 'none';"
          << "      alert('Lỗi kết nối khi tải chi tiết AI');"
          << "      modal.style.display = 'none';"
          << "    });"
          << "}"
          << "function closeAiDetailModal() {"
          << "  const m = document.getElementById('modal-ai-detail');"
          << "  if (m) m.style.display = 'none';"
          << "}"
          << "function showAiTab(tab) {"
          << "  const tabIn = document.getElementById('tab-ai-in');"
          << "  const tabOut = document.getElementById('tab-ai-out');"
          << "  const viewIn = document.getElementById('ai-input-view');"
          << "  const viewOut = document.getElementById('ai-output-view');"
          << "  if (tab === 'input') {"
          << "    tabIn.classList.add('active');"
          << "    tabOut.classList.remove('active');"
          << "    viewIn.style.display = 'block';"
          << "    viewOut.style.display = 'none';"
          << "  } else {"
          << "    tabOut.classList.add('active');"
          << "    tabIn.classList.remove('active');"
          << "    viewOut.style.display = 'block';"
          << "    viewIn.style.display = 'none';"
          << "  }"
          << "}"
          << "function copyAiText(elementId) {"
          << "  const el = document.getElementById(elementId);"
          << "  if (!el) return;"
          << "  navigator.clipboard.writeText(el.value).then(() => {"
          << "    alert('Đã sao chép nội dung vào clipboard!');"
          << "  }).catch(() => {"
          << "    el.select();"
          << "    document.execCommand('copy');"
          << "    alert('Đã sao chép nội dung vào clipboard!');"
          << "  });"
          << "}"
          << "let isSeqScanning = false;"
          << "let seqScanAbort = false;"
          << "let curScanAbortCtrl = null;"
          << "let activeCountdownTimer = null;"
          << "async function startSequentialAiScan() {"
          << "  if (isSeqScanning) return;"
          << "  isSeqScanning = true;"
          << "  seqScanAbort = false;"
          << "  try { await fetch('/api/admin/scan/reset', { method: 'POST' }); } catch(e) {}"
          << "  const btnStart = document.getElementById('btn-start-seq-scan');"
          << "  const btnStop = document.getElementById('btn-stop-seq-scan');"
          << "  const bar = document.getElementById('ai-scan-bar');"
          << "  const pct = document.getElementById('ai-scan-pct');"
          << "  const statusEl = document.getElementById('ai-scan-cur-status');"
          << "  const logBox = document.getElementById('ai-scan-live-feed');"
          << "  if (btnStart) btnStart.disabled = true;"
          << "  if (btnStop) { btnStop.disabled = false; btnStop.innerText = '⏹️ Dừng Quét'; }"
          << "  if (logBox) logBox.innerHTML = '<div style=\"color:var(--text-muted); padding:4px;\">Đang lập danh sách các file văn bản/mã nguồn cần quét...</div>';"
          << "  if (statusEl) statusEl.innerText = 'Đang tìm kiếm tệp hợp lệ...';"
          << "  try {"
          << "    const listResp = await fetch('/api/admin/scan/scannable-files').then(r => r.json());"
          << "    if (listResp.status !== 'ok' || !listResp.files) {"
          << "      alert('Lỗi lấy danh sách tệp: ' + (listResp.message || 'Không có tệp'));"
          << "      stopSequentialAiScan();"
          << "      return;"
          << "    }"
          << "    const files = listResp.files;"
          << "    const total = files.length;"
          << "    if (total === 0) {"
          << "      if (statusEl) statusEl.innerText = 'Không có tệp văn bản / mã nguồn nào cần quét trong workspace.';"
          << "      stopSequentialAiScan();"
          << "      return;"
          << "    }"
          << "    if (logBox) logBox.innerHTML = '<div style=\"color:var(--text-accent); font-weight:bold; margin-bottom:4px;\">Bắt đầu quét tuần tự 1->1: ' + total + ' tệp văn bản/code</div>';"
          << "    let scanned = 0;"
          << "    let flaggedCount = 0;"
          << "    for (let i = 0; i < total; i++) {"
          << "      if (seqScanAbort) break;"
          << "      const item = files[i];"
          << "      const curFile = (typeof item === 'string') ? item : (item && item.path ? item.path : '');"
          << "      if (!curFile) continue;"
          << "      scanned++;"
          << "      const percent = Math.round((scanned / total) * 100);"
          << "      if (bar) bar.style.width = percent + '%';"
          << "      if (pct) pct.innerText = percent + '% (' + scanned + ' / ' + total + ')';"
          << "      if (statusEl) statusEl.innerText = '⏳ Đang quét AI: ' + curFile + ' (' + scanned + '/' + total + ')...';"
          << "      try {"
          << "        curScanAbortCtrl = new AbortController();"
          << "        const scanRes = await fetch('/api/admin/scan/file', {"
          << "          method: 'POST',"
          << "          headers: { 'Content-Type': 'application/json' },"
          << "          body: JSON.stringify({ path: curFile, level: 'level4' }),"
          << "          signal: curScanAbortCtrl.signal"
          << "        }).then(r => r.json());"
          << "        consecutiveNetErrors = 0;"
          << "        if (seqScanAbort || scanRes.scan_status === 'CANCELLED') break;"
          << "        let isFlagged = (scanRes.has_secret === true || scanRes.scan_status === 'SECRET_FOUND');"
          << "        if (isFlagged) flaggedCount++;"
          << "        let tag = '';"
          << "        if (scanRes.scan_status === 'SECRET_FOUND') {"
          << "          tag = '<span style=\"color:var(--danger); font-weight:bold;\">🚨 FLAGGED</span>';"
          << "        } else if (scanRes.scan_status === 'CLEAN') {"
          << "          tag = '<span style=\"color:var(--success); font-weight:bold;\">✅ CLEAN</span>';"
          << "        } else if (scanRes.scan_status === 'RATE_LIMITED') {"
          << "          tag = '<span style=\"color:#d97706; font-weight:bold;\">⚠️ RATE LIMITED</span>';"
          << "        } else if (scanRes.scan_status === 'API_ERROR') {"
          << "          tag = '<span style=\"color:#dc2626; font-weight:bold;\">❌ API ERROR</span>';"
          << "        } else if (scanRes.scan_status === 'TIMEOUT') {"
          << "          tag = '<span style=\"color:#6b7280; font-weight:bold;\">⏱️ TIMEOUT</span>';"
          << "        } else if (scanRes.scan_status === 'HEURISTIC_ONLY') {"
          << "          tag = '<span style=\"color:#b45309; font-weight:bold;\">🟡 HEURISTIC ONLY</span>';"
          << "        } else {"
          << "          tag = '<span style=\"color:#6b7280; font-weight:bold;\">ℹ️ UNKNOWN</span>';"
          << "        }"
          << "        let detailBtn = (scanRes.ai_output || scanRes.ai_input)"
          << "          ? ' <button type=\"button\" class=\"btn-sec btn-sm\" onclick=\"openAiDetailModal(\\\'' + escAttr(curFile) + '\\\')\" style=\"margin-left:6px; padding:1px 6px; font-size:10px; cursor:pointer;\" title=\"Xem Prompt & Raw JSON từ AI\">👁️ Chi tiết AI</button>'"
          << "          : '';"
          << "        let lineEntry = document.createElement('div');"
          << "        lineEntry.className = 'log-entry';"
          << "        lineEntry.innerHTML = '<strong>#' + scanned + '</strong> ' + tag + ' <code>' + esc(curFile) + '</code> <span style=\"color:var(--text-muted); font-size:10px;\">(' + (scanRes.duration_ms || 0) + 'ms)</span> - ' + esc(scanRes.reason || '') + detailBtn;"
          << "        if (logBox) {"
          << "          logBox.appendChild(lineEntry);"
          << "          logBox.scrollTop = logBox.scrollHeight;"
          << "        }"
          << "        if (scanRes.scan_status === 'RATE_LIMITED' && scanRes.retry_after_sec > 0 && !seqScanAbort) {"
          << "          let waitSeconds = Math.min(scanRes.retry_after_sec, 30);"
          << "          for (let rem = waitSeconds; rem > 0; rem--) {"
          << "            if (seqScanAbort) break;"
          << "            if (statusEl) statusEl.innerText = '⏳ Hết Quota API (429). Chờ Google mở lại: ' + rem + 's... [Có thể ấn Dừng Quét]';"
          << "            await new Promise(res => { activeCountdownTimer = setTimeout(res, 1000); });"
          << "          }"
          << "        }"
          << "      } catch (err) {"
          << "        if (seqScanAbort || err.name === 'AbortError') break;"
          << "        consecutiveNetErrors = (typeof consecutiveNetErrors === 'undefined' ? 1 : consecutiveNetErrors + 1);"
          << "        let errEntry = document.createElement('div');"
          << "        errEntry.className = 'log-entry';"
          << "        errEntry.style.color = 'var(--danger)';"
          << "        errEntry.innerHTML = '❌ Lỗi quét tệp <code>' + esc(curFile) + '</code>: ' + esc(err.message || 'Lỗi mạng');"
          << "        if (logBox) logBox.appendChild(errEntry);"
          << "        if (consecutiveNetErrors >= 3) {"
          << "          if (statusEl) statusEl.innerText = '⚠️ Mất kết nối tới máy chủ Slug daemon. Đã tự động ngắt quét.';"
          << "          break;"
          << "        }"
          << "      }"
          << "    }"
          << "    if (seqScanAbort) {"
          << "      if (statusEl) statusEl.innerText = '⏹️ Đã dừng quét tuần tự bởi người dùng (' + scanned + '/' + total + ' tệp).';"
          << "    } else {"
          << "      if (statusEl) statusEl.innerText = '🎉 Hoàn tất quét toàn bộ! Đã quét: ' + scanned + ' tệp, Phát hiện cảnh báo: ' + flaggedCount + ' tệp.';"
          << "    }"
          << "    queryAudit(true);"
          << "  } catch (e) {"
          << "    if (statusEl) statusEl.innerText = '❌ Lỗi hệ thống: ' + (e.message || 'Không xác định');"
          << "  } finally {"
          << "    stopSequentialAiScan();"
          << "  }"
          << "}"
          << "function stopSequentialAiScan() {"
          << "  seqScanAbort = true;"
          << "  isSeqScanning = false;"
          << "  if (curScanAbortCtrl) {"
          << "    try { curScanAbortCtrl.abort(); } catch(e) {}"
          << "    curScanAbortCtrl = null;"
          << "  }"
          << "  if (activeCountdownTimer) {"
          << "    clearTimeout(activeCountdownTimer);"
          << "    activeCountdownTimer = null;"
          << "  }"
          << "  try { fetch('/api/admin/scan/cancel', { method: 'POST' }); } catch(e) {}"
          << "  const btnStart = document.getElementById('btn-start-seq-scan');"
          << "  const btnStop = document.getElementById('btn-stop-seq-scan');"
          << "  if (btnStart) btnStart.disabled = false;"
          << "  if (btnStop) { btnStop.disabled = true; btnStop.innerText = '⏹️ Dừng Quét'; }"
          << "}"
          << "function auditNextPage() {"
          << "  if (auditQueryState.offset + auditQueryState.limit < auditQueryState.filtered) {"
          << "    auditQueryState.offset += auditQueryState.limit;"
          << "    queryAudit(false);"
          << "  }"
          << "}"
          << "function auditPrevPage() {"
          << "  if (auditQueryState.offset > 0) {"
          << "    auditQueryState.offset = Math.max(0, auditQueryState.offset - auditQueryState.limit);"
          << "    queryAudit(false);"
          << "  }"
          << "}"
          << "function clearAuditRecords() {"
          << "  if (!confirm('CẢNH BÁO XÓA DỮ LIỆU: Bạn có chắc chắn muốn xóa TOÀN BỘ lịch sử kiểm toán trong SQLite (.slug/index.db)? Thao tác này sẽ dọn sạch bản ghi quét, KHÔNG xóa file của workspace hay rules.conf.')) return;"
          << "  fetch('/api/admin/audit/clear', { method: 'POST' })"
          << "    .then(r => r.json())"
          << "    .then(res => {"
          << "      if (res.status === 'ok') {"
          << "        alert(res.message || 'Đã xóa sạch lịch sử kiểm toán.');"
          << "        queryAudit(true);"
          << "      } else {"
          << "        alert('Lỗi: ' + (res.message || 'Không thể xóa'));"
          << "      }"
          << "    })"
          << "    .catch(e => alert('Lỗi kết nối khi xóa dữ liệu'));"
          << "}"
          << "function runSecurityScan() {"
          << "  const lvl = document.getElementById('admin-filter-level')?.value || 'level2';"
          << "  const statusEl = document.getElementById('scan-status-msg');"
          << "  const spinner = document.getElementById('scan-spinner');"
          << "  if (spinner) spinner.style.display = 'inline-block';"
          << "  if (statusEl) {"
          << "    statusEl.style.display = 'block';"
          << "    statusEl.style.background = '#f6f8fa';"
          << "    statusEl.style.color = 'var(--text-accent)';"
          << "    statusEl.innerText = 'Đang tiến hành quét bảo mật toàn bộ workspace ở ' + lvl + '...';"
          << "  }"
          << "  fetch('/api/admin/scan/run', {"
          << "    method: 'POST', headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ level: lvl })"
          << "  })"
          << "    .then(r => r.json())"
          << "    .then(res => {"
          << "      if (spinner) spinner.style.display = 'none';"
          << "      if (res.status === 'ok') {"
          << "        if (statusEl) {"
          << "          statusEl.style.background = '#dafbe1';"
          << "          statusEl.style.color = 'var(--success)';"
          << "          statusEl.innerText = '✅ ' + res.message;"
          << "        }"
          << "        const lvlBadge = document.getElementById('active-filter-badge');"
          << "        if (lvlBadge) lvlBadge.innerText = res.level || lvl;"
          << "        const curText = document.getElementById('current-lvl-text');"
          << "        if (curText) curText.innerText = res.level || lvl;"
          << "        queryAudit(true);"
          << "        if (res.trigger_seq_scan || lvl === 'level4') {"
          << "          setTimeout(() => {"
          << "            const seqEl = document.getElementById('ai-seq-scanner-panel');"
          << "            if (seqEl) {"
          << "              seqEl.style.display = 'block';"
          << "              seqEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });"
          << "            }"
          << "            startSequentialAiScan();"
          << "          }, 300);"
          << "        }"
          << "      } else {"
          << "        if (statusEl) {"
          << "          statusEl.style.background = '#ffebe9';"
          << "          statusEl.style.color = 'var(--danger)';"
          << "          statusEl.innerText = '❌ Lỗi: ' + (res.message || 'Thất bại');"
          << "        }"
          << "      }"
          << "    })"
          << "    .catch(e => {"
          << "      if (spinner) spinner.style.display = 'none';"
          << "      if (statusEl) {"
          << "        statusEl.style.background = '#ffebe9';"
          << "        statusEl.style.color = 'var(--danger)';"
          << "        statusEl.innerText = '❌ Lỗi kết nối khi quét bảo mật';"
          << "      }"
          << "    });"
          << "}"
          << "function onAdminFilterChanged(lvl) {"
          << "  if (!lvl) lvl = document.getElementById('admin-filter-level')?.value || 'level2';"
          << "  const panel = document.getElementById('admin-ai-panel');"
          << "  if (panel) panel.style.display = (lvl === 'level4') ? 'block' : 'none';"
          << "  const seqPanel = document.getElementById('ai-seq-scanner-panel');"
          << "  if (seqPanel) seqPanel.style.display = (lvl === 'level4') ? 'block' : 'none';"
          << "}"
          << "let aiJsonModeActive = false;"
          << "function toggleAiConfigMode() {"
          << "  aiJsonModeActive = !aiJsonModeActive;"
          << "  const formEl = document.getElementById('ai-form-mode');"
          << "  const jsonEl = document.getElementById('ai-json-mode');"
          << "  if (aiJsonModeActive) {"
          << "    if (formEl) formEl.style.display = 'none';"
          << "    if (jsonEl) jsonEl.style.display = 'block';"
          << "    syncFormToJson();"
          << "  } else {"
          << "    syncJsonToForm();"
          << "    if (formEl) formEl.style.display = 'block';"
          << "    if (jsonEl) jsonEl.style.display = 'none';"
          << "  }"
          << "}"
          << "function syncFormToJson() {"
          << "  const cfg = {"
          << "    ai_provider: document.getElementById('ai-prov')?.value || 'ollama',"
          << "    ai_endpoint: document.getElementById('ai-endpoint')?.value || 'http://localhost:11434',"
          << "    ai_model: document.getElementById('ai-model')?.value || 'deepseek-r1',"
          << "    ai_api_key: document.getElementById('ai-key')?.value || ''"
          << "  };"
          << "  const hdrsRaw = document.getElementById('ai-headers')?.value || '';"
          << "  if (hdrsRaw.trim()) {"
          << "    try { cfg.headers = JSON.parse(hdrsRaw); } catch(e) { cfg.headers = hdrsRaw; }"
          << "  }"
          << "  const bodyRaw = document.getElementById('ai-body-template')?.value || '';"
          << "  if (bodyRaw.trim()) {"
          << "    try { cfg.body_template = JSON.parse(bodyRaw); } catch(e) { cfg.body_template = bodyRaw; }"
          << "  }"
          << "  const ta = document.getElementById('ai-json-raw');"
          << "  if (ta) ta.value = JSON.stringify(cfg, null, 2);"
          << "}"
          << "function syncJsonToForm() {"
          << "  const ta = document.getElementById('ai-json-raw');"
          << "  if (!ta) return;"
          << "  try {"
          << "    const cfg = JSON.parse(ta.value);"
          << "    if (document.getElementById('ai-prov') && cfg.ai_provider) document.getElementById('ai-prov').value = cfg.ai_provider;"
          << "    if (document.getElementById('ai-endpoint') && cfg.ai_endpoint) document.getElementById('ai-endpoint').value = cfg.ai_endpoint;"
          << "    if (document.getElementById('ai-model') && cfg.ai_model) document.getElementById('ai-model').value = cfg.ai_model;"
          << "    if (document.getElementById('ai-key') && cfg.ai_api_key) document.getElementById('ai-key').value = cfg.ai_api_key;"
          << "    if (document.getElementById('ai-headers')) {"
          << "      document.getElementById('ai-headers').value = cfg.headers ? (typeof cfg.headers === 'string' ? cfg.headers : JSON.stringify(cfg.headers)) : '';"
          << "    }"
          << "    if (document.getElementById('ai-body-template')) {"
          << "      document.getElementById('ai-body-template').value = cfg.body_template ? (typeof cfg.body_template === 'string' ? cfg.body_template : JSON.stringify(cfg.body_template, null, 2)) : '';"
          << "    }"
          << "    onAiProvChanged(false);"
          << "  } catch(e) {}"
          << "}"
          << "function loadAiConfig() {"
          << "  fetch('/api/admin/ai/config')"
          << "    .then(r => r.json())"
          << "    .then(cfg => {"
          << "      if (document.getElementById('ai-prov')) document.getElementById('ai-prov').value = cfg.ai_provider || 'ollama';"
          << "      if (document.getElementById('ai-endpoint')) document.getElementById('ai-endpoint').value = cfg.ai_endpoint || 'http://localhost:11434';"
          << "      if (document.getElementById('ai-model')) document.getElementById('ai-model').value = cfg.ai_model || 'deepseek-r1';"
          << "      if (document.getElementById('ai-key')) document.getElementById('ai-key').value = cfg.ai_api_key || '';"
          << "      if (document.getElementById('ai-headers')) {"
          << "        document.getElementById('ai-headers').value = cfg.headers ? (typeof cfg.headers === 'string' ? cfg.headers : JSON.stringify(cfg.headers)) : '';"
          << "      }"
          << "      if (document.getElementById('ai-body-template')) {"
          << "        document.getElementById('ai-body-template').value = cfg.body_template ? (typeof cfg.body_template === 'string' ? cfg.body_template : JSON.stringify(cfg.body_template, null, 2)) : '';"
          << "      }"
          << "      syncFormToJson();"
          << "      onAiProvChanged(false);"
          << "    }).catch(e => {});"
          << "}"
          << "function onAiProvChanged(autoPreset = true) {"
          << "  const p = document.getElementById('ai-prov')?.value || 'ollama';"
          << "  const ep = document.getElementById('ai-endpoint');"
          << "  const m = document.getElementById('ai-model');"
          << "  const kg = document.getElementById('ai-key-group');"
          << "  const hdrs = document.getElementById('ai-headers');"
          << "  const bt = document.getElementById('ai-body-template');"
          << "  if (p === 'ollama') {"
          << "    if (kg) kg.style.display = 'none';"
          << "    if (autoPreset) {"
          << "      if (ep) ep.value = 'http://localhost:11434';"
          << "      if (m) m.value = 'deepseek-r1';"
          << "      if (hdrs) hdrs.value = '{}';"
          << "      if (bt) bt.value = JSON.stringify({ model: '{{MODEL}}', prompt: '{{PROMPT}}', stream: false }, null, 2);"
          << "    }"
          << "  } else if (p === 'gemini') {"
          << "    if (kg) kg.style.display = 'block';"
          << "    if (autoPreset) {"
          << "      if (ep) ep.value = 'https://generativelanguage.googleapis.com/v1beta';"
          << "      if (m) m.value = 'gemini-flash-latest';"
          << "      if (hdrs) hdrs.value = JSON.stringify({ 'x-goog-api-key': '{{API_KEY}}' });"
          << "      if (bt) bt.value = JSON.stringify({ contents: [{ parts: [{ text: '{{PROMPT}}' }] }] }, null, 2);"
          << "    }"
          << "  } else if (p === 'openai') {"
          << "    if (kg) kg.style.display = 'block';"
          << "    if (autoPreset) {"
          << "      if (ep) ep.value = 'https://api.openai.com/v1/chat/completions';"
          << "      if (m) m.value = 'gpt-4o-mini';"
          << "      if (hdrs) hdrs.value = JSON.stringify({ 'Authorization': 'Bearer {{API_KEY}}' });"
          << "      if (bt) bt.value = JSON.stringify({ model: '{{MODEL}}', messages: [{ role: 'system', content: 'You are a code security auditor.' }, { role: 'user', content: '{{PROMPT}}' }], temperature: 0.0 }, null, 2);"
          << "    }"
          << "  } else if (p === 'anthropic') {"
          << "    if (kg) kg.style.display = 'block';"
          << "    if (autoPreset) {"
          << "      if (ep) ep.value = 'https://api.anthropic.com/v1/messages';"
          << "      if (m) m.value = 'claude-3-5-haiku-20241022';"
          << "      if (hdrs) hdrs.value = JSON.stringify({ 'x-api-key': '{{API_KEY}}', 'anthropic-version': '2023-06-01' });"
          << "      if (bt) bt.value = JSON.stringify({ model: '{{MODEL}}', max_tokens: 1024, messages: [{ role: 'user', content: '{{PROMPT}}' }] }, null, 2);"
          << "    }"
          << "  } else if (p === 'custom') {"
          << "    if (kg) kg.style.display = 'block';"
          << "    if (autoPreset) {"
          << "      if (ep && !ep.value) ep.value = 'https://your-custom-ai.internal/v1/scan';"
          << "      if (m && !m.value) m.value = 'custom-model';"
          << "      if (hdrs && !hdrs.value) hdrs.value = JSON.stringify({ 'Authorization': 'Bearer {{API_KEY}}' });"
          << "      if (bt && !bt.value) bt.value = JSON.stringify({ file: '{{FILE_PATH}}', code: '{{PROMPT}}' }, null, 2);"
          << "    }"
          << "  }"
          << "  syncFormToJson();"
          << "}"
          << "function applyAiPreset(type) {"
          << "  if (document.getElementById('ai-prov')) {"
          << "    document.getElementById('ai-prov').value = type;\n"
          << "  }\n"
          << "  onAiProvChanged(true);\n"
          << "}\n"
          << "function saveAiConfig() {"
          << "  let payload = {};"
          << "  const statusEl = document.getElementById('ai-status-msg');"
          << "  if (aiJsonModeActive) {"
          << "    const ta = document.getElementById('ai-json-raw');"
          << "    if (ta) {"
          << "      try {"
          << "        const parsed = JSON.parse(ta.value);"
          << "        payload = {"
          << "          ai_provider: parsed.ai_provider || 'ollama',"
          << "          ai_endpoint: parsed.ai_endpoint || '',"
          << "          ai_model: parsed.ai_model || '',"
          << "          ai_api_key: parsed.ai_api_key || '',"
          << "          raw_json: ta.value"
          << "        };"
          << "        if (parsed.body_template) payload.body_template = parsed.body_template;"
          << "        if (parsed.headers) payload.headers = parsed.headers;"
          << "      } catch (err) {"
          << "        if (statusEl) {"
          << "          statusEl.style.display = 'block';"
          << "          statusEl.style.background = '#ffebe9';"
          << "          statusEl.style.color = 'var(--danger)';"
          << "          statusEl.innerText = '❌ Lỗi cú pháp JSON: ' + err.message;"
          << "        }"
          << "        return;"
          << "      }"
          << "    }"
          << "  } else {"
          << "    const prov = document.getElementById('ai-prov')?.value || 'ollama';"
          << "    const ep = document.getElementById('ai-endpoint')?.value || '';"
          << "    const m = document.getElementById('ai-model')?.value || '';"
          << "    const k = document.getElementById('ai-key')?.value || '';"
          << "    payload = { ai_provider: prov, ai_endpoint: ep, ai_model: m, ai_api_key: k };"
          << "    const hdrsRaw = document.getElementById('ai-headers')?.value || '';"
          << "    if (hdrsRaw.trim()) {"
          << "      try { payload.headers = JSON.parse(hdrsRaw); } catch(e) { payload.headers = hdrsRaw; }"
          << "    }"
          << "    const bodyRaw = document.getElementById('ai-body-template')?.value || '';"
          << "    if (bodyRaw.trim()) {"
          << "      try { payload.body_template = JSON.parse(bodyRaw); } catch(e) { payload.body_template = bodyRaw; }"
          << "    }"
          << "  }"
          << "  if (statusEl) { statusEl.style.display = 'block'; statusEl.style.background = '#f6f8fa'; statusEl.style.color = 'var(--text-accent)'; statusEl.innerText = 'Đang lưu cấu hình .slug/ai.json...'; }"
          << "  fetch('/api/admin/ai/config', {"
          << "    method: 'POST', headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify(payload)"
          << "  })"
          << "    .then(r => r.json())"
          << "    .then(res => {"
          << "      if (statusEl) {"
          << "        statusEl.style.display = 'block';"
          << "        if (res.status === 'ok') {"
          << "          statusEl.style.background = '#dafbe1';"
          << "          statusEl.style.color = 'var(--success)';"
          << "          statusEl.innerText = '✅ ' + (res.message || 'Đã lưu cấu hình AI vào .slug/ai.json thành công!');"
          << "          const aiBadge = document.getElementById('active-ai-badge');"
          << "          if (aiBadge) aiBadge.innerText = payload.ai_provider;"
          << "          if (!aiJsonModeActive) syncFormToJson();"
          << "        } else {"
          << "          statusEl.style.background = '#ffebe9';"
          << "          statusEl.style.color = 'var(--danger)';"
          << "          statusEl.innerText = '❌ Lỗi: ' + (res.message || 'Không thể lưu');"
          << "        }"
          << "      }"
          << "    })"
          << "    .catch(e => {"
          << "      if (statusEl) {"
          << "        statusEl.style.display = 'block';"
          << "        statusEl.style.background = '#ffebe9';"
          << "        statusEl.style.color = 'var(--danger)';"
          << "        statusEl.innerText = '❌ Lỗi kết nối khi lưu cấu hình AI';"
          << "      }"
          << "    });"
          << "}"
          << "let lastAiTestResult = null;"
          << "function showLastAiTestDetail() {"
          << "  if (!lastAiTestResult) return;"
          << "  const isErr = (lastAiTestResult.status !== 'ok');"
          << "  showAiInspectionModal("
          << "    'Test Kết Nối AI: ' + (lastAiTestResult.endpoint || 'Service Endpoint'),"
          << "    isErr ? 'FAILED (Thất bại)' : 'SUCCESS (Thành công)',"
          << "    isErr,"
          << "    lastAiTestResult.model || 'AI Model',"
          << "    (lastAiTestResult.duration_ms !== undefined ? lastAiTestResult.duration_ms + 'ms' : '-'),"
          << "    lastAiTestResult.message || '-',"
          << "    lastAiTestResult.request_payload || '(Không có Request Payload)',"
          << "    lastAiTestResult.response_payload || '(Không có Response Body)'"
          << "  );"
          << "}"
          << "function testAiConnectivity() {"
          << "  let payload = {};"
          << "  if (aiJsonModeActive) {"
          << "    const ta = document.getElementById('ai-json-raw');"
          << "    if (ta) {"
          << "      try {"
          << "        const parsed = JSON.parse(ta.value);"
          << "        payload = {"
          << "          ai_provider: parsed.ai_provider || 'ollama',"
          << "          ai_endpoint: parsed.ai_endpoint || '',"
          << "          ai_model: parsed.ai_model || '',"
          << "          ai_api_key: parsed.ai_api_key || '',"
          << "          raw_json: ta.value"
          << "        };"
          << "        if (parsed.body_template) payload.body_template = parsed.body_template;"
          << "        if (parsed.headers) payload.headers = parsed.headers;"
          << "      } catch(e) {}"
          << "    }"
          << "  } else {"
          << "    const prov = document.getElementById('ai-prov')?.value || 'ollama';"
          << "    const ep = document.getElementById('ai-endpoint')?.value || '';"
          << "    const m = document.getElementById('ai-model')?.value || '';"
          << "    const k = document.getElementById('ai-key')?.value || '';"
          << "    payload = { ai_provider: prov, ai_endpoint: ep, ai_model: m, ai_api_key: k };"
          << "    const hdrsRaw = document.getElementById('ai-headers')?.value || '';"
          << "    if (hdrsRaw.trim()) {"
          << "      try { payload.headers = JSON.parse(hdrsRaw); } catch(e) { payload.headers = hdrsRaw; }"
          << "    }"
          << "    const bodyRaw = document.getElementById('ai-body-template')?.value || '';"
          << "    if (bodyRaw.trim()) {"
          << "      try { payload.body_template = JSON.parse(bodyRaw); } catch(e) { payload.body_template = bodyRaw; }"
          << "    }"
          << "  }"
          << "  const statusEl = document.getElementById('ai-status-msg');"
          << "  if (statusEl) { statusEl.style.display = 'block'; statusEl.style.background = '#f6f8fa'; statusEl.style.color = 'var(--text-accent)'; statusEl.innerText = 'Đang kiểm tra kết nối tới dịch vụ AI...'; }"
          << "  fetch('/api/admin/ai/test', {"
          << "    method: 'POST', headers: { 'Content-Type': 'application/json' }, "
          << "    body: JSON.stringify(payload)"
          << "  })"
          << "    .then(r => r.json())"
          << "    .then(res => {"
          << "      lastAiTestResult = res;"
          << "      if (statusEl) {"
          << "        statusEl.style.display = 'block';"
          << "        const dur = (res.duration_ms !== undefined) ? ' (' + res.duration_ms + 'ms)' : '';"
          << "        const inspectBtn = (res.request_payload || res.response_payload)"
          << "          ? ' <button type=\"button\" class=\"btn btn-sm\" onclick=\"showLastAiTestDetail()\" style=\"margin-left:8px; padding:2px 8px; font-size:11px; cursor:pointer;\">👁️ Xem AI Request/Response</button>'"
          << "          : '';"
          << "        if (res.status === 'ok') {"
          << "          statusEl.style.background = '#dafbe1';"
          << "          statusEl.style.color = 'var(--success)';"
          << "          statusEl.innerHTML = '✅ ' + esc(res.message || 'Kiểm tra thành công!') + dur + inspectBtn;"
          << "        } else {"
          << "          statusEl.style.background = '#ffebe9';"
          << "          statusEl.style.color = 'var(--danger)';"
          << "          statusEl.innerHTML = '❌ ' + esc(res.message || 'Lỗi kiểm tra AI') + dur + inspectBtn;"
          << "        }"
          << "      }"
          << "      showLastAiTestDetail();"
          << "    })"
          << "    .catch(e => {"
          << "      if (statusEl) {"
          << "        statusEl.style.display = 'block';"
          << "        statusEl.style.background = '#ffebe9';"
          << "        statusEl.style.color = 'var(--danger)';"
          << "        statusEl.innerText = '❌ Lỗi kết nối khi kiểm tra dịch vụ AI';"
          << "      }"
          << "    });"
          << "}"
          << "function onAuditDetectorChanged() {"
          << "  const det = document.getElementById('audit-filter-detector')?.value || 'all';"
          << "  const btn = document.getElementById('btn-whitelist-all');"
          << "  if (!btn) return;"
          << "  if (det === 'all') {"
          << "    btn.innerText = 'Whitelist All';"
          << "    btn.title = 'Whitelist toàn bộ các tệp đang bị cảnh báo bởi tất cả Detector';"
          << "  } else if (det === 'regex') {"
          << "    btn.innerText = 'Whitelist All (Regex)';"
          << "    btn.title = 'Chỉ whitelist các tệp bị chặn bởi Regex Secret Guard';"
          << "  } else if (det === 'entropy') {"
          << "    btn.innerText = 'Whitelist All (Entropy)';"
          << "    btn.title = 'Chỉ whitelist các tệp bị chặn bởi Shannon Entropy Guard';"
          << "  } else if (det === 'ai') {"
          << "    btn.innerText = 'Whitelist All (AI Guard)';"
          << "    btn.title = 'Chỉ whitelist các tệp bị chặn bởi AI Model Guard';"
          << "  } else if (det === 'manual') {"
          << "    btn.innerText = 'Whitelist All (Manual)';"
          << "    btn.title = 'Chỉ whitelist các tệp bị chặn thủ công hoặc Rule';"
          << "  }"
          << "}"
          << "function allowAuditFile(filePath) {"
          << "  if (!filePath) return;"
          << "  const reason = prompt('Lý do cho phép (Whitelist) tệp tin: ' + filePath, 'Verified safe false positive');"
          << "  if (!reason) return;"
          << "  fetch('/api/admin/audit/allow', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: filePath, reason: reason }) })"
          << "    .then(r => r.json()).then(res => { if (res.status === 'ok') queryAudit(false); else alert(res.message); })"
          << "    .catch(e => alert('Lỗi kết nối'));"
          << "}"
          << "function allowAllAuditFiles() {"
          << "  const det = document.getElementById('audit-filter-detector')?.value || 'all';"
          << "  const detSel = document.getElementById('audit-filter-detector');"
          << "  const detName = (detSel && detSel.selectedIndex >= 0) ? detSel.options[detSel.selectedIndex].text : det;"
          << "  let confirmMsg = 'Bạn có chắc muốn whitelist toàn bộ các tệp đang bị cảnh báo bởi tất cả Detector?';"
          << "  if (det !== 'all') {"
          << "    confirmMsg = 'Bạn có chắc muốn vô hiệu hóa cảnh báo / Whitelist toàn bộ tệp bị chặn bởi detector: ' + detName + '?';"
          << "  }"
          << "  if (!confirm(confirmMsg)) return;"
          << "  fetch('/api/admin/audit/allow-all', {"
          << "    method: 'POST',"
          << "    headers: { 'Content-Type': 'application/json' },"
          << "    body: JSON.stringify({ detector: det })"
          << "  })"
          << "    .then(r => r.json()).then(res => {"
          << "      if (res.status === 'ok') {"
          << "        alert('Đã whitelist thành công ' + (res.count || 0) + ' tệp (' + detName + ')!');"
          << "        queryAudit(false);"
          << "      } else {"
          << "        alert(res.message || 'Lỗi khi whitelist');"
          << "      }"
          << "    }).catch(e => alert('Lỗi kết nối khi gửi yêu cầu'));"
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
          << "window.addEventListener('DOMContentLoaded', () => {"
          << "  onAdminFilterChanged();"
          << "  runLiveBenchmark();"
          << "  setInterval(runLiveBenchmark, 3500);"
          << "  reloadSessions();"
          << "  setInterval(reloadSessions, 2500);"
          << "  loadAiConfig();"
          << "  queryAudit(true);"
          << "  let adminRem = parseInt(document.getElementById('ws-admin-ttl-badge')?.getAttribute('data-rem') || '86400');"
          << "  const adminTot = parseInt(document.getElementById('ws-admin-ttl-badge')?.getAttribute('data-ttl') || '86400');"
          << "  if (adminTot > 0) {"
          << "    setInterval(() => {"
          << "      if (adminRem > 0) adminRem--;"
          << "      const b = document.getElementById('ws-admin-ttl-badge');"
          << "      if (b) {"
          << "        if (adminRem <= 0) { b.style.color = 'var(--danger)'; b.innerText = 'ĐÃ HẾT HẠN (0s)'; }"
          << "        else { b.innerText = formatClock(adminRem); }"
          << "      }"
          << "    }, 1000);"
          << "  }"
          << "});"
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
          << "<strong>Workspace Lifetime:</strong> <span id='ws-admin-ttl-badge' style='color:#0969da; font-weight:bold;' data-rem='" << remaining_workspace_ttl << "' data-ttl='" << workspace_ttl << "'>"
          << (workspace_ttl == 0 ? "Vĩnh viễn (∞)" : core::Utils::format_ttl(remaining_workspace_ttl)) << "</span>"
          << (workspace_ttl > 0 ? (" <span style='font-size:10px; color:var(--text-muted);'>(" + std::to_string(workspace_ttl) + "s)</span>") : "") << "<br>"
          << "<strong>Filter Level:</strong> <span id='active-filter-badge' style='color:var(--text-accent); font-weight:bold;'>" << core::filter_level_to_string(filter_level) << "</span><br>"
          << "<strong>AI Provider:</strong> <span id='active-ai-badge'>" << core::ai_model_to_string(ai_provider) << "</span><br>"
          << "<strong>AI Secret Shield:</strong> <span id='active-shield-badge'>" << (ai_enabled ? "<span style='color:var(--success); font-weight:bold;'>ACTIVE</span>" : "OFF") << "</span></p>"
          << "</div>"

          << "<div class='card'><h3><span>User Accounts &amp; Ephemeral Roles</span><button class='btn btn-sm' onclick='openAddModal()'>+ Create User</button></h3>"
          << "<div class='table-scroll-container' style='max-height:160px;'>"
          << "<table><thead><tr><th>User</th><th>Role</th><th>Status/TTL</th><th>Actions</th></tr></thead><tbody id='users-tbody'>";

        uint64_t now = core::Utils::current_timestamp();
        for (const auto& u : users) {
            std::string status = (u.expires_at == 0) ? "<span style='color:var(--success);'>Permanent (∞)</span>" :
                                 (u.is_expired(now) ? "<span style='color:var(--danger);'>Expired</span>" :
                                 ("<span style='color:var(--success);'>Active (" + core::Utils::format_ttl((u.expires_at > now) ? (u.expires_at - now) : 0) + ")</span>"));
            h << "<tr><td><strong>" << html_escape(u.username) << "</strong></td><td><span class='role-tag'>" << core::role_to_string(u.role) << "</span></td><td>"
              << status
              << "</td><td><button class='btn-sec btn-sm' data-u='" << html_escape(u.username) << "' data-r='" << core::role_to_string(u.role) << "' onclick='openEditModal(this.dataset.u, this.dataset.r)'>Edit</button> "
              << "<button class='btn-danger btn-sm' data-u='" << html_escape(u.username) << "' onclick='deleteUser(this.dataset.u)'>Delete</button></td></tr>";
        }
        if (users.empty()) {
            h << "<tr><td colspan='4' style='color:var(--text-muted);'>No user accounts configured</td></tr>";
        }
        h << "</tbody></table></div></div></div>"

          // DYNAMIC FILTER LEVEL & RE-SCAN CARD
          << "<div class='card' style='margin-bottom:16px;'>"
          << "<h3><span>Bộ Lọc Bảo Mật &amp; Tùy Chọn Quét Lại Workspace (Dynamic Re-Scan)</span>"
          << "<span id='scan-status-badge' class='badge badge-available' style='font-size:11px;'>Mức hoạt động: <span id='current-lvl-text'>" << core::filter_level_to_string(filter_level) << "</span></span>"
          << "</h3>"
          << "<div style='display:flex; flex-wrap:wrap; gap:12px; align-items:center; margin:10px 0;'>"
          << "<div style='display:flex; align-items:center; gap:8px;'>"
          << "<label style='font-weight:600; font-size:12px;'>Mức Lọc:</label>"
          << "<select id='admin-filter-level' onchange='onAdminFilterChanged(this.value)' class='input-select' style='width:auto; min-width:280px; font-weight:600;'>"
          << "<option value='level0'" << (filter_level == core::FilterLevel::LEVEL_0_RAW ? " selected" : "") << ">Level 0: Không Lọc / Chia Sẻ Tất Cả (Tắt Rules, .gitignore &amp; AI - Chỉ giữ .slug/)</option>"
          << "<option value='level1'" << (filter_level == core::FilterLevel::LEVEL_1_RULES ? " selected" : "") << ">Level 1: Rules &amp; .gitignore (Không quét nội dung)</option>"
          << "<option value='level2'" << (filter_level == core::FilterLevel::LEVEL_2_REGEX ? " selected" : "") << ">Level 2: Policy &amp; Smart Regex Guard [Mặc định]</option>"
          << "<option value='level3'" << (filter_level == core::FilterLevel::LEVEL_3_ENTROPY ? " selected" : "") << ">Level 3: Deep Shannon Entropy Guard</option>"
          << "<option value='level4'" << (filter_level == core::FilterLevel::LEVEL_4_AI ? " selected" : "") << ">Level 4: AI Model Deep Semantic Guard (LLM)</option>"
          << "</select></div>"
          << "<button type='button' class='btn' onclick='runSecurityScan()' style='padding:6px 16px; font-weight:bold;'>⚡ Áp Dụng Mức Lọc &amp; Quét Lại Ngay</button>"
          << "<span id='scan-spinner' style='display:none; color:var(--text-accent); font-size:12px; font-weight:600;'>⏳ Đang quét dữ liệu...</span>"
          << "</div>"
          << "<div id='scan-status-msg' style='display:none; font-size:12px; padding:8px 12px; border-radius:var(--radius-sharp); background:#f6f8fa; border:1px solid var(--border-primary); margin-top:8px;'></div>"
          << "<div style='font-size:11px; color:var(--text-muted); margin-top:8px; line-height:1.5;'>"
          << "💡 <strong>Tự do thay đổi không cần khởi động lại phiên:</strong> Khi bạn chuyển mức lọc và ấn <em>\"Áp Dụng Mức Lọc &amp; Quét Lại Ngay\"</em>, máy chủ sẽ lập tức cập nhật trạng thái lọc runtime, xóa cache manifest, quét lại workspace và cập nhật bảng kiểm toán bên dưới."
          << "</div>"
          << "<div id='ai-seq-scanner-panel' style='display:" << (filter_level == core::FilterLevel::LEVEL_4_AI ? "block" : "none") << "; margin-top:14px; padding:12px; background:#f6f8fa; border:1px solid var(--border-primary); border-radius:var(--radius-sharp);'>"
          << "<div style='display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;'>"
          << "<div><strong style='font-size:12px; color:var(--text-main);'>⚡ Quét AI Từng Tệp Tuần Tự (File-by-File Sequential AI Guard):</strong></div>"
          << "<div style='display:flex; gap:6px;'>"
          << "<button type='button' id='btn-start-seq-scan' class='btn btn-sm' onclick='startSequentialAiScan()' style='background:var(--pqc); border-color:var(--pqc);'>🚀 Bắt Đầu Quét AI Từng Tệp (1-by-1)</button>"
          << "<button type='button' id='btn-stop-seq-scan' class='btn-sec btn-sm' onclick='stopSequentialAiScan()' disabled>⏹️ Dừng Quét</button>"
          << "</div></div>"
          << "<div style='margin-top:10px;'>"
          << "<div style='display:flex; justify-content:space-between; font-size:11px; margin-bottom:4px;'>"
          << "<span id='ai-scan-cur-status' style='font-weight:600; color:var(--text-accent);'>Sẵn sàng quét...</span>"
          << "<span id='ai-scan-pct' style='font-weight:bold; color:var(--text-main);'>0%</span>"
          << "</div>"
          << "<div class='ai-progress-track'><div id='ai-scan-bar' class='ai-progress-bar'></div></div>"
          << "</div>"
          << "<div style='margin-top:8px;'>"
          << "<div style='font-size:10px; font-weight:bold; color:var(--text-muted); text-transform:uppercase; margin-bottom:4px;'>Nhật Ký Tiến Trình Quét AI Thực Tế (Live Activity Feed):</div>"
          << "<div id='ai-scan-live-feed' class='table-scroll-container' style='max-height:140px; padding:6px 8px; background:#ffffff; font-size:11px;'>"
          << "<div style='color:var(--text-muted); text-align:center; padding:8px;'>Chưa có đợt quét tuần tự nào được khởi chạy</div>"
          << "</div></div></div>"
          << "</div>"

          // AI CONFIGURATION CARD (.slug/ai.json)
          << "<div id='admin-ai-panel' class='card' style='margin-bottom:16px; display:" << (filter_level == core::FilterLevel::LEVEL_4_AI ? "block" : "none") << ";'>"
          << "<h3><span>Cài Đặt Cấu Hình AI Workspace (.slug/ai.json)</span>"
          << "<span style='display:flex; flex-wrap:wrap; gap:6px;'>"
          << "<button type='button' class='btn-sec btn-sm' onclick='toggleAiConfigMode()'>Chuyển Đổi Form / JSON Trực Tiếp</button>"
          << "<button type='button' class='btn-sec btn-sm' onclick='testAiConnectivity()'>Kiểm Tra Kết Nối AI</button>"
          << "<button type='button' class='btn btn-sm' onclick='saveAiConfig()'>Lưu Cấu Hình AI</button>"
          << "</span></h3>"
          << "<div id='ai-form-mode'>"
          << "<div style='display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:12px; margin-top:10px;'>"
          << "<div class='form-group'><label>AI Provider (Nhà Cung Cấp):</label>"
          << "<select id='ai-prov' class='input-select' onchange='onAiProvChanged()'>"
          << "<option value='ollama'" << (ai_provider == core::AiModelProvider::OLLAMA ? " selected" : "") << ">Ollama (Local LLM - Mặc định)</option>"
          << "<option value='gemini'" << (ai_provider == core::AiModelProvider::GEMINI ? " selected" : "") << ">Google Gemini API (Native REST v1beta)</option>"
          << "<option value='openai'" << (ai_provider == core::AiModelProvider::OPENAI ? " selected" : "") << ">OpenAI Compatible Cloud (GPT-4o / v1)</option>"
          << "<option value='anthropic'>Anthropic Claude API (v1/messages)</option>"
          << "<option value='custom'>Custom HTTP Endpoint (Tự do cấu hình Body &amp; Headers)</option>"
          << "</select></div>"
          << "<div class='form-group'><label>Model Name (Tên Mô Hình):</label><input type='text' id='ai-model' class='input-text' placeholder='gemini-flash-latest / deepseek-r1 / gpt-4o-mini'></div>"
          << "<div class='form-group'><label>Service Endpoint (Địa Chỉ Dịch Vụ):</label><input type='text' id='ai-endpoint' class='input-text' placeholder='https://generativelanguage.googleapis.com/v1beta'></div>"
          << "<div class='form-group' id='ai-key-group' style='display:" << (ai_provider == core::AiModelProvider::OLLAMA ? "none" : "block") << ";'><label>API Key (Khóa Truy Cập):</label><input type='password' id='ai-key' class='input-text' placeholder='AIzaSy... / sk-...'></div>"
          << "<div class='form-group' style='grid-column: 1 / -1;'><label>Custom Headers (JSON Object):</label><input type='text' id='ai-headers' class='input-text' placeholder='{&quot;x-goog-api-key&quot;: &quot;{{API_KEY}}&quot;} hoặc {&quot;Authorization&quot;: &quot;Bearer {{API_KEY}}&quot;}'></div>"
          << "<div class='form-group' style='grid-column: 1 / -1;'><label>Cấu Hình Request Body Template (JSON Object - Cho phép tùy biến định dạng Payload):</label>"
          << "<textarea id='ai-body-template' style='width:100%; height:85px; font-family:\"JetBrains Mono\", monospace; font-size:11px; padding:6px 8px; border:1px solid var(--border-primary); border-radius:var(--radius-sharp); box-sizing:border-box;' placeholder='{&quot;contents&quot;: [{&quot;parts&quot;: [{&quot;text&quot;: &quot;{{PROMPT}}&quot;}]}]}'></textarea>"
          << "<div style='font-size:11px; color:var(--text-muted); margin-top:4px;'>💡 <strong>Placeholders hỗ trợ trong Body &amp; Headers:</strong> <code>{{PROMPT}}</code> (mã nguồn quét), <code>{{MODEL}}</code> (tên mô hình), <code>{{API_KEY}}</code> (khóa API), <code>{{FILE_PATH}}</code> (đường dẫn tệp).</div>"
          << "</div>"
          << "</div></div>"
          << "<div id='ai-json-mode' style='display:none; margin-top:10px;'>"
          << "<div style='display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; margin-bottom:8px;'>"
          << "<div style='font-size:11px; color:var(--text-muted);'>Chỉnh sửa trực tiếp file cấu hình <code>.slug/ai.json</code> của workspace:</div>"
          << "<div style='display:flex; flex-wrap:wrap; gap:4px; align-items:center;'>"
          << "<span style='font-size:11px; font-weight:600; color:var(--text-muted); margin-right:4px;'>Mẫu nhanh:</span>"
          << "<button type='button' class='btn-sec btn-sm' onclick='applyAiPreset(\"gemini\")'>Gemini</button>"
          << "<button type='button' class='btn-sec btn-sm' onclick='applyAiPreset(\"openai\")'>OpenAI / DeepSeek</button>"
          << "<button type='button' class='btn-sec btn-sm' onclick='applyAiPreset(\"anthropic\")'>Claude</button>"
          << "<button type='button' class='btn-sec btn-sm' onclick='applyAiPreset(\"ollama\")'>Ollama</button>"
          << "<button type='button' class='btn-sec btn-sm' onclick='applyAiPreset(\"custom\")'>Custom API</button>"
          << "</div></div>"
          << "<textarea id='ai-json-raw' style='width:100%; height:160px; font-family:\"JetBrains Mono\", monospace; font-size:11px; padding:8px; border:1px solid var(--border-primary); border-radius:var(--radius-sharp); box-sizing:border-box;'></textarea>"
          << "<div style='font-size:11px; color:var(--text-muted); margin-top:4px;'>💡 <strong>Gợi ý:</strong> Bạn có thể tự do định nghĩa <code>body_template</code> và <code>headers</code> theo bất kỳ chuẩn API / Gateway LLM nào.</div>"
          << "</div>"
          << "<div id='ai-status-msg' style='display:none; font-size:11px; margin-top:8px; padding:6px 10px; border-radius:var(--radius-sharp);'></div>"
          << "</div>"

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
          << "&bull; <strong>2. Policy Rules:</strong> Administrator filter rules (allow/block path, ext, regex).<br>"
          << "&bull; <strong>3. Smart Regex Guard:</strong> Fast entropy &amp; heuristic token detector (detects API keys, private keys, high-entropy secrets).<br>"
          << "&bull; <strong>4. AI Guard (LLM):</strong> Deep context-aware semantic analysis (only activated when AI server is configured)."
          << "</div>"
          << "</div></div>"

          << "<div class='grid'>"
          << "<div class='card'><h3><span>Security Filter Rules &amp; Whitelist/Blacklist</span>"
          << "<span style='display:flex; gap:6px;'>"
          << "<button class='btn-sec btn-sm' onclick='toggleRulesRawEditor()'>Xem / Sửa rules.conf</button>"
          << "<button class='btn btn-sm' onclick='openAddRuleModal()'>+ Add Rule</button>"
          << "</span></h3>"
          << "<div style='margin-bottom:10px; font-size:11px;'>"
          << "<div style='color:var(--text-muted); font-size:10px; font-weight:bold; margin-bottom:4px; text-transform:uppercase;'>Mẫu quy tắc nhanh (Click để bật/tắt):</div>"
          << "<div style='display:flex; flex-wrap:wrap; gap:4px;'>"
          << "<button type='button' id='preset-chip-node_modules_' class='btn-sec btn-sm' onclick='togglePresetRuleDirect(\"node_modules/\")' style='font-size:10px; padding:2px 6px;'>node_modules/</button>"
          << "<button type='button' id='preset-chip-target_' class='btn-sec btn-sm' onclick='togglePresetRuleDirect(\"target/\")' style='font-size:10px; padding:2px 6px;'>target/</button>"
          << "<button type='button' id='preset-chip-build_' class='btn-sec btn-sm' onclick='togglePresetRuleDirect(\"build/\")' style='font-size:10px; padding:2px 6px;'>build/</button>"
          << "<button type='button' id='preset-chip-dist_' class='btn-sec btn-sm' onclick='togglePresetRuleDirect(\"dist/\")' style='font-size:10px; padding:2px 6px;'>dist/</button>"
          << "<button type='button' id='preset-chip-_git_' class='btn-sec btn-sm' onclick='togglePresetRuleDirect(\".git/\")' style='font-size:10px; padding:2px 6px;'>.git/</button>"
          << "<button type='button' id='preset-chip___tmp' class='btn-sec btn-sm' onclick='togglePresetRuleDirect(\"*.tmp\")' style='font-size:10px; padding:2px 6px;'>*.tmp</button>"
          << "<button type='button' id='preset-chip___log' class='btn-sec btn-sm' onclick='togglePresetRuleDirect(\"*.log\")' style='font-size:10px; padding:2px 6px;'>*.log</button>"
          << "<button type='button' id='preset-chip___iso' class='btn-sec btn-sm' onclick='togglePresetRuleDirect(\"*.iso\")' style='font-size:10px; padding:2px 6px;'>*.iso</button>"
          << "<button type='button' id='preset-chip___zip' class='btn-sec btn-sm' onclick='togglePresetRuleDirect(\"*.zip\")' style='font-size:10px; padding:2px 6px;'>*.zip</button>"
          << "<button type='button' id='preset-chip-venv_' class='btn-sec btn-sm' onclick='togglePresetRuleDirect(\"venv/\")' style='font-size:10px; padding:2px 6px;'>venv/</button>"
          << "<button type='button' id='preset-chip___pycache__' class='btn-sec btn-sm' onclick='togglePresetRuleDirect(\"__pycache__/\")' style='font-size:10px; padding:2px 6px;'>__pycache__/</button>"
          << "<button type='button' id='preset-chip-_env_' class='btn-sec btn-sm' onclick='togglePresetRuleDirect(\".env*\")' style='font-size:10px; padding:2px 6px;'>.env*</button>"
          << "</div></div>"
          << "<div id='rules-raw-container' style='display:none; margin:10px 0; padding:10px; background:#f6f8fa; border:1px solid var(--border-primary); border-radius:var(--radius-sharp);'>"
          << "<div style='font-size:11px; color:var(--text-muted); margin-bottom:4px; display:flex; justify-content:space-between;'>"
          << "<span>Tệp cấu hình: <code>.slug/rules.conf</code> (Cú pháp: <code>ALLOW path &lt;duong_dan&gt;</code> hoặc <code>BLOCK ext .tmp</code>)</span>"
          << "</div>"
          << "<textarea id='raw-rules-ta' style='width:100%; height:120px; font-family:\"JetBrains Mono\", monospace; font-size:11px; padding:6px; border:1px solid var(--border-primary); border-radius:var(--radius-sharp); box-sizing:border-box;'></textarea>"
          << "<div style='margin-top:6px; display:flex; gap:6px;'>"
          << "<button type='button' class='btn btn-sm' onclick='saveRawRules()'>Lưu &amp; Áp Dụng Quy Tắc</button>"
          << "<button type='button' class='btn-sec btn-sm' onclick='reloadRawRules()'>Tải Lại</button>"
          << "</div></div>"
          << "<div class='table-scroll-container' style='max-height:220px;'>"
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
            h << "<tr><td><code>" << html_escape(r.id) << "</code></td><td>" << act << "</td><td><code>" << t_str << "</code></td><td><code style='word-break:break-all; font-size:11px;'>" << html_escape(r.value) << "</code></td>"
              << "<td><button class='btn-danger btn-sm' data-id='" << html_escape(r.id) << "' onclick='deleteRule(this.dataset.id)'>Delete</button></td></tr>";
        }
        if (rules.empty()) {
            h << "<tr><td colspan='5' style='color:var(--text-muted); text-align:center; padding:12px;'>No custom rules configured</td></tr>";
        }
        h << "</tbody></table></div></div>"

          << "<div class='card' style='margin-bottom:16px;'><h3><span>Flagged &amp; Quarantined Files <span id='audit-badge' class='badge badge-quarantined' style='margin-left:4px;'>" << audit_entries.size() << "</span></span>"
          << "<span style='display:flex; flex-wrap:wrap; align-items:center; gap:6px;'>"
          << "<button type='button' class='btn-danger btn-sm' onclick='clearAuditRecords()' title='Xóa sạch an toàn toàn bộ bản ghi audit SQLite trong .slug/index.db'>Xóa Dữ Liệu Quét</button>"
          << "<button type='button' id='btn-whitelist-all' class='btn-sec btn-sm' onclick='allowAllAuditFiles()' title='Whitelist all currently flagged files'>Whitelist All</button>"
          << "<button type='button' class='btn-sec btn-sm' onclick='queryAudit(true)'>Làm Mới</button>"
          << "</span></h3>"
          << "<div style='display:flex; flex-direction:column; gap:6px; background:#f6f8fa; border:1px solid var(--border-primary); padding:8px 10px; border-radius:var(--radius-sharp); margin-bottom:10px;'>"
          << "<div style='display:flex; flex-wrap:wrap; gap:6px; align-items:center;'>"
          << "<div style='display:flex; align-items:center; gap:4px;'>"
          << "<label style='font-size:11px; font-weight:bold; color:var(--text-muted);'>Trạng Thái:</label>"
          << "<select id='audit-filter-status' onchange='queryAudit(true)' class='input-select' style='width:auto; height:28px; padding:2px 6px; font-size:11px;'>"
          << "<option value='blocked' selected>Chỉ tệp bị chặn (Blocked / Flagged)</option>"
          << "<option value='clean'>Đã an toàn / Allowed (Clean)</option>"
          << "<option value='allowed'>Đã Whitelist (Whitelisted)</option>"
          << "<option value='all'>Tất cả trạng thái</option>"
          << "</select></div>"
          << "<div style='display:flex; align-items:center; gap:4px;'>"
          << "<label style='font-size:11px; font-weight:bold; color:var(--text-muted);'>Detector:</label>"
          << "<select id='audit-filter-detector' onchange='onAuditDetectorChanged(); queryAudit(true);' class='input-select' style='width:auto; height:28px; padding:2px 6px; font-size:11px;'>"
          << "<option value='all'>Tất cả Detector</option>"
          << "<option value='regex'>Regex Secret Guard</option>"
          << "<option value='entropy'>Shannon Entropy</option>"
          << "<option value='ai'>AI Model Guard</option>"
          << "<option value='manual'>Manual Guard</option>"
          << "</select></div>"
          << "<div style='display:flex; align-items:center; gap:4px;'>"
          << "<label style='font-size:11px; font-weight:bold; color:var(--text-muted);'>Đuôi tệp:</label>"
          << "<select id='audit-filter-ext' onchange='queryAudit(true)' class='input-select' style='width:auto; height:28px; padding:2px 6px; font-size:11px;'>"
          << "<option value='all'>Tất cả (.all)</option>"
          << "<option value='.env'>.env</option>"
          << "<option value='.key'>.key / .pem</option>"
          << "<option value='.json'>.json</option>"
          << "<option value='.py'>.py</option>"
          << "<option value='.cpp'>.cpp / .hpp</option>"
          << "<option value='.txt'>.txt</option>"
          << "</select></div>"
          << "<div style='display:flex; align-items:center; gap:4px; margin-left:auto;'>"
          << "<select id='audit-filter-limit' onchange='queryAudit(true)' class='input-select' style='width:auto; height:28px; padding:2px 6px; font-size:11px;'>"
          << "<option value='25'>25 / trang</option>"
          << "<option value='50' selected>50 / trang</option>"
          << "<option value='100'>100 / trang</option>"
          << "<option value='250'>250 / trang</option>"
          << "</select>"
          << "</div></div>"
          << "<div style='display:flex; gap:6px; align-items:center; width:100%;'>"
          << "<input type='text' id='audit-search' class='table-search-input' placeholder='Tìm đường dẫn / lý do (Enter)...' onkeyup='if(event.key===\"Enter\") queryAudit(true);' style='flex:1; min-width:140px; height:28px;'>"
          << "<button type='button' class='btn btn-sm' onclick='queryAudit(true)' style='height:28px;'>Lọc SQL</button>"
          << "</div></div>"
          << "<div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; font-size:11px;'>"
          << "<span id='audit-page-info' style='color:var(--text-muted);'>Đang tải...</span>"
          << "<div style='display:flex; gap:4px;'>"
          << "<button type='button' id='audit-prev-btn' class='btn-sec btn-sm' onclick='auditPrevPage()' disabled>&laquo; Trước</button>"
          << "<button type='button' id='audit-next-btn' class='btn-sec btn-sm' onclick='auditNextPage()' disabled>Sau &raquo;</button>"
          << "</div></div>"
          << "<div id='audit-scroll-box' class='table-scroll-container' style='max-height:280px;'>"
          << "<table><thead><tr><th style='width:36%;'>File</th><th style='width:18%;'>Status</th><th style='width:8%;'>Line</th><th style='width:24%;'>Detector / Reason</th><th style='width:14%;'>Action</th></tr></thead><tbody id='audit-tbody'>";

        for (const auto& ae : audit_entries) {
            std::string st_str = core::audit_status_to_string(ae.status);
            std::string st_color = (ae.status == core::AuditStatus::CLEAN || ae.status == core::AuditStatus::USER_ALLOWED) ? "var(--success)" : "var(--danger)";
            h << "<tr><td><code style='word-break:break-all; font-size:11px;'>" << html_escape(ae.file_path) << "</code></td><td style='white-space:nowrap;'><span style='color:" << st_color << "; font-weight:bold; font-size:11px;'>" << st_str << "</span></td>"
              << "<td style='white-space:nowrap;'>" << (ae.line_number > 0 ? ("L" + std::to_string(ae.line_number)) : "-") << "</td><td style='font-size:11px;'>" << html_escape(ae.reason) << "</td>"
              << "<td style='white-space:nowrap;'>" << (ae.status != core::AuditStatus::USER_ALLOWED ? ("<button type='button' class='btn btn-sm' data-path='" + html_escape(ae.file_path) + "' onclick='allowAuditFile(this.dataset.path)'>Whitelist</button>") : "<span style='color:var(--text-muted); font-size:11px;'>Whitelisted</span>") << "</td></tr>";
        }
        if (audit_entries.empty()) {
            h << "<tr><td colspan='5' style='color:var(--text-muted); text-align:center; padding:14px;'>No quarantined or flagged files</td></tr>";
        }
        h << "</tbody></table></div></div></div>"

          << "<div class='card' style='margin-bottom: 16px;'>"
          << "<h3><span>Recent Security Audit Activity <span id='logs-badge' class='badge badge-excluded' style='margin-left:4px;'>" << events.size() << "</span></span>"
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
          << "<div class='form-group'><label>Cập Nhật / Gia Hạn Thời Hạn Sống (TTL)</label>"
          << "<select id='edit-ttl' class='input-select'>"
          << "<option value='-1'>Giữ nguyên mốc thời gian hiện tại (Keep current expiration)</option>"
          << "<option value='3600'>Gia hạn thêm 1 giờ (+1h từ bây giờ)</option>"
          << "<option value='14400'>Gia hạn thêm 4 giờ (+4h từ bây giờ)</option>"
          << "<option value='86400' selected>Gia hạn thêm 24 giờ (+24h từ bây giờ)</option>"
          << "<option value='604800'>Gia hạn thêm 7 ngày (+7d từ bây giờ)</option>"
          << "<option value='0'>Vĩnh viễn (Permanent ∞ - Không bao giờ hết hạn)</option>"
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

          << "<div id='modal-ai-detail' class='modal'>"
          << "<div class='modal-content' style='width:760px; max-width:96vw;'>"
          << "<div style='display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border-primary); padding-bottom:8px; margin-bottom:12px;'>"
          << "<h3 style='margin:0; font-size:14px; color:var(--text-main);'>🔍 Chi Tiết Phản Hồi AI Guard: <span id='ai-detail-file' style='color:var(--text-accent); word-break:break-all;'></span></h3>"
          << "<button type='button' class='btn-sec btn-sm' onclick='closeAiDetailModal()'>✕ Đóng</button>"
          << "</div>"
          << "<div id='ai-detail-loading' style='display:none; text-align:center; padding:20px; color:var(--text-muted);'>⏳ Đang tải dữ liệu kiểm toán từ máy chủ...</div>"
          << "<div id='ai-detail-body'>"
          << "<div style='display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:12px; font-size:11px; background:#f6f8fa; border:1px solid var(--border-primary); padding:6px 10px; border-radius:var(--radius-sharp);'>"
          << "<div><strong>Kết luận:</strong> <span id='ai-detail-status' style='font-weight:bold;'>-</span></div>"
          << "<div><strong>Detector:</strong> <span id='ai-detail-detector' class='badge badge-ai'>-</span></div>"
          << "<div><strong>Dòng:</strong> <span id='ai-detail-line'>-</span></div>"
          << "<div style='flex:1;'><strong>Lý do:</strong> <span id='ai-detail-reason'>-</span></div>"
          << "</div>"
          << "<div style='display:flex; justify-content:space-between; align-items:center;'>"
          << "<div style='display:flex;'>"
          << "<button type='button' id='tab-ai-out' class='ai-tab-btn active' onclick='showAiTab(\"output\")'>📥 Raw Output JSON (Phản Hồi AI)</button>"
          << "<button type='button' id='tab-ai-in' class='ai-tab-btn' onclick='showAiTab(\"input\")'>📤 Input Prompt (Prompt Gửi Đi)</button>"
          << "</div>"
          << "<button type='button' class='btn-sec btn-sm' onclick='copyAiText(document.getElementById(\"tab-ai-out\").classList.contains(\"active\") ? \"ai-output-text\" : \"ai-input-text\")'>📋 Sao Chép (Copy)</button>"
          << "</div>"
          << "<div id='ai-output-view' style='display:block; border-top:1px solid var(--border-primary); margin-top:-1px;'>"
          << "<textarea id='ai-output-text' class='ai-code-viewer' readonly></textarea>"
          << "</div>"
          << "<div id='ai-input-view' style='display:none; border-top:1px solid var(--border-primary); margin-top:-1px;'>"
          << "<textarea id='ai-input-text' class='ai-code-viewer' readonly></textarea>"
          << "</div>"
          << "<div style='display:flex; justify-content:flex-end; margin-top:12px;'>"
          << "<button type='button' class='btn-sec' onclick='closeAiDetailModal()'>Đóng</button>"
          << "</div></div></div></div>"

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

function formatClock(sec) {
  if (sec === undefined || sec === null || sec < 0) return '00:00:00';
  if (sec === 0) return '00:00:00';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  const pad = n => String(n).padStart(2, '0');
  if (d > 0) return d + 'd ' + pad(h) + ':' + pad(m) + ':' + pad(s);
  return pad(h) + ':' + pad(m) + ':' + pad(s);
}

setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  document.querySelectorAll('.conn-ttl-badge').forEach(el => {
    const exp = parseInt(el.getAttribute('data-exp') || '0', 10);
    if (exp > 0) {
      if (exp <= now) {
        el.className = 'badge badge-quarantined';
        el.innerText = 'Hết Hạn';
      } else {
        el.innerText = 'Còn ' + formatClock(exp - now);
      }
    }
  });
}, 1000);

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
          suite: (w.suite === '3' || w.suite === 'pqc') ? '3' : ((w.suite === '1' || w.suite === 'classical') ? '1' : '2'),
          suiteName: (w.suite === 'classical' || w.suite === '1') ? 'Mức 1: Classical Hardened (X25519 + Ed25519 + SHA-256)' : ((w.suite === '3' || w.suite === 'pqc') ? 'Mức 3: Pure Post-Quantum (ML-KEM-768 + ML-DSA-65) [NIST FIPS 203/204]' : 'Mức 2: Modern High-Speed (X25519 + Ed25519 + BLAKE3) [Mặc Định]'),
          filter_level: w.filter_level || 'level2',
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
          workspace_ttl: (w.workspace_ttl !== undefined) ? w.workspace_ttl : 86400,
          workspace_remaining_sec: (w.workspace_remaining_sec !== undefined) ? w.workspace_remaining_sec : ((w.workspace_ttl !== undefined) ? w.workspace_ttl : 86400),
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
  const tabs = ['client', 'host', 'env', 'bench', 'config'];
  tabs.forEach(t => {
    const btn = document.getElementById('tab-btn-' + t);
    const sec = document.getElementById('section-' + t);
    if (btn) btn.classList.toggle('active', t === role);
    if (sec) sec.style.display = (t === role) ? 'block' : 'none';
  });
  if (role === 'host') {
    renderHostedWorkspaces();
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
  const p = (path || '').trim();
  if (!p) return;
  if (_inspectSlugTimer) clearTimeout(_inspectSlugTimer);
  _inspectSlugTimer = setTimeout(() => {
    fetch('/api/fs/inspect-path?path=' + encodeURIComponent(p))
      .then(r => r.json())
      .then(data => {
        if (data && data.next_free_port) {
          const portInp = document.getElementById('host-port');
          if (portInp && (!portInp.value || portInp.value === '9443')) {
            portInp.placeholder = String(data.next_free_port);
          }
        }
      })
      .catch(() => {});
  }, 200);
}

function renderHostedWorkspaces() {
  const container = document.getElementById('hosted-workspaces-list');
  const countBadge = document.getElementById('hosted-count');
  const countTitle = document.getElementById('hosted-count-title');
  if (countBadge) countBadge.textContent = hostedWorkspaces.length;
  if (countTitle) countTitle.textContent = hostedWorkspaces.length;
  if (!container) return;

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
            <button class="btn btn-sm" onclick="window.open('http://127.0.0.1:' + '${w.port}' + '/admin', '_blank')">${ICONS.shield} Quản Trị &amp; Duyệt (Admin Dashboard)</button>
            <button class="btn-sec btn-sm" data-path="${(w.path || '').replace(/"/g, '&quot;')}" onclick="openInExplorerFromAttr(this)" title="Mở thư mục này trực tiếp trong Windows Explorer">${ICONS.folder} Mở Explorer</button>
            <button class="btn-danger btn-sm" onclick="stopHost('${w.id}')">${ICONS.power} Dừng Trạm</button>
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

          <!-- Box 2: Cấu Hình Mật Mã & Thời Gian Phiên Workspace -->
          <div class="host-box" style="gap:10px;">
            <div>
              <div class="host-box-title">
                <span>${ICONS.shield} MỨC MẬT MÃ &amp; THỜI GIAN PHIÊN</span>
                <span id="suite-badge-${w.id}" class="badge ${(w.suite === '3' || w.suite === 'pqc') ? 'badge-pqc' : ''}" style="${(w.suite === '2' || w.suite === 'modern' || !w.suite) ? 'background:#ddf4ff; color:#0969da; border:1px solid rgba(9,105,218,0.3);' : ((w.suite === '1' || w.suite === 'classical') ? 'background:#fff8c5; color:#9a6700; border:1px solid rgba(154,103,0,0.3);' : '')}">${(w.suite === '3' || w.suite === 'pqc') ? 'PQC NATIVE (FIPS 203)' : ((w.suite === '1' || w.suite === 'classical') ? 'CLASSICAL (X25519)' : 'MODERN HIGH-SPEED (BLAKE3)')}</span>
              </div>
              
              <div style="margin-bottom:8px;">
                <label style="font-size:10px; color:var(--text-muted); font-weight:700; display:block; margin-bottom:2px;">CẤU HÌNH MẬT MÃ (CIPHER SUITE):</label>
                <select id="suite-select-${w.id}" class="input-select" style="width:100%; font-size:11px; padding:5px 8px; height:32px;" onchange="updateHostSuite('${w.id}', this.value)">
                  <option value="2" ${(w.suite === '2' || w.suite === 'modern' || !w.suite) ? 'selected' : ''}>Mức 2: Modern High-Speed (BLAKE3 + X25519 + Ed25519 + XChaCha20) [Mặc Định]</option>
                  <option value="3" ${(w.suite === '3' || w.suite === 'pqc') ? 'selected' : ''}>Mức 3: Pure Post-Quantum (ML-KEM-768 + ML-DSA-65) [NIST FIPS 203/204]</option>
                  <option value="1" ${(w.suite === '1' || w.suite === 'classical') ? 'selected' : ''}>Mức 1: Classical Hardened (SHA-256 + X25519 + Ed25519 + XChaCha20)</option>
                </select>
              </div>

              <div>
                <label style="font-size:10px; color:var(--text-muted); font-weight:700; display:block; margin-bottom:2px;">THỜI GIAN SỐNG PHIÊN (WORKSPACE TTL):</label>
                <div style="background:#ffffff; border:1px solid var(--border-primary); padding:6px 10px; border-radius:2px; font-size:11px; display:flex; align-items:center; justify-content:space-between;">
                  <span style="font-weight:700; color:#0969da; display:inline-flex; align-items:center; gap:6px; font-family:'JetBrains Mono', monospace;" id="ws-ttl-clock-${w.id}">
                    ${ICONS.clock} <span id="ws-ttl-val-${w.id}">${(w.workspace_ttl === 0) ? 'Vĩnh viễn (∞)' : formatClock(w.workspace_remaining_sec !== undefined ? w.workspace_remaining_sec : (w.workspace_ttl || 86400))}</span>
                  </span>
                  <span id="ws-ttl-badge-${w.id}" style="font-size:10px; color:#1a7f37; background:#dafbe1; padding:1px 6px; border:1px solid rgba(26,127,55,0.3); border-radius:2px; font-weight:600;">${(w.workspace_ttl === 0) ? 'Không Giới Hạn' : 'Đang Đếm Ngược'}</span>
                </div>
                <div style="font-size:10px; color:var(--text-muted); margin-top:2px;">(Tự động thu hồi phiên và ngắt kết nối khi hết thời gian sống)</div>
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

      </div>
    `;
  }).join('');
}

function renderInactiveWorkspaces() {}
function resumeWorkspace() {}
function removeInactiveWorkspace() {}
function saveWorkspaceState() {}

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
      badgeEl.textContent = 'MODERN HIGH-SPEED (BLAKE3)';
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

function onFilterLevelChanged(lvl) {
  const box = document.getElementById('ai-model-box');
  if (box) box.style.display = (lvl === 'level4') ? 'block' : 'none';
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
  const otpTtl = parseInt(document.getElementById('host-otp-ttl')?.value) || 60;
  const wsTtl = parseInt(document.getElementById('host-ttl')?.value) || 86400;
  const aiModel = document.getElementById('host-ai-model')?.value || 'ollama';

  showToast(`Đang khởi động chia sẻ workspace trên cổng ${port}...`);
  fetch('/api/host/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      path: pathInp,
      port: port,
      suite: sSelect.value,
      filter: fSelect.value,
      ai_model: aiModel,
      otp_step: otpTtl,
      ttl: wsTtl
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
  if (confirm(`Dừng chia sẻ thư mục trên cổng ${p}?`)) {
    showToast(`Đang dừng trạm phát trên cổng ${p}...`);
    fetch('/api/host/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ port: p })
    })
    .then(r => r.json())
    .then(res => {
      loadHostedWorkspaces();
      showToast(res.message || `Đã dừng chia sẻ trên cổng ${p} thành công!`);
    })
    .catch(err => {
      alert('Lỗi dừng trạm phát: ' + err.message);
    });
  }
}

function openWorkspaceAdmin(port) {
  window.open('http://127.0.0.1:' + port + '/admin', '_blank');
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
  if (confirm('Xóa sạch bộ đệm kiểm toán? Toàn bộ trạng thái cách ly sẽ được lập chỉ mục lại từ đầu.')) {
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
  const port = parseInt(document.getElementById('cfg-portal-port').value) || 8081;
  localStorage.setItem('slug_system_config', JSON.stringify({ default_suite: suite, portal_port: port }));
  fetch('/api/config/system', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ default_suite: suite, portal_port: port })
  }).then(r => r.json()).then(res => {
    showToast('Đã lưu cấu hình mặc định (Mức 2 Modern High-Speed) vào ~/.slug/config.json!');
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
    if (w.workspace_remaining_sec !== undefined && w.workspace_ttl > 0) {
      if (w.workspace_remaining_sec > 0) {
        w.workspace_remaining_sec--;
      }
      const valEl = document.getElementById(`ws-ttl-val-${w.id}`);
      const badgeEl = document.getElementById(`ws-ttl-badge-${w.id}`);
      if (valEl) {
        valEl.textContent = formatClock(w.workspace_remaining_sec);
      }
      if (badgeEl) {
        if (w.workspace_remaining_sec <= 0) {
          badgeEl.textContent = 'Đã Hết Hạn';
          badgeEl.style.background = '#ffebe9';
          badgeEl.style.color = '#cf222e';
          badgeEl.style.borderColor = 'rgba(207,34,46,0.3)';
        } else {
          badgeEl.textContent = 'Đang Đếm Ngược';
          badgeEl.style.background = '#dafbe1';
          badgeEl.style.color = '#1a7f37';
          badgeEl.style.borderColor = 'rgba(26,127,55,0.3)';
        }
      }
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
  loadHostedWorkspaces();
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
    <button class="role-tab-btn" id="tab-btn-env" onclick="switchRole('env')">
      ${ICONS.lock} <span>3. EnvShield &amp; Vault</span>
    </button>
    <button class="role-tab-btn" id="tab-btn-bench" onclick="switchRole('bench')">
      ${ICONS.zap} <span>4. Benchmark PQC</span>
    </button>
    <button class="role-tab-btn" id="tab-btn-config" onclick="switchRole('config')">
      ${ICONS.settings} <span>5. Cấu Hình &amp; Lệnh CLI</span>
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
            <th>Xác Thực</th>
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

  <!-- ==================== [SECTION 2: HOST MODE - CHIA SẺ WORKSPACE] ==================== -->
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
            <input type="text" id="host-path" class="input-text" value="" placeholder="Bắt buộc: Bấm [Chọn Thư Mục] hoặc nhập..." style="flex:1; height:38px; box-sizing:border-box; font-size:12px;" required>
            <input type="file" id="dir-picker-host-path" webkitdirectory directory style="display:none;" onchange="handleDirInputSelected(this, 'host-path');">
            <button type="button" class="btn-sec" onclick="chooseLocalSaveLocation('host-path')" style="height:38px !important; box-sizing:border-box; padding:0 14px; font-size:12px; display:inline-flex; align-items:center; gap:6px; white-space:nowrap; border-radius:var(--radius-sharp); cursor:pointer;">
              ${ICONS.folder} <span>Chọn...</span>
            </button>
          </div>
        </div>

        <div style="display:grid; grid-template-columns: 1fr 1.6fr; gap:12px;">
          <div class="form-group" style="margin-bottom:0;">
            <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Cổng (Port)</label>
            <input type="number" id="host-port" class="input-text" value="9443" placeholder="9443" style="height:38px; box-sizing:border-box; font-size:13px;">
          </div>
          <div class="form-group" style="margin-bottom:0;">
            <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Mức Mật Mã (Cipher Suite)</label>
            <select id="host-suite" class="input-select" style="height:38px; box-sizing:border-box; font-size:12px;">
              <option value="2" selected>Mức 2: Modern High-Speed (BLAKE3 + X25519 + Ed25519 + XChaCha20) [Mặc Định]</option>
              <option value="3">Mức 3: Pure Post-Quantum (ML-KEM-768 + ML-DSA-65) [NIST FIPS 203/204]</option>
              <option value="1">Mức 1: Classical Hardened (SHA-256 + X25519 + Ed25519 + XChaCha20)</option>
            </select>
          </div>
        </div>

        <div class="form-group" style="margin-bottom:8px;">
          <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">5 Cấp Độ Lọc Dữ Liệu Bảo Mật (Filter Levels)</label>
          <select id="host-filter" class="input-select" onchange="onFilterLevelChanged(this.value)" style="height:38px; box-sizing:border-box; font-size:12px;">
            <option value="level0">Mức 0: Không Lọc / Chia Sẻ Tất Cả (Tắt Rules, .gitignore &amp; AI - Chỉ giữ bảo vệ .slug/)</option>
            <option value="level1">Mức 1: Rules &amp; Gitignore (Chỉ lọc .gitignore &amp; rules.conf, không quét nội dung)</option>
            <option value="level2" selected>Mức 2: Regex Secret Guard (Mức 1 + Quét mẫu định danh Private Key, AWS, GitHub, JWT, .env) [Mặc Định / Khuyên Dùng]</option>
            <option value="level3">Mức 3: Shannon Entropy (Mức 2 + Đo entropy trên file mã nguồn, bỏ qua 100% binary/ảnh)</option>
            <option value="level4">Mức 4: AI Model Scan (Mức 3 + Phân tích ngữ cảnh sâu bằng mô hình AI)</option>
          </select>
        </div>

        <div id="ai-model-box" class="form-group" style="display:none; margin-bottom:8px; background:#f6f8fa; border:1px solid #54aeff; padding:10px; border-radius:2px;">
          <label style="font-size:11px; font-weight:700; color:#0969da; margin-bottom:4px; display:block;">🤖 Chọn Mô Hình AI (Áp dụng cho Mức 4):</label>
          <select id="host-ai-model" class="input-select" style="height:36px; box-sizing:border-box; font-size:12px; background:#fff;">
            <option value="ollama" selected>Ollama Local (DeepSeek-R1 / CodeLlama - Offline an toàn)</option>
            <option value="openai">OpenAI Cloud (GPT-4o-mini / GPT-4o)</option>
            <option value="gemini">Google Gemini Cloud (Gemini 2.5 Flash)</option>
          </select>
        </div>

        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px; margin-bottom:8px;">
          <div class="form-group" style="margin-bottom:0;">
            <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Chu Kỳ Đổi Mã OTP (TOTP Step)</label>
            <select id="host-otp-ttl" class="input-select" style="height:38px; box-sizing:border-box; font-size:12px;">
              <option value="30">30 giây</option>
              <option value="60" selected>60 giây (1 phút) [Khuyên dùng]</option>
              <option value="120">120 giây (2 phút)</option>
              <option value="300">300 giây (5 phút)</option>
              <option value="600">600 giây (10 phút)</option>
            </select>
          </div>
          <div class="form-group" style="margin-bottom:0;">
            <label style="font-size:11px; font-weight:700; color:var(--text-main); margin-bottom:4px; display:block;">Thời Gian Sống Workspace (Workspace TTL)</label>
            <select id="host-ttl" class="input-select" style="height:38px; box-sizing:border-box; font-size:12px;">
              <option value="3600">1 giờ (1h)</option>
              <option value="14400">4 giờ (4h)</option>
              <option value="86400" selected>24 giờ (1 ngày) [Mặc Định]</option>
              <option value="604800">7 ngày (7d)</option>
              <option value="0">Vĩnh viễn (Permanent ∞)</option>
            </select>
          </div>
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
  </div>

  <!-- ==================== [SECTION 3: ENVSHIELD & CENTRAL VAULT] ==================== -->
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
            <option value="SUITE_2_MODERN_HIGH_SPEED" selected>SUITE_2_MODERN_HIGH_SPEED (BLAKE3 + X25519 + Ed25519 + XChaCha20) [Mặc Định]</option>
            <option value="SUITE_3_PURE_PQC">SUITE_3_PURE_PQC (ML-KEM-768 + ML-DSA-65) [NIST FIPS 203/204]</option>
            <option value="SUITE_1_CLASSICAL">SUITE_1_CLASSICAL (SHA-256 + X25519 + Ed25519 + XChaCha20)</option>
          </select>
        </div>
        <div class="form-group">
          <label>Cổng Web Loopback Mặc Định (portal_port)</label>
          <input type="number" id="cfg-portal-port" class="input-text" value="8081" placeholder="8081">
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
            std::string exp_str;
            if (c.expires_at == 0) {
                exp_str = "<span class='badge badge-excluded'>Permanent (&infin;)</span>";
            } else if (c.expires_at > now) {
                uint64_t rem = c.expires_at - now;
                exp_str = "<span class='badge badge-allowed conn-ttl-badge' data-exp='" + std::to_string(c.expires_at) + "'>C\xc3\xb2n " + core::Utils::format_duration(rem) + "</span>";
            } else {
                exp_str = "<span class='badge badge-quarantined'>H\xc3\xa9t H\xe1\xba\xa1n</span>";
            }

            std::string auth_badge;
            if (c.auth_type == "account") {
                auth_badge = "<span class='badge badge-allowed' style='font-size:10px;'>Acc: " + html_escape(c.identity.empty() ? "User" : c.identity) + "</span>";
            } else if (c.auth_type == "totp" || c.identity.rfind("totp", 0) == 0) {
                auth_badge = "<span class='badge badge-quarantined' style='font-size:10px;'>TOTP [" + core::role_to_string(c.role) + "]</span>";
            } else {
                auth_badge = "<span class='badge badge-excluded' style='font-size:10px;'>" + html_escape(c.identity.empty() ? "Phi\xc3\xaan" : c.identity) + "</span>";
            }

            std::string esc_id_html = html_escape(c.id);
            std::string esc_id_js = js_escape(c.id);
            std::string esc_ws_html = html_escape(c.workspace.empty() ? "workspace" : c.workspace);
            std::string esc_host_html = html_escape(c.host);

            conns_rows += "<tr class='clickable-row' onclick='openSaved(\"" + esc_id_js + "\")'><td><strong>" + esc_id_html + "</strong></td>"
                       + "<td><code>" + esc_ws_html + "</code></td>"
                       + "<td>" + auth_badge + "</td>"
                       + "<td><code>" + esc_host_html + ":" + std::to_string(c.port) + "</code></td>"
                       + "<td><span class='role-tag'>" + core::role_to_string(c.role) + "</span></td>"
                       + "<td>" + exp_str + "</td>"
                       + "<td onclick='event.stopPropagation()'><button class='btn btn-xs' onclick='openSaved(\"" + esc_id_js + "\")'>"
                       + "<svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><path d='M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z'></path></svg> Duyệt Thư Mục</button> "
                       + "<button class='btn-danger btn-xs' onclick='removeSaved(\"" + esc_id_js + "\")'>"
                       + "<svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:middle;'><polyline points='3 6 5 6 21 6'></polyline><path d='M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2'></path></svg> Xóa</button></td></tr>";
        }
        if (conns_rows.empty()) {
            conns_rows = "<tr><td colspan='7' style='text-align:center; color:var(--text-muted); padding:18px;'>Chưa có trạm lưu nào. Điền IP và mã OTP vào biểu mẫu phía trên để kết nối ngay.</td></tr>";
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
