#!/usr/bin/env python3
"""
Slug Local Web UI Previewer & Simulator
---------------------------------------
Đọc trực tiếp mã nguồn HTML từ 'src/net/web_assets.hpp' (Single Source of Truth),
mô phỏng trạm điều khiển Client & Host Portal cùng Web Dropbox thời gian thực
mà không cần biên dịch trước C++.

Mỗi khi bạn chỉnh sửa 'src/net/web_assets.hpp' và F5 (Refresh) trên trình duyệt,
máy chủ sẽ tự động nạp lại giao diện thật mới nhất từ file C++!
"""

import http.server
import socketserver
import webbrowser
import json
import socket
import sys
import os
import io
import zipfile
import urllib.parse
import threading
import time

PORT = 8080

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LAN_IP = get_lan_ip()
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HPP_PATH = os.path.join(BASE_DIR, "src", "net", "web_assets.hpp")

UNQUARANTINED_FILES = set()
INCLUDED_EXCLUDED_FILES = set()

# In-memory mock user accounts
USER_ACCOUNTS = [
    {
        "username": "admin",
        "role": "rw",
        "roleName": "Toàn Quyền (Đọc & Ghi)",
        "ttl": 0,
        "status": "Permanent (∞)",
        "createdAt": "16/10/2026 22:00",
        "revoked": False
    },
    {
        "username": "colleague_bob",
        "role": "r",
        "roleName": "Chỉ Đọc (Tải Về)",
        "ttl": 6300,
        "status": "Còn 1h 45m",
        "createdAt": "16/10/2026 22:10",
        "revoked": False
    },
    {
        "username": "student_alice",
        "role": "w",
        "roleName": "Hộp Thư Nộp Bài (Upload)",
        "ttl": 19200,
        "status": "Còn 5h 20m",
        "createdAt": "16/10/2026 22:25",
        "revoked": False
    }
]

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KiB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MiB"
    return f"{size_bytes / (1024 * 1024 * 1024):.1f} GiB"

def get_file_status(name):
    global UNQUARANTINED_FILES, INCLUDED_EXCLUDED_FILES
    if name in UNQUARANTINED_FILES:
        return 'CLEAN_UNQUARANTINED'
    lower = name.lower()
    if lower.startswith('.env') or lower.endswith('.pem') or lower.endswith('.key') or 'id_rsa' in lower or 'secret' in lower:
        return 'QUARANTINED'
    if lower in ['node_modules', 'target', '.git', 'build', '__pycache__', '.vs'] or lower.endswith('.obj') or lower.endswith('.exe') or lower.endswith('.pdb'):
        if name in INCLUDED_EXCLUDED_FILES:
            return 'CLEAN'
        return 'EXCLUDED'
    return 'CLEAN'

def get_portal_html():
    """
    Đọc trực tiếp template HTML từ hàm render_client_portal trong file src/net/web_assets.hpp
    và thực hiện các thay thế tham số C++ tương đương.
    """
    if not os.path.exists(HPP_PATH):
        return f"""<!DOCTYPE html><html><body style="font-family:sans-serif; padding:40px;">
        <h2>Không tìm thấy tệp mã nguồn C++:</h2>
        <code>{HPP_PATH}</code>
        </body></html>"""

    try:
        with open(HPP_PATH, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return f"<h2>Lỗi đọc web_assets.hpp: {str(e)}</h2>"

    idx = content.find("render_client_portal")
    if idx == -1:
        return "<h2>Lỗi: Không tìm thấy hàm render_client_portal trong web_assets.hpp</h2>"

    raw_start = content.find('R"raw(<!DOCTYPE html>', idx)
    if raw_start == -1:
        raw_start = content.find('R"raw(', idx)
    
    if raw_start == -1:
        return "<h2>Lỗi: Không tìm thấy chuỗi R\"raw( trong render_client_portal</h2>"

    html_start = raw_start + len('R"raw(')
    html_end = content.find(')raw";', html_start)
    if html_end == -1:
        return "<h2>Lỗi: Không tìm thấy kết thúc chuỗi )raw\"; trong render_client_portal</h2>"

    raw_html = content[html_start:html_end]

    # C++ Replacement simulation
    saved_conns_rows = f"""
    <tr class='clickable-row' onclick="window.location.href='/drop'">
      <td><strong>lab-peer-local</strong></td>
      <td><code>./ ({os.path.basename(BASE_DIR)})</code></td>
      <td><code>127.0.0.1:9443</code></td>
      <td><span class='role-tag'>RW</span></td>
      <td>Permanent (∞)</td>
      <td onclick='event.stopPropagation()'>
        <button class='btn btn-xs' onclick="window.location.href='/drop'">🚀 Duyệt Thư Mục</button>
        <button class='btn-danger btn-xs' onclick="showToast('Đã xóa trạm lưu khỏi danh bạ!')">Xóa</button>
      </td>
    </tr>
    """

    rendered = raw_html.replace("{{PORTAL_PORT}}", str(PORT))
    rendered = rendered.replace("{{SAVED_CONNS_ROWS}}", saved_conns_rows.strip())
    rendered = rendered.replace("{{SAVED_CONNS_COUNT}}", "1")

    return rendered

def get_dropbox_explorer_html(rel_subpath=""):
    """
    Giao diện Web Dropbox Explorer xem và tải file trực tiếp từ đĩa cứng của workspace.
    Được đồng bộ phong cách với web_assets.hpp.
    """
    abs_target = os.path.normpath(os.path.join(BASE_DIR, rel_subpath))
    if not os.path.exists(abs_target):
        abs_target = BASE_DIR
        rel_subpath = ""

    norm_rel = os.path.relpath(abs_target, BASE_DIR).replace("\\", "/")
    if norm_rel == ".":
        norm_rel = ""

    parent_path = ""
    if norm_rel:
        p = os.path.dirname(norm_rel)
        parent_path = p.replace("\\", "/")

    return f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Slug Web Dropbox - {os.path.basename(BASE_DIR)} / {norm_rel or 'root'}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {{
  --bg-canvas: #f6f8fa;
  --bg-surface: #ffffff;
  --bg-surface-hover: #f3f4f6;
  --border-primary: #d0d7de;
  --border-subtle: #e1e4e8;
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
}}
* {{ box-sizing: border-box; }}
body {{
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg-canvas);
  color: var(--text-main);
  margin: 0;
  padding: 24px;
  line-height: 1.5;
}}
code, pre, .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
.container {{
  max-width: 1100px;
  margin: 0 auto;
  background: var(--bg-surface);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-sharp);
  padding: 24px;
  box-shadow: 0 1px 3px rgba(31,35,40,0.06);
}}
.top-bar {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--border-primary);
  padding-bottom: 16px;
  margin-bottom: 16px;
  flex-wrap: wrap;
  gap: 12px;
}}
.btn, .btn-sec, .btn-danger {{
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
  box-sizing: border-box;
  height: 34px;
  padding: 0 14px;
}}
.btn {{ background: #0969da; color: #fff; border: 1px solid #0969da; }}
.btn:hover {{ background: #0858b8; }}
.btn-sec {{ background: #fff; color: var(--text-main); border: 1px solid var(--border-primary); }}
.btn-sec:hover {{ background: var(--bg-surface-hover); }}
.btn-danger {{ background: #fff; color: var(--danger); border: 1px solid var(--danger); }}
.btn-danger:hover {{ background: var(--danger); color: #fff; }}
.btn-sm {{ height: 28px; padding: 0 10px; font-size: 11px; }}
.btn-xs {{ height: 24px; padding: 0 8px; font-size: 10px; }}

.badge {{
  padding: 2px 7px;
  border-radius: var(--radius-sharp);
  font-size: 11px;
  font-weight: 600;
  font-family: 'JetBrains Mono', monospace;
  text-transform: uppercase;
}}
.badge-available {{ background: var(--success-bg); color: var(--success); border: 1px solid rgba(26,127,55,0.3); }}
.badge-quarantined {{ background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(207,34,46,0.3); }}
.badge-excluded {{ background: var(--bg-surface-hover); color: var(--text-muted); border: 1px solid var(--border-primary); }}
.badge-pqc {{ background: var(--pqc-bg); color: var(--pqc); border: 1px solid rgba(130,80,223,0.3); }}

.nav-bar {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #f6f8fa;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-sharp);
  padding: 10px 14px;
  margin-bottom: 14px;
  flex-wrap: wrap;
  gap: 10px;
}}
.breadcrumb {{
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  display: flex;
  align-items: center;
  gap: 6px;
}}
.breadcrumb a {{ color: #0969da; text-decoration: none; font-weight: 600; }}
.breadcrumb a:hover {{ text-decoration: underline; }}

table {{
  width: 100%;
  border-collapse: collapse;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  margin-top: 8px;
}}
th, td {{
  text-align: left;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border-subtle);
  vertical-align: middle;
}}
th {{
  background: #f6f8fa;
  color: var(--text-muted);
  font-size: 11px;
  text-transform: uppercase;
}}
tr.clickable-row {{ cursor: pointer; }}
tr.clickable-row:hover {{ background-color: #f0f6fc; }}

.dropzone {{
  border: 2px dashed var(--border-primary);
  border-radius: var(--radius-sharp);
  padding: 20px;
  text-align: center;
  color: var(--text-muted);
  font-size: 12px;
  margin-top: 18px;
  font-family: 'JetBrains Mono', monospace;
  background: #fdfefe;
  transition: all 0.2s ease;
}}
.dropzone.active {{
  border-color: #0969da;
  background: #f0f7ff;
  color: #0969da;
}}
</style>
<script>
let currentSubpath = '{norm_rel}';

function openFolder(sub) {{
  window.location.href = '/drop?path=' + encodeURIComponent(sub);
}}

function downloadZip() {{
  window.location.href = '/api/workspace/download-zip?path=' + encodeURIComponent(currentSubpath);
}}

function downloadFile(fullRel) {{
  window.location.href = '/api/workspace/download-file?path=' + encodeURIComponent(fullRel);
}}

function toggleUnquarantine(fname) {{
  fetch('/api/host/unquarantine', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{ filename: fname, hostId: 'host-9443' }})
  }}).then(() => window.location.reload());
}}

function setupDropzone() {{
  const dz = document.getElementById('dropzone');
  if (!dz) return;
  ['dragenter', 'dragover'].forEach(name => {{
    dz.addEventListener(name, (e) => {{ e.preventDefault(); dz.classList.add('active'); }}, false);
  }});
  ['dragleave', 'drop'].forEach(name => {{
    dz.addEventListener(name, (e) => {{ e.preventDefault(); dz.classList.remove('active'); }}, false);
  }});
  dz.addEventListener('drop', (e) => {{
    const files = e.dataTransfer.files;
    if (files.length > 0) {{
      alert(`Đã nhận ${{files.length}} tệp! Slug Guard đang kiểm toán trong RAM Shield...`);
    }}
  }});
}}
window.onload = setupDropzone;
</script>
</head>
<body>
<div class="container">
  <div class="top-bar">
    <div>
      <div style="display:flex; align-items:center; gap:10px;">
        <span style="font-weight:900; font-family:'JetBrains Mono', monospace; font-size:16px; background:#1f2328; color:#fff; padding:4px 8px; border-radius:4px;">SLUG</span>
        <h2 style="margin:0; font-size:16px;">Web Dropbox Explorer</h2>
        <span class="badge badge-pqc">⭐ ML-KEM-1024</span>
        <span class="badge badge-available">Quyền: RW</span>
      </div>
      <div style="font-size:11px; color:var(--text-muted); font-family:'JetBrains Mono', monospace; margin-top:4px;">
        Đọc và đồng bộ dữ liệu thật từ ổ đĩa: <code>{BASE_DIR}</code>
      </div>
    </div>
    <div style="display:flex; gap:8px;">
      <button class="btn" onclick="downloadZip()">📥 Tải Toàn Bộ Thư Mục Này (.ZIP)</button>
      <button class="btn-sec" onclick="window.location.href='/'">🔙 Trở Về Trạm Điều Khiển</button>
    </div>
  </div>

  <div class="nav-bar">
    <div class="breadcrumb">
      <span>📂</span>
      <a href="/drop">root</a>
      {f'<span>/</span> <span>{norm_rel}</span>' if norm_rel else ''}
    </div>
    <div>
      {f'<button class="btn-sec btn-sm" onclick="openFolder(\'{parent_path}\')">⬆️ Thư Mục Cha</button>' if norm_rel else ''}
      <button class="btn-sec btn-sm" onclick="window.location.reload()">🔄 Làm Mới</button>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Tên Tệp / Thư Mục</th>
        <th>Loại</th>
        <th>Dung Lượng</th>
        <th>Trạng Thái Slug Guard</th>
        <th>Thao Tác</th>
      </tr>
    </thead>
    <tbody>
      {generate_folder_rows(abs_target, norm_rel)}
    </tbody>
  </table>

  <div class="dropzone" id="dropzone">
    <div style="font-size:18px; margin-bottom:6px;">📤 Kéo &amp; Thả Tệp Vào Đây Để Tải Lên Workspace</div>
    <div>Slug Guard sẽ tự động kiểm toán bảo mật 4 tầng (Slug Rule + Slug Regex + Slug AI + RAM Shield)</div>
  </div>

  <div style="text-align:center; padding:18px 0 6px 0; font-size:11px; color:var(--text-muted); font-family:'JetBrains Mono', monospace; border-top:1px solid var(--border-subtle); margin-top:20px;">
    Slug 1.0.0 &bull; Post-Quantum P2P Workspace Sharing &bull; NIST FIPS 203/204
  </div>
</div>
</body>
</html>"""

def generate_folder_rows(abs_target, norm_rel):
    rows = []
    try:
        with os.scandir(abs_target) as it:
            entries = sorted(it, key=lambda e: (not e.is_dir(), e.name.lower()))
            for entry in entries:
                try:
                    is_dir = entry.is_dir()
                    st = entry.stat()
                    name = entry.name
                    sub = (norm_rel + "/" + name) if norm_rel else name
                    status = get_file_status(name)
                    size_str = format_size(st.st_size) if not is_dir else "-"
                    
                    if is_dir:
                        badge = '<span class="badge badge-available">Thư Mục</span>'
                        action = f'<button class="btn-sec btn-xs" onclick="openFolder(\'{sub}\')">📂 Mở</button>'
                        row_click = f'onclick="openFolder(\'{sub}\')"'
                        name_display = f'📁 <strong>{name}</strong>'
                    else:
                        if status == 'QUARANTINED':
                            badge = '<span class="badge badge-quarantined">🔒 Cách Ly (Secret)</span>'
                            action = f'<button class="btn btn-xs" onclick="toggleUnquarantine(\'{name}\')">🔓 Gỡ Cách Ly</button>'
                            row_click = ""
                            name_display = f'📄 <strong style="color:var(--danger);">{name}</strong>'
                        elif status == 'CLEAN_UNQUARANTINED':
                            badge = '<span class="badge badge-available">🔓 Đã Cho Phép</span>'
                            action = f'<button class="btn-sec btn-xs" onclick="downloadFile(\'{sub}\')">⬇️ Tải Về</button> ' \
                                     f'<button class="btn-danger btn-xs" onclick="toggleUnquarantine(\'{name}\')">🔒 Tái Khóa</button>'
                            row_click = f'onclick="downloadFile(\'{sub}\')"'
                            name_display = f'📄 <strong style="color:var(--success);">{name}</strong>'
                        elif status == 'EXCLUDED':
                            badge = '<span class="badge badge-excluded">📦 Bỏ Qua (Slug Rule)</span>'
                            action = '<span style="color:var(--text-muted); font-size:10px;">Bị loại trừ</span>'
                            row_click = ""
                            name_display = f'📄 <span style="color:var(--text-muted);">{name}</span>'
                        else:
                            badge = '<span class="badge badge-available">🟢 Sạch (PQC Ready)</span>'
                            action = f'<button class="btn-sec btn-xs" onclick="downloadFile(\'{sub}\')">⬇️ Tải Về</button>'
                            row_click = f'onclick="downloadFile(\'{sub}\')"'
                            name_display = f'📄 {name}'

                    rows.append(f"""
                    <tr class="clickable-row" {row_click}>
                      <td>{name_display}</td>
                      <td><code>{"Directory" if is_dir else os.path.splitext(name)[1].upper() or "File"}</code></td>
                      <td><code>{size_str}</code></td>
                      <td>{badge}</td>
                      <td onclick="event.stopPropagation()">{action}</td>
                    </tr>
                    """)
                except Exception:
                    continue
    except Exception as e:
        rows.append(f'<tr><td colspan="5" style="color:red; text-align:center;">Lỗi đọc thư mục: {str(e)}</td></tr>')

    if not rows:
        rows.append('<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:20px;">Thư mục trống.</td></tr>')

    return "".join(rows)

class PreviewHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Main Client & Host Portal (Loaded directly from web_assets.hpp!)
        if path in ["/", "/index.html", "/portal"]:
            html = get_portal_html()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        # 2. Web Dropbox Workspace File Explorer
        if path in ["/drop", "/files", "/explorer"]:
            rel_subpath = query.get("path", [""])[0]
            html = get_dropbox_explorer_html(rel_subpath)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        # 3. API Download single real file
        if path == "/api/workspace/download-file":
            rel_path = query.get("path", [""])[0]
            abs_target = os.path.normpath(os.path.join(BASE_DIR, rel_path))
            if os.path.isfile(abs_target):
                fname = os.path.basename(abs_target)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
                self.end_headers()
                with open(abs_target, "rb") as f:
                    self.wfile.write(f.read())
                return
            else:
                self.send_response(404)
                self.end_headers()
                return

        # 4. API Download directory as real ZIP
        if path == "/api/workspace/download-zip":
            rel_path = query.get("path", [""])[0]
            abs_target = os.path.normpath(os.path.join(BASE_DIR, rel_path))
            if os.path.isdir(abs_target):
                folder_name = os.path.basename(abs_target) or "workspace"
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    for root, dirs, files in os.walk(abs_target):
                        dirs[:] = [d for d in dirs if get_file_status(d) != 'EXCLUDED']
                        for file in files:
                            st = get_file_status(file)
                            if st in ['CLEAN', 'CLEAN_UNQUARANTINED']:
                                full_file = os.path.join(root, file)
                                arcname = os.path.relpath(full_file, abs_target)
                                zf.write(full_file, arcname)
                zip_bytes = buf.getvalue()
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", f'attachment; filename="{folder_name}.zip"')
                self.end_headers()
                self.wfile.write(zip_bytes)
                return
            else:
                self.send_response(404)
                self.end_headers()
                return

        # 5. API List Users
        if path == "/api/users/list":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"users": USER_ACCOUNTS}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        global USER_ACCOUNTS, UNQUARANTINED_FILES
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        length = int(self.headers.get('content-length', 0))
        body = self.rfile.read(length) if length > 0 else b'{}'
        try:
            req_data = json.loads(body.decode('utf-8'))
        except Exception:
            req_data = {}

        # Connect simulation
        if path == "/api/portal/connect":
            auth_mode = req_data.get("auth_mode", "otp")
            if auth_mode == "otp":
                otp = req_data.get("otp", "")
                if len(otp) != 8 or not otp.isdigit():
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status":"error","message":"Ma OTP hop le phai gom 8 chu so!"}')
                    return
            else:
                username = req_data.get("username", "")
                if not username:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status":"error","message":"Vui long nhap ten tai khoan!"}')
                    return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","url":"/drop"}')
            return

        # Quit simulation
        if path in ["/api/portal/quit", "/api/quit"]:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            print("\n[*] Nhan tin hieu thoat tu Web UI. Dang dung server...")
            threading.Thread(target=self.server.shutdown).start()
            return

        # Un-quarantine toggle
        if path == "/api/host/unquarantine":
            fname = req_data.get('filename')
            if fname in UNQUARANTINED_FILES:
                UNQUARANTINED_FILES.remove(fname)
            else:
                UNQUARANTINED_FILES.add(fname)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        # User accounts CRUD
        if path == "/api/users/add":
            USER_ACCOUNTS.insert(0, req_data)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        if path == "/api/users/update":
            uname = req_data.get('username')
            for u in USER_ACCOUNTS:
                if u.get('username') == uname:
                    u['role'] = req_data.get('role', u['role'])
                    u['ttl'] = req_data.get('ttl', u['ttl'])
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        if path == "/api/users/delete":
            uname = req_data.get('username')
            USER_ACCOUNTS = [u for u in USER_ACCOUNTS if u.get('username') != uname]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        pass

def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    print("=" * 75)
    print("SLUG WEB ASSETS PREVIEWER & ENGINE SIMULATOR")
    print("=" * 75)
    print(f"[*] Dang tai template HTML truc tiep tu: {HPP_PATH}")
    print(f"[*] Dang khoi dong Web Server tai:       http://127.0.0.1:{PORT}")
    print(f"[*] Dia chi IP LAN cua may ban:          {LAN_IP}")
    print(f"[*] Thu muc goc workspace duoc browse:   {BASE_DIR}")
    print("[*] (Moi khi sua web_assets.hpp, chi can F5 tren trinh duyet la cap nhat)")
    print("=" * 75)

    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer(("127.0.0.1", PORT), PreviewHandler) as httpd:
            threading.Timer(0.6, lambda: webbrowser.open(f"http://127.0.0.1:{PORT}")).start()
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Da dung Web Server.")

if __name__ == "__main__":
    main()
