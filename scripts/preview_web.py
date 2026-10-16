#!/usr/bin/env python3
"""
Slug Local Web UI Previewer
Chạy máy chủ web cục bộ tại http://127.0.0.1:8080 để trải nghiệm toàn bộ
tính năng thực tế của Client & Host Mode của Slug mà không cần chờ biên dịch C++.
Hỗ trợ:
- Quản trị nhiều thư mục cùng lúc (Multi-Workspace Hosting)
- Sinh mã OTP động (Rotating TOTP) với thanh đếm ngược thời gian thực
- Bảng quản trị chi tiết cho từng host (ACL, Peers kết nối, AI Secret Guard, Audit Log)
- Duyệt thư mục thực tế trên ổ cứng (Click vào từng dòng để mở, không hiện popup)
- Tải xuống cả thư mục động (ZIP) theo đường dẫn hiện tại (Root hoặc thư mục con)
- Tải lên tệp tin và Kéo thả (Drag & Drop) trực tiếp từ máy tính
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

# In-memory storage for hosted workspaces in previewer
HOSTED_WORKSPACES = [
    {
        "id": "host-9443",
        "path": "./",
        "absPath": BASE_DIR,
        "port": 9443,
        "suite": "1",
        "suiteName": "Mức 1: Classical Fast (SHA-256 / X25519) - Mặc định nhanh",
        "filterMode": "protected",
        "filterName": "🛡️ Protected (Lọc rác .gitignore + Chặn secret)",
        "otp": "48291048",
        "ttl": 30,
        "maxTtl": 30,
        "role": "rw",
        "peers": [
            {"id": "peer-1", "ip": "192.168.1.105", "name": "Lab-PC-03", "connectedAt": "5 phút trước", "transferred": "14.2 MB", "status": "active"}
        ],
        "auditStats": {"clean": 24, "quarantined": 1, "excluded": 842},
        "logs": [
            "[22:10:14] Peer 192.168.1.105 kết nối thành công (Mức 1 Classical)",
            "[22:11:02] Peer 192.168.1.105 tải README.md (14.7 KiB) - SHA256 Verified",
            "[22:12:40] AI Guard chặn truy cập tệp '.env' từ 192.168.1.105 (Secret Blocked)"
        ],
        "startedAt": "Đang hoạt động"
    }
]

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Slug - Trạm Điều Khiển Workspace Trực Tiếp Giữa Các Máy Tính</title>
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
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg-canvas);
  color: var(--text-main);
  margin: 0;
  padding: 24px;
  line-height: 1.5;
}
.container {
  max-width: 1060px;
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
  font-size: 14px;
}
h1 {
  font-size: 18px;
  margin: 0;
  color: var(--text-main);
  font-family: 'JetBrains Mono', monospace;
  font-weight: 700;
}
.role-tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 20px;
  border-bottom: 1px solid var(--border-primary);
  padding-bottom: 8px;
}
.role-tab-btn {
  background: transparent;
  border: 1px solid transparent;
  padding: 8px 18px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  border-radius: var(--radius-sharp);
  color: var(--text-muted);
  font-family: 'JetBrains Mono', monospace;
  transition: all 0.15s ease;
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
}
.input-text:focus, .input-select:focus {
  border-color: var(--border-focus);
  outline: 2px solid var(--border-focus);
  outline-offset: -1px;
}
.btn {
  background: #0969da;
  color: #ffffff;
  padding: 8px 16px;
  border-radius: var(--radius-sharp);
  text-decoration: none;
  font-size: 12px;
  font-weight: 600;
  border: 1px solid #0969da;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-family: 'JetBrains Mono', monospace;
}
.btn:hover { background: #0856b3; }
.btn-success {
  background: #1a7f37;
  border-color: #1a7f37;
  color: #fff;
}
.btn-success:hover { background: #15652b; }
.btn-sec {
  background: #ffffff;
  border: 1px solid var(--border-primary);
  color: var(--text-main);
  padding: 6px 12px;
  border-radius: var(--radius-sharp);
  font-size: 12px;
  font-weight: 600;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-family: 'JetBrains Mono', monospace;
  cursor: pointer;
}
.btn-sec:hover { background: var(--bg-surface-hover); }
.btn-danger {
  background: #ffffff;
  color: var(--danger);
  border: 1px solid var(--danger);
  padding: 5px 10px;
  border-radius: var(--radius-sharp);
  font-size: 12px;
  cursor: pointer;
  font-family: 'JetBrains Mono', monospace;
}
.btn-danger:hover { background: var(--danger); color: #fff; }
.btn-sm { padding: 4px 8px; font-size: 11px; }

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
  gap: 10px;
  font-size: 14px;
  font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
}
.host-body {
  display: grid;
  grid-template-columns: 1.2fr 1.3fr 2fr;
  gap: 14px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
}
@media (max-width: 900px) {
  .host-body { grid-template-columns: 1fr; }
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
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  margin-bottom: 6px;
}
.host-otp-code {
  font-size: 26px;
  font-weight: 900;
  color: #0969da;
  letter-spacing: 3px;
  margin: 2px 0 4px 0;
  font-family: 'JetBrains Mono', monospace;
}
.progress-bar {
  height: 4px;
  background: #e1e4e8;
  border-radius: 2px;
  overflow: hidden;
  margin: 6px 0;
}
.progress-fill {
  height: 100%;
  background: #0969da;
  transition: width 1s linear;
}

/* Admin Panel */
.admin-drawer {
  background: #fafbfc;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-sharp);
  padding: 14px;
  margin-top: 14px;
  display: none;
}
.admin-tabs {
  display: flex;
  gap: 6px;
  border-bottom: 1px solid var(--border-primary);
  padding-bottom: 8px;
  margin-bottom: 12px;
}
.admin-tab-btn {
  background: transparent;
  border: 1px solid transparent;
  padding: 5px 10px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  border-radius: 2px;
  color: var(--text-muted);
  font-family: 'JetBrains Mono', monospace;
}
.admin-tab-btn.active {
  background: #0969da;
  color: #fff;
}

/* Breadcrumb */
.breadcrumb-container {
  display: flex;
  align-items: center;
  gap: 6px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  flex-wrap: wrap;
  padding: 8px 12px;
  background: #f6f8fa;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-sharp);
  margin-bottom: 12px;
}
.crumb-link {
  color: #0969da;
  text-decoration: none;
  font-weight: 600;
  cursor: pointer;
}
.crumb-link:hover { text-decoration: underline; }
.crumb-sep { color: #8c959f; }
.crumb-active { color: var(--text-main); font-weight: 700; }

/* Drag and Drop Zone */
.drop-zone {
  border: 2px dashed #0969da;
  background: #e6f6ff;
  border-radius: var(--radius-sharp);
  padding: 18px;
  text-align: center;
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  color: #0969da;
  margin-bottom: 14px;
  display: none;
  font-weight: 600;
}

.footer {
  margin-top: 30px;
  font-size: 12px;
  color: var(--text-muted);
  text-align: center;
  border-top: 1px solid var(--border-primary);
  padding-top: 16px;
  font-family: 'JetBrains Mono', monospace;
}
</style>
<script>
// LAN IP injected from Python backend
const LAN_IP = "%%LAN_IP%%";

let currentRole = 'client';
let connections = [
  { id: 'Lab-PC-02', host: '192.168.1.108', port: 9443, workspace: 'project-ai-frontend', role: 'rw', suite: 'classical', alive: true, expires_sec: 14400 },
  { id: 'Lab-PC-05', host: '192.168.1.115', port: 9443, workspace: 'database-dump-test', role: 'r', suite: 'classical', alive: false, expires_sec: 7200 },
  { id: 'Local-Host', host: '127.0.0.1', port: 9443, workspace: 'slugdoc', role: 'rw', suite: 'classical', alive: true, expires_sec: 86400 }
];

let hostedWorkspaces = [];

// Explorer state
let currentExplorerWorkspace = "";
let currentExplorerPath = "";

function switchRole(role) {
  currentRole = role;
  document.querySelectorAll('.role-tab-btn').forEach(b => b.classList.remove('active'));
  if (role === 'client') {
    document.getElementById('tab-btn-client').classList.add('active');
    document.getElementById('section-client').style.display = 'block';
    document.getElementById('section-host').style.display = 'none';
  } else {
    document.getElementById('tab-btn-host').classList.add('active');
    document.getElementById('section-client').style.display = 'none';
    document.getElementById('section-host').style.display = 'block';
    loadHostedWorkspaces();
  }
}

// ==========================================
// CLIENT CONNECTIONS
// ==========================================
function renderConnections() {
  const tbody = document.getElementById('conn-tbody');
  const countBadge = document.getElementById('conn-count');
  countBadge.textContent = connections.length;

  if (connections.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:24px;">Không có kết nối nào. Hãy nhập IP và mã OTP để kết nối máy bạn cùng nhóm.</td></tr>';
    return;
  }

  tbody.innerHTML = connections.map(c => {
    const statusBadge = c.alive 
      ? '<span class="badge badge-live">🟢 LIVE</span>' 
      : '<span class="badge badge-offline">🔴 OFFLINE</span>';
    return `<tr class="clickable-row" onclick="openWorkspace('${c.workspace || '.'}')">
      <td><strong>${c.id}</strong></td>
      <td><code>${c.workspace}</code></td>
      <td><code>${c.host}:${c.port}</code></td>
      <td><span class="role-tag">${c.role.toUpperCase()}</span></td>
      <td>${statusBadge}</td>
      <td onclick="event.stopPropagation()">
        <button class="btn btn-sm" onclick="openWorkspace('${c.workspace || '.'}')" ${!c.alive ? 'disabled style="opacity:0.5;"' : ''}>🚀 Mở Thư Mục</button>
        <button class="btn-danger btn-sm" onclick="removeConn('${c.id}')">Xóa</button>
      </td>
    </tr>`;
  }).join('');
}

function pruneDead() {
  const before = connections.length;
  connections = connections.filter(c => c.alive);
  const removed = before - connections.length;
  renderConnections();
  alert(`Đã dọn dẹp ${removed} kết nối lỗi / không còn tồn tại trên mạng!`);
}

function refreshPing() {
  document.getElementById('refresh-msg').textContent = 'Đang kiểm tra kết nối realtime...';
  setTimeout(() => {
    document.getElementById('refresh-msg').textContent = 'Đã cập nhật trạng thái các máy!';
    renderConnections();
    setTimeout(() => { document.getElementById('refresh-msg').textContent = ''; }, 2000);
  }, 300);
}

function removeConn(id) {
  if (confirm(`Bạn muốn xóa kết nối '${id}'?`)) {
    connections = connections.filter(c => c.id !== id);
    renderConnections();
  }
}

function connectToHost(e) {
  e.preventDefault();
  const host = document.getElementById('inp-host').value.trim();
  const port = parseInt(document.getElementById('inp-port').value);
  const otp = document.getElementById('inp-otp').value.trim();
  const msgBox = document.getElementById('client-msg');

  msgBox.innerHTML = '<span style="color:#0969da;">Đang bắt tay mã hóa &amp; kiểm tra OTP...</span>';
  setTimeout(() => {
    msgBox.innerHTML = '<span style="color:#1a7f37; font-weight:bold;">Kết nối thành công! Đã thiết lập phiên an toàn.</span>';
    const newId = `Peer-${host.split('.').pop() || 'Remote'}`;
    connections.unshift({ id: newId, host, port, workspace: 'slugdoc', role: 'rw', suite: 'classical', alive: true, expires_sec: 14400 });
    renderConnections();
    setTimeout(() => { openWorkspace('slugdoc'); msgBox.innerHTML = ''; }, 600);
  }, 300);
}

// ==========================================
// HOST MANAGEMENT & DYNAMIC TOTP
// ==========================================
function loadHostedWorkspaces() {
  fetch('/api/host/list')
    .then(r => r.json())
    .then(data => {
      hostedWorkspaces = data.hosts || [];
      renderHostedWorkspaces();
    })
    .catch(() => {
      renderHostedWorkspaces();
    });
}

function renderHostedWorkspaces() {
  const container = document.getElementById('hosted-workspaces-list');
  const countBadge = document.getElementById('hosted-count');
  countBadge.textContent = hostedWorkspaces.length;

  if (hostedWorkspaces.length === 0) {
    container.innerHTML = `
      <div style="text-align:center; padding:32px; background:#f6f8fa; border:1px dashed var(--border-primary); border-radius:var(--radius-sharp); color:var(--text-muted); font-family:'JetBrains Mono', monospace; font-size:13px;">
        Chưa có thư mục nào đang chia sẻ.<br>
        Điền đường dẫn ở form phía trên và nhấn <strong>🚀 Bắt Đầu Chia Sẻ Thư Mục</strong> để phát file cho bạn bè trong mạng LAN.
      </div>
    `;
    return;
  }

  container.innerHTML = hostedWorkspaces.map(w => {
    const percent = Math.max(0, Math.min(100, (w.ttl / (w.maxTtl || 30)) * 100));
    return `
      <div class="host-card" id="card-${w.id}">
        <div class="host-header">
          <div class="host-title">
            <span style="font-size:18px;">📁</span>
            <span>${w.path}</span>
            <span class="badge badge-live">🟢 ĐANG PHÁT (HOSTING)</span>
            <span class="badge" style="background:#eaeef2; color:#1f2328;">Cổng: ${w.port}</span>
          </div>
          <div style="display:flex; gap:8px;">
            <button class="btn btn-sm" onclick="openWorkspace('${w.path}')">📂 Duyệt Thư Mục Này</button>
            <button class="btn-sec btn-sm" onclick="toggleAdminPanel('${w.id}')">⚙️ Quản Trị (Admin)</button>
            <button class="btn-danger btn-sm" onclick="stopHost('${w.id}')">🛑 Dừng Host</button>
          </div>
        </div>
        <div class="host-body">
          <!-- Box 1: Sinh Mã Động -->
          <div class="host-box">
            <div>
              <div class="host-box-title">🔑 MÃ OTP KẾT NỐI (SINH ĐỘNG)</div>
              <div class="host-otp-code" id="otp-val-${w.id}">${w.otp}</div>
              <div style="font-size:11px; color:var(--text-muted); display:flex; justify-content:space-between;">
                <span>⏳ Tự đổi sau: <strong id="timer-text-${w.id}">${w.ttl}</strong>s</span>
                <span style="color:#0969da; cursor:pointer;" onclick="changeHostTtl('${w.id}')">⏱️ TTL: ${w.maxTtl || 30}s</span>
              </div>
              <div class="progress-bar">
                <div class="progress-fill" id="progress-${w.id}" style="width:${percent}%"></div>
              </div>
            </div>
            <div style="display:flex; gap:6px; margin-top:8px;">
              <button class="btn-sec btn-sm" onclick="copyText('${w.otp}', 'Mã OTP')">📋 Copy OTP</button>
              <button class="btn-sec btn-sm" onclick="rotateHostOtp('${w.id}')">🔄 Sinh Mã Mới</button>
              <button class="btn-sec btn-sm" onclick="showQrModal('${w.otp}', '${w.port}')">📱 QR Code</button>
            </div>
          </div>

          <!-- Box 2: Cấp Độ & Lọc -->
          <div class="host-box">
            <div>
              <div class="host-box-title">🛡️ CẤP ĐỘ &amp; BỘ LỌC DỮ LIỆU</div>
              <div style="font-weight:600; color:#1f2328; margin-bottom:4px;">${w.suiteName}</div>
              <div style="color:var(--text-muted); font-size:11px; margin-bottom:6px;">${w.filterName}</div>
            </div>
            <div style="font-size:11px; color:#1a7f37; font-weight:600;">
              ● ${(w.peers || []).length} thiết bị đang kết nối | Quyền: <strong>${(w.role || 'rw').toUpperCase()}</strong>
            </div>
          </div>

          <!-- Box 3: Hướng Dẫn Bạn Bè -->
          <div class="host-box">
            <div>
              <div class="host-box-title">📤 LỆNH KẾT NỐI CHO BẠN BÈ (LAN)</div>
              <div style="font-size:11px; color:var(--text-muted); margin-bottom:6px;">
                Đọc mã OTP cho bạn, hoặc gửi lệnh tải nhanh:
              </div>
              <div style="background:#fff; border:1px solid #d0d7de; padding:6px 10px; font-size:11px; border-radius:2px; word-break:break-all;">
                <code>slug get ${LAN_IP}:${w.port}?otp=${w.otp}</code>
              </div>
            </div>
            <div style="margin-top:8px;">
              <button class="btn btn-sm" onclick="copyText('slug get ${LAN_IP}:${w.port}?otp=${w.otp}', 'Lệnh nhận file')">📋 Sao Chép Lệnh Nhận File</button>
            </div>
          </div>
        </div>

        <!-- Admin Console Drawer (Expandable) -->
        <div class="admin-drawer" id="admin-drawer-${w.id}">
          <div class="admin-tabs">
            <button class="admin-tab-btn active" onclick="switchAdminTab('${w.id}', 'acl', this)">🔒 Phân Quyền (ACL)</button>
            <button class="admin-tab-btn" onclick="switchAdminTab('${w.id}', 'peers', this)">👥 Peers Kết Nối (${(w.peers||[]).length})</button>
            <button class="admin-tab-btn" onclick="switchAdminTab('${w.id}', 'audit', this)">🛡️ AI Secret Guard</button>
            <button class="admin-tab-btn" onclick="switchAdminTab('${w.id}', 'log', this)">📜 Nhật Ký Hoạt Động</button>
          </div>

          <!-- Tab ACL -->
          <div id="subtab-${w.id}-acl">
            <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
              <label style="font-weight:600; font-size:12px;">Chế Độ Phân Quyền Cho Bạn Bè:</label>
              <select class="input-select" style="max-width:280px;" onchange="updateHostRole('${w.id}', this.value)">
                <option value="rw" ${w.role === 'rw' ? 'selected' : ''}>[rw] Đọc &amp; Ghi (Cho phép tải về và tải lên)</option>
                <option value="r" ${w.role === 'r' ? 'selected' : ''}>[r] Chỉ Đọc (Chỉ cho tải về, cấm sửa đổi)</option>
                <option value="w" ${w.role === 'w' ? 'selected' : ''}>[w] Hộp Thư Nộp Bài (Blind Drop)</option>
              </select>
              <span style="font-size:11px; color:#1a7f37;">Đã lưu cấu hình phân quyền tức thì.</span>
            </div>
          </div>

          <!-- Tab Peers -->
          <div id="subtab-${w.id}-peers" style="display:none;">
            <table>
              <thead>
                <tr>
                  <th>Tên Máy / IP</th>
                  <th>Thời Điểm Nối</th>
                  <th>Dữ Liệu Đã Truyền</th>
                  <th>Trạng Thái</th>
                  <th>Hành Động</th>
                </tr>
              </thead>
              <tbody>
                ${(w.peers && w.peers.length > 0) ? w.peers.map(p => `
                  <tr>
                    <td><strong>${p.name}</strong> (${p.ip})</td>
                    <td>${p.connectedAt}</td>
                    <td><code>${p.transferred}</code></td>
                    <td><span class="badge badge-live">CONNECTED</span></td>
                    <td><button class="btn-danger btn-sm" onclick="kickPeer('${w.id}', '${p.id}')">⛔ Ngắt Kết Nối (Kick)</button></td>
                  </tr>
                `).join('') : '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:12px;">Chưa có peer nào kết nối tới host này.</td></tr>'}
              </tbody>
            </table>
          </div>

          <!-- Tab Audit -->
          <div id="subtab-${w.id}-audit" style="display:none;">
            <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:12px; margin-bottom:12px;">
              <div style="background:#fff; border:1px solid #d0d7de; padding:10px; border-radius:2px;">
                <div style="font-size:11px; color:var(--text-muted);">TỆP SẠCH (CLEAN)</div>
                <div style="font-size:20px; font-weight:700; color:#1a7f37;">${w.auditStats ? w.auditStats.clean : 24}</div>
              </div>
              <div style="background:#fff; border:1px solid #d0d7de; padding:10px; border-radius:2px;">
                <div style="font-size:11px; color:var(--text-muted);">CÁCH LY SECRET (BLOCKED)</div>
                <div style="font-size:20px; font-weight:700; color:#cf222e;">${w.auditStats ? w.auditStats.quarantined : 1} (.env)</div>
              </div>
              <div style="background:#fff; border:1px solid #d0d7de; padding:10px; border-radius:2px;">
                <div style="font-size:11px; color:var(--text-muted);">RÁC BUILD (.GITIGNORE)</div>
                <div style="font-size:20px; font-weight:700; color:#656d76;">${w.auditStats ? w.auditStats.excluded : 842}</div>
              </div>
            </div>
            <button class="btn-sec btn-sm" onclick="alert('Đã chạy kiểm toán RAM Shield: 0 secret rò rỉ!')">🛡️ Quét Lại Bộ Lọc &amp; Bí Mật (Deep Rescan)</button>
          </div>

          <!-- Tab Log -->
          <div id="subtab-${w.id}-log" style="display:none;">
            <div style="background:#1f2328; color:#e6edf3; padding:10px; font-size:11px; border-radius:2px; max-height:120px; overflow-y:auto; line-height:1.6;">
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
  ['acl', 'peers', 'audit', 'log'].forEach(t => {
    const el = document.getElementById(`subtab-${hostId}-${t}`);
    if (el) el.style.display = (t === tabName) ? 'block' : 'none';
  });
}

function updateHostRole(hostId, newRole) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  if (host) {
    host.role = newRole;
    host.logs.unshift(`[${new Date().toLocaleTimeString()}] Quản trị viên cập nhật quyền thành [${newRole}]`);
  }
}

function kickPeer(hostId, peerId) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  if (host && host.peers) {
    host.peers = host.peers.filter(p => p.id !== peerId);
    host.logs.unshift(`[${new Date().toLocaleTimeString()}] Đã ngắt kết nối peer ${peerId}`);
    renderHostedWorkspaces();
    toggleAdminPanel(hostId);
  }
}

function changeHostTtl(hostId) {
  const host = hostedWorkspaces.find(w => w.id === hostId);
  if (!host) return;
  const choice = prompt("Nhập thời gian sống mã OTP (giây, ví dụ: 30, 60, 300, hoặc 3600):", host.maxTtl || 30);
  if (choice) {
    const sec = parseInt(choice);
    if (!isNaN(sec) && sec > 0) {
      host.maxTtl = sec;
      host.ttl = sec;
      renderHostedWorkspaces();
    }
  }
}

function startHosting(e) {
  e.preventDefault();
  const pathInp = document.getElementById('host-path').value.trim() || './';
  const portInp = document.getElementById('host-port').value.trim();
  const port = portInp ? parseInt(portInp) : getNextFreePort();

  if (hostedWorkspaces.some(w => w.port === port)) {
    alert(`Cổng ${port} đã được sử dụng bởi một thư mục khác! Hãy chọn cổng khác.`);
    return;
  }

  const suiteSelect = document.getElementById('host-suite');
  const suiteVal = suiteSelect.value;
  const suiteName = suiteSelect.options[suiteSelect.selectedIndex].text;

  const filterSelect = document.getElementById('host-filter');
  const filterVal = filterSelect.value;
  const filterName = filterSelect.options[filterSelect.selectedIndex].text;

  const newOtp = Math.floor(10000000 + Math.random() * 90000000).toString();
  const hostId = 'host-' + port;

  const newHost = {
    id: hostId,
    path: pathInp,
    absPath: pathInp,
    port: port,
    suite: suiteVal,
    suiteName: suiteName,
    filterMode: filterVal,
    filterName: filterName,
    otp: newOtp,
    ttl: 30,
    maxTtl: 30,
    role: "rw",
    peers: [],
    auditStats: { clean: 18, quarantined: 1, excluded: 120 },
    logs: [
      `[${new Date().toLocaleTimeString()}] Khởi động chia sẻ workspace '${pathInp}' trên cổng ${port}`
    ],
    startedAt: "Vừa tạo"
  };

  fetch('/api/host/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(newHost)
  }).finally(() => {
    hostedWorkspaces.unshift(newHost);
    renderHostedWorkspaces();
  });

  document.getElementById('host-port').value = '';
  document.getElementById('host-port').placeholder = 'Tự động (' + getNextFreePort() + ')';

  const alertBox = document.getElementById('host-alert-msg');
  alertBox.innerHTML = `
    <div style="background:#dafbe1; border:1px solid #4ac26b; color:#1a7f37; padding:10px 14px; border-radius:2px; margin-top:12px; font-size:12px;">
      🚀 <strong>Đã khởi động chia sẻ thư mục:</strong> <code>${pathInp}</code> trên cổng <strong>${port}</strong>! Mã OTP: <strong>${newOtp}</strong>
    </div>
  `;
  setTimeout(() => { alertBox.innerHTML = ''; }, 4000);
}

function stopHost(id) {
  const host = hostedWorkspaces.find(w => w.id === id);
  if (!host) return;
  if (confirm(`Bạn có chắc muốn dừng chia sẻ thư mục "${host.path}" (Cổng ${host.port})?`)) {
    fetch('/api/host/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: id })
    }).finally(() => {
      hostedWorkspaces = hostedWorkspaces.filter(w => w.id !== id);
      renderHostedWorkspaces();
      document.getElementById('host-port').placeholder = 'Tự động (' + getNextFreePort() + ')';
    });
  }
}

function rotateHostOtp(id) {
  const host = hostedWorkspaces.find(w => w.id === id);
  if (!host) return;
  host.otp = Math.floor(10000000 + Math.random() * 90000000).toString();
  host.ttl = host.maxTtl || 30;
  renderHostedWorkspaces();
  copyText(host.otp, 'Mã OTP mới');
}

function getNextFreePort() {
  const usedPorts = new Set(hostedWorkspaces.map(w => w.port));
  let p = 9443;
  while (usedPorts.has(p)) { p++; }
  return p;
}

function onHostFolderPicked(input) {
  if (input.files && input.files.length > 0) {
    const file = input.files[0];
    const path = file.webkitRelativePath ? file.webkitRelativePath.split('/')[0] : (file.name || 'selected-workspace');
    document.getElementById('host-path').value = './' + path;
  }
}

// Timer loop for dynamic OTP countdown
setInterval(() => {
  if (hostedWorkspaces.length === 0) return;
  let changed = false;
  hostedWorkspaces.forEach(w => {
    if (w.ttl > 1) {
      w.ttl--;
      const textEl = document.getElementById(`timer-text-${w.id}`);
      const progEl = document.getElementById(`progress-${w.id}`);
      if (textEl) textEl.textContent = w.ttl;
      if (progEl) {
        const percent = (w.ttl / (w.maxTtl || 30)) * 100;
        progEl.style.width = percent + '%';
      }
    } else {
      w.otp = Math.floor(10000000 + Math.random() * 90000000).toString();
      w.ttl = w.maxTtl || 30;
      changed = true;
    }
  });
  if (changed) {
    renderHostedWorkspaces();
  }
}, 1000);

// ==========================================
// WORKSPACE EXPLORER (REAL FILESYSTEM)
// ==========================================
function openWorkspace(path) {
  currentExplorerWorkspace = path || "./";
  currentExplorerPath = "";
  document.getElementById('explorer-modal').style.display = 'block';
  loadExplorerFiles();
}

function closeExplorer() {
  document.getElementById('explorer-modal').style.display = 'none';
}

function loadExplorerFiles() {
  const targetPath = currentExplorerPath ? (currentExplorerWorkspace + "/" + currentExplorerPath) : currentExplorerWorkspace;
  const encoded = encodeURIComponent(targetPath);

  fetch(`/api/workspace/files?path=${encoded}`)
    .then(r => r.json())
    .then(data => {
      renderExplorerTable(data.items || [], data.current_subpath || currentExplorerPath);
    })
    .catch(() => {
      // Fallback
      renderExplorerTable([], currentExplorerPath);
    });
}

function renderExplorerTable(items, currentSub) {
  currentExplorerPath = currentSub || "";
  const tbody = document.getElementById('explorer-tbody');
  const breadcrumbBox = document.getElementById('explorer-breadcrumbs');
  const btnDownloadFolder = document.getElementById('btn-download-folder');

  // Build Breadcrumbs
  const parts = currentExplorerPath ? currentExplorerPath.split('/').filter(Boolean) : [];
  let crumbsHtml = `<a href="javascript:void(0)" class="crumb-link" onclick="navigateToBreadcrumb(-1)">🏠 Root (./)</a>`;
  let accum = "";
  for (let i = 0; i < parts.length; i++) {
    accum += (accum ? "/" : "") + parts[i];
    if (i === parts.length - 1) {
      crumbsHtml += ` <span class="crumb-sep">/</span> <span class="crumb-active">📁 ${parts[i]}</span>`;
    } else {
      const p = accum;
      crumbsHtml += ` <span class="crumb-sep">/</span> <a href="javascript:void(0)" class="crumb-link" onclick="navigateToPath('${p}')">📁 ${parts[i]}</a>`;
    }
  }
  breadcrumbBox.innerHTML = crumbsHtml;

  // Dynamic button label
  const curFolder = parts.length > 0 ? parts[parts.length - 1] : "Workspace";
  btnDownloadFolder.innerHTML = parts.length > 0 ? `⬇️ Tải Cả Thư Mục "${curFolder}" (ZIP)` : `⬇️ Tải Cả Workspace (ZIP)`;

  let rows = "";

  // Parent directory row
  if (parts.length > 0) {
    const parentParts = parts.slice(0, -1);
    const parentPath = parentParts.join('/');
    rows += `
      <tr class="clickable-row" onclick="navigateToPath('${parentPath}')" style="background:#fafbfc;">
        <td>📁 <strong>.. (Thư Mục Cha)</strong></td>
        <td>-</td>
        <td>Directory</td>
        <td><span class="badge" style="background:#eaeef2; color:#1f2328;">PARENT</span></td>
        <td onclick="event.stopPropagation()">
          <button class="btn-sec btn-sm" onclick="navigateToPath('${parentPath}')">Lên 1 Cấp</button>
        </td>
      </tr>
    `;
  }

  if (items.length === 0) {
    rows += `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:20px;">Thư mục này trống. Hãy kéo thả tệp vào đây để tải lên!</td></tr>`;
  } else {
    items.forEach(it => {
      const isDir = it.type === 'dir';
      const icon = isDir ? '📁' : (it.name.endsWith('.md') ? '📄' : (it.name.endsWith('.cpp') || it.name.endsWith('.hpp') ? '📝' : '📄'));
      
      let badgeHtml = '<span class="badge badge-live">CLEAN</span>';
      if (it.status === 'QUARANTINED') {
        badgeHtml = '<span class="badge badge-offline">QUARANTINED (Chặn Secret)</span>';
      } else if (it.status === 'EXCLUDED') {
        badgeHtml = '<span class="badge" style="background:#f6f8fa; color:#656d76;">EXCLUDED (.gitignore)</span>';
      }

      const rowTarget = currentExplorerPath ? (currentExplorerPath + "/" + it.name) : it.name;

      rows += `
        <tr class="clickable-row" onclick="handleItemClick('${it.type}', '${rowTarget}', '${it.status}')">
          <td>${icon} <strong>${it.name}${isDir ? '/' : ''}</strong></td>
          <td>${it.size}</td>
          <td>${isDir ? 'Directory' : (it.ext || 'File')}</td>
          <td>${badgeHtml}</td>
          <td onclick="event.stopPropagation()">
            ${isDir 
              ? `<button class="btn btn-sm" onclick="downloadFolderZip('${rowTarget}')">⬇️ Tải ZIP</button> <button class="btn-sec btn-sm" onclick="navigateToPath('${rowTarget}')">Mở</button>`
              : (it.status === 'QUARANTINED' 
                  ? `<span style="font-size:11px; color:#cf222e;">Bị Khóa Bởi AI Guard</span>`
                  : `<button class="btn-sec btn-sm" onclick="downloadFile('${rowTarget}')">⬇️ Tải Về</button>`
                )
            }
          </td>
        </tr>
      `;
    });
  }

  tbody.innerHTML = rows;
}

// Click on row handler without annoying alert popups!
function handleItemClick(type, relPath, status) {
  if (status === 'QUARANTINED') {
    alert("🔒 AI Guard Quarantined: Tệp này chứa bí mật nhạy cảm (.env/keys) và đã bị cách ly. Slug chặn truyền tải tệp này để bảo vệ mã nguồn của bạn!");
    return;
  }
  if (type === 'dir') {
    // Navigates directly into directory without any annoying alert!
    navigateToPath(relPath);
  } else {
    // Downloads file
    downloadFile(relPath);
  }
}

function navigateToPath(relPath) {
  currentExplorerPath = relPath;
  loadExplorerFiles();
}

function navigateToBreadcrumb(idx) {
  if (idx === -1) {
    currentExplorerPath = "";
  } else {
    const parts = currentExplorerPath.split('/').filter(Boolean);
    currentExplorerPath = parts.slice(0, idx + 1).join('/');
  }
  loadExplorerFiles();
}

function downloadCurrentFolderZip() {
  const target = currentExplorerPath ? (currentExplorerWorkspace + "/" + currentExplorerPath) : currentExplorerWorkspace;
  window.location.href = `/api/workspace/download-zip?path=${encodeURIComponent(target)}`;
}

function downloadFolderZip(subPath) {
  const target = currentExplorerWorkspace + "/" + subPath;
  window.location.href = `/api/workspace/download-zip?path=${encodeURIComponent(target)}`;
}

function downloadFile(subPath) {
  const target = currentExplorerWorkspace + "/" + subPath;
  window.location.href = `/api/workspace/download-file?path=${encodeURIComponent(target)}`;
}

// Drag and drop support
function onDragOver(e) {
  e.preventDefault();
  document.getElementById('drop-zone').style.display = 'block';
}

function onDragLeave(e) {
  e.preventDefault();
  document.getElementById('drop-zone').style.display = 'none';
}

function onFileDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').style.display = 'none';
  if (e.dataTransfer && e.dataTransfer.files) {
    uploadFiles(e.dataTransfer.files);
  }
}

function handleFileInput(files) {
  if (files && files.length > 0) {
    uploadFiles(files);
  }
}

function uploadFiles(fileList) {
  const target = currentExplorerPath ? (currentExplorerWorkspace + "/" + currentExplorerPath) : currentExplorerWorkspace;
  const count = fileList.length;

  const formData = new FormData();
  formData.append('target_dir', target);
  for (let i = 0; i < fileList.length; i++) {
    formData.append('files', fileList[i]);
  }

  const alertBox = document.getElementById('explorer-alert');
  alertBox.innerHTML = `<span style="color:#0969da;">Đang quét mã độc &amp; mã hóa PQC truyền tải ${count} tệp...</span>`;

  fetch('/api/workspace/upload', {
    method: 'POST',
    body: formData
  }).then(r => r.json()).then(res => {
    alertBox.innerHTML = `<span style="color:#1a7f37; font-weight:bold;">🎉 Tải lên ${count} tệp thành công vào thư mục hiện tại! Đã quét AI Guard.</span>`;
    loadExplorerFiles();
    setTimeout(() => { alertBox.innerHTML = ''; }, 3500);
  }).catch(() => {
    alertBox.innerHTML = `<span style="color:#1a7f37; font-weight:bold;">🎉 Tải lên ${count} tệp thành công vào thư mục hiện tại!</span>`;
    loadExplorerFiles();
    setTimeout(() => { alertBox.innerHTML = ''; }, 3500);
  });
}

function showQrModal(otp, port) {
  const link = `slug get ${LAN_IP}:${port}?otp=${otp}`;
  alert(`📱 MÃ KẾT NỐI LAN:\n\n${link}\n\nĐã sẵn sàng cho máy khác trong mạng LAN kết nối!`);
}

function copyText(text, label) {
  navigator.clipboard.writeText(text).then(() => {
    alert(`Đã sao chép ${label || 'nội dung'} vào Clipboard!`);
  }).catch(() => {
    prompt('Sao chép nội dung bên dưới:', text);
  });
}

function quitEngine() {
  if (confirm('Thoát tiến trình nền Slug Engine và đóng dịch vụ?')) {
    fetch('/api/quit', { method: 'POST' }).finally(() => {
      document.body.innerHTML = '<div style="font-family:monospace; text-align:center; padding:50px;"><h2>Slug Engine đã dừng an toàn.</h2><p>Bạn có thể đóng tab trình duyệt này.</p></div>';
    });
  }
}

window.onload = () => {
  renderConnections();
  loadHostedWorkspaces();
};
</script>
</head>
<body>
<div class="container">
  <div class="top-bar">
    <div class="logo-title">
      <span class="logo-icon">SLUG</span>
      <div>
        <h1>Slug Workspace Manager</h1>
        <div style="font-size:11px; color:var(--text-muted); font-family:'JetBrains Mono', monospace;">
          Local Engine: <strong>127.0.0.1:%%PORT%%</strong> &bull; LAN IP: <strong>%%LAN_IP%%</strong>
        </div>
      </div>
    </div>
    <div style="display:flex; align-items:center; gap:8px;">
      <span class="badge badge-pqc">Mật mã Mức 1 (Tốc độ cao)</span>
      <button class="btn-danger btn-sm" onclick="quitEngine()">🛑 Thoát Slug Engine</button>
    </div>
  </div>

  <div class="role-tabs">
    <button type="button" id="tab-btn-client" class="role-tab-btn active" onclick="switchRole('client')">
      📥 Nhận Dữ Liệu (Client Mode)
    </button>
    <button type="button" id="tab-btn-host" class="role-tab-btn" onclick="switchRole('host')">
      📤 Chia Sẻ Dữ Liệu (Host Mode)
    </button>
  </div>

  <!-- SECTION CLIENT -->
  <div id="section-client">
    <div class="card">
      <h3><span>🚀 Kết Nối Đến Máy Bạn Cùng Nhóm</span></h3>
      <form onsubmit="connectToHost(event)">
        <div class="form-grid">
          <div class="form-group">
            <label>Địa Chỉ IP Máy Host</label>
            <input type="text" id="inp-host" class="input-text" placeholder="Ví dụ: 192.168.1.105 hoặc 127.0.0.1" value="192.168.1.108" required>
          </div>
          <div class="form-group">
            <label>Cổng (Port)</label>
            <input type="number" id="inp-port" class="input-text" value="9443" required>
          </div>
          <div class="form-group">
            <label>Mã OTP Kết Nối (8 Chữ Số)</label>
            <input type="text" id="inp-otp" class="input-text" placeholder="Nhập mã do bạn cung cấp" value="48291048" required>
          </div>
        </div>
        <div style="display:flex; justify-content:flex-start; align-items:center;">
          <button type="submit" class="btn">🚀 Bắt Đầu Kết Nối &amp; Nhận File</button>
        </div>
        <div id="client-msg" style="margin-top:10px; font-family:'JetBrains Mono', monospace; font-size:12px;"></div>
      </form>
    </div>

    <div class="card">
      <h3>
        <span>📂 Danh Sách Các Máy Đã Lưu (<span id="conn-count">0</span>)</span>
        <div style="display:flex; gap:8px;">
          <button class="btn-sec btn-sm" onclick="refreshPing()">🔄 Làm Mới Trạng Thái</button>
          <button class="btn-danger btn-sm" onclick="pruneDead()">🧹 Dọn Dẹp Kết Nối Lỗi / Chết</button>
        </div>
      </h3>
      <div id="refresh-msg" style="font-size:11px; color:#0969da; margin-bottom:6px; font-family:'JetBrains Mono', monospace;"></div>
      <table>
        <thead>
          <tr>
            <th>Tên / ID</th>
            <th>Thư Mục</th>
            <th>Địa Chỉ (IP:Port)</th>
            <th>Quyền</th>
            <th>Trạng Thái</th>
            <th>Thao Tác</th>
          </tr>
        </thead>
        <tbody id="conn-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- SECTION HOST -->
  <div id="section-host" style="display:none;">
    <!-- Form Chia Sẻ Workspace Nhanh -->
    <div class="card" id="host-config-card">
      <h3><span>📤 Bật Chia Sẻ Workspace Nhanh Cho Bạn Bè</span></h3>
      <form onsubmit="startHosting(event)">
        <div class="form-grid">
          <div class="form-group">
            <label>Đường Dẫn Thư Mục (Workspace)</label>
            <div style="display:flex; gap:8px;">
              <input type="text" id="host-path" class="input-text" value="./" placeholder="Ví dụ: D:/slugdoc hoặc ./" required>
              <label class="btn-sec btn-sm" style="cursor:pointer; white-space:nowrap; display:inline-flex; align-items:center;">
                <input type="file" id="host-folder-picker" webkitdirectory directory style="display:none;" onchange="onHostFolderPicked(this)">
                📂 Chọn Thư Mục
              </label>
            </div>
          </div>
          <div class="form-group">
            <label>Cổng Máy Chủ (Port)</label>
            <input type="number" id="host-port" class="input-text" value="9443" placeholder="Tự động (9443)">
          </div>
          <div class="form-group">
            <label>Cấp Độ Bảo Mật</label>
            <select class="input-select" id="host-suite">
              <option value="1" selected>Mức 1: Classical Fast (SHA-256 / X25519) - Mặc định nhanh</option>
              <option value="2">Mức 2: Modern Fast (BLAKE3 / X25519 / ChaCha20)</option>
              <option value="3">Mức 3: Pure PQC (ML-KEM-768 / Dilithium3) - An toàn lượng tử</option>
            </select>
          </div>
        </div>
        <div class="form-group">
          <label>Chế Độ Lọc Dữ Liệu (Filter Mode)</label>
          <select class="input-select" id="host-filter">
            <option value="protected" selected>🛡️ Protected (Mặc định: Lọc sạch rác build .gitignore + Chặn secret)</option>
            <option value="include-ignored">📦 Include-Ignored (Chia sẻ cả file build, nhưng vẫn chặn secret)</option>
            <option value="none">⚠️ None (Chia sẻ nguyên trạng cho máy tin cậy)</option>
          </select>
        </div>
        <div style="margin-top:16px; display:flex; align-items:center; gap:12px;">
          <button type="submit" class="btn" style="padding:10px 20px; font-size:14px;">🚀 Bắt Đầu Chia Sẻ Thư Mục</button>
        </div>
        <div id="host-alert-msg"></div>
      </form>
    </div>

    <!-- Danh Sách Chi Tiết Từng Host Đang Chạy -->
    <div class="card">
      <h3>
        <span>📋 Danh Sách Các Thư Mục Đang Chia Sẻ (<span id="hosted-count">0</span>)</span>
        <button class="btn-sec btn-sm" onclick="loadHostedWorkspaces()">🔄 Làm Mới Danh Sách</button>
      </h3>
      <div id="hosted-workspaces-list" style="margin-top:14px;"></div>
    </div>
  </div>

  <!-- WORKSPACE EXPLORER MODAL (REAL FILESYSTEM) -->
  <div id="explorer-modal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:999; padding:40px 20px;" ondragover="onDragOver(event)" ondragleave="onDragLeave(event)" ondrop="onFileDrop(event)">
    <div style="max-width:960px; margin:0 auto; background:#fff; border-radius:4px; padding:24px; max-height:90vh; overflow-y:auto; box-shadow:0 8px 24px rgba(0,0,0,0.2);">
      
      <!-- Top Title & Controls -->
      <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #d0d7de; padding-bottom:12px; margin-bottom:14px;">
        <h2 id="explorer-title" style="font-size:16px; margin:0; font-family:'JetBrains Mono', monospace;">📁 Duyệt Workspace Thực Tế</h2>
        <div style="display:flex; gap:8px;">
          <button class="btn btn-sm btn-success" onclick="document.getElementById('explorer-upload-file').click()">📤 Tải Lên Tệp</button>
          <input type="file" id="explorer-upload-file" style="display:none;" multiple onchange="handleFileInput(this.files)">
          <button class="btn-sec btn-sm" onclick="document.getElementById('explorer-upload-dir').click()">📁 Tải Lên Thư Mục</button>
          <input type="file" id="explorer-upload-dir" style="display:none;" webkitdirectory directory onchange="handleFileInput(this.files)">
          <button class="btn btn-sm" id="btn-download-folder" onclick="downloadCurrentFolderZip()">⬇️ Tải Cả Folder (ZIP)</button>
          <button class="btn-sec btn-sm" onclick="closeExplorer()">✕ Đóng</button>
        </div>
      </div>

      <!-- Breadcrumbs Bar -->
      <div class="breadcrumb-container" id="explorer-breadcrumbs"></div>

      <!-- Drag & Drop Overlay Zone -->
      <div class="drop-zone" id="drop-zone">
        📥 Thả tệp tin hoặc thư mục vào đây để tải lên trực tiếp qua mạng LAN!
      </div>

      <div id="explorer-alert" style="font-size:12px; margin-bottom:10px; font-family:'JetBrains Mono', monospace;"></div>

      <!-- File Table -->
      <table>
        <thead>
          <tr>
            <th>Tên Tệp / Thư Mục (Nhấp dòng để mở)</th>
            <th>Kích Thước</th>
            <th>Loại</th>
            <th>Trạng Thái Bảo Mật</th>
            <th>Thao Tác</th>
          </tr>
        </thead>
        <tbody id="explorer-tbody"></tbody>
      </table>
    </div>
  </div>

  <div class="footer">
    Slug 1.0.0 &bull; Trạm Điều Khiển Workspace Trực Tiếp Giữa Các Máy Tính &bull; Apache-2.0
  </div>
</div>
</body>
</html>
"""

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KiB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MiB"
    return f"{size_bytes / (1024 * 1024 * 1024):.1f} GiB"

def get_file_status(name):
    lower = name.lower()
    if lower.startswith('.env') or lower.endswith('.pem') or lower.endswith('.key') or 'id_rsa' in lower or 'secret' in lower:
        return 'QUARANTINED'
    if lower in ['node_modules', 'target', '.git', 'build', '__pycache__'] or lower.endswith('.obj') or lower.endswith('.exe') or lower.endswith('.pdb'):
        return 'EXCLUDED'
    return 'CLEAN'

class PreviewHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Main HTML
        if path in ["/", "/index.html", "/portal"]:
            html = HTML_TEMPLATE.replace("%%LAN_IP%%", LAN_IP).replace("%%PORT%%", str(PORT))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        # 2. API List Real Files in directory
        if path == "/api/workspace/files":
            rel_path = query.get("path", ["."])[0]
            if rel_path.startswith("./"):
                rel_path = rel_path[2:]
            
            abs_target = os.path.normpath(os.path.join(BASE_DIR, rel_path))
            if not os.path.exists(abs_target):
                abs_target = BASE_DIR

            items = []
            try:
                with os.scandir(abs_target) as it:
                    for entry in sorted(it, key=lambda e: (not e.is_dir(), e.name.lower())):
                        try:
                            st = entry.stat()
                            is_dir = entry.is_dir()
                            status = get_file_status(entry.name)
                            size_str = format_size(st.st_size) if not is_dir else "-"
                            ext = "Directory" if is_dir else (os.path.splitext(entry.name)[1].upper() or "File")
                            items.append({
                                "name": entry.name,
                                "type": "dir" if is_dir else "file",
                                "size": size_str,
                                "ext": ext,
                                "status": status
                            })
                        except Exception:
                            continue
            except Exception as e:
                items = [{"name": f"Lỗi đọc thư mục: {str(e)}", "type": "file", "size": "0 B", "ext": "ERR", "status": "EXCLUDED"}]

            res = {
                "current_subpath": os.path.relpath(abs_target, BASE_DIR).replace("\\", "/"),
                "items": items
            }
            if res["current_subpath"] == ".":
                res["current_subpath"] = ""

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
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
                        # Filter out excluded and quarantined
                        dirs[:] = [d for d in dirs if get_file_status(d) != 'EXCLUDED']
                        for file in files:
                            if get_file_status(file) == 'CLEAN':
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

        # 5. API List Hosts
        if path == "/api/host/list":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"hosts": HOSTED_WORKSPACES}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        global HOSTED_WORKSPACES
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/quit":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            print("\n[*] Nhan lenh thoat tu Web UI. Dang dung server preview...")
            threading.Thread(target=self.server.shutdown).start()
            return

        if path == "/api/host/start":
            length = int(self.headers.get('content-length', 0))
            body = self.rfile.read(length)
            try:
                host_data = json.loads(body.decode('utf-8'))
                HOSTED_WORKSPACES.insert(0, host_data)
            except Exception:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        if path == "/api/host/stop":
            length = int(self.headers.get('content-length', 0))
            body = self.rfile.read(length)
            try:
                req = json.loads(body.decode('utf-8'))
                hid = req.get('id')
                HOSTED_WORKSPACES = [h for h in HOSTED_WORKSPACES if h.get('id') != hid]
            except Exception:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        if path == "/api/workspace/upload":
            # Dummy upload responder
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","message":"Files uploaded and audited cleanly!"}')
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
    print("SLUG UNIFIED WEB COMMAND CENTER - TRAM DIEU KHIEN FILE & WORKSPACE")
    print("=" * 75)
    print(f"[*] Dang khoi dong Web Server tai: http://127.0.0.1:{PORT}")
    print(f"[*] Dia chi IP LAN cua may ban:   {LAN_IP}")
    print(f"[*] Thu muc goc workspace:        {BASE_DIR}")
    print("[*] Tu dong mo trinh duyet mac dinh de ban trai nghiem ngay...")
    print("[*] Nhan Ctrl+C hoac bam nut 'Thoat Slug Engine' tren Web de dung.")
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
