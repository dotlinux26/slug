<#
.SYNOPSIS
    Slug EnvShield Automated Showcase Generator (Windows PowerShell)
.DESCRIPTION
    Tự động tạo ra một thư mục dự án mẫu 'demo_env_workspace' tại thư mục hiện tại
    để mô phỏng tính năng niêm phong .env hậu lượng tử (ML-KEM-1024) và AI Directive.
    Tất cả các secret, token, mật khẩu được sinh ngẫu nhiên 100% tại thời điểm chạy
    để tránh bị bot của GitHub quét nhầm.
#>

$ErrorActionPreference = "Stop"

Write-Host "`n+----------------------------------------------------------------------------+" -ForegroundColor Cyan
Write-Host "|   SLUG ENVSHIELD - SHOWCASE GENERATOR (POST-QUANTUM .ENV PROTECTION)       |" -ForegroundColor Cyan
Write-Host "+----------------------------------------------------------------------------+" -ForegroundColor Cyan

$targetDir = Join-Path (Get-Location) "demo_env_workspace"

if (Test-Path $targetDir) {
    Write-Host "[!] Thu muc 'demo_env_workspace' da ton tai. Dang xoa de lam moi..." -ForegroundColor Yellow
    Remove-Item -Path $targetDir -Recurse -Force
}

New-Item -ItemType Directory -Path $targetDir | Out-Null
Write-Host "[+] Da tao thu muc demo: $targetDir" -ForegroundColor Green

# 1. Sinh ngau nhien cac khoa bi mat (Dynamic generation - tranh trigger bot GitHub)
$randDbPass = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 24 | ForEach-Object {[char]$_})
$randStripe = "demo_stripe_" + ([System.Guid]::NewGuid().ToString("N"))
$randAiToken = "slug_tok_" + ([System.Guid]::NewGuid().ToString("N"))
$randJwtSecret = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})

# 2. Tao file .env dong
$envContent = @"
# ==============================================================================
# SENSITIVE ENVIRONMENT VARIABLES (AUTOMATICALLY GENERATED FOR DEMO)
# ==============================================================================
DATABASE_URL=postgresql://postgres:$randDbPass@127.0.0.1:5432/production_app
STRIPE_API_KEY=$randStripe
AI_MODEL_TOKEN=$randAiToken
JWT_SECRET=$randJwtSecret
PORT=8000
APP_ENV=production
"@

$envPath = Join-Path $targetDir ".env"
[System.IO.File]::WriteAllText($envPath, $envContent, [System.Text.Encoding]::UTF8)
Write-Host "[+] Da tao file .env gia lap voi secret dong ngau nhien." -ForegroundColor Green

# 3. Tao file ung dung Python test (Zero-dependency - khong can thu vien ngoai)
$appPyContent = @'
import os
import sys

print("\n" + "=" * 70)
print("  UNG DUNG DEMO (PYTHON ZERO-DEPENDENCY PROCESS)")
print("=" * 70)
print("[*] Tien trinh he dieu hanh PID: " + str(os.getpid()))
print("[*] Doc bien moi truong truc tiep tu OS Memory (os.environ)...")

db = os.getenv("DATABASE_URL")
api_key = os.getenv("STRIPE_API_KEY")
token = os.getenv("AI_MODEL_TOKEN")
jwt_sec = os.getenv("JWT_SECRET")

if not db or not api_key or not token:
    print("\n[-] THAT BAI: Khong tim thay bien moi truong trong RAM!")
    print("    Tren o dia khong co file .env (hoac chua duoc nap). Ung dung bi crash.")
    print("=" * 70 + "\n")
    sys.exit(1)

print("\n[SUCCESS] Ket noi Database thanh cong: " + db[:28] + "...")
print("[SUCCESS] Stripe Payment Engine Ready: " + api_key[:22] + "...")
print("[SUCCESS] AI Engine Token Loaded:      " + token[:20] + "...")
print("[SUCCESS] JWT Authentication Secret:   " + jwt_sec[:16] + "...")
print("[+] Ung dung khoi dong thanh cong 100% tren cong: " + os.getenv("PORT", "8000"))
print("=" * 70 + "\n")
'@

$appPyPath = Join-Path $targetDir "app.py"
[System.IO.File]::WriteAllText($appPyPath, $appPyContent, [System.Text.Encoding]::UTF8)
Write-Host "[+] Da tao file ung dung mau: app.py" -ForegroundColor Green

# 4. Tao script run_demo.ps1 huong dan tung buoc
$runDemoContent = @'
Write-Host "`n+----------------------------------------------------------------------------+" -ForegroundColor Yellow
Write-Host "|   KICH BAN KIEM THU SLUG ENVSHIELD (5 BUOC THUC TE)                         |" -ForegroundColor Yellow
Write-Host "+----------------------------------------------------------------------------+" -ForegroundColor Yellow

Write-Host "`n[BUOC 1] Kiem tra xem slug co san tren may khong..." -ForegroundColor Cyan
if (-not (Get-Command slug -ErrorAction SilentlyContinue)) {
    Write-Host "[-] Canh bao: 'slug' chua co trong PATH. Hay build slug hoac copy slug.exe vao thu muc nay." -ForegroundColor Red
} else {
    Write-Host "[+] Tim thay Slug CLI san sang!" -ForegroundColor Green
}

Write-Host "`n[BUOC 2] Chay thu khi .env con o dang plaintext (Trang thai truyen thong):" -ForegroundColor Cyan
Write-Host "  > python app.py" -ForegroundColor Gray
python app.py

Write-Host "`n[BUOC 3] Chu dong Niem Phong .env bang Slug EnvShield:" -ForegroundColor Cyan
Write-Host "  > slug env init" -ForegroundColor Gray
slug env init

Write-Host "`nKiem tra file trong thu muc:" -ForegroundColor Cyan
Get-ChildItem -Force | Select-Object Name, Length

Write-Host "`n[BUOC 4] Thu chay lai bang python thuong (Khong co .env plaintext tren dia):" -ForegroundColor Cyan
Write-Host "  > python app.py" -ForegroundColor Gray
try { python app.py } catch {}

Write-Host "`n[BUOC 5] Chay an toan qua Slug EnvShield (In-RAM Decryption & Injected Process):" -ForegroundColor Cyan
Write-Host "  > slug env run -- python app.py" -ForegroundColor Gray
slug env run -- python app.py

Write-Host "`n[BUOC 6] Xem lich su backup tren Central Vault (~/.slug/env_vault/):" -ForegroundColor Cyan
Write-Host "  > slug env history" -ForegroundColor Gray
slug env history

Write-Host "`n[BUOC 7] Khi can phuc hoi .env truyen thong (1-touch restore):" -ForegroundColor Cyan
Write-Host "  > slug env restore" -ForegroundColor Gray
'@

$runDemoPath = Join-Path $targetDir "run_demo.ps1"
[System.IO.File]::WriteAllText($runDemoPath, $runDemoContent, [System.Text.Encoding]::UTF8)
Write-Host "[+] Da tao script huong dan test: run_demo.ps1" -ForegroundColor Green

Write-Host "`n>>> KHOI TAO THANH CONG! <<<" -ForegroundColor Green
Write-Host "Cach su dung ngay bay gio:" -ForegroundColor White
Write-Host "  cd demo_env_workspace" -ForegroundColor Cyan
Write-Host "  powershell -ExecutionPolicy Bypass -File .\run_demo.ps1`n" -ForegroundColor Cyan
