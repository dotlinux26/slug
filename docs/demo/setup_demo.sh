#!/usr/bin/env bash
# ==============================================================================
# Slug EnvShield Automated Showcase Generator (Linux / macOS)
# ==============================================================================
# Tự động tạo thư mục 'demo_env_workspace' để mô phỏng tính năng niêm phong .env
# hậu lượng tử (ML-KEM-1024) và AI Directive. Tất cả secrets được sinh ngẫu nhiên
# 100% tại runtime để tránh trigger bot quét mã của GitHub.
# ==============================================================================

set -euo pipefail

echo -e "\033[1;36m"
echo "+----------------------------------------------------------------------------+"
echo "|   SLUG ENVSHIELD - SHOWCASE GENERATOR (POST-QUANTUM .ENV PROTECTION)       |"
echo "+----------------------------------------------------------------------------+"
echo -e "\033[0m"

TARGET_DIR="$(pwd)/demo_env_workspace"

if [ -d "$TARGET_DIR" ]; then
    echo -e "\033[1;33m[!] Thư mục 'demo_env_workspace' đã tồn tại. Đang làm mới...\033[0m"
    rm -rf "$TARGET_DIR"
fi

mkdir -p "$TARGET_DIR"
echo -e "\033[1;32m[+] Đã tạo thư mục demo: $TARGET_DIR\033[0m"

# 1. Sinh ngẫu nhiên các khóa bí mật (Dynamic generation - không chứa pattern tĩnh)
gen_hex() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$1"
    else
        head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

RAND_DB_PASS="$(gen_hex 16)"
RAND_STRIPE="demo_stripe_$(gen_hex 16)"
RAND_AI_TOKEN="slug_tok_$(gen_hex 16)"
RAND_JWT_SECRET="$(gen_hex 24)"

# 2. Tạo file .env động
cat <<EOF > "$TARGET_DIR/.env"
# ==============================================================================
# SENSITIVE ENVIRONMENT VARIABLES (AUTOMATICALLY GENERATED FOR DEMO)
# ==============================================================================
DATABASE_URL=postgresql://postgres:${RAND_DB_PASS}@127.0.0.1:5432/production_app
STRIPE_API_KEY=${RAND_STRIPE}
AI_MODEL_TOKEN=${RAND_AI_TOKEN}
JWT_SECRET=${RAND_JWT_SECRET}
PORT=8000
APP_ENV=production
EOF
echo -e "\033[1;32m[+] Đã tạo file .env với secret động ngẫu nhiên.\033[0m"

# 3. Tạo file ứng dụng Python test (Zero-dependency - không cần thư viện ngoài)
cat <<'EOF' > "$TARGET_DIR/app.py"
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
EOF
echo -e "\033[1;32m[+] Đã tạo file ứng dụng mẫu: app.py\033[0m"

# 4. Tạo script run_demo.sh
cat <<'EOF' > "$TARGET_DIR/run_demo.sh"
#!/usr/bin/env bash
set -e

echo -e "\033[1;33m"
echo "+----------------------------------------------------------------------------+"
echo "|   KICH BAN KIEM THU SLUG ENVSHIELD (5 BUOC THUC TE)                         |"
echo "+----------------------------------------------------------------------------+"
echo -e "\033[0m"

echo -e "\033[1;36m[BUOC 1] Kiem tra xem slug co san tren may khong...\033[0m"
if ! command -v slug >/dev/null 2>&1; then
    echo -e "\033[1;31m[-] Canh bao: 'slug' chua co trong PATH. Hay build slug hoac copy slug vao thu muc nay.\033[0m"
else
    echo -e "\033[1;32m[+] Tim thay Slug CLI san sang!\033[0m"
fi

echo -e "\n\033[1;36m[BUOC 2] Chay thu khi .env con o dang plaintext (Trang thai truyen thong):\033[0m"
python3 app.py || python app.py

echo -e "\n\033[1;36m[BUOC 3] Chu dong Niem Phong .env bang Slug EnvShield:\033[0m"
echo "  > slug env init"
slug env init

echo -e "\nKiem tra file trong thu muc (xem .env plaintext da bien mat chua):"
ls -la

echo -e "\n\033[1;36m[BUOC 4] Thu chay lai bang python thuong (Khong co .env plaintext tren dia):\033[0m"
echo "  > python app.py"
(python3 app.py 2>/dev/null || python app.py 2>/dev/null) || echo -e "\033[1;33m=> Ket qua dung thiet ke: App crash vi tren dia khong con .env thô de doc!\033[0m"

echo -e "\n\033[1;36m[BUOC 5] Chay an toan qua Slug EnvShield (In-RAM Decryption & Injected Process):\033[0m"
echo "  > slug env run -- python3 app.py"
slug env run -- python3 app.py || slug env run -- python app.py

echo -e "\n\033[1;36m[BUOC 6] Xem lich su backup tren Central Vault (~/.slug/env_vault/):\033[0m"
echo "  > slug env history"
slug env history

echo -e "\n\033[1;36m[BUOC 7] Khi can phuc hoi .env truyen thong (1-touch restore):\033[0m"
echo "  > slug env restore"
EOF

chmod +x "$TARGET_DIR/run_demo.sh"
echo -e "\033[1;32m[+] Đã tạo script hướng dẫn test: run_demo.sh\033[0m"

echo -e "\n\033[1;32m>>> KHỞI TẠO THÀNH CÔNG! <<<\033[0m"
echo -e "Cách sử dụng ngay bây giờ:"
echo -e "  \033[1;36mcd demo_env_workspace\033[0m"
echo -e "  \033[1;36m./run_demo.sh\033[0m\n"
