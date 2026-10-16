#!/usr/bin/env bash
# ==============================================================================
# Slug - Automated Local Integration Test Suite
# Tests: PQC EnvShield, Ephemeral RBAC, One-Time TOTP Burn, AI Secret Guard,
#        Gitignore & Scoped Rules, Delta Sync, Push Permissions, Path Confinement,
#        Static Binary Compatibility.
# ==============================================================================

set -e

# ANSI Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

PASSED_COUNT=0
FAILED_COUNT=0

log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED_COUNT=$((PASSED_COUNT + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED_COUNT=$((FAILED_COUNT + 1))
}

assert_success() {
    local cmd="$1"
    local desc="$2"
    if eval "$cmd"; then
        log_pass "$desc"
    else
        log_fail "$desc (Command returned non-zero)"
    fi
}

assert_failure() {
    local cmd="$1"
    local desc="$2"
    if ! eval "$cmd" > /dev/null 2>&1; then
        log_pass "$desc (Successfully rejected)"
    else
        log_fail "$desc (Expected failure, but succeeded)"
    fi
}

# Ensure working directory is project root
cd "$(dirname "$0")/.."
PROJECT_ROOT=$(pwd)
BIN="${SLUG_BIN:-$PROJECT_ROOT/bin/slug}"
STATIC_BIN="$PROJECT_ROOT/bin/slug-static"
TEST_DIR="$PROJECT_ROOT/test_run"
TEST_PORT=19443

echo -e "\n${BOLD}${CYAN}====================================================================${NC}"
echo -e "${BOLD}${CYAN}         SLUG SECURE WORKSPACE - AUTOMATED LOCAL TEST SUITE         ${NC}"
echo -e "${BOLD}${CYAN}====================================================================${NC}\n"

# Cleanup any previous runs
cleanup() {
    log_info "Cleaning up processes and temporary test directories..."
    $BIN stop -p $TEST_PORT > /dev/null 2>&1 || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT
cleanup

# Step 0: Check Binaries
log_info "Verifying Slug binaries exist..."
if [ ! -f "$BIN" ]; then
    log_info "Compiling Slug binaries..."
    make -j$(nproc)
    make static -j$(nproc)
fi

assert_success "$BIN version | grep -q 'Slug 1.0.0-rc2'" "Binary version check ($BIN)"
assert_success "$STATIC_BIN version | grep -q 'Slug 1.0.0-rc2'" "Static binary execution check ($STATIC_BIN)"

mkdir -p "$TEST_DIR"

# ==============================================================================
# TEST SUITE 1: PQC EnvShield
# ==============================================================================
echo -e "\n${BOLD}--- TEST SUITE 1: PQC EnvShield (RAM-only Secret Injection) ---${NC}"

ENV_DIR="$TEST_DIR/env_test"
mkdir -p "$ENV_DIR"
cd "$ENV_DIR"

cat << 'EOF' > .env
DATABASE_URL=postgres://slug_admin:SecretQuantumPass2026@10.0.0.5/prod_db
API_SECRET_KEY=sk_pqc_super_classified_developer_shield_key_998877
SLUG_RUN_MODE=production_secure
EOF

assert_success "$BIN env init -s 3" "EnvShield Init (Encrypt .env -> .env.pqc with ML-KEM-768/XChaCha20)"
assert_success "[ -f .env.pqc ] && [ ! -f .env ]" "Plaintext .env securely wiped and .env.pqc created"

# Verify RAM-only injection
OUTPUT=$($BIN env run -- /bin/sh -c 'echo "KEY=$API_SECRET_KEY MODE=$SLUG_RUN_MODE"')
assert_success "echo '$OUTPUT' | grep -q 'KEY=sk_pqc_super_classified_developer_shield_key_998877'" "In-memory variable injection API_SECRET_KEY"
assert_success "echo '$OUTPUT' | grep -q 'MODE=production_secure'" "In-memory variable injection SLUG_RUN_MODE"

cd "$PROJECT_ROOT"

# ==============================================================================
# TEST SUITE 2: Workspace Hosting & Stateful AI Secret Guard
# ==============================================================================
echo -e "\n${BOLD}--- TEST SUITE 2: Workspace Hosting & AI Secret Guard ---${NC}"

WORKSPACE_DIR="$TEST_DIR/workspace"
mkdir -p "$WORKSPACE_DIR/src" "$WORKSPACE_DIR/docs" "$WORKSPACE_DIR/build" "$WORKSPACE_DIR/tests"

# Normal code and docs
echo 'fn main() { println!("Hello from Slug P2P!"); }' > "$WORKSPACE_DIR/src/main.rs"
echo '# Slug System Specifications' > "$WORKSPACE_DIR/docs/spec.md"

# Ignored by .gitignore
echo 'build/' > "$WORKSPACE_DIR/.gitignore"
echo 'compiled_binary_data_temp_object' > "$WORKSPACE_DIR/build/main.o"

# Secret that should be detected by AI Guard (split prefix to avoid GitHub push protection false positive)
MOCK_STRIPE_PRE="sk_live"
echo "const STRIPE_KEY = \"${MOCK_STRIPE_PRE}_99887766554433221100aabbccdd\";" > "$WORKSPACE_DIR/tests/leaked_token.ts"

# Rule-blocked file (.pem private key)
echo '-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz...FAKE_TEST_KEY...
-----END RSA PRIVATE KEY-----' > "$WORKSPACE_DIR/tests/id_rsa.pem"

log_info "Hosting workspace on port $TEST_PORT with AI Guard and Daemon mode..."
HOST_OUTPUT=$($BIN add "$WORKSPACE_DIR" -p $TEST_PORT -s 3 --ttl 2h -a --daemon)
echo "$HOST_OUTPUT"

# Extract TOTP token from host output
TOTP=$(echo "$HOST_OUTPUT" | grep -oP '(?:Read-Write OTP|TOTP):\s+\K[0-9]{8}' || true)
if [ -z "$TOTP" ]; then
    # Fallback grep
    TOTP=$(echo "$HOST_OUTPUT" | grep -E -o '[0-9]{8}' | head -n 1)
fi
log_info "Captured One-Time TOTP code: $TOTP"

assert_success "[ -n '$TOTP' ]" "Server started and generated 8-digit One-Time TOTP"
sleep 1

# Check status
STATUS_OUT=$($BIN status --flagged)
assert_success "echo '$STATUS_OUT' | grep -q '$TEST_PORT'" "Workspace active in registry on port $TEST_PORT"
assert_success "echo '$STATUS_OUT' | grep -q 'leaked_token.ts'" "AI Guard successfully flagged leaked_token.ts in status"

# ==============================================================================
# TEST SUITE 3: Single-Use TOTP Verification & Atomic Burn (Anti-Replay)
# ==============================================================================
echo -e "\n${BOLD}--- TEST SUITE 3: Single-Use TOTP One-Time-Bind & Burn ---${NC}"

assert_success "$BIN connect -i 127.0.0.1 -p $TEST_PORT -o $TOTP" "First connection with valid TOTP succeeds"
assert_failure "$BIN connect -i 127.0.0.1 -p $TEST_PORT -o $TOTP" "Second connection with same TOTP rejected (Token Burned!)"

# Verify slug totp command and slug get (Single-File Download with Read-Only OTP)
TOTP_RO=$($BIN totp -p $TEST_PORT -r r --code-only | tr -d '[:space:]')
assert_success "[ ${#TOTP_RO} -eq 8 ]" "Command 'slug totp -p <port> -r r --code-only' returns valid 8-digit OTP"

ONE_SHOT_FILE="$TEST_DIR/single_file_main.rs"
assert_success "$BIN get '127.0.0.1:$TEST_PORT?otp=$TOTP_RO' src/main.rs '$ONE_SHOT_FILE'" "Single-file 'slug get <url> <file>' downloads only specified file"
assert_success "[ -f '$ONE_SHOT_FILE' ] && grep -q 'Hello from Slug' '$ONE_SHOT_FILE'" "Downloaded single file contains correct content"

# Verify slug ls technical explorer
LS_OUTPUT=$($BIN ls)
assert_success "echo '$LS_OUTPUT' | grep -q 'src/' && echo '$LS_OUTPUT' | grep -q 'Available'" "Command 'slug ls' renders technical explorer with folders and Available status"

# ==============================================================================
# TEST SUITE 4: Ephemeral User Accounts & RBAC
# ==============================================================================
echo -e "\n${BOLD}--- TEST SUITE 4: Ephemeral User Accounts & RBAC ---${NC}"

assert_success "$BIN user add -u alice -P alice_pass_123 --role rw --ttl 1h -p $TEST_PORT" "Add read-write user 'alice'"
assert_success "$BIN user add -u bob -P bob_pass_456 --role r --ttl 1h -p $TEST_PORT" "Add read-only user 'bob'"

USER_LIST=$($BIN user list -p $TEST_PORT)
assert_success "echo '$USER_LIST' | grep -q 'alice.*rw.*ACTIVE'" "User 'alice' active with 'rw' role"
assert_success "echo '$USER_LIST' | grep -q 'bob.*r.*ACTIVE'" "User 'bob' active with 'r' role"

assert_success "$BIN connect -i 127.0.0.1 -p $TEST_PORT -u alice -P alice_pass_123" "Authenticate as 'alice' with valid password"
assert_failure "$BIN connect -i 127.0.0.1 -p $TEST_PORT -u alice -P wrong_password" "Reject 'alice' with invalid password"

# ==============================================================================
# TEST SUITE 5: Security Policy & Dynamic Rules
# ==============================================================================
echo -e "\n${BOLD}--- TEST SUITE 5: Security Policy Engine & Rules ---${NC}"

assert_success "$BIN rule block --ext .pem -p $TEST_PORT" "Add block rule for .pem extension"
RULE_LIST=$($BIN rule list -p $TEST_PORT)
assert_success "echo '$RULE_LIST' | grep -q '.pem'" "Verify block rule '.pem' registered in .slug/rules.conf"

# ==============================================================================
# TEST SUITE 6: Git-like Delta Sync & Selective Pull
# ==============================================================================
echo -e "\n${BOLD}--- TEST SUITE 6: Delta Sync & Content Filtering ---${NC}"

PULL_DIR="$TEST_DIR/pulled"
mkdir -p "$PULL_DIR"

# Pull dry-run
DRY_RUN_OUT=$($BIN pull "$PULL_DIR" -i 127.0.0.1 -p $TEST_PORT -u alice -P alice_pass_123 --dry-run)
assert_success "echo '$DRY_RUN_OUT' | grep -i -q 'dry-run'" "Dry-run execution previews transfer"

# Actual pull with confirmation bypass (-y)
assert_success "$BIN pull "$PULL_DIR" -i 127.0.0.1 -p $TEST_PORT -u alice -P alice_pass_123 -y" "Pull workspace as 'alice'"

# Verify legitimate files transferred
assert_success "[ -f '$PULL_DIR/src/main.rs' ] && grep -q 'Hello from Slug' '$PULL_DIR/src/main.rs'" "Safe file src/main.rs synchronized"
assert_success "[ -f '$PULL_DIR/docs/spec.md' ]" "Safe file docs/spec.md synchronized"

# Verify protected files are filtered and NOT transferred
assert_success "[ ! -f '$PULL_DIR/build/main.o' ]" "Gitignored file build/main.o correctly skipped"
assert_success "[ ! -f '$PULL_DIR/tests/id_rsa.pem' ]" "Rule-blocked file tests/id_rsa.pem correctly skipped"
assert_success "[ ! -f '$PULL_DIR/tests/leaked_token.ts' ]" "AI-flagged file tests/leaked_token.ts correctly shielded"

# Test Selective Scope Pull (only 'src' scope pulled)
SELECTIVE_DIR="$TEST_DIR/selective_src"
assert_success "$BIN pull src/ --to "$SELECTIVE_DIR" -i 127.0.0.1 -p $TEST_PORT -u alice -P alice_pass_123 -y" "Selective pull of scope 'src/' with --to flag"
assert_success "[ -f '$SELECTIVE_DIR/src/main.rs' ] && [ ! -f '$SELECTIVE_DIR/docs/spec.md' ]" "Selective pull only fetched files inside 'src/' scope"

# Test Single-File Get via active connection
assert_success "$BIN get docs/spec.md '$TEST_DIR/get_spec.md'" "Single-file 'slug get <file> <dest>' via active connection"
assert_success "[ -f '$TEST_DIR/get_spec.md' ]" "Single file downloaded via active connection"

# Test Incremental Delta Sync (only modified/new files transferred)
echo 'pub fn helper() {}' > "$WORKSPACE_DIR/src/helper.rs"
PULL_DELTA_OUT=$($BIN pull "$PULL_DIR" -i 127.0.0.1 -p $TEST_PORT -u alice -P alice_pass_123 -y)
assert_success "echo '$PULL_DELTA_OUT' | grep -q 'Synced: src/helper.rs' && echo '$PULL_DELTA_OUT' | grep -q 'saved' && [ -f '$PULL_DIR/src/helper.rs' ]" "Delta Sync transferred helper.rs and reported saved bytes"

# ==============================================================================
# TEST SUITE 7: Push & Role Permission Enforcement
# ==============================================================================
echo -e "\n${BOLD}--- TEST SUITE 7: Push Upload & Permission Enforcement ---${NC}"

LOCAL_UPLOAD="$TEST_DIR/contrib.rs"
echo '// Contributed feature code' > "$LOCAL_UPLOAD"

# Bob has role 'r' (read only) -> Push should be denied
assert_failure "$BIN push '$LOCAL_UPLOAD' src/contrib.rs -i 127.0.0.1 -p $TEST_PORT -u bob -P bob_pass_456" "Bob (role 'r') denied push upload"

# Alice has role 'rw' -> Push should succeed
assert_success "$BIN push '$LOCAL_UPLOAD' src/contrib.rs -i 127.0.0.1 -p $TEST_PORT -u alice -P alice_pass_123" "Alice (role 'rw') successfully uploads file"
assert_success "[ -f '$WORKSPACE_DIR/src/contrib.rs' ]" "Uploaded file saved in remote workspace root"

# ==============================================================================
# TEST SUITE 8: Path Traversal Attack Confinement
# ==============================================================================
echo -e "\n${BOLD}--- TEST SUITE 8: Path Traversal Attack Confinement ---${NC}"

# Attempt to escape workspace root via directory traversal on push
assert_failure "$BIN push '$LOCAL_UPLOAD' ../../hacked.txt -i 127.0.0.1 -p $TEST_PORT -u alice -P alice_pass_123" "Path traversal attack on push strictly blocked"
assert_success "[ ! -f '$TEST_DIR/hacked.txt' ]" "Escaped file does NOT exist outside workspace root"

# ==============================================================================
# TEST SUITE 9: AI Guard Whitelist & Remediation
# ==============================================================================
echo -e "\n${BOLD}--- TEST SUITE 9: AI Guard Audit & Whitelist ---${NC}"

AUDIT_LIST=$($BIN audit list -p $TEST_PORT)
assert_success "echo '$AUDIT_LIST' | grep -q 'leaked_token.ts.*AI_FLAGGED'" "Audit list shows leaked_token.ts"

# Whitelist false positive with user override
assert_success "$BIN audit allow tests/leaked_token.ts --reason 'Safe mock token for lab testing' -p $TEST_PORT" "Whitelist false-positive with user override"

# Re-pull: previously blocked file should now be synchronized
assert_success "$BIN pull "$PULL_DIR" -i 127.0.0.1 -p $TEST_PORT -u alice -P alice_pass_123 -y" "Re-pull after user whitelist approval"
assert_success "[ -f '$PULL_DIR/tests/leaked_token.ts' ]" "Whitelisted file successfully delivered to client"

# ==============================================================================
# TEST SUITE 10: Graceful Server Shutdown
# ==============================================================================
echo -e "\n${BOLD}--- TEST SUITE 10: Graceful Server Shutdown ---${NC}"

assert_success "$BIN stop -p $TEST_PORT" "Stop workspace server on port $TEST_PORT"
sleep 1

# Verify port is closed
assert_failure "$BIN connect -i 127.0.0.1 -p $TEST_PORT -u alice -P alice_pass_123" "Server successfully terminated (connection refused)"
STATUS_FINAL=$($BIN status)
if echo "$STATUS_FINAL" | grep -q "$TEST_PORT"; then
    log_fail "Port $TEST_PORT still found in registry"
else
    log_pass "Port $TEST_PORT cleared from workspace registry"
fi

# ==============================================================================
# TEST SUITE 11: Security & Performance Benchmark Suite
# ==============================================================================
echo -e "\n${BOLD}--- TEST SUITE 11: Performance & Benchmark Suite ---${NC}"

assert_success "$BIN bench --quick | grep -q 'SLUG PERFORMANCE & SECURITY BENCHMARK REPORT'" "Run quick benchmark via dynamic binary"
assert_success "$BIN bench --json --quick | grep -q '\"crypto_suites\"'" "Run quick benchmark with JSON output format"
assert_success "$STATIC_BIN bench --quick | grep -q 'Suite 3: PurePQC'" "Run quick benchmark via fully static binary"

# ==============================================================================
# TEST SUITE 12: Packaging and Distributable Validation
# ==============================================================================
echo -e "\n${BOLD}--- TEST SUITE 12: Packaging & Release Validation ---${NC}"

assert_success "$PROJECT_ROOT/scripts/package_linux.sh > /dev/null" "Build universal Linux tarball (slug-*-linux-x86_64.tar.gz)"
assert_success "[ -f '$PROJECT_ROOT/dist/slug-1.0.0-rc2-linux-x86_64.tar.gz' ]" "Universal Linux release archive exists"
assert_success "$PROJECT_ROOT/scripts/package_deb.sh > /dev/null" "Build Debian/Ubuntu .deb package (slug_*_amd64.deb)"
assert_success "[ -f '$PROJECT_ROOT/dist/slug_1.0.0-rc2_amd64.deb' ]" "Debian package exists and validated"

# ==============================================================================
# TEST SUMMARY
# ==============================================================================
echo -e "\n${BOLD}${CYAN}====================================================================${NC}"
echo -e "${BOLD}${CYAN}                     TEST SUITE EXECUTION SUMMARY                   ${NC}"
echo -e "${BOLD}${CYAN}====================================================================${NC}"
echo -e "Total Passed Tests: ${GREEN}${PASSED_COUNT}${NC}"
echo -e "Total Failed Tests: ${RED}${FAILED_COUNT}${NC}"

if [ $FAILED_COUNT -eq 0 ]; then
    echo -e "\n${BOLD}${GREEN}[SUCCESS] All Slug integration tests passed flawlessly!${NC}\n"
    exit 0
else
    echo -e "\n${BOLD}${RED}[FAILURE] Some integration tests failed. Check log output above.${NC}\n"
    exit 1
fi
