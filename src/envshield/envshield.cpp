#include "src/envshield/envshield.hpp"
#include "src/crypto/crypto_suite.hpp"
#include "src/crypto/xchacha20poly1305.hpp"
#include "src/platform/fs.hpp"
#include "src/platform/process.hpp"
#include "src/core/utils.hpp"
#include <iostream>
#include <cstring>
#include <openssl/crypto.h>

namespace slug::envshield {

namespace fs = std::filesystem;

static const char kMagicHeader[] = "SLUG_ENV_PQC\0";
static constexpr size_t kMagicLen = 13;

std::map<std::string, std::string> EnvShield::parse_env_content(const std::string& content) {
    std::map<std::string, std::string> env_map;
    auto lines = core::Utils::split(content, '\n');
    for (const auto& raw_line : lines) {
        std::string line = core::Utils::trim(raw_line);
        if (line.empty() || line.front() == '#') continue;

        size_t eq = line.find('=');
        if (eq == std::string::npos || eq == 0) continue;

        std::string key = core::Utils::trim(line.substr(0, eq));
        std::string val = core::Utils::trim(line.substr(eq + 1));

        // Unquote value if quoted
        if (val.size() >= 2 && ((val.front() == '"' && val.back() == '"') || (val.front() == '\'' && val.back() == '\''))) {
            val = val.substr(1, val.size() - 2);
        }

        env_map[key] = val;
    }
    return env_map;
}

bool EnvShield::init(const fs::path& workspace_root, core::SuiteID suite_id) {
    fs::path env_file = workspace_root / ".env";
    fs::path env_pqc_file = workspace_root / ".env.pqc";
    fs::path slug_dir = workspace_root / ".slug";
    fs::path key_file = slug_dir / "env_key.bin";

    platform::PathUtils::ensure_directory(slug_dir);

    // Read or create sample .env
    std::string env_data;
    if (fs::exists(env_file)) {
        auto cur = platform::PathUtils::read_text_file(env_file);
        if (cur) env_data = *cur;
    } else {
        env_data = "# Application Environment Configured with Slug EnvShield\n"
                   "APP_ENV=production\n"
                   "PORT=8080\n"
                   "DATABASE_URL=postgres://user:super_secret_pqc_password@localhost:5432/main_db\n"
                   "API_SECRET_KEY=" + core::Utils::to_hex(core::Utils::random_bytes(24)) + "\n";
    }

    auto suite = crypto::ICryptoSuite::create(suite_id);

    // Load or generate recipient KEM keypair
    crypto::KemKeyPair kem_keys;
    if (fs::exists(key_file)) {
        auto raw = platform::PathUtils::read_binary_file(key_file);
        if (raw && raw->size() > 4) {
            uint32_t pub_len = (static_cast<uint32_t>((*raw)[0]) << 24) |
                               (static_cast<uint32_t>((*raw)[1]) << 16) |
                               (static_cast<uint32_t>((*raw)[2]) << 8) |
                                static_cast<uint32_t>((*raw)[3]);
            if (raw->size() >= 4 + pub_len) {
                kem_keys.public_key.assign(raw->begin() + 4, raw->begin() + 4 + pub_len);
                kem_keys.private_key.assign(raw->begin() + 4 + pub_len, raw->end());
            }
        }
    }

    if (kem_keys.public_key.empty() || kem_keys.private_key.empty()) {
        kem_keys = suite->generate_kem_keypair();
        // Save keypair to .slug/env_key.bin
        uint32_t pub_len = static_cast<uint32_t>(kem_keys.public_key.size());
        std::vector<uint8_t> key_storage(4 + kem_keys.public_key.size() + kem_keys.private_key.size());
        key_storage[0] = static_cast<uint8_t>((pub_len >> 24) & 0xFF);
        key_storage[1] = static_cast<uint8_t>((pub_len >> 16) & 0xFF);
        key_storage[2] = static_cast<uint8_t>((pub_len >> 8) & 0xFF);
        key_storage[3] = static_cast<uint8_t>(pub_len & 0xFF);
        std::memcpy(key_storage.data() + 4, kem_keys.public_key.data(), kem_keys.public_key.size());
        std::memcpy(key_storage.data() + 4 + pub_len, kem_keys.private_key.data(), kem_keys.private_key.size());
        platform::PathUtils::write_binary_file_atomic(key_file, key_storage);
    }

    // Step 1: Encapsulate shared secret using recipient public key
    auto encaps_opt = suite->encapsulate(kem_keys.public_key);
    if (!encaps_opt) {
        std::cerr << "slug env: KEM encapsulation failed" << std::endl;
        return false;
    }
    const auto& encaps = *encaps_opt;

    // Step 2: Derive KEK (Key Encryption Key) from shared secret
    auto kek = suite->kdf(encaps.shared_secret, "slug_envshield_kek_v1");

    // Step 3: Generate DEK (Data Encryption Key) and wrap it
    auto dek_vec = core::Utils::random_bytes(32);
    std::array<uint8_t, 32> dek{};
    std::memcpy(dek.data(), dek_vec.data(), 32);

    std::array<uint8_t, 24> dek_nonce{};
    auto dek_nonce_vec = core::Utils::random_bytes(24);
    std::memcpy(dek_nonce.data(), dek_nonce_vec.data(), 24);

    auto wrapped_dek = crypto::XChaCha20Poly1305::encrypt(dek, kek, dek_nonce);

    // Step 4: Encrypt .env plaintext using DEK
    std::array<uint8_t, 24> env_nonce{};
    auto env_nonce_vec = core::Utils::random_bytes(24);
    std::memcpy(env_nonce.data(), env_nonce_vec.data(), 24);

    std::span<const uint8_t> pt_span(reinterpret_cast<const uint8_t*>(env_data.data()), env_data.size());
    auto encrypted_payload = crypto::XChaCha20Poly1305::encrypt(pt_span, dek, env_nonce);

    // Assemble binary .env.pqc container
    std::vector<uint8_t> out;
    out.insert(out.end(), kMagicHeader, kMagicHeader + kMagicLen);
    out.push_back(static_cast<uint8_t>(suite_id));

    // Wrapped DEK length & data
    uint32_t wdek_len = static_cast<uint32_t>(wrapped_dek.size());
    out.push_back(static_cast<uint8_t>((wdek_len >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((wdek_len >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((wdek_len >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(wdek_len & 0xFF));
    out.insert(out.end(), dek_nonce.begin(), dek_nonce.end());
    out.insert(out.end(), wrapped_dek.begin(), wrapped_dek.end());

    // KEM ciphertext length & data
    uint32_t ct_len = static_cast<uint32_t>(encaps.ciphertext.size());
    out.push_back(static_cast<uint8_t>((ct_len >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((ct_len >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((ct_len >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(ct_len & 0xFF));
    out.insert(out.end(), encaps.ciphertext.begin(), encaps.ciphertext.end());

    // Payload nonce & encrypted .env payload
    out.insert(out.end(), env_nonce.begin(), env_nonce.end());
    out.insert(out.end(), encrypted_payload.begin(), encrypted_payload.end());

    if (!platform::PathUtils::write_binary_file_atomic(env_pqc_file, out)) {
        return false;
    }

    // Safely remove or backup original .env
    std::error_code ec;
    if (fs::exists(env_file, ec)) {
        fs::rename(env_file, workspace_root / ".env.bak", ec);
    }

    std::cout << "[+] Encrypted .env -> .env.pqc successfully with " << suite->name() << std::endl;
    std::cout << "[+] Original plaintext moved to .env.bak (You can delete .env.bak to prevent AI Agent inspection)" << std::endl;
    return true;
}

int EnvShield::run(const fs::path& workspace_root, const std::vector<std::string>& command_and_args) {
    fs::path env_pqc_file = workspace_root / ".env.pqc";
    fs::path key_file = workspace_root / ".slug" / "env_key.bin";

    if (!fs::exists(env_pqc_file)) {
        std::cerr << "slug env: .env.pqc not found. Run 'slug env init' first." << std::endl;
        return 1;
    }

    if (!fs::exists(key_file)) {
        std::cerr << "slug env: Encryption key not found at " << key_file.string() << std::endl;
        return 1;
    }

    auto raw_key = platform::PathUtils::read_binary_file(key_file);
    if (!raw_key || raw_key->size() < 4) {
        std::cerr << "slug env: Corrupt key file" << std::endl;
        return 1;
    }

    uint32_t pub_len = (static_cast<uint32_t>((*raw_key)[0]) << 24) |
                       (static_cast<uint32_t>((*raw_key)[1]) << 16) |
                       (static_cast<uint32_t>((*raw_key)[2]) << 8) |
                        static_cast<uint32_t>((*raw_key)[3]);

    std::vector<uint8_t> priv_key(raw_key->begin() + 4 + pub_len, raw_key->end());

    auto pqc_data = platform::PathUtils::read_binary_file(env_pqc_file);
    if (!pqc_data || pqc_data->size() < kMagicLen + 1 + 4 + 24) {
        std::cerr << "slug env: Corrupt .env.pqc file" << std::endl;
        return 1;
    }

    // Verify magic
    if (std::memcmp(pqc_data->data(), kMagicHeader, kMagicLen) != 0) {
        std::cerr << "slug env: Invalid header magic in .env.pqc" << std::endl;
        return 1;
    }

    size_t offset = kMagicLen;
    core::SuiteID suite_id = static_cast<core::SuiteID>((*pqc_data)[offset++]);
    auto suite = crypto::ICryptoSuite::create(suite_id);

    // Read wrapped DEK
    uint32_t wdek_len = (static_cast<uint32_t>((*pqc_data)[offset]) << 24) |
                        (static_cast<uint32_t>((*pqc_data)[offset + 1]) << 16) |
                        (static_cast<uint32_t>((*pqc_data)[offset + 2]) << 8) |
                         static_cast<uint32_t>((*pqc_data)[offset + 3]);
    offset += 4;

    std::array<uint8_t, 24> dek_nonce{};
    std::memcpy(dek_nonce.data(), pqc_data->data() + offset, 24);
    offset += 24;

    std::span<const uint8_t> wrapped_dek(pqc_data->data() + offset, wdek_len);
    offset += wdek_len;

    // Read KEM ciphertext
    uint32_t ct_len = (static_cast<uint32_t>((*pqc_data)[offset]) << 24) |
                      (static_cast<uint32_t>((*pqc_data)[offset + 1]) << 16) |
                      (static_cast<uint32_t>((*pqc_data)[offset + 2]) << 8) |
                       static_cast<uint32_t>((*pqc_data)[offset + 3]);
    offset += 4;

    std::span<const uint8_t> kem_ct(pqc_data->data() + offset, ct_len);
    offset += ct_len;

    // Decapsulate shared secret
    auto ss_opt = suite->decapsulate(kem_ct, priv_key);
    if (!ss_opt) {
        std::cerr << "slug env: KEM decapsulation failed" << std::endl;
        return 1;
    }

    // Derive KEK
    auto kek = suite->kdf(*ss_opt, "slug_envshield_kek_v1");

    // Decrypt DEK
    auto dek_opt = crypto::XChaCha20Poly1305::decrypt(wrapped_dek, kek, dek_nonce);
    if (!dek_opt || dek_opt->size() != 32) {
        std::cerr << "slug env: Failed to unwrap DEK (AEAD tag mismatch)" << std::endl;
        return 1;
    }

    std::array<uint8_t, 32> dek{};
    std::memcpy(dek.data(), dek_opt->data(), 32);

    // Read payload nonce & encrypted .env
    std::array<uint8_t, 24> env_nonce{};
    std::memcpy(env_nonce.data(), pqc_data->data() + offset, 24);
    offset += 24;

    std::span<const uint8_t> enc_payload(pqc_data->data() + offset, pqc_data->size() - offset);

    // Decrypt payload directly on RAM
    auto env_plaintext = crypto::XChaCha20Poly1305::decrypt(enc_payload, dek, env_nonce);
    if (!env_plaintext) {
        std::cerr << "slug env: Failed to decrypt .env.pqc payload" << std::endl;
        return 1;
    }

    std::string env_str(env_plaintext->begin(), env_plaintext->end());
    auto env_map = parse_env_content(env_str);

    // Zero out sensitive RAM buffers with compiler-guaranteed memory wipe
    OPENSSL_cleanse(env_plaintext->data(), env_plaintext->size());
    OPENSSL_cleanse(dek.data(), dek.size());

    std::cout << "[+] Injected " << env_map.size() << " environment variables from RAM directly into process" << std::endl;
    return platform::ProcessUtils::run_process_with_env(command_and_args, env_map);
}

} // namespace slug::envshield
