#include "src/envshield/envshield.hpp"
#include "src/crypto/crypto_suite.hpp"
#include "src/crypto/xchacha20poly1305.hpp"
#include "src/crypto/blake3_wrapper.hpp"
#include "src/platform/fs.hpp"
#include "src/platform/process.hpp"
#include "src/core/utils.hpp"
#include "third_party/json/json.hpp"
#include <iostream>
#include <cstring>
#include <chrono>
#include <ctime>
#include <openssl/crypto.h>

namespace slug::envshield {

namespace fs = std::filesystem;

static const char kMagicHeader[] = "SLUG_ENV_PQC\0";
static constexpr size_t kMagicLen = 13;

static std::string format_timestamp(std::chrono::system_clock::time_point tp) {
    auto t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_buf{};
#if defined(SLUG_PLATFORM_WINDOWS)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &tm_buf);
    return std::string(buf);
}

std::string EnvShield::get_workspace_hash(const fs::path& workspace_root) {
    std::error_code ec;
    fs::path canonical_p = fs::weakly_canonical(workspace_root, ec);
    if (ec) canonical_p = fs::absolute(workspace_root).lexically_normal();

    std::string p_str = canonical_p.generic_string();
#if defined(SLUG_PLATFORM_WINDOWS)
    for (auto& c : p_str) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
#endif
    std::string hash = crypto::Blake3::hash_hex(p_str);
    return hash.substr(0, 16);
}

fs::path EnvShield::get_vault_dir(const fs::path& workspace_root) {
    fs::path home = platform::get_user_home();
    return home / ".slug" / "env_vault" / get_workspace_hash(workspace_root);
}

std::string EnvShield::agent_prompt(const fs::path& /*workspace_root*/) {
    return "# SLUG ENVSHIELD AGENT DIRECTIVE\n"
           "- In this repository, sensitive environment variables are sealed in `.env.pqc`.\n"
           "- DO NOT attempt to create or read plaintext `.env` on disk.\n"
           "- ALWAYS execute runtime commands (npm start, pytest, python, cargo, etc.) through Slug EnvShield:\n"
           "    slug env run -- <command>\n"
           "- Slug will decrypt secrets directly in process memory (RAM).\n";
}

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

std::vector<EnvVaultEntry> EnvShield::history(const fs::path& workspace_root) {
    std::vector<EnvVaultEntry> result;
    fs::path vault_dir = get_vault_dir(workspace_root);
    fs::path meta_path = vault_dir / "meta.json";
    if (!fs::exists(meta_path)) return result;

    auto data = platform::PathUtils::read_text_file(meta_path);
    if (!data) return result;

    try {
        auto j = nlohmann::json::parse(*data);
        if (j.contains("backups") && j["backups"].is_array()) {
            for (const auto& item : j["backups"]) {
                EnvVaultEntry entry;
                entry.filename = item.value("filename", "");
                entry.timestamp = item.value("timestamp", 0ULL);
                entry.blake3_hash = item.value("blake3", "");
                entry.size_bytes = item.value("size_bytes", 0ULL);
                entry.version = item.value("version", 1U);
                result.push_back(entry);
            }
        }
    } catch (...) {
        std::error_code ec;
        uint32_t v = 1;
        for (const auto& entry : fs::directory_iterator(vault_dir, ec)) {
            if (entry.path().extension() == ".bak") {
                EnvVaultEntry e;
                e.filename = entry.path().filename().string();
                e.size_bytes = fs::file_size(entry.path(), ec);
                e.version = v++;
                result.push_back(e);
            }
        }
    }
    return result;
}

static std::optional<std::string> decrypt_env_file(const fs::path& workspace_root) {
    fs::path env_pqc_file = workspace_root / ".env.pqc";
    fs::path vault_key_file = EnvShield::get_vault_dir(workspace_root) / "env_key.bin";
    fs::path legacy_key_file = workspace_root / ".slug" / "env_key.bin";
    fs::path key_file;
    if (fs::exists(vault_key_file)) {
        key_file = vault_key_file;
    } else if (fs::exists(legacy_key_file)) {
        key_file = legacy_key_file;
    } else {
        std::cerr << "slug env: Encryption key not found in Central Vault or workspace (" << vault_key_file.string() << ")" << std::endl;
        return std::nullopt;
    }

    if (!fs::exists(env_pqc_file)) {
        std::cerr << "slug env: .env.pqc not found. Run 'slug env init' first." << std::endl;
        return std::nullopt;
    }

    auto raw_key = platform::PathUtils::read_binary_file(key_file);
    if (!raw_key || raw_key->size() < 4) {
        std::cerr << "slug env: Corrupt key file" << std::endl;
        return std::nullopt;
    }

    uint32_t pub_len = (static_cast<uint32_t>((*raw_key)[0]) << 24) |
                       (static_cast<uint32_t>((*raw_key)[1]) << 16) |
                       (static_cast<uint32_t>((*raw_key)[2]) << 8) |
                        static_cast<uint32_t>((*raw_key)[3]);

    if (raw_key->size() < 4 + pub_len) {
        std::cerr << "slug env: Corrupt key file length" << std::endl;
        return std::nullopt;
    }

    std::vector<uint8_t> priv_key(raw_key->begin() + 4 + pub_len, raw_key->end());

    auto pqc_data = platform::PathUtils::read_binary_file(env_pqc_file);
    if (!pqc_data || pqc_data->size() < kMagicLen + 1 + 4 + 24) {
        std::cerr << "slug env: Corrupt .env.pqc file" << std::endl;
        return std::nullopt;
    }

    // Verify magic
    if (std::memcmp(pqc_data->data(), kMagicHeader, kMagicLen) != 0) {
        std::cerr << "slug env: Invalid header magic in .env.pqc" << std::endl;
        return std::nullopt;
    }

    size_t offset = kMagicLen;
    core::SuiteID suite_id = static_cast<core::SuiteID>((*pqc_data)[offset++]);
    auto suite = crypto::ICryptoSuite::create(suite_id);

    // Read wrapped DEK
    if (offset + 4 > pqc_data->size()) return std::nullopt;
    uint32_t wdek_len = (static_cast<uint32_t>((*pqc_data)[offset]) << 24) |
                        (static_cast<uint32_t>((*pqc_data)[offset + 1]) << 16) |
                        (static_cast<uint32_t>((*pqc_data)[offset + 2]) << 8) |
                         static_cast<uint32_t>((*pqc_data)[offset + 3]);
    offset += 4;

    if (offset + 24 + wdek_len > pqc_data->size()) return std::nullopt;
    std::array<uint8_t, 24> dek_nonce{};
    std::memcpy(dek_nonce.data(), pqc_data->data() + offset, 24);
    offset += 24;

    std::span<const uint8_t> wrapped_dek(pqc_data->data() + offset, wdek_len);
    offset += wdek_len;

    // Read KEM ciphertext
    if (offset + 4 > pqc_data->size()) return std::nullopt;
    uint32_t ct_len = (static_cast<uint32_t>((*pqc_data)[offset]) << 24) |
                      (static_cast<uint32_t>((*pqc_data)[offset + 1]) << 16) |
                      (static_cast<uint32_t>((*pqc_data)[offset + 2]) << 8) |
                       static_cast<uint32_t>((*pqc_data)[offset + 3]);
    offset += 4;

    if (offset + ct_len + 24 > pqc_data->size()) return std::nullopt;
    std::span<const uint8_t> kem_ct(pqc_data->data() + offset, ct_len);
    offset += ct_len;

    // Decapsulate shared secret
    auto ss_opt = suite->decapsulate(kem_ct, priv_key);
    if (!ss_opt) {
        std::cerr << "slug env: KEM decapsulation failed" << std::endl;
        return std::nullopt;
    }

    // Derive KEK
    auto kek = suite->kdf(*ss_opt, "slug_envshield_kek_v1");

    // Decrypt DEK
    auto dek_opt = crypto::XChaCha20Poly1305::decrypt(wrapped_dek, kek, dek_nonce);
    if (!dek_opt || dek_opt->size() != 32) {
        std::cerr << "slug env: Failed to unwrap DEK (AEAD tag mismatch)" << std::endl;
        return std::nullopt;
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
        return std::nullopt;
    }

    std::string env_str(env_plaintext->begin(), env_plaintext->end());
    OPENSSL_cleanse(env_plaintext->data(), env_plaintext->size());
    OPENSSL_cleanse(dek.data(), dek.size());

    return env_str;
}

bool EnvShield::init(const fs::path& workspace_root, core::SuiteID suite_id, bool keep_plaintext) {
    fs::path env_file = workspace_root / ".env";
    fs::path env_pqc_file = workspace_root / ".env.pqc";
    fs::path vault_dir = get_vault_dir(workspace_root);
    platform::PathUtils::ensure_directory(vault_dir);
    fs::path key_file = vault_dir / "env_key.bin";
    fs::path legacy_key_file = workspace_root / ".slug" / "env_key.bin";

    // Read or create sample .env
    std::string env_data;
    bool existed_on_disk = false;
    if (fs::exists(env_file)) {
        auto cur = platform::PathUtils::read_text_file(env_file);
        if (cur) {
            env_data = *cur;
            existed_on_disk = true;
        }
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
    fs::path load_key_path = fs::exists(key_file) ? key_file : (fs::exists(legacy_key_file) ? legacy_key_file : fs::path());
    if (!load_key_path.empty()) {
        auto raw = platform::PathUtils::read_binary_file(load_key_path);
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
        // Save keypair safely to Central Vault outside workspace repository
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

    // Backup original .env to Central Vault (~/.slug/env_vault/<hash>/)
    platform::PathUtils::ensure_directory(vault_dir);

    auto existing_backups = history(workspace_root);
    uint32_t next_version = static_cast<uint32_t>(existing_backups.size()) + 1;

    auto now = std::chrono::system_clock::now();
    std::string ts_str = format_timestamp(now);
    uint64_t epoch_sec = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
    std::string backup_fname = "env_" + ts_str + "_v" + std::to_string(next_version) + ".bak";
    fs::path backup_path = vault_dir / backup_fname;

    platform::PathUtils::write_text_file_atomic(backup_path, env_data);

    // Update meta.json
    nlohmann::json meta_json;
    fs::path meta_path = vault_dir / "meta.json";
    if (fs::exists(meta_path)) {
        auto mdata = platform::PathUtils::read_text_file(meta_path);
        if (mdata) {
            try {
                meta_json = nlohmann::json::parse(*mdata);
            } catch (...) {
                meta_json = nlohmann::json::object();
            }
        }
    }

    std::error_code ec;
    meta_json["workspace_path"] = fs::weakly_canonical(workspace_root, ec).generic_string();
    meta_json["workspace_hash"] = get_workspace_hash(workspace_root);
    meta_json["updated_at"] = epoch_sec;

    nlohmann::json b_entry;
    b_entry["filename"] = backup_fname;
    b_entry["timestamp"] = epoch_sec;
    b_entry["blake3"] = crypto::Blake3::hash_hex(env_data);
    b_entry["size_bytes"] = env_data.size();
    b_entry["version"] = next_version;

    if (!meta_json.contains("backups") || !meta_json["backups"].is_array()) {
        meta_json["backups"] = nlohmann::json::array();
    }
    meta_json["backups"].push_back(b_entry);

    platform::PathUtils::write_text_file_atomic(meta_path, meta_json.dump(2));

    // Automatically generate .slug/ai-rule.md for AI coding assistants
    fs::path slug_dir = workspace_root / ".slug";
    platform::PathUtils::ensure_directory(slug_dir);
    platform::PathUtils::write_text_file_atomic(slug_dir / "ai-rule.md", agent_prompt(workspace_root));

    // Clean legacy local .env.bak if present
    if (fs::exists(workspace_root / ".env.bak", ec)) {
        fs::remove(workspace_root / ".env.bak", ec);
    }

    if (keep_plaintext) {
        if (!existed_on_disk) {
            platform::PathUtils::write_text_file_atomic(env_file, env_data);
        }
        std::cout << "[+] Encrypted .env -> .env.pqc successfully with " << suite->name() << std::endl;
        std::cout << "[+] Saved backup into Central Vault: " << backup_path.string() << std::endl;
        std::cout << "[!] Retained plaintext .env (--keep enabled). AI assistants may still read .env!" << std::endl;
    } else {
        if (fs::exists(env_file, ec)) {
            fs::remove(env_file, ec);
        }
        std::cout << "[+] Encrypted .env -> .env.pqc successfully with " << suite->name() << std::endl;
        std::cout << "[+] Saved backup into Central Vault: " << backup_path.string() << std::endl;
        std::cout << "[+] Safely removed plaintext .env from workspace." << std::endl;
        std::cout << "[+] AI agents can no longer read secrets from disk. Use 'slug env run -- <cmd>'." << std::endl;
        std::cout << "[+] Generated AI directive at .slug/ai-rule.md" << std::endl;
    }

    return true;
}

bool EnvShield::restore(const fs::path& workspace_root) {
    fs::path env_file = workspace_root / ".env";
    fs::path env_pqc_file = workspace_root / ".env.pqc";
    fs::path vault_dir = get_vault_dir(workspace_root);

    std::string restored_content;
    bool found_in_vault = false;

    // Check Central Vault first
    auto hist = history(workspace_root);
    if (!hist.empty()) {
        const auto& latest = hist.back();
        fs::path backup_file = vault_dir / latest.filename;
        if (fs::exists(backup_file)) {
            auto data = platform::PathUtils::read_text_file(backup_file);
            if (data) {
                restored_content = *data;
                found_in_vault = true;
                std::cout << "[+] Found backup in Central Vault: " << latest.filename
                          << " (v" << latest.version << ")" << std::endl;
            }
        }
    }

    // Fallback: If not found in vault, decrypt directly from .env.pqc
    if (!found_in_vault) {
        if (fs::exists(env_pqc_file)) {
            std::cout << "[*] Central Vault backup not found, attempting PQC direct decryption..." << std::endl;
            auto dec = decrypt_env_file(workspace_root);
            if (dec) {
                restored_content = *dec;
            } else {
                std::cerr << "[-] Error: Failed to decrypt .env.pqc for restoration." << std::endl;
                return false;
            }
        } else {
            std::cerr << "[-] Error: Neither Central Vault backup nor .env.pqc was found." << std::endl;
            return false;
        }
    }

    // Write restored plaintext .env
    if (!platform::PathUtils::write_text_file_atomic(env_file, restored_content)) {
        std::cerr << "[-] Error: Failed to write restored .env file." << std::endl;
        return false;
    }

    // Remove .env.pqc
    std::error_code ec;
    if (fs::exists(env_pqc_file, ec)) {
        fs::remove(env_pqc_file, ec);
    }

    std::cout << "[+] Successfully restored plaintext .env" << std::endl;
    std::cout << "[+] Removed .env.pqc from workspace. Project returned to traditional state." << std::endl;
    return true;
}

int EnvShield::run(const fs::path& workspace_root, const std::vector<std::string>& command_and_args) {
    auto env_str_opt = decrypt_env_file(workspace_root);
    if (!env_str_opt) {
        return 1;
    }

    auto env_map = parse_env_content(*env_str_opt);
    OPENSSL_cleanse(env_str_opt->data(), env_str_opt->size());

    std::cout << "[+] Injected " << env_map.size() << " environment variables from RAM directly into process" << std::endl;
    return platform::ProcessUtils::run_process_with_env(command_and_args, env_map);
}

} // namespace slug::envshield
