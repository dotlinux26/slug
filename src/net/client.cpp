#include "src/net/client.hpp"
#include "src/platform/fs.hpp"
#include "src/core/utils.hpp"
#include "src/crypto/blake3_wrapper.hpp"
#include "third_party/json/json.hpp"
#include <iostream>

namespace slug::net {

namespace fs = std::filesystem;
using json = nlohmann::json;

SlugClient::SlugClient() = default;

SlugClient::~SlugClient() {
    disconnect();
}

void SlugClient::disconnect() {
    socket_.close();
    session_id_ = 0;
    is_encrypted_ = false;
    tx_seq_ = 1;
}

bool SlugClient::send_packet(const std::string& json_str) {
    if (is_encrypted_) {
        std::span<const uint8_t> bytes(reinterpret_cast<const uint8_t*>(json_str.data()), json_str.size());
        return AeadFrameChannel::send_frame(socket_, session_keys_.session_key, session_keys_.client_to_server_salt, tx_seq_++, bytes);
    } else {
        uint32_t len = static_cast<uint32_t>(json_str.size());
        uint8_t hdr[4];
        hdr[0] = static_cast<uint8_t>((len >> 24) & 0xFF);
        hdr[1] = static_cast<uint8_t>((len >> 16) & 0xFF);
        hdr[2] = static_cast<uint8_t>((len >> 8) & 0xFF);
        hdr[3] = static_cast<uint8_t>(len & 0xFF);
        if (!socket_.send_all(std::span<const uint8_t>(hdr, 4))) return false;
        return socket_.send_all(json_str);
    }
}

std::optional<std::string> SlugClient::recv_packet(int timeout_ms) {
    if (is_encrypted_) {
        auto dec = AeadFrameChannel::recv_frame(socket_, session_keys_.session_key, session_keys_.server_to_client_salt, s2c_window_, timeout_ms);
        if (!dec) return std::nullopt;
        return std::string(dec->begin(), dec->end());
    } else {
        uint8_t hdr[4];
        if (!socket_.receive_exact(std::span<uint8_t>(hdr, 4), timeout_ms)) return std::nullopt;
        uint32_t len = (static_cast<uint32_t>(hdr[0]) << 24) |
                       (static_cast<uint32_t>(hdr[1]) << 16) |
                       (static_cast<uint32_t>(hdr[2]) << 8)  |
                        static_cast<uint32_t>(hdr[3]);
        if (len > 50 * 1024 * 1024) return std::nullopt;
        std::vector<uint8_t> body(len);
        if (!socket_.receive_exact(std::span<uint8_t>(body), timeout_ms)) return std::nullopt;
        return std::string(body.begin(), body.end());
    }
}

bool SlugClient::send_json(const json& j) {
    return send_packet(j.dump());
}

std::optional<json> SlugClient::recv_json(int timeout_ms) {
    auto s = recv_packet(timeout_ms);
    if (!s) return std::nullopt;
    try {
        return json::parse(*s);
    } catch (...) {
        return std::nullopt;
    }
}

bool SlugClient::connect(const std::string& host, uint16_t port, int timeout_ms) {
    disconnect();
    is_encrypted_ = false;
    tx_seq_ = 1;

    if (!socket_.connect(host, port, timeout_ms)) {
        return false;
    }

    // Step 1: Handshake ClientHello
    std::vector<uint8_t> client_random = core::Utils::random_bytes(32);
    json ch;
    ch["type"] = "client_hello";
    ch["version"] = 1;
    ch["client_random"] = core::Utils::to_hex(client_random);
    if (!send_json(ch)) {
        disconnect();
        return false;
    }

    // Step 2: ServerHello
    auto sh_opt = recv_json(timeout_ms);
    if (!sh_opt) {
        disconnect();
        return false;
    }

    const auto& sh = *sh_opt;
    if (sh.value("type", "") != "server_hello") {
        disconnect();
        return false;
    }

    uint8_t sid = sh.value("suite_id", static_cast<uint8_t>(3));
    suite_id_ = static_cast<core::SuiteID>(sid);
    suite_name_ = sh.value("suite_name", "PurePQC");
    suite_ = crypto::ICryptoSuite::create(suite_id_);

    // Step 3: KEM Exchange & AEAD Key Derivation
    std::string server_kem_pub_hex = sh.value("server_kem_pub", "");
    std::string server_random_hex = sh.value("server_random", "");
    if (!server_kem_pub_hex.empty()) {
        auto server_kem_pub = core::Utils::from_hex(server_kem_pub_hex);
        auto server_random = core::Utils::from_hex(server_random_hex);
        auto kem_res = suite_->encapsulate(server_kem_pub);
        if (kem_res) {
            json kx;
            kx["type"] = "kem_exchange";
            kx["ciphertext"] = core::Utils::to_hex(kem_res->ciphertext);
            if (send_json(kx)) {
                auto ok_opt = recv_json(timeout_ms);
                if (ok_opt && ok_opt->value("type", "") == "kem_ok" && ok_opt->value("status", "") == "ok") {
                    session_keys_ = SessionKeys::derive(kem_res->shared_secret, client_random, server_random);
                    is_encrypted_ = true;
                    tx_seq_ = 1;
                }
            }
        }
    }

    return true;
}

ClientAuthResult SlugClient::authenticate_totp(const std::string& totp_code) {
    ClientAuthResult res;
    if (!socket_.is_valid()) {
        res.message = "Not connected";
        return res;
    }

    json req;
    req["type"] = "auth_totp";
    req["code"] = totp_code;
    if (!send_json(req)) {
        res.message = "Failed to send auth request";
        return res;
    }

    auto resp_opt = recv_json(5000);
    if (!resp_opt) {
        res.message = "No response from server";
        return res;
    }

    const auto& resp = *resp_opt;
    if (resp.value("status", "") == "ok") {
        res.success = true;
        res.session_id = resp.value("session_id", 0U);
        res.role = core::role_from_string(resp.value("role", "rw"));
        res.ttl = resp.value("ttl", 0ULL);
        res.web_ticket = resp.value("web_ticket", "");
        res.workspace_name = resp.value("workspace", "");
        res.message = resp.value("message", "Authenticated");

        session_id_ = res.session_id;
        role_ = res.role;
    } else {
        res.success = false;
        res.message = resp.value("message", "Authentication failed");
    }
    return res;
}

ClientAuthResult SlugClient::authenticate_user(const std::string& username, const std::string& password, const std::string& role) {
    ClientAuthResult res;
    if (!socket_.is_valid()) {
        res.message = "Not connected";
        return res;
    }

    json req;
    req["type"] = "auth_user";
    req["username"] = username;
    req["password"] = password;
    req["role"] = role;
    if (!send_json(req)) {
        res.message = "Failed to send auth request";
        return res;
    }

    auto resp_opt = recv_json(5000);
    if (!resp_opt) {
        res.message = "No response from server";
        return res;
    }

    const auto& resp = *resp_opt;
    if (resp.value("status", "") == "ok") {
        res.success = true;
        res.session_id = resp.value("session_id", 0U);
        res.role = core::role_from_string(resp.value("role", "r"));
        res.ttl = resp.value("ttl", 0ULL);
        res.web_ticket = resp.value("web_ticket", "");
        res.workspace_name = resp.value("workspace", "");
        res.message = resp.value("message", "Authenticated");

        session_id_ = res.session_id;
        role_ = res.role;
    } else {
        res.success = false;
        res.message = resp.value("message", "Authentication failed");
    }
    return res;
}

ClientAuthResult SlugClient::authenticate_ticket(const std::string& ticket) {
    ClientAuthResult res;
    if (!socket_.is_valid()) {
        res.message = "Not connected";
        return res;
    }

    json req;
    req["type"] = "auth_ticket";
    req["ticket"] = ticket;
    if (!send_json(req)) {
        res.message = "Failed to send auth request";
        return res;
    }

    auto resp_opt = recv_json(5000);
    if (!resp_opt) {
        res.message = "No response from server";
        return res;
    }

    const auto& resp = *resp_opt;
    if (resp.value("status", "") == "ok") {
        res.success = true;
        res.session_id = resp.value("session_id", 0U);
        res.role = core::role_from_string(resp.value("role", "r"));
        res.ttl = resp.value("ttl", 0ULL);
        res.web_ticket = ticket;
        res.workspace_name = resp.value("workspace", "");
        res.message = resp.value("message", "Authenticated via ticket");

        session_id_ = res.session_id;
        role_ = res.role;
    } else {
        res.success = false;
        res.message = resp.value("message", "Ticket authentication failed");
    }
    return res;
}

std::optional<sync::WorkspaceManifest> SlugClient::fetch_manifest() {
    if (!socket_.is_valid()) return std::nullopt;

    json req;
    req["type"] = "get_manifest";
    if (!send_json(req)) return std::nullopt;

    auto resp_opt = recv_json(10000);
    if (!resp_opt) return std::nullopt;

    const auto& resp = *resp_opt;
    if (resp.value("status", "") != "ok" || !resp.contains("manifest")) {
        return std::nullopt;
    }

    return sync::WorkspaceManifest::from_json(resp["manifest"].dump());
}

std::optional<std::vector<uint8_t>> SlugClient::fetch_chunk(const std::string& rel_path, uint32_t chunk_idx) {
    json req;
    req["type"] = "get_chunk";
    req["path"] = rel_path;
    req["chunk_index"] = chunk_idx;
    if (!send_json(req)) return std::nullopt;

    auto resp_opt = recv_json(10000);
    if (!resp_opt) return std::nullopt;

    const auto& resp = *resp_opt;
    if (resp.value("status", "") != "ok") return std::nullopt;

    std::string b64 = resp.value("data_b64", "");
    return core::Utils::from_base64(b64);
}

bool SlugClient::pull(const fs::path& local_target_dir,
                      const sync::DeltaSyncOptions& options,
                      std::function<void(const std::string&)> log_callback,
                      const std::optional<sync::WorkspaceManifest>& cached_manifest) {

    auto log = [&](const std::string& m) {
        if (log_callback) log_callback(m);
        else std::cout << m << std::endl;
    };

    auto manifest_opt = cached_manifest ? cached_manifest : fetch_manifest();
    if (!manifest_opt) {
        log("Error: Failed to fetch workspace manifest");
        return false;
    }

    const auto& manifest = *manifest_opt;
    auto plan = sync::DeltaCalculator::compute_plan(manifest, local_target_dir, options);

    if (options.dry_run) {
        log("--- Delta Sync Dry-Run Summary ---");
        log("Remote files total: " + std::to_string(plan.total_files_remote));
        log("Unchanged (0 bytes sent): " + std::to_string(plan.count_unchanged));
        log("New files: " + std::to_string(plan.count_new));
        log("Modified files: " + std::to_string(plan.count_modified));
        log("Bytes to transfer: " + core::Utils::format_size(plan.bytes_to_transfer));
        log("Bytes saved: " + core::Utils::format_size(plan.bytes_saved));
        if (options.prune) {
            log("Files to prune: " + std::to_string(plan.files_to_prune.size()));
        }
        if (!plan.skipped_by_remote.empty()) {
            log("Skipped by remote policy/AI: " + std::to_string(plan.skipped_by_remote.size()) + " files");
            for (const auto& s : plan.skipped_by_remote) {
                log("  [SKIPPED] " + s.relative_path + " (" + s.reason + ")");
            }
        }
        return true;
    }

    // Execute transfer
    platform::PathUtils::ensure_directory(local_target_dir);

    for (const auto& delta : plan.file_deltas) {
        if (delta.is_unchanged) continue;

        fs::path dest = local_target_dir / delta.relative_path;
        platform::PathUtils::ensure_directory(dest.parent_path());

        // Read existing file if modifying
        std::vector<uint8_t> file_buf;
        if (delta.is_modified && fs::exists(dest)) {
            auto cur = platform::PathUtils::read_binary_file(dest);
            if (cur) file_buf = std::move(*cur);
        }
        if (file_buf.size() < delta.total_size) {
            file_buf.resize(delta.total_size);
        }

        // Fetch each needed chunk
        for (uint32_t chunk_idx : delta.needed_chunk_indices) {
            auto chunk_data = fetch_chunk(delta.relative_path, chunk_idx);
            if (!chunk_data) {
                log("Error downloading chunk " + std::to_string(chunk_idx) + " of " + delta.relative_path);
                return false;
            }

            uint64_t offset = static_cast<uint64_t>(chunk_idx) * sync::Chunker::kDefaultChunkSize;
            if (offset + chunk_data->size() > file_buf.size()) {
                file_buf.resize(offset + chunk_data->size());
            }
            std::memcpy(file_buf.data() + offset, chunk_data->data(), chunk_data->size());
        }

        // Verify full file BLAKE3 hash against remote manifest
        std::string computed_hash = crypto::Blake3::hash_hex(file_buf);
        for (const auto& rf : manifest.files) {
            if (rf.relative_path == delta.relative_path) {
                if (computed_hash != rf.file_blake3_hash) {
                    log("Warning: Hash mismatch on " + delta.relative_path);
                }
                break;
            }
        }

        // Write atomically
        platform::PathUtils::write_binary_file_atomic(dest, file_buf);
        log("Synced: " + delta.relative_path + " (" + core::Utils::format_size(delta.total_size) + ")");
    }

    // Prune if requested
    if (options.prune) {
        for (const auto& p : plan.files_to_prune) {
            fs::path dead_file = local_target_dir / p;
            std::error_code ec;
            fs::remove(dead_file, ec);
            log("Pruned: " + p);
        }
    }

    log("Pull complete! Transferred " + core::Utils::format_size(plan.bytes_to_transfer) +
        ", saved " + core::Utils::format_size(plan.bytes_saved) + " (Git-like Delta Sync)");
    return true;
}

bool SlugClient::get_file(const std::string& remote_path,
                          const fs::path& local_dest,
                          std::function<void(const std::string&)> log_callback) {
    auto log = [&](const std::string& m) {
        if (log_callback) log_callback(m);
        else std::cout << m << std::endl;
    };

    auto manifest_opt = fetch_manifest();
    if (!manifest_opt) {
        log("Error: Failed to fetch workspace manifest");
        return false;
    }

    std::string norm_remote = remote_path;
    std::replace(norm_remote.begin(), norm_remote.end(), '\\', '/');
    while (!norm_remote.empty() && norm_remote.front() == '/') norm_remote.erase(0, 1);

    const auto& manifest = *manifest_opt;
    const sync::ManifestFileEntry* target_entry = nullptr;
    for (const auto& f : manifest.files) {
        if (f.relative_path == norm_remote) {
            target_entry = &f;
            break;
        }
    }

    if (!target_entry) {
        for (const auto& s : manifest.skipped) {
            if (s.relative_path == norm_remote) {
                log("Error: File '" + norm_remote + "' is unavailable (" + s.reason + " - " + s.status + ")");
                return false;
            }
        }
        log("Error: Remote file '" + norm_remote + "' not found in workspace");
        return false;
    }

    std::vector<uint8_t> file_buf(target_entry->size);
    for (const auto& chunk : target_entry->chunks) {
        auto chunk_data = fetch_chunk(target_entry->relative_path, chunk.index);
        if (!chunk_data) {
            log("Error: Failed to download chunk " + std::to_string(chunk.index) + " for " + remote_path);
            return false;
        }
        uint64_t offset = chunk.offset;
        if (offset + chunk_data->size() > file_buf.size()) {
            file_buf.resize(offset + chunk_data->size());
        }
        std::memcpy(file_buf.data() + offset, chunk_data->data(), chunk_data->size());
    }

    std::string computed_hash = crypto::Blake3::hash_hex(file_buf);
    if (computed_hash != target_entry->file_blake3_hash) {
        log("Error: Hash verification failed for " + remote_path);
        return false;
    }

    fs::path final_dest = local_dest;
    if (fs::is_directory(final_dest)) {
        final_dest = final_dest / fs::path(remote_path).filename();
    }
    platform::PathUtils::ensure_directory(final_dest.parent_path());

    if (!platform::PathUtils::write_binary_file_atomic(final_dest, file_buf)) {
        log("Error: Failed to write downloaded file to " + final_dest.string());
        return false;
    }

    log("Downloaded: " + remote_path + " -> " + final_dest.string() + " (" + core::Utils::format_size(target_entry->size) + ") [BLAKE3: " + computed_hash.substr(0, 12) + "...]");
    return true;
}

bool SlugClient::push(const fs::path& local_file,
                      const std::string& remote_dest,
                      std::function<void(const std::string&)> log_callback) {

    auto log = [&](const std::string& m) {
        if (log_callback) log_callback(m);
        else std::cout << m << std::endl;
    };

    auto data = platform::PathUtils::read_binary_file(local_file);
    if (!data) {
        log("Error: Cannot read local file " + local_file.string());
        return false;
    }

    std::string norm_dest = remote_dest;
    std::replace(norm_dest.begin(), norm_dest.end(), '\\', '/');
    while (!norm_dest.empty() && norm_dest.front() == '/') norm_dest.erase(0, 1);

    json req;
    req["type"] = "push_file";
    req["path"] = norm_dest;
    req["data_b64"] = core::Utils::to_base64(*data);

    if (!send_json(req)) {
        log("Error: Failed to send push request");
        return false;
    }

    auto resp_opt = recv_json(15000);
    if (!resp_opt) {
        log("Error: No response from server");
        return false;
    }

    const auto& resp = *resp_opt;
    if (resp.value("status", "") == "ok") {
        log("Push successful: " + remote_dest + " (" + core::Utils::format_size(data->size()) + ")");
        return true;
    } else {
        log("Push rejected: " + resp.value("message", "Permission denied"));
        return false;
    }
}

} // namespace slug::net
