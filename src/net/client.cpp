#include "src/net/client.hpp"
#include "src/net/protocol.hpp"
#include "src/platform/fs.hpp"
#include "src/core/utils.hpp"
#include "src/crypto/blake3_wrapper.hpp"
#include "third_party/json/json.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <algorithm>

namespace slug::net {


namespace fs = std::filesystem;
using json = nlohmann::json;

SlugClient::SlugClient() = default;

SlugClient::SlugClient(const std::string& host, uint16_t port, core::SuiteID suite_id) {
    suite_id_ = suite_id;
    connect(host, port);
}

SlugClient::~SlugClient() {
    disconnect();
}

void SlugClient::disconnect() {
    socket_.close();
    session_id_ = 0;
    session_ticket_.clear();
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
        session_ticket_ = res.web_ticket;
        session_ttl_ = res.ttl;
        expires_at_ = (res.ttl > 0) ? (core::Utils::current_timestamp() + res.ttl) : 0;
        workspace_name_ = res.workspace_name;
        identity_ = "totp_" + core::role_to_string(res.role);
        auth_type_ = "totp";
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
    if (!role.empty()) {
        req["role"] = role;
    }
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
        session_ticket_ = res.web_ticket;
        session_ttl_ = res.ttl;
        expires_at_ = (res.ttl > 0) ? (core::Utils::current_timestamp() + res.ttl) : 0;
        workspace_name_ = res.workspace_name;
        identity_ = username;
        auth_type_ = "account";
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
        session_ticket_ = res.web_ticket;
        session_ttl_ = res.ttl;
        expires_at_ = (res.ttl > 0) ? (core::Utils::current_timestamp() + res.ttl) : 0;
        workspace_name_ = res.workspace_name;
        identity_ = "ticket";
        auth_type_ = "ticket";
    } else {
        res.success = false;
        res.message = resp.value("message", "Ticket authentication failed");
    }
    return res;
}

bool SlugClient::authenticate_user(const std::string& username, const std::string& password, uint64_t ttl, bool save) {
    (void)ttl;
    (void)save;
    auto r = authenticate_user(username, password, "");
    if (r.success) {
        session_ticket_ = r.web_ticket;
        session_ttl_ = r.ttl;
        expires_at_ = (r.ttl > 0) ? (core::Utils::current_timestamp() + r.ttl) : 0;
        workspace_name_ = r.workspace_name;
        identity_ = username;
        auth_type_ = "account";
        return true;
    }
    last_error_ = r.message;
    return false;
}

bool SlugClient::authenticate_token(const std::string& token_or_ticket, uint64_t ttl, bool save) {
    (void)ttl;
    (void)save;
    if (token_or_ticket.size() == 8 && std::all_of(token_or_ticket.begin(), token_or_ticket.end(), ::isdigit)) {
        auto r = authenticate_totp(token_or_ticket);
        if (r.success) {
            session_ticket_ = r.web_ticket;
            session_ttl_ = r.ttl;
            expires_at_ = (r.ttl > 0) ? (core::Utils::current_timestamp() + r.ttl) : 0;
            workspace_name_ = r.workspace_name;
            identity_ = "totp_" + core::role_to_string(r.role);
            auth_type_ = "totp";
            return true;
        }
        last_error_ = r.message;
        return false;
    }
    auto r = authenticate_ticket(token_or_ticket);
    if (r.success) {
        session_ticket_ = r.web_ticket;
        session_ttl_ = r.ttl;
        expires_at_ = (r.ttl > 0) ? (core::Utils::current_timestamp() + r.ttl) : 0;
        workspace_name_ = r.workspace_name;
        identity_ = "ticket";
        auth_type_ = "ticket";
        return true;
    }
    last_error_ = r.message;
    return false;
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
    if (!resp_opt) {
        last_error_ = "Timeout waiting for server chunk response";
        return std::nullopt;
    }

    const auto& resp = *resp_opt;
    if (resp.value("status", "") != "ok") {
        last_error_ = resp.value("message", "Server rejected chunk request");
        return std::nullopt;
    }

    std::string b64 = resp.value("data_b64", "");
    return core::Utils::from_base64(b64);
}

bool SlugClient::stream_pull_to_sink(const std::string& remote_path,
                                    StreamHeaderCallback on_header,
                                    StreamChunkCallback on_chunk,
                                    const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
                                    StreamProgressCallback progress_cb,
                                    std::atomic<bool>* cancel_flag) {
    if (!is_connected()) {
        last_error_ = "Client not connected or not encrypted";
        return false;
    }

    std::string norm_remote = remote_path;
    std::replace(norm_remote.begin(), norm_remote.end(), '\\', '/');
    while (!norm_remote.empty() && norm_remote.front() == '/') norm_remote.erase(0, 1);

    static std::atomic<uint32_t> s_transfer_seq{100};
    uint32_t transfer_id = s_transfer_seq++;

    json req;
    req["type"] = "start_stream_pull";
    req["path"] = norm_remote;
    req["transfer_id"] = transfer_id;
    if (!ranges.empty()) {
        json r_arr = json::array();
        for (const auto& [ro, rl] : ranges) {
            json rj;
            rj["offset"] = ro;
            rj["length"] = rl;
            r_arr.push_back(rj);
        }
        req["ranges"] = r_arr;
    }

    if (!send_json(req)) {
        last_error_ = "Failed to send start_stream_pull request";
        return false;
    }

    auto resp_opt = recv_json(15000);
    if (!resp_opt) {
        last_error_ = "Timeout waiting for server to open stream pull";
        return false;
    }

    const auto& resp = *resp_opt;
    if (resp.value("status", "") != "ok") {
        last_error_ = resp.value("message", "Server rejected stream pull request");
        return false;
    }

    uint64_t remote_file_size = resp.value("file_size", 0ULL);
    std::string final_blake3 = resp.value("blake3_hash", "");

    if (on_header) {
        if (!on_header(remote_file_size, final_blake3)) {
            StreamDataFrameHeader abort_hdr{};
            abort_hdr.magic = 0x53;
            abort_hdr.frame_type = static_cast<uint8_t>(StreamFrameType::ABORT);
            abort_hdr.transfer_id = transfer_id;
            std::span<const uint8_t> pt(reinterpret_cast<const uint8_t*>(&abort_hdr), sizeof(abort_hdr));
            AeadFrameChannel::send_frame(socket_, session_keys_.session_key, session_keys_.client_to_server_salt, tx_seq_++, pt);
            last_error_ = "Stream aborted by header handler";
            return false;
        }
    }

    uint64_t bytes_received = 0;
    auto start_time = std::chrono::steady_clock::now();
    auto last_update_time = start_time;
    uint64_t last_bytes = 0;
    double smoothed_mbps = 0.0;
    bool pull_ok = false;

    while (true) {
        if (cancel_flag && cancel_flag->load()) {
            last_error_ = "Transfer cancelled by user";
            StreamDataFrameHeader abort_hdr{};
            abort_hdr.magic = 0x53;
            abort_hdr.frame_type = static_cast<uint8_t>(StreamFrameType::ABORT);
            abort_hdr.transfer_id = transfer_id;
            std::span<const uint8_t> pt(reinterpret_cast<const uint8_t*>(&abort_hdr), sizeof(abort_hdr));
            AeadFrameChannel::send_frame(socket_, session_keys_.session_key, session_keys_.client_to_server_salt, tx_seq_++, pt);
            break;
        }

        auto frame_opt = AeadFrameChannel::recv_frame(socket_, session_keys_.session_key, session_keys_.server_to_client_salt, s2c_window_, 60000);
        if (!frame_opt) {
            last_error_ = "Timeout or integrity failure reading stream frame";
            break;
        }

        const auto& frame_bytes = *frame_opt;
        if (frame_bytes.size() < sizeof(StreamDataFrameHeader)) {
            last_error_ = "Malformed frame header received";
            break;
        }

        StreamDataFrameHeader hdr;
        std::memcpy(&hdr, frame_bytes.data(), sizeof(StreamDataFrameHeader));
        if (hdr.magic != 0x53 || hdr.transfer_id != transfer_id) {
            last_error_ = "Frame magic or transfer_id mismatch";
            break;
        }

        if (hdr.frame_type == static_cast<uint8_t>(StreamFrameType::ABORT)) {
            last_error_ = "Transfer aborted by server";
            break;
        }

        if (hdr.frame_type == static_cast<uint8_t>(StreamFrameType::DATA)) {
            if (frame_bytes.size() < sizeof(StreamDataFrameHeader) + hdr.payload_len) {
                last_error_ = "Truncated frame payload";
                break;
            }
            const uint8_t* payload = frame_bytes.data() + sizeof(StreamDataFrameHeader);
            if (on_chunk) {
                if (!on_chunk(payload, hdr.payload_len, hdr.offset)) {
                    StreamDataFrameHeader abort_hdr{};
                    abort_hdr.magic = 0x53;
                    abort_hdr.frame_type = static_cast<uint8_t>(StreamFrameType::ABORT);
                    abort_hdr.transfer_id = transfer_id;
                    std::span<const uint8_t> pt(reinterpret_cast<const uint8_t*>(&abort_hdr), sizeof(abort_hdr));
                    AeadFrameChannel::send_frame(socket_, session_keys_.session_key, session_keys_.client_to_server_salt, tx_seq_++, pt);
                    last_error_ = "Stream aborted by sink handler";
                    break;
                }
            }
            bytes_received += hdr.payload_len;

            auto now = std::chrono::steady_clock::now();
            double elapsed_sec = std::chrono::duration<double>(now - last_update_time).count();
            if (elapsed_sec >= 0.25) {
                double inst_speed = (static_cast<double>(bytes_received - last_bytes) / (1024.0 * 1024.0)) / elapsed_sec;
                smoothed_mbps = (smoothed_mbps == 0.0) ? inst_speed : (0.7 * smoothed_mbps + 0.3 * inst_speed);
                last_bytes = bytes_received;
                last_update_time = now;
                if (progress_cb) {
                    progress_cb(bytes_received, remote_file_size, smoothed_mbps);
                }
            }
        } else if (hdr.frame_type == static_cast<uint8_t>(StreamFrameType::END_OF_STREAM)) {
            if (progress_cb) {
                auto total_elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start_time).count();
                double avg_speed = (total_elapsed > 0) ? (static_cast<double>(bytes_received) / (1024.0 * 1024.0) / total_elapsed) : smoothed_mbps;
                progress_cb(remote_file_size, remote_file_size, avg_speed);
            }
            pull_ok = true;
            break;
        }
    }

    return pull_ok;
}

bool SlugClient::stream_pull_file(const std::string& remote_path,
                                  const fs::path& local_dest,
                                  uint64_t expected_size,
                                  const std::string& expected_hash,
                                  const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
                                  StreamProgressCallback progress_cb,
                                  std::atomic<bool>* cancel_flag) {
    if (!is_connected()) {
        last_error_ = "Client not connected or not encrypted";
        return false;
    }

    std::string norm_remote = remote_path;
    std::replace(norm_remote.begin(), norm_remote.end(), '\\', '/');
    while (!norm_remote.empty() && norm_remote.front() == '/') norm_remote.erase(0, 1);

    static std::atomic<uint32_t> s_file_tmp_seq{1000};
    uint32_t tmp_id = s_file_tmp_seq++;

    // Resolve destination path
    fs::path final_dest = local_dest;
    if (final_dest.empty()) {
        final_dest = fs::path(norm_remote).filename();
    } else if (fs::is_directory(final_dest)) {
        final_dest = final_dest / fs::path(norm_remote).filename();
    }

    platform::PathUtils::ensure_directory(final_dest.parent_path());

    // Temporary download file (.slug_tmp.<tid>)
    fs::path temp_dest = final_dest.parent_path() / (final_dest.filename().string() + ".slug_tmp." + std::to_string(tmp_id));

    // If partial ranges and base file exists, copy existing file as base
    if (!ranges.empty() && fs::exists(final_dest)) {
        std::error_code ec_cp;
        fs::copy_file(final_dest, temp_dest, fs::copy_options::overwrite_existing, ec_cp);
    }

    std::ofstream out;
    std::string final_blake3 = expected_hash;

    auto on_header = [&](uint64_t remote_file_size, const std::string& hash) -> bool {
        (void)remote_file_size;
        if (!hash.empty()) final_blake3 = hash;
        out.open(temp_dest, std::ios::binary | (ranges.empty() ? std::ios::trunc : (std::ios::in | std::ios::out)));
        if (!out.is_open()) {
            out.open(temp_dest, std::ios::binary | std::ios::trunc);
            if (!out.is_open()) {
                last_error_ = "Failed to open temporary file for writing: " + temp_dest.string();
                return false;
            }
        }
        return true;
    };

    auto on_chunk = [&](const uint8_t* payload, size_t payload_len, uint64_t offset) -> bool {
        if (!out.is_open()) return false;
        out.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
        out.write(reinterpret_cast<const char*>(payload), payload_len);
        return out.good();
    };

    bool pull_ok = stream_pull_to_sink(norm_remote, on_header, on_chunk, ranges, progress_cb, cancel_flag);

    if (out.is_open()) {
        out.flush();
        out.close();
    }

    if (pull_ok) {
        // Verify BLAKE3 hash of complete assembled file
        std::string actual_hash = crypto::Blake3::hash_file(temp_dest).value_or("");
        if (!final_blake3.empty() && actual_hash != final_blake3) {
            last_error_ = "Integrity check failed: BLAKE3 hash mismatch on " + remote_path;
            std::error_code ec;
            fs::remove(temp_dest, ec);
            return false;
        }

        // Commit atomically
        std::error_code ec_ren;
        fs::rename(temp_dest, final_dest, ec_ren);
        if (ec_ren) {
            fs::copy_file(temp_dest, final_dest, fs::copy_options::overwrite_existing, ec_ren);
            fs::remove(temp_dest, ec_ren);
        }
        return true;
    } else {
        std::error_code ec;
        fs::remove(temp_dest, ec);
        return false;
    }
}

bool SlugClient::stream_push_file(const fs::path& local_file,
                                  const std::string& remote_dest,
                                  StreamProgressCallback progress_cb,
                                  std::atomic<bool>* cancel_flag) {
    if (!is_connected()) {
        last_error_ = "Client not connected or not encrypted";
        return false;
    }

    std::error_code ec;
    if (!fs::exists(local_file, ec) || fs::is_directory(local_file, ec)) {
        last_error_ = "Local file does not exist or is a directory: " + local_file.string();
        return false;
    }

    uint64_t file_size = fs::file_size(local_file, ec);
    auto hash_opt = crypto::Blake3::hash_file(local_file);
    if (!hash_opt) {
        last_error_ = "Failed to compute BLAKE3 hash for " + local_file.string();
        return false;
    }
    std::string file_hash = *hash_opt;

    std::string norm_dest = remote_dest;
    std::replace(norm_dest.begin(), norm_dest.end(), '\\', '/');
    while (!norm_dest.empty() && norm_dest.front() == '/') norm_dest.erase(0, 1);

    static std::atomic<uint32_t> s_transfer_seq{500};
    uint32_t transfer_id = s_transfer_seq++;

    json req;
    req["type"] = "start_stream_push";
    req["path"] = norm_dest;
    req["transfer_id"] = transfer_id;
    req["file_size"] = file_size;
    req["blake3_hash"] = file_hash;

    if (!send_json(req)) {
        last_error_ = "Failed to send start_stream_push request";
        return false;
    }

    auto resp_opt = recv_json(15000);
    if (!resp_opt) {
        last_error_ = "Timeout waiting for server to accept stream push";
        return false;
    }

    const auto& resp = *resp_opt;
    if (resp.value("status", "") != "ok") {
        last_error_ = resp.value("message", "Server rejected stream push");
        return false;
    }

    std::ifstream src(local_file, std::ios::binary);
    if (!src.is_open()) {
        last_error_ = "Cannot open local file for reading: " + local_file.string();
        return false;
    }

    uint64_t bytes_sent = 0;
    auto start_time = std::chrono::steady_clock::now();
    auto last_update_time = start_time;
    uint64_t last_bytes = 0;
    double smoothed_mbps = 0.0;
    bool stream_ok = true;

    std::vector<uint8_t> frame_buf(sizeof(StreamDataFrameHeader) + kStreamPayloadChunkSize);

    while (bytes_sent < file_size && stream_ok) {
        if (cancel_flag && cancel_flag->load()) {
            last_error_ = "Upload cancelled by user";
            StreamDataFrameHeader abort_hdr{};
            abort_hdr.magic = 0x53;
            abort_hdr.frame_type = static_cast<uint8_t>(StreamFrameType::ABORT);
            abort_hdr.transfer_id = transfer_id;
            std::span<const uint8_t> pt(reinterpret_cast<const uint8_t*>(&abort_hdr), sizeof(abort_hdr));
            AeadFrameChannel::send_frame(socket_, session_keys_.session_key, session_keys_.client_to_server_salt, tx_seq_++, pt);
            return false;
        }

        size_t to_read = static_cast<size_t>(std::min<uint64_t>(kStreamPayloadChunkSize, file_size - bytes_sent));
        src.read(reinterpret_cast<char*>(frame_buf.data() + sizeof(StreamDataFrameHeader)), to_read);
        std::streamsize actual = src.gcount();
        if (actual <= 0) break;

        StreamDataFrameHeader* phdr = reinterpret_cast<StreamDataFrameHeader*>(frame_buf.data());
        phdr->magic = 0x53;
        phdr->frame_type = static_cast<uint8_t>(StreamFrameType::DATA);
        phdr->reserved = 0;
        phdr->transfer_id = transfer_id;
        phdr->offset = bytes_sent;
        phdr->payload_len = static_cast<uint32_t>(actual);

        std::span<const uint8_t> frame_span(frame_buf.data(), sizeof(StreamDataFrameHeader) + actual);
        if (!AeadFrameChannel::send_frame(socket_, session_keys_.session_key, session_keys_.client_to_server_salt, tx_seq_++, frame_span)) {
            last_error_ = "Socket write failed during streaming upload";
            stream_ok = false;
            break;
        }
        bytes_sent += actual;

        auto now = std::chrono::steady_clock::now();
        double elapsed_sec = std::chrono::duration<double>(now - last_update_time).count();
        if (elapsed_sec >= 0.25) {
            double inst_speed = (static_cast<double>(bytes_sent - last_bytes) / (1024.0 * 1024.0)) / elapsed_sec;
            smoothed_mbps = (smoothed_mbps == 0.0) ? inst_speed : (0.7 * smoothed_mbps + 0.3 * inst_speed);
            last_bytes = bytes_sent;
            last_update_time = now;
            if (progress_cb) {
                progress_cb(bytes_sent, file_size, smoothed_mbps);
            }
        }
    }

    if (!stream_ok) return false;

    // Send END_OF_STREAM
    std::vector<uint8_t> eos_buf(sizeof(StreamDataFrameHeader) + file_hash.size());
    StreamDataFrameHeader* peos = reinterpret_cast<StreamDataFrameHeader*>(eos_buf.data());
    peos->magic = 0x53;
    peos->frame_type = static_cast<uint8_t>(StreamFrameType::END_OF_STREAM);
    peos->reserved = 0;
    peos->transfer_id = transfer_id;
    peos->offset = file_size;
    peos->payload_len = static_cast<uint32_t>(file_hash.size());
    std::memcpy(eos_buf.data() + sizeof(StreamDataFrameHeader), file_hash.data(), file_hash.size());

    if (!AeadFrameChannel::send_frame(socket_, session_keys_.session_key, session_keys_.client_to_server_salt, tx_seq_++, eos_buf)) {
        last_error_ = "Failed to send END_OF_STREAM frame";
        return false;
    }

    // Wait for server's final commit response
    auto final_resp_opt = recv_json(30000);
    if (!final_resp_opt) {
        last_error_ = "Timeout waiting for server upload confirmation";
        return false;
    }

    const auto& final_resp = *final_resp_opt;
    if (final_resp.value("status", "") == "ok") {
        if (progress_cb) {
            auto total_elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start_time).count();
            double avg_speed = (total_elapsed > 0) ? (static_cast<double>(file_size) / (1024.0 * 1024.0) / total_elapsed) : smoothed_mbps;
            progress_cb(file_size, file_size, avg_speed);
        }
        return true;
    } else {
        last_error_ = final_resp.value("message", "Server rejected upload commit");
        return false;
    }
}

bool SlugClient::pull(const fs::path& local_target_dir,
                      const sync::DeltaSyncOptions& options,
                      std::function<void(const std::string&)> log_callback,
                      const std::optional<sync::WorkspaceManifest>& cached_manifest,
                      StreamProgressCallback progress_cb,
                      std::atomic<bool>* cancel_flag) {

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
        for (const auto& delta : plan.file_deltas) {
            if (delta.is_unchanged) {
                log("  [CACHE HIT] " + delta.relative_path + " (" + core::Utils::format_size(delta.total_size) + ", 0 bytes transferred)");
            }
        }
        log("New / Modified files to transfer: " + std::to_string(plan.count_new + plan.count_modified));
        for (const auto& delta : plan.file_deltas) {
            if (delta.is_new) {
                log("  [PULL NEW] " + delta.relative_path + " (" + core::Utils::format_size(delta.total_size) + ", " + std::to_string(delta.needed_chunk_indices.size()) + " chunks)");
            } else if (delta.is_modified) {
                log("  [PULL MODIFIED] " + delta.relative_path + " (" + core::Utils::format_size(delta.total_size) + ", " + std::to_string(delta.needed_chunk_indices.size()) + " chunks)");
            }
        }
        log("Bytes to transfer: " + core::Utils::format_size(plan.bytes_to_transfer));
        log("Bytes saved: " + core::Utils::format_size(plan.bytes_saved));
        if (options.prune) {
            log("Files to prune: " + std::to_string(plan.files_to_prune.size()));
            for (const auto& p : plan.files_to_prune) {
                log("  [PRUNE] " + p);
            }
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

    uint64_t total_job_transferred = 0;
    for (const auto& delta : plan.file_deltas) {
        if (delta.is_unchanged) continue;

        if (cancel_flag && cancel_flag->load()) {
            log("[*] Transfer cancelled by user.");
            return false;
        }

        auto safe_dest = platform::PathUtils::resolve_safe_path(local_target_dir, delta.relative_path);
        if (!safe_dest) {
            log("Security Warning: Remote path '" + delta.relative_path + "' attempted path traversal. Skipped!");
            continue;
        }
        fs::path dest = *safe_dest;

        // Find manifest entry for expected hash
        std::string expected_hash;
        for (const auto& rf : manifest.files) {
            if (rf.relative_path == delta.relative_path) {
                expected_hash = rf.file_blake3_hash;
                break;
            }
        }

        auto file_progress_cb = [&](uint64_t f_done, uint64_t f_total, double inst_mbps) {
            if (progress_cb) {
                progress_cb(total_job_transferred + f_done, plan.bytes_to_transfer, inst_mbps);
            }
        };

        bool ok = false;
        if (delta.is_new) {
            ok = stream_pull_file(delta.relative_path, dest, delta.total_size, expected_hash, {}, file_progress_cb, cancel_flag);
        } else if (delta.is_modified) {
            // Coalesce needed chunks into contiguous ranges
            std::vector<std::pair<uint64_t, uint64_t>> ranges;
            if (!delta.needed_chunk_indices.empty()) {
                auto sorted_indices = delta.needed_chunk_indices;
                std::sort(sorted_indices.begin(), sorted_indices.end());
                uint64_t cur_start = static_cast<uint64_t>(sorted_indices[0]) * sync::Chunker::kDefaultChunkSize;
                uint64_t cur_len = std::min<uint64_t>(sync::Chunker::kDefaultChunkSize, delta.total_size - cur_start);

                for (size_t i = 1; i < sorted_indices.size(); ++i) {
                    uint64_t next_offset = static_cast<uint64_t>(sorted_indices[i]) * sync::Chunker::kDefaultChunkSize;
                    if (next_offset == cur_start + cur_len) {
                        uint64_t add_len = std::min<uint64_t>(sync::Chunker::kDefaultChunkSize, delta.total_size - next_offset);
                        cur_len += add_len;
                    } else {
                        ranges.push_back({cur_start, cur_len});
                        cur_start = next_offset;
                        cur_len = std::min<uint64_t>(sync::Chunker::kDefaultChunkSize, delta.total_size - cur_start);
                    }
                }
                ranges.push_back({cur_start, cur_len});
            }
            ok = stream_pull_file(delta.relative_path, dest, delta.total_size, expected_hash, ranges, file_progress_cb, cancel_flag);
        }

        if (!ok) {
            std::string err_suffix = last_error_.empty() ? "" : " (" + last_error_ + ")";
            log("Error transferring " + delta.relative_path + err_suffix);
            return false;
        }

        uint64_t delta_bytes = delta.is_new ? delta.total_size : (delta.needed_chunk_indices.size() * sync::Chunker::kDefaultChunkSize);
        total_job_transferred += delta_bytes;
        log("Synced: " + delta.relative_path + " (" + core::Utils::format_size(delta.total_size) + ")");
    }

    // Prune if requested
    if (options.prune) {
        for (const auto& p : plan.files_to_prune) {
            auto safe_prune = platform::PathUtils::resolve_safe_path(local_target_dir, p);
            if (!safe_prune) continue;
            std::error_code ec;
            fs::remove(*safe_prune, ec);
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

    bool ok = stream_pull_file(remote_path, local_dest, 0, "", {}, nullptr, nullptr);
    if (ok) {
        log("Downloaded: " + remote_path + " -> " + local_dest.string());
    } else {
        log("Error downloading " + remote_path + ": " + last_error_);
    }
    return ok;
}

bool SlugClient::push(const fs::path& local_file,
                      const std::string& remote_dest,
                      std::function<void(const std::string&)> log_callback) {

    auto log = [&](const std::string& m) {
        if (log_callback) log_callback(m);
        else std::cout << m << std::endl;
    };

    bool ok = stream_push_file(local_file, remote_dest, nullptr, nullptr);
    if (ok) {
        log("Push successful: " + remote_dest);
    } else {
        log("Push rejected: " + last_error_);
    }
    return ok;
}


std::vector<uint8_t> SlugClient::tunnel_http(const std::string& raw_http_request) {
    if (!is_encrypted_) return {};
    json req;
    req["type"] = "http_tunnel";
    req["raw_req_b64"] = core::Utils::to_base64(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(raw_http_request.data()), raw_http_request.size()));

    if (!send_json(req)) return {};
    auto resp_opt = recv_json(60000);
    if (!resp_opt) return {};

    const auto& resp = *resp_opt;
    if (resp.value("status", "") != "ok") return {};
    std::string b64 = resp.value("raw_resp_b64", "");
    return core::Utils::from_base64(b64);
}

} // namespace slug::net
