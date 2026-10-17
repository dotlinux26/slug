#pragma once

#include "src/crypto/xchacha20poly1305.hpp"
#include "src/crypto/blake3_wrapper.hpp"
#include "src/net/sliding_window.hpp"
#include "src/platform/socket.hpp"
#include <array>
#include <span>
#include <vector>
#include <optional>
#include <cstdint>
#include <cstring>

namespace slug::net {

struct SessionKeys {
    std::array<uint8_t, 32> session_key{};
    std::array<uint8_t, 16> client_to_server_salt{};
    std::array<uint8_t, 16> server_to_client_salt{};

    static SessionKeys derive(std::span<const uint8_t> shared_secret,
                              std::span<const uint8_t> client_random,
                              std::span<const uint8_t> server_random) {
        std::vector<uint8_t> mat;
        mat.reserve(shared_secret.size() + client_random.size() + server_random.size());
        mat.insert(mat.end(), shared_secret.begin(), shared_secret.end());
        mat.insert(mat.end(), client_random.begin(), client_random.end());
        mat.insert(mat.end(), server_random.begin(), server_random.end());

        SessionKeys keys;
        keys.session_key = crypto::Blake3::derive_key("slug-session-key-v1", mat);
        auto c2s = crypto::Blake3::derive_key("slug-c2s-salt-v1", mat);
        std::memcpy(keys.client_to_server_salt.data(), c2s.data(), 16);
        auto s2c = crypto::Blake3::derive_key("slug-s2c-salt-v1", mat);
        std::memcpy(keys.server_to_client_salt.data(), s2c.data(), 16);
        return keys;
    }
};

class AeadFrameChannel {
public:
    static std::array<uint8_t, 24> make_nonce(std::span<const uint8_t, 16> salt, uint64_t seq_num) {
        std::array<uint8_t, 24> nonce{};
        std::memcpy(nonce.data(), salt.data(), 16);
        for (int i = 7; i >= 0; --i) {
            nonce[16 + (7 - i)] = static_cast<uint8_t>((seq_num >> (i * 8)) & 0xFF);
        }
        return nonce;
    }

    static bool send_frame(platform::TcpSocket& sock,
                           std::span<const uint8_t, 32> key,
                           std::span<const uint8_t, 16> salt,
                           uint64_t seq_num,
                           std::span<const uint8_t> plaintext) {
        auto nonce = make_nonce(salt, seq_num);

        // AAD = [Len(4B) || SeqNum(8B)]
        uint32_t cipher_len = static_cast<uint32_t>(plaintext.size() + crypto::XChaCha20Poly1305::kTagSize);
        std::array<uint8_t, 12> aad{};
        aad[0] = static_cast<uint8_t>((cipher_len >> 24) & 0xFF);
        aad[1] = static_cast<uint8_t>((cipher_len >> 16) & 0xFF);
        aad[2] = static_cast<uint8_t>((cipher_len >> 8) & 0xFF);
        aad[3] = static_cast<uint8_t>(cipher_len & 0xFF);
        for (int i = 7; i >= 0; --i) {
            aad[4 + (7 - i)] = static_cast<uint8_t>((seq_num >> (i * 8)) & 0xFF);
        }

        auto cipher_and_tag = crypto::XChaCha20Poly1305::encrypt(plaintext, key, nonce, aad);

        std::vector<uint8_t> frame(12 + cipher_and_tag.size());
        std::memcpy(frame.data(), aad.data(), 12);
        std::memcpy(frame.data() + 12, cipher_and_tag.data(), cipher_and_tag.size());

        return sock.send_all(frame);
    }

    static std::optional<std::vector<uint8_t>> recv_frame(platform::TcpSocket& sock,
                                                          std::span<const uint8_t, 32> key,
                                                          std::span<const uint8_t, 16> salt,
                                                          AntiReplaySlidingWindow& sliding_window,
                                                          int timeout_ms = 10000) {
        std::array<uint8_t, 12> hdr{};
        if (!sock.receive_exact(std::span<uint8_t>(hdr), timeout_ms)) {
            return std::nullopt;
        }

        uint32_t cipher_len = (static_cast<uint32_t>(hdr[0]) << 24) |
                              (static_cast<uint32_t>(hdr[1]) << 16) |
                              (static_cast<uint32_t>(hdr[2]) << 8)  |
                               static_cast<uint32_t>(hdr[3]);

        uint64_t seq_num = 0;
        for (int i = 0; i < 8; ++i) {
            seq_num = (seq_num << 8) | hdr[4 + i];
        }

        // Check Anti-Replay
        if (!sliding_window.check(seq_num)) {
            return std::nullopt; // Replay packet dropped!
        }

        if (cipher_len < crypto::XChaCha20Poly1305::kTagSize || cipher_len > 16 * 1024 * 1024) {
            return std::nullopt;
        }

        std::vector<uint8_t> cipher_and_tag(cipher_len);
        if (!sock.receive_exact(std::span<uint8_t>(cipher_and_tag), timeout_ms)) {
            return std::nullopt;
        }

        auto nonce = make_nonce(salt, seq_num);
        auto plaintext_opt = crypto::XChaCha20Poly1305::decrypt(cipher_and_tag, key, nonce, hdr);
        if (!plaintext_opt) {
            return std::nullopt; // Tag verification failed!
        }

        sliding_window.update(seq_num);
        return plaintext_opt;
    }
};

} // namespace slug::net
