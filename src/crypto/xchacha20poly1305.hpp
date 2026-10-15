#pragma once

#include <vector>
#include <array>
#include <span>
#include <cstdint>
#include <string_view>
#include <optional>

namespace slug::crypto {

class XChaCha20Poly1305 {
public:
    static constexpr size_t kKeySize = 32;
    static constexpr size_t kNonceSize = 24;
    static constexpr size_t kTagSize = 16;

    // Encrypts plaintext with key and 24-byte nonce, authenticating aad.
    // Output format: ciphertext || 16-byte Poly1305 tag
    static std::vector<uint8_t> encrypt(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t, kKeySize> key,
        std::span<const uint8_t, kNonceSize> nonce,
        std::span<const uint8_t> aad = {});

    // Decrypts ciphertext (which must end with 16-byte Poly1305 tag)
    // Returns std::nullopt if tag verification fails.
    static std::optional<std::vector<uint8_t>> decrypt(
        std::span<const uint8_t> ciphertext_and_tag,
        std::span<const uint8_t, kKeySize> key,
        std::span<const uint8_t, kNonceSize> nonce,
        std::span<const uint8_t> aad = {});
};

} // namespace slug::crypto
