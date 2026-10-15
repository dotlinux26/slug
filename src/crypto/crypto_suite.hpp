#pragma once

#include "src/core/types.hpp"
#include "src/crypto/xchacha20poly1305.hpp"
#include <string>
#include <vector>
#include <array>
#include <span>
#include <memory>
#include <optional>

namespace slug::crypto {

struct KemKeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
};

struct KemEncapsulation {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> shared_secret;
};

struct SigKeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
};

class ICryptoSuite {
public:
    virtual ~ICryptoSuite() = default;

    virtual core::SuiteID id() const = 0;
    virtual std::string name() const = 0;

    // Content & transcript hash
    virtual std::vector<uint8_t> hash(std::span<const uint8_t> data) const = 0;

    // Session Key Derivation Function
    virtual std::array<uint8_t, 32> kdf(
        std::span<const uint8_t> shared_secret,
        std::string_view context,
        std::span<const uint8_t> salt = {}) const = 0;

    // Key encapsulation mechanism (KEM / ECDH)
    virtual KemKeyPair generate_kem_keypair() const = 0;
    virtual std::optional<KemEncapsulation> encapsulate(std::span<const uint8_t> peer_pubkey) const = 0;
    virtual std::optional<std::vector<uint8_t>> decapsulate(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> private_key) const = 0;

    // Digital signature for identity, session certificate, and manifest signing
    virtual SigKeyPair generate_sig_keypair() const = 0;
    virtual std::optional<std::vector<uint8_t>> sign(
        std::span<const uint8_t> message,
        std::span<const uint8_t> private_key) const = 0;
    virtual bool verify(
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> public_key) const = 0;

    // Stream / Chunk AEAD: All 3 suites use XChaCha20-Poly1305 with 24-byte nonce
    std::vector<uint8_t> aead_encrypt(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t, 32> key,
        std::span<const uint8_t, 24> nonce,
        std::span<const uint8_t> aad = {}) const {
        return XChaCha20Poly1305::encrypt(plaintext, key, nonce, aad);
    }

    std::optional<std::vector<uint8_t>> aead_decrypt(
        std::span<const uint8_t> ciphertext_and_tag,
        std::span<const uint8_t, 32> key,
        std::span<const uint8_t, 24> nonce,
        std::span<const uint8_t> aad = {}) const {
        return XChaCha20Poly1305::decrypt(ciphertext_and_tag, key, nonce, aad);
    }

    // Factory
    static std::unique_ptr<ICryptoSuite> create(core::SuiteID id);
};

} // namespace slug::crypto
