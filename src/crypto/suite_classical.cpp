#include "src/crypto/crypto_suite.hpp"
#include "src/crypto/sha256.hpp"
#include "src/core/utils.hpp"
#include <openssl/evp.h>
#include <cstring>

namespace slug::crypto {

class ClassicalCryptoSuite : public ICryptoSuite {
public:
    core::SuiteID id() const override {
        return core::SuiteID::SUITE_1_CLASSICAL;
    }

    std::string name() const override {
        return "Suite 1: Classical (SHA-256/Ed25519/X25519/XChaCha)";
    }

    std::vector<uint8_t> hash(std::span<const uint8_t> data) const override {
        auto h = Sha256::hash(data);
        return std::vector<uint8_t>(h.begin(), h.end());
    }

    std::array<uint8_t, 32> kdf(
        std::span<const uint8_t> shared_secret,
        std::string_view context,
        std::span<const uint8_t> salt) const override {
        return Sha256::kdf(shared_secret, context, salt);
    }

    KemKeyPair generate_kem_keypair() const override {
        EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
        if (!pkey) return {};

        size_t pub_len = 32, priv_len = 32;
        std::vector<uint8_t> pub(32), priv(32);
        EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len);
        EVP_PKEY_get_raw_private_key(pkey, priv.data(), &priv_len);
        EVP_PKEY_free(pkey);
        return {pub, priv};
    }

    std::optional<KemEncapsulation> encapsulate(std::span<const uint8_t> peer_pubkey) const override {
        if (peer_pubkey.size() != 32) return std::nullopt;

        // Ephemeral X25519 keypair
        EVP_PKEY *eph = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
        if (!eph) return std::nullopt;

        size_t eph_pub_len = 32;
        std::vector<uint8_t> eph_pub(32);
        EVP_PKEY_get_raw_public_key(eph, eph_pub.data(), &eph_pub_len);

        EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pubkey.data(), 32);
        if (!peer) {
            EVP_PKEY_free(eph);
            return std::nullopt;
        }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(eph, nullptr);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, peer);
        size_t secret_len = 0;
        EVP_PKEY_derive(ctx, nullptr, &secret_len);
        std::vector<uint8_t> secret(secret_len);
        EVP_PKEY_derive(ctx, secret.data(), &secret_len);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer);
        EVP_PKEY_free(eph);

        return KemEncapsulation{eph_pub, secret};
    }

    std::optional<std::vector<uint8_t>> decapsulate(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> private_key) const override {

        if (ciphertext.size() != 32 || private_key.size() != 32) return std::nullopt;

        EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), 32);
        EVP_PKEY *eph_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, ciphertext.data(), 32);
        if (!priv || !eph_pub) {
            if (priv) EVP_PKEY_free(priv);
            if (eph_pub) EVP_PKEY_free(eph_pub);
            return std::nullopt;
        }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, nullptr);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, eph_pub);
        size_t secret_len = 0;
        EVP_PKEY_derive(ctx, nullptr, &secret_len);
        std::vector<uint8_t> secret(secret_len);
        EVP_PKEY_derive(ctx, secret.data(), &secret_len);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(eph_pub);
        EVP_PKEY_free(priv);
        return secret;
    }

    SigKeyPair generate_sig_keypair() const override {
        EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
        if (!pkey) return {};

        size_t pub_len = 32, priv_len = 32;
        std::vector<uint8_t> pub(32), priv(32);
        EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len);
        EVP_PKEY_get_raw_private_key(pkey, priv.data(), &priv_len);
        EVP_PKEY_free(pkey);
        return {pub, priv};
    }

    std::optional<std::vector<uint8_t>> sign(
        std::span<const uint8_t> message,
        std::span<const uint8_t> private_key) const override {

        if (private_key.size() != 32) return std::nullopt;
        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key.data(), 32);
        if (!pkey) return std::nullopt;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        EVP_DigestSignInit_ex(mctx, nullptr, nullptr, nullptr, nullptr, pkey, nullptr);
        size_t sig_len = 0;
        EVP_DigestSign(mctx, nullptr, &sig_len, message.data(), message.size());
        std::vector<uint8_t> sig(sig_len);
        EVP_DigestSign(mctx, sig.data(), &sig_len, message.data(), message.size());

        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return sig;
    }

    bool verify(
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> public_key) const override {

        if (public_key.size() != 32) return false;
        EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key.data(), 32);
        if (!pkey) return false;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit_ex(mctx, nullptr, nullptr, nullptr, nullptr, pkey, nullptr);
        int res = EVP_DigestVerify(mctx, signature.data(), signature.size(), message.data(), message.size());

        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return (res == 1);
    }
};

std::unique_ptr<ICryptoSuite> create_suite_classical() {
    return std::make_unique<ClassicalCryptoSuite>();
}

} // namespace slug::crypto
