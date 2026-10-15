#include "src/crypto/crypto_suite.hpp"
#include "src/crypto/blake3_wrapper.hpp"
#include "src/core/utils.hpp"
#include <openssl/evp.h>
#include <cstring>

namespace slug::crypto {

class PurePqcCryptoSuite : public ICryptoSuite {
public:
    core::SuiteID id() const override {
        return core::SuiteID::SUITE_3_PURE_PQC;
    }

    std::string name() const override {
        return "Suite 3: PurePQC (BLAKE3/ML-DSA-65/ML-KEM-768/XChaCha)";
    }

    std::vector<uint8_t> hash(std::span<const uint8_t> data) const override {
        auto h = Blake3::hash(data);
        return std::vector<uint8_t>(h.begin(), h.end());
    }

    std::array<uint8_t, 32> kdf(
        std::span<const uint8_t> shared_secret,
        std::string_view context,
        std::span<const uint8_t> /*salt*/) const override {
        return Blake3::derive_key(context, shared_secret);
    }

    KemKeyPair generate_kem_keypair() const override {
        EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-KEM-768");
        if (!pkey) return {};

        size_t pub_len = 0, priv_len = 0;
        EVP_PKEY_get_raw_public_key(pkey, nullptr, &pub_len);
        std::vector<uint8_t> pub(pub_len);
        EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len);

        EVP_PKEY_get_raw_private_key(pkey, nullptr, &priv_len);
        std::vector<uint8_t> priv(priv_len);
        EVP_PKEY_get_raw_private_key(pkey, priv.data(), &priv_len);

        EVP_PKEY_free(pkey);
        return {pub, priv};
    }

    std::optional<KemEncapsulation> encapsulate(std::span<const uint8_t> peer_pubkey) const override {
        EVP_PKEY *peer = EVP_PKEY_new_raw_public_key_ex(nullptr, "ML-KEM-768", nullptr,
                                                        peer_pubkey.data(), peer_pubkey.size());
        if (!peer) return std::nullopt;

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, peer, nullptr);
        if (!ctx) {
            EVP_PKEY_free(peer);
            return std::nullopt;
        }

        if (EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer);
            return std::nullopt;
        }

        size_t ct_len = 0, ss_len = 0;
        EVP_PKEY_encapsulate(ctx, nullptr, &ct_len, nullptr, &ss_len);
        std::vector<uint8_t> ct(ct_len), ss(ss_len);

        if (EVP_PKEY_encapsulate(ctx, ct.data(), &ct_len, ss.data(), &ss_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer);
            return std::nullopt;
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer);
        return KemEncapsulation{ct, ss};
    }

    std::optional<std::vector<uint8_t>> decapsulate(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> private_key) const override {

        EVP_PKEY *priv = EVP_PKEY_new_raw_private_key_ex(nullptr, "ML-KEM-768", nullptr,
                                                         private_key.data(), private_key.size());
        if (!priv) return std::nullopt;

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, priv, nullptr);
        if (!ctx) {
            EVP_PKEY_free(priv);
            return std::nullopt;
        }

        if (EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(priv);
            return std::nullopt;
        }

        size_t ss_len = 0;
        EVP_PKEY_decapsulate(ctx, nullptr, &ss_len, ciphertext.data(), ciphertext.size());
        std::vector<uint8_t> ss(ss_len);

        if (EVP_PKEY_decapsulate(ctx, ss.data(), &ss_len, ciphertext.data(), ciphertext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(priv);
            return std::nullopt;
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv);
        return ss;
    }

    SigKeyPair generate_sig_keypair() const override {
        EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-DSA-65");
        if (!pkey) return {};

        size_t pub_len = 0, priv_len = 0;
        EVP_PKEY_get_raw_public_key(pkey, nullptr, &pub_len);
        std::vector<uint8_t> pub(pub_len);
        EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len);

        EVP_PKEY_get_raw_private_key(pkey, nullptr, &priv_len);
        std::vector<uint8_t> priv(priv_len);
        EVP_PKEY_get_raw_private_key(pkey, priv.data(), &priv_len);

        EVP_PKEY_free(pkey);
        return {pub, priv};
    }

    std::optional<std::vector<uint8_t>> sign(
        std::span<const uint8_t> message,
        std::span<const uint8_t> private_key) const override {

        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key_ex(nullptr, "ML-DSA-65", nullptr,
                                                         private_key.data(), private_key.size());
        if (!pkey) return std::nullopt;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (EVP_DigestSignInit_ex(mctx, nullptr, nullptr, nullptr, nullptr, pkey, nullptr) <= 0) {
            EVP_MD_CTX_free(mctx);
            EVP_PKEY_free(pkey);
            return std::nullopt;
        }

        size_t sig_len = 0;
        EVP_DigestSign(mctx, nullptr, &sig_len, message.data(), message.size());
        std::vector<uint8_t> sig(sig_len);
        if (EVP_DigestSign(mctx, sig.data(), &sig_len, message.data(), message.size()) <= 0) {
            EVP_MD_CTX_free(mctx);
            EVP_PKEY_free(pkey);
            return std::nullopt;
        }

        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return sig;
    }

    bool verify(
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> public_key) const override {

        EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key_ex(nullptr, "ML-DSA-65", nullptr,
                                                        public_key.data(), public_key.size());
        if (!pkey) return false;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (EVP_DigestVerifyInit_ex(mctx, nullptr, nullptr, nullptr, nullptr, pkey, nullptr) <= 0) {
            EVP_MD_CTX_free(mctx);
            EVP_PKEY_free(pkey);
            return false;
        }

        int res = EVP_DigestVerify(mctx, signature.data(), signature.size(), message.data(), message.size());
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return (res == 1);
    }
};

std::unique_ptr<ICryptoSuite> create_suite_pqc() {
    return std::make_unique<PurePqcCryptoSuite>();
}

} // namespace slug::crypto
