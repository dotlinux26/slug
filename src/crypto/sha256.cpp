#include "src/crypto/sha256.hpp"
#include "src/core/utils.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <cstring>

namespace slug::crypto {

std::array<uint8_t, Sha256::kHashSize> Sha256::hash(std::span<const uint8_t> data) {
    std::array<uint8_t, kHashSize> out{};
    size_t len = 0;
    EVP_Q_digest(nullptr, "SHA256", nullptr, data.data(), data.size(), out.data(), &len);
    return out;
}

std::array<uint8_t, Sha256::kHashSize> Sha256::hash(std::string_view str) {
    return hash(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
}

std::string Sha256::hash_hex(std::span<const uint8_t> data) {
    auto h = hash(data);
    return core::Utils::to_hex(h);
}

std::string Sha256::hash_hex(std::string_view str) {
    auto h = hash(str);
    return core::Utils::to_hex(h);
}

std::array<uint8_t, Sha256::kHashSize> Sha256::kdf(
    std::span<const uint8_t> shared_secret,
    std::string_view info,
    std::span<const uint8_t> salt) {

    std::array<uint8_t, kHashSize> out{};
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) return out;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return out;

    OSSL_PARAM params[5];
    char md[] = "SHA256";
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                    const_cast<uint8_t*>(shared_secret.data()), shared_secret.size());
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                    const_cast<char*>(info.data()), info.size());
    if (!salt.empty()) {
        params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                        const_cast<uint8_t*>(salt.data()), salt.size());
        params[4] = OSSL_PARAM_construct_end();
    } else {
        params[3] = OSSL_PARAM_construct_end();
    }

    EVP_KDF_derive(kctx, out.data(), out.size(), params);
    EVP_KDF_CTX_free(kctx);
    return out;
}

} // namespace slug::crypto
