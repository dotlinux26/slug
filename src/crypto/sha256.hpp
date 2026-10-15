#pragma once

#include <vector>
#include <array>
#include <span>
#include <string>
#include <string_view>
#include <cstdint>

namespace slug::crypto {

class Sha256 {
public:
    static constexpr size_t kHashSize = 32;

    static std::array<uint8_t, kHashSize> hash(std::span<const uint8_t> data);
    static std::array<uint8_t, kHashSize> hash(std::string_view str);
    static std::string hash_hex(std::span<const uint8_t> data);
    static std::string hash_hex(std::string_view str);

    // HKDF-SHA256 for key derivation
    static std::array<uint8_t, kHashSize> kdf(
        std::span<const uint8_t> shared_secret,
        std::string_view info,
        std::span<const uint8_t> salt = {});
};

} // namespace slug::crypto
