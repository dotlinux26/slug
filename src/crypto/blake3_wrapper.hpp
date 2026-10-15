#pragma once

#include <vector>
#include <array>
#include <span>
#include <string>
#include <string_view>
#include <cstdint>

namespace slug::crypto {

class Blake3 {
public:
    static constexpr size_t kHashSize = 32;

    // Computes BLAKE3 256-bit hash of data
    static std::array<uint8_t, kHashSize> hash(std::span<const uint8_t> data);
    static std::array<uint8_t, kHashSize> hash(std::string_view str);

    // Formatted hex string
    static std::string hash_hex(std::span<const uint8_t> data);
    static std::string hash_hex(std::string_view str);

    // Key Derivation Function (KDF) using BLAKE3 derive_key
    static std::array<uint8_t, kHashSize> derive_key(
        std::string_view context,
        std::span<const uint8_t> key_material);
};

} // namespace slug::crypto
