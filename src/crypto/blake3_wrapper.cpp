#include "src/crypto/blake3_wrapper.hpp"
#include "src/core/utils.hpp"
extern "C" {
#include "third_party/blake3/blake3.h"
}
#include <cstring>

namespace slug::crypto {

std::array<uint8_t, Blake3::kHashSize> Blake3::hash(std::span<const uint8_t> data) {
    std::array<uint8_t, kHashSize> out{};
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data.data(), data.size());
    blake3_hasher_finalize(&hasher, out.data(), kHashSize);
    return out;
}

std::array<uint8_t, Blake3::kHashSize> Blake3::hash(std::string_view str) {
    return hash(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
}

std::string Blake3::hash_hex(std::span<const uint8_t> data) {
    auto h = hash(data);
    return core::Utils::to_hex(h);
}

std::string Blake3::hash_hex(std::string_view str) {
    auto h = hash(str);
    return core::Utils::to_hex(h);
}

std::array<uint8_t, Blake3::kHashSize> Blake3::derive_key(
    std::string_view context,
    std::span<const uint8_t> key_material) {

    std::array<uint8_t, kHashSize> out{};
    blake3_hasher hasher;
    blake3_hasher_init_derive_key_raw(&hasher, context.data(), context.size());
    blake3_hasher_update(&hasher, key_material.data(), key_material.size());
    blake3_hasher_finalize(&hasher, out.data(), kHashSize);
    return out;
}

} // namespace slug::crypto
