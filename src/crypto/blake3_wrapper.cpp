#include "src/crypto/blake3_wrapper.hpp"
#include "src/core/utils.hpp"
extern "C" {
#include "third_party/blake3/blake3.h"
}
#include <cstring>
#include <fstream>

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

std::optional<std::string> Blake3::hash_file(const std::filesystem::path& file_path, size_t buffer_size) {
    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs.is_open()) return std::nullopt;

    Blake3Hasher hasher;
    std::vector<uint8_t> buf(std::max<size_t>(4096, buffer_size));
    while (ifs) {
        ifs.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        std::streamsize bytes_read = ifs.gcount();
        if (bytes_read > 0) {
            hasher.update(buf.data(), static_cast<size_t>(bytes_read));
        }
    }
    return hasher.finalize_hex();
}

struct Blake3Hasher::Impl {
    blake3_hasher hasher;
    Impl() {
        blake3_hasher_init(&hasher);
    }
};

Blake3Hasher::Blake3Hasher() : impl_(std::make_unique<Impl>()) {}
Blake3Hasher::~Blake3Hasher() = default;
Blake3Hasher::Blake3Hasher(Blake3Hasher&&) noexcept = default;
Blake3Hasher& Blake3Hasher::operator=(Blake3Hasher&&) noexcept = default;

void Blake3Hasher::update(std::span<const uint8_t> data) {
    if (!data.empty() && impl_) {
        blake3_hasher_update(&impl_->hasher, data.data(), data.size());
    }
}

void Blake3Hasher::update(const void* data, size_t len) {
    if (data && len > 0 && impl_) {
        blake3_hasher_update(&impl_->hasher, data, len);
    }
}

std::array<uint8_t, Blake3::kHashSize> Blake3Hasher::finalize() const {
    std::array<uint8_t, Blake3::kHashSize> out{};
    if (impl_) {
        blake3_hasher_finalize(&impl_->hasher, out.data(), Blake3::kHashSize);
    }
    return out;
}

std::string Blake3Hasher::finalize_hex() const {
    auto h = finalize();
    return core::Utils::to_hex(h);
}

void Blake3Hasher::reset() {
    if (impl_) {
        blake3_hasher_init(&impl_->hasher);
    }
}

} // namespace slug::crypto

