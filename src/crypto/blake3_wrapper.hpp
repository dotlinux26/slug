#pragma once

#include <vector>
#include <array>
#include <span>
#include <string>
#include <string_view>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <memory>

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

    // Streams file in bounded chunks (e.g. 256KB) and computes BLAKE3 hex hash without loading entire file to RAM
    static std::optional<std::string> hash_file(const std::filesystem::path& file_path, size_t buffer_size = 256 * 1024);

    // Key Derivation Function (KDF) using BLAKE3 derive_key
    static std::array<uint8_t, kHashSize> derive_key(
        std::string_view context,
        std::span<const uint8_t> key_material);
};

// Streaming incremental BLAKE3 hasher (bounded-memory hashing for files up to 100 GB)
class Blake3Hasher {
public:
    Blake3Hasher();
    ~Blake3Hasher();
    Blake3Hasher(Blake3Hasher&&) noexcept;
    Blake3Hasher& operator=(Blake3Hasher&&) noexcept;
    Blake3Hasher(const Blake3Hasher&) = delete;
    Blake3Hasher& operator=(const Blake3Hasher&) = delete;

    void update(std::span<const uint8_t> data);
    void update(const void* data, size_t len);
    std::array<uint8_t, Blake3::kHashSize> finalize() const;
    std::string finalize_hex() const;
    void reset();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace slug::crypto

