#pragma once

#include <vector>
#include <string>
#include <span>
#include <cstdint>
#include <filesystem>

namespace slug::sync {

struct ChunkInfo {
    uint32_t index{0};
    uint64_t offset{0};
    uint32_t size{0};
    std::string blake3_hash;
};

class Chunker {
public:
    static constexpr size_t kDefaultChunkSize = 64 * 1024; // 64 KiB

    // Splits data into chunks and computes BLAKE3 hash for each
    static std::vector<ChunkInfo> chunk_buffer(std::span<const uint8_t> data, size_t chunk_size = kDefaultChunkSize);

    // Reads file and computes chunk list
    static std::vector<ChunkInfo> chunk_file(const std::filesystem::path& file_path, size_t chunk_size = kDefaultChunkSize);
};

} // namespace slug::sync
