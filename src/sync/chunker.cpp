#include "src/sync/chunker.hpp"
#include "src/crypto/blake3_wrapper.hpp"
#include "src/platform/fs.hpp"
#include <fstream>

namespace slug::sync {

std::vector<ChunkInfo> Chunker::chunk_buffer(std::span<const uint8_t> data, size_t chunk_size) {
    std::vector<ChunkInfo> chunks;
    if (data.empty()) return chunks;

    uint32_t index = 0;
    uint64_t offset = 0;
    size_t remaining = data.size();

    while (remaining > 0) {
        size_t cur = std::min(remaining, chunk_size);
        std::span<const uint8_t> chunk_span = data.subspan(offset, cur);

        ChunkInfo ci;
        ci.index = index++;
        ci.offset = offset;
        ci.size = static_cast<uint32_t>(cur);
        ci.blake3_hash = crypto::Blake3::hash_hex(chunk_span);
        chunks.push_back(std::move(ci));

        offset += cur;
        remaining -= cur;
    }
    return chunks;
}

std::vector<ChunkInfo> Chunker::chunk_file(const std::filesystem::path& file_path, size_t chunk_size) {
    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs.is_open()) return {};

    std::vector<ChunkInfo> chunks;
    std::vector<uint8_t> buf(chunk_size);
    uint32_t index = 0;
    uint64_t offset = 0;

    while (ifs) {
        ifs.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(chunk_size));
        std::streamsize bytes_read = ifs.gcount();
        if (bytes_read <= 0) break;

        ChunkInfo ci;
        ci.index = index++;
        ci.offset = offset;
        ci.size = static_cast<uint32_t>(bytes_read);
        ci.blake3_hash = crypto::Blake3::hash_hex(std::span<const uint8_t>(buf.data(), static_cast<size_t>(bytes_read)));
        chunks.push_back(std::move(ci));

        offset += static_cast<uint64_t>(bytes_read);
    }
    return chunks;
}

} // namespace slug::sync
