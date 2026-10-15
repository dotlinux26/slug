#include "src/sync/chunker.hpp"
#include "src/crypto/blake3_wrapper.hpp"
#include "src/platform/fs.hpp"

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
    auto data = platform::PathUtils::read_binary_file(file_path);
    if (!data) return {};
    return chunk_buffer(*data, chunk_size);
}

} // namespace slug::sync
