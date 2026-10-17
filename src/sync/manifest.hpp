#pragma once

#include "src/sync/chunker.hpp"
#include "src/core/types.hpp"
#include <optional>
#include <string>
#include <vector>
#include <filesystem>
#include <cstdint>

namespace slug::sync {

struct ManifestFileEntry {
    std::string relative_path;
    uint64_t size{0};
    uint64_t mtime{0};
    std::string file_blake3_hash;
    std::vector<ChunkInfo> chunks;
};

struct ManifestSkippedEntry {
    std::string relative_path;
    std::string reason;
    std::string status;
};

struct WorkspaceManifest {
    uint32_t protocol_version{1};
    uint8_t suite_id{3};
    uint64_t epoch{1};
    uint64_t timestamp{0};
    std::string root_hash;
    std::vector<ManifestFileEntry> files;
    std::vector<ManifestSkippedEntry> skipped;

    std::string to_json() const;
    static std::optional<WorkspaceManifest> from_json(const std::string& json_str);
    void compute_root_hash();
};

class ManifestBuilder {
public:
    static WorkspaceManifest build(
        const std::filesystem::path& workspace_root,
        uint64_t epoch = 1,
        uint8_t suite_id = 3,
        bool enable_ai = false,
        core::FilterMode filter_mode = core::FilterMode::PROTECTED,
        core::FilterLevel filter_level = core::FilterLevel::LEVEL_2_REGEX,
        core::AiModelProvider ai_provider = core::AiModelProvider::OLLAMA);
};

} // namespace slug::sync
