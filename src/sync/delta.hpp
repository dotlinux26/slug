#pragma once

#include "src/sync/manifest.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <cstdint>

namespace slug::sync {

struct FileDelta {
    std::string relative_path;
    bool is_new{false};
    bool is_modified{false};
    bool is_unchanged{false};
    uint64_t total_size{0};
    std::vector<uint32_t> needed_chunk_indices; // empty if unchanged
};

struct DeltaPlan {
    std::vector<FileDelta> file_deltas;
    std::vector<std::string> files_to_prune;
    std::vector<ManifestSkippedEntry> skipped_by_remote;

    size_t total_files_remote{0};
    size_t count_unchanged{0};
    size_t count_new{0};
    size_t count_modified{0};
    uint64_t bytes_to_transfer{0};
    uint64_t bytes_saved{0};
};

struct DeltaSyncOptions {
    bool dry_run{false};
    std::string only_pattern;
    std::string ext_filter;
    uint64_t max_size_bytes{0}; // 0 = unlimited
    bool prune{false};
};

class DeltaCalculator {
public:
    static DeltaPlan compute_plan(
        const WorkspaceManifest& remote_manifest,
        const std::filesystem::path& local_target_dir,
        const DeltaSyncOptions& options = {});
};

} // namespace slug::sync
