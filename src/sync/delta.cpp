#include "src/sync/delta.hpp"
#include "src/crypto/blake3_wrapper.hpp"
#include "src/core/utils.hpp"
#include "src/platform/fs.hpp"
#include <set>

namespace slug::sync {

namespace fs = std::filesystem;

DeltaPlan DeltaCalculator::compute_plan(
    const WorkspaceManifest& remote_manifest,
    const fs::path& local_target_dir,
    const DeltaSyncOptions& options) {

    DeltaPlan plan;
    plan.total_files_remote = remote_manifest.files.size();
    plan.skipped_by_remote = remote_manifest.skipped;

    // Parse ext filter
    std::vector<std::string> allowed_exts;
    if (!options.ext_filter.empty()) {
        auto list = core::Utils::split(options.ext_filter, ',');
        for (const auto& e : list) {
            allowed_exts.push_back(core::Utils::trim(e));
        }
    }

    std::set<std::string> remote_paths;

    for (const auto& rem_file : remote_manifest.files) {
        remote_paths.insert(rem_file.relative_path);

        // 1. Check --only pattern
        if (!options.only_pattern.empty()) {
            std::string pat = options.only_pattern;
            if (pat.back() == '*') {
                std::string prefix = pat.substr(0, pat.size() - 1);
                if (rem_file.relative_path.rfind(prefix, 0) != 0) continue;
            } else if (rem_file.relative_path != pat) {
                continue;
            }
        }

        // 2. Check --ext filter
        if (!allowed_exts.empty()) {
            bool matched = false;
            for (const auto& ext : allowed_exts) {
                if (core::Utils::ends_with(rem_file.relative_path, ext)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) continue;
        }

        // 3. Check --max-size filter
        if (options.max_size_bytes > 0 && rem_file.size > options.max_size_bytes) {
            continue;
        }

        fs::path local_file = local_target_dir / rem_file.relative_path;
        std::error_code ec;

        if (!fs::exists(local_file, ec)) {
            // New file: need all chunks
            FileDelta fd;
            fd.relative_path = rem_file.relative_path;
            fd.is_new = true;
            fd.total_size = rem_file.size;
            for (const auto& c : rem_file.chunks) {
                fd.needed_chunk_indices.push_back(c.index);
            }
            plan.count_new++;
            plan.bytes_to_transfer += rem_file.size;
            plan.file_deltas.push_back(std::move(fd));
            continue;
        }

        // File exists locally: read and compare hash
        auto local_data = platform::PathUtils::read_binary_file(local_file);
        if (!local_data) {
            // Could not read: mark as new / full transfer
            FileDelta fd;
            fd.relative_path = rem_file.relative_path;
            fd.is_new = true;
            fd.total_size = rem_file.size;
            for (const auto& c : rem_file.chunks) {
                fd.needed_chunk_indices.push_back(c.index);
            }
            plan.count_new++;
            plan.bytes_to_transfer += rem_file.size;
            plan.file_deltas.push_back(std::move(fd));
            continue;
        }

        std::string local_hash = crypto::Blake3::hash_hex(*local_data);

        if (local_hash == rem_file.file_blake3_hash) {
            // Identical: 100% skipped! Zero bytes over wire!
            FileDelta fd;
            fd.relative_path = rem_file.relative_path;
            fd.is_unchanged = true;
            fd.total_size = rem_file.size;
            plan.count_unchanged++;
            plan.bytes_saved += rem_file.size;
            plan.file_deltas.push_back(std::move(fd));
            continue;
        }

        // Modified file: compare chunks to find exactly which changed
        auto local_chunks = Chunker::chunk_buffer(*local_data);
        FileDelta fd;
        fd.relative_path = rem_file.relative_path;
        fd.is_modified = true;
        fd.total_size = rem_file.size;

        uint64_t file_transfer_bytes = 0;
        for (const auto& rem_chunk : rem_file.chunks) {
            bool chunk_match = false;
            if (rem_chunk.index < local_chunks.size()) {
                if (local_chunks[rem_chunk.index].blake3_hash == rem_chunk.blake3_hash &&
                    local_chunks[rem_chunk.index].size == rem_chunk.size) {
                    chunk_match = true;
                }
            }
            if (!chunk_match) {
                fd.needed_chunk_indices.push_back(rem_chunk.index);
                file_transfer_bytes += rem_chunk.size;
            } else {
                plan.bytes_saved += rem_chunk.size;
            }
        }

        plan.count_modified++;
        plan.bytes_to_transfer += file_transfer_bytes;
        plan.file_deltas.push_back(std::move(fd));
    }

    // Handle --prune: find local files not in remote manifest
    if (options.prune && fs::exists(local_target_dir)) {
        std::error_code ec;
        for (const auto& entry : fs::recursive_directory_iterator(local_target_dir, fs::directory_options::skip_permission_denied, ec)) {
            if (entry.is_regular_file(ec)) {
                fs::path rel = entry.path().lexically_relative(local_target_dir);
                std::string proto = platform::PathUtils::to_protocol_path(rel);
                if (!platform::PathUtils::is_internal_slug_path(rel)) {
                    if (remote_paths.find(proto) == remote_paths.end()) {
                        plan.files_to_prune.push_back(proto);
                    }
                }
            }
        }
    }

    return plan;
}

} // namespace slug::sync
