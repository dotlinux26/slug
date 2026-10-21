#pragma once

#include <filesystem>
#include <string>
#include <vector>
#include <optional>
#include <span>
#include <cstdint>

namespace slug::platform {

namespace fs = std::filesystem;

class PathUtils {
public:
    // Resolves a relative path within root_dir and verifies it does NOT escape root_dir.
    // Returns std::nullopt if the path attempts traversal (e.g. "../", symlink pointing outside).
    static std::optional<fs::path> resolve_safe_path(const fs::path& root_dir, const std::string& relative_path);

    // Validates that all path components contain only portable, cross-platform valid characters (blocks <>:"|?* and controls)
    static bool is_valid_portable_path(const std::string& path_str);

    // UTF-8 string to std::filesystem::path conversion (cross-platform, handles Windows Unicode)
    static fs::path u8_to_path(std::string_view utf8_str);

    // std::filesystem::path to UTF-8 string conversion (cross-platform, handles Windows Unicode)
    static std::string path_to_u8(const fs::path& p);

    // Normalizes path separators to forward slashes for cross-platform protocol consistency
    static std::string to_protocol_path(const fs::path& relative_path);

    // Converts a protocol path back to a filesystem path
    static fs::path from_protocol_path(const std::string& protocol_path);

    // Checks if path represents a hidden or internal file/dir (.slug/, .git/)
    static bool is_internal_slug_path(const fs::path& path);

    // Read full file content safely
    static std::optional<std::vector<uint8_t>> read_binary_file(const fs::path& path, size_t max_bytes = 2048ULL * 1024 * 1024);
    
    // Read text file
    static std::optional<std::string> read_text_file(const fs::path& path);

    // Fast head & tail sample comparison for large files (64KB head + 64KB tail)
    static bool fast_head_tail_match_data(const fs::path& existing_file, std::span<const uint8_t> incoming_data, size_t sample_size = 64 * 1024);
    static bool fast_head_tail_match_files(const fs::path& path_a, const fs::path& path_b, size_t sample_size = 64 * 1024);

    // Atomic write to file via temporary file
    static bool write_binary_file_atomic(const fs::path& path, std::span<const uint8_t> data);
    static bool write_text_file_atomic(const fs::path& path, const std::string& content);

    // Directory creation
    static bool ensure_directory(const fs::path& path);

    // Returns current user's home directory (~ or %USERPROFILE%)
    static fs::path get_user_home();
};

inline fs::path get_user_home() {
    return PathUtils::get_user_home();
}

} // namespace slug::platform
