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

    // Normalizes path separators to forward slashes for cross-platform protocol consistency
    static std::string to_protocol_path(const fs::path& relative_path);

    // Converts a protocol path back to a filesystem path
    static fs::path from_protocol_path(const std::string& protocol_path);

    // Checks if path represents a hidden or internal file/dir (.slug/, .git/)
    static bool is_internal_slug_path(const fs::path& path);

    // Read full file content safely
    static std::optional<std::vector<uint8_t>> read_binary_file(const fs::path& path, size_t max_bytes = 100 * 1024 * 1024);
    
    // Read text file
    static std::optional<std::string> read_text_file(const fs::path& path);

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
