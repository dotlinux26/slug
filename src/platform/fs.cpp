#include "src/platform/fs.hpp"
#include <fstream>
#include <algorithm>
#include <system_error>
#include <random>

namespace slug::platform {

std::string PathUtils::to_protocol_path(const fs::path& relative_path) {
    std::string s = relative_path.generic_string();
    while (!s.empty() && (s.front() == '/' || s.front() == '.')) {
        if (s.rfind("./", 0) == 0) {
            s = s.substr(2);
        } else if (s.front() == '/') {
            s = s.substr(1);
        } else {
            break;
        }
    }
    return s;
}

fs::path PathUtils::from_protocol_path(const std::string& protocol_path) {
    return fs::path(protocol_path);
}

bool PathUtils::is_internal_slug_path(const fs::path& path) {
    for (const auto& part : path) {
        std::string s = part.string();
        if (s == ".slug" || s == ".git") {
            return true;
        }
    }
    return false;
}

std::optional<fs::path> PathUtils::resolve_safe_path(const fs::path& root_dir, const std::string& relative_path) {
    std::error_code ec;
    fs::path root_canonical = fs::weakly_canonical(root_dir, ec);
    if (ec) return std::nullopt;

    // Check raw string for obvious traversal tricks
    if (relative_path.find("..") != std::string::npos) {
        // Detailed check through path components
        fs::path test_path(relative_path);
        for (const auto& comp : test_path) {
            if (comp == "..") return std::nullopt;
        }
    }

    fs::path target = root_canonical / relative_path;
    fs::path target_canonical = fs::weakly_canonical(target, ec);
    if (ec) return std::nullopt;

    std::string root_str = root_canonical.string();
    std::string target_str = target_canonical.string();

    // Ensure root_str has trailing separator for prefix check
    if (!root_str.empty() && root_str.back() != fs::path::preferred_separator) {
        root_str += fs::path::preferred_separator;
    }

    // Target must match root exactly or start with root_str
    if (target_str == root_canonical.string()) {
        return target_canonical;
    }

    if (target_str.rfind(root_str, 0) != 0) {
        // Path escaped root! Traversal detected!
        return std::nullopt;
    }

    // Check if target is a symlink pointing outside root
    if (fs::is_symlink(target, ec)) {
        fs::path symlink_target = fs::canonical(target, ec);
        if (ec) return std::nullopt;
        std::string sym_str = symlink_target.string();
        if (sym_str != root_canonical.string() && sym_str.rfind(root_str, 0) != 0) {
            return std::nullopt;
        }
    }

    return target_canonical;
}

std::optional<std::vector<uint8_t>> PathUtils::read_binary_file(const fs::path& path, size_t max_bytes) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return std::nullopt;

    auto size = file.tellg();
    if (size < 0 || static_cast<size_t>(size) > max_bytes) return std::nullopt;

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return std::nullopt;
    }
    return buffer;
}

std::optional<std::string> PathUtils::read_text_file(const fs::path& path) {
    auto bin = read_binary_file(path);
    if (!bin) return std::nullopt;
    return std::string(bin->begin(), bin->end());
}

bool PathUtils::ensure_directory(const fs::path& path) {
    std::error_code ec;
    if (fs::exists(path, ec)) return true;
    return fs::create_directories(path, ec);
}

bool PathUtils::write_binary_file_atomic(const fs::path& path, std::span<const uint8_t> data) {
    ensure_directory(path.parent_path());

    // Generate random temp name in the same directory
    static thread_local std::mt19937_64 rng(1337);
    fs::path temp_path = path;
    temp_path += ".tmp." + std::to_string(rng());

    {
        std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        out.write(reinterpret_cast<const char*>(data.data()), data.size());
        if (!out.good()) {
            std::error_code ec;
            fs::remove(temp_path, ec);
            return false;
        }
    }

    std::error_code ec;
#if defined(SLUG_PLATFORM_WINDOWS)
    // Windows atomic rename requires target removal first or MoveFileEx
    fs::remove(path, ec);
#endif
    fs::rename(temp_path, path, ec);
    if (ec) {
        fs::remove(temp_path, ec);
        return false;
    }
    return true;
}

bool PathUtils::write_text_file_atomic(const fs::path& path, const std::string& content) {
    return write_binary_file_atomic(path, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(content.data()), content.size()));
}

} // namespace slug::platform
