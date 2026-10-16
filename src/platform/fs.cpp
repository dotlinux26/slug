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

bool PathUtils::is_valid_portable_path(const std::string& path_str) {
    const std::string forbidden_chars = "<>:\"|?*";
    fs::path p(path_str);
    for (const auto& comp : p) {
        std::string s = comp.string();
        if (s == "." || s == "..") continue;
        for (char c : s) {
            if (forbidden_chars.find(c) != std::string::npos || static_cast<unsigned char>(c) < 32) {
                return false;
            }
        }
    }
    return true;
}

std::optional<fs::path> PathUtils::resolve_safe_path(const fs::path& root_dir, const std::string& relative_path) {
    // 1. Check portable filename characters
    if (!is_valid_portable_path(relative_path)) {
        return std::nullopt;
    }

    std::error_code ec;
    fs::path root_canonical = fs::weakly_canonical(root_dir, ec);
    if (ec) return std::nullopt;

    // Check raw string for obvious traversal tricks
    if (relative_path.find("..") != std::string::npos) {
        fs::path test_path(relative_path);
        for (const auto& comp : test_path) {
            if (comp == "..") return std::nullopt;
        }
    }

    fs::path candidate = root_canonical / fs::path(relative_path).relative_path();
    fs::path target_canonical = fs::weakly_canonical(candidate, ec);
    if (ec) return std::nullopt;

    // Strict path jailing via mismatch on canonical path components
    auto [root_end, nothing] = std::mismatch(root_canonical.begin(), root_canonical.end(), target_canonical.begin());
    if (root_end != root_canonical.end()) {
        return std::nullopt; // Escaped root! Traversal detected!
    }

    // Additional symlink escape check
    if (fs::is_symlink(candidate, ec)) {
        fs::path symlink_target = fs::canonical(candidate, ec);
        if (ec) return std::nullopt;
        auto [sym_end, sym_nothing] = std::mismatch(root_canonical.begin(), root_canonical.end(), symlink_target.begin());
        if (sym_end != root_canonical.end()) {
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
