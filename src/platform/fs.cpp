#include "src/platform/fs.hpp"
#include "src/platform/platform.hpp"
#include <fstream>
#include <algorithm>
#include <cstring>
#include <system_error>
#include <random>
#include <set>

namespace slug::platform {

fs::path PathUtils::u8_to_path(std::string_view utf8_str) {
    if (utf8_str.empty()) return fs::path();
#if defined(SLUG_PLATFORM_WINDOWS)
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8_str.data(), static_cast<int>(utf8_str.size()), nullptr, 0);
    if (wlen <= 0) {
        return fs::path(std::string(utf8_str));
    }
    std::wstring wstr(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8_str.data(), static_cast<int>(utf8_str.size()), wstr.data(), wlen);
    return fs::path(wstr);
#else
    return fs::path(utf8_str);
#endif
}

std::string PathUtils::path_to_u8(const fs::path& p) {
#if defined(SLUG_PLATFORM_WINDOWS)
    std::wstring wstr = p.wstring();
    if (wstr.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return p.string();
    std::string u8(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), u8.data(), len, nullptr, nullptr);
    return u8;
#else
    return p.string();
#endif
}

std::string PathUtils::to_protocol_path(const fs::path& relative_path) {
    std::string s = path_to_u8(relative_path);
    std::replace(s.begin(), s.end(), '\\', '/');
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
    return u8_to_path(protocol_path);
}

bool PathUtils::is_internal_slug_path(const fs::path& path) {
    for (const auto& part : path) {
        std::string s = path_to_u8(part);
        if (s == ".slug" || s == ".git") {
            return true;
        }
    }
    return false;
}

bool PathUtils::is_valid_portable_path(const std::string& path_str) {
    const std::wstring forbidden_chars = L"<>:\"|?*";
    static const std::set<std::string> dos_devices = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    fs::path p = u8_to_path(path_str);
    for (const auto& comp : p) {
        std::wstring ws = comp.wstring();
        if (ws == L"." || ws == L"..") continue;
        for (wchar_t wc : ws) {
            if (forbidden_chars.find(wc) != std::wstring::npos || (static_cast<uint32_t>(wc) < 32)) {
                return false;
            }
        }

        // Reject Windows DOS reserved device names (CON, NUL, COM1, AUX, etc.)
        std::string stem = path_to_u8(comp.stem());
        for (char& c : stem) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        if (dos_devices.find(stem) != dos_devices.end()) {
            return false;
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
        fs::path test_path = u8_to_path(relative_path);
        for (const auto& comp : test_path) {
            if (comp == "..") return std::nullopt;
        }
    }

    fs::path candidate = root_canonical / u8_to_path(relative_path).relative_path();
    fs::path target_canonical = fs::weakly_canonical(candidate, ec);
    if (ec) return std::nullopt;

    // Strict path jailing via mismatch on canonical path components
    auto [root_end, nothing] = std::mismatch(root_canonical.begin(), root_canonical.end(),
                                             target_canonical.begin(), target_canonical.end());
    if (root_end != root_canonical.end()) {
        return std::nullopt; // Escaped root! Traversal detected!
    }

    // Additional symlink escape check
    if (fs::is_symlink(candidate, ec)) {
        fs::path symlink_target = fs::canonical(candidate, ec);
        if (ec) return std::nullopt;
        auto [sym_end, sym_nothing] = std::mismatch(root_canonical.begin(), root_canonical.end(),
                                                   symlink_target.begin(), symlink_target.end());
        if (sym_end != root_canonical.end()) {
            return std::nullopt;
        }
    }

    return target_canonical;
}

std::optional<std::vector<uint8_t>> PathUtils::read_binary_file(const fs::path& path, size_t max_bytes) {
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
        return std::nullopt;
    }

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

bool PathUtils::fast_head_tail_match_data(const fs::path& existing_file, std::span<const uint8_t> incoming_data, size_t sample_size) {
    std::error_code ec;
    uint64_t file_sz = fs::file_size(existing_file, ec);
    if (ec || file_sz != incoming_data.size()) {
        return false;
    }
    if (file_sz <= sample_size * 2) {
        return true;
    }

    std::ifstream file(existing_file, std::ios::binary);
    if (!file.is_open()) return false;

    constexpr size_t kChunk = 65536;
    size_t check_len = std::min(sample_size, kChunk);
    uint8_t buf[kChunk];

    // Check head
    file.read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(check_len));
    if (file.gcount() != static_cast<std::streamsize>(check_len)) return false;
    if (std::memcmp(buf, incoming_data.data(), check_len) != 0) {
        return false;
    }

    // Check tail
    file.seekg(static_cast<std::streamoff>(file_sz - check_len), std::ios::beg);
    file.read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(check_len));
    if (file.gcount() != static_cast<std::streamsize>(check_len)) return false;
    if (std::memcmp(buf, incoming_data.data() + (file_sz - check_len), check_len) != 0) {
        return false;
    }

    return true;
}

bool PathUtils::fast_head_tail_match_files(const fs::path& path_a, const fs::path& path_b, size_t sample_size) {
    std::error_code ec;
    uint64_t sz_a = fs::file_size(path_a, ec);
    if (ec) return false;
    uint64_t sz_b = fs::file_size(path_b, ec);
    if (ec || sz_a != sz_b) return false;
    if (sz_a <= sample_size * 2) return true;

    std::ifstream fa(path_a, std::ios::binary);
    std::ifstream fb(path_b, std::ios::binary);
    if (!fa.is_open() || !fb.is_open()) return false;

    constexpr size_t kChunk = 65536;
    size_t check_len = std::min(sample_size, kChunk);
    uint8_t bufa[kChunk];
    uint8_t bufb[kChunk];

    // Check head
    fa.read(reinterpret_cast<char*>(bufa), static_cast<std::streamsize>(check_len));
    fb.read(reinterpret_cast<char*>(bufb), static_cast<std::streamsize>(check_len));
    if (fa.gcount() != fb.gcount() || std::memcmp(bufa, bufb, static_cast<size_t>(fa.gcount())) != 0) {
        return false;
    }

    // Check tail
    fa.seekg(static_cast<std::streamoff>(sz_a - check_len), std::ios::beg);
    fb.seekg(static_cast<std::streamoff>(sz_b - check_len), std::ios::beg);
    fa.read(reinterpret_cast<char*>(bufa), static_cast<std::streamsize>(check_len));
    fb.read(reinterpret_cast<char*>(bufb), static_cast<std::streamsize>(check_len));
    if (fa.gcount() != fb.gcount() || std::memcmp(bufa, bufb, static_cast<size_t>(fa.gcount())) != 0) {
        return false;
    }

    return true;
}

bool PathUtils::ensure_directory(const fs::path& path) {
    std::error_code ec;
    if (fs::exists(path, ec)) return true;
    return fs::create_directories(path, ec);
}

bool PathUtils::write_binary_file_atomic(const fs::path& path, std::span<const uint8_t> data) {
    ensure_directory(path.parent_path());

    // Generate random temp name in the same directory using unpredictable seed
    static thread_local std::mt19937_64 rng(std::random_device{}());
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
    if (!MoveFileExW(temp_path.wstring().c_str(), path.wstring().c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        fs::remove(temp_path, ec);
        return false;
    }
    return true;
#else
    fs::rename(temp_path, path, ec);
    if (ec) {
        fs::remove(temp_path, ec);
        return false;
    }
    return true;
#endif
}

bool PathUtils::write_text_file_atomic(const fs::path& path, const std::string& content) {
    return write_binary_file_atomic(path, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(content.data()), content.size()));
}

fs::path PathUtils::get_user_home() {
    const char* home = std::getenv("HOME");
    if (!home) home = std::getenv("USERPROFILE");
    if (home) return fs::path(home);
    return fs::temp_directory_path();
}

} // namespace slug::platform
