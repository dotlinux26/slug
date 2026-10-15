#include "src/core/utils.hpp"
#include <iomanip>
#include <sstream>
#include <random>
#include <cctype>
#include <algorithm>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace slug::core {

std::string Utils::to_hex(std::span<const uint8_t> data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::vector<uint8_t> Utils::from_hex(std::string_view hex) {
    std::vector<uint8_t> bytes;
    if (hex.size() % 2 != 0) return bytes;
    bytes.reserve(hex.size() / 2);

    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_val(hex[i]);
        int lo = hex_val(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return bytes;
}

static const char kBase64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Utils::to_base64(std::span<const uint8_t> data) {
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(kBase64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(kBase64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::vector<uint8_t> Utils::from_base64(std::string_view b64) {
    std::vector<uint8_t> out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[static_cast<unsigned char>(kBase64Chars[i])] = i;

    int val = 0, valb = -8;
    for (char c : b64) {
        if (T[static_cast<unsigned char>(c)] == -1) break;
        val = (val << 6) + T[static_cast<unsigned char>(c)];
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::vector<uint8_t> Utils::random_bytes(size_t count) {
    std::vector<uint8_t> buffer(count);
    if (RAND_bytes(buffer.data(), static_cast<int>(count)) != 1) {
        // Fallback to std::random_device
        std::random_device rd;
        for (size_t i = 0; i < count; ++i) {
            buffer[i] = static_cast<uint8_t>(rd() & 0xFF);
        }
    }
    return buffer;
}

bool Utils::constant_time_compare(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

bool Utils::constant_time_compare(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string Utils::format_size(uint64_t bytes) {
    constexpr const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double d = static_cast<double>(bytes);
    while (d >= 1024.0 && i < 4) {
        d /= 1024.0;
        i++;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << d << " " << units[i];
    return oss.str();
}

std::string Utils::format_duration(uint64_t seconds) {
    if (seconds >= 86400) return std::to_string(seconds / 86400) + "d";
    if (seconds >= 3600)  return std::to_string(seconds / 3600) + "h";
    if (seconds >= 60)    return std::to_string(seconds / 60) + "m";
    return std::to_string(seconds) + "s";
}

uint64_t Utils::parse_ttl(std::string_view ttl_str) {
    if (ttl_str.empty()) return 86400; // default 24h
    std::string s(ttl_str);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    if (s == "inf" || s == "infinity" || s == "forever" || s == "permanent" || s == "0") {
        return 0; // 0 = permanent / no expiration
    }
    uint64_t val = 0;
    size_t i = 0;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
        val = val * 10 + (s[i] - '0');
        i++;
    }
    if (i == 0) return 86400;
    if (i >= s.size()) return val; // plain seconds

    char unit = s[i];
    switch (unit) {
        case 's': return val;
        case 'm': return val * 60;
        case 'h': return val * 3600;
        case 'd': return val * 86400;
        case 'w': return val * 86400 * 7;
        case 'y': return val * 86400 * 365;
        default: return val;
    }
}

std::string Utils::format_ttl(uint64_t expires_at, uint64_t now) {
    if (expires_at == 0) return "∞ (Permanent)";
    if (now == 0) now = current_timestamp();
    if (now >= expires_at) return "Expired";
    return format_duration(expires_at - now);
}

uint64_t Utils::current_timestamp() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string Utils::trim(std::string_view s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) start++;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) end--;
    return std::string(s.substr(start, end - start));
}

std::vector<std::string> Utils::split(std::string_view s, char delim) {
    std::vector<std::string> res;
    size_t start = 0;
    while (start < s.size()) {
        size_t pos = s.find(delim, start);
        if (pos == std::string_view::npos) {
            res.emplace_back(s.substr(start));
            break;
        }
        res.emplace_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return res;
}

std::string Utils::join(const std::vector<std::string>& list, std::string_view delim) {
    std::string res;
    for (size_t i = 0; i < list.size(); ++i) {
        if (i > 0) res += delim;
        res += list[i];
    }
    return res;
}

bool Utils::starts_with(std::string_view str, std::string_view prefix) {
    return str.rfind(prefix, 0) == 0;
}

bool Utils::ends_with(std::string_view str, std::string_view suffix) {
    if (suffix.size() > str.size()) return false;
    return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

FileLockGuard::FileLockGuard(const std::string& file_path) {
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    std::string lock_file = file_path + ".lock";
    fd_ = ::open(lock_file.c_str(), O_RDWR | O_CREAT, 0600);
    if (fd_ >= 0) {
        ::flock(fd_, LOCK_EX);
    }
#else
    (void)file_path;
#endif
}

FileLockGuard::~FileLockGuard() {
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    if (fd_ >= 0) {
        ::flock(fd_, LOCK_UN);
        ::close(fd_);
    }
#endif
}

} // namespace slug::core
