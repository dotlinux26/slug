#pragma once

#include <string>
#include <vector>
#include <span>
#include <cstdint>
#include <chrono>

namespace slug::core {

class Utils {
public:
    // Hex
    static std::string to_hex(std::span<const uint8_t> data);
    static std::vector<uint8_t> from_hex(std::string_view hex);

    // Base64
    static std::string to_base64(std::span<const uint8_t> data);
    static std::vector<uint8_t> from_base64(std::string_view b64);

    // Crypto-secure random bytes
    static std::vector<uint8_t> random_bytes(size_t count);

    // Constant-time buffer / string comparison (timing attack resistance)
    static bool constant_time_compare(std::string_view a, std::string_view b);
    static bool constant_time_compare(std::span<const uint8_t> a, std::span<const uint8_t> b);

    // Human-readable size (e.g. 1.2 MB)
    static std::string format_size(uint64_t bytes);

    // Human-readable duration
    static std::string format_duration(uint64_t seconds);

    // Parse TTL string like "30s", "5m", "2h", "24h", "7d", "inf", "forever", "0" -> seconds (0 = permanent)
    static uint64_t parse_ttl(std::string_view ttl_str);

    // Format expiration timestamp: "∞ (Permanent)", "Expired", or duration e.g. "23h 59m"
    static std::string format_ttl(uint64_t expires_at, uint64_t now = 0);

    // Current Unix timestamp in seconds
    static uint64_t current_timestamp();

    // Format timestamp as "YYYY-MM-DD HH:MM:SS"
    static std::string format_timestamp(uint64_t timestamp);

    // String utilities
    static std::string trim(std::string_view s);
    static std::vector<std::string> split(std::string_view s, char delim);
    static std::string join(const std::vector<std::string>& list, std::string_view delim);
    static bool starts_with(std::string_view str, std::string_view prefix);
    static bool ends_with(std::string_view str, std::string_view suffix);
};

class FileLockGuard {
public:
    explicit FileLockGuard(const std::string& file_path);
    ~FileLockGuard();
    FileLockGuard(const FileLockGuard&) = delete;
    FileLockGuard& operator=(const FileLockGuard&) = delete;
private:
    int fd_{-1};
    void* handle_{nullptr};
};

} // namespace slug::core
