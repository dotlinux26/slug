#pragma once

#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <cstdint>

namespace slug::crypto {

class TotpManager {
public:
    static constexpr uint32_t kStepSeconds = 60; // 60s rotation
    static constexpr size_t kCodeDigits = 8;     // 8 digits

    explicit TotpManager(std::vector<uint8_t> secret_seed = {});

    // Generates current 8-digit TOTP code
    std::string generate_code(uint64_t timestamp = 0) const;

    // Checks code validity and burns it atomically (single-use)
    // Returns true if code is valid and was successfully burned.
    // Subsequent calls with the same code return false (One-Time-Bind).
    bool verify_and_burn(const std::string& code, uint64_t timestamp = 0);

    // Remaining seconds before next rotation
    uint32_t remaining_seconds(uint64_t timestamp = 0) const;

    // Returns raw secret seed
    const std::vector<uint8_t>& secret_seed() const { return seed_; }

private:
    std::vector<uint8_t> seed_;
    mutable std::mutex mutex_;
    std::set<std::string> burned_codes_;
    uint64_t last_cleanup_step_{0};

    std::string compute_code_for_step(uint64_t step) const;
};

} // namespace slug::crypto
