#pragma once

#include "src/core/types.hpp"
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <cstdint>
#include <optional>

namespace slug::crypto {

class TotpManager {
public:
    static constexpr uint32_t kStepSeconds = 60; // 60s rotation
    static constexpr size_t kCodeDigits = 8;     // 8 digits

    explicit TotpManager(std::vector<uint8_t> secret_seed = {});

    // Generates current 8-digit TOTP code for a specific role (default: READ_WRITE)
    std::string generate_code(core::Role role = core::Role::READ_WRITE, uint64_t timestamp = 0) const;

    // Checks code validity, returns the verified role, and burns it atomically (single-use)
    std::optional<core::Role> verify_and_burn_role(const std::string& code, uint64_t timestamp = 0);

    // Backward-compatible overload: returns true if code is valid for any role and burns it
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

    std::string compute_code_for_step(uint64_t step, core::Role role) const;
};

} // namespace slug::crypto
