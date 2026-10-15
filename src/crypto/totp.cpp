#include "src/crypto/totp.hpp"
#include "src/core/utils.hpp"
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <sstream>
#include <iomanip>

namespace slug::crypto {

TotpManager::TotpManager(std::vector<uint8_t> secret_seed)
    : seed_(std::move(secret_seed)) {
    if (seed_.empty()) {
        seed_ = core::Utils::random_bytes(32);
    }
}

std::string TotpManager::compute_code_for_step(uint64_t step) const {
    // Big-endian 8-byte step
    uint8_t step_bytes[8];
    for (int i = 7; i >= 0; --i) {
        step_bytes[i] = static_cast<uint8_t>(step & 0xFF);
        step >>= 8;
    }

    uint8_t mac[32];
    size_t mac_len = 0;
    OSSL_PARAM params[2];
    char md[] = "SHA256";
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, md, 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_Q_mac(nullptr, "HMAC", nullptr, nullptr, params,
              seed_.data(), seed_.size(),
              step_bytes, sizeof(step_bytes),
              mac, sizeof(mac), &mac_len);

    if (mac_len < 20) return "00000000";

    // Dynamic truncation per RFC 4226 / RFC 6238
    int offset = mac[mac_len - 1] & 0x0F;
    uint32_t binary =
        ((mac[offset] & 0x7F) << 24) |
        ((mac[offset + 1] & 0xFF) << 16) |
        ((mac[offset + 2] & 0xFF) << 8) |
        (mac[offset + 3] & 0xFF);

    uint32_t code_num = binary % 100000000; // 8 digits

    std::ostringstream oss;
    oss << std::setw(8) << std::setfill('0') << code_num;
    return oss.str();
}

std::string TotpManager::generate_code(uint64_t timestamp) const {
    if (timestamp == 0) timestamp = core::Utils::current_timestamp();
    uint64_t step = timestamp / kStepSeconds;
    return compute_code_for_step(step);
}

uint32_t TotpManager::remaining_seconds(uint64_t timestamp) const {
    if (timestamp == 0) timestamp = core::Utils::current_timestamp();
    return kStepSeconds - static_cast<uint32_t>(timestamp % kStepSeconds);
}

bool TotpManager::verify_and_burn(const std::string& code, uint64_t timestamp) {
    if (code.size() != 8) return false;
    if (timestamp == 0) timestamp = core::Utils::current_timestamp();

    uint64_t cur_step = timestamp / kStepSeconds;

    std::lock_guard<std::mutex> lock(mutex_);

    // Check if code was already burned
    if (burned_codes_.find(code) != burned_codes_.end()) {
        return false; // Token burned / invalid!
    }

    // Allow current step, or step-1 to accommodate clock drift (grace period)
    bool matched = false;
    std::string step_code = compute_code_for_step(cur_step);
    if (core::Utils::constant_time_compare(step_code, code)) {
        matched = true;
    } else if (cur_step > 0) {
        std::string prev_code = compute_code_for_step(cur_step - 1);
        if (core::Utils::constant_time_compare(prev_code, code)) {
            matched = true;
        }
    }

    if (!matched) {
        return false;
    }

    // Burn token immediately
    burned_codes_.insert(code);

    // Housekeeping: periodic cleanup if history grows too large
    if (cur_step > last_cleanup_step_ + 10) {
        last_cleanup_step_ = cur_step;
        if (burned_codes_.size() > 1000) {
            burned_codes_.clear();
            burned_codes_.insert(code);
        }
    }

    return true;
}

} // namespace slug::crypto
