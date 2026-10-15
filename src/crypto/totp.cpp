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

std::string TotpManager::compute_code_for_step(uint64_t step, core::Role role) const {
    // Big-endian 8-byte step + 1-byte role prefix ('r', 'w', 'x' for rw)
    uint8_t data[9];
    uint64_t s = step;
    for (int i = 7; i >= 0; --i) {
        data[i] = static_cast<uint8_t>(s & 0xFF);
        s >>= 8;
    }
    uint8_t role_byte = 'x'; // default rw
    if (role == core::Role::READ_ONLY) role_byte = 'r';
    else if (role == core::Role::WRITE_ONLY) role_byte = 'w';
    else if (role == core::Role::READ_WRITE) role_byte = 'x';
    data[8] = role_byte;

    uint8_t mac[32];
    size_t mac_len = 0;
    OSSL_PARAM params[2];
    char md[] = "SHA256";
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, md, 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_Q_mac(nullptr, "HMAC", nullptr, nullptr, params,
              seed_.data(), seed_.size(),
              data, sizeof(data),
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

std::string TotpManager::generate_code(core::Role role, uint64_t timestamp) const {
    if (timestamp == 0) timestamp = core::Utils::current_timestamp();
    uint64_t step = timestamp / kStepSeconds;
    return compute_code_for_step(step, role);
}

uint32_t TotpManager::remaining_seconds(uint64_t timestamp) const {
    if (timestamp == 0) timestamp = core::Utils::current_timestamp();
    return kStepSeconds - static_cast<uint32_t>(timestamp % kStepSeconds);
}

std::optional<core::Role> TotpManager::verify_and_burn_role(const std::string& code, uint64_t timestamp) {
    if (code.size() != 8) return std::nullopt;
    if (timestamp == 0) timestamp = core::Utils::current_timestamp();

    uint64_t cur_step = timestamp / kStepSeconds;

    std::lock_guard<std::mutex> lock(mutex_);

    // Check if code was already burned
    if (burned_codes_.find(code) != burned_codes_.end()) {
        return std::nullopt; // Token burned / invalid!
    }

    const std::vector<core::Role> candidate_roles = {
        core::Role::READ_WRITE,
        core::Role::READ_ONLY,
        core::Role::WRITE_ONLY
    };

    std::optional<core::Role> matched_role;
    for (auto r : candidate_roles) {
        std::string step_code = compute_code_for_step(cur_step, r);
        if (core::Utils::constant_time_compare(step_code, code)) {
            matched_role = r;
            break;
        }
        if (cur_step > 0) {
            std::string prev_code = compute_code_for_step(cur_step - 1, r);
            if (core::Utils::constant_time_compare(prev_code, code)) {
                matched_role = r;
                break;
            }
        }
    }

    if (!matched_role) {
        return std::nullopt;
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

    return matched_role;
}

bool TotpManager::verify_and_burn(const std::string& code, uint64_t timestamp) {
    return verify_and_burn_role(code, timestamp).has_value();
}

} // namespace slug::crypto
