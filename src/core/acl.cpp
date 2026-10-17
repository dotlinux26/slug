#include "src/core/acl.hpp"
#include "src/core/utils.hpp"
#include "src/crypto/sha256.hpp"
#include "src/platform/fs.hpp"
#include "third_party/json/json.hpp"
#include <fstream>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace slug::core {

using json = nlohmann::json;

bool UserAccount::is_expired(uint64_t now) const {
    if (revoked) return true;
    if (expires_at == 0) return false;
    if (now == 0) now = Utils::current_timestamp();
    return now >= expires_at;
}

bool UserAccount::has_permission(Role required) const {
    if (role == Role::READ_WRITE) return true;
    return role == required;
}

std::string AclManager::hash_password(const std::string& password) {
    constexpr int kIterations = 100000;
    constexpr int kSaltLen = 16;
    constexpr int kKeyLen = 32;

    std::vector<uint8_t> salt(kSaltLen);
    if (RAND_bytes(salt.data(), kSaltLen) != 1) {
        auto rb = Utils::random_bytes(kSaltLen);
        std::memcpy(salt.data(), rb.data(), kSaltLen);
    }

    std::vector<uint8_t> derived_key(kKeyLen);
    PKCS5_PBKDF2_HMAC(
        password.data(), static_cast<int>(password.size()),
        salt.data(), static_cast<int>(salt.size()),
        kIterations, EVP_sha256(),
        kKeyLen, derived_key.data()
    );

    std::string salt_hex = Utils::to_hex(salt);
    std::string key_hex = Utils::to_hex(derived_key);
    return "$pbkdf2$" + std::to_string(kIterations) + "$" + salt_hex + "$" + key_hex;
}

bool AclManager::verify_password(const std::string& password, const std::string& stored_hash) {
    if (stored_hash.rfind("$pbkdf2$", 0) == 0) {
        auto parts = Utils::split(stored_hash, '$');
        if (parts.size() >= 5) {
            try {
                int iterations = std::stoi(parts[2]);
                std::string salt_hex = parts[3];
                std::string expected_key_hex = parts[4];
                auto salt = Utils::from_hex(salt_hex);
                int key_len = static_cast<int>(expected_key_hex.size() / 2);
                if (key_len > 0) {
                    std::vector<uint8_t> derived_key(key_len);
                    PKCS5_PBKDF2_HMAC(
                        password.data(), static_cast<int>(password.size()),
                        salt.data(), static_cast<int>(salt.size()),
                        iterations, EVP_sha256(),
                        key_len, derived_key.data()
                    );
                    std::string derived_key_hex = Utils::to_hex(derived_key);
                    return Utils::constant_time_compare(derived_key_hex, expected_key_hex);
                }
            } catch (...) {}
        }
    }

    // Backward compatibility: SHA-256 legacy hash check
    std::string legacy_hash = crypto::Sha256::hash_hex(password);
    return Utils::constant_time_compare(legacy_hash, stored_hash);
}

AclManager::AclManager(std::filesystem::path storage_path)
    : storage_path_(std::move(storage_path)) {
    if (!storage_path_.empty()) {
        load();
    }
}

bool AclManager::load() {
    std::lock_guard<std::mutex> lock(mutex_);
    users_.clear();

    if (storage_path_.empty() || !std::filesystem::exists(storage_path_)) {
        return false;
    }

    auto content = platform::PathUtils::read_text_file(storage_path_);
    if (!content) return false;

    try {
        auto j = json::parse(*content);
        if (j.contains("users") && j["users"].is_array()) {
            for (const auto& u : j["users"]) {
                UserAccount acc;
                acc.username = u.value("username", "");
                acc.password_hash = u.value("password_hash", "");
                acc.role = role_from_string(u.value("role", "r"));
                acc.created_at = u.value("created_at", 0ULL);
                acc.expires_at = u.value("expires_at", 0ULL);
                acc.revoked = u.value("revoked", false);
                if (!acc.username.empty()) {
                    users_[acc.username] = acc;
                }
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool AclManager::save() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (storage_path_.empty()) return false;

    json j;
    j["users"] = json::array();
    for (const auto& [_, u] : users_) {
        json item;
        item["username"] = u.username;
        item["password_hash"] = u.password_hash;
        item["role"] = role_to_string(u.role);
        item["created_at"] = u.created_at;
        item["expires_at"] = u.expires_at;
        item["revoked"] = u.revoked;
        j["users"].push_back(item);
    }

    return platform::PathUtils::write_text_file_atomic(storage_path_, j.dump(2));
}

bool AclManager::add_user(const std::string& username, const std::string& password, Role role, uint64_t ttl_seconds) {
    if (username.empty()) return false;
    load();

    uint64_t now = Utils::current_timestamp();
    UserAccount acc;
    acc.username = username;
    acc.password_hash = hash_password(password);
    acc.role = role;
    acc.created_at = now;
    acc.expires_at = (ttl_seconds > 0) ? (now + ttl_seconds) : 0;
    acc.revoked = false;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        users_[username] = acc;
    }
    return save();
}

bool AclManager::update_user(const std::string& username, const std::string& new_password, std::optional<Role> new_role, std::optional<uint64_t> new_ttl_seconds) {
    if (username.empty()) return false;
    load();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = users_.find(username);
        if (it == users_.end()) return false;
        if (!new_password.empty()) {
            it->second.password_hash = hash_password(new_password);
        }
        if (new_role.has_value()) {
            it->second.role = *new_role;
        }
        if (new_ttl_seconds.has_value()) {
            uint64_t now = Utils::current_timestamp();
            it->second.expires_at = (*new_ttl_seconds > 0) ? (now + *new_ttl_seconds) : 0;
            it->second.revoked = false;
        }
    }
    return save();
}

bool AclManager::remove_user(const std::string& username) {
    load();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = users_.find(username);
        if (it == users_.end()) return false;
        users_.erase(it);
    }
    return save();
}

std::vector<UserAccount> AclManager::list_users() const {
    const_cast<AclManager*>(this)->load();
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<UserAccount> res;
    for (const auto& [_, u] : users_) {
        res.push_back(u);
    }
    return res;
}

std::optional<UserAccount> AclManager::get_user(const std::string& username) const {
    const_cast<AclManager*>(this)->load();
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = users_.find(username);
    if (it != users_.end()) return it->second;
    return std::nullopt;
}

bool AclManager::authenticate(const std::string& username, const std::string& password, std::optional<Role> required_role) const {
    const_cast<AclManager*>(this)->load();
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = users_.find(username);
    if (it == users_.end()) return false;

    const auto& acc = it->second;
    if (acc.is_expired()) return false;
    if (required_role.has_value() && !acc.has_permission(*required_role)) return false;

    // Verify password hash (PBKDF2 with legacy SHA-256 fallback)
    return verify_password(password, acc.password_hash);
}

} // namespace slug::core
