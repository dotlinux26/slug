#include "src/core/acl.hpp"
#include "src/core/utils.hpp"
#include "src/crypto/sha256.hpp"
#include "src/platform/fs.hpp"
#include "third_party/json/json.hpp"
#include <fstream>

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
    return crypto::Sha256::hash_hex(password);
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

bool AclManager::authenticate(const std::string& username, const std::string& password, Role required_role) const {
    const_cast<AclManager*>(this)->load();
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = users_.find(username);
    if (it == users_.end()) return false;

    const auto& acc = it->second;
    if (acc.is_expired()) return false;
    if (!acc.has_permission(required_role)) return false;

    // Verify password hash
    std::string h = hash_password(password);
    return Utils::constant_time_compare(h, acc.password_hash);
}

} // namespace slug::core
