#pragma once

#include "src/core/types.hpp"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <optional>
#include <filesystem>

namespace slug::core {

struct UserAccount {
    std::string username;
    std::string password_hash; // SHA-256 or BLAKE3 hash of password
    Role role{Role::READ_ONLY};
    uint64_t created_at{0};
    uint64_t expires_at{0};   // 0 = no expiration, otherwise unix epoch seconds
    bool revoked{false};

    bool is_expired(uint64_t now = 0) const;
    bool has_permission(Role required) const;
};

class AclManager {
public:
    explicit AclManager(std::filesystem::path storage_path = {});

    bool load();
    bool save() const;

    bool add_user(const std::string& username, const std::string& password, Role role, uint64_t ttl_seconds = 86400);
    bool remove_user(const std::string& username);
    std::vector<UserAccount> list_users() const;
    std::optional<UserAccount> get_user(const std::string& username) const;

    // Authenticates user and checks role permission
    bool authenticate(const std::string& username, const std::string& password, Role required_role) const;

private:
    std::filesystem::path storage_path_;
    mutable std::mutex mutex_;
    std::map<std::string, UserAccount> users_;

    static std::string hash_password(const std::string& password);
};

} // namespace slug::core
