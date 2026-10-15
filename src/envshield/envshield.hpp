#pragma once

#include "src/core/types.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <map>

namespace slug::envshield {

class EnvShield {
public:
    // Encrypts .env into .env.pqc using Suite 3 (BLAKE3 + ML-KEM-768 + XChaCha20-Poly1305 + ML-DSA-65)
    static bool init(const std::filesystem::path& workspace_root,
                     core::SuiteID suite_id = core::SuiteID::SUITE_3_PURE_PQC);

    // Decrypts .env.pqc directly on RAM and executes command with injected environment variables
    static int run(const std::filesystem::path& workspace_root,
                   const std::vector<std::string>& command_and_args);

    // Parses a .env format string into key-value map
    static std::map<std::string, std::string> parse_env_content(const std::string& content);
};

} // namespace slug::envshield
