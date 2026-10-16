#pragma once

#include "src/core/types.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <map>

namespace slug::envshield {

struct EnvVaultEntry {
    std::string filename;
    uint64_t timestamp{0};
    std::string blake3_hash;
    uint64_t size_bytes{0};
    uint32_t version{1};
};

class EnvShield {
public:
    // Encrypts .env into .env.pqc using Post-Quantum suite, backs up to Central Vault, removes plaintext (unless keep_plaintext)
    static bool init(const std::filesystem::path& workspace_root,
                     core::SuiteID suite_id = core::SuiteID::SUITE_2_MODERN,
                     bool keep_plaintext = false);

    // Restores original .env plaintext from Central Vault (or decrypts .env.pqc) and removes .env.pqc
    static bool restore(const std::filesystem::path& workspace_root);

    // Lists backup history in Central Vault for this workspace
    static std::vector<EnvVaultEntry> history(const std::filesystem::path& workspace_root);

    // Returns the AI Agent Directive prompt string
    static std::string agent_prompt(const std::filesystem::path& workspace_root);

    // Decrypts .env.pqc directly on RAM and executes command with injected environment variables
    static int run(const std::filesystem::path& workspace_root,
                   const std::vector<std::string>& command_and_args);

    // Parses a .env format string into key-value map
    static std::map<std::string, std::string> parse_env_content(const std::string& content);

    // Computes unique hash for workspace based on normalized absolute path
    static std::string get_workspace_hash(const std::filesystem::path& workspace_root);

    // Returns path to Central Vault directory for this workspace (~/.slug/env_vault/<workspace_hash>/)
    static std::filesystem::path get_vault_dir(const std::filesystem::path& workspace_root);
};

} // namespace slug::envshield

