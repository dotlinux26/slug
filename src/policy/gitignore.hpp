#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <regex>

namespace slug::policy {

struct GitignoreRule {
    std::string pattern;
    std::filesystem::path scope_dir; // Directory where this .gitignore was found
    bool is_negation{false};
    bool is_directory_only{false};
    std::regex regex;
};

class HierarchicalGitignore {
public:
    HierarchicalGitignore() = default;

    // Load .gitignore for a specific directory scope
    bool load_gitignore(const std::filesystem::path& gitignore_path, const std::filesystem::path& workspace_root);

    // Recursively scan workspace and load all .gitignore files in subdirectories
    void scan_and_load_all(const std::filesystem::path& workspace_root);

    // Check if relative_path (from workspace_root) is ignored
    bool is_ignored(const std::filesystem::path& relative_path, bool is_dir) const;

    const std::vector<GitignoreRule>& rules() const { return rules_; }

private:
    std::vector<GitignoreRule> rules_;

    static std::regex glob_to_regex(const std::string& pattern, bool is_dir_only);
};

} // namespace slug::policy
