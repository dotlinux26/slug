#pragma once

#include "src/policy/gitignore.hpp"
#include "src/policy/rules.hpp"
#include <string>
#include <filesystem>
#include <string_view>

namespace slug::policy {

struct FilterDecision {
    bool is_allowed{true};
    std::string rule_id;
    std::string reason;
};

class PolicyEngine {
public:
    PolicyEngine(std::filesystem::path workspace_root, std::filesystem::path rules_file = {});

    // Evaluate whether a file should be transferred or skipped
    FilterDecision evaluate(const std::filesystem::path& relative_path, bool is_dir, std::string_view content = {}) const;

    HierarchicalGitignore& gitignore() { return gitignore_; }
    const HierarchicalGitignore& gitignore() const { return gitignore_; }

    RulesManager& rules() { return rules_; }
    const RulesManager& rules() const { return rules_; }

private:
    std::filesystem::path workspace_root_;
    HierarchicalGitignore gitignore_;
    RulesManager rules_;
};

} // namespace slug::policy
