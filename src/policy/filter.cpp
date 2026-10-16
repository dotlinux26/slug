#include "src/policy/filter.hpp"
#include "src/platform/fs.hpp"

namespace slug::policy {

PolicyEngine::PolicyEngine(std::filesystem::path workspace_root, std::filesystem::path rules_file)
    : workspace_root_(std::move(workspace_root)), rules_(std::move(rules_file)) {
    gitignore_.scan_and_load_all(workspace_root_);
}

FilterDecision PolicyEngine::evaluate(const std::filesystem::path& relative_path, bool is_dir, std::string_view content, bool ignore_gitignore) const {
    std::string proto_path = platform::PathUtils::to_protocol_path(relative_path);

    // 1. Mandatory isolation: .slug/ and .git/ internal metadata are unconditionally blocked
    if (platform::PathUtils::is_internal_slug_path(relative_path)) {
        return {false, "mandatory_internal", "Internal Slug or Git metadata is strictly protected"};
    }

    // 2. Explicit rules in .slug/rules.conf (Allow or Block)
    const SlugRule* matched_rule = rules_.match(proto_path, content);
    if (matched_rule) {
        if (matched_rule->action == RuleAction::ALLOW) {
            return {true, matched_rule->id, "Explicitly allowed by rule " + matched_rule->id};
        } else {
            return {false, matched_rule->id, "Blocked by rule " + matched_rule->id + " (" + matched_rule->value + ")"};
        }
    }

    // 3. Hierarchical .gitignore evaluation (skipped if ignore_gitignore is true)
    if (!ignore_gitignore && gitignore_.is_ignored(relative_path, is_dir)) {
        return {false, "gitignore", "Ignored by .gitignore"};
    }

    return {true, "", ""};
}

} // namespace slug::policy
