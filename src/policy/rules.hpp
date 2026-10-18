#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <regex>

namespace slug::policy {

enum class RuleAction {
    BLOCK,
    ALLOW
};

enum class RuleType {
    PATH,
    EXT,
    CONTENT,
    REGEX
};

struct SlugRule {
    std::string id;
    RuleAction action{RuleAction::BLOCK};
    RuleType type{RuleType::PATH};
    std::string value;
    std::regex regex;
};

class RulesManager {
public:
    explicit RulesManager(std::filesystem::path rules_file = {});

    bool load();
    bool save() const;

    bool add_rule(const std::string& id, RuleAction action, RuleType type, const std::string& value);
    bool remove_rule(const std::string& id);
    const std::vector<SlugRule>& rules() const { return rules_; }
    void prune_redundant_rules();

    // Evaluates against a file path and optionally its content
    // Returns matching rule pointer or nullptr
    const SlugRule* match(const std::string& protocol_path, std::string_view content = {}) const;

private:
    std::filesystem::path rules_file_;
    std::vector<SlugRule> rules_;

    static SlugRule parse_rule_line(const std::string& line);
};

} // namespace slug::policy
