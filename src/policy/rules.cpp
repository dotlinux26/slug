#include "src/policy/rules.hpp"
#include "src/core/utils.hpp"
#include "src/platform/fs.hpp"
#include <fstream>
#include <sstream>

namespace slug::policy {

RulesManager::RulesManager(std::filesystem::path rules_file)
    : rules_file_(std::move(rules_file)) {
    if (!rules_file_.empty()) {
        load();
    }
}

SlugRule RulesManager::parse_rule_line(const std::string& line) {
    SlugRule rule;
    std::string s = core::Utils::trim(line);
    if (s.empty()) return rule;

    // Check for XML-like tag: # <rule id="..." action="..." type="...">value</rule>
    // or without leading #
    if (s.front() == '#') {
        s = core::Utils::trim(s.substr(1));
    }

    if (s.rfind("<rule", 0) == 0) {
        // Parse attributes
        auto get_attr = [&](const std::string& attr_name) -> std::string {
            std::string needle = attr_name + "=\"";
            size_t pos = s.find(needle);
            if (pos == std::string::npos) return "";
            size_t start = pos + needle.size();
            size_t end = s.find('"', start);
            if (end == std::string::npos) return "";
            return s.substr(start, end - start);
        };

        rule.id = get_attr("id");
        if (rule.id.empty()) {
            static int auto_id = 1;
            rule.id = "r_" + std::to_string(auto_id++);
        }

        std::string act = get_attr("action");
        rule.action = (act == "allow") ? RuleAction::ALLOW : RuleAction::BLOCK;

        std::string typ = get_attr("type");
        if (typ == "ext") rule.type = RuleType::EXT;
        else if (typ == "content") rule.type = RuleType::CONTENT;
        else if (typ == "regex") rule.type = RuleType::REGEX;
        else rule.type = RuleType::PATH;

        size_t close_bracket = s.find('>');
        size_t end_tag = s.find("</rule>", close_bracket);
        if (close_bracket != std::string::npos && end_tag != std::string::npos) {
            rule.value = s.substr(close_bracket + 1, end_tag - (close_bracket + 1));
        }

        if (rule.type == RuleType::REGEX) {
            try {
                rule.regex = std::regex(rule.value, std::regex::icase);
            } catch (...) {}
        }
    } else {
        // Plain gitignore-style rule in rules.conf
        rule.id = "rule_" + std::to_string(rule.value.size());
        rule.action = RuleAction::BLOCK;
        rule.type = RuleType::PATH;
        rule.value = s;
    }
    return rule;
}

bool RulesManager::load() {
    rules_.clear();
    if (rules_file_.empty() || !std::filesystem::exists(rules_file_)) {
        return false;
    }

    auto content = platform::PathUtils::read_text_file(rules_file_);
    if (!content) return false;

    auto lines = core::Utils::split(*content, '\n');
    for (const auto& line : lines) {
        SlugRule rule = parse_rule_line(line);
        if (!rule.value.empty()) {
            rules_.push_back(std::move(rule));
        }
    }
    return true;
}

bool RulesManager::save() const {
    if (rules_file_.empty()) return false;

    std::ostringstream oss;
    oss << "# Slug Rules Configuration (.slug/rules.conf)\n";
    oss << "# Automatically managed by slug rule commands\n\n";

    for (const auto& r : rules_) {
        oss << "# <rule id=\"" << r.id << "\" action=\""
            << (r.action == RuleAction::ALLOW ? "allow" : "block") << "\" type=\"";
        switch (r.type) {
            case RuleType::PATH: oss << "path"; break;
            case RuleType::EXT: oss << "ext"; break;
            case RuleType::CONTENT: oss << "content"; break;
            case RuleType::REGEX: oss << "regex"; break;
        }
        oss << "\">" << r.value << "</rule>\n";
    }

    return platform::PathUtils::write_text_file_atomic(rules_file_, oss.str());
}

bool RulesManager::add_rule(const std::string& id, RuleAction action, RuleType type, const std::string& value) {
    SlugRule rule;
    rule.id = id.empty() ? ("r_" + std::to_string(rules_.size() + 1)) : id;
    rule.action = action;
    rule.type = type;
    rule.value = value;
    if (type == RuleType::REGEX) {
        try {
            rule.regex = std::regex(value, std::regex::icase);
        } catch (...) {
            return false;
        }
    }

    // Replace if id exists
    for (auto& r : rules_) {
        if (r.id == rule.id) {
            r = std::move(rule);
            return save();
        }
    }

    rules_.push_back(std::move(rule));
    return save();
}

bool RulesManager::remove_rule(const std::string& id) {
    for (auto it = rules_.begin(); it != rules_.end(); ++it) {
        if (it->id == id) {
            rules_.erase(it);
            return save();
        }
    }
    return false;
}

const SlugRule* RulesManager::match(const std::string& protocol_path, std::string_view content) const {
    for (const auto& r : rules_) {
        switch (r.type) {
            case RuleType::PATH: {
                std::string pat = r.value;
                if (pat.rfind("./", 0) == 0) pat = pat.substr(2);

                if (protocol_path == pat || protocol_path == r.value || protocol_path.rfind(pat, 0) == 0) {
                    return &r;
                }
                // Check filename match (e.g. rule ".env" matches "subfolder/.env")
                std::filesystem::path pp(protocol_path);
                if (pp.filename().string() == pat || pp.filename().string() == r.value) {
                    return &r;
                }
                // Check wildcard pattern match
                if (pat.find('*') != std::string::npos) {
                    if (pat.back() == '*') {
                        std::string prefix = pat.substr(0, pat.size() - 1);
                        if (protocol_path.rfind(prefix, 0) == 0) return &r;
                    }
                }
                break;
            }
            case RuleType::EXT: {
                auto exts = core::Utils::split(r.value, ',');
                for (const auto& ext : exts) {
                    std::string clean_ext = core::Utils::trim(ext);
                    if (core::Utils::ends_with(protocol_path, clean_ext)) {
                        return &r;
                    }
                }
                break;
            }
            case RuleType::CONTENT: {
                if (!content.empty() && content.find(r.value) != std::string_view::npos) {
                    return &r;
                }
                break;
            }
            case RuleType::REGEX: {
                if (!content.empty()) {
                    std::string c_str(content);
                    if (std::regex_search(c_str, r.regex)) {
                        return &r;
                    }
                }
                break;
            }
        }
    }
    return nullptr;
}

} // namespace slug::policy
