#include "src/policy/rules.hpp"
#include "src/core/utils.hpp"
#include "src/platform/fs.hpp"
#include <fstream>
#include <sstream>
#include <atomic>

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
    bool has_hash = false;
    if (s.front() == '#') {
        has_hash = true;
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
        if (has_hash) {
            // It is a comment line, e.g. "# Slug Rules Configuration" - do not convert to rule!
            return rule;
        }

        // Support syntax: ALLOW [type] <value> or BLOCK [type] <value>
        std::string upper_s = s;
        std::transform(upper_s.begin(), upper_s.end(), upper_s.begin(), ::toupper);
        if (upper_s.rfind("ALLOW ", 0) == 0 || upper_s.rfind("BLOCK ", 0) == 0) {
            bool is_allow = (upper_s.rfind("ALLOW ", 0) == 0);
            rule.action = is_allow ? RuleAction::ALLOW : RuleAction::BLOCK;
            std::string rest = core::Utils::trim(s.substr(6));
            std::string upper_rest = rest;
            std::transform(upper_rest.begin(), upper_rest.end(), upper_rest.begin(), ::tolower);

            if (upper_rest.rfind("path ", 0) == 0) {
                rule.type = RuleType::PATH;
                rule.value = core::Utils::trim(rest.substr(5));
            } else if (upper_rest.rfind("ext ", 0) == 0) {
                rule.type = RuleType::EXT;
                rule.value = core::Utils::trim(rest.substr(4));
            } else if (upper_rest.rfind("content ", 0) == 0) {
                rule.type = RuleType::CONTENT;
                rule.value = core::Utils::trim(rest.substr(8));
            } else if (upper_rest.rfind("regex ", 0) == 0) {
                rule.type = RuleType::REGEX;
                rule.value = core::Utils::trim(rest.substr(6));
                try { rule.regex = std::regex(rule.value, std::regex::icase); } catch (...) {}
            } else {
                rule.type = RuleType::PATH;
                rule.value = rest;
            }
        } else {
            // Plain gitignore-style rule in rules.conf / .slugignore
            rule.type = RuleType::PATH;
            if (s.front() == '!') {
                rule.action = RuleAction::ALLOW;
                rule.value = core::Utils::trim(s.substr(1));
            } else {
                rule.action = RuleAction::BLOCK;
                rule.value = s;
            }
        }
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
            // Filter out any ghost rules created from comment lines in legacy files
            if (rule.value.find("rules.conf") != std::string::npos ||
                rule.value.find("Automatically managed") != std::string::npos ||
                rule.value.find("Default Slug Rules") != std::string::npos) {
                continue;
            }
            if (rule.id.empty()) {
                rule.id = "rule_" + std::to_string(rules_.size() + 1);
            }
            rules_.push_back(std::move(rule));
        }
    }
    prune_redundant_rules();
    return true;
}

void RulesManager::prune_redundant_rules() {
    std::vector<std::string> allow_prefixes;
    for (const auto& r : rules_) {
        if (r.action == RuleAction::ALLOW && r.type == RuleType::PATH) {
            std::string pat = r.value;
            if (pat.rfind("./", 0) == 0) pat = pat.substr(2);
            size_t star_pos = pat.find('*');
            if (star_pos != std::string::npos) {
                allow_prefixes.push_back(pat.substr(0, star_pos));
            } else if (!pat.empty() && pat.back() == '/') {
                allow_prefixes.push_back(pat);
            } else if (!pat.empty() && pat.find('.') == std::string::npos) {
                allow_prefixes.push_back(pat + "/");
            }
        }
    }
    if (allow_prefixes.empty()) return;

    std::vector<SlugRule> kept;
    bool changed = false;
    for (const auto& r : rules_) {
        bool redundant = false;
        if (r.action == RuleAction::ALLOW && r.type == RuleType::PATH) {
            std::string pat = r.value;
            if (pat.rfind("./", 0) == 0) pat = pat.substr(2);
            // Don't prune the wildcard/directory rule itself
            if (pat.find('*') == std::string::npos && (pat.empty() || pat.back() != '/')) {
                for (const auto& pfx : allow_prefixes) {
                    if (!pfx.empty() && pat.rfind(pfx, 0) == 0 && pat != pfx) {
                        redundant = true;
                        changed = true;
                        break;
                    }
                }
            }
        }
        if (!redundant) kept.push_back(r);
    }
    if (changed) {
        rules_ = std::move(kept);
        save();
    }
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
    // If adding an ALLOW path rule, check if already covered by an existing ALLOW rule
    if (action == RuleAction::ALLOW && type == RuleType::PATH) {
        const auto* existing = match(value);
        if (existing && existing->action == RuleAction::ALLOW) {
            // Already allowed by a parent rule or wildcard; avoid creating redundant child rules
            return true;
        }
    }

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
            prune_redundant_rules();
            return save();
        }
    }

    rules_.push_back(std::move(rule));
    prune_redundant_rules();
    return save();
}

bool RulesManager::remove_rule(const std::string& id) {
    for (auto it = rules_.begin(); it != rules_.end(); ++it) {
        if (it->id == id || it->value == id ||
            ("BLOCK path " + it->value) == id ||
            ("ALLOW path " + it->value) == id) {
            rules_.erase(it);
            return save();
        }
    }
    return false;
}

const SlugRule* RulesManager::match(const std::string& protocol_path, std::string_view content) const {
    const SlugRule* last_match = nullptr;
    for (const auto& r : rules_) {
        bool matches = false;
        switch (r.type) {
            case RuleType::PATH: {
                std::string pat = r.value;
                if (pat.rfind("./", 0) == 0) pat = pat.substr(2);

                if (protocol_path == pat || protocol_path == r.value) {
                    matches = true;
                } else {
                    std::filesystem::path pp(protocol_path);
                    std::string fname = pp.filename().generic_string();
                    if (fname == pat || fname == r.value) {
                        matches = true;
                    } else if (!pat.empty() && pat.back() == '/') {
                        // Directory match: e.g. "node_modules/" matches "node_modules/foo" or "sub/node_modules/foo"
                        if (protocol_path.rfind(pat, 0) == 0 || protocol_path.find("/" + pat) != std::string::npos) {
                            matches = true;
                        }
                    } else if (pat.find('*') != std::string::npos) {
                        if (pat.front() == '*' && pat.back() != '*') {
                            // Suffix wildcard: e.g. "*.example", "*.tmp", "*.bak"
                            std::string suffix = pat.substr(1);
                            if (core::Utils::ends_with(protocol_path, suffix) || core::Utils::ends_with(fname, suffix)) {
                                matches = true;
                            }
                        } else if (pat.back() == '*' && pat.front() != '*') {
                            // Prefix wildcard: e.g. ".env*"
                            std::string prefix = pat.substr(0, pat.size() - 1);
                            if (protocol_path.rfind(prefix, 0) == 0 || fname.rfind(prefix, 0) == 0) {
                                matches = true;
                            }
                        } else if (pat == "*") {
                            matches = true;
                        }
                    } else if (protocol_path.rfind(pat + "/", 0) == 0 || protocol_path.find("/" + pat + "/") != std::string::npos) {
                        matches = true;
                    }
                }
                break;
            }
            case RuleType::EXT: {
                auto exts = core::Utils::split(r.value, ',');
                for (const auto& ext : exts) {
                    std::string clean_ext = core::Utils::trim(ext);
                    if (core::Utils::ends_with(protocol_path, clean_ext)) {
                        matches = true;
                        break;
                    }
                }
                break;
            }
            case RuleType::CONTENT: {
                if (!content.empty() && content.find(r.value) != std::string_view::npos) {
                    matches = true;
                }
                break;
            }
            case RuleType::REGEX: {
                if (!content.empty()) {
                    std::string c_str(content);
                    if (std::regex_search(c_str, r.regex)) {
                        matches = true;
                    }
                }
                break;
            }
        }
        if (matches) {
            last_match = &r;
        }
    }
    return last_match;
}

} // namespace slug::policy
