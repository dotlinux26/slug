#include "src/policy/gitignore.hpp"
#include "src/core/utils.hpp"
#include "src/platform/fs.hpp"
#include <fstream>
#include <iostream>

namespace slug::policy {

namespace fs = std::filesystem;

std::regex HierarchicalGitignore::glob_to_regex(const std::string& pattern, bool is_dir_only) {
    std::string rx = "^";
    bool leading_slash = (!pattern.empty() && pattern.front() == '/');
    std::string pat = leading_slash ? pattern.substr(1) : pattern;

    if (!leading_slash) {
        // Can match anywhere in subdirectory
        rx += "(?:.*/)?";
    }

    for (size_t i = 0; i < pat.size(); ++i) {
        char c = pat[i];
        if (c == '*') {
            if (i + 1 < pat.size() && pat[i + 1] == '*') {
                rx += ".*";
                i++;
                if (i + 1 < pat.size() && pat[i + 1] == '/') {
                    rx += "/?";
                    i++;
                }
            } else {
                rx += "[^/]*";
            }
        } else if (c == '?') {
            rx += "[^/]";
        } else if (c == '.' || c == '+' || c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}' || c == '^' || c == '$' || c == '|') {
            rx += '\\';
            rx += c;
        } else {
            rx += c;
        }
    }

    if (is_dir_only) {
        rx += "(?:/.*)?$";
    } else {
        rx += "(?:/.*)?$";
    }

    try {
        return std::regex(rx, std::regex::ECMAScript);
    } catch (...) {
        return std::regex(".*a^"); // Matches nothing
    }
}

bool HierarchicalGitignore::load_gitignore(const fs::path& gitignore_path, const fs::path& workspace_root) {
    auto content = platform::PathUtils::read_text_file(gitignore_path);
    if (!content) return false;

    fs::path scope = gitignore_path.parent_path().lexically_relative(workspace_root);
    if (scope == ".") scope = "";

    auto lines = core::Utils::split(*content, '\n');
    for (auto& raw_line : lines) {
        std::string line = core::Utils::trim(raw_line);
        if (line.empty() || line.front() == '#') continue;

        GitignoreRule rule;
        rule.scope_dir = scope;

        if (line.front() == '!') {
            rule.is_negation = true;
            line = core::Utils::trim(line.substr(1));
        }

        if (!line.empty() && line.back() == '/') {
            rule.is_directory_only = true;
            line.pop_back();
        }

        rule.pattern = line;
        rule.regex = glob_to_regex(line, rule.is_directory_only);
        rules_.push_back(std::move(rule));
    }
    return true;
}

void HierarchicalGitignore::scan_and_load_all(const fs::path& workspace_root) {
    rules_.clear();
    std::error_code ec;
    if (!fs::exists(workspace_root, ec)) return;

    for (const auto& entry : fs::recursive_directory_iterator(workspace_root, fs::directory_options::skip_permission_denied, ec)) {
        if (entry.is_regular_file(ec) && entry.path().filename() == ".gitignore") {
            load_gitignore(entry.path(), workspace_root);
        }
    }
}

bool HierarchicalGitignore::is_ignored(const fs::path& relative_path, bool is_dir) const {
    std::string rel_str = platform::PathUtils::to_protocol_path(relative_path);
    if (rel_str.empty()) return false;

    bool ignored = false;
    for (const auto& rule : rules_) {
        std::string scope_str = platform::PathUtils::to_protocol_path(rule.scope_dir);
        std::string test_str = rel_str;

        if (!scope_str.empty()) {
            // Path must fall under scope directory
            if (test_str != scope_str && test_str.rfind(scope_str + "/", 0) != 0) {
                continue;
            }
            test_str = test_str.substr(scope_str.size() + 1);
        }

        if (rule.is_directory_only && !is_dir) {
            // Check if leading directory component matches
            size_t slash = test_str.find('/');
            if (slash == std::string::npos) continue;
        }

        if (std::regex_match(test_str, rule.regex)) {
            ignored = !rule.is_negation;
        }
    }

    return ignored;
}

} // namespace slug::policy
