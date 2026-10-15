#pragma once

#include "src/platform/platform.hpp"
#include <string>
#include <vector>
#include <map>

namespace slug::platform {

class ProcessUtils {
public:
    // Runs a command with the given arguments, injecting extra environment variables directly into RAM.
    // Blocks until completion and returns the process exit code.
    static int run_process_with_env(const std::vector<std::string>& command_and_args,
                                    const std::map<std::string, std::string>& injected_env);
};

} // namespace slug::platform
