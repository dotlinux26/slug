#include "src/platform/process.hpp"
#include <iostream>
#include <cstdlib>
#include <cstring>

#if defined(SLUG_PLATFORM_POSIX)
extern "C" char **environ;
#endif

namespace slug::platform {

int ProcessUtils::run_process_with_env(const std::vector<std::string>& command_and_args,
                                       const std::map<std::string, std::string>& injected_env) {
    if (command_and_args.empty()) return -1;

#if defined(SLUG_PLATFORM_POSIX)
    // Build combined environment: current environ + injected_env
    std::map<std::string, std::string> env_map;
    for (char** env = environ; *env != nullptr; ++env) {
        std::string entry(*env);
        size_t eq = entry.find('=');
        if (eq != std::string::npos) {
            env_map[entry.substr(0, eq)] = entry.substr(eq + 1);
        }
    }
    for (const auto& [k, v] : injected_env) {
        env_map[k] = v;
    }

    std::vector<std::string> env_strings;
    std::vector<char*> env_ptrs;
    for (const auto& [k, v] : env_map) {
        env_strings.push_back(k + "=" + v);
    }
    for (auto& s : env_strings) {
        env_ptrs.push_back(s.data());
    }
    env_ptrs.push_back(nullptr);

    std::vector<char*> arg_ptrs;
    for (const auto& arg : command_and_args) {
        arg_ptrs.push_back(const_cast<char*>(arg.c_str()));
    }
    arg_ptrs.push_back(nullptr);

    pid_t pid = fork();
    if (pid == 0) {
        // Child process: execute command
        execvpe(arg_ptrs[0], arg_ptrs.data(), env_ptrs.data());
        // If execvpe fails, try searching PATH manually or execvp
        std::cerr << "slug: failed to execute " << arg_ptrs[0] << " (" << strerror(errno) << ")" << std::endl;
        _exit(127);
    } else if (pid > 0) {
        // Parent process: wait for child
        int status = 0;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        return -1;
    } else {
        return -1;
    }

#elif defined(SLUG_PLATFORM_WINDOWS)
    // Windows CreateProcess with environment block
    std::wstring cmd_line;
    for (size_t i = 0; i < command_and_args.size(); ++i) {
        if (i > 0) cmd_line += L" ";
        std::string a = command_and_args[i];
        std::wstring wa(a.begin(), a.end());
        if (wa.find(L' ') != std::wstring::npos) {
            cmd_line += L"\"" + wa + L"\"";
        } else {
            cmd_line += wa;
        }
    }

    // Inherit current environment and overlay injected variables
    // Environment block in Windows is a null-terminated block of null-terminated strings
    std::vector<wchar_t> env_block;
    LPWCH cur_env = GetEnvironmentStringsW();
    if (cur_env) {
        LPWCH var = cur_env;
        while (*var) {
            std::wstring s(var);
            size_t eq = s.find(L'=');
            if (eq != std::wstring::npos && eq > 0) {
                std::string k(s.begin(), s.begin() + eq);
                if (injected_env.find(k) == injected_env.end()) {
                    for (wchar_t c : s) env_block.push_back(c);
                    env_block.push_back(L'\0');
                }
            }
            var += s.length() + 1;
        }
        FreeEnvironmentStringsW(cur_env);
    }
    for (const auto& [k, v] : injected_env) {
        std::string entry = k + "=" + v;
        std::wstring wentry(entry.begin(), entry.end());
        for (wchar_t c : wentry) env_block.push_back(c);
        env_block.push_back(L'\0');
    }
    env_block.push_back(L'\0'); // double null termination

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> cmd_buf(cmd_line.begin(), cmd_line.end());
    cmd_buf.push_back(L'\0');

    if (!CreateProcessW(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE,
                        CREATE_UNICODE_ENVIRONMENT, env_block.data(), nullptr, &si, &pi)) {
        return -1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exit_code);
#endif
}

} // namespace slug::platform
