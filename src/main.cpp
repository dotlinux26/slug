#include "src/core/workspace.hpp"
#include "src/core/connection_manager.hpp"
#include "src/core/utils.hpp"
#include "src/core/acl.hpp"
#include "src/crypto/blake3_wrapper.hpp"
#include "src/policy/rules.hpp"
#include "src/ai/stateful_audit.hpp"
#include "src/ai/scanner.hpp"
#include "src/net/client.hpp"
#include "src/envshield/envshield.hpp"
#include "src/bench/benchmark.hpp"
#include "src/platform/platform.hpp"
#include "src/platform/fs.hpp"
#include "src/platform/socket.hpp"
#include "src/net/web_assets.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>
#include <cstdlib>
#include <algorithm>
#include <set>

static std::atomic<bool> g_stop_signal_received{false};
static void signal_handler(int) {
    g_stop_signal_received = true;
}

#if defined(SLUG_PLATFORM_POSIX)
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static std::string read_hidden_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    termios old_t, new_t;
    tcgetattr(STDIN_FILENO, &old_t);
    new_t = old_t;
    new_t.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_t);

    std::string pass;
    std::getline(std::cin, pass);

    tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
    std::cout << std::endl;
    return pass;
}

static std::string read_confirmed_hidden_password(const std::string& prompt) {
    while (true) {
        std::string p1 = read_hidden_password(prompt);
        if (p1.empty()) {
            std::cerr << "[-] Password cannot be empty. Please try again." << std::endl;
            continue;
        }
        std::string p2 = read_hidden_password("Retype password: ");
        if (p1 == p2) {
            return p1;
        }
        std::cerr << "[-] Passwords do not match. Please try again." << std::endl;
    }
}

static std::string get_host_lan_ip() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return "127.0.0.1";
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = inet_addr("8.8.8.8");
    target.sin_port = htons(53);
    if (connect(sock, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == -1) {
        close(sock);
        return "127.0.0.1";
    }
    sockaddr_in name{};
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, reinterpret_cast<sockaddr*>(&name), &namelen) == -1) {
        close(sock);
        return "127.0.0.1";
    }
    char buf[INET_ADDRSTRLEN];
    const char* p = inet_ntop(AF_INET, &name.sin_addr, buf, sizeof(buf));
    close(sock);
    return p ? std::string(p) : "127.0.0.1";
}
static bool is_terminal_interactive() {
    return isatty(STDIN_FILENO) != 0;
}
#elif defined(SLUG_PLATFORM_WINDOWS)
static std::string read_hidden_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(hStdin, &mode)) {
        SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
        std::string pass;
        std::getline(std::cin, pass);
        SetConsoleMode(hStdin, mode);
        std::cout << std::endl;
        return pass;
    }
    std::string pass;
    std::getline(std::cin, pass);
    return pass;
}

static std::string read_confirmed_hidden_password(const std::string& prompt) {
    while (true) {
        std::string p1 = read_hidden_password(prompt);
        if (p1.empty()) {
            std::cerr << "[-] Password cannot be empty. Please try again." << std::endl;
            continue;
        }
        std::string p2 = read_hidden_password("Retype password: ");
        if (p1 == p2) {
            return p1;
        }
        std::cerr << "[-] Passwords do not match. Please try again." << std::endl;
    }
}

static std::string get_host_lan_ip() {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return "127.0.0.1";
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = inet_addr("8.8.8.8");
    target.sin_port = htons(53);
    if (connect(sock, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == SOCKET_ERROR) {
        closesocket(sock);
        return "127.0.0.1";
    }
    sockaddr_in name{};
    int namelen = sizeof(name);
    if (getsockname(sock, reinterpret_cast<sockaddr*>(&name), &namelen) == SOCKET_ERROR) {
        closesocket(sock);
        return "127.0.0.1";
    }
    char buf[INET_ADDRSTRLEN];
    const char* p = inet_ntop(AF_INET, &name.sin_addr, buf, sizeof(buf));
    closesocket(sock);
    return p ? std::string(p) : "127.0.0.1";
}

static bool is_terminal_interactive() {
    return _isatty(_fileno(stdin)) != 0;
}
#else
static std::string read_hidden_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string pass;
    std::getline(std::cin, pass);
    return pass;
}
static std::string read_confirmed_hidden_password(const std::string& prompt) {
    while (true) {
        std::cout << prompt << std::flush;
        std::string p1;
        std::getline(std::cin, p1);
        if (p1.empty()) continue;
        std::cout << "Retype password: " << std::flush;
        std::string p2;
        std::getline(std::cin, p2);
        if (p1 == p2) return p1;
        std::cerr << "[-] Passwords do not match. Please try again." << std::endl;
    }
}
static std::string get_host_lan_ip() { return "127.0.0.1"; }
static bool is_terminal_interactive() {
    return true;
}
#endif

static void open_browser(const std::string& url) {
#if defined(__APPLE__)
    std::string cmd = "open \"" + url + "\" &";
#elif defined(_WIN32)
    std::string cmd = "start \"\" \"" + url + "\"";
#else
    std::string cmd = "xdg-open \"" + url + "\" >/dev/null 2>&1 &";
#endif
    [[maybe_unused]] int r = std::system(cmd.c_str());
}

static std::string get_current_executable_path() {
#if defined(SLUG_PLATFORM_POSIX)
    char buf[4096];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        return std::string(buf);
    }
#elif defined(SLUG_PLATFORM_WINDOWS)
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, buf, MAX_PATH);
    if (len > 0) {
        return std::string(buf, len);
    }
#endif
    return "";
}

struct TerminalCursorRestorer {
    bool enabled{false};
    explicit TerminalCursorRestorer(bool enable) : enabled(enable) {
        if (enabled) std::cout << "\033[?25l" << std::flush;
    }
    ~TerminalCursorRestorer() {
        if (enabled) std::cout << "\033[?25h" << std::flush;
    }
};

using namespace slug;

class SlugConfig {
public:
    static std::filesystem::path config_path() {
        return platform::get_user_home() / ".slug" / "config.json";
    }

    static nlohmann::json load() {
        auto p = config_path();
        if (!std::filesystem::exists(p)) return nlohmann::json::object();
        auto data = platform::PathUtils::read_binary_file(p.string());
        if (!data || data->empty()) return nlohmann::json::object();
        try {
            return nlohmann::json::parse(std::string(data->begin(), data->end()));
        } catch (...) {
            return nlohmann::json::object();
        }
    }

    static bool save(const nlohmann::json& j) {
        auto p = config_path();
        std::error_code ec;
        std::filesystem::create_directories(p.parent_path(), ec);
        std::string s = j.dump(2);
        std::vector<uint8_t> bytes(s.begin(), s.end());
        return platform::PathUtils::write_binary_file(p.string(), bytes);
    }

    static std::string get(const std::string& key, const std::string& default_val = "") {
        auto j = load();
        if (j.contains(key)) {
            if (j[key].is_string()) return j[key].get<std::string>();
            return j[key].dump();
        }
        return default_val;
    }

    static void set(const std::string& key, const std::string& val) {
        auto j = load();
        if (val == "true") j[key] = true;
        else if (val == "false") j[key] = false;
        else if (!val.empty() && std::all_of(val.begin(), val.end(), ::isdigit)) {
            j[key] = std::stoull(val);
        } else {
            j[key] = val;
        }
        save(j);
    }
};

int cmd_config(int argc, char* argv[]) {
    if (argc < 3 || std::string(argv[2]) == "list") {
        auto j = SlugConfig::load();
        std::cout << "SLUG CONFIGURATION (~/.slug/config.json):\n" << std::endl;
        std::cout << std::left << std::setw(24) << "[KEY]" << std::setw(40) << "[VALUE]" << std::endl;
        std::cout << std::string(64, '-') << std::endl;
        if (j.empty()) {
            std::cout << "  (No custom settings. Using defaults: default_suite=SUITE_3_PURE_PQC, portal_port=8080)" << std::endl;
        } else {
            for (auto it = j.begin(); it != j.end(); ++it) {
                std::cout << std::left << std::setw(24) << it.key() << std::setw(40) << it.value().dump() << std::endl;
            }
        }
        std::cout << "\nSet setting: slug config set <key> <val>" << std::endl;
        std::cout << "Get setting: slug config get <key>" << std::endl;
        return 0;
    }

    std::string sub = argv[2];
    if (sub == "get" && argc >= 4) {
        std::string key = argv[3];
        std::string val = SlugConfig::get(key);
        if (val.empty()) {
            std::cout << "(not set)" << std::endl;
        } else {
            std::cout << val << std::endl;
        }
        return 0;
    } else if (sub == "set" && argc >= 5) {
        std::string key = argv[3];
        std::string val = argv[4];
        SlugConfig::set(key, val);
        std::cout << "[+] Set " << key << " = " << val << " in ~/.slug/config.json" << std::endl;
        return 0;
    }

    std::cerr << "Usage: slug config [list|get <key>|set <key> <val>]" << std::endl;
    return 1;
}

int cmd_shortcut(int, char*[]) {
#if defined(_WIN32)
    std::string exe = get_current_executable_path();
    if (exe.empty()) {
        std::cerr << "[-] Failed to determine slug executable path." << std::endl;
        return 1;
    }
    std::string ps = "powershell -NoProfile -NonInteractive -Command \""
                     "$ws = New-Object -ComObject WScript.Shell; "
                     "$desktop = [Environment]::GetFolderPath('Desktop'); "
                     "$sc = $ws.CreateShortcut(\\\"$desktop\\Slug Workspace.lnk\\\"); "
                     "$sc.TargetPath = \\\"" + exe + "\\\"; "
                     "$sc.Arguments = \\\"portal\\\"; "
                     "$sc.Description = \\\"Slug Post-Quantum Workspace Viewing Engine\\\"; "
                     "$sc.IconLocation = \\\"" + exe + ",0\\\"; "
                     "$sc.Save()\"";
    int r = std::system(ps.c_str());
    if (r == 0) {
        std::cout << "[+] Created Desktop shortcut: Slug Workspace.lnk" << std::endl;
        std::cout << "    Target:    " << exe << " portal" << std::endl;
        std::cout << "    Double-click it anytime to open the Web Viewing Engine!" << std::endl;
        return 0;
    } else {
        std::cerr << "[-] Failed to create Desktop shortcut." << std::endl;
        return 1;
    }
#else
    std::cout << "[*] Desktop shortcut creation is supported on Windows." << std::endl;
    std::cout << "    On Linux/macOS, simply run 'slug' in terminal." << std::endl;
    return 0;
#endif
}

void print_banner() {
    std::cout << R"(
   _____ _             
  / ____| |            
 | (___ | |_   _  __ _ 
  \___ \| | | | |/ _` |
  ____) | | |_| | (_| |
 |_____/|_|\__,_|\__, |
                  __/ |
                 |___/ 
  Slug: Secure, Ephemeral, Git-like Workspace Sharing & Synchronization
  Version: 1.0.0 | Post-Quantum Cryptography & AI Guard (Apache-2.0)
)" << std::endl;
}

void print_help() {
    print_banner();
    std::cout << R"(
THE ESSENTIAL 9 - CORE COMMAND SUITE:

  [CLIENT WORKSPACE & WEB VIEWING ENGINE]
    portal [-p <port>]       Launch local loopback Web Viewing Engine (Default: http://127.0.0.1:8080)
                             (Zero Remote HTTP - all remote traffic is tunneled via pure Post-Quantum frames)
                             Aliases: slug (no arguments), slug web, slug ui
    shortcut                 Create Windows Desktop shortcut ("Slug Workspace.lnk") for 1-click launch
    config [list|get|set]    Manage preferences (~/.slug/config.json): default_suite, portal_port, etc.

  [HOST WORKSPACE]
    add <path>               Share folder with Post-Quantum protection (PurePQC default)
                             Flags: -p, --port <port>       (Default: 9443)
                                    -s, --suite <1|2|3|pqc> (Default: 3 pure-pqc)
                                    -t, --ttl <duration>    (Default: 24h, inf for permanent)
                                    -a, --ai                (Enable Stateful AI Secret Guard)
                                    --filter-mode <mode>    (protected [default], include-ignored, none)
                                    --no-filter             (Raw transfer: disable gitignore & quarantine)
                                    --include-ignored       (Transfer gitignored files but enforce rules)
                                    -d, --daemon            (Run as background daemon)

    status                   Inspect active workspaces, ports, suites, and realtime OTPs
                             Flags: -s, --short             (Ultra-compact view)
                                    -p, --port <port>       (Inspect specific server)
                                    --sessions              (List connected client sessions)
                                    --flagged               (List AI-quarantined files)

    totp [-p <port>]         Display active role-based One-Time TOTP tokens (rw, r, w)
                             Flags: -r, --role <rw|r|w>     (Target specific role)
                                    --code-only             (Print raw 8-digit code only)

    stop [-p <port>] [-a]    Stop active workspace server(s)
                             Flags: -a, --all               (Stop all hosted servers)

  [ACCESS CONTROL & SECURITY]
    session <list|kill <id>> Inspect and terminate connected client sessions (TOTP, Account, Ticket)
                             Flags: -p, --port <port>       (Target server port)

    user <add|mod|rm|list>   Manage ephemeral & permanent accounts with RBAC (rw, r, w)
                             Flags: -u, --user <name>       (Username)
                                    -P, --pass <password>   (Account password; prompts if omitted)
                                    -r, --role <rw|r|w>     (Default: r)
                                    -t, --ttl <duration>    (e.g. 2h, 24h, inf)
                                    -p, --port <port>       (Target server port)

    audit <list|scan|allow>  Stateful AI Secret Guard management
                             Subcommands: list              (View flagged files)
                                          scan <file>       (Deep semantic scan)
                                          allow <file|--all>(Whitelist false positive or unblock all)
                                          clear             (Reset quarantine index)
                                          recheck [--all]   (Rescan modified files)

  [CLIENT WORKSPACE SYNC]
    connect -i <ip> -p <port> Authenticate to remote workspace and save connection certificate
    ls [subpath]             Browse remote workspace items with statuses (Available, Excluded, Quarantined)
                             Flags: -r, --recursive         (List all files recursively)
                                    -c, --conn <id>         (Target specific connection)

    get <file> [local_dest]  Download ONLY the specified single file (never whole workspace)
                             Examples: slug get src/main.rs ./main.rs
                                       slug get 192.168.1.107:9443?otp=12822565 src/main.rs

    pull [scope] [--to <dir>] Differential delta sync with transfer plan preview (Git-like delta sync)
                             Flags: -y, --yes               (Bypass transfer plan confirmation)
                                    --dry-run               (Preview changes without downloading)
                                    --only <pattern>        (Selective pull, e.g. "src/*")
                                    --prune                 (Remove deleted local files)

    push <file> [dest]       Upload file to remote workspace (requires 'w' or 'rw' role)

  [SYSTEM UTILITIES]
    conn <list|use|prune|rm> Manage saved client connections (alias: connections)
    connect -i <ip> -p <port> Authenticate to remote workspace and save connection certificate
    serve [-p <port>] [-w]   Server inspection box; pass -w to open Web Admin Dashboard
    completion <bash|zsh>    Generate shell autocompletion script
    env <init|restore|history|prompt|run> Post-Quantum EnvShield & Central Vault
                             init [--keep]           Seal .env into .env.pqc & Central Vault
                             restore                 1-touch restore plaintext .env from Vault
                             history                 Inspect versioned backups in Vault
                             prompt                  Print directive instructions for AI agents
                             run -- <cmd...>         Inject secrets in RAM & execute command
    bench [--quick] [--json] Run cryptography & I/O performance benchmarks
    version                  Display version and platform build details

Run 'slug help' to view this cheat sheet.
)" << std::endl;
}

static int cmd_serve(int argc, char* argv[]);

int cmd_add(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: slug add <path> [-p <port>] [-s <suite>] [-t <duration>] [-a|--ai] [-d|--daemon]" << std::endl;
        return 1;
    }

    std::error_code ec;
    std::filesystem::path resolved_path = std::filesystem::canonical(argv[2], ec);
    if (ec) {
        resolved_path = std::filesystem::absolute(argv[2]).lexically_normal();
    }
    std::string folder_path = resolved_path.string();
    uint16_t port = core::kDefaultPort;
    std::string default_suite_name = SlugConfig::get("default_suite", "SUITE_3_PURE_PQC");
    core::SuiteID suite = core::suite_from_string(default_suite_name);
    uint64_t ttl_sec = 86400;
    bool enable_ai = false;
    core::FilterMode filter_mode = core::FilterMode::PROTECTED;
    bool daemon = false;
    bool is_internal_worker = false;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if ((arg == "-s" || arg == "--suite") && i + 1 < argc) {
            suite = core::suite_from_string(argv[++i]);
        } else if ((arg == "-t" || arg == "--ttl") && i + 1 < argc) {
            ttl_sec = core::Utils::parse_ttl(argv[++i]);
        } else if (arg == "-a" || arg == "--ai" || arg == "-ai") {
            enable_ai = true;
        } else if (arg == "--filter-mode" && i + 1 < argc) {
            filter_mode = core::filter_mode_from_string(argv[++i]);
        } else if (arg == "--no-filter" || arg == "--raw") {
            filter_mode = core::FilterMode::NONE;
        } else if (arg == "--include-ignored" || arg == "--all") {
            filter_mode = core::FilterMode::INCLUDE_IGNORED;
        } else if (arg == "--daemon" || arg == "-d") {
            daemon = true;
        } else if (arg == "--internal-worker") {
            is_internal_worker = true;
        }
    }

#if defined(SLUG_PLATFORM_POSIX)
    int pipefd[2] = {-1, -1};
    if (daemon) {
        if (pipe(pipefd) < 0) {
            std::cerr << "[-] Failed to create IPC pipe for daemon" << std::endl;
            return 1;
        }
        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "[-] Failed to fork daemon process" << std::endl;
            return 1;
        }
        if (pid > 0) {
            // Parent process: wait for child to finish setup and display banner
            close(pipefd[1]);
            char buf[16];
            ssize_t n = read(pipefd[0], buf, sizeof(buf));
            (void)n;
            close(pipefd[0]);
            std::cout << "[+] Server running in background (PID: " << pid << ")." << std::endl;
            return 0;
        }
        // Child process
        close(pipefd[0]);
        setsid();
        std::signal(SIGTERM, signal_handler);
        std::signal(SIGINT, signal_handler);
    } else {
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
    }
#elif defined(SLUG_PLATFORM_WINDOWS)
    if (daemon && !is_internal_worker) {
        std::string exe = get_current_executable_path();
        std::string cmdline = "\"" + exe + "\" add \"" + folder_path + "\" -p " + std::to_string(port) +
                              " -s " + core::suite_to_string(suite) +
                              " -t " + std::to_string(ttl_sec) +
                              (enable_ai ? " -a" : "") +
                              " --filter-mode " + core::filter_mode_to_string(filter_mode) +
                              " --internal-worker";
        STARTUPINFOA si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);
        std::vector<char> cmd_buf(cmdline.begin(), cmdline.end());
        cmd_buf.push_back('\0');
        BOOL ok = CreateProcessA(NULL, cmd_buf.data(), NULL, NULL, FALSE,
                                 CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi);
        if (ok) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            std::cout << "[+] Server running in background (PID: " << pi.dwProcessId << ")." << std::endl;
            std::cout << "    Workspace: " << folder_path << std::endl;
            std::cout << "    Port:      " << port << std::endl;
            std::cout << "    Crypto:    " << core::suite_to_string(suite) << std::endl;
            std::cout << "    Filter:    " << core::filter_mode_to_string(filter_mode) << std::endl;
            return 0;
        } else {
            std::cerr << "[-] Failed to spawn background worker process (error " << GetLastError() << ")." << std::endl;
            return 1;
        }
    }
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
#else
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
#endif

    print_banner();
    std::cout << "[*] Initializing Workspace at: " << std::filesystem::absolute(folder_path).string() << std::endl;
    if (filter_mode == core::FilterMode::NONE) {
        std::cout << "[!] WARNING: Workspace hosted with --filter-mode none." << std::endl;
        std::cout << "    Content quarantine and .gitignore filters are DISABLED for this session." << std::endl;
        std::cout << "    All files (except internal .slug metadata) will be accessible to authenticated peers." << std::endl;
    } else if (filter_mode == core::FilterMode::INCLUDE_IGNORED) {
        std::cout << "[*] Filter Mode: include-ignored (.gitignore disabled, rules & secret quarantine active)." << std::endl;
    }

    if (!core::WorkspaceManager::instance().add_workspace(folder_path, port, suite, ttl_sec, enable_ai, filter_mode)) {
#if defined(SLUG_PLATFORM_POSIX)
        if (daemon && pipefd[1] >= 0) {
            char fail[] = "FAIL";
            [[maybe_unused]] auto w = write(pipefd[1], fail, sizeof(fail));
            close(pipefd[1]);
        }
#endif
        return 1;
    }

    auto server = core::WorkspaceManager::instance().get_server(port);
    if (!server) return 1;

    std::string lan_ip = get_host_lan_ip();
    std::string totp_rw = server->totp_manager().generate_code(core::Role::READ_WRITE);
    std::string totp_r  = server->totp_manager().generate_code(core::Role::READ_ONLY);
    std::string totp_w  = server->totp_manager().generate_code(core::Role::WRITE_ONLY);
    uint32_t rem = server->totp_manager().remaining_seconds();

    std::cout << "\n+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "| SLUG SECURE WORKSPACE HOSTED SUCCESSFULLY                                  |" << std::endl;
    std::cout << "+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "  Port:            " << port << std::endl;
    std::cout << "  Crypto Suite:    " << core::suite_to_string(suite) << std::endl;
    std::cout << "  AI Secret Guard: " << (enable_ai ? "ENABLED (Stateful BLAKE3 Audit)" : "OFF") << std::endl;
    std::cout << "  Filter Mode:     " << core::filter_mode_to_string(filter_mode) << std::endl;
    std::cout << "  Session TTL:     " << core::Utils::format_duration(ttl_sec) << std::endl;
    auto print_dynamic_panel = [&](uint32_t current_rem, const std::string& crw, const std::string& cr, const std::string& cw, bool clear_trailing) {
        std::string clr = clear_trailing ? "\033[K\n" : "\n";
        std::cout << "  Role OTPs (Rotates in " << current_rem << "s):" << clr;
        std::cout << "    [rw] Read-Write OTP: " << crw << " (Full Sync & Web Dropbox)" << clr;
        std::cout << "    [r]  Read-Only OTP:  " << cr  << " (Read/Pull/View files only)" << clr;
        std::cout << "    [w]  Write-Only OTP: " << cw  << " (Blind Drop/Upload only)" << clr;
        std::cout << "+----------------------------------------------------------------------------+" << clr;
        std::cout << "Connect (One-Shot): slug get " << lan_ip << ":" << port << "?otp=" << crw << clr;
        std::cout << "Connect (Local):    slug get 127.0.0.1:" << port << "?otp=" << crw << clr;
        std::cout << "Connect (Standard): slug connect -i " << lan_ip << " -p " << port << " -o " << crw << clr;
        std::cout << "                    (Replace " << lan_ip << " with your PUBLIC_IP if sharing over internet)" << clr;
        std::cout << "+----------------------------------------------------------------------------+" << clr;
        std::cout << clr;
        std::cout << "[*] Press Ctrl+C to stop server..." << clr;
        std::cout << std::flush;
    };

#if defined(SLUG_PLATFORM_POSIX)
    if (daemon) {
        print_dynamic_panel(rem, totp_rw, totp_r, totp_w, false);
        char ok[] = "OK";
        [[maybe_unused]] auto w = write(pipefd[1], ok, sizeof(ok));
        close(pipefd[1]);

        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        while (server->is_running() && !g_stop_signal_received) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        server->stop();
        return 0;
    }
#else
    if (is_internal_worker) {
        while (server->is_running() && !g_stop_signal_received) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        server->stop();
        return 0;
    }
#endif

    bool is_terminal = false;
#if defined(SLUG_PLATFORM_POSIX)
    is_terminal = (isatty(STDOUT_FILENO) != 0);
#elif defined(SLUG_PLATFORM_WINDOWS)
    is_terminal = (_isatty(_fileno(stdout)) != 0);
#endif

    TerminalCursorRestorer cursor_guard(is_terminal);
    print_dynamic_panel(rem, totp_rw, totp_r, totp_w, is_terminal);

    uint32_t last_rem = rem;
    while (server->is_running() && !g_stop_signal_received) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!server->is_running() || g_stop_signal_received) break;

        uint32_t current_rem = server->totp_manager().remaining_seconds();
        if (is_terminal && current_rem != last_rem) {
            last_rem = current_rem;
            std::string cur_totp_rw = server->totp_manager().generate_code(core::Role::READ_WRITE);
            std::string cur_totp_r  = server->totp_manager().generate_code(core::Role::READ_ONLY);
            std::string cur_totp_w  = server->totp_manager().generate_code(core::Role::WRITE_ONLY);

            std::cout << "\033[11A\r";
            print_dynamic_panel(current_rem, cur_totp_rw, cur_totp_r, cur_totp_w, true);
        }
    }

    std::cout << "\n[*] Stopping workspace server..." << std::endl;
    server->stop();
    std::cout << "[+] Server stopped." << std::endl;
    return 0;
}

static nlohmann::json query_workspace_api(uint16_t port, const std::string& path = "/api/status", int timeout_ms = 800) {
    platform::TcpSocket sock;
    if (!sock.connect("127.0.0.1", port, timeout_ms)) {
        return nullptr;
    }
    std::string req = "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    if (!sock.send_all(req)) {
        return nullptr;
    }
    std::vector<uint8_t> buf(4096);
    std::string resp;
    while (true) {
        int n = sock.receive(buf, 1000);
        if (n <= 0) break;
        resp.append(reinterpret_cast<char*>(buf.data()), n);
    }
    size_t body_pos = resp.find("\r\n\r\n");
    if (body_pos == std::string::npos) return nullptr;
    try {
        return nlohmann::json::parse(resp.substr(body_pos + 4));
    } catch (...) {
        return nullptr;
    }
}

static nlohmann::json post_workspace_api(uint16_t port, const std::string& path, const nlohmann::json& payload, int timeout_ms = 1200) {
    platform::TcpSocket sock;
    if (!sock.connect("127.0.0.1", port, timeout_ms)) {
        return nullptr;
    }
    std::string body = payload.dump();
    std::string req = "POST " + path + " HTTP/1.1\r\n" +
                      "Host: 127.0.0.1\r\n" +
                      "Content-Type: application/json\r\n" +
                      "Content-Length: " + std::to_string(body.size()) + "\r\n" +
                      "Connection: close\r\n\r\n" + body;
    if (!sock.send_all(req)) {
        return nullptr;
    }
    std::vector<uint8_t> buf(4096);
    std::string resp;
    while (true) {
        int n = sock.receive(buf, 1000);
        if (n <= 0) break;
        resp.append(reinterpret_cast<char*>(buf.data()), n);
    }
    size_t body_pos = resp.find("\r\n\r\n");
    if (body_pos == std::string::npos) return nullptr;
    try {
        return nlohmann::json::parse(resp.substr(body_pos + 4));
    } catch (...) {
        return nullptr;
    }
}

int cmd_session(int argc, char* argv[]) {
    std::string action = "list";
    uint32_t kill_id = 0;
    uint16_t port = 0;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "list" || arg == "ls") {
            action = "list";
        } else if (arg == "kill" || arg == "revoke" || arg == "rm" || arg == "del") {
            action = "kill";
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                kill_id = static_cast<uint32_t>(std::stoul(argv[++i]));
            }
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (kill_id == 0 && std::isdigit(arg[0])) {
            kill_id = static_cast<uint32_t>(std::stoul(arg));
        }
    }

    auto list = core::WorkspaceManager::load_registry();
    if (list.empty()) {
        std::cout << "[-] No active workspace servers found. Share a folder with: slug add <path>" << std::endl;
        return 1;
    }

    if (port == 0) {
        if (list.size() == 1) {
            port = list[0].port;
        } else {
            std::cout << "[!] Multiple active servers detected. Specify server port with -p <port>:" << std::endl;
            for (const auto& w : list) {
                std::cout << "    - Port " << w.port << " (" << w.path << ")" << std::endl;
            }
            return 1;
        }
    }

    if (action == "kill") {
        if (kill_id == 0) {
            std::cerr << "Usage: slug session kill <session_id> [-p <port>]" << std::endl;
            return 1;
        }
        nlohmann::json payload;
        payload["session_id"] = kill_id;
        auto res = post_workspace_api(port, "/api/admin/sessions/revoke", payload);
        if (res.is_object() && res.value("status", "") == "ok") {
            std::cout << "[+] Client session #" << kill_id << " successfully revoked and terminated on port " << port << "." << std::endl;
            return 0;
        } else {
            std::string msg = (res.is_object() && res.contains("message")) ? res["message"].get<std::string>() : "Failed to revoke session";
            std::cerr << "[-] Error: " << msg << std::endl;
            return 1;
        }
    }

    // Default: list sessions
    auto st = query_workspace_api(port);
    if (!st.is_object()) {
        std::cerr << "[-] Cannot connect to workspace server on port " << port << " (server might not be running)" << std::endl;
        return 1;
    }

    std::string ws_name = st.value("workspace_name", st.value("workspace", "workspace"));
    std::cout << "\nCLIENT SESSIONS (Port " << port << " - " << ws_name << "):\n" << std::endl;

    if (!st.contains("sessions") || !st["sessions"].is_array() || st["sessions"].empty()) {
        std::cout << "  No connected client sessions recorded yet.\n" << std::endl;
        return 0;
    }

    std::cout << std::left
              << std::setw(8)  << "[ID]"
              << std::setw(24) << "[IDENTITY]"
              << std::setw(12) << "[TYPE]"
              << std::setw(24) << "[ENDPOINT]"
              << std::setw(8)  << "[ROLE]"
              << std::setw(22) << "[STATUS / TTL]"
              << std::setw(14) << "[LAST ACTIVE]"
              << std::endl;
    std::cout << std::string(112, '-') << std::endl;

    uint64_t now_ts = core::Utils::current_timestamp();
    for (const auto& s : st["sessions"]) {
        uint32_t sid = s.value("session_id", 0U);
        std::string ident = s.value("identity", "-");
        std::string auth_t = s.value("auth_type", "-");
        std::string ep = s.value("remote_endpoint", "-");
        std::string role_s = s.value("role", "-");
        std::string status_s = s.value("status", "ACTIVE");
        uint64_t rem_sec = s.value("remaining_sec", 0ULL);
        uint64_t exp_at = s.value("expires_at", 0ULL);
        uint64_t last_act = s.value("last_active_at", 0ULL);

        std::string st_display = status_s;
        if (status_s == "ACTIVE") {
            if (exp_at == 0) st_display = "ACTIVE (Permanent)";
            else st_display = "ACTIVE (" + core::Utils::format_ttl(rem_sec) + ")";
        }

        std::string act_display = "-";
        if (last_act > 0 && now_ts >= last_act) {
            uint64_t diff = now_ts - last_act;
            if (diff < 5) act_display = "just now";
            else if (diff < 60) act_display = std::to_string(diff) + "s ago";
            else if (diff < 3600) act_display = std::to_string(diff / 60) + "m ago";
            else act_display = std::to_string(diff / 3600) + "h ago";
        }

        std::cout << std::left
                  << std::setw(8)  << ("#" + std::to_string(sid))
                  << std::setw(24) << (ident.size() > 22 ? ident.substr(0, 20) + ".." : ident)
                  << std::setw(12) << auth_t
                  << std::setw(24) << (ep.size() > 22 ? ep.substr(0, 20) + ".." : ep)
                  << std::setw(8)  << role_s
                  << std::setw(22) << st_display
                  << std::setw(14) << act_display
                  << std::endl;
    }
    std::cout << std::endl;
    return 0;
}

int cmd_status(int argc, char* argv[]) {
    bool show_flagged = false;
    bool show_sessions = false;
    bool short_mode = false;
    uint16_t target_port = 0;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--flagged") show_flagged = true;
        else if (arg == "--sessions" || arg == "-S") show_sessions = true;
        else if (arg == "-s" || arg == "--short" || arg == "--compact") short_mode = true;
        else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            target_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        }
    }

    if (target_port > 0 && !show_sessions && !show_flagged) {
        return cmd_serve(argc, argv);
    }

    auto list = core::WorkspaceManager::load_registry();
    if (target_port > 0) {
        std::vector<core::WorkspaceInfo> filtered;
        for (const auto& w : list) {
            if (w.port == target_port) filtered.push_back(w);
        }
        list = filtered;
    }

    print_banner();
    std::cout << "ACTIVE WORKSPACE SERVERS (" << list.size() << "):\n" << std::endl;

    if (list.empty()) {
        std::cout << "  No active workspaces found. Run 'slug add <path>' to share a folder.\n" << std::endl;
        return 0;
    }

    std::cout << std::left
              << std::setw(8)  << "[PORT]"
              << std::setw(20) << "[WORKSPACE]"
              << std::setw(20) << "[ONE-TIME TOTP]"
              << std::setw(24) << "[CRYPTO SUITE]"
              << std::setw(10) << "[AI-EXT]"
              << std::setw(10) << "[PID]"
              << std::endl;
    std::cout << std::string(92, '-') << std::endl;

    for (const auto& w : list) {
        std::filesystem::path norm_path = w.path.lexically_normal();
        std::string path_str = norm_path.filename().string();
        if (path_str.empty() || path_str == ".") {
            path_str = norm_path.parent_path().filename().string();
            if (path_str.empty() || path_str == ".") path_str = norm_path.string();
        }

        std::string totp_display = "-";
        std::string live_rw = "", live_r = "", live_w = "";
        int rem = 0;
        auto st = query_workspace_api(w.port);
        if (st.is_object() && st.contains("totp_rw")) {
            live_rw = st.value("totp_rw", st.value("totp", ""));
            live_r  = st.value("totp_r", "");
            live_w  = st.value("totp_w", "");
            rem = st.value("totp_remaining_sec", 0);
            totp_display = live_rw + " (" + std::to_string(rem) + "s)";
        } else if (st.is_object() && st.contains("totp")) {
            live_rw = st["totp"].get<std::string>();
            rem = st.value("totp_remaining_sec", 0);
            totp_display = live_rw + " (" + std::to_string(rem) + "s)";
        }

        std::cout << std::left
                  << std::setw(8)  << w.port
                  << std::setw(20) << (path_str.size() > 18 ? path_str.substr(0, 15) + "..." : path_str)
                  << std::setw(20) << totp_display
                  << std::setw(24) << core::suite_to_short_name(w.suite)
                  << std::setw(10) << (w.ai_enabled ? "ON" : "OFF")
                  << std::setw(10) << w.pid
                  << std::endl;

        std::cout << "  Path:      " << norm_path.string() << std::endl;
        std::cout << "  Filter:    " << core::filter_mode_to_string(w.filter_mode) << std::endl;
        if (!live_r.empty() && !live_w.empty()) {
            std::cout << "  Role OTPs: [rw] " << live_rw << " | [r] " << live_r << " | [w] " << live_w << " (Rotates in " << rem << "s)" << std::endl;
        }
        if (!short_mode) {
            std::string lan_ip = get_host_lan_ip();
            if (!live_rw.empty()) {
                std::cout << "  Connect:   slug connect -i " << lan_ip << " -p " << w.port << " -o " << live_rw << std::endl;
                std::cout << "  One-Shot:  slug get " << lan_ip << ":" << w.port << "?otp=" << live_rw << std::endl;
            } else {
                std::cout << "  Endpoint:  " << lan_ip << ":" << w.port << " (Server offline or query unreachable)" << std::endl;
            }
        }
        std::cout << std::endl;

        if (show_sessions && st.is_object() && st.contains("sessions") && st["sessions"].is_array()) {
            const auto& sessions = st["sessions"];
            std::cout << "   |-> Connected Client Sessions (" << sessions.size() << "):" << std::endl;
            for (const auto& s : sessions) {
                uint32_t sid = s.value("session_id", 0U);
                std::string ident = s.value("identity", "-");
                std::string auth_t = s.value("auth_type", "-");
                std::string ep = s.value("remote_endpoint", "-");
                std::string role_s = s.value("role", "-");
                std::string status_s = s.value("status", "ACTIVE");
                std::cout << "       #" << sid << " " << ident << " (" << auth_t << ") [" << role_s << "] " << ep << " - " << status_s << std::endl;
            }
            std::cout << std::endl;
        }

        if (show_flagged) {
            std::filesystem::path idx_path = norm_path / ".slug" / "index.db";
            ai::StatefulAuditIndex audit_idx(idx_path);
            auto flagged = audit_idx.list_flagged_or_all(true);
            if (!flagged.empty()) {
                std::cout << "   |-> AI Flagged Files (" << flagged.size() << "):" << std::endl;
                for (const auto& f : flagged) {
                    std::cout << "       [FLAGGED] " << f.file_path << " (L" << f.line_number << ": " << f.reason << ")" << std::endl;
                }
                std::cout << std::endl;
            }
        }
    }
    return 0;
}

int cmd_totp(int argc, char* argv[]) {
    uint16_t port = 0;
    std::string req_role = "";
    bool code_only = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if ((arg == "-r" || arg == "--role") && i + 1 < argc) {
            req_role = argv[++i];
        } else if (arg == "--code-only") {
            code_only = true;
        }
    }
    if (port == 0) {
        auto list = core::WorkspaceManager::load_registry();
        if (list.size() == 1) {
            port = list[0].port;
        } else {
            port = core::kDefaultPort;
        }
    }

    auto st = query_workspace_api(port);
    if (!st.is_object() || !st.contains("totp_rw")) {
        std::cerr << "[-] Cannot connect to workspace server on port " << port << " (server might not be running)" << std::endl;
        return 1;
    }

    std::string totp_rw = st.value("totp_rw", st.value("totp", ""));
    std::string totp_r  = st.value("totp_r", "");
    std::string totp_w  = st.value("totp_w", "");
    int rem = st.value("totp_remaining_sec", 0);
    std::string lan_ip = get_host_lan_ip();

    if (code_only) {
        std::string code = (req_role == "r") ? totp_r : ((req_role == "w") ? totp_w : totp_rw);
        std::cout << code << std::endl;
        return 0;
    }

    if (!req_role.empty()) {
        std::string code = (req_role == "r") ? totp_r : ((req_role == "w") ? totp_w : totp_rw);
        std::cout << "[*] Role [" << req_role << "] One-Time TOTP (Port " << port << ", Rotates in " << rem << "s): " << code << std::endl;
        std::cout << "    slug connect -i " << lan_ip << " -p " << port << " -o " << code << std::endl;
        return 0;
    }

    std::cout << "[*] Active Role-Based One-Time TOTPs (Port " << port << ", Rotates in " << rem << "s):\n" << std::endl;
    std::cout << "  [rw] Read-Write OTP: " << totp_rw << " (Full Sync & Web Dropbox)" << std::endl;
    std::cout << "       slug connect -i " << lan_ip << " -p " << port << " -o " << totp_rw << "\n" << std::endl;
    std::cout << "  [r]  Read-Only OTP:  " << totp_r  << " (Read/Pull files only)" << std::endl;
    std::cout << "       slug connect -i " << lan_ip << " -p " << port << " -o " << totp_r << "\n" << std::endl;
    std::cout << "  [w]  Write-Only OTP: " << totp_w  << " (Blind Drop/Upload only)" << std::endl;
    std::cout << "       slug connect -i " << lan_ip << " -p " << port << " -o " << totp_w << "\n" << std::endl;
    std::cout << "  * Note: Replace " << lan_ip << " with your PUBLIC_IP if connecting from external network." << std::endl;
    return 0;
}

int cmd_stop(int argc, char* argv[]) {
    uint16_t port = 0;
    bool stop_all = false;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "-a" || arg == "--all") {
            stop_all = true;
        }
    }
    if (stop_all) {
        auto list = core::WorkspaceManager::load_registry();
        int count = 0;
        for (const auto& w : list) {
            if (core::WorkspaceManager::instance().stop_workspace(w.port)) {
                count++;
            }
        }
        std::cout << "[+] Stopped " << count << " workspace server(s)." << std::endl;
        return 0;
    }
    if (port == 0) {
        auto list = core::WorkspaceManager::load_registry();
        if (list.size() == 1) {
            port = list[0].port;
        } else {
            port = core::kDefaultPort;
        }
    }

    if (core::WorkspaceManager::instance().stop_workspace(port)) {
        std::cout << "[+] Stopped workspace server on port " << port << std::endl;
        return 0;
    } else {
        std::cerr << "[-] No workspace found on port " << port << std::endl;
        return 1;
    }
}

int cmd_serve(int argc, char* argv[]) {
    bool open_web = false;
    uint16_t port = 0;
    std::string sub = "";

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "list" || arg == "ls") {
            sub = "list";
        } else if (arg == "stop") {
            sub = "stop";
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "-w" || arg == "--web") {
            open_web = true;
        }
    }

    if (sub == "list") {
        return cmd_status(argc, argv);
    }
    if (sub == "stop") {
        return cmd_stop(argc, argv);
    }

    auto list = core::WorkspaceManager::load_registry();
    if (list.empty()) {
        std::cout << "[-] No active workspace servers found. Host a workspace with: slug add <path>" << std::endl;
        return 1;
    }

    if (port == 0) {
        if (list.size() == 1) {
            port = list[0].port;
        } else {
            std::cout << "[!] Multiple active servers detected. Specify server port with -p <port>:\n" << std::endl;
            return cmd_status(argc, argv);
        }
    }

    auto st = query_workspace_api(port);
    if (!st.is_object() || !st.contains("totp_rw")) {
        std::cerr << "[-] Cannot connect to workspace server on port " << port << " (server might not be running)" << std::endl;
        return 1;
    }

    std::string ticket = st.value("admin_ticket", "");
    if (open_web) {
        std::string url = "http://127.0.0.1:" + std::to_string(port) + "/admin?ticket=" + ticket;
        std::cout << "[*] Opening Host Admin Web Dashboard (Port " << port << ")..." << std::endl;
        std::cout << "    URL: " << url << std::endl;
        open_browser(url);
        return 0;
    }

    // Detailed server view matching hosted box
    std::string totp_rw = st.value("totp_rw", st.value("totp", ""));
    std::string totp_r  = st.value("totp_r", "");
    std::string totp_w  = st.value("totp_w", "");
    int rem = st.value("totp_remaining_sec", 0);
    std::string lan_ip = get_host_lan_ip();
    std::string ws_path = st.value("workspace", "");
    std::string suite = st.value("suite", "");
    bool ai_enabled = st.value("ai_enabled", false);
    uint64_t ttl_sec = st.value("ttl_seconds", 86400ULL);
    std::string ttl_str = (ttl_sec == 0) ? "∞ (Permanent)"
                        : (ttl_sec % 86400 == 0) ? std::to_string(ttl_sec / 86400) + "d"
                        : (ttl_sec % 3600 == 0) ? std::to_string(ttl_sec / 3600) + "h"
                        : core::Utils::format_duration(ttl_sec);

    std::cout << "[*] Inspecting Workspace at: " << ws_path << "\n" << std::endl;
    std::cout << "+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "| SLUG SECURE WORKSPACE HOSTED SUCCESSFULLY                                  |" << std::endl;
    std::cout << "+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "  Port:            " << port << std::endl;
    std::cout << "  Crypto Suite:    " << suite << std::endl;
    std::cout << "  AI Secret Guard: " << (ai_enabled ? "ON" : "OFF") << std::endl;
    std::cout << "  Session TTL:     " << ttl_str << std::endl;
    std::cout << "  Role OTPs (Rotates in " << rem << "s):" << std::endl;
    std::cout << "    [rw] Read-Write OTP: " << totp_rw << " (Full Sync & Web Dropbox)" << std::endl;
    std::cout << "    [r]  Read-Only OTP:  " << totp_r  << " (Read/Pull/View files only)" << std::endl;
    std::cout << "    [w]  Write-Only OTP: " << totp_w  << " (Blind Drop/Upload only)" << std::endl;
    std::cout << "+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "Connect (One-Shot): slug get " << lan_ip << ":" << port << "?otp=" << totp_rw << std::endl;
    std::cout << "Connect (Local):    slug get 127.0.0.1:" << port << "?otp=" << totp_rw << std::endl;
    std::cout << "Connect (Standard): slug connect -i " << lan_ip << " -p " << port << " -o " << totp_rw << std::endl;
    std::cout << "                    (Replace " << lan_ip << " with your PUBLIC_IP if sharing over internet)" << std::endl;
    if (!ticket.empty()) {
        std::cout << "Admin Dashboard:   http://127.0.0.1:" << port << "/admin?ticket=" << ticket << std::endl;
    }
    std::cout << "+----------------------------------------------------------------------------+\n" << std::endl;
    std::cout << "Tip: Pass -w to open the Admin Web Dashboard directly: slug serve -p " << port << " -w\n" << std::endl;
    return 0;
}

int cmd_connect(int argc, char* argv[]) {
    if (argc >= 3 && std::string(argv[2]) == "prune") {
        size_t pruned = core::ConnectionManager::instance().prune_dead_connections(400);
        std::cout << "[+] Pruned " << pruned << " dead or expired connection(s)." << std::endl;
        return 0;
    }

    if (argc >= 3 && std::string(argv[2]) == "list") {
        bool prune_dead = false;
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--prune") prune_dead = true;
        }
        if (prune_dead) {
            size_t pruned = core::ConnectionManager::instance().prune_dead_connections(400);
            if (pruned > 0) {
                std::cout << "[+] Pruned " << pruned << " dead or expired connection(s)." << std::endl;
            }
        }

        auto list = core::ConnectionManager::instance().list_connections(true);
        std::string active_id = core::ConnectionManager::instance().get_active_connection();

        std::cout << "\nCLIENT CONNECTIONS (" << list.size() << "):\n" << std::endl;
        if (list.empty()) {
            std::cout << "  No saved connections. Connect with: slug connect -i <host> -p <port> -o <otp>\n" << std::endl;
            return 0;
        }

        std::cout << std::left
                  << std::setw(4)  << " "
                  << std::setw(12) << "[ID]"
                  << std::setw(12) << "[STATUS]"
                  << std::setw(8)  << "[ROLE]"
                  << std::setw(18) << "[WORKSPACE]"
                  << std::setw(24) << "[ENDPOINT]"
                  << std::setw(20) << "[EXPIRES IN]"
                  << std::endl;
        std::cout << std::string(98, '-') << std::endl;

        uint64_t now = core::Utils::current_timestamp();
        bool has_dead = false;
        for (const auto& c : list) {
            bool is_active = (c.id == active_id);
            bool alive = core::ConnectionManager::ping_connection(c, 250);
            if (!alive) has_dead = true;
            std::string status_str = alive ? "ONLINE" : "DEAD";

            std::string exp_str = (c.expires_at == 0) ? "Permanent"
                                  : (c.expires_at > now ? core::Utils::format_duration(c.expires_at - now) : "Expired");
            std::string marker = is_active ? "* " : "  ";
            std::string endpoint = c.host + ":" + std::to_string(c.port);

            std::cout << std::left
                      << std::setw(4)  << marker
                      << std::setw(12) << c.id
                      << std::setw(12) << status_str
                      << std::setw(8)  << core::role_to_string(c.role)
                      << std::setw(18) << (c.workspace.size() > 16 ? c.workspace.substr(0, 14) + ".." : c.workspace)
                      << std::setw(24) << endpoint
                      << std::setw(20) << exp_str
                      << std::endl;
        }
        std::cout << "\n  * indicates currently active connection context." << std::endl;
        std::cout << "  Switch context with: slug set <id>" << std::endl;
        if (has_dead) {
            std::cout << "  [!] Notice: Dead connections detected. Run 'slug connect prune' to clean up.\n" << std::endl;
        } else {
            std::cout << std::endl;
        }
        return 0;
    }

    bool open_web = false;
    std::string explicit_id;
    std::string ip = "";
    uint16_t port = core::kDefaultPort;
    std::string totp, user, pass;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" || arg == "--host") { if (i + 1 < argc) ip = argv[++i]; }
        else if (arg == "-p" || arg == "--port") { if (i + 1 < argc) port = static_cast<uint16_t>(std::stoi(argv[++i])); }
        else if (arg == "-o" || arg == "--otp") { if (i + 1 < argc) totp = argv[++i]; }
        else if (arg == "-u" || arg == "--user") { if (i + 1 < argc) user = argv[++i]; }
        else if (arg == "-P" || arg == "--pass" || arg == "--password" || arg == "-W") { if (i + 1 < argc) pass = argv[++i]; }
        else if (arg == "-w" || arg == "--web") { open_web = true; }
        else if (arg.front() != '-') {
            explicit_id = arg;
        }
    }

    if (ip.empty() && totp.empty() && user.empty()) {
        auto conn_opt = core::ConnectionManager::instance().resolve_connection(explicit_id);
        if (!conn_opt) {
            std::cerr << "[-] No connection found. Connect with: slug connect -i <host> -p <port> -o <otp>" << std::endl;
            return 1;
        }
        const auto& conn = *conn_opt;
        std::string web_url = "http://" + conn.host + ":" + std::to_string(conn.port) + "/drop?ticket=" + conn.ticket;
        std::cout << "[*] Connection '" << conn.id << "' (" << conn.workspace << " @ " << conn.host << ":" << conn.port << ")" << std::endl;
        std::cout << "    Role:        " << core::role_to_string(conn.role) << std::endl;
        std::cout << "    Certificate: " << conn.ticket.substr(0, 16) << "..." << std::endl;
        std::cout << "    Web URL:     " << web_url << std::endl;
        if (open_web) {
            std::cout << "[+] Launching authenticated web view..." << std::endl;
            open_browser(web_url);
        }
        return 0;
    }

    if (ip.empty()) ip = "127.0.0.1";

    net::SlugClient client;
    std::cout << "[*] Connecting to " << ip << ":" << port << "..." << std::endl;
    if (!client.connect(ip, port)) {
        std::cerr << "[-] Connection failed to " << ip << ":" << port << std::endl;
        return 1;
    }

    std::cout << "[+] Handshake OK! Negotiated: " << client.negotiated_suite_name() << std::endl;

    net::ClientAuthResult auth;
    if (!totp.empty()) {
        std::cout << "[*] Authenticating with single-use TOTP: " << totp << "..." << std::endl;
        auth = client.authenticate_totp(totp);
    } else if (!user.empty()) {
        if (pass.empty()) {
            pass = read_hidden_password("Enter password for '" + user + "': ");
        }
        std::cout << "[*] Authenticating with account '" << user << "'..." << std::endl;
        auth = client.authenticate_user(user, pass);
    } else {
        std::cerr << "[-] Authentication credential required: -o <otp> or -u <user> [-P <pass>]" << std::endl;
        return 1;
    }

    if (!auth.success) {
        std::cerr << "[-] " << auth.message << std::endl;
        return 1;
    }

    auto conns = core::ConnectionManager::instance().list_connections();
    int max_idx = 0;
    for (const auto& c : conns) {
        if (c.id.rfind("conn_", 0) == 0) {
            try {
                int idx = std::stoi(c.id.substr(5));
                if (idx > max_idx) max_idx = idx;
            } catch (...) {}
        }
    }
    std::string new_id = "conn_" + std::to_string(max_idx + 1);

    core::ConnectionInfo ci;
    ci.id = new_id;
    ci.host = ip;
    ci.port = port;
    ci.workspace = auth.workspace_name.empty() ? "workspace" : auth.workspace_name;
    ci.identity = user.empty() ? ("totp_client_" + ip) : user;
    ci.role = auth.role;
    ci.ticket = auth.web_ticket;
    ci.created_at = core::Utils::current_timestamp();
    ci.expires_at = (auth.ttl > 0) ? (ci.created_at + auth.ttl) : 0;

    core::ConnectionManager::instance().save_connection(ci);
    core::ConnectionManager::instance().set_active_connection(new_id);

    std::string web_url = "http://" + ip + ":" + std::to_string(port) + "/drop?ticket=" + ci.ticket;

    std::cout << "\n[+] " << auth.message << std::endl;
    std::cout << "[+] Connection saved: " << new_id << std::endl;
    std::cout << "[+] Your active connection changed to: " << new_id << " (" << ip << ":" << port << " - " << ci.workspace << ")" << std::endl;
    std::cout << "    Workspace:   " << ci.workspace << std::endl;
    std::cout << "    Endpoint:    " << ip << ":" << port << std::endl;
    std::cout << "    Role:        " << core::role_to_string(ci.role) << " (" << (ci.role == core::Role::READ_ONLY ? "Read-Only" : ci.role == core::Role::WRITE_ONLY ? "Write-Only" : "Read-Write") << ")" << std::endl;
    std::cout << "    Certificate: " << ci.ticket.substr(0, 16) << "... (TTL: " << (auth.ttl > 0 ? core::Utils::format_duration(auth.ttl) : "Session") << ")" << std::endl;
    std::cout << "    Web Drop:    " << web_url << std::endl;

    std::cout << "\nQuick Actions (no IP/port/OTP needed):" << std::endl;
    if (ci.role != core::Role::WRITE_ONLY) {
        std::cout << "  slug ls                Browse remote files" << std::endl;
        std::cout << "  slug pull ./clone      Pull remote files incrementally" << std::endl;
    }
    if (ci.role != core::Role::READ_ONLY) {
        std::cout << "  slug push <file>       Push file to remote workspace" << std::endl;
    }
    std::cout << "  slug connect -w        Open authenticated Web Dropbox" << std::endl;
    std::cout << "  slug conn list         List all saved connections\n" << std::endl;

    if (open_web) {
        std::cout << "[*] Opening browser..." << std::endl;
        open_browser(web_url);
    }

    return 0;
}

int cmd_set(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: slug set <connection_id>" << std::endl;
        return 1;
    }
    std::string id = argv[2];
    auto conn = core::ConnectionManager::instance().get_connection(id);
    if (!conn) {
        std::cerr << "[-] Connection '" << id << "' not found. Run 'slug conn list' to see available connections." << std::endl;
        return 1;
    }
    core::ConnectionManager::instance().set_active_connection(id);
    std::cout << "[+] Active connection context set to '" << id << "' (" << conn->workspace << " @ " << conn->host << ":" << conn->port << ")" << std::endl;
    return 0;
}

int cmd_conn(int argc, char* argv[]) {
    if (argc < 3 || std::string(argv[2]) == "list" || std::string(argv[2]) == "ls") {
        std::vector<char*> fwd = { argv[0], (char*)"connect", (char*)"list" };
        for (int i = 3; i < argc; ++i) fwd.push_back(argv[i]);
        return cmd_connect(static_cast<int>(fwd.size()), fwd.data());
    }
    std::string sub = argv[2];
    if (sub == "prune") {
        char* prune_argv[] = { argv[0], (char*)"connect", (char*)"prune" };
        return cmd_connect(3, prune_argv);
    }
    if (sub == "use" || sub == "set") {
        if (argc < 4) {
            std::cerr << "Usage: slug conn use <connection_id>" << std::endl;
            return 1;
        }
        char* set_argv[] = { argv[0], (char*)"set", argv[3] };
        return cmd_set(3, set_argv);
    }
    if (sub == "rm" || sub == "remove" || sub == "del" || sub == "delete") {
        if (argc < 4) {
            std::cerr << "Usage: slug conn rm <connection_id>" << std::endl;
            return 1;
        }
        std::string id = argv[3];
        core::ConnectionManager::instance().remove_connection(id);
        std::cout << "[+] Connection '" << id << "' removed from saved connections." << std::endl;
        return 0;
    }

    // Direct inspect e.g. `slug conn conn_1` or `slug conn conn_1 -w`
    return cmd_connect(argc, argv);
}

int cmd_list(int argc, char* argv[]) {
    std::string explicit_id = "";
    std::string subpath = "";
    bool recursive = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-r" || arg == "--recursive") {
            recursive = true;
        } else if (arg == "-c" || arg == "--conn") {
            if (i + 1 < argc) explicit_id = argv[++i];
        } else if (arg.front() != '-') {
            if (arg.rfind("conn_", 0) == 0 && explicit_id.empty()) {
                explicit_id = arg;
            } else if (subpath.empty()) {
                subpath = arg;
            }
        }
    }

    auto conn_opt = core::ConnectionManager::instance().resolve_connection(explicit_id);
    if (!conn_opt) {
        std::cerr << "[-] No active connection. Connect first with: slug connect -i <host> -p <port> -o <otp>" << std::endl;
        return 1;
    }
    const auto& conn = *conn_opt;

    if (conn.role == core::Role::WRITE_ONLY) {
        std::cerr << "[-] Permission Denied: Connection '" << conn.id << "' has Write-Only role (Blind Drop mode). Workspace listing is shielded." << std::endl;
        return 1;
    }

    net::SlugClient client;
    if (!client.connect(conn.host, conn.port)) {
        std::cerr << "[-] Failed to connect to remote workspace at " << conn.host << ":" << conn.port << std::endl;
        return 1;
    }

    auto auth = client.authenticate_ticket(conn.ticket);
    if (!auth.success) {
        std::cerr << "[-] Session ticket invalid or expired (" << auth.message << "). Please reconnect with 'slug connect'." << std::endl;
        return 1;
    }

    auto manifest_opt = client.fetch_manifest();
    if (!manifest_opt) {
        std::cerr << "[-] Failed to retrieve remote workspace manifest." << std::endl;
        return 1;
    }

    const auto& manifest = *manifest_opt;

    std::string norm_sub = subpath;
    std::replace(norm_sub.begin(), norm_sub.end(), '\\', '/');
    while (!norm_sub.empty() && norm_sub.front() == '/') norm_sub.erase(0, 1);
    while (!norm_sub.empty() && norm_sub.back() == '/') norm_sub.pop_back();

    std::cout << "\nREMOTE WORKSPACE: " << conn.workspace << " (" << conn.id << " @ " << conn.host << ":" << conn.port << ")" << std::endl;
    std::cout << "Scope: " << (norm_sub.empty() ? "[root]" : norm_sub) << " | Role: " << core::role_to_string(conn.role) << " | Crypto: " << client.negotiated_suite_name() << "\n" << std::endl;

    std::cout << std::left
              << std::setw(32) << "NAME"
              << std::setw(10) << "TYPE"
              << std::setw(12) << "SIZE"
              << "STATUS"
              << std::endl;
    std::cout << std::string(80, '-') << std::endl;

    struct Row {
        bool is_dir;
        std::string name;
        uint64_t size{0};
        std::string type;
        std::string status;
    };
    std::vector<Row> rows;
    std::set<std::string> seen_dirs;
    std::map<std::string, uint64_t> dir_sizes;

    auto format_skipped_status = [](const sync::ManifestSkippedEntry& s) -> std::string {
        if (s.status == "AI_FLAGGED") {
            return "Quarantined (AI Secret Guard: " + s.reason + ")";
        }
        if (s.status == "RULE_OR_GITIGNORE_BLOCKED") {
            if (s.reason.find("gitignore") != std::string::npos) {
                return "Excluded (gitignore)";
            }
            return "Blocked (policy: " + s.reason + ")";
        }
        return "Excluded (" + s.reason + ")";
    };

    if (recursive) {
        for (const auto& f : manifest.files) {
            if (norm_sub.empty() || f.relative_path.rfind(norm_sub + "/", 0) == 0 || f.relative_path == norm_sub) {
                rows.push_back({false, f.relative_path, f.size, "file", "Available"});
            }
        }
        for (const auto& s : manifest.skipped) {
            if (norm_sub.empty() || s.relative_path.rfind(norm_sub + "/", 0) == 0 || s.relative_path == norm_sub) {
                rows.push_back({false, s.relative_path, 0, "file", format_skipped_status(s)});
            }
        }
    } else {
        for (const auto& f : manifest.files) {
            std::string p = f.relative_path;
            if (norm_sub.empty()) {
                size_t slash = p.find('/');
                if (slash != std::string::npos) {
                    std::string dname = p.substr(0, slash);
                    dir_sizes[dname] += f.size;
                    if (seen_dirs.insert(dname).second) {
                        rows.push_back({true, dname + "/", 0, "folder", "Available"});
                    }
                } else {
                    rows.push_back({false, p, f.size, "file", "Available"});
                }
            } else {
                if (p.rfind(norm_sub + "/", 0) == 0) {
                    std::string rem = p.substr(norm_sub.size() + 1);
                    size_t slash = rem.find('/');
                    if (slash != std::string::npos) {
                        std::string dname = rem.substr(0, slash);
                        std::string full_d = norm_sub + "/" + dname;
                        dir_sizes[full_d] += f.size;
                        if (seen_dirs.insert(full_d).second) {
                            rows.push_back({true, dname + "/", 0, "folder", "Available"});
                        }
                    } else {
                        rows.push_back({false, rem, f.size, "file", "Available"});
                    }
                }
            }
        }

        for (auto& r : rows) {
            if (r.is_dir) {
                std::string full_d = norm_sub.empty() ? r.name.substr(0, r.name.size() - 1) : (norm_sub + "/" + r.name.substr(0, r.name.size() - 1));
                r.size = dir_sizes[full_d];
            }
        }

        for (const auto& s : manifest.skipped) {
            std::string p = s.relative_path;
            std::string st = format_skipped_status(s);
            if (norm_sub.empty()) {
                size_t slash = p.find('/');
                if (slash != std::string::npos) {
                    std::string dname = p.substr(0, slash);
                    if (seen_dirs.insert(dname).second) {
                        rows.push_back({true, dname + "/", 0, "folder", st});
                    }
                } else {
                    rows.push_back({false, p, 0, "file", st});
                }
            } else {
                if (p.rfind(norm_sub + "/", 0) == 0) {
                    std::string rem = p.substr(norm_sub.size() + 1);
                    size_t slash = rem.find('/');
                    if (slash != std::string::npos) {
                        std::string dname = rem.substr(0, slash);
                        if (seen_dirs.insert(dname).second) {
                            rows.push_back({true, dname + "/", 0, "folder", st});
                        }
                    } else {
                        rows.push_back({false, rem, 0, "file", st});
                    }
                }
            }
        }
    }

    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        if (a.is_dir != b.is_dir) return a.is_dir > b.is_dir;
        return a.name < b.name;
    });

    for (const auto& r : rows) {
        std::string sz = (r.size > 0) ? core::Utils::format_size(r.size) : "-";
        std::cout << std::left
                  << std::setw(32) << r.name
                  << std::setw(10) << r.type
                  << std::setw(12) << sz
                  << r.status
                  << std::endl;
    }

    uint64_t total_avail = 0;
    for (const auto& f : manifest.files) total_avail += f.size;

    std::cout << std::string(80, '-') << std::endl;
    std::cout << "Total: " << manifest.files.size() << " available file(s) (" << core::Utils::format_size(total_avail) << ") | "
              << manifest.skipped.size() << " excluded/quarantined item(s)\n" << std::endl;

    return 0;
}

int cmd_pull(int argc, char* argv[]) {
    std::string ip = "";
    uint16_t port = core::kDefaultPort;
    std::string totp, user, pass;
    std::string target_dir = "";
    std::string remote_scope = "";
    std::string conn_id = "";
    bool bypass_confirm = false;
    sync::DeltaSyncOptions opts;

    std::vector<std::string> pos_args;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" || arg == "--host") { if (i + 1 < argc) ip = argv[++i]; }
        else if (arg == "-p" || arg == "--port") { if (i + 1 < argc) port = static_cast<uint16_t>(std::stoi(argv[++i])); }
        else if (arg == "-o" || arg == "--otp") { if (i + 1 < argc) totp = argv[++i]; }
        else if (arg == "-u" || arg == "--user") { if (i + 1 < argc) user = argv[++i]; }
        else if (arg == "-P" || arg == "--pass" || arg == "--password" || arg == "-W") { if (i + 1 < argc) pass = argv[++i]; }
        else if (arg == "-c" || arg == "--conn") { if (i + 1 < argc) conn_id = argv[++i]; }
        else if (arg == "--to") { if (i + 1 < argc) target_dir = argv[++i]; }
        else if (arg == "-s" || arg == "--scope") { if (i + 1 < argc) remote_scope = argv[++i]; }
        else if (arg == "-y" || arg == "--yes") bypass_confirm = true;
        else if (arg == "--dry-run") opts.dry_run = true;
        else if (arg == "--prune") opts.prune = true;
        else if (arg == "--only" && i + 1 < argc) opts.only_pattern = argv[++i];
        else if (arg == "--ext" && i + 1 < argc) opts.ext_filter = argv[++i];
        else if (arg == "--max-size" && i + 1 < argc) {
            opts.max_size_bytes = std::stoull(argv[++i]);
        } else if (arg.front() != '-') {
            pos_args.push_back(arg);
        }
    }

    // Disambiguate positional arguments
    for (const auto& a : pos_args) {
        if (a.rfind("conn_", 0) == 0 && conn_id.empty()) {
            conn_id = a;
        } else if (a.front() == '/' || core::Utils::starts_with(a, "./") || core::Utils::starts_with(a, "../")) {
            if (target_dir.empty()) target_dir = a;
            else if (remote_scope.empty()) remote_scope = a;
        } else {
            if (!target_dir.empty() && remote_scope.empty()) {
                remote_scope = a;
            } else if (remote_scope.empty() && (a.find('/') != std::string::npos || a.back() == '/')) {
                remote_scope = a;
            } else if (target_dir.empty()) {
                target_dir = a;
            } else if (remote_scope.empty()) {
                remote_scope = a;
            }
        }
    }

    std::replace(remote_scope.begin(), remote_scope.end(), '\\', '/');
    while (!remote_scope.empty() && remote_scope.front() == '/') remote_scope.erase(0, 1);

    if (target_dir.empty()) {
        target_dir = "./pulled_workspace";
    }

    if (!remote_scope.empty() && opts.only_pattern.empty()) {
        opts.only_pattern = (remote_scope.back() == '/') ? (remote_scope + "*") : (remote_scope + "/*");
    }

    net::SlugClient client;

    if (!ip.empty()) {
        if (!client.connect(ip, port)) {
            std::cerr << "[-] Connection failed to " << ip << ":" << port << std::endl;
            return 1;
        }

        net::ClientAuthResult auth;
        if (!totp.empty()) {
            auth = client.authenticate_totp(totp);
        } else if (!user.empty()) {
            if (pass.empty()) {
                pass = read_hidden_password("Enter password for '" + user + "': ");
            }
            auth = client.authenticate_user(user, pass);
        } else {
            std::cerr << "[-] Auth credential required: -o <otp> or -u <user> [-P <pass>]" << std::endl;
            return 1;
        }

        if (!auth.success) {
            std::cerr << "[-] " << auth.message << std::endl;
            return 1;
        }
    } else {
        auto conn_opt = core::ConnectionManager::instance().resolve_connection(conn_id);
        if (!conn_opt) {
            std::cerr << "[-] No active connection. Connect with 'slug connect' first or specify -i <host> -o <otp>." << std::endl;
            return 1;
        }
        const auto& conn = *conn_opt;
        if (conn.role == core::Role::WRITE_ONLY) {
            std::cerr << "[-] Permission Denied: Connection '" << conn.id << "' has Write-Only role. File pulling is not permitted." << std::endl;
            return 1;
        }

        if (!client.connect(conn.host, conn.port)) {
            std::cerr << "[-] Connection failed to " << conn.host << ":" << conn.port << std::endl;
            return 1;
        }

        auto auth = client.authenticate_ticket(conn.ticket);
        if (!auth.success) {
            std::cerr << "[-] Ticket expired or invalid (" << auth.message << "). Please reconnect." << std::endl;
            return 1;
        }
    }

    auto manifest_opt = client.fetch_manifest();
    if (!manifest_opt) {
        std::cerr << "[-] Failed to retrieve workspace manifest from remote." << std::endl;
        return 1;
    }

    auto plan = sync::DeltaCalculator::compute_plan(*manifest_opt, target_dir, opts);

    uint64_t selected_size = 0;
    for (const auto& d : plan.file_deltas) {
        selected_size += d.total_size;
    }

    size_t excluded_count = 0;
    size_t quarantined_count = 0;
    for (const auto& s : manifest_opt->skipped) {
        if (!remote_scope.empty()) {
            if (s.relative_path.rfind(remote_scope, 0) != 0) continue;
        }
        if (s.status == "AI_FLAGGED") quarantined_count++;
        else excluded_count++;
    }

    std::cout << "\n--- Workspace Transfer Plan Preview ---" << std::endl;
    std::cout << "Remote scope:        " << (remote_scope.empty() ? "[all / root]" : remote_scope) << std::endl;
    std::cout << "Local destination:   " << target_dir << std::endl;
    std::cout << "Files selected:      " << plan.file_deltas.size() << " (" << core::Utils::format_size(selected_size) << ")" << std::endl;
    std::cout << "Files excluded:      " << excluded_count << " (gitignore / policy)" << std::endl;
    std::cout << "Files quarantined:   " << quarantined_count << " (AI Secret Guard)" << std::endl;
    std::cout << "Estimated download:  " << core::Utils::format_size(plan.bytes_to_transfer) << std::endl;
    std::cout << "Overwriting:         " << plan.count_modified << " local file(s)" << std::endl;
    std::cout << "---------------------------------------" << std::endl;

    if (opts.dry_run) {
        std::cout << "[*] Dry-run complete. No files transferred.\n" << std::endl;
        return 0;
    }

    bool auto_proceed = bypass_confirm || !is_terminal_interactive();
    if (!auto_proceed) {
        std::cout << "Proceed with transfer? [y/N]: " << std::flush;
        std::string ans;
        if (!std::getline(std::cin, ans) || (ans != "y" && ans != "Y" && ans != "yes" && ans != "Yes")) {
            std::cout << "[*] Transfer cancelled by user.\n" << std::endl;
            return 0;
        }
    }

    std::cout << "[*] Starting Delta Sync into " << target_dir << "..." << std::endl;
    bool ok = client.pull(target_dir, opts, nullptr, manifest_opt);
    return ok ? 0 : 1;
}

int cmd_get(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "[-] Error: 'slug get' requires a specific remote file path to download." << std::endl;
        std::cerr << "Usage: slug get <remote_path> [local_dest]" << std::endl;
        std::cerr << "       slug get <ENDPOINT?otp=CODE> <remote_path> [local_dest]" << std::endl;
        std::cerr << "\nExamples:" << std::endl;
        std::cerr << "  slug get src/main.rs ./main.rs" << std::endl;
        std::cerr << "  slug get 192.168.1.107:9443?otp=12822565 src/main.rs" << std::endl;
        std::cerr << "\nTo browse remote files:  slug ls" << std::endl;
        std::cerr << "To pull workspace files: slug pull" << std::endl;
        return 1;
    }

    std::string arg1 = argv[2];
    std::string remote_path = "";
    std::string local_dest = "";
    std::string ip = "";
    uint16_t port = core::kDefaultPort;
    std::string totp, user, pass, ticket;
    std::string conn_id = "";

    bool arg1_is_endpoint = (arg1.find("?otp=") != std::string::npos ||
                             arg1.find("?token=") != std::string::npos ||
                             core::Utils::starts_with(arg1, "slug://") ||
                             core::Utils::starts_with(arg1, "http://") ||
                             core::Utils::starts_with(arg1, "https://") ||
                             (arg1.find(':') != std::string::npos && arg1.find('/') == std::string::npos));

    std::vector<std::string> remaining_pos;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-o" || arg == "--otp") { if (i + 1 < argc) totp = argv[++i]; }
        else if (arg == "-u" || arg == "--user") { if (i + 1 < argc) user = argv[++i]; }
        else if (arg == "-P" || arg == "--pass" || arg == "--password" || arg == "-W") { if (i + 1 < argc) pass = argv[++i]; }
        else if (arg == "-p" || arg == "--port") { if (i + 1 < argc) port = static_cast<uint16_t>(std::stoi(argv[++i])); }
        else if (arg == "-i" || arg == "--host") { if (i + 1 < argc) ip = argv[++i]; }
        else if (arg == "-c" || arg == "--conn") { if (i + 1 < argc) conn_id = argv[++i]; }
        else if (arg.front() != '-') {
            remaining_pos.push_back(arg);
        }
    }

    if (arg1_is_endpoint) {
        std::string endpoint = arg1;
        if (core::Utils::starts_with(endpoint, "slug://")) endpoint = endpoint.substr(7);
        else if (core::Utils::starts_with(endpoint, "http://")) endpoint = endpoint.substr(7);
        else if (core::Utils::starts_with(endpoint, "https://")) endpoint = endpoint.substr(8);

        size_t qpos = endpoint.find('?');
        std::string query = "";
        if (qpos != std::string::npos) {
            query = endpoint.substr(qpos + 1);
            endpoint = endpoint.substr(0, qpos);
        }
        size_t slashpos = endpoint.find('/');
        if (slashpos != std::string::npos) {
            endpoint = endpoint.substr(0, slashpos);
        }

        if (!endpoint.empty()) {
            size_t colon = endpoint.rfind(':');
            if (colon != std::string::npos) {
                ip = endpoint.substr(0, colon);
                try {
                    port = static_cast<uint16_t>(std::stoi(endpoint.substr(colon + 1)));
                } catch (...) {}
            } else {
                ip = endpoint;
            }
        }

        if (!query.empty()) {
            std::stringstream ss(query);
            std::string token;
            while (std::getline(ss, token, '&')) {
                size_t eq = token.find('=');
                if (eq != std::string::npos) {
                    std::string k = token.substr(0, eq);
                    std::string v = token.substr(eq + 1);
                    if (k == "otp" || k == "token") { if (totp.empty()) totp = v; }
                    else if (k == "user" || k == "username") { if (user.empty()) user = v; }
                    else if (k == "pass" || k == "password") { if (pass.empty()) pass = v; }
                    else if (k == "ticket") { if (ticket.empty()) ticket = v; }
                }
            }
        }

        if (!remaining_pos.empty()) {
            remote_path = remaining_pos[0];
            if (remaining_pos.size() > 1) local_dest = remaining_pos[1];
        }
    } else {
        remote_path = arg1;
        if (!remaining_pos.empty()) {
            local_dest = remaining_pos[0];
        }
    }

    std::replace(remote_path.begin(), remote_path.end(), '\\', '/');
    while (!remote_path.empty() && remote_path.front() == '/') remote_path.erase(0, 1);

    if (local_dest.empty() && !remote_path.empty()) {
        local_dest = std::filesystem::path(remote_path).filename().string();
    }

    net::SlugClient client;

    if (!ip.empty()) {
        std::cout << "[*] Connecting to " << ip << ":" << port << "..." << std::endl;
        if (!client.connect(ip, port)) {
            std::cerr << "[-] Connection failed to " << ip << ":" << port << std::endl;
            return 1;
        }

        net::ClientAuthResult auth;
        if (!totp.empty()) {
            auth = client.authenticate_totp(totp);
        } else if (!user.empty()) {
            if (pass.empty()) pass = read_hidden_password("Enter password for '" + user + "': ");
            auth = client.authenticate_user(user, pass);
        } else if (!ticket.empty()) {
            auth = client.authenticate_ticket(ticket);
        } else {
            std::cerr << "[-] Authentication credential missing in link. Pass ?otp=<code> or -o <code>." << std::endl;
            return 1;
        }

        if (!auth.success) {
            std::cerr << "[-] " << auth.message << std::endl;
            return 1;
        }

        auto conns = core::ConnectionManager::instance().list_connections();
        int max_idx = 0;
        for (const auto& c : conns) {
            if (c.id.rfind("conn_", 0) == 0) {
                try {
                    int idx = std::stoi(c.id.substr(5));
                    if (idx > max_idx) max_idx = idx;
                } catch (...) {}
            }
        }
        std::string new_id = "conn_" + std::to_string(max_idx + 1);

        core::ConnectionInfo ci;
        ci.id = new_id;
        ci.host = ip;
        ci.port = port;
        ci.workspace = auth.workspace_name.empty() ? "workspace" : auth.workspace_name;
        ci.identity = user.empty() ? ("get_client_" + ip) : user;
        ci.role = auth.role;
        ci.ticket = auth.web_ticket;
        ci.created_at = core::Utils::current_timestamp();
        ci.expires_at = (auth.ttl > 0) ? (ci.created_at + auth.ttl) : 0;
        core::ConnectionManager::instance().save_connection(ci);
        core::ConnectionManager::instance().set_active_connection(new_id);

        std::cout << "[+] Authentication succeeded! Saved connection context as: " << new_id << " (" << ci.workspace << ")" << std::endl;

        if (remote_path.empty()) {
            std::cout << "\n[-] Notice: 'slug get' downloads a specific single file, not the whole workspace." << std::endl;
            std::cout << "    To browse remote files:  slug ls" << std::endl;
            std::cout << "    To pull workspace files: slug pull" << std::endl;
            std::cout << "    To get a specific file:  slug get <file_path> [local_dest]" << std::endl;
            return 0;
        }
    } else {
        auto conn_opt = core::ConnectionManager::instance().resolve_connection(conn_id);
        if (!conn_opt) {
            std::cerr << "[-] No active connection. Connect first with 'slug connect' or pass magic link." << std::endl;
            return 1;
        }
        const auto& conn = *conn_opt;
        if (conn.role == core::Role::WRITE_ONLY) {
            std::cerr << "[-] Permission Denied: Connection '" << conn.id << "' has Write-Only role. File downloading is not permitted." << std::endl;
            return 1;
        }

        if (!client.connect(conn.host, conn.port)) {
            std::cerr << "[-] Connection failed to " << conn.host << ":" << conn.port << std::endl;
            return 1;
        }

        auto auth = client.authenticate_ticket(conn.ticket);
        if (!auth.success) {
            std::cerr << "[-] Ticket expired or invalid (" << auth.message << "). Please reconnect." << std::endl;
            return 1;
        }
    }

    if (remote_path.empty()) {
        std::cerr << "[-] Error: Please specify the remote file path to download (e.g. slug get src/main.rs)." << std::endl;
        return 1;
    }

    std::cout << "[*] Downloading single file: " << remote_path << " -> " << local_dest << "..." << std::endl;
    bool ok = client.get_file(remote_path, local_dest);
    return ok ? 0 : 1;
}

int cmd_completion(int argc, char* argv[]) {
    std::string shell = "bash";
    if (argc >= 3) {
        shell = argv[2];
    }

    if (shell == "zsh") {
        std::cout << R"(#compdef slug
_slug() {
    local -a commands
    commands=(
        'add:Share a folder with Post-Quantum protection'
        'status:List all active workspaces, suites, role OTPs, and ports'
        'totp:Display active role-based One-Time TOTP tokens'
        'stop:Stop workspace server'
        'user:Manage workspace accounts and RBAC permissions'
        'session:Inspect or terminate connected client sessions'
        'audit:Inspect or whitelist AI-flagged files'
        'get:One-shot connect and pull remote workspace'
        'pull:Incremental differential sync using BLAKE3'
        'push:Upload file to remote workspace'
        'conn:Manage saved client connections'
        'serve:Detailed server view or open Admin Dashboard'
        'web:Launch authenticated Web Dropbox'
        'completion:Generate shell autocompletion script'
        'env:Post-quantum RAM-only environment secret injection'
        'bench:Performance and cryptography benchmark'
        'version:Show version information'
        'help:Show help information'
    )
    _arguments -C \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe -t commands 'slug command' commands
            ;;
        args)
            case $line[1] in
                add)
                    _arguments -s \
                        '-p[Port number]:port:' \
                        '--port[Port number]:port:' \
                        '-s[Crypto suite (1|2|3|pqc)]:suite:(1 2 3 classical modern pqc)' \
                        '--suite[Crypto suite (1|2|3|pqc)]:suite:(1 2 3 classical modern pqc)' \
                        '-t[Session TTL]:ttl:' \
                        '--ttl[Session TTL]:ttl:' \
                        '-a[Enable Stateful AI Secret Guard]' \
                        '--ai[Enable Stateful AI Secret Guard]' \
                        '-d[Run in background as daemon]' \
                        '--daemon[Run in background as daemon]' \
                        '*:directory:_files -/'
                    ;;
                user)
                    _arguments '1:subcommand:(add mod rm list)' '*:args:_files'
                    ;;
                conn)
                    _arguments '1:subcommand:(list use prune rm)' '*:args:_files'
                    ;;
                audit)
                    _arguments '1:subcommand:(list scan allow recheck)' '*:args:_files'
                    ;;
                *)
                    _files
                    ;;
            esac
            ;;
    esac
}
_slug "$@"
)" << std::endl;
        return 0;
    }

    // Default to Bash
    std::cout << R"(# Bash completion for Slug CLI
_slug_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local commands="add status totp stop session user audit get pull push conn serve web completion env bench ls set version help"

    case "${prev}" in
        slug)
            COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
            return 0
            ;;
        serve|server|stop)
            local ports=$(slug --internal-list-ports 2>/dev/null)
            COMPREPLY=( $(compgen -W "${ports} list stop -p --port -w --web -a --all" -- ${cur}) )
            return 0
            ;;
        session|sessions)
            local ports=$(slug --internal-list-ports 2>/dev/null)
            COMPREPLY=( $(compgen -W "${ports} list kill revoke rm -p --port" -- ${cur}) )
            return 0
            ;;
        totp)
            local ports=$(slug --internal-list-ports 2>/dev/null)
            COMPREPLY=( $(compgen -W "${ports} -p --port -r --role --code-only" -- ${cur}) )
            return 0
            ;;
        conn)
            COMPREPLY=( $(compgen -W "list use prune rm" -- ${cur}) )
            return 0
            ;;
        connect)
            COMPREPLY=( $(compgen -W "list prune -i --host -p --port -o --otp -u --user -P --pass -w --web" -- ${cur}) )
            return 0
            ;;
        user)
            local ports=$(slug --internal-list-ports 2>/dev/null)
            COMPREPLY=( $(compgen -W "add mod rm list -p --port -u --user -P --pass -r --role -t --ttl" -- ${cur}) )
            return 0
            ;;
        audit)
            local ports=$(slug --internal-list-ports 2>/dev/null)
            COMPREPLY=( $(compgen -W "list scan allow recheck -p --port --deep" -- ${cur}) )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh" -- ${cur}) )
            return 0
            ;;
        -s|--suite)
            COMPREPLY=( $(compgen -W "1 2 3 classical modern pqc" -- ${cur}) )
            return 0
            ;;
        -r|--role)
            COMPREPLY=( $(compgen -W "rw r w" -- ${cur}) )
            return 0
            ;;
        env)
            COMPREPLY=( $(compgen -W "init run -s --suite" -- ${cur}) )
            return 0
            ;;
        bench)
            COMPREPLY=( $(compgen -W "--quick -q --json" -- ${cur}) )
            return 0
            ;;
        *)
            ;;
    esac

    if [[ "${cur}" == -* ]]; then
        local flags="-p --port -P --pass -s --short --suite -t --ttl -a --ai -d --daemon -i --host -o --otp -u --user -r --role -w --web --dry-run --code-only --quick -q --json -y --yes -n --no --keep-data"
        COMPREPLY=( $(compgen -W "${flags}" -- ${cur}) )
        return 0
    fi

    COMPREPLY=( $(compgen -f -- "${cur}") )
}
complete -F _slug_completions slug
)" << std::endl;
    return 0;
}

int cmd_push(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: slug push <local_file> [remote_dest] [-i <host> -p <port> -o <otp>]" << std::endl;
        return 1;
    }

    std::string local_file = argv[2];
    std::string remote_dest = "";
    std::string ip = "";
    uint16_t port = core::kDefaultPort;
    std::string totp, user, pass;
    std::string conn_id = "";

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" || arg == "--host") { if (i + 1 < argc) ip = argv[++i]; }
        else if (arg == "-p" || arg == "--port") { if (i + 1 < argc) port = static_cast<uint16_t>(std::stoi(argv[++i])); }
        else if (arg == "-o" || arg == "--otp") { if (i + 1 < argc) totp = argv[++i]; }
        else if (arg == "-u" || arg == "--user") { if (i + 1 < argc) user = argv[++i]; }
        else if (arg == "-P" || arg == "--pass" || arg == "--password" || arg == "-W") { if (i + 1 < argc) pass = argv[++i]; }
        else if (arg.front() != '-') {
            if (remote_dest.empty()) remote_dest = arg;
            else conn_id = arg;
        }
    }

    if (remote_dest.empty()) {
        remote_dest = std::filesystem::path(local_file).filename().string();
    }

    net::SlugClient client;

    if (!ip.empty()) {
        if (!client.connect(ip, port)) {
            std::cerr << "[-] Connection failed to " << ip << ":" << port << std::endl;
            return 1;
        }

        net::ClientAuthResult auth;
        if (!totp.empty()) {
            auth = client.authenticate_totp(totp);
        } else if (!user.empty()) {
            if (pass.empty()) {
                pass = read_hidden_password("Enter password for '" + user + "': ");
            }
            auth = client.authenticate_user(user, pass, "w");
        }

        if (!auth.success) {
            std::cerr << "[-] Auth failed: " << auth.message << std::endl;
            return 1;
        }
    } else {
        auto conn_opt = core::ConnectionManager::instance().resolve_connection(conn_id);
        if (!conn_opt) {
            std::cerr << "[-] No active connection. Connect with 'slug connect' first or specify -i <host>." << std::endl;
            return 1;
        }
        const auto& conn = *conn_opt;
        if (conn.role == core::Role::READ_ONLY) {
            std::cerr << "[-] Permission Denied: Connection '" << conn.id << "' has Read-Only role. File pushing is not permitted." << std::endl;
            return 1;
        }

        if (!client.connect(conn.host, conn.port)) {
            std::cerr << "[-] Connection failed to " << conn.host << ":" << conn.port << std::endl;
            return 1;
        }

        auto auth = client.authenticate_ticket(conn.ticket);
        if (!auth.success) {
            std::cerr << "[-] Ticket expired or invalid (" << auth.message << "). Please reconnect." << std::endl;
            return 1;
        }
    }

    std::cout << "[*] Pushing '" << local_file << "' -> '" << remote_dest << "'..." << std::endl;
    bool ok = client.push(local_file, remote_dest);
    return ok ? 0 : 1;
}

struct PortalSession {
    std::mutex mtx;
    std::unique_ptr<net::SlugClient> client;
    std::string active_id;
    std::string active_host;
    uint16_t active_port{0};
    core::SuiteID active_suite{core::SuiteID::SUITE_3_PURE_PQC};
};
static PortalSession g_portal;

static bool read_http_request_raw(platform::TcpSocket& sock, std::string& raw_out, std::string& method, std::string& path, std::string& query, std::string& body) {
    std::vector<uint8_t> buffer;
    std::vector<uint8_t> chunk(8192);
    size_t header_end = std::string::npos;

    while (buffer.size() < 64 * 1024) {
        std::string s(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        header_end = s.find("\r\n\r\n");
        if (header_end != std::string::npos) break;
        int n = sock.receive(chunk, 3000);
        if (n <= 0) break;
        buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + n);
    }
    if (header_end == std::string::npos) return false;

    std::string header_str(reinterpret_cast<const char*>(buffer.data()), header_end);
    std::istringstream h_stream(header_str);
    std::string line;
    if (!std::getline(h_stream, line)) return false;

    std::istringstream req_line(line);
    std::string uri;
    req_line >> method >> uri;
    size_t qmark = uri.find('?');
    if (qmark != std::string::npos) {
        path = uri.substr(0, qmark);
        query = uri.substr(qmark + 1);
    } else {
        path = uri;
        query = "";
    }

    size_t content_length = 0;
    while (std::getline(h_stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 1);
            while (!val.empty() && val.front() == ' ') val.erase(0, 1);
            std::string lower_k = key;
            std::transform(lower_k.begin(), lower_k.end(), lower_k.begin(), ::tolower);
            if (lower_k == "content-length") {
                try { content_length = std::stoull(val); } catch (...) {}
            }
        }
    }

    size_t total_expected = header_end + 4 + content_length;
    if (content_length > 100 * 1024 * 1024) return false;

    while (buffer.size() < total_expected) {
        size_t needed = total_expected - buffer.size();
        size_t to_read = std::min(needed, chunk.size());
        int n = sock.receive(std::span<uint8_t>(chunk.data(), to_read), 5000);
        if (n <= 0) break;
        buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + n);
    }

    raw_out.assign(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    if (buffer.size() > header_end + 4) {
        body.assign(reinterpret_cast<const char*>(buffer.data() + header_end + 4), buffer.size() - (header_end + 4));
    }
    return true;
}

static void send_portal_http(platform::TcpSocket& sock, int code, const std::string& status_txt, const std::string& content_type, const std::string& body, const std::string& extra_headers = "") {
    std::string resp = "HTTP/1.1 " + std::to_string(code) + " " + status_txt + "\r\n"
                       "Content-Type: " + content_type + "\r\n"
                       "Content-Length: " + std::to_string(body.size()) + "\r\n"
                       "Connection: close\r\n" +
                       (extra_headers.empty() ? "" : (extra_headers + "\r\n")) +
                       "\r\n" + body;
    sock.send_all(resp);
}

int cmd_portal(int argc, char* argv[]) {
    uint16_t start_port = 8080;
    std::string cfg_port = SlugConfig::get("portal_port", "8080");
    try { start_port = static_cast<uint16_t>(std::stoi(cfg_port)); } catch (...) {}

    std::string auto_connect_id = "";
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            try { start_port = static_cast<uint16_t>(std::stoi(argv[++i])); } catch (...) {}
        } else if (arg != "portal" && arg != "web" && arg != "ui" && arg.front() != '-') {
            auto_connect_id = arg;
        }
    }

    // Try binding 127.0.0.1 starting from start_port, auto-incrementing if occupied (tự tịnh tiến cổng)
    platform::TcpListener listener;
    uint16_t actual_port = start_port;
    bool bound = false;
    for (int i = 0; i < 50; ++i) {
        if (listener.bind_and_listen("127.0.0.1", actual_port, 32)) {
            bound = true;
            break;
        }
        actual_port++;
    }

    if (!bound) {
        std::cerr << "[-] Error: Failed to bind local viewing engine to 127.0.0.1 (ports " << start_port << "-" << actual_port << " occupied)." << std::endl;
        return 1;
    }

    std::cout << "\n+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "| SLUG POST-QUANTUM VIEWING ENGINE (Local Loopback GUI)                       |" << std::endl;
    std::cout << "+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "  Viewing Engine:  http://127.0.0.1:" << actual_port << "/" << std::endl;
    std::cout << "  Loopback Port:   " << actual_port << " (Internal GUI engine only)" << std::endl;
    std::cout << "  Architecture:    Zero Remote HTTP - Encrypted PQC Binary Frames (Kyber/Dilithium)" << std::endl;
    std::cout << "  Status:          READY. Opening default browser..." << std::endl;
    std::cout << "+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "[*] Press Ctrl+C to stop local viewing engine.\n" << std::endl;

    std::string portal_url = "http://127.0.0.1:" + std::to_string(actual_port) + "/";
    open_browser(portal_url);

    // If an auto_connect_id was passed on command line, connect in background
    if (!auto_connect_id.empty()) {
        auto c_opt = core::ConnectionManager::instance().resolve_connection(auto_connect_id);
        if (c_opt) {
            std::lock_guard<std::mutex> lk(g_portal.mtx);
            auto cl = std::make_unique<net::SlugClient>(c_opt->host, c_opt->port, c_opt->suite);
            if (cl->authenticate_token(c_opt->ticket, 86400, false)) {
                g_portal.client = std::move(cl);
                g_portal.active_id = c_opt->id;
                g_portal.active_host = c_opt->host;
                g_portal.active_port = c_opt->port;
                g_portal.active_suite = c_opt->suite;
                std::cout << "[+] Auto-connected to saved workspace '" << c_opt->id << "' (" << c_opt->host << ":" << c_opt->port << ")" << std::endl;
            }
        }
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    while (!g_stop_signal_received) {
        auto client_opt = listener.accept(500);
        if (!client_opt) continue;

        std::thread([sock = std::move(*client_opt), actual_port]() mutable {
            std::string raw, method, path, query, body;
            if (!read_http_request_raw(sock, raw, method, path, query, body)) {
                return;
            }

            if (path == "/" || path == "/portal") {
                auto conns = core::ConnectionManager::instance().list_connections();
                std::string html = web::WebAssets::render_client_portal(conns, actual_port);
                send_portal_http(sock, 200, "OK", "text/html; charset=utf-8", html);
                return;
            }

            if (path == "/api/portal/connect" && method == "POST") {
                try {
                    auto j = nlohmann::json::parse(body);
                    std::string host = j.value("host", "127.0.0.1");
                    uint16_t port = static_cast<uint16_t>(j.value("port", 9443));
                    std::string suite_str = j.value("suite", "SUITE_3_PURE_PQC");
                    std::string auth_type = j.value("auth_type", "otp");
                    std::string token = j.value("token", "");
                    std::string user = j.value("username", "");
                    std::string pass = j.value("password", "");
                    bool save = j.value("save", false);
                    std::string id = j.value("id", "");

                    core::SuiteID suite = core::suite_from_string(suite_str);
                    auto client = std::make_unique<net::SlugClient>(host, port, suite);

                    bool auth_ok = false;
                    if (auth_type == "account") {
                        auth_ok = client->authenticate_user(user, pass, 86400, false);
                    } else {
                        auth_ok = client->authenticate_token(token, 86400, false);
                    }

                    if (auth_ok) {
                        if (save) {
                            std::string cid = id.empty() ? (host + ":" + std::to_string(port)) : id;
                            core::ConnectionInfo ci;
                            ci.id = cid;
                            ci.host = host;
                            ci.port = port;
                            ci.suite = suite;
                            ci.ticket = client->session_ticket();
                            ci.role = client->role();
                            ci.created_at = core::Utils::current_timestamp();
                            ci.last_active = ci.created_at;
                            core::ConnectionManager::instance().add_connection(ci);
                        }

                        {
                            std::lock_guard<std::mutex> lk(g_portal.mtx);
                            g_portal.client = std::move(client);
                            g_portal.active_id = id;
                            g_portal.active_host = host;
                            g_portal.active_port = port;
                            g_portal.active_suite = suite;
                        }

                        nlohmann::json res;
                        res["status"] = "ok";
                        res["redirect"] = "/drop";
                        send_portal_http(sock, 200, "OK", "application/json", res.dump());
                    } else {
                        nlohmann::json res;
                        res["status"] = "error";
                        res["message"] = client->get_last_error().empty() ? "Authentication failed or server unreachable." : client->get_last_error();
                        send_portal_http(sock, 200, "OK", "application/json", res.dump());
                    }
                } catch (const std::exception& e) {
                    nlohmann::json res;
                    res["status"] = "error";
                    res["message"] = e.what();
                    send_portal_http(sock, 400, "Bad Request", "application/json", res.dump());
                }
                return;
            }

            if (path == "/api/portal/open" && method == "POST") {
                try {
                    auto j = nlohmann::json::parse(body);
                    std::string id = j.value("id", "");
                    auto c_opt = core::ConnectionManager::instance().resolve_connection(id);
                    if (!c_opt) {
                        nlohmann::json res;
                        res["status"] = "error";
                        res["message"] = "Connection not found";
                        send_portal_http(sock, 404, "Not Found", "application/json", res.dump());
                        return;
                    }

                    auto client = std::make_unique<net::SlugClient>(c_opt->host, c_opt->port, c_opt->suite);
                    if (client->authenticate_token(c_opt->ticket, 86400, false)) {
                        {
                            std::lock_guard<std::mutex> lk(g_portal.mtx);
                            g_portal.client = std::move(client);
                            g_portal.active_id = c_opt->id;
                            g_portal.active_host = c_opt->host;
                            g_portal.active_port = c_opt->port;
                            g_portal.active_suite = c_opt->suite;
                        }
                        nlohmann::json res;
                        res["status"] = "ok";
                        res["redirect"] = "/drop";
                        send_portal_http(sock, 200, "OK", "application/json", res.dump());
                    } else {
                        nlohmann::json res;
                        res["status"] = "error";
                        res["message"] = client->get_last_error().empty() ? "Session ticket expired or host unreachable." : client->get_last_error();
                        send_portal_http(sock, 200, "OK", "application/json", res.dump());
                    }
                } catch (const std::exception& e) {
                    nlohmann::json res;
                    res["status"] = "error";
                    res["message"] = e.what();
                    send_portal_http(sock, 400, "Bad Request", "application/json", res.dump());
                }
                return;
            }

            if (path == "/api/portal/remove" && method == "POST") {
                try {
                    auto j = nlohmann::json::parse(body);
                    std::string id = j.value("id", "");
                    core::ConnectionManager::instance().remove_connection(id);
                    nlohmann::json res;
                    res["status"] = "ok";
                    send_portal_http(sock, 200, "OK", "application/json", res.dump());
                } catch (...) {
                    send_portal_http(sock, 400, "Bad Request", "application/json", "{\"status\":\"error\"}");
                }
                return;
            }

            // Tunnel file browsing, downloads, ZIP archives, uploads, and APIs through the encrypted PQC channel!
            std::lock_guard<std::mutex> lk(g_portal.mtx);
            if (!g_portal.client || !g_portal.client->is_connected()) {
                if (path == "/drop" || path == "/browse") {
                    send_portal_http(sock, 302, "Found", "text/plain", "Redirecting to portal...", "Location: /portal");
                    return;
                }
                send_portal_http(sock, 401, "Unauthorized", "text/plain", "Error: Not connected to any Post-Quantum workspace. Go to /portal to connect.");
                return;
            }

            // Tunnel the HTTP request over pure Post-Quantum frames
            auto tunnel_resp = g_portal.client->tunnel_http(raw);
            if (!tunnel_resp.empty()) {
                sock.send_all(tunnel_resp);
            } else {
                send_portal_http(sock, 502, "Bad Gateway", "text/plain", "Error: Remote Post-Quantum workspace failed to respond.");
            }
        }).detach();
    }

    listener.close();
    std::cout << "[*] Local viewing engine stopped." << std::endl;
    return 0;
}

int cmd_web(int argc, char* argv[]) {
    return cmd_portal(argc, argv);
}

int cmd_user(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: slug user [add|mod|rm|list] ..." << std::endl;
        return 1;
    }
    std::string sub = argv[2];
    std::filesystem::path dir = ".";
    uint16_t port = 0;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            std::string val = argv[++i];
            if (std::all_of(val.begin(), val.end(), ::isdigit)) {
                port = static_cast<uint16_t>(std::stoi(val));
            }
        } else if (arg == "--dir" && i + 1 < argc) {
            dir = argv[++i];
        }
    }

    if (port > 0) {
        auto list = core::WorkspaceManager::load_registry();
        for (const auto& w : list) {
            if (w.port == port) dir = w.path;
        }
    } else {
        auto list = core::WorkspaceManager::load_registry();
        if (list.size() == 1) {
            dir = list[0].path;
        }
    }

    core::AclManager acl(dir / ".slug" / "acl.db");

    if (sub == "add") {
        std::string u, p, r = "r", ttl_str = "24h";
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "-u" || arg == "--user") && i + 1 < argc) u = argv[++i];
            else if ((arg == "-P" || arg == "--pass" || arg == "--password") && i + 1 < argc) p = argv[++i];
            else if ((arg == "-r" || arg == "--role") && i + 1 < argc) r = argv[++i];
            else if ((arg == "-t" || arg == "--ttl") && i + 1 < argc) ttl_str = argv[++i];
        }
        if (u.empty()) {
            std::cerr << "Usage: slug user add -u <username> [-P <password>] [-r r|w|rw] [-t <ttl>] [-p <port>]" << std::endl;
            return 1;
        }
        if (p.empty()) {
            p = read_confirmed_hidden_password("Enter password for '" + u + "': ");
            if (p.empty()) return 1;
        }

        uint64_t ttl_sec = core::Utils::parse_ttl(ttl_str);
        if (acl.add_user(u, p, core::role_from_string(r), ttl_sec)) {
            std::cout << "[+] Ephemeral account '" << u << "' created with role [" << r << "] (TTL: " << core::Utils::format_ttl(ttl_sec) << ")" << std::endl;
            return 0;
        }
        return 1;

    } else if (sub == "mod" || sub == "modify" || sub == "edit") {
        std::string u, p;
        std::optional<core::Role> role = std::nullopt;
        std::optional<uint64_t> ttl_sec = std::nullopt;

        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "-u" || arg == "--user") && i + 1 < argc) u = argv[++i];
            else if ((arg == "-P" || arg == "--pass" || arg == "--password") && i + 1 < argc) p = argv[++i];
            else if ((arg == "-r" || arg == "--role") && i + 1 < argc) role = core::role_from_string(argv[++i]);
            else if ((arg == "-t" || arg == "--ttl") && i + 1 < argc) ttl_sec = core::Utils::parse_ttl(argv[++i]);
        }
        if (u.empty()) {
            std::cerr << "Usage: slug user mod -u <username> [-P <new_pass>] [-r r|w|rw] [-t <ttl>] [-p <port>]" << std::endl;
            return 1;
        }

        if (p.empty() && !role.has_value() && !ttl_sec.has_value()) {
            p = read_confirmed_hidden_password("Enter new password for '" + u + "': ");
            if (p.empty()) return 1;
        }

        if (acl.update_user(u, p, role, ttl_sec)) {
            std::cout << "[+] Account '" << u << "' modified successfully." << std::endl;
            return 0;
        } else {
            std::cerr << "[-] Failed to modify user '" << u << "' (user not found or invalid options)." << std::endl;
            return 1;
        }

    } else if (sub == "rm" || sub == "del" || sub == "delete") {
        std::string u;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "-u" || arg == "--user") && i + 1 < argc) u = argv[++i];
        }
        if (u.empty() && argc >= 4 && argv[3][0] != '-') u = argv[3];
        if (u.empty()) {
            std::cerr << "Usage: slug user rm -u <username> [-p <port>]" << std::endl;
            return 1;
        }
        if (acl.remove_user(u)) {
            std::cout << "[+] User '" << u << "' removed" << std::endl;
            return 0;
        }
        std::cerr << "[-] User not found: " << u << std::endl;
        return 1;

    } else if (sub == "list" || sub == "ls") {
        auto users = acl.list_users();
        std::cout << "WORKSPACE USERS (" << users.size() << "):\n" << std::endl;
        std::cout << std::left
                  << std::setw(16) << "[USER]"
                  << std::setw(10) << "[ROLE]"
                  << std::setw(16) << "[STATUS]"
                  << std::setw(24) << "[EXPIRES IN]"
                  << std::endl;
        std::cout << std::string(66, '-') << std::endl;
        uint64_t now = core::Utils::current_timestamp();
        for (const auto& u : users) {
            std::string exp_str = (u.expires_at == 0) ? "Permanent (∞)"
                                  : (u.expires_at > now ? core::Utils::format_duration(u.expires_at - now) : "Expired");
            std::cout << std::left
                      << std::setw(16) << u.username
                      << std::setw(10) << core::role_to_string(u.role)
                      << std::setw(16) << (u.is_expired() ? "EXPIRED" : "ACTIVE")
                      << std::setw(24) << exp_str
                      << std::endl;
        }
        std::cout << std::endl;
        return 0;
    }
    return 1;
}

int cmd_rule(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: slug rule [list|block|allow|rm] ..." << std::endl;
        return 1;
    }
    std::string sub = argv[2];
    std::filesystem::path dir = ".";
    uint16_t port = 0;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port" || arg == "-P") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--dir" && i + 1 < argc) {
            dir = argv[++i];
        }
    }

    if (port > 0) {
        auto list = core::WorkspaceManager::load_registry();
        for (const auto& w : list) {
            if (w.port == port) dir = w.path;
        }
    } else {
        auto list = core::WorkspaceManager::load_registry();
        if (list.size() == 1) {
            dir = list[0].path;
        }
    }

    std::filesystem::path rules_file = dir / ".slug" / "rules.conf";
    policy::RulesManager mgr(rules_file);

    if (sub == "list") {
        const auto& rules = mgr.rules();
        std::cout << "SECURITY FILTER RULES (" << rules.size() << "):\n" << std::endl;
        std::cout << std::left
                  << std::setw(12) << "[ID]"
                  << std::setw(10) << "[ACTION]"
                  << std::setw(12) << "[TYPE]"
                  << std::setw(32) << "[PATTERN/VALUE]"
                  << std::endl;
        std::cout << std::string(66, '-') << std::endl;
        for (const auto& r : rules) {
            std::string t_str;
            switch (r.type) {
                case policy::RuleType::PATH: t_str = "path"; break;
                case policy::RuleType::EXT: t_str = "ext"; break;
                case policy::RuleType::CONTENT: t_str = "content"; break;
                case policy::RuleType::REGEX: t_str = "regex"; break;
            }
            std::cout << std::left
                      << std::setw(12) << r.id
                      << std::setw(10) << (r.action == policy::RuleAction::ALLOW ? "ALLOW" : "BLOCK")
                      << std::setw(12) << t_str
                      << std::setw(32) << r.value
                      << std::endl;
        }
        std::cout << std::endl;
        return 0;

    } else if (sub == "block") {
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--path" && i + 1 < argc) {
                mgr.add_rule("", policy::RuleAction::BLOCK, policy::RuleType::PATH, argv[++i]);
            } else if (arg == "--ext" && i + 1 < argc) {
                mgr.add_rule("", policy::RuleAction::BLOCK, policy::RuleType::EXT, argv[++i]);
            } else if (arg == "--contains" && i + 1 < argc) {
                mgr.add_rule("", policy::RuleAction::BLOCK, policy::RuleType::CONTENT, argv[++i]);
            } else if (arg == "--regex" && i + 1 < argc) {
                mgr.add_rule("", policy::RuleAction::BLOCK, policy::RuleType::REGEX, argv[++i]);
            }
        }
        std::cout << "[+] Block rule added to .slug/rules.conf" << std::endl;
        return 0;

    } else if (sub == "allow") {
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--path" && i + 1 < argc) {
                mgr.add_rule("", policy::RuleAction::ALLOW, policy::RuleType::PATH, argv[++i]);
            }
        }
        std::cout << "[+] Allow rule added to .slug/rules.conf" << std::endl;
        return 0;

    } else if (sub == "rm" && argc >= 4) {
        std::string id = argv[3];
        if (mgr.remove_rule(id)) {
            std::cout << "[+] Rule '" << id << "' removed" << std::endl;
            return 0;
        }
        std::cerr << "[-] Rule not found: " << id << std::endl;
        return 1;
    }
    return 1;
}

int cmd_audit(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: slug audit [list|recheck|allow] ..." << std::endl;
        return 1;
    }
    std::string sub = argv[2];
    std::filesystem::path dir = ".";
    uint16_t port = 0;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port" || arg == "-P") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--dir" && i + 1 < argc) {
            dir = argv[++i];
        }
    }

    if (port > 0) {
        auto list = core::WorkspaceManager::load_registry();
        for (const auto& w : list) {
            if (w.port == port) dir = w.path;
        }
    } else {
        auto list = core::WorkspaceManager::load_registry();
        if (list.size() == 1) {
            dir = list[0].path;
        }
    }

    std::filesystem::path idx_file = dir / ".slug" / "index.db";
    ai::StatefulAuditIndex audit_idx(idx_file);

    if (sub == "list") {
        auto list = audit_idx.list_flagged_or_all(false);
        std::cout << "AI GUARD AUDIT STATE (" << list.size() << " files):\n" << std::endl;
        std::cout << std::left
                  << std::setw(28) << "[FILE PATH]"
                  << std::setw(16) << "[STATUS]"
                  << std::setw(8)  << "[LINE]"
                  << std::setw(32) << "[AI REASON / DETAILS]"
                  << std::endl;
        std::cout << std::string(84, '-') << std::endl;
        for (const auto& e : list) {
            std::cout << std::left
                      << std::setw(28) << e.file_path
                      << std::setw(16) << core::audit_status_to_string(e.status)
                      << std::setw(8)  << (e.line_number > 0 ? ("L" + std::to_string(e.line_number)) : "-")
                      << std::setw(32) << e.reason
                      << std::endl;
        }
        std::cout << std::endl;
        return 0;

    } else if (sub == "recheck") {
        std::string target = (argc >= 4) ? argv[3] : "--all";
        ai::AiScanner scanner;
        auto list = audit_idx.list_flagged_or_all(false);

        int resolved = 0;
        for (const auto& e : list) {
            if (target != "--all" && e.file_path != target) continue;

            auto data = platform::PathUtils::read_binary_file(e.file_path);
            if (!data) continue;

            std::string text(data->begin(), data->end());
            auto finding = scanner.scan_content(e.file_path, text, true);

            ai::AuditIndexEntry updated = e;
            updated.blake3_hash = crypto::Blake3::hash_hex(*data);
            updated.scanned_at = core::Utils::current_timestamp();

            if (!finding.has_secret) {
                updated.status = core::AuditStatus::CLEAN;
                updated.reason = "Secret resolved and removed";
                updated.line_number = 0;
                audit_idx.update_entry(updated);
                std::cout << "[+] UNBLOCKED: " << e.file_path << " (CLEAN - secret removed)" << std::endl;
                resolved++;
            } else {
                std::cout << "[-] STILL FLAGGED: " << e.file_path << " (" << finding.reason << " at line " << finding.line_number << ")" << std::endl;
            }
        }
        std::cout << "[*] Recheck complete: " << resolved << " file(s) unblocked." << std::endl;
        return 0;

    } else if (sub == "scan" && argc >= 4) {
        std::string target_file = argv[3];
        bool deep = false;
        ai::AiScanner::ProviderType prov = ai::AiScanner::ProviderType::LOCAL_HEURISTIC;
        std::string endpoint = "http://127.0.0.1:11434";
        std::string model = "qwen2.5-coder:7b";

        for (int i = 4; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--deep") deep = true;
            else if (arg == "--ollama") prov = ai::AiScanner::ProviderType::LOCAL_OLLAMA;
            else if (arg == "--cloud") prov = ai::AiScanner::ProviderType::CLOUD_API;
            else if (arg == "--endpoint" && i + 1 < argc) endpoint = argv[++i];
            else if (arg == "--model" && i + 1 < argc) model = argv[++i];
        }

        auto data = platform::PathUtils::read_binary_file(target_file);
        if (!data) {
            std::cerr << "[-] Error: Failed to read file: " << target_file << std::endl;
            return 1;
        }

        ai::AiScanner scanner(prov, endpoint, model);
        std::string prov_name = (prov == ai::AiScanner::ProviderType::LOCAL_HEURISTIC) ? "LOCAL_HEURISTIC (Entropy & Heuristics)" :
                                (prov == ai::AiScanner::ProviderType::LOCAL_OLLAMA) ? ("LOCAL_OLLAMA (" + endpoint + ")") :
                                "CLOUD_API (OpenAI-compatible / Groq / Gemini / OpenRouter)";

        std::cout << "[*] Scanning file: " << target_file << std::endl;
        std::cout << "    Provider: " << prov_name << std::endl;

        std::string text(data->begin(), data->end());
        auto finding = scanner.scan_content(target_file, text, deep);

        if (finding.has_secret) {
            std::cout << "\n[!] SECRET DETECTED BY AI GUARD!" << std::endl;
            std::cout << "    Line:    " << (finding.line_number > 0 ? std::to_string(finding.line_number) : "-") << std::endl;
            std::cout << "    Reason:  " << finding.reason << std::endl;
            if (!finding.matched_snippet.empty()) {
                std::cout << "    Matched: " << finding.matched_snippet << std::endl;
            }
            std::cout << "    Status:  BLOCKED from sync transit." << std::endl;
            return 2;
        } else {
            std::cout << "\n[+] No secrets detected. File is CLEAN and safe to synchronize." << std::endl;
            return 0;
        }

    } else if (sub == "allow" && argc >= 4) {
        std::string p = argv[3];
        std::string reason = "Manual whitelist exception";
        for (int i = 4; i < argc; ++i) {
            if (std::string(argv[i]) == "--reason" && i + 1 < argc) reason = argv[++i];
        }
        if (p == "--all" || p == "all") {
            auto list = audit_idx.list_flagged_or_all(false);
            int count = 0;
            for (const auto& e : list) {
                if (audit_idx.allow_file(e.file_path, reason, "admin")) {
                    count++;
                }
            }
            std::cout << "[+] Whitelisted all " << count << " quarantined file(s) (USER_ALLOWED)." << std::endl;
            return 0;
        }
        if (audit_idx.allow_file(p, reason, "admin")) {
            std::cout << "[+] Whitelisted: " << p << " (USER_ALLOWED)" << std::endl;
            return 0;
        }
        return 1;
    } else if (sub == "clear" || sub == "reset") {
        auto list = audit_idx.list_flagged_or_all(false);
        int count = 0;
        for (const auto& e : list) {
            if (audit_idx.allow_file(e.file_path, "Audit quarantine cleared", "admin")) {
                count++;
            }
        }
        std::cout << "[+] Cleared quarantine for " << count << " file(s)." << std::endl;
        return 0;
    }
    return 1;
}

int cmd_env(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: slug env <init|restore|history|prompt|run> [options]" << std::endl;
        std::cerr << "  slug env init [-s <suite>] [-k|--keep] : Seal .env into .env.pqc & Central Vault" << std::endl;
        std::cerr << "  slug env restore                       : 1-touch restore plaintext .env from Vault" << std::endl;
        std::cerr << "  slug env history                       : Inspect versioned backups in Central Vault" << std::endl;
        std::cerr << "  slug env prompt                        : Print directive prompt for AI agents" << std::endl;
        std::cerr << "  slug env run -- <command...>           : Decrypt secrets in RAM & run command" << std::endl;
        return 1;
    }
    std::string sub = argv[2];

    if (sub == "init") {
        core::SuiteID suite = core::SuiteID::SUITE_3_PURE_PQC;
        bool keep = false;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "-k" || arg == "--keep") {
                keep = true;
            } else if ((arg == "-s" || arg == "--suite") && i + 1 < argc) {
                suite = core::suite_from_string(argv[++i]);
            }
        }
        bool ok = envshield::EnvShield::init(".", suite, keep);
        return ok ? 0 : 1;

    } else if (sub == "restore" || sub == "revert" || sub == "unshield") {
        bool ok = envshield::EnvShield::restore(".");
        return ok ? 0 : 1;

    } else if (sub == "history" || sub == "list" || sub == "backups") {
        auto list = envshield::EnvShield::history(".");
        auto vault_dir = envshield::EnvShield::get_vault_dir(".");
        auto hash = envshield::EnvShield::get_workspace_hash(".");

        std::cout << "================================================================================" << std::endl;
        std::cout << "SLUG CENTRAL ENV VAULT HISTORY" << std::endl;
        std::cout << "Workspace Hash: " << hash << std::endl;
        std::cout << "Vault Location: " << vault_dir.string() << std::endl;
        std::cout << "================================================================================" << std::endl;
        if (list.empty()) {
            std::cout << "No backups found for this workspace in Central Vault." << std::endl;
            return 0;
        }

        std::cout << std::left << std::setw(8) << "VERSION"
                  << std::setw(22) << "TIMESTAMP"
                  << std::setw(12) << "SIZE"
                  << std::setw(18) << "BLAKE3"
                  << "BACKUP FILE" << std::endl;
        std::cout << std::string(80, '-') << std::endl;

        for (const auto& item : list) {
            std::string time_str = "-";
            if (item.timestamp > 0) {
                std::time_t t = static_cast<std::time_t>(item.timestamp);
                std::tm tm_buf{};
#if defined(SLUG_PLATFORM_WINDOWS)
                localtime_s(&tm_buf, &t);
#else
                localtime_r(&t, &tm_buf);
#endif
                char buf[32];
                std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
                time_str = buf;
            }
            std::string hash_short = item.blake3_hash.size() >= 12 ? (item.blake3_hash.substr(0, 12) + "...") : item.blake3_hash;
            std::string size_str = std::to_string(item.size_bytes) + " B";
            std::cout << std::left << std::setw(8) << ("v" + std::to_string(item.version))
                      << std::setw(22) << time_str
                      << std::setw(12) << size_str
                      << std::setw(18) << hash_short
                      << item.filename << std::endl;
        }
        std::cout << "================================================================================" << std::endl;
        std::cout << "Run 'slug env restore' to revert the workspace to the latest version." << std::endl;
        return 0;

    } else if (sub == "prompt" || sub == "directive") {
        std::cout << envshield::EnvShield::agent_prompt(".") << std::endl;
        std::cout << "[*] AI rule file has also been saved to .slug/ai-rule.md" << std::endl;
        std::cout << "[*] You can copy the above directive into your Cursor Rules (.cursorrules), Claude instructions, or Copilot prompts." << std::endl;
        return 0;

    } else if (sub == "run") {
        // Collect command after "--"
        std::vector<std::string> cmd;
        bool found_sep = false;
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--") {
                found_sep = true;
                continue;
            }
            if (found_sep) {
                cmd.push_back(argv[i]);
            }
        }
        if (cmd.empty()) {
            std::cerr << "Usage: slug env run -- <command...>" << std::endl;
            return 1;
        }

        return envshield::EnvShield::run(".", cmd);
    }

    std::cerr << "Unknown slug env subcommand: " << sub << ". Run 'slug help' for usage." << std::endl;
    return 1;
}

int cmd_bench(int argc, char* argv[]) {
    bool quick = false;
    bool json_output = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--quick" || arg == "-q") quick = true;
        else if (arg == "--json") json_output = true;
    }

    if (!json_output) {
        print_banner();
        std::cout << "[*] Running Slug Security & Performance Benchmark Suite..." << std::endl;
        std::cout << "    Benchmarking ML-KEM-768, ML-DSA-65, BLAKE3, AI Guard, & Chunker...\n" << std::endl;
    }

    auto report = bench::BenchmarkEngine::run_all(quick);

    if (json_output) {
        std::cout << report.to_json().dump(2) << std::endl;
        return 0;
    }

    bench::BenchmarkEngine::print_report(report);
    return 0;
}

int cmd_uninstall(int argc, char* argv[]) {
    bool auto_confirm = false;
    bool abort_now = false;
    bool keep_data = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-y" || arg == "--yes") {
            auto_confirm = true;
        } else if (arg == "-n" || arg == "--no") {
            abort_now = true;
        } else if (arg == "--keep-data") {
            keep_data = true;
        }
    }

    if (abort_now) {
        std::cout << "[*] Uninstallation cancelled." << std::endl;
        return 0;
    }

    if (!auto_confirm) {
        std::cout << "[?] Are you sure you want to completely uninstall Slug from your system? [y/N]: " << std::flush;
        std::string answer;
        if (!std::getline(std::cin, answer)) {
            std::cout << "\n[*] Uninstallation cancelled." << std::endl;
            return 0;
        }
        size_t first = answer.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) {
            std::cout << "[*] Uninstallation cancelled." << std::endl;
            return 0;
        }
        size_t last = answer.find_last_not_of(" \t\r\n");
        std::string trimmed = answer.substr(first, (last - first + 1));
        std::transform(trimmed.begin(), trimmed.end(), trimmed.begin(), ::tolower);

        if (trimmed != "y" && trimmed != "yes") {
            std::cout << "[*] Uninstallation cancelled." << std::endl;
            return 0;
        }
    }

    std::cout << "[*] Initiating Slug uninstallation..." << std::endl;

    // 1. Terminate all active workspace daemons
    auto workspaces = core::WorkspaceManager::load_registry();
    if (!workspaces.empty()) {
        std::cout << "[*] Stopping " << workspaces.size() << " active workspace server(s)..." << std::endl;
        for (const auto& w : workspaces) {
            core::WorkspaceManager::instance().stop_workspace(w.port);
            std::cout << "    [+] Stopped workspace on port " << w.port << " (PID " << w.pid << ")" << std::endl;
        }
    }

    // 2. Discover binaries to remove
    std::set<std::filesystem::path> binaries_to_remove;
    std::string self_path = get_current_executable_path();
    if (!self_path.empty()) {
        std::error_code ec;
        auto p = std::filesystem::canonical(self_path, ec);
        if (!ec && std::filesystem::exists(p)) {
            bool in_source_repo = false;
            auto parent = p.parent_path();
            if (std::filesystem::exists(parent / ".git") || std::filesystem::exists(parent.parent_path() / ".git")) {
                in_source_repo = true;
            }
            if (!in_source_repo) {
                binaries_to_remove.insert(p);
            }
        }
    }

    const char* home = std::getenv("HOME");
    if (!home) home = std::getenv("USERPROFILE");

    std::vector<std::filesystem::path> candidate_bin_paths = {
        "/usr/local/bin/slug",
        "/usr/bin/slug"
    };
    if (home) {
        candidate_bin_paths.push_back(std::filesystem::path(home) / ".local" / "bin" / "slug");
        candidate_bin_paths.push_back(std::filesystem::path(home) / "bin" / "slug");
    }

    for (const auto& cb : candidate_bin_paths) {
        std::error_code ec;
        if (std::filesystem::exists(cb, ec)) {
            auto can = std::filesystem::canonical(cb, ec);
            binaries_to_remove.insert(ec ? cb : can);
        }
    }

    bool removed_any_bin = false;
    for (const auto& bp : binaries_to_remove) {
        std::error_code ec;
        if (std::filesystem::remove(bp, ec)) {
            std::cout << "[+] Removed binary: " << bp.string() << std::endl;
            removed_any_bin = true;
        } else if (ec) {
            std::cerr << "[-] Permission denied removing " << bp.string() << " (" << ec.message() << ")" << std::endl;
            std::cerr << "    Try running: sudo rm -f " << bp.string() << std::endl;
        }
    }
    if (!removed_any_bin && binaries_to_remove.empty()) {
        std::cout << "[*] No system binary found in standard PATH directories." << std::endl;
    }

    // 3. Remove shell completions
    std::vector<std::filesystem::path> completion_paths = {
        "/etc/bash_completion.d/slug",
        "/usr/share/bash-completion/completions/slug",
        "/usr/local/share/zsh/site-functions/_slug"
    };
    if (home) {
        completion_paths.push_back(std::filesystem::path(home) / ".bash_completion.d" / "slug");
        completion_paths.push_back(std::filesystem::path(home) / ".zsh" / "completion" / "_slug");
    }

    for (const auto& cp : completion_paths) {
        std::error_code ec;
        if (std::filesystem::exists(cp, ec)) {
            if (std::filesystem::remove(cp, ec)) {
                std::cout << "[+] Removed shell completion: " << cp.string() << std::endl;
            } else if (ec) {
                std::cerr << "[-] Failed removing completion " << cp.string() << ": " << ec.message() << std::endl;
            }
        }
    }

    // 4. Remove user config and sessions directory (~/.slug)
    if (!keep_data && home) {
        std::filesystem::path slug_dir = std::filesystem::path(home) / ".slug";
        std::error_code ec;
        if (std::filesystem::exists(slug_dir, ec)) {
            std::uintmax_t count = std::filesystem::remove_all(slug_dir, ec);
            if (!ec) {
                std::cout << "[+] Removed configuration and connection store: " << slug_dir.string() << " (" << count << " items)" << std::endl;
            } else {
                std::cerr << "[-] Failed removing directory " << slug_dir.string() << ": " << ec.message() << std::endl;
            }
        }
    } else if (keep_data && home) {
        std::cout << "[*] Preserved user directory (--keep-data): " << (std::filesystem::path(home) / ".slug").string() << std::endl;
    }

    // 5. Debian package status check
#if defined(SLUG_PLATFORM_POSIX)
    if (std::system("dpkg -s slug >/dev/null 2>&1") == 0) {
        std::cout << "[!] Note: Slug was detected in Debian dpkg database." << std::endl;
        std::cout << "    To clean up package database entry, run: sudo apt purge slug" << std::endl;
    }
#endif

    std::cout << "[+] Slug has been successfully uninstalled from this system." << std::endl;
    return 0;
}

int main(int argc, char* argv[]) {
    platform::initialize_network();

    if (argc < 2) {
        return cmd_portal(argc, argv);
    }

    std::string cmd = argv[1];

    if (cmd == "portal" || cmd == "web" || cmd == "ui") return cmd_portal(argc, argv);
    if (cmd == "config") return cmd_config(argc, argv);
    if (cmd == "shortcut") return cmd_shortcut(argc, argv);
    if (cmd == "add") return cmd_add(argc, argv);
    if (cmd == "status") return cmd_status(argc, argv);
    if (cmd == "serve" || cmd == "server" || cmd == "inspect") return cmd_serve(argc, argv);
    if (cmd == "totp") return cmd_totp(argc, argv);
    if (cmd == "stop") return cmd_stop(argc, argv);
    if (cmd == "connect") return cmd_connect(argc, argv);
    if (cmd == "conn" || cmd == "connections") return cmd_conn(argc, argv);
    if (cmd == "set") return cmd_set(argc, argv);
    if (cmd == "list" || cmd == "ls") return cmd_list(argc, argv);
    if (cmd == "pull") return cmd_pull(argc, argv);
    if (cmd == "push") return cmd_push(argc, argv);
    if (cmd == "user") return cmd_user(argc, argv);
    if (cmd == "session" || cmd == "sessions") return cmd_session(argc, argv);
    if (cmd == "rule") return cmd_rule(argc, argv);
    if (cmd == "audit") return cmd_audit(argc, argv);
    if (cmd == "env") return cmd_env(argc, argv);
    if (cmd == "bench" || cmd == "benchmark") return cmd_bench(argc, argv);
    if (cmd == "--internal-list-ports") {
        auto list = core::WorkspaceManager::load_registry();
        for (size_t i = 0; i < list.size(); ++i) {
            std::cout << list[i].port << (i + 1 < list.size() ? " " : "");
        }
        std::cout << std::endl;
        return 0;
    }
    if (cmd == "get") return cmd_get(argc, argv);
    if (cmd == "completion") return cmd_completion(argc, argv);
    if (cmd == "version" || cmd == "-v" || cmd == "--version") {
        std::cout << "Slug 1.0.0 (Linux/Windows/macOS x86_64, Post-Quantum Suites 1-3, Apache-2.0)" << std::endl;
        return 0;
    }
    if (cmd == "help" || cmd == "-h" || cmd == "--help") {
        print_help();
        return 0;
    }

    std::cerr << "Unknown command: " << cmd << ". Run 'slug help' for usage." << std::endl;
    platform::cleanup_network();
    return 1;
}
