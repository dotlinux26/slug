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

#if defined(SLUG_PLATFORM_POSIX)
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static std::atomic<bool> g_stop_signal_received{false};
static void signal_handler(int) {
    g_stop_signal_received = true;
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
#else
static std::string get_host_lan_ip() { return "127.0.0.1"; }
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
  Version: 1.0.0-rc1 | Post-Quantum Cryptography & AI Guard (Apache-2.0)
)" << std::endl;
}

void print_help() {
    print_banner();
    std::cout << R"(
USAGE:
  slug [COMMAND] [OPTIONS]

WORKSPACE HOSTING (SERVER):
  add <path>               Host and share a folder with Post-Quantum protection
                           Flags: -p, --port <port>       (Port number, default: 9443)
                                  -s, --suite <1|2|3|pqc> (Crypto suite, default: 3 pure-pqc)
                                  -t, --ttl <duration>    (Session TTL, e.g. 10m, 4h, 24h, 7d; default: 24h)
                                  -ai, --ai               (Enable Stateful AI Secret Guard)
                                  -d, --daemon            (Run as background daemon)

  status                   List all active workspaces, suites, role OTPs, and ports
                           Flags: --flagged               (Show AI-flagged / skipped files)

  totp [-p <port>]         Display active role-based One-Time TOTP tokens (rw, r, w)
                           Flags: -r, --role <r|w|rw>     (Show token for specific role)
                                  --code-only             (Print raw 8-digit code only)

  stop [-p <port>]         Stop sharing workspace (defaults to active workspace)

  serve [-p <port>] [-w]   Inspect specific workspace server or launch Admin Web Dashboard
                           Subcommands: list              (List all active servers)
                           Flags: -p, --port <port>       (Target server port/ID; defaults to active server)
                                  -w, --web               (Open Admin Dashboard in browser immediately)

  web [id] [-p <port>]     Open authenticated Web Dropbox in browser

CLIENT WORKSPACE ACCESS:
  connect -i <ip> -p <port> Connect to a remote Slug workspace & receive certificate
                           Flags: -o, --otp <8_digit_code> (Role-based One-Time TOTP)
                                  -u, --user <username>    (Ephemeral account username)
                                  --pass <password>        (Account password)
                                  -w, --web                (Launch Web Dropbox immediately)

  connect list             List all saved client connections with live heartbeat status
                           Flags: --prune                 (Automatically prune dead connections)
  connect prune            Prune dead/unreachable and expired client connections
  connect [id] [-w]        Inspect connection certificate or launch web view (-w)

  set <id>                 Set active connection context (omits need for ID on list/pull)

  list [id]                List remote workspace files from root using connection cert

  pull <target_dir> [id]   Pull remote workspace with Git-like Delta Sync
                           Flags: -i, --host <ip> -p, --port <port> -o, --otp <otp>
                                  --dry-run                (Preview transfer diff without saving)
                                  --only <pattern>         (Selective pull, e.g. "src/*")
                                  --ext <exts>             (e.g. ".cpp,.hpp,.md")
                                  --max-size <bytes>       (e.g. 50MB)
                                  --prune                  (Remove deleted local files)

  push <file> [dest] [id]  Upload file to remote workspace (requires 'w' or 'rw' role)
                           Flags: -i, --host <ip> -p, --port <port> -o, --otp <otp>

WORKSPACE ACCESS CONTROL:
  user add -u <user>       Create ephemeral workspace account
                           Flags: --pass <password>        (Account password)
                                  -r, --role <r|w|rw>      (r=read, w=write, rw=full; default: r)
                                  -t, --ttl <duration>     (Account TTL, e.g. 2h, 24h; default: 24h)
                                  -p, --port <port>        (Target workspace port)
                                  --dir <path>             (Target workspace directory)

  user rm -u <user>        Remove workspace user account
  user list [-p <port>]    List active accounts and remaining TTL

SECURITY & SECRETS:
  rule list                List security filter rules (.slug/rules.conf)
  rule block               Add a block rule (--path | --ext | --contains | --regex)
  rule allow               Add a whitelist rule (--path <path>)
  rule rm <rule_id>        Remove a security rule

  audit list               List all files currently flagged or skipped by AI Guard
  audit scan <file>        Inspect a single file directly (--deep | --ollama | --cloud)
  audit recheck <path|--all> Rescan file(s); automatically unblocks if secret was removed
  audit allow <path>       Whitelist false positive (--reason "...")

  env init                 Encrypt .env into .env.pqc with Suite 3 PurePQC
  env run -- <cmd...>      Decrypt .env.pqc in RAM only and execute command

BENCHMARK & UTILS:
  bench                    Run crypto suites, BLAKE3, AI Guard, & chunker benchmark
                           Flags: --quick (fast run) | --json (machine-readable)

  uninstall                Completely uninstall Slug from this system
                           Flags: -y, --yes               (Non-interactive automatic confirmation)
                                  -n, --no                (Cancel uninstallation immediately)
                                  --keep-data             (Preserve ~/.slug directory)

  version                  Print version information
  help                     Show this help message
)" << std::endl;
}

static int cmd_serve(int argc, char* argv[]);

int cmd_add(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: slug add <path> [-p <port>] [-s <suite>] [--ttl <duration>] [-ai] [--daemon]" << std::endl;
        return 1;
    }

    std::error_code ec;
    std::filesystem::path resolved_path = std::filesystem::canonical(argv[2], ec);
    if (ec) {
        resolved_path = std::filesystem::absolute(argv[2]).lexically_normal();
    }
    std::string folder_path = resolved_path.string();
    uint16_t port = core::kDefaultPort;
    core::SuiteID suite = core::SuiteID::SUITE_3_PURE_PQC;
    uint64_t ttl_sec = 86400;
    bool enable_ai = false;
    bool daemon = false;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if ((arg == "-s" || arg == "--suite") && i + 1 < argc) {
            suite = core::suite_from_string(argv[++i]);
        } else if ((arg == "-t" || arg == "--ttl") && i + 1 < argc) {
            ttl_sec = core::Utils::parse_ttl(argv[++i]);
        } else if (arg == "-ai" || arg == "--ai") {
            enable_ai = true;
        } else if (arg == "--daemon" || arg == "-d") {
            daemon = true;
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
#endif

    print_banner();
    std::cout << "[*] Initializing Workspace at: " << std::filesystem::absolute(folder_path).string() << std::endl;

    if (!core::WorkspaceManager::instance().add_workspace(folder_path, port, suite, ttl_sec, enable_ai)) {
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
    std::cout << "  Session TTL:     " << core::Utils::format_duration(ttl_sec) << std::endl;
    auto print_dynamic_panel = [&](uint32_t current_rem, const std::string& crw, const std::string& cr, const std::string& cw, bool clear_trailing) {
        std::string clr = clear_trailing ? "\033[K\n" : "\n";
        std::cout << "  Role OTPs (Rotates in " << current_rem << "s):" << clr;
        std::cout << "    [rw] Read-Write OTP: " << crw << " (Full Sync & Web Dropbox)" << clr;
        std::cout << "    [r]  Read-Only OTP:  " << cr  << " (Read/Pull/View files only)" << clr;
        std::cout << "    [w]  Write-Only OTP: " << cw  << " (Blind Drop/Upload only)" << clr;
        std::cout << "+----------------------------------------------------------------------------+" << clr;
        std::cout << "Connect (Local):   slug connect -i 127.0.0.1 -p " << port << " -o " << crw << clr;
        std::cout << "Connect (Network): slug connect -i " << lan_ip << " -p " << port << " -o " << crw << clr;
        std::cout << "                   (Replace " << lan_ip << " with your PUBLIC_IP if sharing over internet)" << clr;
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
    if (daemon) {
        print_dynamic_panel(rem, totp_rw, totp_r, totp_w, false);
        std::cout << "[+] Server running in background." << std::endl;
        return 0;
    }
#endif

    bool is_terminal = false;
#if defined(SLUG_PLATFORM_POSIX)
    is_terminal = (isatty(STDOUT_FILENO) != 0);
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

int cmd_status(int argc, char* argv[]) {
    bool show_flagged = false;
    uint16_t target_port = 0;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--flagged") show_flagged = true;
        else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            target_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        }
    }

    if (target_port > 0) {
        return cmd_serve(argc, argv);
    }

    auto list = core::WorkspaceManager::load_registry();

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
        auto st = query_workspace_api(w.port);
        if (st.is_object() && st.contains("totp_rw")) {
            std::string live_rw = st.value("totp_rw", st.value("totp", ""));
            int rem = st.value("totp_remaining_sec", 0);
            totp_display = live_rw + " (" + std::to_string(rem) + "s)";
        } else if (st.is_object() && st.contains("totp")) {
            std::string live_rw = st["totp"].get<std::string>();
            int rem = st.value("totp_remaining_sec", 0);
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

        std::cout << "  Path:    " << norm_path.string() << "\n" << std::endl;

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

    if (!req_role.empty()) {
        std::string code = (req_role == "r") ? totp_r : ((req_role == "w") ? totp_w : totp_rw);
        if (code_only) {
            std::cout << code << std::endl;
            return 0;
        }
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
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
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

    // Detailed server view
    std::string totp_rw = st.value("totp_rw", st.value("totp", ""));
    std::string totp_r  = st.value("totp_r", "");
    std::string totp_w  = st.value("totp_w", "");
    int rem = st.value("totp_remaining_sec", 0);
    std::string lan_ip = get_host_lan_ip();
    std::string ws_path = st.value("workspace", "");
    std::string suite = st.value("suite", "");
    bool ai_enabled = st.value("ai_enabled", false);
    uint64_t ttl_sec = st.value("ttl_seconds", 86400ULL);
    std::string ttl_str = (ttl_sec % 86400 == 0) ? std::to_string(ttl_sec / 86400) + "d"
                        : (ttl_sec % 3600 == 0) ? std::to_string(ttl_sec / 3600) + "h"
                        : core::Utils::format_duration(ttl_sec);

    std::cout << "\n+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "| SLUG SECURE WORKSPACE HOSTED SUCCESSFULLY                                  |" << std::endl;
    std::cout << "+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "  Port:            " << port << std::endl;
    if (!ws_path.empty()) {
        std::cout << "  Workspace:       " << ws_path << std::endl;
    }
    std::cout << "  Crypto Suite:    " << suite << std::endl;
    std::cout << "  AI Secret Guard: " << (ai_enabled ? "ON" : "OFF") << std::endl;
    std::cout << "  Session TTL:     " << ttl_str << std::endl;
    std::cout << "  Role OTPs (Rotates in " << rem << "s):" << std::endl;
    std::cout << "    [rw] Read-Write OTP: " << totp_rw << " (Full Sync & Web Dropbox)" << std::endl;
    std::cout << "    [r]  Read-Only OTP:  " << totp_r  << " (Read/Pull/View files only)" << std::endl;
    std::cout << "    [w]  Write-Only OTP: " << totp_w  << " (Blind Drop/Upload only)" << std::endl;
    std::cout << "+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "Connect (Local):   slug connect -i 127.0.0.1 -p " << port << " -o " << totp_rw << std::endl;
    std::cout << "Connect (Network): slug connect -i " << lan_ip << " -p " << port << " -o " << totp_rw << std::endl;
    std::cout << "                   (Replace " << lan_ip << " with your PUBLIC_IP if sharing over internet)" << std::endl;
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
        else if (arg == "--pass" || arg == "--password" || arg == "-W") { if (i + 1 < argc) pass = argv[++i]; }
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
        std::cout << "[*] Authenticating with account '" << user << "'..." << std::endl;
        auth = client.authenticate_user(user, pass);
    } else {
        std::cerr << "[-] Authentication credential required: -o <otp> or -u <user> --pass <pass>" << std::endl;
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
        std::cout << "  slug list              Browse remote files" << std::endl;
        std::cout << "  slug pull ./clone      Pull remote files incrementally" << std::endl;
    }
    if (ci.role != core::Role::READ_ONLY) {
        std::cout << "  slug push <file>       Push file to remote workspace" << std::endl;
    }
    std::cout << "  slug connect -w        Open authenticated Web Dropbox" << std::endl;
    std::cout << "  slug connect list      List all saved connections\n" << std::endl;

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
        std::cerr << "[-] Connection '" << id << "' not found. Run 'slug connect list' to see available connections." << std::endl;
        return 1;
    }
    core::ConnectionManager::instance().set_active_connection(id);
    std::cout << "[+] Active connection context set to '" << id << "' (" << conn->workspace << " @ " << conn->host << ":" << conn->port << ")" << std::endl;
    return 0;
}

int cmd_list(int argc, char* argv[]) {
    std::string explicit_id = "";
    if (argc >= 3 && argv[2][0] != '-') {
        explicit_id = argv[2];
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

    std::cout << "\nREMOTE WORKSPACE: " << conn.workspace << " (" << conn.id << " @ " << conn.host << ":" << conn.port << ")" << std::endl;
    std::cout << "Role: " << core::role_to_string(conn.role) << " | Crypto: " << client.negotiated_suite_name() << "\n" << std::endl;

    std::cout << std::left
              << std::setw(12) << "[SIZE]"
              << std::setw(18) << "[BLAKE3 HASH]"
              << "[FILE PATH]"
              << std::endl;
    std::cout << std::string(72, '-') << std::endl;

    uint64_t total_size = 0;
    for (const auto& f : manifest.files) {
        total_size += f.size;
        std::string hash_trunc = (f.file_blake3_hash.size() > 14) ? (f.file_blake3_hash.substr(0, 14) + "..") : f.file_blake3_hash;
        std::cout << std::left
                  << std::setw(12) << core::Utils::format_size(f.size)
                  << std::setw(18) << hash_trunc
                  << f.relative_path
                  << std::endl;
    }
    std::cout << std::string(72, '-') << std::endl;
    std::cout << "Total: " << manifest.files.size() << " file(s) (" << core::Utils::format_size(total_size) << ")\n" << std::endl;

    return 0;
}

int cmd_pull(int argc, char* argv[]) {
    std::string ip = "";
    uint16_t port = core::kDefaultPort;
    std::string totp, user, pass;
    std::string target_dir = "./pulled_workspace";
    std::string conn_id = "";
    sync::DeltaSyncOptions opts;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" || arg == "--host") { if (i + 1 < argc) ip = argv[++i]; }
        else if (arg == "-p" || arg == "--port") { if (i + 1 < argc) port = static_cast<uint16_t>(std::stoi(argv[++i])); }
        else if (arg == "-o" || arg == "--otp") { if (i + 1 < argc) totp = argv[++i]; }
        else if (arg == "-u" || arg == "--user") { if (i + 1 < argc) user = argv[++i]; }
        else if (arg == "--pass" || arg == "--password" || arg == "-W") { if (i + 1 < argc) pass = argv[++i]; }
        else if (arg == "--dry-run") opts.dry_run = true;
        else if (arg == "--prune") opts.prune = true;
        else if (arg == "--only" && i + 1 < argc) opts.only_pattern = argv[++i];
        else if (arg == "--ext" && i + 1 < argc) opts.ext_filter = argv[++i];
        else if (arg == "--max-size" && i + 1 < argc) {
            opts.max_size_bytes = std::stoull(argv[++i]);
        } else if (arg.front() != '-') {
            if (target_dir == "./pulled_workspace") {
                target_dir = arg;
            } else {
                conn_id = arg;
            }
        }
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
            auth = client.authenticate_user(user, pass);
        } else {
            std::cerr << "[-] Auth credential required: -o <otp> or -u <user> --pass <pass>" << std::endl;
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

    std::cout << "[*] Starting Delta Sync into " << target_dir << "..." << std::endl;
    bool ok = client.pull(target_dir, opts);
    return ok ? 0 : 1;
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
        else if (arg == "--pass" || arg == "--password" || arg == "-W") { if (i + 1 < argc) pass = argv[++i]; }
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

int cmd_web(int argc, char* argv[]) {
    std::string explicit_id = "";
    uint16_t port = 0;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg.front() != '-') {
            explicit_id = arg;
        }
    }

    auto conn_opt = core::ConnectionManager::instance().resolve_connection(explicit_id);
    if (conn_opt && !explicit_id.empty()) {
        std::string url = "http://" + conn_opt->host + ":" + std::to_string(conn_opt->port) + "/drop?ticket=" + conn_opt->ticket;
        std::cout << "[*] Opening Web Dropbox for saved connection '" << conn_opt->id << "'..." << std::endl;
        std::cout << "    URL: " << url << std::endl;
        open_browser(url);
        return 0;
    }

    if (port == 0) {
        auto list = core::WorkspaceManager::load_registry();
        if (!list.empty()) port = list[0].port;
        else port = core::kDefaultPort;
    }

    auto st = query_workspace_api(port);
    if (st.is_object() && st.contains("admin_ticket")) {
        std::string ticket = st["admin_ticket"].get<std::string>();
        std::string url = "http://127.0.0.1:" + std::to_string(port) + "/drop?ticket=" + ticket;
        std::cout << "[*] Opening Host Web Workspace (Port " << port << ")..." << std::endl;
        std::cout << "    URL: " << url << std::endl;
        open_browser(url);
        return 0;
    }

    if (conn_opt) {
        std::string url = "http://" + conn_opt->host + ":" + std::to_string(conn_opt->port) + "/drop?ticket=" + conn_opt->ticket;
        std::cout << "[*] Opening Web Dropbox for connection '" << conn_opt->id << "'..." << std::endl;
        std::cout << "    URL: " << url << std::endl;
        open_browser(url);
        return 0;
    }

    std::cerr << "[-] No local running workspace on port " << port << " and no active client connections." << std::endl;
    std::cerr << "    Host a workspace:  slug add <path>" << std::endl;
    std::cerr << "    Connect to remote: slug connect -i <host> -p <port> -o <otp>" << std::endl;
    return 1;
}

int cmd_user(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: slug user [add|rm|list] ..." << std::endl;
        return 1;
    }
    std::string sub = argv[2];
    std::filesystem::path dir = ".";
    uint16_t port = 0;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "-P" || arg == "--port") && i + 1 < argc) {
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
    }

    core::AclManager acl(dir / ".slug" / "acl.db");

    if (sub == "add") {
        std::string u, p, r = "r", ttl_str = "24h";
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "-u" || arg == "--user") && i + 1 < argc) u = argv[++i];
            else if ((arg == "--pass" || arg == "--password") && i + 1 < argc) p = argv[++i];
            else if ((arg == "-r" || arg == "--role") && i + 1 < argc) r = argv[++i];
            else if ((arg == "-t" || arg == "--ttl") && i + 1 < argc) ttl_str = argv[++i];
            else if ((arg == "-p" || arg == "-P" || arg == "--port") && i + 1 < argc) {
                std::string val = argv[++i];
                if (std::all_of(val.begin(), val.end(), ::isdigit) && port == 0) {
                    port = static_cast<uint16_t>(std::stoi(val));
                } else if (p.empty()) {
                    p = val;
                }
            }
        }
        if (u.empty() || p.empty()) {
            std::cerr << "Usage: slug user add -u <username> --pass <password> [-r r|w|rw] [-t <ttl>] [-p <port>]" << std::endl;
            return 1;
        }

        uint64_t ttl_sec = core::Utils::parse_ttl(ttl_str);
        if (acl.add_user(u, p, core::role_from_string(r), ttl_sec)) {
            std::cout << "[+] Ephemeral account '" << u << "' created with role [" << r << "] (TTL: " << ttl_str << ")" << std::endl;
            return 0;
        }
        return 1;

    } else if (sub == "rm") {
        std::string u;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "-u" || arg == "--user") && i + 1 < argc) u = argv[++i];
        }
        if (acl.remove_user(u)) {
            std::cout << "[+] User '" << u << "' removed" << std::endl;
            return 0;
        }
        return 1;

    } else if (sub == "list") {
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
            std::string exp_str = (u.expires_at == 0) ? "Permanent"
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
        if ((arg == "-p" || arg == "-P" || arg == "--port") && i + 1 < argc) {
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
        if (std::string(argv[i]) == "-P" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (std::string(argv[i]) == "--dir" && i + 1 < argc) {
            dir = argv[++i];
        }
    }

    if (port > 0) {
        auto list = core::WorkspaceManager::load_registry();
        for (const auto& w : list) {
            if (w.port == port) dir = w.path;
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
        if (audit_idx.allow_file(p, reason, "admin")) {
            std::cout << "[+] Whitelisted: " << p << " (USER_ALLOWED)" << std::endl;
            return 0;
        }
        return 1;
    }
    return 1;
}

int cmd_env(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: slug env [init|run] ..." << std::endl;
        return 1;
    }
    std::string sub = argv[2];

    if (sub == "init") {
        core::SuiteID suite = core::SuiteID::SUITE_3_PURE_PQC;
        for (int i = 3; i < argc; ++i) {
            if ((std::string(argv[i]) == "-s" || std::string(argv[i]) == "--suite") && i + 1 < argc) {
                suite = core::suite_from_string(argv[++i]);
            }
        }
        bool ok = envshield::EnvShield::init(".", suite);
        return ok ? 0 : 1;

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
        print_help();
        return 0;
    }

    std::string cmd = argv[1];

    if (cmd == "add") return cmd_add(argc, argv);
    if (cmd == "status") return cmd_status(argc, argv);
    if (cmd == "serve" || cmd == "server") return cmd_serve(argc, argv);
    if (cmd == "totp") return cmd_totp(argc, argv);
    if (cmd == "stop") return cmd_stop(argc, argv);
    if (cmd == "connect") return cmd_connect(argc, argv);
    if (cmd == "set") return cmd_set(argc, argv);
    if (cmd == "list" || cmd == "ls") return cmd_list(argc, argv);
    if (cmd == "web") return cmd_web(argc, argv);
    if (cmd == "pull") return cmd_pull(argc, argv);
    if (cmd == "push") return cmd_push(argc, argv);
    if (cmd == "user") return cmd_user(argc, argv);
    if (cmd == "rule") return cmd_rule(argc, argv);
    if (cmd == "audit") return cmd_audit(argc, argv);
    if (cmd == "env") return cmd_env(argc, argv);
    if (cmd == "bench" || cmd == "benchmark") return cmd_bench(argc, argv);
    if (cmd == "uninstall") return cmd_uninstall(argc, argv);
    if (cmd == "version" || cmd == "-v" || cmd == "--version") {
        std::cout << "Slug 1.0.0-rc1 (Linux/Windows/macOS x86_64, Post-Quantum Suites 1-3, Apache-2.0)" << std::endl;
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
