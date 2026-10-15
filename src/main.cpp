#include "src/core/workspace.hpp"
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

#if defined(SLUG_PLATFORM_POSIX)
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

static std::atomic<bool> g_stop_signal_received{false};
static void signal_handler(int) {
    g_stop_signal_received = true;
}
#endif

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

COMMANDS:
  add <path>               Host and share a folder on an isolated port
                           Flags: -p <port> (default: 9443)
                                  -s <1|2|3|classical|modern|pqc> (default: 3 pure-pqc)
                                  --ttl <duration> (e.g. 10m, 2h, 24h, 7d; default: 24h)
                                  -ai (Enable Stateful AI Secret Guard)
                                  --daemon (Run in background)

  status                   List all active workspaces, suites, TOTP codes, and ports
                           Flags: --flagged (Show AI-flagged / skipped files)

  stop -p <port>           Stop sharing workspace at the specified port

  connect -i <ip> -p <port> Test connection to a remote Slug workspace
                           Flags: -o <totp_8_digit_code> (One-Time-Bind TOTP)
                                  -u <username> -W <password> (Account login)

  pull <target_dir>        Pull remote workspace with Git-like Delta Sync
                           Flags: -i <ip> -p <port>
                                  -o <totp> | -u <user> -W <pass>
                                  --dry-run (Preview transfer diff without saving)
                                  --only <pattern> (Selective pull, e.g. "src/*")
                                  --ext <exts> (e.g. ".cpp,.hpp,.md")
                                  --max-size <bytes_or_str> (e.g. 50MB)
                                  --prune (Remove deleted local files)

  push <file> <remote_dest> Upload file to remote workspace (requires 'w' or 'rw' role)
                           Flags: -i <ip> -p <port>
                                  -o <totp> | -u <user> -W <pass>

  user add -u <user>       Create ephemeral workspace account
                           Flags: -p <password>
                                  --role <r|w|rw> (default: r)
                                  --ttl <duration> (e.g. 2h, 24h)
                                  [-P <port> | --dir <path>]

  user rm -u <user>        Remove workspace user account
  user list                List active accounts and remaining TTL

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

  bench                    Run crypto suites, BLAKE3, AI Guard, & chunker benchmark
                           Flags: --quick (fast run) | --json (machine-readable)

  version                  Print version information
  help                     Show this help message
)" << std::endl;
}

int cmd_add(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: slug add <path> [-p <port>] [-s <suite>] [--ttl <duration>] [-ai] [--daemon]" << std::endl;
        return 1;
    }

    std::string folder_path = argv[2];
    uint16_t port = core::kDefaultPort;
    core::SuiteID suite = core::SuiteID::SUITE_3_PURE_PQC;
    uint64_t ttl_sec = 86400;
    bool enable_ai = false;
    bool daemon = false;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-p" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if ((arg == "-s" || arg == "--suite") && i + 1 < argc) {
            suite = core::suite_from_string(argv[++i]);
        } else if (arg == "--ttl" && i + 1 < argc) {
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

    std::string totp = server->totp_manager().generate_code();
    uint32_t rem = server->totp_manager().remaining_seconds();

    std::cout << "\n+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "| SLUG SECURE WORKSPACE HOSTED SUCCESSFULLY                                  |" << std::endl;
    std::cout << "+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "  Port:            " << port << std::endl;
    std::cout << "  Crypto Suite:    " << core::suite_to_string(suite) << std::endl;
    std::cout << "  AI Secret Guard: " << (enable_ai ? "ENABLED (Stateful BLAKE3 Audit)" : "OFF") << std::endl;
    std::cout << "  Session TTL:     " << core::Utils::format_duration(ttl_sec) << std::endl;
    std::cout << "  One-Time TOTP:   " << totp << " (Rotates in " << rem << "s)" << std::endl;
    std::cout << "  Directory Drop:  http://127.0.0.1:" << port << "/drop" << std::endl;
    std::cout << "  Admin Dashboard: http://127.0.0.1:" << port << "/admin" << std::endl;
    std::cout << "+----------------------------------------------------------------------------+" << std::endl;
    std::cout << "Connect with:  slug connect -i 127.0.0.1 -p " << port << " -o " << totp << std::endl;
    std::cout << "Sync with:     slug pull ./local_dir -i 127.0.0.1 -p " << port << " -o " << totp << std::endl;
    std::cout << "+----------------------------------------------------------------------------+\n" << std::endl;

#if defined(SLUG_PLATFORM_POSIX)
    if (daemon) {
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
    } else {
        std::cout << "[*] Press Ctrl+C to stop server..." << std::endl;
    }

    while (server->is_running() && !g_stop_signal_received) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
#else
    if (daemon) {
        std::cout << "[+] Server running in background." << std::endl;
        return 0;
    }
    std::cout << "[*] Press Ctrl+C to stop server..." << std::endl;
    while (server->is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
#endif

    server->stop();
    return 0;
}

int cmd_status(int argc, char* argv[]) {
    bool show_flagged = false;
    for (int i = 2; i < argc; ++i) {
        if (std::string(argv[i]) == "--flagged") show_flagged = true;
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
              << std::setw(28) << "[WORKSPACE]"
              << std::setw(28) << "[CRYPTO SUITE]"
              << std::setw(10) << "[AI-EXT]"
              << std::setw(12) << "[PID]"
              << std::endl;
    std::cout << std::string(86, '-') << std::endl;

    for (const auto& w : list) {
        std::string path_str = w.path.filename().string();
        if (path_str.empty()) path_str = w.path.string();

        std::cout << std::left
                  << std::setw(8)  << w.port
                  << std::setw(28) << (path_str.size() > 26 ? path_str.substr(0, 23) + "..." : path_str)
                  << std::setw(28) << core::suite_to_short_name(w.suite)
                  << std::setw(10) << (w.ai_enabled ? "ON" : "OFF")
                  << std::setw(12) << w.pid
                  << std::endl;

        if (show_flagged) {
            std::filesystem::path idx_path = w.path / ".slug" / "index.db";
            ai::StatefulAuditIndex audit_idx(idx_path);
            auto flagged = audit_idx.list_flagged_or_all(true);
            if (!flagged.empty()) {
                std::cout << "   |-> AI Flagged Files (" << flagged.size() << "):" << std::endl;
                for (const auto& f : flagged) {
                    std::cout << "       [FLAGGED] " << f.file_path << " (L" << f.line_number << ": " << f.reason << ")" << std::endl;
                }
            }
        }
    }
    std::cout << std::endl;
    return 0;
}

int cmd_stop(int argc, char* argv[]) {
    uint16_t port = 0;
    for (int i = 2; i < argc; ++i) {
        if (std::string(argv[i]) == "-p" && i + 1 < argc) {
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

int cmd_connect(int argc, char* argv[]) {
    std::string ip = "127.0.0.1";
    uint16_t port = core::kDefaultPort;
    std::string totp, user, pass;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) ip = argv[++i];
        else if (arg == "-p" && i + 1 < argc) port = static_cast<uint16_t>(std::stoi(argv[++i]));
        else if (arg == "-o" && i + 1 < argc) totp = argv[++i];
        else if (arg == "-u" && i + 1 < argc) user = argv[++i];
        else if (arg == "-W" && i + 1 < argc) pass = argv[++i];
    }

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
        std::cerr << "[-] Authentication credential required (-o <totp> or -u <user> -W <pass>)" << std::endl;
        return 1;
    }

    if (auth.success) {
        std::cout << "[+] " << auth.message << " | Role: " << core::role_to_string(auth.role)
                  << " | Session ID: " << auth.session_id << std::endl;
        return 0;
    } else {
        std::cerr << "[-] " << auth.message << std::endl;
        return 1;
    }
}

int cmd_pull(int argc, char* argv[]) {
    std::string ip = "127.0.0.1";
    uint16_t port = core::kDefaultPort;
    std::string totp, user, pass;
    std::string target_dir = "./pulled_workspace";
    sync::DeltaSyncOptions opts;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) ip = argv[++i];
        else if (arg == "-p" && i + 1 < argc) port = static_cast<uint16_t>(std::stoi(argv[++i]));
        else if (arg == "-o" && i + 1 < argc) totp = argv[++i];
        else if (arg == "-u" && i + 1 < argc) user = argv[++i];
        else if (arg == "-W" && i + 1 < argc) pass = argv[++i];
        else if (arg == "--dry-run") opts.dry_run = true;
        else if (arg == "--prune") opts.prune = true;
        else if (arg == "--only" && i + 1 < argc) opts.only_pattern = argv[++i];
        else if (arg == "--ext" && i + 1 < argc) opts.ext_filter = argv[++i];
        else if (arg == "--max-size" && i + 1 < argc) {
            opts.max_size_bytes = std::stoull(argv[++i]);
        } else if (arg.front() != '-') {
            target_dir = arg;
        }
    }

    net::SlugClient client;
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
        std::cerr << "[-] Auth credential required (-o <totp> or -u <user> -W <pass>)" << std::endl;
        return 1;
    }

    if (!auth.success) {
        std::cerr << "[-] " << auth.message << std::endl;
        return 1;
    }

    std::cout << "[*] Starting Delta Sync into " << target_dir << "..." << std::endl;
    bool ok = client.pull(target_dir, opts);
    return ok ? 0 : 1;
}

int cmd_push(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: slug push <local_file> <remote_dest> -i <ip> -p <port> -o <totp> | -u <user> -W <pass>" << std::endl;
        return 1;
    }

    std::string local_file = argv[2];
    std::string remote_dest = argv[3];
    std::string ip = "127.0.0.1";
    uint16_t port = core::kDefaultPort;
    std::string totp, user, pass;

    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) ip = argv[++i];
        else if (arg == "-p" && i + 1 < argc) port = static_cast<uint16_t>(std::stoi(argv[++i]));
        else if (arg == "-o" && i + 1 < argc) totp = argv[++i];
        else if (arg == "-u" && i + 1 < argc) user = argv[++i];
        else if (arg == "-W" && i + 1 < argc) pass = argv[++i];
    }

    net::SlugClient client;
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

    bool ok = client.push(local_file, remote_dest);
    return ok ? 0 : 1;
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

    core::AclManager acl(dir / ".slug" / "acl.db");

    if (sub == "add") {
        std::string u, p, r = "r", ttl_str = "24h";
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "-u" && i + 1 < argc) u = argv[++i];
            else if (arg == "-p" && i + 1 < argc) p = argv[++i];
            else if (arg == "--role" && i + 1 < argc) r = argv[++i];
            else if (arg == "--ttl" && i + 1 < argc) ttl_str = argv[++i];
        }
        if (u.empty() || p.empty()) {
            std::cerr << "Usage: slug user add -u <username> -p <password> [--role r|w|rw] [--ttl 24h]" << std::endl;
            return 1;
        }

        uint64_t ttl_sec = core::Utils::parse_ttl(ttl_str);
        if (acl.add_user(u, p, core::role_from_string(r), ttl_sec)) {
            std::cout << "[+] User '" << u << "' added with role " << r << " (TTL: " << ttl_str << ")" << std::endl;
            return 0;
        }
        return 1;

    } else if (sub == "rm") {
        std::string u;
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "-u" && i + 1 < argc) u = argv[++i];
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

int main(int argc, char* argv[]) {
    platform::initialize_network();

    if (argc < 2) {
        print_help();
        return 0;
    }

    std::string cmd = argv[1];

    if (cmd == "add") return cmd_add(argc, argv);
    if (cmd == "status") return cmd_status(argc, argv);
    if (cmd == "stop") return cmd_stop(argc, argv);
    if (cmd == "connect") return cmd_connect(argc, argv);
    if (cmd == "pull") return cmd_pull(argc, argv);
    if (cmd == "push") return cmd_push(argc, argv);
    if (cmd == "user") return cmd_user(argc, argv);
    if (cmd == "rule") return cmd_rule(argc, argv);
    if (cmd == "audit") return cmd_audit(argc, argv);
    if (cmd == "env") return cmd_env(argc, argv);
    if (cmd == "bench" || cmd == "benchmark") return cmd_bench(argc, argv);
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
