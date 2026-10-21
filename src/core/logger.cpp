#include "src/core/logger.hpp"
#include "src/platform/fs.hpp"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <thread>
#include <exception>

#if defined(_WIN32) || defined(_WIN64)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace slug::core {

namespace {

const char* level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG_LEVEL: return "DEBUG";
        case LogLevel::INFO_LEVEL:  return "INFO";
        case LogLevel::WARN_LEVEL:  return "WARN";
        case LogLevel::ERROR_LEVEL: return "ERROR";
        case LogLevel::FATAL_LEVEL: return "FATAL";
        default:                    return "UNKNOWN";
    }
}

std::string current_timestamp_formatted() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    auto timer = std::chrono::system_clock::to_time_t(now);

    std::tm bt{};
#if defined(_WIN32) || defined(_WIN64)
    localtime_s(&bt, &timer);
#else
    localtime_r(&timer, &bt);
#endif

    std::ostringstream oss;
    oss << std::put_time(&bt, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

#if defined(_WIN32) || defined(_WIN64)
LONG WINAPI slug_windows_exception_filter(EXCEPTION_POINTERS* ep) {
    DWORD code = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0;
    PVOID addr = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionAddress : nullptr;

    std::ostringstream oss;
    oss << "[CRASH SEH] Unhandled Windows Exception 0x" 
        << std::hex << std::uppercase << code 
        << " at Address 0x" << reinterpret_cast<uintptr_t>(addr);

    if (code == 0xC0000005) {
        oss << " (Access Violation: ";
        if (ep->ExceptionRecord->NumberParameters >= 2) {
            ULONG_PTR op = ep->ExceptionRecord->ExceptionInformation[0];
            ULONG_PTR bad_addr = ep->ExceptionRecord->ExceptionInformation[1];
            oss << (op == 0 ? "Read from" : (op == 1 ? "Write to" : "Execute at"))
                << " 0x" << std::hex << bad_addr;
        }
        oss << ")";
    } else if (code == 0xC0000409) {
        oss << " (STATUS_STACK_BUFFER_OVERRUN / __fastfail / abort)";
    } else if (code == 0xC00000FD) {
        oss << " (STATUS_STACK_OVERFLOW)";
    } else if (code == 0xC000001D) {
        oss << " (STATUS_ILLEGAL_INSTRUCTION)";
    }

    SLUG_LOG_FATAL(oss.str());
    Logger::instance().flush();

    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

void slug_terminate_handler() {
    std::string err_desc;
    try {
        auto ex_ptr = std::current_exception();
        if (ex_ptr) {
            std::rethrow_exception(ex_ptr);
        } else {
            err_desc = "std::terminate() called without active exception (abort() or abnormal exit)";
        }
    } catch (const std::exception& e) {
        err_desc = std::string("Unhandled std::exception: ") + e.what();
    } catch (...) {
        err_desc = "Unhandled unknown C++ exception (non-std::exception thrown)";
    }

    SLUG_LOG_FATAL("[CRASH TERMINATE] " << err_desc);
    Logger::instance().flush();

    std::abort();
}

} // namespace

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

Logger::~Logger() {
    flush();
    if (master_stream_.is_open()) master_stream_.close();
    if (ws_stream_.is_open()) ws_stream_.close();
}

void Logger::install_crash_handlers() {
    if (handlers_installed_) return;
    handlers_installed_ = true;

    std::set_terminate(slug_terminate_handler);

#if defined(_WIN32) || defined(_WIN64)
    SetUnhandledExceptionFilter(slug_windows_exception_filter);
#endif
}

void Logger::rotate_if_needed(const std::filesystem::path& path, std::ofstream& stream) {
    std::error_code ec;
    auto sz = std::filesystem::file_size(path, ec);
    if (!ec && sz > 10ULL * 1024 * 1024) { // 10MB limit
        stream.close();
        auto old_path = path;
        old_path += ".old";
        std::filesystem::remove(old_path, ec);
        std::filesystem::rename(path, old_path, ec);
        stream.open(path, std::ios::out | std::ios::app);
    }
}

void Logger::init(const std::filesystem::path& log_path) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (log_path.empty()) {
        auto home = platform::PathUtils::get_user_home();
        auto slug_dir = home / ".slug";
        std::error_code ec;
        std::filesystem::create_directories(slug_dir, ec);
        master_path_ = slug_dir / "debug.log";
    } else {
        std::error_code ec;
        std::filesystem::create_directories(log_path.parent_path(), ec);
        master_path_ = log_path;
    }

    if (master_stream_.is_open()) {
        master_stream_.close();
    }

    master_stream_.open(master_path_, std::ios::out | std::ios::app);
    rotate_if_needed(master_path_, master_stream_);

    initialized_ = true;
    install_crash_handlers();

    // Log initialization banner
    auto now_str = current_timestamp_formatted();
    master_stream_ << "[" << now_str << "] [INFO] [logger.cpp] "
                   << "=== Slug Master Debug Logger initialized (Log path: " 
                   << master_path_.string() << ") ===" << std::endl;
    master_stream_.flush();
}

void Logger::set_workspace_log(const std::filesystem::path& ws_root) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto ws_slug = ws_root / ".slug";
    std::error_code ec;
    std::filesystem::create_directories(ws_slug, ec);
    ws_path_ = ws_slug / "debug.log";

    if (ws_stream_.is_open()) {
        ws_stream_.close();
    }

    ws_stream_.open(ws_path_, std::ios::out | std::ios::app);
    rotate_if_needed(ws_path_, ws_stream_);

    auto now_str = current_timestamp_formatted();
    ws_stream_ << "[" << now_str << "] [INFO] [logger.cpp] "
               << "=== Slug Workspace Debug Logger active: " << ws_path_.string() << " ===" << std::endl;
    ws_stream_.flush();
}

void Logger::log(LogLevel level, const char* file, int line, std::string_view message) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!initialized_) {
        // Fallback auto-init if log is called before main() initializes Logger
        auto home = platform::PathUtils::get_user_home();
        auto slug_dir = home / ".slug";
        std::error_code ec;
        std::filesystem::create_directories(slug_dir, ec);
        master_path_ = slug_dir / "debug.log";
        master_stream_.open(master_path_, std::ios::out | std::ios::app);
        initialized_ = true;
        install_crash_handlers();
    }

    // Extract basename from file path for brevity
    std::string_view fname = file;
    size_t last_slash = fname.find_last_of("/\\");
    if (last_slash != std::string_view::npos) {
        fname = fname.substr(last_slash + 1);
    }

    std::string ts = current_timestamp_formatted();
    const char* lvl = level_to_string(level);

    std::ostringstream prefix;
    prefix << "[" << ts << "] [" << lvl << "] [" << fname << ":" << line << "] ";
    std::string line_str = prefix.str() + std::string(message);

    if (master_stream_.is_open()) {
        master_stream_ << line_str << std::endl;
        master_stream_.flush();
    }

    if (ws_stream_.is_open()) {
        ws_stream_ << line_str << std::endl;
        ws_stream_.flush();
    }

    // Also mirror errors to stderr in debug / console runs
    if (level == LogLevel::ERROR_LEVEL || level == LogLevel::FATAL_LEVEL) {
        std::cerr << line_str << std::endl;
    }
}

void Logger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (master_stream_.is_open()) master_stream_.flush();
    if (ws_stream_.is_open()) ws_stream_.flush();
}

std::filesystem::path Logger::master_log_path() const {
    return master_path_;
}

} // namespace slug::core
