#pragma once

#include <string>
#include <string_view>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>

namespace slug::core {

enum class LogLevel {
    DEBUG_LEVEL,
    INFO_LEVEL,
    WARN_LEVEL,
    ERROR_LEVEL,
    FATAL_LEVEL
};

class Logger {
public:
    static Logger& instance();

    // Initialize the master debug log file.
    // If log_path is empty, defaults to ~/.slug/debug.log
    void init(const std::filesystem::path& log_path = {});

    // Optionally mirror logs to a specific workspace: <workspace>/.slug/debug.log
    void set_workspace_log(const std::filesystem::path& ws_root);

    // Core log method with auto-flush
    void log(LogLevel level, const char* file, int line, std::string_view message);

    // Flush all active log files to disk immediately
    void flush();

    // Get current master log file path
    std::filesystem::path master_log_path() const;

private:
    Logger() = default;
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void install_crash_handlers();
    void rotate_if_needed(const std::filesystem::path& path, std::ofstream& stream);

    std::mutex mutex_;
    std::filesystem::path master_path_;
    std::ofstream master_stream_;
    std::filesystem::path ws_path_;
    std::ofstream ws_stream_;
    bool initialized_ = false;
    bool handlers_installed_ = false;
};

// Stream-based log helper for effortless syntax:
// SLUG_LOG_ERROR("Code failed with rc=" << rc << " for file " << fname);
class LogMessageVoidify {
public:
    void operator&(const std::ostream&) const {}
};

class LogStreamCapture {
public:
    LogStreamCapture(LogLevel level, const char* file, int line)
        : level_(level), file_(file), line_(line) {}

    ~LogStreamCapture() {
        Logger::instance().log(level_, file_, line_, stream_.str());
    }

    std::ostringstream& stream() { return stream_; }

private:
    LogLevel level_;
    const char* file_;
    int line_;
    std::ostringstream stream_;
};

} // namespace slug::core

#define SLUG_LOG_STREAM(level) \
    ::slug::core::LogMessageVoidify() & ::slug::core::LogStreamCapture(level, __FILE__, __LINE__).stream()

#define SLUG_LOG_DEBUG(expr) SLUG_LOG_STREAM(::slug::core::LogLevel::DEBUG_LEVEL) << expr
#define SLUG_LOG_INFO(expr)  SLUG_LOG_STREAM(::slug::core::LogLevel::INFO_LEVEL)  << expr
#define SLUG_LOG_WARN(expr)  SLUG_LOG_STREAM(::slug::core::LogLevel::WARN_LEVEL)  << expr
#define SLUG_LOG_ERROR(expr) SLUG_LOG_STREAM(::slug::core::LogLevel::ERROR_LEVEL) << expr
#define SLUG_LOG_FATAL(expr) SLUG_LOG_STREAM(::slug::core::LogLevel::FATAL_LEVEL) << expr
