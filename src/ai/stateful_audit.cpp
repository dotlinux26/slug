#include "src/ai/stateful_audit.hpp"
#include "src/core/utils.hpp"
#include "src/platform/fs.hpp"
#include "third_party/sqlite/sqlite3.h"
#include "third_party/json/json.hpp"
#include <iostream>

namespace slug::ai {

using json = nlohmann::json;

static std::string normalize_path_key(const std::string& p) {
    std::string s = p;
    for (auto& c : s) {
        if (c == '\\') c = '/';
    }
    while (s.rfind("./", 0) == 0) {
        s = s.substr(2);
    }
    return s;
}

StatefulAuditIndex::StatefulAuditIndex(std::filesystem::path index_file)
    : index_file_(std::move(index_file)) {
    if (!index_file_.empty()) {
        init_sqlite();
    }
}

StatefulAuditIndex::~StatefulAuditIndex() {
    close_sqlite();
}

StatefulAuditIndex::StatefulAuditIndex(StatefulAuditIndex&& other) noexcept {
    std::lock_guard<std::mutex> lk(other.mutex_);
    index_file_ = std::move(other.index_file_);
    db_ = other.db_;
    other.db_ = nullptr;
}

StatefulAuditIndex& StatefulAuditIndex::operator=(StatefulAuditIndex&& other) noexcept {
    if (this != &other) {
        std::scoped_lock lock(mutex_, other.mutex_);
        close_sqlite();
        index_file_ = std::move(other.index_file_);
        db_ = other.db_;
        other.db_ = nullptr;
    }
    return *this;
}

void StatefulAuditIndex::close_sqlite() {
    if (db_) {
        sqlite3_close_v2(db_);
        db_ = nullptr;
    }
}

void StatefulAuditIndex::init_sqlite() {
    close_sqlite();
    if (index_file_.empty()) return;

    platform::PathUtils::ensure_directory(index_file_.parent_path());

    // Check if existing file is legacy JSON document
    std::vector<AuditIndexEntry> legacy_entries;
    if (std::filesystem::exists(index_file_)) {
        auto content = platform::PathUtils::read_text_file(index_file_);
        if (content && !content->empty()) {
            std::string trimmed = core::Utils::trim(*content);
            if (!trimmed.empty() && trimmed.front() == '{') {
                try {
                    auto j = json::parse(trimmed);
                    if (j.contains("entries") && j["entries"].is_array()) {
                        for (const auto& item : j["entries"]) {
                            AuditIndexEntry e;
                            e.file_path = normalize_path_key(item.value("file_path", ""));
                            e.blake3_hash = item.value("blake3_hash", "");
                            e.status = core::audit_status_from_string(item.value("status", "UNKNOWN"));
                            e.line_number = item.value("line_number", 0);
                            e.reason = item.value("reason", "");
                            e.scanned_at = item.value("scanned_at", 0ULL);
                            e.decision_actor = item.value("decision_actor", "");
                            e.decision_reason = item.value("decision_reason", "");
                            if (!e.file_path.empty()) {
                                legacy_entries.push_back(e);
                            }
                        }
                    }
                } catch (...) {}
                std::error_code ec;
                std::filesystem::remove(index_file_, ec);
            }
        }
    }

    // Open SQLite 3 Database
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
#if defined(_WIN32)
    int rc = sqlite3_open_v2(reinterpret_cast<const char*>(index_file_.u8string().c_str()), &db_, flags, nullptr);
#else
    int rc = sqlite3_open_v2(index_file_.c_str(), &db_, flags, nullptr);
#endif
    if (rc != SQLITE_OK || !db_) {
        return;
    }

    // Configure SQLite3 pragmas for high speed & durability
    sqlite3_exec(db_, "PRAGMA journal_mode = WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA synchronous = NORMAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout = 5000;", nullptr, nullptr, nullptr);

    // Initialize Schema
    const char* schema = 
        "CREATE TABLE IF NOT EXISTS audit_entries ("
        "  file_path TEXT PRIMARY KEY,"
        "  blake3_hash TEXT,"
        "  status INTEGER,"
        "  line_number INTEGER,"
        "  reason TEXT,"
        "  scanned_at INTEGER,"
        "  decision_actor TEXT,"
        "  decision_reason TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_status ON audit_entries(status);";

    sqlite3_exec(db_, schema, nullptr, nullptr, nullptr);

    // Auto-heal legacy false positives: immediately purge any AI/Smart-Filter flagged non-scannable files (binaries, compiled, media, .pyd, .dll)
    const char* heal_sql =
        "DELETE FROM audit_entries WHERE status IN (1, 2) AND ("
        "  file_path LIKE '%.pyd' OR file_path LIKE '%.dll' OR file_path LIKE '%.exe' OR "
        "  file_path LIKE '%.bin' OR file_path LIKE '%.pak' OR file_path LIKE '%.so' OR "
        "  file_path LIKE '%.dylib' OR file_path LIKE '%.obj' OR file_path LIKE '%.o' OR "
        "  file_path LIKE '%.class' OR file_path LIKE '%.pyc' OR file_path LIKE '%.dat' OR "
        "  file_path LIKE '%.png' OR file_path LIKE '%.jpg' OR file_path LIKE '%.jpeg' OR "
        "  file_path LIKE '%.gif' OR file_path LIKE '%.ico' OR file_path LIKE '%.webp' OR "
        "  file_path LIKE '%.svg' OR file_path LIKE '%.mp4' OR file_path LIKE '%.mp3' OR "
        "  file_path LIKE '%.pdf' OR file_path LIKE '%.zip' OR file_path LIKE '%.tar' OR "
        "  file_path LIKE '%.gz' OR file_path LIKE '%.7z' OR file_path LIKE '%.iso' OR "
        "  file_path LIKE '%.ttf' OR file_path LIKE '%.woff' OR file_path LIKE '%.woff2' OR "
        "  file_path LIKE '%.wasm' OR file_path LIKE '%.pdb' OR file_path LIKE '%.lib' OR "
        "  file_path LIKE '%.a' OR file_path LIKE '%.node'"
        ");";
    sqlite3_exec(db_, heal_sql, nullptr, nullptr, nullptr);

    // Import legacy entries if any existed
    if (!legacy_entries.empty()) {
        sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
        for (const auto& e : legacy_entries) {
            update_entry(e);
        }
        sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, nullptr);
    }
}

bool StatefulAuditIndex::load() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) {
        init_sqlite();
    }
    return db_ != nullptr;
}

bool StatefulAuditIndex::save() const {
    // SQLite auto-persists in WAL mode; checkpoint passively
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_) {
        sqlite3_wal_checkpoint_v2(db_, nullptr, SQLITE_CHECKPOINT_PASSIVE, nullptr, nullptr);
        return true;
    }
    return false;
}

core::AuditStatus StatefulAuditIndex::check_cached_status(const std::string& file_path, const std::string& current_blake3_hash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return core::AuditStatus::UNKNOWN;

    std::string key = normalize_path_key(file_path);
    const char* sql = "SELECT blake3_hash, status FROM audit_entries WHERE file_path = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return core::AuditStatus::UNKNOWN;
    }

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    core::AuditStatus result = core::AuditStatus::UNKNOWN;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* h = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        int st = sqlite3_column_int(stmt, 1);
        if (h && current_blake3_hash == h) {
            result = static_cast<core::AuditStatus>(st);
        }
    }
    sqlite3_finalize(stmt);
    return result;
}

void StatefulAuditIndex::update_entry(const AuditIndexEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return;

    std::string key = normalize_path_key(entry.file_path);
    const char* sql = 
        "INSERT INTO audit_entries (file_path, blake3_hash, status, line_number, reason, scanned_at, decision_actor, decision_reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(file_path) DO UPDATE SET "
        "blake3_hash=excluded.blake3_hash, "
        "status=excluded.status, "
        "line_number=excluded.line_number, "
        "reason=excluded.reason, "
        "scanned_at=excluded.scanned_at, "
        "decision_actor=excluded.decision_actor, "
        "decision_reason=excluded.decision_reason;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, entry.blake3_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, static_cast<int>(entry.status));
    sqlite3_bind_int(stmt, 4, entry.line_number);
    sqlite3_bind_text(stmt, 5, entry.reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, static_cast<sqlite3_int64>(entry.scanned_at));
    sqlite3_bind_text(stmt, 7, entry.decision_actor.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, entry.decision_reason.c_str(), -1, SQLITE_STATIC);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

bool StatefulAuditIndex::allow_file(const std::string& file_path, const std::string& reason, const std::string& actor) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return false;

    std::string key = normalize_path_key(file_path);
    const char* sql = 
        "INSERT INTO audit_entries (file_path, blake3_hash, status, line_number, reason, scanned_at, decision_actor, decision_reason) "
        "VALUES (?, '', ?, 0, ?, ?, ?, ?) "
        "ON CONFLICT(file_path) DO UPDATE SET "
        "status=excluded.status, "
        "reason=excluded.reason, "
        "decision_actor=excluded.decision_actor, "
        "decision_reason=excluded.decision_reason, "
        "scanned_at=excluded.scanned_at;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    uint64_t now = core::Utils::current_timestamp();
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, static_cast<int>(core::AuditStatus::USER_ALLOWED));
    sqlite3_bind_text(stmt, 3, reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(now));
    sqlite3_bind_text(stmt, 5, actor.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, reason.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool StatefulAuditIndex::allow_folder(const std::string& folder_path, const std::string& reason, const std::string& actor) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return false;

    std::string norm = normalize_path_key(folder_path);
    while (!norm.empty() && norm.back() == '/') norm.pop_back();

    const char* sql = 
        "UPDATE audit_entries SET status = ?, decision_actor = ?, decision_reason = ?, reason = ?, scanned_at = ? "
        "WHERE (file_path = ? OR file_path LIKE ? || '/%');";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    uint64_t now = core::Utils::current_timestamp();
    sqlite3_bind_int(stmt, 1, static_cast<int>(core::AuditStatus::USER_ALLOWED));
    sqlite3_bind_text(stmt, 2, actor.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(now));
    sqlite3_bind_text(stmt, 6, norm.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, norm.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool StatefulAuditIndex::allow_all(const std::string& reason, const std::string& actor) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return false;

    const char* sql =
        "UPDATE audit_entries SET status = ?, decision_actor = ?, decision_reason = ?, reason = ?, scanned_at = ? "
        "WHERE status IN (1, 2, 5);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    uint64_t now = core::Utils::current_timestamp();
    sqlite3_bind_int(stmt, 1, static_cast<int>(core::AuditStatus::USER_ALLOWED));
    sqlite3_bind_text(stmt, 2, actor.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(now));

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool StatefulAuditIndex::clear_flagged_for_path(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return false;

    std::string norm = normalize_path_key(path);
    const char* sql =
        "DELETE FROM audit_entries WHERE (file_path = ? OR file_path LIKE ? || '/%') AND status IN (1, 2, 5);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, norm.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, norm.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool StatefulAuditIndex::block_file(const std::string& file_path, const std::string& reason, const std::string& actor) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return false;

    std::string key = normalize_path_key(file_path);
    const char* sql = 
        "INSERT INTO audit_entries (file_path, blake3_hash, status, line_number, reason, scanned_at, decision_actor, decision_reason) "
        "VALUES (?, '', ?, 0, ?, ?, ?, ?) "
        "ON CONFLICT(file_path) DO UPDATE SET "
        "status=excluded.status, "
        "reason=excluded.reason, "
        "decision_actor=excluded.decision_actor, "
        "decision_reason=excluded.decision_reason, "
        "scanned_at=excluded.scanned_at;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    uint64_t now = core::Utils::current_timestamp();
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, static_cast<int>(core::AuditStatus::RULE_BLOCKED));
    sqlite3_bind_text(stmt, 3, reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(now));
    sqlite3_bind_text(stmt, 5, actor.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, reason.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool StatefulAuditIndex::remove_entry(const std::string& file_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return false;

    std::string key = normalize_path_key(file_path);
    const char* sql = "DELETE FROM audit_entries WHERE file_path = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::optional<AuditIndexEntry> StatefulAuditIndex::get_entry(const std::string& file_path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return std::nullopt;

    std::string key = normalize_path_key(file_path);
    const char* sql = "SELECT file_path, blake3_hash, status, line_number, reason, scanned_at, decision_actor, decision_reason "
                      "FROM audit_entries WHERE file_path = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    std::optional<AuditIndexEntry> res = std::nullopt;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        AuditIndexEntry e;
        e.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const char* h = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        e.blake3_hash = h ? h : "";
        e.status = static_cast<core::AuditStatus>(sqlite3_column_int(stmt, 2));
        e.line_number = sqlite3_column_int(stmt, 3);
        const char* r = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        e.reason = r ? r : "";
        e.scanned_at = static_cast<uint64_t>(sqlite3_column_int64(stmt, 5));
        const char* da = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        e.decision_actor = da ? da : "";
        const char* dr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        e.decision_reason = dr ? dr : "";
        res = e;
    }
    sqlite3_finalize(stmt);
    return res;
}

bool StatefulAuditIndex::is_flagged(const std::string& file_path) const {
    auto entry = get_entry(file_path);
    if (!entry) return false;
    return entry->status == core::AuditStatus::AI_FLAGGED ||
           entry->status == core::AuditStatus::SMART_FILTER_FLAGGED ||
           entry->status == core::AuditStatus::RULE_BLOCKED;
}

std::vector<AuditIndexEntry> StatefulAuditIndex::list_flagged_or_all(bool only_flagged) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AuditIndexEntry> results;
    if (!db_) return results;

    const char* sql = only_flagged
        ? "SELECT file_path, blake3_hash, status, line_number, reason, scanned_at, decision_actor, decision_reason "
          "FROM audit_entries WHERE status IN (1, 2, 5) ORDER BY scanned_at DESC;"
        : "SELECT file_path, blake3_hash, status, line_number, reason, scanned_at, decision_actor, decision_reason "
          "FROM audit_entries ORDER BY scanned_at DESC;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return results;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AuditIndexEntry e;
        const char* fp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        e.file_path = fp ? fp : "";
        const char* h = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        e.blake3_hash = h ? h : "";
        e.status = static_cast<core::AuditStatus>(sqlite3_column_int(stmt, 2));
        e.line_number = sqlite3_column_int(stmt, 3);
        const char* r = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        e.reason = r ? r : "";
        e.scanned_at = static_cast<uint64_t>(sqlite3_column_int64(stmt, 5));
        const char* da = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        e.decision_actor = da ? da : "";
        const char* dr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        e.decision_reason = dr ? dr : "";
        results.push_back(e);
    }
    sqlite3_finalize(stmt);
    return results;
}

size_t StatefulAuditIndex::clear_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) {
        init_sqlite();
    }
    if (!db_) return 0;

    int total_before = 0;
    sqlite3_stmt* count_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM audit_entries;", -1, &count_stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(count_stmt) == SQLITE_ROW) {
            total_before = sqlite3_column_int(count_stmt, 0);
        }
        sqlite3_finalize(count_stmt);
    }

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, "BEGIN TRANSACTION; DELETE FROM audit_entries; COMMIT;", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        if (err_msg) {
            sqlite3_free(err_msg);
        }
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        return 0;
    }
    sqlite3_wal_checkpoint_v2(db_, nullptr, SQLITE_CHECKPOINT_PASSIVE, nullptr, nullptr);
    return static_cast<size_t>(total_before);
}

StatefulAuditIndex::QueryResult StatefulAuditIndex::query_entries(
    const std::string& status_filter,
    const std::string& detector_filter,
    const std::string& ext_filter,
    const std::string& search_text,
    size_t limit,
    size_t offset
) const {
    std::lock_guard<std::mutex> lock(mutex_);
    QueryResult result;
    if (!db_) return result;

    // Total count of all rows in DB
    sqlite3_stmt* total_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM audit_entries;", -1, &total_stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(total_stmt) == SQLITE_ROW) {
            result.total_count = static_cast<size_t>(sqlite3_column_int(total_stmt, 0));
        }
        sqlite3_finalize(total_stmt);
    }

    std::vector<std::string> conditions;
    std::vector<std::string> bind_strings;

    // Status filter: all | quarantined | allowed | clean | rule
    if (status_filter == "quarantined") {
        conditions.push_back("status IN (1, 2, 5)");
    } else if (status_filter == "allowed") {
        conditions.push_back("status IN (3, 4)");
    } else if (status_filter == "clean") {
        conditions.push_back("status = 0");
    } else if (status_filter == "rule") {
        conditions.push_back("status = 5");
    }

    // Detector filter: all | ai | regex | entropy | rule
    if (detector_filter == "ai") {
        conditions.push_back("(status = 1 OR reason LIKE '%AI%' OR reason LIKE '%Model%')");
    } else if (detector_filter == "regex") {
        conditions.push_back("(status = 2 AND (reason LIKE '%Regex%' OR reason LIKE '%Secret%' OR reason LIKE '%Pattern%'))");
    } else if (detector_filter == "entropy") {
        conditions.push_back("(status = 2 AND reason LIKE '%Entropy%')");
    } else if (detector_filter == "rule") {
        conditions.push_back("(status = 5 OR reason LIKE '%Rule%')");
    }

    // Extension / File Type filter: all | config | code | binary
    if (ext_filter == "config") {
        conditions.push_back("(file_path LIKE '%.env%' OR file_path LIKE '%.key' OR file_path LIKE '%.pem' OR file_path LIKE '%.json' OR file_path LIKE '%.yaml' OR file_path LIKE '%.yml' OR file_path LIKE '%.toml' OR file_path LIKE '%.conf')");
    } else if (ext_filter == "code") {
        conditions.push_back("(file_path LIKE '%.py' OR file_path LIKE '%.cpp' OR file_path LIKE '%.h' OR file_path LIKE '%.hpp' OR file_path LIKE '%.c' OR file_path LIKE '%.js' OR file_path LIKE '%.ts' OR file_path LIKE '%.go' OR file_path LIKE '%.rs')");
    } else if (ext_filter == "binary") {
        conditions.push_back("(file_path LIKE '%.pyd' OR file_path LIKE '%.dll' OR file_path LIKE '%.so' OR file_path LIKE '%.exe' OR file_path LIKE '%.bin' OR file_path LIKE '%.pak')");
    }

    // Search text filter
    if (!search_text.empty()) {
        conditions.push_back("(file_path LIKE ? OR reason LIKE ?)");
        bind_strings.push_back("%" + search_text + "%");
        bind_strings.push_back("%" + search_text + "%");
    }

    std::string where_clause = "";
    if (!conditions.empty()) {
        where_clause = " WHERE ";
        for (size_t i = 0; i < conditions.size(); ++i) {
            if (i > 0) where_clause += " AND ";
            where_clause += conditions[i];
        }
    }

    // Filtered count
    std::string count_sql = "SELECT COUNT(*) FROM audit_entries" + where_clause + ";";
    sqlite3_stmt* fcount_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, count_sql.c_str(), -1, &fcount_stmt, nullptr) == SQLITE_OK) {
        for (size_t i = 0; i < bind_strings.size(); ++i) {
            sqlite3_bind_text(fcount_stmt, static_cast<int>(i + 1), bind_strings[i].c_str(), -1, SQLITE_TRANSIENT);
        }
        if (sqlite3_step(fcount_stmt) == SQLITE_ROW) {
            result.filtered_count = static_cast<size_t>(sqlite3_column_int(fcount_stmt, 0));
        }
        sqlite3_finalize(fcount_stmt);
    }

    // Query rows with LIMIT and OFFSET
    size_t q_limit = (limit == 0 || limit > 1000) ? 100 : limit;
    std::string query_sql = "SELECT file_path, blake3_hash, status, line_number, reason, scanned_at, decision_actor, decision_reason "
                            "FROM audit_entries" + where_clause + " ORDER BY scanned_at DESC LIMIT " + std::to_string(q_limit) +
                            " OFFSET " + std::to_string(offset) + ";";

    sqlite3_stmt* q_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, query_sql.c_str(), -1, &q_stmt, nullptr) == SQLITE_OK) {
        for (size_t i = 0; i < bind_strings.size(); ++i) {
            sqlite3_bind_text(q_stmt, static_cast<int>(i + 1), bind_strings[i].c_str(), -1, SQLITE_TRANSIENT);
        }
        while (sqlite3_step(q_stmt) == SQLITE_ROW) {
            AuditIndexEntry e;
            const char* fp = reinterpret_cast<const char*>(sqlite3_column_text(q_stmt, 0));
            e.file_path = fp ? fp : "";
            const char* h = reinterpret_cast<const char*>(sqlite3_column_text(q_stmt, 1));
            e.blake3_hash = h ? h : "";
            e.status = static_cast<core::AuditStatus>(sqlite3_column_int(q_stmt, 2));
            e.line_number = sqlite3_column_int(q_stmt, 3);
            const char* r = reinterpret_cast<const char*>(sqlite3_column_text(q_stmt, 4));
            e.reason = r ? r : "";
            e.scanned_at = static_cast<uint64_t>(sqlite3_column_int64(q_stmt, 5));
            const char* da = reinterpret_cast<const char*>(sqlite3_column_text(q_stmt, 6));
            e.decision_actor = da ? da : "";
            const char* dr = reinterpret_cast<const char*>(sqlite3_column_text(q_stmt, 7));
            e.decision_reason = dr ? dr : "";
            result.entries.push_back(e);
        }
        sqlite3_finalize(q_stmt);
    }

    return result;
}

} // namespace slug::ai
