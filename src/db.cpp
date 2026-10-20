#include "db.h"

namespace eah {

static void check(sqlite3* db, int rc, const char* what) {
    if (rc != SQLITE_OK && rc != SQLITE_ROW && rc != SQLITE_DONE)
        throw DbError(std::string(what) + ": " + sqlite3_errmsg(db));
}

Stmt::Stmt(sqlite3* db, std::string_view sql) : db_(db) {
    check(db, sqlite3_prepare_v2(db, sql.data(), static_cast<int>(sql.size()), &s_, nullptr), "prepare");
}

Stmt::~Stmt() { sqlite3_finalize(s_); }

Stmt& Stmt::operator=(Stmt&& o) noexcept {
    if (this != &o) {
        sqlite3_finalize(s_);
        db_ = o.db_;
        s_ = o.s_;
        o.s_ = nullptr;
    }
    return *this;
}

Stmt& Stmt::bind(int i, int64_t v) {
    check(db_, sqlite3_bind_int64(s_, i, v), "bind");
    return *this;
}

Stmt& Stmt::bind(int i, std::string_view v) {
    check(db_, sqlite3_bind_text(s_, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT), "bind");
    return *this;
}

Stmt& Stmt::bind_blob(int i, std::span<const uint8_t> v) {
    check(db_, sqlite3_bind_blob(s_, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT), "bind");
    return *this;
}

Stmt& Stmt::bind_null(int i) {
    check(db_, sqlite3_bind_null(s_, i), "bind");
    return *this;
}

bool Stmt::step() {
    int rc = sqlite3_step(s_);
    if (rc == SQLITE_ROW) return true;
    sqlite3_reset(s_);
    check(db_, rc, "step");
    return false;
}

void Stmt::reset() {
    sqlite3_reset(s_);
    sqlite3_clear_bindings(s_);
}

std::string Stmt::text(int col) const {
    auto p = sqlite3_column_text(s_, col);
    return p ? std::string(reinterpret_cast<const char*>(p), sqlite3_column_bytes(s_, col)) : std::string();
}

std::vector<uint8_t> Stmt::blob(int col) const {
    auto p = static_cast<const uint8_t*>(sqlite3_column_blob(s_, col));
    return p ? std::vector<uint8_t>(p, p + sqlite3_column_bytes(s_, col)) : std::vector<uint8_t>();
}

Db::Db(const std::string& path) {
    int rc = sqlite3_open_v2(path.c_str(), &h_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (rc != SQLITE_OK) {
        std::string msg = h_ ? sqlite3_errmsg(h_) : "out of memory";
        sqlite3_close(h_);
        throw DbError("open " + path + ": " + msg);
    }
    sqlite3_busy_timeout(h_, 5000);
    exec("PRAGMA foreign_keys = ON");
}

Db::~Db() { sqlite3_close(h_); }

void Db::exec(std::string_view sql) {
    char* err = nullptr;
    std::string s(sql);
    if (sqlite3_exec(h_, s.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown";
        sqlite3_free(err);
        throw DbError("exec: " + msg);
    }
}

}  // namespace eah
