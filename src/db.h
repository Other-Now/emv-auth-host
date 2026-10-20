// Minimal RAII wrapper over the SQLite C API.
#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace eah {

struct DbError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

class Stmt {
  public:
    Stmt() = default;
    Stmt(sqlite3* db, std::string_view sql);
    ~Stmt();
    Stmt(Stmt&& o) noexcept : db_(o.db_), s_(o.s_) { o.s_ = nullptr; }
    Stmt& operator=(Stmt&& o) noexcept;
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    Stmt& bind(int i, int64_t v);
    Stmt& bind(int i, std::string_view v);
    Stmt& bind_blob(int i, std::span<const uint8_t> v);
    Stmt& bind_null(int i);
    bool step();  // true = row available; resets itself when done
    void reset();
    int64_t i64(int col) const { return sqlite3_column_int64(s_, col); }
    bool is_null(int col) const { return sqlite3_column_type(s_, col) == SQLITE_NULL; }
    std::string text(int col) const;
    std::vector<uint8_t> blob(int col) const;

  private:
    sqlite3* db_ = nullptr;
    sqlite3_stmt* s_ = nullptr;
};

class Db {
  public:
    explicit Db(const std::string& path);
    ~Db();
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;
    void exec(std::string_view sql);
    Stmt prepare(std::string_view sql) { return Stmt(h_, sql); }
    int64_t changes() const { return sqlite3_changes64(h_); }
    sqlite3* raw() { return h_; }

  private:
    sqlite3* h_ = nullptr;
};

// The DDL in sql/schema.sql, embedded at build time.
extern const char* const kSchemaSql;

}  // namespace eah
