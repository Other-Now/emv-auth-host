// The issuer authorization engine: one ISO 8583 request in, one response out,
// with every state change made inside the caller's SQLite transaction.
#pragma once

#include "db.h"
#include "emv_crypto.h"
#include "iso8583.h"

#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

namespace eah {

struct HostConfig {
    Key16 imk{};                     // issuer master key for ARQCs (an HSM in real life)
    std::vector<uint8_t> token_key;  // PAN tokenization key
    std::string today_yymm;          // for expiry checks; fixed in tests
    FILE* log = nullptr;             // one line per message, PAN masked
};

struct HostStats {
    uint64_t approved = 0, declined = 0, duplicates = 0, format_errors = 0, reversals = 0, echoes = 0,
             system_errors = 0;
};

enum class Sync { Off, Normal, Full };

void apply_schema(Db& db, Sync sync);
void seed_cards(Db& db, const HostConfig& cfg, int ncards, int64_t balance_minor, int64_t limit_minor);
HostConfig default_config();  // test keys from env or built-in defaults

class AuthHost {
  public:
    AuthHost(Db& db, HostConfig cfg);

    void begin();
    void commit();
    void rollback();

    // Call between begin() and commit(). Each request runs in its own
    // savepoint, so one request's failure cannot take others in the same
    // batch with it. An empty result means "close the connection".
    std::vector<uint8_t> process(std::span<const uint8_t> request);

    const HostStats& stats() const { return stats_; }

  private:
    std::vector<uint8_t> dispatch(std::span<const uint8_t> request);
    std::vector<uint8_t> financial(const iso_msg& m, std::span<const uint8_t> request);
    std::vector<uint8_t> reversal(const iso_msg& m, std::span<const uint8_t> request);
    void log_line(const std::string& s);

    Db& db_;
    HostConfig cfg_;
    HostStats stats_;
    Stmt begin_, commit_, rollback_, savepoint_, release_, rollback_to_;
    Stmt auth_by_key_, next_auth_id_, card_by_token_, update_atc_, debit_, credit_, insert_auth_, mark_reversed_;
    Stmt reversal_by_key_, insert_reversal_;
};

}  // namespace eah
