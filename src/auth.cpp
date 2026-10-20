#include "auth.h"

#include "msg.h"
#include "pan.h"
#include "tlv.h"

#include <cstdlib>
#include <ctime>
#include <format>

namespace eah {

namespace {

// Test keys. Anything real comes from the environment (and, in production,
// from an HSM that never releases the IMK at all).
constexpr const char* kDefaultImk = "0123456789ABCDEFFEDCBA9876543210";
constexpr const char* kDefaultTokenKey = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";

// The data the ARQC is computed over: EMV Book 2's recommended minimum CDOL1
// set, in order. Real cards add the CVR from 9F10; this host does not.
struct IccTag {
    uint32_t tag;
    uint16_t len;
};
constexpr IccTag kArqcData[] = {
    {0x9F02, 6}, {0x9F03, 6}, {0x9F1A, 2}, {0x95, 5},   {0x5F2A, 2},
    {0x9A, 3},   {0x9C, 1},   {0x9F37, 4}, {0x82, 2},   {0x9F36, 2},
};

std::string today_yymm() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    return std::format("{:02d}{:02d}", tm.tm_year % 100, tm.tm_mon + 1);
}

int64_t parse_amount(std::string_view s) {
    int64_t v = 0;
    for (char c : s) v = v * 10 + (c - '0');  // DE4 is validated as 12 digits
    return v;
}

}  // namespace

HostConfig default_config() {
    HostConfig c;
    const char* imk = std::getenv("EAH_IMK_HEX");
    const char* tk = std::getenv("EAH_TOKEN_KEY_HEX");
    if (!from_hex(imk ? imk : kDefaultImk, c.imk.data(), 16)) throw std::invalid_argument("EAH_IMK_HEX");
    std::string_view tks = tk ? tk : kDefaultTokenKey;
    c.token_key.resize(tks.size() / 2);
    if (tks.size() < 32 || !from_hex(tks, c.token_key.data(), c.token_key.size()))
        throw std::invalid_argument("EAH_TOKEN_KEY_HEX");
    c.today_yymm = today_yymm();
    return c;
}

void apply_schema(Db& db, Sync sync) {
    db.exec("PRAGMA journal_mode = WAL");
    db.exec(sync == Sync::Full ? "PRAGMA synchronous = FULL"
            : sync == Sync::Normal ? "PRAGMA synchronous = NORMAL"
                                   : "PRAGMA synchronous = OFF");
    db.exec(kSchemaSql);
}

void seed_cards(Db& db, const HostConfig& cfg, int ncards, int64_t balance, int64_t limit) {
    db.exec("BEGIN IMMEDIATE");
    Stmt acct = db.prepare("INSERT INTO accounts(account_id, currency, opening_minor, available_minor) VALUES (?1, '826', ?2, ?2)");
    Stmt card = db.prepare(
        "INSERT INTO cards(pan_token, pan_last4, psn, expiry_yymm, status, account_id, per_txn_limit_minor) "
        "VALUES (?1, ?2, ?3, ?4, 'ACTIVE', ?5, ?6)");
    for (int i = 0; i < ncards; i++) {
        std::string pan = sim_pan(i);
        Digest tok = pan_token(cfg.token_key, pan);
        acct.bind(1, i + 1).bind(2, balance);
        acct.step();
        acct.reset();
        card.bind_blob(1, tok).bind(2, std::string_view(pan).substr(pan.size() - 4)).bind(3, kSimPsn)
            .bind(4, kSimExpiry).bind(5, i + 1).bind(6, limit);
        card.step();
        card.reset();
    }
    db.exec("COMMIT");
}

AuthHost::AuthHost(Db& db, HostConfig cfg) : db_(db), cfg_(std::move(cfg)) {
    begin_ = db.prepare("BEGIN IMMEDIATE");
    commit_ = db.prepare("COMMIT");
    rollback_ = db.prepare("ROLLBACK");
    savepoint_ = db.prepare("SAVEPOINT req");
    release_ = db.prepare("RELEASE req");
    rollback_to_ = db.prepare("ROLLBACK TO req");
    auth_by_key_ = db.prepare(
        "SELECT request_hash, response, auth_id, state, amount_minor, account_id FROM authorizations "
        "WHERE terminal_id = ?1 AND stan = ?2 AND tx_datetime = ?3");
    next_auth_id_ = db.prepare("SELECT COALESCE(MAX(auth_id), 0) + 1 FROM authorizations");
    card_by_token_ = db.prepare(
        "SELECT c.psn, c.expiry_yymm, c.status, c.account_id, c.last_atc, c.per_txn_limit_minor, a.currency "
        "FROM cards c JOIN accounts a ON a.account_id = c.account_id WHERE c.pan_token = ?1");
    update_atc_ = db.prepare("UPDATE cards SET last_atc = ?2 WHERE pan_token = ?1");
    debit_ = db.prepare(
        "UPDATE accounts SET available_minor = available_minor - ?1 WHERE account_id = ?2 AND available_minor >= ?1");
    credit_ = db.prepare("UPDATE accounts SET available_minor = available_minor + ?1 WHERE account_id = ?2");
    insert_auth_ = db.prepare(
        "INSERT INTO authorizations(auth_id, terminal_id, stan, tx_datetime, request_hash, pan_token, pan_last4, "
        "account_id, amount_minor, currency, atc, response_code, reason, auth_code, rrn, state, response) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)");
    mark_reversed_ = db.prepare("UPDATE authorizations SET state = 'REVERSED' WHERE auth_id = ?1 AND state = 'APPROVED'");
    reversal_by_key_ = db.prepare(
        "SELECT request_hash, response FROM reversals WHERE terminal_id = ?1 AND stan = ?2 AND tx_datetime = ?3");
    insert_reversal_ = db.prepare(
        "INSERT INTO reversals(terminal_id, stan, tx_datetime, request_hash, orig_auth_id, response_code, reason, "
        "response) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
}

void AuthHost::begin() { begin_.step(); }
void AuthHost::commit() { commit_.step(); }
void AuthHost::rollback() { rollback_.step(); }

void AuthHost::log_line(const std::string& s) {
    if (cfg_.log) std::fprintf(cfg_.log, "%s\n", s.c_str());
}

std::vector<uint8_t> AuthHost::process(std::span<const uint8_t> req) {
    savepoint_.step();
    try {
        auto r = dispatch(req);
        release_.step();
        return r;
    } catch (const std::exception& e) {
        rollback_to_.step();
        release_.step();
        stats_.system_errors++;
        log_line(std::string("system error: ") + e.what());
        iso_msg m;
        int bad;
        if (iso_decode(req.data(), req.size(), &m, &bad) != ISO_OK) return {};
        auto rm = response_mti(m.mti);
        if (!rm) return {};
        OutMsg r{*rm, {}};
        for (int n : {3, 4, 7, 11, 41, 49, 90})
            if (iso_has(&m, n)) r.f[n] = std::string(field(m, n));
        r.f[39] = "96";
        return r.encode();
    }
}

std::vector<uint8_t> AuthHost::dispatch(std::span<const uint8_t> req) {
    iso_msg m;
    int bad = 0;
    iso_status st = iso_decode(req.data(), req.size(), &m, &bad);
    if (st == ISO_E_MTI || req.size() < 4) return {};  // not ISO 8583 at all: drop the link
    auto rm = response_mti(std::string_view(reinterpret_cast<const char*>(req.data()), 4));
    if (!rm) return {};  // never answer a response, or two hosts can loop forever
    if (st != ISO_OK) {
        stats_.format_errors++;
        log_line(std::format("{} format error: {} (field {})", std::string_view(m.mti, 4), iso_strerror(st), bad));
        return OutMsg{*rm, {{39, "30"}}}.encode();
    }
    std::string_view mti(m.mti, 4);
    if (mti == "0200") return financial(m, req);
    if (mti == "0400") return reversal(m, req);
    if (mti == "0800") {
        stats_.echoes++;
        OutMsg r{"0810", {}};
        for (int n : {7, 11, 70})
            if (iso_has(&m, n)) r.f[n] = std::string(field(m, n));
        r.f[39] = iso_has(&m, 70) ? "00" : "30";
        return r.encode();
    }
    stats_.format_errors++;
    return OutMsg{*rm, {{39, "12"}}}.encode();  // valid ISO, but not a transaction we do
}

std::vector<uint8_t> AuthHost::financial(const iso_msg& m, std::span<const uint8_t> req) {
    OutMsg r{"0210", {}};
    for (int n : {3, 4, 7, 11, 41, 42, 49})
        if (iso_has(&m, n)) r.f[n] = std::string(field(m, n));
    for (int n : {2, 3, 4, 7, 11, 14, 41, 49, 55}) {
        if (!iso_has(&m, n)) {
            stats_.format_errors++;
            log_line(std::format("0200 missing DE{}", n));
            r.f[39] = "30";
            return r.encode();
        }
    }
    const std::string tid(field(m, 41)), stan(field(m, 11)), dt(field(m, 7));
    const Digest req_hash = sha256(req);

    // 1. Idempotency. A retransmission (same key, same bytes) gets the exact
    // response we sent the first time and changes nothing. This must run
    // before the ATC check, or every retransmit would look like a replay.
    auth_by_key_.bind(1, tid).bind(2, stan).bind(3, dt);
    if (auth_by_key_.step()) {
        auto stored_hash = auth_by_key_.blob(0);
        auto stored_resp = auth_by_key_.blob(1);
        auth_by_key_.reset();
        if (stored_hash.size() == 32 && ct_equal(stored_hash.data(), req_hash.data(), 32)) {
            stats_.duplicates++;
            log_line(std::format("0200 {}/{} duplicate -> replay", tid, stan));
            return stored_resp;
        }
        stats_.format_errors++;
        log_line(std::format("0200 {}/{} key reused with different content", tid, stan));
        r.f[39] = "94";  // duplicate transmission; nothing recorded
        return r.encode();
    }
    auth_by_key_.reset();

    const std::string pan(field(m, 2));
    const Digest tok = pan_token(cfg_.token_key, pan);
    const std::string last4 = pan.size() >= 4 ? pan.substr(pan.size() - 4) : pan;
    const int64_t amount = parse_amount(field(m, 4));
    const std::string currency(field(m, 49));

    next_auth_id_.step();
    const int64_t auth_id = next_auth_id_.i64(0);
    next_auth_id_.reset();
    r.f[37] = std::format("{:012d}", auth_id);

    int64_t account_id = -1, atc = -1;
    bool arqc_ok = false;
    Key16 sk{};
    Block arqc{};

    auto finish = [&](const char* rc, const char* reason) {
        const bool approved = std::string_view(rc) == "00";
        r.f[39] = rc;
        if (approved) r.f[38] = std::format("{:06d}", (auth_id * 7919) % 1000000);
        if (arqc_ok) {
            // Issuer Authentication Data (tag 91) = ARPC || ARC; the card checks it.
            std::array<uint8_t, 2> arc{static_cast<uint8_t>(rc[0]), static_cast<uint8_t>(rc[1])};
            Block arpc = compute_arpc(sk, arqc, arc);
            uint8_t iad[10], out[16];
            std::copy(arpc.begin(), arpc.end(), iad);
            iad[8] = arc[0];
            iad[9] = arc[1];
            size_t n = tlv_put(out, sizeof out, 0x91, iad, sizeof iad);
            r.f[55] = std::string(reinterpret_cast<char*>(out), n);
        }
        std::vector<uint8_t> resp = r.encode();
        insert_auth_.bind(1, auth_id).bind(2, tid).bind(3, stan).bind(4, dt).bind_blob(5, req_hash)
            .bind_blob(6, tok).bind(7, last4);
        if (account_id > 0) insert_auth_.bind(8, account_id); else insert_auth_.bind_null(8);
        insert_auth_.bind(9, amount).bind(10, currency);
        if (atc >= 0) insert_auth_.bind(11, atc); else insert_auth_.bind_null(11);
        insert_auth_.bind(12, rc).bind(13, reason);
        if (approved) insert_auth_.bind(14, r.f[38]); else insert_auth_.bind_null(14);
        insert_auth_.bind(15, r.f[37]).bind(16, approved ? "APPROVED" : "DECLINED").bind_blob(17, resp);
        insert_auth_.step();
        insert_auth_.reset();
        (approved ? stats_.approved : stats_.declined)++;
        log_line(std::format("0200 {}/{} {} amt={} rc={} {}", tid, stan, mask_pan(pan), amount, rc, reason));
        return resp;
    };

    if (field(m, 3) != "000000") return finish("12", "UNSUPPORTED_PROCESSING_CODE");
    if (amount == 0) return finish("13", "ZERO_AMOUNT");
    if (!luhn_valid(pan)) return finish("14", "LUHN_FAIL");

    card_by_token_.bind_blob(1, tok);
    if (!card_by_token_.step()) {
        card_by_token_.reset();
        return finish("14", "UNKNOWN_CARD");
    }
    const std::string card_psn = card_by_token_.text(0), expiry = card_by_token_.text(1),
                      status = card_by_token_.text(2), acct_currency = card_by_token_.text(6);
    account_id = card_by_token_.i64(3);
    const int64_t last_atc = card_by_token_.i64(4), limit = card_by_token_.i64(5);
    card_by_token_.reset();

    if (status == "LOST") return finish("41", "CARD_LOST");
    if (status != "ACTIVE") return finish("62", "CARD_BLOCKED");
    if (field(m, 14) != expiry) return finish("54", "EXPIRY_MISMATCH");
    if (expiry < cfg_.today_yymm) return finish("54", "CARD_EXPIRED");

    // 2. Cryptogram. Verify the ARQC first, then trust the ICC fields it covers.
    tlv_item items[32];
    size_t count = 0;
    if (tlv_parse(m.f[55].data, m.f[55].len, items, 32, &count) != TLV_OK) return finish("30", "BAD_ICC_TLV");
    std::vector<uint8_t> mac_input;
    for (const auto& need : kArqcData) {
        const tlv_item* it = tlv_find(items, count, need.tag);
        if (!it || it->len != need.len) return finish("30", "MISSING_ICC_TAG");
        mac_input.insert(mac_input.end(), it->val, it->val + it->len);
    }
    const tlv_item* t26 = tlv_find(items, count, 0x9F26);
    const tlv_item* t27 = tlv_find(items, count, 0x9F27);
    if (!t26 || t26->len != 8 || !t27 || t27->len != 1) return finish("30", "MISSING_ICC_TAG");
    if ((t27->val[0] & 0xC0) != 0x80) return finish("30", "CID_NOT_ARQC");  // card did not ask to go online

    const tlv_item* t36 = tlv_find(items, count, 0x9F36);
    atc = (t36->val[0] << 8) | t36->val[1];
    const std::string psn = iso_has(&m, 23) ? std::string(field(m, 23).substr(1)) : card_psn;
    const Key16 mk = derive_icc_master_key(cfg_.imk, pan, psn);
    sk = derive_session_key(mk, static_cast<uint16_t>(atc));
    std::copy(t26->val, t26->val + 8, arqc.begin());
    const Block expect = retail_mac(sk, mac_input);
    if (!ct_equal(expect.data(), arqc.data(), 8)) {
        atc = -1;  // unauthenticated: do not record the ATC as if the card sent it
        return finish("82", "ARQC_FAIL");
    }
    arqc_ok = true;

    // 3. Replay. A valid cryptogram with an ATC we have already seen is a
    // captured message being played back.
    if (atc <= last_atc) return finish("82", "ATC_REPLAY");
    update_atc_.bind_blob(1, tok).bind(2, atc);
    update_atc_.step();
    update_atc_.reset();

    // 4. The clear fields must agree with what the card signed.
    const tlv_item* t02 = tlv_find(items, count, 0x9F02);
    const tlv_item* t2a = tlv_find(items, count, 0x5F2A);
    if (to_hex({t02->val, 6}) != field(m, 4)) return finish("13", "AMOUNT_MISMATCH");
    if (to_hex({t2a->val, 2}) != "0" + currency) return finish("30", "CURRENCY_MISMATCH");
    if (currency != acct_currency) return finish("05", "CURRENCY_NOT_SUPPORTED");

    // 5. Money.
    if (amount > limit) return finish("61", "OVER_LIMIT");
    debit_.bind(1, amount).bind(2, account_id);
    debit_.step();
    debit_.reset();
    if (db_.changes() == 0) return finish("51", "INSUFFICIENT_FUNDS");
    return finish("00", "APPROVED");
}

std::vector<uint8_t> AuthHost::reversal(const iso_msg& m, std::span<const uint8_t> req) {
    OutMsg r{"0410", {}};
    for (int n : {3, 4, 7, 11, 41, 49, 90})
        if (iso_has(&m, n)) r.f[n] = std::string(field(m, n));
    for (int n : {4, 7, 11, 41, 90}) {
        if (!iso_has(&m, n)) {
            stats_.format_errors++;
            r.f[39] = "30";
            return r.encode();
        }
    }
    const std::string tid(field(m, 41)), stan(field(m, 11)), dt(field(m, 7));
    const Digest req_hash = sha256(req);

    reversal_by_key_.bind(1, tid).bind(2, stan).bind(3, dt);
    if (reversal_by_key_.step()) {
        auto stored_hash = reversal_by_key_.blob(0);
        auto stored_resp = reversal_by_key_.blob(1);
        reversal_by_key_.reset();
        if (ct_equal(stored_hash.data(), req_hash.data(), 32)) {
            stats_.duplicates++;
            return stored_resp;
        }
        r.f[39] = "94";
        return r.encode();
    }
    reversal_by_key_.reset();

    // DE90: original MTI(4) STAN(6) date/time(10) acquirer(11) forwarder(11).
    const std::string_view de90 = field(m, 90);
    const std::string orig_mti(de90.substr(0, 4)), orig_stan(de90.substr(4, 6)), orig_dt(de90.substr(10, 10));
    const int64_t amount = parse_amount(field(m, 4));

    int64_t orig_id = -1;
    const char* rc = "00";
    const char* reason;
    if (orig_mti != "0200") {
        rc = "12";
        reason = "ORIG_NOT_0200";
    } else {
        auth_by_key_.bind(1, tid).bind(2, orig_stan).bind(3, orig_dt);
        if (!auth_by_key_.step()) {
            // Never reached us (or never committed). Nothing to undo; the
            // acquirer gets a definitive answer and can stop retrying.
            rc = "25";
            reason = "ORIG_NOT_FOUND";
        } else {
            orig_id = auth_by_key_.i64(2);
            const std::string state = auth_by_key_.text(3);
            const int64_t orig_amount = auth_by_key_.i64(4);
            const int64_t account = auth_by_key_.is_null(5) ? -1 : auth_by_key_.i64(5);
            auth_by_key_.reset();
            if (amount != orig_amount) {
                rc = "13";
                reason = "PARTIAL_REVERSAL_UNSUPPORTED";
            } else if (state == "APPROVED") {
                mark_reversed_.bind(1, orig_id);
                mark_reversed_.step();
                mark_reversed_.reset();
                credit_.bind(1, amount).bind(2, account);
                credit_.step();
                credit_.reset();
                reason = "REVERSED";
            } else if (state == "REVERSED") {
                reason = "ALREADY_REVERSED";  // a second, different 0400 for the same original
            } else {
                reason = "ORIG_DECLINED";
            }
        }
        auth_by_key_.reset();
    }
    r.f[39] = rc;
    std::vector<uint8_t> resp = r.encode();
    insert_reversal_.bind(1, tid).bind(2, stan).bind(3, dt).bind_blob(4, req_hash);
    if (orig_id > 0) insert_reversal_.bind(5, orig_id); else insert_reversal_.bind_null(5);
    insert_reversal_.bind(6, rc).bind(7, reason).bind_blob(8, resp);
    insert_reversal_.step();
    insert_reversal_.reset();
    stats_.reversals++;
    log_line(std::format("0400 {}/{} orig={} amt={} rc={} {}", tid, stan, orig_stan, amount, rc, reason));
    return resp;
}

}  // namespace eah
