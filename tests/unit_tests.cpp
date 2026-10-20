// Unit tests: codec, TLV, crypto, PAN rules, and the engine against an
// in-memory database.
#include "auth.h"
#include "msg.h"
#include "pan.h"
#include "simcard.h"
#include "tlv.h"

#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

using namespace eah;

static int g_checks = 0, g_failed = 0;
#define CHECK(cond)                                                              \
    do {                                                                         \
        g_checks++;                                                              \
        if (!(cond)) {                                                           \
            g_failed++;                                                          \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
        }                                                                        \
    } while (0)

static std::vector<std::pair<const char*, std::function<void()>>>& registry() {
    static std::vector<std::pair<const char*, std::function<void()>>> r;
    return r;
}
struct Reg {
    Reg(const char* n, std::function<void()> f) { registry().emplace_back(n, std::move(f)); }
};
#define TEST(name)                         \
    static void name();                    \
    static Reg reg_##name(#name, name);    \
    static void name()

static std::vector<uint8_t> bytes(const char* s) { return {s, s + std::strlen(s)}; }

// ------------------------------------------------------------- PAN

TEST(luhn) {
    CHECK(luhn_valid("4111111111111111"));
    CHECK(!luhn_valid("4111111111111112"));
    CHECK(!luhn_valid("41111111111a1111"));
    CHECK(!luhn_valid("41111"));
    CHECK(luhn_check_digit("411111111111111") == '1');
    for (int i = 0; i < 1000; i++) CHECK(luhn_valid(sim_pan(i)));
}

TEST(pan_mask_and_token) {
    CHECK(mask_pan("4761730000000001") == "476173******0001");
    CHECK(mask_pan("4761730000000000123") == "476173*********0123");
    std::vector<uint8_t> k(32, 7);
    CHECK(pan_token(k, "4111111111111111") != pan_token(k, "4111111111111112"));
    std::vector<uint8_t> k2(32, 8);
    CHECK(pan_token(k, "4111111111111111") != pan_token(k2, "4111111111111111"));
}

// ------------------------------------------------------------- ISO 8583

TEST(iso_roundtrip) {
    auto b = build_0200(default_config().imk, SimTxn{});
    iso_msg m;
    int bad;
    CHECK(iso_decode(b.data(), b.size(), &m, &bad) == ISO_OK);
    CHECK(std::string(m.mti) == "0200");
    CHECK(field(m, 2) == sim_pan(0));
    CHECK(field(m, 4) == "000000001000");
    std::vector<uint8_t> again(ISO_MAX_MSG);
    size_t n = 0;
    CHECK(iso_encode(&m, again.data(), again.size(), &n) == ISO_OK);
    again.resize(n);
    CHECK(again == b);
}

TEST(iso_secondary_bitmap) {
    SimTxn t;
    auto b = build_0400(t, "000009", "1020120000");
    CHECK(b[4] & 0x80);  // bit 1: secondary bitmap present for DE90
    iso_msg m;
    int bad;
    CHECK(iso_decode(b.data(), b.size(), &m, &bad) == ISO_OK);
    CHECK(field(m, 90).substr(0, 10) == "0200000001");
}

TEST(iso_decode_errors) {
    auto good = build_0800("000001", "1020120000");
    iso_msg m;
    int bad;
    CHECK(iso_decode(good.data(), 3, &m, &bad) == ISO_E_SHORT);
    auto x = good;
    x[0] = 'X';
    CHECK(iso_decode(x.data(), x.size(), &m, &bad) == ISO_E_MTI);
    CHECK(iso_decode(good.data(), good.size() - 1, &m, &bad) == ISO_E_SHORT);
    x = good;
    x.push_back('0');
    CHECK(iso_decode(x.data(), x.size(), &m, &bad) == ISO_E_TRAILING);
    x = good;
    x[4] |= 0x08;  // bit 5
    CHECK(iso_decode(x.data(), x.size(), &m, &bad) == ISO_E_UNSUPPORTED_FIELD && bad == 5);
    // Secondary bitmap flagged but empty.
    std::vector<uint8_t> e = bytes("0800");
    uint8_t bm[16] = {0x80};
    e.insert(e.end(), bm, bm + 16);
    CHECK(iso_decode(e.data(), e.size(), &m, &bad) == ISO_E_SECONDARY);
    // Non-digit in a numeric field (DE7 is the first field after the bitmaps).
    x = good;
    x[20] = 'A';
    CHECK(iso_decode(x.data(), x.size(), &m, &bad) == ISO_E_CHARSET && bad == 7);
}

TEST(iso_llvar_limits) {
    iso_msg m;
    iso_init(&m, "0200");
    CHECK(iso_set(&m, 2, "12345678901234567890", 20) == ISO_E_LENGTH);  // PAN max 19
    CHECK(iso_set(&m, 2, "4111111111111111", 16) == ISO_OK);
    CHECK(iso_set(&m, 4, "123", 3) == ISO_E_LENGTH);                    // fixed n12
    CHECK(iso_set(&m, 41, "T\x01" "000001", 8) == ISO_E_CHARSET);
    // LL prefix that is not digits.
    std::vector<uint8_t> b = bytes("0200");
    uint8_t bm[8] = {0x40};  // bit 2 only
    b.insert(b.end(), bm, bm + 8);
    auto tail = bytes("1X4111111111111111");
    b.insert(b.end(), tail.begin(), tail.end());
    int bad;
    CHECK(iso_decode(b.data(), b.size(), &m, &bad) == ISO_E_LENGTH);
    // LL prefix over the maximum.
    b.resize(12);
    tail = bytes("2041111111111111111111");
    b.insert(b.end(), tail.begin(), tail.end());
    CHECK(iso_decode(b.data(), b.size(), &m, &bad) == ISO_E_LENGTH);
}

// ------------------------------------------------------------- TLV

TEST(tlv_parse_forms) {
    const uint8_t d[] = {0x9F, 0x26, 0x02, 0xAA, 0xBB,  // 2-byte tag
                         0x00, 0x00,                    // filler
                         0x95, 0x81, 0x01, 0xCC,        // long-form length
                         0x5F, 0x2A, 0x00};             // empty value
    tlv_item it[8];
    size_t n = 0;
    CHECK(tlv_parse(d, sizeof d, it, 8, &n) == TLV_OK);
    CHECK(n == 3);
    CHECK(it[0].tag == 0x9F26 && it[0].len == 2 && it[0].val[1] == 0xBB);
    CHECK(it[1].tag == 0x95 && it[1].len == 1 && it[1].val[0] == 0xCC);
    CHECK(tlv_find(it, n, 0x5F2A)->len == 0);
    CHECK(tlv_find(it, n, 0x9F37) == nullptr);
}

TEST(tlv_errors) {
    tlv_item it[2];
    size_t n;
    const uint8_t trunc_val[] = {0x95, 0x05, 0x00};
    CHECK(tlv_parse(trunc_val, sizeof trunc_val, it, 2, &n) == TLV_E_TRUNC);
    const uint8_t trunc_tag[] = {0x9F};
    CHECK(tlv_parse(trunc_tag, sizeof trunc_tag, it, 2, &n) == TLV_E_TRUNC);
    const uint8_t long_tag[] = {0x9F, 0x81, 0x81, 0x81, 0x01, 0x00};
    CHECK(tlv_parse(long_tag, sizeof long_tag, it, 2, &n) == TLV_E_TAG);
    const uint8_t indefinite[] = {0x95, 0x80};
    CHECK(tlv_parse(indefinite, sizeof indefinite, it, 2, &n) == TLV_E_LEN);
    const uint8_t dup[] = {0x95, 0x01, 0x01, 0x95, 0x01, 0x02};
    CHECK(tlv_parse(dup, sizeof dup, it, 2, &n) == TLV_E_DUP);
    const uint8_t three[] = {0x95, 0x00, 0x9C, 0x00, 0x82, 0x00};
    CHECK(tlv_parse(three, sizeof three, it, 2, &n) == TLV_E_TOOMANY);
}

TEST(tlv_put_roundtrip) {
    uint8_t v[200], out[256];
    for (int i = 0; i < 200; i++) v[i] = static_cast<uint8_t>(i);
    size_t n = tlv_put(out, sizeof out, 0x9F10, v, 200);
    CHECK(n == 2 + 2 + 200);
    CHECK(out[2] == 0x81 && out[3] == 200);
    tlv_item it[1];
    size_t cnt;
    CHECK(tlv_parse(out, n, it, 1, &cnt) == TLV_OK && it[0].len == 200 && it[0].val[199] == 199);
    CHECK(tlv_put(out, 10, 0x9F10, v, 200) == 0);
}

// ------------------------------------------------------------- crypto

TEST(des_known_answer) {
    // The classic worked DES example (Grabbe): K=133457799BBCDFF1, P=0123456789ABCDEF.
    uint8_t k[8];
    Block p, c;
    from_hex("133457799BBCDFF1", k, 8);
    from_hex("0123456789ABCDEF", p.data(), 8);
    from_hex("85E813540F0AB405", c.data(), 8);
    CHECK(des_encrypt(k, p) == c);
    CHECK(des_decrypt(k, c) == p);
}

TEST(arqc_and_arpc_properties) {
    Key16 imk = default_config().imk;
    Key16 mk = derive_icc_master_key(imk, "4761730000000001", "01");
    CHECK(mk != derive_icc_master_key(imk, "4761730000000001", "02"));  // PSN matters
    Key16 s1 = derive_session_key(mk, 1), s2 = derive_session_key(mk, 2);
    CHECK(s1 != s2);  // every transaction gets its own key
    std::vector<uint8_t> data(33, 0x11);
    Block a = retail_mac(s1, data);
    data[32] ^= 1;
    CHECK(retail_mac(s1, data) != a);
    // Padding method 2 always pads, so data that already ends in 0x80 cannot
    // collide with the padded form of the shorter message.
    std::vector<uint8_t> d7(7, 0), d7pad(7, 0);
    d7pad.push_back(0x80);
    CHECK(retail_mac(s1, d7) != retail_mac(s1, d7pad));
    Block p1 = compute_arpc(s1, a, {'0', '0'}), p2 = compute_arpc(s1, a, {'5', '1'});
    CHECK(p1 != p2);
    // >16-digit PAN: only the rightmost 16 digits of PAN||PSN are used.
    CHECK(derive_icc_master_key(imk, "1234567890123456789", "01") ==
          derive_icc_master_key(imk, "9994567890123456789", "01"));
}

// ------------------------------------------------------------- engine

struct Fixture {
    Db db{":memory:"};
    HostConfig cfg;
    std::unique_ptr<AuthHost> host;
    Fixture() {
        cfg = default_config();
        cfg.today_yymm = "2610";
        apply_schema(db, Sync::Off);
        seed_cards(db, cfg, 4, 100000, 50000);
        host = std::make_unique<AuthHost>(db, cfg);
    }
    std::vector<uint8_t> send(const std::vector<uint8_t>& req) {
        host->begin();
        auto r = host->process(req);
        host->commit();
        return r;
    }
    std::string rc(const std::vector<uint8_t>& resp) {
        iso_msg m;
        int bad;
        if (iso_decode(resp.data(), resp.size(), &m, &bad) != ISO_OK) return "??";
        return std::string(field(m, 39));
    }
    int64_t balance(int account) {
        Stmt s = db.prepare("SELECT available_minor FROM accounts WHERE account_id = ?1");
        s.bind(1, account);
        s.step();
        return s.i64(0);
    }
};

TEST(engine_approve_dup_replay) {
    Fixture f;
    SimTxn t;
    auto req = build_0200(f.cfg.imk, t);
    auto r1 = f.send(req);
    CHECK(f.rc(r1) == "00");
    CHECK(f.balance(1) == 99000);
    auto r2 = f.send(req);
    CHECK(r2 == r1);  // byte-identical replay
    CHECK(f.balance(1) == 99000);
    CHECK(f.host->stats().duplicates == 1);
}

TEST(engine_atc_replay_and_bad_arqc) {
    Fixture f;
    SimTxn t;
    CHECK(f.rc(f.send(build_0200(f.cfg.imk, t))) == "00");
    t.stan = "000002";
    CHECK(f.rc(f.send(build_0200(f.cfg.imk, t))) == "82");  // same ATC, new key
    t.stan = "000003";
    t.atc = 5;
    t.corrupt_arqc = true;
    CHECK(f.rc(f.send(build_0200(f.cfg.imk, t))) == "82");
    // The bad ARQC must not have advanced the stored ATC.
    t.stan = "000004";
    t.corrupt_arqc = false;
    CHECK(f.rc(f.send(build_0200(f.cfg.imk, t))) == "00");
    CHECK(f.balance(1) == 98000);
}

TEST(engine_reversal_idempotent) {
    Fixture f;
    SimTxn t;
    t.amount = 2500;
    CHECK(f.rc(f.send(build_0200(f.cfg.imk, t))) == "00");
    CHECK(f.balance(1) == 97500);
    auto rev = build_0400(t, "000050", "1020120100");
    auto r1 = f.send(rev);
    CHECK(f.rc(r1) == "00");
    CHECK(f.balance(1) == 100000);
    CHECK(f.send(rev) == r1);
    CHECK(f.rc(f.send(build_0400(t, "000051", "1020120200"))) == "00");
    CHECK(f.balance(1) == 100000);  // no double credit
    SimTxn ghost = t;
    ghost.stan = "123456";
    CHECK(f.rc(f.send(build_0400(ghost, "000052", "1020120300"))) == "25");
}

TEST(engine_funds_and_limits) {
    Fixture f;
    SimTxn t;
    t.card = 1;
    t.amount = 60000;
    CHECK(f.rc(f.send(build_0200(f.cfg.imk, t))) == "61");
    // Boundary: limit + 1 declines, exactly the limit approves (mutation
    // testing showed nothing pinned this down).
    t.amount = 50001;
    t.stan = "000005";
    t.atc = 2;
    CHECK(f.rc(f.send(build_0200(f.cfg.imk, t))) == "61");
    t.amount = 50000;
    t.stan = "000002";
    t.atc = 3;
    CHECK(f.rc(f.send(build_0200(f.cfg.imk, t))) == "00");
    t.stan = "000003";
    t.atc = 4;
    CHECK(f.rc(f.send(build_0200(f.cfg.imk, t))) == "00");
    t.stan = "000004";
    t.atc = 5;
    t.amount = 1;
    CHECK(f.rc(f.send(build_0200(f.cfg.imk, t))) == "51");
    CHECK(f.balance(2) == 0);
}

TEST(engine_never_answers_a_response) {
    Fixture f;
    auto b = build_0800("000001", "1020120000");
    b[2] = '1';  // 0810
    CHECK(f.send(b).empty());
    std::vector<uint8_t> junk = bytes("HELLO WORLD!!");
    CHECK(f.send(junk).empty());
}

TEST(engine_no_pan_in_db) {
    Fixture f;
    SimTxn t;
    f.send(build_0200(f.cfg.imk, t));
    // Look for the PAN in every text and blob column of every table.
    const std::string pan = sim_pan(0);
    for (const char* q : {"SELECT quote(response) || quote(pan_token) || quote(pan_last4) FROM authorizations",
                          "SELECT quote(pan_token) || pan_last4 FROM cards"}) {
        Stmt s = f.db.prepare(q);
        while (s.step()) {
            std::string row = s.text(0);
            CHECK(row.find(pan) == std::string::npos);
            CHECK(row.find(to_hex({reinterpret_cast<const uint8_t*>(pan.data()), pan.size()})) == std::string::npos);
        }
    }
}

int main() {
    for (auto& [name, fn] : registry()) {
        int before = g_failed;
        fn();
        std::printf("%s %s\n", g_failed == before ? "ok  " : "FAIL", name);
    }
    std::printf("%d tests, %d checks, %d failed\n", static_cast<int>(registry().size()), g_checks, g_failed);
    return g_failed ? 1 : 0;
}
