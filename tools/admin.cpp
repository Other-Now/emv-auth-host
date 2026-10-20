// eah-admin: create/seed the database, edit cards, reconcile, emit test vectors.
#include "auth.h"
#include "pan.h"
#include "msg.h"
#include "simcard.h"

#include <chrono>
#include <format>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <string>

using namespace eah;

namespace {

std::map<std::string, std::string> flags(int argc, char** argv, int from) {
    std::map<std::string, std::string> f;
    for (int i = from; i < argc; i++) {
        std::string a = argv[i];
        if (a.rfind("--", 0) == 0 && i + 1 < argc) f[a.substr(2)] += (f.count(a.substr(2)) ? "," : "") + std::string(argv[++i]);
    }
    return f;
}

std::string need(const std::map<std::string, std::string>& f, const std::string& k, const std::string& def = "") {
    auto it = f.find(k);
    if (it != f.end()) return it->second;
    if (!def.empty()) return def;
    throw std::invalid_argument("missing --" + k);
}

int cmd_init(const std::map<std::string, std::string>& f) {
    Db db(need(f, "db"));
    apply_schema(db, Sync::Full);
    int n = std::stoi(need(f, "cards", "0"));
    if (n > 0) seed_cards(db, default_config(), n, std::stoll(need(f, "balance", "100000")), std::stoll(need(f, "limit", "50000")));
    std::printf("initialised %s with %d cards\n", need(f, "db").c_str(), n);
    return 0;
}

int cmd_card(const std::map<std::string, std::string>& f) {
    Db db(need(f, "db"));
    HostConfig cfg = default_config();
    Digest tok = pan_token(cfg.token_key, sim_pan(std::stoi(need(f, "index"))));
    if (f.count("status")) {
        Stmt s = db.prepare("UPDATE cards SET status = ?2 WHERE pan_token = ?1");
        s.bind_blob(1, tok).bind(2, f.at("status"));
        s.step();
    }
    if (f.count("expiry")) {
        Stmt s = db.prepare("UPDATE cards SET expiry_yymm = ?2 WHERE pan_token = ?1");
        s.bind_blob(1, tok).bind(2, f.at("expiry"));
        s.step();
    }
    return db.changes() == 1 ? 0 : 1;
}

// Two checks. (1) The ledger: every account balance equals its opening
// balance minus live approvals. (2) The terminals' view: the set of
// transactions terminals believe approved equals the set the host holds as
// APPROVED. A difference is a phantom (merchant shipped goods, issuer has no
// debit) or an orphan (customer charged for a sale the merchant thinks failed).
int cmd_recon(const std::map<std::string, std::string>& f) {
    Db db(need(f, "db"));
    int bad = 0;
    {
        Stmt s = db.prepare("PRAGMA integrity_check");
        s.step();
        std::string r = s.text(0);
        std::printf("integrity_check: %s\n", r.c_str());
        if (r != "ok") bad++;
        s.reset();
    }
    int64_t accounts = 0, mismatched = 0;
    {
        Stmt s = db.prepare("SELECT account_id, expected_minor, actual_minor FROM recon");
        while (s.step()) {
            accounts++;
            if (s.i64(1) != s.i64(2)) {
                mismatched++;
                if (mismatched <= 5)
                    std::printf("  account %lld expected %lld actual %lld\n", (long long)s.i64(0), (long long)s.i64(1),
                                (long long)s.i64(2));
            }
        }
    }
    std::printf("balance recon: %lld accounts, %lld mismatched\n", (long long)accounts, (long long)mismatched);
    bad += mismatched > 0;

    {
        Stmt s = db.prepare("SELECT state, reason, COUNT(*) FROM authorizations GROUP BY state, reason ORDER BY state, reason");
        while (s.step()) std::printf("  %-9s %-28s %lld\n", s.text(0).c_str(), s.text(1).c_str(), (long long)s.i64(2));
        Stmt r = db.prepare("SELECT reason, COUNT(*) FROM reversals GROUP BY reason ORDER BY reason");
        while (r.step()) std::printf("  0400      %-28s %lld\n", r.text(0).c_str(), (long long)r.i64(1));
    }

    if (!f.count("ledger")) return bad ? 1 : 0;
    std::set<std::string> host_approved, term_approved;
    int64_t term_lines = 0;
    {
        Stmt s = db.prepare("SELECT terminal_id, stan, tx_datetime FROM authorizations WHERE state = 'APPROVED'");
        while (s.step()) host_approved.insert(s.text(0) + "|" + s.text(1) + "|" + s.text(2));
    }
    std::stringstream files(f.at("ledger"));
    std::string path;
    while (std::getline(files, path, ',')) {
        std::ifstream in(path);
        if (!in) throw std::runtime_error("cannot read " + path);
        std::string tid, stan, dt, amount, outcome;
        while (in >> tid >> stan >> dt >> amount >> outcome) {
            term_lines++;
            if (outcome == "APPROVED") term_approved.insert(tid + "|" + stan + "|" + dt);
        }
    }
    int64_t phantom = 0, orphan = 0;
    for (const auto& k : term_approved) phantom += !host_approved.count(k);
    for (const auto& k : host_approved) orphan += !term_approved.count(k);
    std::printf("terminal recon: %lld ledger lines, %zu terminal-approved, %zu host-approved, "
                "%lld phantom approvals, %lld orphan debits\n",
                (long long)term_lines, term_approved.size(), host_approved.size(), (long long)phantom, (long long)orphan);
    bad += (phantom + orphan) > 0;
    return bad ? 1 : 0;
}

// JSON lines for tools/crosscheck_arqc.py, which recomputes every value with
// an independent Python implementation.
int cmd_vectors(int n) {
    std::mt19937_64 rng(20261020);
    auto rnd = [&](uint8_t* p, size_t k) {
        for (size_t i = 0; i < k; i++) p[i] = static_cast<uint8_t>(rng());
    };
    for (int i = 0; i < n; i++) {
        Key16 imk;
        rnd(imk.data(), 16);
        std::string pan = sim_pan(static_cast<int>(rng() % 1000000));
        if (i % 3 == 1) pan = pan.substr(0, 13);  // short PAN: exercises the left zero-pad
        if (i % 3 == 2) pan += "123";             // 19-digit PAN: exercises the rightmost-16 cut
        char psn[3];
        std::snprintf(psn, sizeof psn, "%02d", static_cast<int>(rng() % 100));
        uint16_t atc = static_cast<uint16_t>(rng());
        std::vector<uint8_t> data(1 + rng() % 40);
        rnd(data.data(), data.size());
        std::array<uint8_t, 2> arc{'0', static_cast<uint8_t>('0' + rng() % 10)};
        Key16 mk = derive_icc_master_key(imk, pan, psn);
        Key16 sk = derive_session_key(mk, atc);
        Block arqc = retail_mac(sk, data);
        Block arpc = compute_arpc(sk, arqc, arc);
        std::printf("{\"imk\":\"%s\",\"pan\":\"%s\",\"psn\":\"%s\",\"atc\":%u,\"data\":\"%s\",\"arc\":\"%s\","
                    "\"mk\":\"%s\",\"sk\":\"%s\",\"arqc\":\"%s\",\"arpc\":\"%s\"}\n",
                    to_hex(imk).c_str(), pan.c_str(), psn, atc, to_hex(data).c_str(), to_hex(arc).c_str(),
                    to_hex(mk).c_str(), to_hex(sk).c_str(), to_hex(arqc).c_str(), to_hex(arpc).c_str());
    }
    return 0;
}

// Per-component CPU cost of one authorization, in process (no network).
int cmd_selfbench(int n) {
    using C = std::chrono::steady_clock;
    auto per = [&](const char* name, auto&& fn) {
        auto t0 = C::now();
        for (int i = 0; i < n; i++) fn(i);
        double us = std::chrono::duration<double, std::micro>(C::now() - t0).count() / n;
        std::printf("%-34s %8.2f us\n", name, us);
        return us;
    };
    HostConfig cfg = default_config();
    cfg.today_yymm = "2610";
    std::vector<uint8_t> data(33, 0x5A);
    volatile uint8_t sink = 0;
    per("ARQC verify (MK + SK + MAC)", [&](int i) {
        Key16 mk = derive_icc_master_key(cfg.imk, "4761730000000001", "01");
        Key16 sk = derive_session_key(mk, static_cast<uint16_t>(i));
        sink = sink ^ retail_mac(sk, data)[0];
    });
    per("ARPC", [&](int i) {
        Key16 sk{};
        sk[0] = static_cast<uint8_t>(i);
        sink = sink ^ compute_arpc(sk, Block{}, {'0', '0'})[0];
    });
    std::vector<uint8_t> req(180, 0x33);
    per("SHA-256 of request", [&](int) { sink = sink ^ sha256(req)[0]; });
    per("HMAC-SHA256 PAN token", [&](int) { sink = sink ^ pan_token(cfg.token_key, "4761730000000001")[0]; });

    std::vector<std::vector<uint8_t>> reqs;
    for (int i = 0; i < n; i++) {
        SimTxn t;
        t.card = i % 1000;
        t.atc = static_cast<uint16_t>(1 + i / 1000);
        t.stan = std::format("{:06d}", i % 1000000);
        t.dt = std::format("10{:08d}", i / 1000000);
        reqs.push_back(build_0200(cfg.imk, t));
    }
    for (Sync s : {Sync::Off, Sync::Full}) {
        std::string path = std::string("/tmp/eah-selfbench-") + (s == Sync::Off ? "off" : "full") + ".db";
        std::remove(path.c_str());
        std::remove((path + "-wal").c_str());
        Db db(path);
        apply_schema(db, s);
        seed_cards(db, cfg, 1000, 1000000000, 100000);
        AuthHost host(db, cfg);
        int approved = 0;
        // Batches of 32 as group commit would see at 32 connections.
        per(s == Sync::Off ? "engine 0200, sync=OFF, batch 32" : "engine 0200, sync=FULL, batch 32", [&](int i) {
            if (i % 32 == 0) host.begin();
            auto r = host.process(reqs[static_cast<size_t>(i)]);
            approved += r.size() > 0;
            if (i % 32 == 31 || i == n - 1) host.commit();
        });
        if (approved != n) std::printf("  (only %d responses)\n", approved);
    }
    (void)sink;
    return 0;
}

// Seed corpora for the fuzzers: valid messages of every type, and DE55 blobs.
int cmd_corpus(const std::string& dir) {
    Key16 imk = default_config().imk;
    auto write = [&](const std::string& path, const std::vector<uint8_t>& b) {
        std::ofstream(path, std::ios::binary).write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
    };
    int n = 0;
    for (int i = 0; i < 8; i++) {
        SimTxn t;
        t.card = i;
        t.atc = static_cast<uint16_t>(i + 1);
        t.amount = 100 * (i + 1);
        t.stan = std::format("{:06d}", i + 1);
        auto req = build_0200(imk, t);
        write(dir + "/iso/0200_" + std::to_string(i), req);
        write(dir + "/iso/0400_" + std::to_string(i), build_0400(t, std::format("{:06d}", i + 100), t.dt));
        iso_msg m;
        int bad;
        iso_decode(req.data(), req.size(), &m, &bad);
        auto icc = field_bytes(m, 55);
        write(dir + "/tlv/de55_" + std::to_string(i), {icc.begin(), icc.end()});
        n += 3;
    }
    write(dir + "/iso/0800", build_0800("000001", "1020120000"));
    std::printf("wrote %d seeds to %s\n", n + 1, dir.c_str());
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
                     "usage: eah-admin init --db F [--cards N --balance B --limit L]\n"
                     "       eah-admin card --db F --index I [--status ACTIVE|BLOCKED|LOST] [--expiry YYMM]\n"
                     "       eah-admin recon --db F [--ledger FILE]...\n"
                     "       eah-admin pans N | vectors N\n");
        return 2;
    }
    try {
        std::string cmd = argv[1];
        auto f = flags(argc, argv, 2);
        if (cmd == "init") return cmd_init(f);
        if (cmd == "card") return cmd_card(f);
        if (cmd == "recon") return cmd_recon(f);
        if (cmd == "pans") {
            for (int i = 0, n = std::stoi(argv[2]); i < n; i++) std::printf("%s\n", sim_pan(i).c_str());
            return 0;
        }
        if (cmd == "vectors") return cmd_vectors(std::stoi(argv[2]));
        if (cmd == "corpus") return cmd_corpus(argv[2]);
        if (cmd == "selfbench") return cmd_selfbench(std::stoi(argv[2]));
        std::fprintf(stderr, "unknown command %s\n", cmd.c_str());
        return 2;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "eah-admin: %s\n", e.what());
        return 1;
    }
}
