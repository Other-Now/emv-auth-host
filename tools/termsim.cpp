// termsim: terminal / acquirer simulator.
//   termsim golden --port N              scripted regression scenario, prints a transcript
//   termsim load   --port N --conns C --seconds S --cards K
//   termsim chaos  --port N --conns C --txns N --cards K --timeout-ms T --policy safe|naive --ledger FILE
#include "auth.h"
#include "msg.h"
#include "pan.h"
#include "simcard.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <format>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace eah;
using Clock = std::chrono::steady_clock;

namespace {

int64_t ms_since(Clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t).count();
}

class Link {
  public:
    explicit Link(int port) : port_(port) {}
    ~Link() { close(); }

    bool connect_once() {
        close();
        fd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(static_cast<uint16_t>(port_));
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (::connect(fd_, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0) {
            close();
            return false;
        }
        int one = 1;
        setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        return true;
    }

    // Retry until the host is back (it may be restarting after a kill -9).
    bool ensure(int give_up_ms = 60000) {
        if (fd_ >= 0) return true;
        auto t0 = Clock::now();
        while (ms_since(t0) < give_up_ms) {
            if (connect_once()) {
                reconnects_++;
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        return false;
    }

    bool send_raw(const uint8_t* p, size_t n) {
        while (n) {
            ssize_t k = ::send(fd_, p, n, MSG_NOSIGNAL);
            if (k <= 0) {
                if (k < 0 && errno == EINTR) continue;
                close();
                return false;
            }
            p += k;
            n -= static_cast<size_t>(k);
        }
        return true;
    }

    bool send(const std::vector<uint8_t>& payload) {
        if (fd_ < 0) return false;
        std::vector<uint8_t> f;
        frame_append(f, payload);
        return send_raw(f.data(), f.size());
    }

    // One frame, or nullopt on timeout / disconnect (closed() tells which).
    std::optional<std::vector<uint8_t>> recv(int timeout_ms) {
        auto t0 = Clock::now();
        for (;;) {
            std::vector<uint8_t> payload;
            bool bad = false;
            if (frame_pop(in_, payload, bad)) return payload;
            if (bad || fd_ < 0) {
                close();
                return std::nullopt;
            }
            int left = timeout_ms - static_cast<int>(ms_since(t0));
            if (left <= 0) return std::nullopt;
            pollfd p{fd_, POLLIN, 0};
            int r = poll(&p, 1, left);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) return std::nullopt;
            uint8_t buf[8192];
            ssize_t n = ::recv(fd_, buf, sizeof buf, 0);
            if (n <= 0) {
                close();
                return std::nullopt;
            }
            in_.insert(in_.end(), buf, buf + n);
        }
    }

    void close() {
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
        in_.clear();
    }
    bool closed() const { return fd_ < 0; }
    uint64_t reconnects() const { return reconnects_; }

  private:
    int port_;
    int fd_ = -1;
    std::vector<uint8_t> in_;
    uint64_t reconnects_ = 0;
};

std::string field_of(const std::vector<uint8_t>& msg, int n) {
    iso_msg m;
    int bad;
    if (iso_decode(msg.data(), msg.size(), &m, &bad) != ISO_OK) return {};
    return std::string(field(m, n));
}

std::string mti_of(const std::vector<uint8_t>& msg) {
    return msg.size() >= 4 ? std::string(msg.begin(), msg.begin() + 4) : std::string();
}

std::map<std::string, std::string> parse_flags(int argc, char** argv) {
    std::map<std::string, std::string> f;
    for (int i = 2; i + 1 < argc; i += 2) f[std::string(argv[i]).substr(2)] = argv[i + 1];
    return f;
}

std::string get(const std::map<std::string, std::string>& f, const char* k, const char* def) {
    auto it = f.find(k);
    return it == f.end() ? def : it->second;
}

std::string now_de7() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    return std::format("{:02d}{:02d}{:02d}{:02d}{:02d}", tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

// ---------------------------------------------------------------- golden

struct Golden {
    Link link;
    Key16 imk;
    int stan = 100;

    explicit Golden(int port) : link(port), imk(default_config().imk) {}

    std::string next_stan() { return std::format("{:06d}", ++stan); }

    void exchange(const char* name, const std::vector<uint8_t>& req) {
        std::printf("## %s\n> %s\n", name, describe(req).c_str());
        link.ensure();
        link.send(req);
        auto r = link.recv(3000);
        std::printf("< %s\n", r ? describe(*r).c_str() : link.closed() ? "<connection closed>" : "<timeout>");
    }

    SimTxn txn(int card, uint16_t atc, int64_t amount) {
        SimTxn t;
        t.card = card;
        t.atc = atc;
        t.amount = amount;
        t.stan = next_stan();
        return t;
    }

    void raw(const char* name, const std::vector<uint8_t>& bytes, int expect_frames, int gap_ms = 0) {
        std::printf("## %s\n> %zu raw bytes%s\n", name, bytes.size(), gap_ms ? " (one byte at a time)" : "");
        link.ensure();
        if (gap_ms) {
            for (uint8_t b : bytes) {
                link.send_raw(&b, 1);
                std::this_thread::sleep_for(std::chrono::milliseconds(gap_ms));
            }
        } else {
            link.send_raw(bytes.data(), bytes.size());
        }
        for (int i = 0; i < std::max(expect_frames, 1); i++) {
            auto r = link.recv(3000);
            if (!r) {
                std::printf("< %s\n", link.closed() ? "<connection closed>" : "<timeout>");
                break;
            }
            std::printf("< %s\n", describe(*r).c_str());
        }
    }

    int run() {
        exchange("echo test", build_0800(next_stan(), "1020120000"));

        SimTxn t1 = txn(0, 1, 1000);
        auto t1_bytes = build_0200(imk, t1);
        exchange("approve: chip purchase GBP 10.00", t1_bytes);
        exchange("retransmission: identical bytes get the identical response", t1_bytes);
        {
            SimTxn t = t1;
            t.amount = 1500;
            t.icc_amount = 1500;
            exchange("same key, different content: 94, nothing recorded", build_0200(imk, t));
        }
        exchange("replayed ATC with a valid cryptogram: 82", build_0200(imk, txn(0, 1, 1000)));
        exchange("next ATC approves", build_0200(imk, txn(0, 2, 2000)));
        {
            SimTxn t = txn(1, 1, 1000);
            t.corrupt_arqc = true;
            exchange("ARQC one bit wrong: 82", build_0200(imk, t));
        }
        {
            SimTxn t = txn(1, 2, 1000);
            t.pan = sim_pan(1);
            t.pan.back() = static_cast<char>('0' + (t.pan.back() - '0' + 1) % 10);
            exchange("Luhn failure: 14", build_0200(imk, t));
        }
        exchange("unknown card: 14", build_0200(imk, txn(100, 1, 1000)));
        exchange("lost card: 41", build_0200(imk, txn(5, 1, 1000)));
        exchange("blocked card: 62", build_0200(imk, txn(6, 1, 1000)));
        {
            SimTxn t = txn(7, 1, 1000);
            t.expiry = "2401";
            exchange("expired card: 54", build_0200(imk, t));
        }
        {
            SimTxn t = txn(1, 3, 1000);
            t.expiry = "2901";
            exchange("DE14 does not match card expiry: 54", build_0200(imk, t));
        }
        {
            SimTxn t = txn(1, 4, 1000);
            t.icc_amount = 999;
            exchange("DE4 differs from the amount the card signed: 13", build_0200(imk, t));
        }
        {
            SimTxn t = txn(1, 5, 1000);
            t.currency = "978";
            exchange("EUR on a GBP account: 05", build_0200(imk, t));
        }
        {
            SimTxn t = txn(1, 6, 1000);
            t.currency = "978";
            t.icc_currency = "826";
            exchange("DE49 differs from the currency the card signed: 30", build_0200(imk, t));
        }
        exchange("over per-transaction limit: 61", build_0200(imk, txn(1, 7, 60000)));
        exchange("funds 1/3", build_0200(imk, txn(2, 1, 49000)));
        exchange("funds 2/3", build_0200(imk, txn(2, 2, 49000)));
        exchange("funds 3/3: insufficient, 51", build_0200(imk, txn(2, 3, 49000)));
        {
            SimTxn t = txn(3, 1, 1000);
            t.cid = 0x00;
            exchange("card returned AAC, not ARQC: 30", build_0200(imk, t));
        }
        {
            SimTxn t = txn(3, 2, 1000);
            t.duplicate_tag = true;
            exchange("DE55 repeats tag 9F02: 30", build_0200(imk, t));
        }
        {
            SimTxn t = txn(3, 3, 1000);
            t.processing_code = "200000";
            exchange("refund processing code: 12", build_0200(imk, t));
        }
        {
            OutMsg m{"0200", {{2, sim_pan(3)}, {3, "000000"}, {4, "000000001000"}, {7, "1020120000"},
                              {11, next_stan()}, {14, "2812"}, {41, "T0000001"}, {49, "826"}}};
            exchange("DE55 missing: 30", m.encode());
        }
        {
            auto b = build_0200(imk, txn(3, 4, 1000));
            b.resize(b.size() - 5);
            exchange("truncated message: 30", b);
        }
        {
            auto b = build_0200(imk, txn(3, 5, 1000));
            b[4] |= 0x08;  // bit 5: settlement amount, which we have no spec for
            exchange("bitmap names an unsupported field: 30", b);
        }

        auto rev1 = build_0400(t1, next_stan(), "1020120500");
        exchange("reverse the first approval: 00, funds restored", rev1);
        exchange("retransmitted reversal: identical response", rev1);
        exchange("second, distinct reversal of the same original: 00, no double credit",
                 build_0400(t1, next_stan(), "1020120600"));
        {
            SimTxn ghost = t1;
            ghost.stan = "999999";
            exchange("reversal of a transaction the host never saw: 25", build_0400(ghost, next_stan(), "1020120700"));
        }
        {
            SimTxn t = txn(0, 3, 3000);
            exchange("approve then partial reversal", build_0200(imk, t));
            SimTxn half = t;
            half.amount = 1500;
            exchange("partial reversal: 13 (not supported)", build_0400(half, next_stan(), "1020120800"));
        }
        {
            SimTxn declined = txn(1, 8, 70000);  // over limit
            exchange("declined original", build_0200(imk, declined));
            exchange("reversal of a declined original: 00, nothing to undo", build_0400(declined, next_stan(), "1020120900"));
        }

        // Framing / transport.
        {
            std::vector<uint8_t> f;
            frame_append(f, build_0800(next_stan(), "1020121000"));
            raw("frame split across 1-byte TCP writes", f, 1, 2);
        }
        {
            std::vector<uint8_t> f;
            for (int i = 0; i < 3; i++) frame_append(f, build_0800(next_stan(), "1020121100"));
            raw("three frames pipelined in one write", f, 3);
        }
        raw("length header 0xFFFF (over the 2048-byte limit): link dropped", {0xFF, 0xFF, '0', '8'}, 1);
        link.close();
        {
            std::vector<uint8_t> f;
            const char junk[] = "GET / HTTP/1.1\r\n\r\n";
            frame_append(f, {reinterpret_cast<const uint8_t*>(junk), sizeof junk - 1});
            raw("not ISO 8583 at all: link dropped", f, 1);
        }
        link.close();
        exchange("host still serving after the bad links", build_0800(next_stan(), "1020121200"));
        return 0;
    }
};

// ---------------------------------------------------------------- load

int run_load(const std::map<std::string, std::string>& f) {
    const int port = std::stoi(get(f, "port", "8583"));
    const int conns = std::stoi(get(f, "conns", "8"));
    const int seconds = std::stoi(get(f, "seconds", "10"));
    const int cards = std::stoi(get(f, "cards", "1000"));
    const int atc_base = std::stoi(get(f, "atc-base", "1"));
    const Key16 imk = default_config().imk;
    std::vector<std::vector<uint32_t>> lat(static_cast<size_t>(conns));
    std::atomic<uint64_t> approved{0}, other{0}, errors{0};
    auto t_start = Clock::now();
    std::vector<std::thread> th;
    for (int c = 0; c < conns; c++) {
        th.emplace_back([&, c] {
            Link link(port);
            if (!link.ensure(5000)) {
                errors++;
                return;
            }
            std::vector<uint16_t> atc(static_cast<size_t>(cards), static_cast<uint16_t>(atc_base));
            std::mt19937 rng(static_cast<unsigned>(c + 1));
            const std::string tid = std::format("L{:07d}", c);
            const std::string dt = now_de7();
            int stan = 0, card = c;
            auto& mine = lat[static_cast<size_t>(c)];
            while (ms_since(t_start) < seconds * 1000LL && stan < 999999) {
                SimTxn t;
                t.card = card;
                t.atc = atc[static_cast<size_t>(card)]++;
                t.amount = 100 + static_cast<int64_t>(rng() % 4900);
                t.tid = tid;
                t.stan = std::format("{:06d}", ++stan);
                t.dt = dt;
                card += conns;
                if (card >= cards) card = c;
                auto req = build_0200(imk, t);
                auto t0 = Clock::now();
                if (!link.send(req)) {
                    errors++;
                    return;
                }
                auto r = link.recv(10000);
                auto us = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - t0).count();
                if (!r) {
                    errors++;
                    return;
                }
                mine.push_back(static_cast<uint32_t>(us));
                (field_of(*r, 39) == "00" ? approved : other)++;
            }
        });
    }
    for (auto& t : th) t.join();
    double elapsed = static_cast<double>(ms_since(t_start)) / 1000.0;
    std::vector<uint32_t> all;
    for (auto& v : lat) all.insert(all.end(), v.begin(), v.end());
    std::sort(all.begin(), all.end());
    auto pct = [&](double p) -> double {
        return all.empty() ? 0 : all[std::min(all.size() - 1, static_cast<size_t>(p * static_cast<double>(all.size())))];
    };
    std::printf("conns=%d txns=%zu seconds=%.1f tps=%.0f p50_us=%.0f p90_us=%.0f p99_us=%.0f p999_us=%.0f max_us=%.0f "
                "approved=%llu other=%llu errors=%llu\n",
                conns, all.size(), elapsed, static_cast<double>(all.size()) / elapsed, pct(0.50), pct(0.90), pct(0.99),
                pct(0.999), all.empty() ? 0.0 : static_cast<double>(all.back()), (unsigned long long)approved.load(),
                (unsigned long long)other.load(), (unsigned long long)errors.load());
    return errors.load() ? 1 : 0;
}

// ---------------------------------------------------------------- chaos

// Timeout handling as an acquirer must do it ("safe"): a request whose
// response never arrived is in an unknown state, so either retransmit the
// identical bytes (the host replays its stored answer) or reverse it, and
// keep at it until the host gives a definite answer. "naive" treats a
// timeout as a decline and moves on — the classic double-charge bug.
int run_chaos(const std::map<std::string, std::string>& f) {
    const int port = std::stoi(get(f, "port", "8583"));
    const int conns = std::stoi(get(f, "conns", "8"));
    const int txns = std::stoi(get(f, "txns", "1000"));
    const int cards = std::stoi(get(f, "cards", "1000"));
    const int timeout_ms = std::stoi(get(f, "timeout-ms", "300"));
    const bool safe = get(f, "policy", "safe") == "safe";
    const std::string ledger_path = get(f, "ledger", "ledger.txt");
    const std::string tid_prefix = get(f, "tid-prefix", "C");
    const Key16 imk = default_config().imk;

    std::mutex mu;
    std::vector<std::string> ledger;
    std::atomic<uint64_t> n_timeouts{0}, n_retransmits{0}, n_reversals{0}, n_rev25{0}, n_stale{0}, n_approved{0},
        n_reconnects{0}, n_dup_hits{0};
    std::atomic<bool> failed{false};

    std::vector<std::thread> th;
    for (int c = 0; c < conns; c++) {
        th.emplace_back([&, c] {
            Link link(port);
            std::mt19937 rng(static_cast<unsigned>(1000 + c));
            std::vector<uint16_t> atc(static_cast<size_t>(cards), 1);
            const std::string tid = std::format("{}{:07d}", tid_prefix, c);
            int stan = 0, card = c;
            std::vector<std::string> mine;

            // Send req and wait for the response whose MTI and STAN match.
            // Anything else on the link is a late answer to something we
            // already gave up on, and must not be mistaken for this one.
            auto attempt = [&](const std::vector<uint8_t>& req, const std::string& want_mti,
                               const std::string& want_stan) -> std::optional<std::vector<uint8_t>> {
                if (!link.ensure()) {
                    failed = true;
                    return std::nullopt;
                }
                if (!link.send(req)) return std::nullopt;
                auto t0 = Clock::now();
                for (;;) {
                    int left = timeout_ms - static_cast<int>(ms_since(t0));
                    if (left <= 0) return std::nullopt;
                    auto r = link.recv(left);
                    if (!r) return std::nullopt;
                    if (mti_of(*r) == want_mti && field_of(*r, 11) == want_stan) return r;
                    n_stale++;
                }
            };

            for (int i = 0; i < txns && !failed; i++) {
                SimTxn t;
                t.card = card;
                t.atc = atc[static_cast<size_t>(card)]++;
                t.amount = 100 + static_cast<int64_t>(rng() % 4900);
                t.tid = tid;
                t.stan = std::format("{:06d}", ++stan);
                t.dt = now_de7();
                card += conns;
                if (card >= cards) card = c;
                auto req = build_0200(imk, t);

                auto r = attempt(req, "0210", t.stan);
                std::string outcome;
                if (r) {
                    outcome = field_of(*r, 39) == "00" ? "APPROVED" : "NOT_CHARGED";
                } else {
                    n_timeouts++;
                    if (!safe) {
                        outcome = "NOT_CHARGED";  // the bug: "no answer" treated as "declined"
                        link.close();
                    } else {
                        link.close();  // a fresh link sheds any late response for the old request
                        if (rng() % 2 == 0) {
                            // Retransmit the identical bytes a few times.
                            for (int k = 0; k < 3 && !r && !failed; k++) {
                                n_retransmits++;
                                r = attempt(req, "0210", t.stan);
                                if (!r) link.close();
                            }
                            if (r) {
                                n_dup_hits++;
                                outcome = field_of(*r, 39) == "00" ? "APPROVED" : "NOT_CHARGED";
                            }
                        }
                        if (!r) {
                            // Reverse until the host acknowledges. One 0400,
                            // retransmitted unchanged, so retries are idempotent.
                            auto rev_stan = std::format("{:06d}", ++stan);
                            auto rev = build_0400(t, rev_stan, t.dt);
                            std::optional<std::vector<uint8_t>> rr;
                            while (!rr && !failed) {
                                n_reversals++;
                                rr = attempt(rev, "0410", rev_stan);
                                if (!rr) link.close();
                            }
                            if (rr && field_of(*rr, 39) == "25") n_rev25++;
                            outcome = "NOT_CHARGED";
                        }
                    }
                }
                if (outcome == "APPROVED") n_approved++;
                mine.push_back(std::format("{} {} {} {} {}", t.tid, t.stan, t.dt, t.amount, outcome));
            }
            n_reconnects += link.reconnects();
            std::lock_guard<std::mutex> g(mu);
            ledger.insert(ledger.end(), mine.begin(), mine.end());
        });
    }
    for (auto& t : th) t.join();
    std::ofstream out(ledger_path);
    for (const auto& l : ledger) out << l << "\n";
    std::printf("policy=%s conns=%d txns=%zu approved=%llu timeouts=%llu retransmits=%llu resolved_by_retransmit=%llu "
                "reversals_sent=%llu reversal_25=%llu stale_discarded=%llu reconnects=%llu%s\n",
                safe ? "safe" : "naive", conns, ledger.size(), (unsigned long long)n_approved.load(),
                (unsigned long long)n_timeouts.load(), (unsigned long long)n_retransmits.load(),
                (unsigned long long)n_dup_hits.load(), (unsigned long long)n_reversals.load(),
                (unsigned long long)n_rev25.load(), (unsigned long long)n_stale.load(),
                (unsigned long long)n_reconnects.load(), failed ? " FAILED(host unreachable)" : "");
    return failed ? 1 : 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: termsim golden|load|chaos [--flag value]...\n");
        return 2;
    }
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    std::string mode = argv[1];
    auto f = parse_flags(argc, argv);
    try {
        if (mode == "golden") return Golden(std::stoi(get(f, "port", "8583"))).run();
        if (mode == "load") return run_load(f);
        if (mode == "chaos") return run_chaos(f);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "termsim: %s\n", e.what());
        return 1;
    }
    std::fprintf(stderr, "unknown mode %s\n", mode.c_str());
    return 2;
}
