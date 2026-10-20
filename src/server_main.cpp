// eah-server: ISO 8583 over TCP, 2-byte big-endian length framing.
//
// One thread, one poll() loop, one SQLite connection. Every complete frame
// that is ready in an iteration is processed inside a single transaction
// ("group commit"), so one fsync covers the whole batch; no response leaves
// the process until the transaction holding its effects has committed.
#include "auth.h"
#include "msg.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <random>
#include <string>
#include <vector>

using namespace eah;
using Clock = std::chrono::steady_clock;

namespace {

volatile sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

struct Options {
    std::string db = "eah.db", bind = "127.0.0.1", log_path;
    int port = 8583;
    Sync sync = Sync::Full;
    bool group_commit = true;
    std::string today;
    double fault_delay_p = 0, fault_drop_p = 0;
    int fault_delay_ms = 0;
    uint64_t seed = 1;
    int idle_timeout_s = 300;
};

struct Conn {
    int fd = -1;
    std::vector<uint8_t> in, out;
    size_t out_off = 0;
    Clock::time_point last_active;
    bool peer_closed = false, dead = false;
};

struct Delayed {
    uint64_t conn;
    Clock::time_point due;
    std::vector<uint8_t> payload;
};

struct Work {
    uint64_t conn;
    std::vector<uint8_t> req, resp;
};

void usage() {
    std::fprintf(stderr,
                 "usage: eah-server [--db PATH] [--bind ADDR] [--port N] [--sync full|normal|off]\n"
                 "                  [--no-group-commit] [--today YYMM] [--log PATH]\n"
                 "                  [--fault-delay P:MS] [--fault-drop P] [--seed N]\n");
}

bool parse(int argc, char** argv, Options& o) {
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) throw std::invalid_argument(a + " needs a value");
            return argv[++i];
        };
        if (a == "--db") o.db = next();
        else if (a == "--bind") o.bind = next();
        else if (a == "--port") o.port = std::stoi(next());
        else if (a == "--sync") {
            std::string s = next();
            o.sync = s == "full" ? Sync::Full : s == "normal" ? Sync::Normal : s == "off" ? Sync::Off
                                                                                         : throw std::invalid_argument("--sync");
        } else if (a == "--no-group-commit") o.group_commit = false;
        else if (a == "--today") o.today = next();
        else if (a == "--log") o.log_path = next();
        else if (a == "--fault-delay") {
            std::string s = next();
            auto c = s.find(':');
            o.fault_delay_p = std::stod(s.substr(0, c));
            o.fault_delay_ms = std::stoi(s.substr(c + 1));
        } else if (a == "--fault-drop") o.fault_drop_p = std::stod(next());
        else if (a == "--seed") o.seed = std::stoull(next());
        else if (a == "--idle-timeout") o.idle_timeout_s = std::stoi(next());
        else return false;
    }
    return true;
}

int listen_on(const Options& o) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) throw std::runtime_error(std::string("socket: ") + strerror(errno));
    // Without this, restarting after a crash fails with EADDRINUSE while the
    // old connections sit in TIME_WAIT.
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(o.port));
    if (inet_pton(AF_INET, o.bind.c_str(), &a.sin_addr) != 1) throw std::runtime_error("bad --bind address");
    if (bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0 || listen(fd, 512) < 0)
        throw std::runtime_error(std::string("bind/listen: ") + strerror(errno));
    return fd;
}

void flush(Conn& c) {
    while (c.out_off < c.out.size()) {
        ssize_t n = send(c.fd, c.out.data() + c.out_off, c.out.size() - c.out_off, MSG_NOSIGNAL);
        if (n > 0) {
            c.out_off += static_cast<size_t>(n);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            c.dead = true;
            return;
        }
    }
    c.out.clear();
    c.out_off = 0;
}

}  // namespace

int main(int argc, char** argv) {
    Options o;
    try {
        if (!parse(argc, argv, o)) {
            usage();
            return 2;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        usage();
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);

    HostConfig cfg = default_config();
    if (!o.today.empty()) cfg.today_yymm = o.today;
    FILE* log = nullptr;
    if (!o.log_path.empty()) {
        log = std::fopen(o.log_path.c_str(), "a");
        if (!log) {
            std::perror("log");
            return 1;
        }
        setvbuf(log, nullptr, _IOLBF, 0);
        cfg.log = log;
    }

    Db db(o.db);
    apply_schema(db, o.sync);
    AuthHost host(db, cfg);
    int lfd = listen_on(o);
    std::fprintf(stderr, "eah-server listening on %s:%d db=%s group_commit=%d\n", o.bind.c_str(), o.port, o.db.c_str(),
                 o.group_commit);

    std::map<uint64_t, Conn> conns;
    std::deque<Delayed> delayed;  // due times are monotone: every entry uses the same delay
    std::mt19937_64 rng(o.seed);
    std::uniform_real_distribution<double> uni(0, 1);
    uint64_t next_id = 1, batches = 0, batched_msgs = 0, faults_delayed = 0, faults_dropped = 0, max_batch = 0;
    bool leftover = false;
    std::vector<pollfd> pfds;
    std::vector<uint64_t> ids;
    std::vector<uint8_t> rbuf(16384);

    while (!g_stop) {
        pfds.clear();
        ids.clear();
        pfds.push_back({lfd, POLLIN, 0});
        for (auto& [id, c] : conns) {
            pfds.push_back({c.fd, static_cast<short>(POLLIN | (c.out.empty() ? 0 : POLLOUT)), 0});
            ids.push_back(id);
        }
        int timeout = leftover ? 0 : 1000;
        if (!delayed.empty()) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(delayed.front().due - Clock::now()).count();
            timeout = std::min<int>(timeout, static_cast<int>(std::max<int64_t>(0, ms)));
        }
        int pr = poll(pfds.data(), pfds.size(), timeout);
        if (pr < 0 && errno != EINTR) {
            std::perror("poll");
            break;
        }
        const auto now = Clock::now();

        if (pfds[0].revents & POLLIN) {
            for (;;) {
                int fd = accept4(lfd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (fd < 0) break;
                int one = 1;
                setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
                Conn c;
                c.fd = fd;
                c.last_active = now;
                conns.emplace(next_id++, std::move(c));
            }
        }

        for (size_t i = 1; i < pfds.size(); i++) {
            Conn& c = conns[ids[i - 1]];
            if (pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                for (;;) {
                    ssize_t n = recv(c.fd, rbuf.data(), rbuf.size(), 0);
                    if (n > 0) {
                        c.in.insert(c.in.end(), rbuf.begin(), rbuf.begin() + n);
                        c.last_active = now;
                        if (c.in.size() > 64 * kMaxFrame) break;  // back-pressure: let the batch drain first
                    } else if (n == 0) {
                        c.peer_closed = true;
                        break;
                    } else {
                        if (errno == EINTR) continue;
                        if (errno != EAGAIN && errno != EWOULDBLOCK) c.dead = true;
                        break;
                    }
                }
            }
            if (pfds[i].revents & POLLOUT) flush(c);
        }

        // Collect every complete frame (up to 64 per connection for fairness).
        std::vector<Work> work;
        leftover = false;
        for (auto& [id, c] : conns) {
            if (c.dead) continue;
            std::vector<uint8_t> payload;
            bool bad = false;
            int taken = 0;
            while (taken < 64 && frame_pop(c.in, payload, bad)) {
                work.push_back({id, payload, {}});
                taken++;
            }
            if (bad) c.dead = true;  // impossible length header: we cannot resynchronise the stream
            else if (taken == 64) leftover = true;
        }

        if (!work.empty()) {
            try {
                if (o.group_commit) {
                    host.begin();
                    for (auto& w : work) w.resp = host.process(w.req);
                    host.commit();
                    batches++;
                } else {
                    for (auto& w : work) {
                        host.begin();
                        w.resp = host.process(w.req);
                        host.commit();
                        batches++;
                    }
                }
            } catch (const std::exception& e) {
                // The commit itself failed (disk full, I/O error). Nothing in
                // the batch is durable, so nothing may be acknowledged: drop
                // the links and let the terminals time out and reverse.
                std::fprintf(stderr, "commit failed: %s\n", e.what());
                try { host.rollback(); } catch (...) {}
                for (auto& w : work) w.resp.clear();
            }
            batched_msgs += work.size();
            max_batch = std::max<uint64_t>(max_batch, work.size());
            for (auto& w : work) {
                Conn& c = conns[w.conn];
                if (w.resp.empty()) {
                    c.dead = true;
                    continue;
                }
                // Fault injection happens after commit: it models a response
                // lost or delayed on the network, the case reversals exist for.
                double u = (o.fault_drop_p > 0 || o.fault_delay_p > 0) ? uni(rng) : 1.0;
                if (u < o.fault_drop_p) {
                    faults_dropped++;
                    c.dead = true;
                } else if (u < o.fault_drop_p + o.fault_delay_p) {
                    faults_delayed++;
                    delayed.push_back({w.conn, now + std::chrono::milliseconds(o.fault_delay_ms), std::move(w.resp)});
                } else {
                    frame_append(c.out, w.resp);
                }
            }
        }

        while (!delayed.empty() && delayed.front().due <= Clock::now()) {
            auto it = conns.find(delayed.front().conn);
            if (it != conns.end() && !it->second.dead) frame_append(it->second.out, delayed.front().payload);
            delayed.pop_front();
        }

        for (auto it = conns.begin(); it != conns.end();) {
            Conn& c = it->second;
            if (!c.dead && !c.out.empty()) flush(c);
            bool idle = now - c.last_active > std::chrono::seconds(o.idle_timeout_s);
            bool frame_pending = c.in.size() >= 2 && c.in.size() >= 2 + ((size_t(c.in[0]) << 8) | c.in[1]);
            bool drained = c.peer_closed && c.out.empty() && !frame_pending;
            if (c.dead || idle || drained) {
                close(c.fd);
                it = conns.erase(it);
            } else {
                ++it;
            }
        }
    }

    close(lfd);
    const HostStats& s = host.stats();
    std::fprintf(stderr,
                 "eah-server stats: approved=%llu declined=%llu duplicates=%llu reversals=%llu echoes=%llu "
                 "format_errors=%llu system_errors=%llu batches=%llu msgs=%llu max_batch=%llu "
                 "faults_delayed=%llu faults_dropped=%llu\n",
                 (unsigned long long)s.approved, (unsigned long long)s.declined, (unsigned long long)s.duplicates,
                 (unsigned long long)s.reversals, (unsigned long long)s.echoes, (unsigned long long)s.format_errors,
                 (unsigned long long)s.system_errors, (unsigned long long)batches, (unsigned long long)batched_msgs,
                 (unsigned long long)max_batch, (unsigned long long)faults_delayed, (unsigned long long)faults_dropped);
    if (log) std::fclose(log);
    return 0;
}
