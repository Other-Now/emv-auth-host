// libFuzzer target: arbitrary bytes into the whole engine (in-memory DB).
// Must not crash, leak or trip UBSan; any response must itself decode; and
// the ledger must still reconcile after every input.
#include "auth.h"
#include "iso8583.h"

#include <cstdlib>
#include <memory>

using namespace eah;

namespace {
struct World {
    Db db{":memory:"};
    HostConfig cfg = default_config();
    std::unique_ptr<AuthHost> host;
    World() {
        cfg.today_yymm = "2610";
        apply_schema(db, Sync::Off);
        seed_cards(db, cfg, 4, 100000, 50000);
        host = std::make_unique<AuthHost>(db, cfg);
    }
};
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static World w;
    w.host->begin();
    auto r = w.host->process({data, size});
    w.host->commit();
    if (!r.empty()) {
        iso_msg m;
        int bad;
        if (iso_decode(r.data(), r.size(), &m, &bad) != ISO_OK) abort();
    }
    Stmt s = w.db.prepare("SELECT COUNT(*) FROM recon WHERE expected_minor <> actual_minor");
    s.step();
    if (s.i64(0) != 0) abort();
    return 0;
}
