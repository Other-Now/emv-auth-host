# emv-auth-host

An issuer **card-authorization host** for EMV chip transactions. It speaks **ISO 8583** over TCP,
verifies **EMV ARQC** cryptograms, keeps the ledger in **SQLite** behind a strict DDL, and handles
**reversals and retransmissions** so a lost response can never charge a customer twice. The wire
codecs are C99; the engine, server and tools are C++20.

```
terminal ─TCP (2-byte length prefix)─► eah-server: one poll() loop
                                        ├─ c/iso8583.c   decode (zero-copy, bounds-checked)
                                        ├─ c/tlv.c       DE55 BER-TLV
                                        ├─ src/auth.cpp  Luhn → card → ARQC → ATC → amounts → limit → funds
                                        └─ SQLite (WAL)  all ready frames in one transaction ("group commit");
                                                         no response leaves before its COMMIT returns
```

## What it does

| Message | Behaviour |
|---|---|
| **0200 → 0210** | Required fields are checked first. An idempotency check on (terminal, STAN, DE7) replays the *stored response bytes* for a retransmission, or answers 94 if the key is reused with different content. Then come Luhn, the card lookup by HMAC token, status and expiry. **ARQC** verification uses Option A MK → EMV CSK session key → ISO 9797-1 MAC alg 3. **ATC replay** gets 82. Only after the cryptogram verifies are the clear fields compared with what the card signed (DE4 vs 9F02, DE49 vs 5F2A). Last come the limit and the funds, debited atomically. The response carries an **ARPC** (method 1) in tag 91. |
| **0400 → 0410** | A reversal finds its original via DE90 and restores funds exactly once. A retransmitted 0400 replays the stored response, and a second distinct 0400 gets 00 with no second credit. An unknown original gets **25**; a declined original gets 00; a partial reversal gets 13. |
| **0800 → 0810** | Echo test (DE70 = 301). |
| garbage / response MTIs | The link is dropped. The host never answers a response, so two hosts can't loop. |

**PCI.** Full PANs are never stored or logged. Cards are keyed by HMAC-SHA256, the DB keeps only the
last 4 digits, and logs show the 476173\*\*\*\*\*\*1234 mask. **DDL**: CHECK constraints (the
balance can't go negative even if the code is wrong), the UNIQUE idempotency key, FKs, and a
`recon` view — see [`sql/schema.sql`](sql/schema.sql).

## Results

Local numbers come from WSL2 on an i5-9300H (4 vCPU) with ext4. Raw output is in
[`results/local/`](results/local/); CI output is in [`results/ci/`](results/ci/).

**Correctness**

| Check | Result |
|---|---|
| Unit tests | 17 tests, 1,091 checks, 0 failed |
| EMV crypto vs an independent Python implementation (`tools/crosscheck_arqc.py`) | 5,000/5,000 random vectors match (MK, SK, ARQC, ARPC; 13-, 16- and 19-digit PANs) |
| Golden regression transcript (every response code, reversals, framing edge cases) | 40/40 steps byte-identical; same transcript also run against the Docker image in CI |
| Mutation testing: 13 planted bugs | 12 killed, 1 equivalent (redundant length check), 0 survived |
| ASan + UBSan: unit + golden + chaos | clean |
| libFuzzer, 60 s each | ISO decoder 21.1M execs, TLV 23.7M, whole engine 274k — 0 crashes |
| PAN scan of DB + log after an 8,000-txn chaos run (`scripts/pan_scan.sh`) | 0 full-PAN hits in 3.86 MB; positive control 1000/1000 |

**Chaos: lost responses + kill -9.** The server delays 2% of responses past the terminal timeout
(600 ms vs 300 ms) and drops 1%, both *after* commit. On top of that it is killed with `kill -9`
mid-load. Afterwards every terminal's view is reconciled against the DB
([`scripts/chaos.sh`](scripts/chaos.sh)).

| Terminal timeout policy | Txns | Kills | Timeouts | Phantom approvals | Orphan debits | Balance recon |
|---|---|---|---|---|---|---|
| **safe**: retransmit identical bytes, or send 0400 until acknowledged | 8,000 | 13 | 305 (155 resolved by replay, 134 reversed, 16 × "25 not found") | **0** | **0** | 1000/1000 accounts |
| **naive** (control): treat no answer as declined | 8,000 | 11 | 334 | 0 | **276** | 1000/1000 accounts |

The balance recon passes in both cases: the naive bug doesn't corrupt the ledger. Instead it charges
276 customers for sales their terminal recorded as failed. Only the terminal-vs-host reconciliation
catches it.

**Throughput: group commit** (`scripts/bench.sh`). This is closed-loop, with each terminal keeping
one request in flight, at `synchronous=FULL` (an fsync per commit).

| Connections | Group commit | One commit per message | Gain |
|---|---|---|---|
| 1 | 911 TPS, p50 0.94 ms | 968 TPS | – (batch is always 1) |
| 8 | 2,727 TPS, p50 2.7 ms | 920 TPS | 3.0× |
| 32 | 3,487 TPS, p50 7.0 ms | 439 TPS, p50 57 ms | 7.9× |

On the GitHub Actions runner (AMD EPYC 9V45, where fsync is ~0.2 ms) the same matrix gives
4,636 / 10,831 / 14,656 TPS with group commit against 4,819 / 5,535 / 5,603 without: 2.0× at 8
connections and 2.6× at 32. The faster the fsync, the less there is to amortise. CI chaos runs gave
the same picture: safe 0 phantom / 0 orphan over 11 kills, naive control 255 orphan debits.

Without batching, throughput is pinned near 1/fsync and gets *worse* as contention grows. WSL fsync
timing is noisy: an earlier trial of the 32-connection cell gave 4,991 vs 885 TPS. `synchronous=NORMAL`
(no fsync per commit in WAL mode; survives a process crash, not a power cut) reaches ~5.7k TPS.

**CPU per authorization** (`eah-admin selfbench`, in process, no network). The engine costs
54–65 µs with `sync=OFF`, of which ARQC verification is about 10 µs. Caching the fetched OpenSSL 3
cipher and context, instead of an implicit fetch and alloc on every block, cut ARQC verification
from 12.7–13.7 µs to 8.8–10.1 µs in paired runs (~1.4×). That's real, but small next to fsync.

## Build and run

Needs Linux, CMake ≥ 3.20, a C++20 compiler, and OpenSSL 3 + SQLite3 dev packages.

```bash
sudo apt-get install cmake ninja-build g++ libssl-dev libsqlite3-dev python3-cryptography
bash scripts/build.sh release          # → ~/eah-build/release
~/eah-build/release/unit_tests
bash scripts/regress.sh                # golden transcript (fresh DB, fixed clock)
bash scripts/chaos.sh safe 20          # faults + kill -9, then reconcile
bash scripts/chaos.sh naive 20         # control: finds orphan debits
bash scripts/bench.sh local 8
bash scripts/mutants.sh local
bash scripts/fuzz.sh 60 local          # needs clang with libFuzzer
docker build -t eah . && docker run -p 8583:8583 -v $PWD/data:/data eah
```

Keys come from `EAH_IMK_HEX` / `EAH_TOKEN_KEY_HEX`, with built-in **test** defaults. In production
both would live in an HSM.

## CI

[`ci.yml`](.github/workflows/ci.yml) has four jobs:
- **Hardened release:** unit tests, crypto cross-check, golden, both chaos policies, PAN scan,
  mutants, benchmarks.
- **ASan + UBSan:** unit, golden and chaos under the sanitizers.
- **libFuzzer:** 120 s per target.
- **Container:** builds the image and runs the golden transcript against it.

[`codeql.yml`](.github/workflows/codeql.yml) runs CodeQL `security-extended` SAST over the C/C++
code. Its first run raised 3 alerts. One was real and is fixed: the transaction log was created via
`fopen()`, i.e. world-readable under the default umask, and is now opened `0640`. The other two were
triaged and dismissed: an operator-supplied path in the admin CLI, and DES in the known-answer test,
which EMV mandates. Binaries are built with FORTIFY_SOURCE, stack protector, PIE and full RELRO.

## Scope and limits

- **ISO 8583 (1987 subset), not APACS 70 / UKCA.** The EMV logic carries over; the message formats
  don't.
- **The crypto is verified against my own independent Python implementation of the spec** plus the
  classic DES known-answer test, not against card-scheme certification vectors. CVN-specific
  details (e.g. the CVR in 9F10, Visa/Mastercard session-key variants) aren't modelled.
- **No reversal tombstone.** An original that arrives *after* its reversal was answered 25 would
  still be approved. Real hosts keep a tombstone keyed on the original's key.
- **No message MAC or TLS on the link, no PIN handling, and no clearing/settlement.**
- **Single-writer design** (one thread, one SQLite connection). Scaling out would mean sharding by
  account or BIN.
- **Snyk is not used.** The only dependencies are the distro's OpenSSL and SQLite.

See [`docs/NOTES.md`](docs/NOTES.md) for the study sheet.
