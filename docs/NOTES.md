# emv-auth-host — study sheet

This sheet is meant to be read in one sitting before an interview. Every claim below can be traced to a
file in the repo.

## 1. What it is, in one breath

It's an **issuer authorization host** for chip-card payments. A terminal or acquirer sends an
**ISO 8583 0200** request over TCP. The host decodes it with a **C99 codec** and verifies the card's
**EMV ARQC** cryptogram. It then checks the ATC for replay, the card status and expiry, the amounts,
the limit and the funds. All of that runs inside a **SQLite transaction**. The host answers with
**0210** plus an **ARPC**. It also handles **0400 reversals** and **0800 echo**. Requests that are
retransmitted are idempotent, and the host never stores or logs a full PAN.

```
terminal ──TCP, 2-byte len──► poll() loop ──► AuthHost::process()  (one SAVEPOINT per request)
                               │  batch = all ready frames ─► one BEGIN…COMMIT (group commit)
                               └── responses are only sent after COMMIT returns
```

## 2. File map (read these in this order)

| File | What to know |
|---|---|
| `c/iso8583.c` | Field spec table; decode is zero-copy and bounds-checked with `len - pos < need` (never `pos + need > len`). It rejects an empty secondary bitmap, trailing bytes, and unknown fields. |
| `c/tlv.c` | BER-TLV for DE55: multi-byte tags, 0x81/0x82 lengths, 00/FF filler. **Duplicate tags are rejected.** |
| `src/emv_crypto.cpp` | Option A MK derivation → CSK session key → ISO 9797-1 MAC alg 3 → ARPC method 1 |
| `src/auth.cpp` | The decision order (section 4). This is the most important file. |
| `sql/schema.sql` | DDL: CHECK constraints, the idempotency UNIQUE key, the recon view |
| `src/server_main.cpp` | poll loop, framing, group commit, fault injection |
| `tools/termsim.cpp` | Golden script, load generator, and the chaos client (safe vs naive timeout policy) |

## 3. ISO 8583 cheat-sheet

- **MTI** `0200` = financial request, `0210` = its response, `0400` = reversal, `0800` = network
  management. The response MTI is the request MTI with the third digit + 1. The host **never answers
  a response MTI**; otherwise two hosts could loop forever.
- **Bitmap.** It's 8 bytes, binary. Bit 1 set means a secondary bitmap follows, which covers
  fields 65–128 (DE70 and DE90 need it).
- Fields used: 2 PAN (LLVAR), 3 processing code, 4 amount (n12, minor units), 7 transmission
  date/time, 11 STAN, 14 expiry, 22 POS entry mode (`051` = chip), 23 PAN sequence number,
  37 RRN, 38 auth code, 39 response code, 41 terminal ID, 49 currency (826 = GBP),
  **55 ICC data** (LLLVAR binary TLV), 70 network code (`301` = echo), and **90 original data
  elements** (orig MTI + STAN + DE7 — this is how a reversal names its original).
- Response codes used: 00 approved, 05 do not honour, 12 invalid txn, 13 invalid amount,
  14 invalid card, 25 unable to locate original, 30 format error, 41 lost card, 51 insufficient
  funds, 54 expired, 61 over limit, 62 restricted, 82 cryptogram failure (Visa-style),
  94 duplicate transmission, 96 system malfunction.
- **Framing.** A 2-byte big-endian length precedes each message. TCP is a byte stream, so one
  `recv` can hold half a message or three of them. The golden test sends one frame a byte at a
  time and three frames in one write.

## 4. The decision order in `financial()` — and why it is that order

1. **Required fields** present, else 30 (not recorded: without the key there is nothing to dedupe on).
2. **Idempotency first.** The key is (DE41, DE11, DE7). If the key and the SHA-256 of the bytes both
   match, the host replays the *stored response bytes* and changes nothing. If the key matches but
   the content differs, the answer is 94. *It has to run before the ATC check*: otherwise every
   honest retransmission would look like a replay and get an 82.
3. Processing code, zero amount, **Luhn**, card lookup (by token), status, expiry.
4. **ARQC.** Derive the MK (Option A, from PAN + PSN) and the SK (from the ATC). MAC the CDOL data
   and compare in constant time. A failure gives 82, and *the ATC is not recorded* because the
   message is unauthenticated.
5. **ATC replay.** A valid cryptogram whose ATC ≤ the stored last ATC is a captured message being
   replayed, so it gets 82.
6. **Only now, compare the clear fields with what the card signed.** DE4 against 9F02 gives 13;
   DE49 against 5F2A gives 30. Comparing first would mean trusting unauthenticated data.
7. Limit (61), then funds (51). The funds check is
   `UPDATE … SET available = available - ? WHERE … AND available >= ?`, so it is atomic, and the
   schema's `CHECK (available_minor >= 0)` acts as a second guard.
8. Approve: auth code, RRN, and tag 91 = ARPC ‖ ARC so the card can authenticate the issuer.

## 5. EMV crypto (Book 2, Annex A1)

- **IMK → ICC master key (Option A).** Take Y = the rightmost 16 digits of PAN‖PSN, left-padded
  with zeros if short. Then MK = 3DES_IMK(Y) ‖ 3DES_IMK(Y ⊕ FF…FF).
- **Session key (EMV CSK).** SK_L = 3DES_MK(ATC‖F0‖00…), SK_R = 3DES_MK(ATC‖0F‖00…). Each
  transaction gets a fresh key.
- **ARQC.** ISO 9797-1 MAC algorithm 3 ("retail MAC") over the CDOL1 data (9F02 9F03 9F1A 95 5F2A
  9A 9C 9F37 82 9F36). It uses padding method 2: always append 80, then zeros. It runs single-DES
  CBC under K_L, and the last block is put through D_KR then E_KL.
- **ARPC method 1.** 3DES_SK(ARQC ⊕ (ARC‖000000000000)).
- **CID 9F27.** `80` = ARQC (go online), `40` = TC (offline approve), `00` = AAC (decline). The host
  only accepts ARQCs.
- **9F37 unpredictable number.** This is the terminal's nonce, so a merchant cannot pre-compute
  cryptograms.
- **OpenSSL 3 detail.** Single DES lives in the legacy provider. 2-key EDE with K1 = K2 collapses to
  single DES, so everything uses DES-EDE-ECB from the default provider.
- **Verified how?** Against the classic DES known-answer vector (K=133457799BBCDFF1), and against
  an independent Python implementation written from the spec (`tools/crosscheck_arqc.py`). 5,000
  random vectors are checked, including 13- and 19-digit PANs. **Caveat:** the check is two
  implementations of my reading of the spec, not a scheme's certified test vectors.

## 6. Reversals and timeouts — the payments-specific reasoning

- A terminal that gets **no answer** does not know whether it was charged. Treating "no answer" as
  "declined" is the classic bug. The chaos control (`--policy naive`) shows it: **165 orphan
  debits** — customers charged for sales the terminal recorded as failed.
- The correct (safe) policy has two options:
  - **Retransmit the identical bytes.** The host replays the stored answer.
  - **Send a 0400.** Retransmit the *same* 0400 until the host acknowledges it.
- Host behaviour for 0400:
  - APPROVED original → credit back and mark REVERSED.
  - A second distinct 0400 → 00, *no second credit*.
  - Unknown original → **25**, a definite answer, so the acquirer can stop retrying.
  - Declined original → 00, nothing to undo.
  - Partial reversal → 13 (not supported).
- **Ack only after commit.** A response leaves the process only after the transaction holding its
  effects has committed. If the commit fails, the whole batch is unacknowledged and the links are
  dropped. Terminals then time out and reverse, which is safe.
- **Known gap.** A late-arriving original *after* its reversal was answered 25 would still be
  approved. Real hosts keep a "reversal tombstone" keyed on the original's key. That is the
  natural next step and makes a good interview discussion point.

## 7. Group commit — the performance story

- With `synchronous=FULL` every commit pays an fsync, about 1 ms on this disk. Without batching,
  one fsync per transaction caps the host at roughly 1/fsync ≈ 700–900 TPS, *regardless of
  connection count*.
- With group commit, all frames that arrive while the previous fsync was running form the next
  batch. The fsync is amortised, so throughput scales with concurrency (see README for numbers).
- The cost is latency at low load: a request may wait for the batch ahead of it.
- `synchronous=NORMAL` in WAL mode skips the per-commit fsync. It survives a process crash but not
  a power loss — a durability choice that has to be made explicitly for money.

## 8. PCI DSS touches

- Cards are keyed by **HMAC-SHA256(token key, PAN)** plus the last four digits. The full PAN is
  never in the DB. Responses don't echo DE2, so the stored response blob has no PAN either.
- Logs show first-6/last-4 masks only. `scripts/pan_scan.sh` greps the DB, WAL and log for all
  1000 seeded PANs: 0 hits, with a positive control proving the grep works.
- In production the IMK and token key would live in an **HSM**. Here they come from env vars, with
  test defaults.

## 9. Testing story ("regression testing" in the JD)

- **Unit:** 17 tests and 1,091 checks — codec, TLV, crypto KATs, and the engine against an
  in-memory DB.
- **Golden transcript:** 40 scripted steps covering every response code, the reversal cases and
  the framing edge cases. The run must byte-match `tests/golden/expected.txt`. The same transcript
  is run against the Docker image.
- **Mutation testing** checks whether the suite catches bugs. 13 planted bugs give 12 killed and
  1 *equivalent* mutant: the early LLVAR length check is redundant with `check_value()`. The first
  run found a real gap: an off-by-one in the limit check survived, so a boundary test was added.
- **Fuzzing:** libFuzzer with ASan/UBSan on the ISO decoder (round-trip property), the TLV parser
  (values in bounds, no duplicates) and the whole engine (responses decode, recon holds). No crashes
  found.
- **Security scans:** CodeQL `security-extended` in CI, the SAST role Checkmarx plays. Its first run raised 3 alerts. One was real and is fixed: the log was created world-readable via fopen, and is now `open(..., 0640)`. Two were triaged as false positives: an operator CLI path, and the DES known-answer test. The build is
  hardened: FORTIFY, stack protector, full RELRO, PIE. **Snyk is not used** — there are no
  third-party packages beyond distro OpenSSL/SQLite to scan.

## 10. Questions to expect, and short answers

- *Why C for the codec?* It's the part exposed to hostile bytes and the one most likely to be
  shared with other C code (terminals, switches). A small C99 surface is easy to fuzz.
- *Why single-threaded?* SQLite has one writer anyway. One thread means no locks, deterministic
  ordering per connection, and ~5k TPS on a laptop. To scale out, shard by BIN or account, with
  one writer per shard.
- *Why SQLite, not Oracle/Postgres?* It keeps the project self-contained. The DDL is plain SQL
  (CHECK, UNIQUE, FK, views) and ports directly. The idempotency key would become a unique index
  there too.
- *What's APACS / UKCA?* It's the UK card standards — APACS 70 terminal-to-acquirer messages, now
  maintained as UK Card Association standards. **This project implements ISO 8583, not APACS 70.**
  The concepts carry over: message pairs, reversals, EMV data, response codes.
- *Cloud migration?* The container image passes the same golden transcript. The DB is on a
  volume. Config and keys come from env (HSM/KMS in a real deployment). The next steps would be a
  health check (0800 echo) and a managed DB.

## 11. Commands

```bash
bash scripts/deps.sh                 # local only: SQLite headers without sudo
bash scripts/build.sh release        # → ~/eah-build/release
~/eah-build/release/unit_tests
bash scripts/regress.sh              # golden transcript
bash scripts/chaos.sh safe 20        # faults + kill -9, then reconcile
bash scripts/chaos.sh naive 20       # the control: finds orphan debits
bash scripts/bench.sh local 8
bash scripts/mutants.sh local
bash scripts/fuzz.sh 60 local
```
