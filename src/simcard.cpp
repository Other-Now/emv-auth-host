#include "simcard.h"

#include "msg.h"
#include "pan.h"
#include "tlv.h"

#include <format>

namespace eah {

namespace {

void bcd(std::vector<uint8_t>& out, const std::string& digits) {
    for (size_t i = 0; i + 1 < digits.size(); i += 2)
        out.push_back(static_cast<uint8_t>(((digits[i] - '0') << 4) | (digits[i + 1] - '0')));
}

void put(std::string& icc, uint32_t tag, const std::vector<uint8_t>& v) {
    uint8_t buf[300];
    size_t n = tlv_put(buf, sizeof buf, tag, v.data(), v.size());
    icc.append(reinterpret_cast<char*>(buf), n);
}

}  // namespace

std::vector<uint8_t> build_0200(const Key16& imk, const SimTxn& t) {
    const std::string pan = t.pan.empty() ? sim_pan(t.card) : t.pan;
    const int64_t icc_amount = t.icc_amount >= 0 ? t.icc_amount : t.amount;
    const std::string icc_cur = t.icc_currency.empty() ? t.currency : t.icc_currency;

    std::vector<uint8_t> amt, other, country, tvr(5, 0), cur, date, type{0x00}, un, aip{0x19, 0x80}, atc;
    bcd(amt, std::format("{:012d}", icc_amount));
    bcd(other, "000000000000");
    bcd(country, "0826");
    bcd(cur, "0" + icc_cur);
    bcd(date, "26" + t.dt.substr(0, 4));  // YYMMDD from DE7's MMDD
    // Unpredictable number: the terminal's nonce. Derived from the key so
    // that golden transcripts are reproducible.
    const std::string key = t.tid + t.stan + t.dt;
    Digest h = sha256({reinterpret_cast<const uint8_t*>(key.data()), key.size()});
    un.assign(h.begin(), h.begin() + 4);
    atc = {static_cast<uint8_t>(t.atc >> 8), static_cast<uint8_t>(t.atc)};

    std::vector<uint8_t> mac_input;
    for (const auto* v : {&amt, &other, &country, &tvr, &cur, &date, &type, &un, &aip, &atc})
        mac_input.insert(mac_input.end(), v->begin(), v->end());
    Key16 mk = derive_icc_master_key(imk, pan, kSimPsn);
    Key16 sk = derive_session_key(mk, t.atc);
    Block arqc = retail_mac(sk, mac_input);
    if (t.corrupt_arqc) arqc[7] ^= 0x01;

    std::string icc;
    put(icc, 0x9F26, {arqc.begin(), arqc.end()});
    put(icc, 0x9F27, {t.cid});
    put(icc, 0x9F02, amt);
    put(icc, 0x9F03, other);
    put(icc, 0x9F1A, country);
    put(icc, 0x95, tvr);
    put(icc, 0x5F2A, cur);
    put(icc, 0x9A, date);
    put(icc, 0x9C, type);
    put(icc, 0x9F37, un);
    put(icc, 0x82, aip);
    put(icc, 0x9F36, atc);
    if (t.duplicate_tag) put(icc, 0x9F02, amt);

    OutMsg m{"0200", {}};
    m.f[2] = pan;
    m.f[3] = t.processing_code;
    m.f[4] = std::format("{:012d}", t.amount);
    m.f[7] = t.dt;
    m.f[11] = t.stan;
    m.f[14] = t.expiry.empty() ? kSimExpiry : t.expiry;
    m.f[22] = "051";  // chip read, PIN capable
    m.f[23] = std::string("0") + kSimPsn;
    m.f[41] = t.tid;
    m.f[42] = "MERCHANT0000001";
    m.f[49] = t.currency;
    m.f[55] = icc;
    return m.encode();
}

std::vector<uint8_t> build_0400(const SimTxn& orig, const std::string& stan, const std::string& dt) {
    OutMsg m{"0400", {}};
    m.f[2] = orig.pan.empty() ? sim_pan(orig.card) : orig.pan;
    m.f[3] = orig.processing_code;
    m.f[4] = std::format("{:012d}", orig.amount);
    m.f[7] = dt;
    m.f[11] = stan;
    m.f[41] = orig.tid;
    m.f[49] = orig.currency;
    m.f[90] = "0200" + orig.stan + orig.dt + std::string(22, '0');
    return m.encode();
}

std::vector<uint8_t> build_0800(const std::string& stan, const std::string& dt) {
    OutMsg m{"0800", {}};
    m.f[7] = dt;
    m.f[11] = stan;
    m.f[70] = "301";  // echo test
    return m.encode();
}

}  // namespace eah
