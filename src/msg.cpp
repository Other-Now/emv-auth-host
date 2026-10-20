#include "msg.h"

#include "emv_crypto.h"
#include "tlv.h"

#include <stdexcept>

namespace eah {

std::vector<uint8_t> OutMsg::encode() const {
    iso_msg m;
    iso_init(&m, mti.c_str());
    for (const auto& [n, v] : f) {
        iso_status st = iso_set(&m, n, v.data(), v.size());
        if (st != ISO_OK)
            throw std::logic_error("field " + std::to_string(n) + ": " + iso_strerror(st));
    }
    std::vector<uint8_t> out(ISO_MAX_MSG);
    size_t n = 0;
    iso_status st = iso_encode(&m, out.data(), out.size(), &n);
    if (st != ISO_OK) throw std::logic_error(std::string("encode: ") + iso_strerror(st));
    out.resize(n);
    return out;
}

std::optional<std::string> response_mti(std::string_view mti) {
    if (mti.size() != 4 || mti[2] != '0') return std::nullopt;
    std::string r(mti);
    r[2] = '1';
    return r;
}

std::string describe(std::span<const uint8_t> msg) {
    iso_msg m;
    int bad = 0;
    iso_status st = iso_decode(msg.data(), msg.size(), &m, &bad);
    if (st != ISO_OK)
        return std::string("<undecodable: ") + iso_strerror(st) + " field " + std::to_string(bad) + ">";
    std::string s(m.mti);
    for (int n = 2; n <= ISO_MAX_FIELDS; n++) {
        if (!iso_has(&m, n)) continue;
        s += " " + std::to_string(n) + "=";
        if (n == 2) {
            s += "<pan>";
        } else if (n == 55) {
            tlv_item it[32];
            size_t cnt = 0;
            if (tlv_parse(m.f[55].data, m.f[55].len, it, 32, &cnt) != TLV_OK) {
                s += "<bad tlv>";
                continue;
            }
            for (size_t i = 0; i < cnt; i++) {
                char tag[12];
                snprintf(tag, sizeof tag, "%X", it[i].tag);
                s += (i ? "," : "") + std::string(tag) + ":" + to_hex({it[i].val, it[i].len});
            }
        } else {
            s += field(m, n);
        }
    }
    return s;
}

void frame_append(std::vector<uint8_t>& out, std::span<const uint8_t> payload) {
    out.push_back(static_cast<uint8_t>(payload.size() >> 8));
    out.push_back(static_cast<uint8_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
}

bool frame_pop(std::vector<uint8_t>& buf, std::vector<uint8_t>& payload, bool& bad) {
    bad = false;
    if (buf.size() < 2) return false;
    size_t len = (size_t(buf[0]) << 8) | buf[1];
    if (len == 0 || len > kMaxFrame) {
        bad = true;
        return false;
    }
    if (buf.size() < 2 + len) return false;
    payload.assign(buf.begin() + 2, buf.begin() + 2 + static_cast<long>(len));
    buf.erase(buf.begin(), buf.begin() + 2 + static_cast<long>(len));
    return true;
}

}  // namespace eah
