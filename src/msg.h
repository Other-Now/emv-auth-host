// C++ conveniences over the C codec, plus the 2-byte length-prefix framing
// used on the TCP link.
#pragma once

#include "iso8583.h"

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace eah {

// An outgoing message that owns its field values.
struct OutMsg {
    std::string mti;
    std::map<int, std::string> f;
    std::vector<uint8_t> encode() const;  // throws on a field that violates its spec
};

inline std::string_view field(const iso_msg& m, int n) {
    if (!iso_has(&m, n)) return {};
    return {reinterpret_cast<const char*>(m.f[n].data), m.f[n].len};
}

inline std::span<const uint8_t> field_bytes(const iso_msg& m, int n) {
    if (!iso_has(&m, n)) return {};
    return {m.f[n].data, m.f[n].len};
}

// "0200" -> "0210"; std::nullopt for MTIs that are themselves responses.
std::optional<std::string> response_mti(std::string_view mti);

// One-line human summary used by logs and the golden transcript.
std::string describe(std::span<const uint8_t> msg);

inline constexpr size_t kMaxFrame = ISO_MAX_MSG;

// Appends a 2-byte big-endian length then the payload.
void frame_append(std::vector<uint8_t>& out, std::span<const uint8_t> payload);

// Pops one complete frame off the front of buf. Returns false if more bytes
// are needed; sets bad=true if the header announces an impossible length.
bool frame_pop(std::vector<uint8_t>& buf, std::vector<uint8_t>& payload, bool& bad);

}  // namespace eah
