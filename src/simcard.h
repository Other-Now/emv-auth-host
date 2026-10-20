// The terminal + card side, for tests and the load/chaos simulator. A real
// card is personalised with its own master key; the simulator derives it
// from the IMK the same way the issuer does.
#pragma once

#include "emv_crypto.h"

#include <cstdint>
#include <string>
#include <vector>

namespace eah {

struct SimTxn {
    int card = 0;
    uint16_t atc = 1;
    int64_t amount = 1000;
    std::string tid = "T0000001";
    std::string stan = "000001";
    std::string dt = "1020120000";
    std::string currency = "826";
    // Knobs for negative tests.
    std::string pan;                // overrides sim_pan(card)
    std::string expiry;             // overrides the card's expiry in DE14
    int64_t icc_amount = -1;        // 9F02 different from DE4
    std::string icc_currency;       // 5F2A different from DE49
    uint8_t cid = 0x80;             // 9F27: 0x80 = ARQC
    bool corrupt_arqc = false;
    bool duplicate_tag = false;     // repeat 9F02 inside DE55
    std::string processing_code = "000000";
};

std::vector<uint8_t> build_0200(const Key16& imk, const SimTxn& t);
std::vector<uint8_t> build_0400(const SimTxn& orig, const std::string& stan, const std::string& dt);
std::vector<uint8_t> build_0800(const std::string& stan, const std::string& dt);

}  // namespace eah
