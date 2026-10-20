// PAN handling. The host never stores or logs a full PAN (PCI DSS 3.4):
// the database keys cards by an HMAC token and keeps only the last four
// digits; logs show the first-six/last-four mask.
#pragma once

#include "emv_crypto.h"

#include <span>
#include <string>
#include <string_view>

namespace eah {

bool luhn_valid(std::string_view pan);
char luhn_check_digit(std::string_view pan_without_check);
std::string mask_pan(std::string_view pan);  // 476173******1234
Digest pan_token(std::span<const uint8_t> token_key, std::string_view pan);

// Deterministic simulator cards shared by the seeder and the terminal
// simulator: BIN 476173, 9-digit index, Luhn digit.
std::string sim_pan(int index);
inline constexpr const char* kSimPsn = "01";
inline constexpr const char* kSimExpiry = "2812";

}  // namespace eah
