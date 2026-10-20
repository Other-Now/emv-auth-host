// EMV issuer-side cryptography (EMV 4.3 Book 2, Annex A1):
//   ICC master key derivation, Option A        (A1.4.1)
//   common session key derivation, 2-key 3DES  (A1.3.1, "EMV CSK")
//   application cryptogram = ISO 9797-1 MAC Algorithm 3, padding method 2
//   ARPC Method 1                              (8.2.1)
// In production the IMK lives in an HSM and none of this runs in process.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace eah {

using Block = std::array<uint8_t, 8>;
using Key16 = std::array<uint8_t, 16>;
using Digest = std::array<uint8_t, 32>;

Block des_encrypt(const uint8_t key8[8], const Block& in);
Block des_decrypt(const uint8_t key8[8], const Block& in);
Block tdes_encrypt(const Key16& key, const Block& in);

// psn2 is the 2-digit PAN sequence number ("00" when the card has none).
Key16 derive_icc_master_key(const Key16& imk, std::string_view pan, std::string_view psn2);
Key16 derive_session_key(const Key16& mk, uint16_t atc);
Block retail_mac(const Key16& key, std::span<const uint8_t> data);
Block compute_arpc(const Key16& session_key, const Block& arqc, const std::array<uint8_t, 2>& arc);

Digest sha256(std::span<const uint8_t> data);
Digest hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data);
bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n);

std::string to_hex(std::span<const uint8_t> b);
bool from_hex(std::string_view s, uint8_t* out, size_t n);  // exactly n bytes

}  // namespace eah
