#include "emv_crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdexcept>
#include <vector>

namespace eah {
namespace {

// OpenSSL 3 moved single DES into the legacy provider. Two-key EDE with
// K1 == K2 collapses to single DES (E_K(D_K(E_K(x))) = E_K(x)), so every
// primitive here goes through DES-EDE-ECB from the default provider.
//
// The cipher is fetched once and the context reused per thread: with the
// OpenSSL 3 provider model, passing EVP_des_ede_ecb() to every init does an
// implicit fetch plus a context alloc each time, which was most of the cost
// of an ARQC verify (see results/ "selfbench").
struct CipherCache {
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, "DES-EDE-ECB", nullptr);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ~CipherCache() {
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher);
    }
};

Block ede_ecb(const uint8_t key16[16], const Block& in, bool encrypt) {
    thread_local CipherCache c;
    if (!c.cipher || !c.ctx) throw std::runtime_error("DES-EDE-ECB unavailable");
    Block out{};
    int n1 = 0, n2 = 0;
    bool ok = EVP_CipherInit_ex2(c.ctx, c.cipher, key16, nullptr, encrypt ? 1 : 0, nullptr) == 1 &&
              EVP_CIPHER_CTX_set_padding(c.ctx, 0) == 1 &&
              EVP_CipherUpdate(c.ctx, out.data(), &n1, in.data(), 8) == 1 &&
              EVP_CipherFinal_ex(c.ctx, out.data() + n1, &n2) == 1 && n1 + n2 == 8;
    if (!ok) throw std::runtime_error("DES-EDE-ECB failed");
    return out;
}

Block single(const uint8_t key8[8], const Block& in, bool encrypt) {
    uint8_t k[16];
    std::copy(key8, key8 + 8, k);
    std::copy(key8, key8 + 8, k + 8);
    Block r = ede_ecb(k, in, encrypt);
    OPENSSL_cleanse(k, sizeof k);
    return r;
}

Block xor8(Block a, const Block& b) {
    for (int i = 0; i < 8; i++) a[i] ^= b[i];
    return a;
}

}  // namespace

Block des_encrypt(const uint8_t key8[8], const Block& in) { return single(key8, in, true); }
Block des_decrypt(const uint8_t key8[8], const Block& in) { return single(key8, in, false); }
Block tdes_encrypt(const Key16& key, const Block& in) { return ede_ecb(key.data(), in, true); }

Key16 derive_icc_master_key(const Key16& imk, std::string_view pan, std::string_view psn2) {
    std::string digits = std::string(pan) + std::string(psn2);
    if (digits.size() < 16) digits.insert(0, 16 - digits.size(), '0');
    digits = digits.substr(digits.size() - 16);
    Block y{};
    for (int i = 0; i < 8; i++) {
        char hi = digits[2 * i], lo = digits[2 * i + 1];
        if (hi < '0' || hi > '9' || lo < '0' || lo > '9') throw std::invalid_argument("PAN/PSN not numeric");
        y[i] = static_cast<uint8_t>(((hi - '0') << 4) | (lo - '0'));
    }
    Block ff;
    ff.fill(0xFF);
    Block zl = tdes_encrypt(imk, y);
    Block zr = tdes_encrypt(imk, xor8(y, ff));
    Key16 mk;
    std::copy(zl.begin(), zl.end(), mk.begin());
    std::copy(zr.begin(), zr.end(), mk.begin() + 8);
    return mk;
}

Key16 derive_session_key(const Key16& mk, uint16_t atc) {
    Block rl{static_cast<uint8_t>(atc >> 8), static_cast<uint8_t>(atc), 0xF0, 0, 0, 0, 0, 0};
    Block rr{static_cast<uint8_t>(atc >> 8), static_cast<uint8_t>(atc), 0x0F, 0, 0, 0, 0, 0};
    Block l = tdes_encrypt(mk, rl), r = tdes_encrypt(mk, rr);
    Key16 sk;
    std::copy(l.begin(), l.end(), sk.begin());
    std::copy(r.begin(), r.end(), sk.begin() + 8);
    return sk;
}

Block retail_mac(const Key16& key, std::span<const uint8_t> data) {
    // ISO 9797-1 padding method 2: always append 0x80, then zero-fill.
    std::vector<uint8_t> p(data.begin(), data.end());
    p.push_back(0x80);
    while (p.size() % 8) p.push_back(0x00);
    const uint8_t* kl = key.data();
    const uint8_t* kr = key.data() + 8;
    Block h{};
    for (size_t off = 0; off < p.size(); off += 8) {
        Block b;
        std::copy(p.begin() + off, p.begin() + off + 8, b.begin());
        h = des_encrypt(kl, xor8(h, b));
    }
    // MAC Algorithm 3 output transformation: e_KL(d_KR(H)).
    return des_encrypt(kl, des_decrypt(kr, h));
}

Block compute_arpc(const Key16& sk, const Block& arqc, const std::array<uint8_t, 2>& arc) {
    Block x = arqc;
    x[0] ^= arc[0];
    x[1] ^= arc[1];
    return tdes_encrypt(sk, x);
}

Digest sha256(std::span<const uint8_t> data) {
    Digest d{};
    unsigned int n = 0;
    if (EVP_Digest(data.data(), data.size(), d.data(), &n, EVP_sha256(), nullptr) != 1 || n != 32)
        throw std::runtime_error("sha256");
    return d;
}

Digest hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    Digest d{};
    unsigned int n = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), d.data(), &n) || n != 32)
        throw std::runtime_error("hmac-sha256");
    return d;
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) { return CRYPTO_memcmp(a, b, n) == 0; }

std::string to_hex(std::span<const uint8_t> b) {
    static const char* d = "0123456789ABCDEF";
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t x : b) {
        s.push_back(d[x >> 4]);
        s.push_back(d[x & 15]);
    }
    return s;
}

bool from_hex(std::string_view s, uint8_t* out, size_t n) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    if (s.size() != 2 * n) return false;
    for (size_t i = 0; i < n; i++) {
        int hi = nib(s[2 * i]), lo = nib(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

}  // namespace eah
