#include "pan.h"

#include <cstdio>

namespace eah {

static int luhn_sum(std::string_view digits, bool double_first) {
    int sum = 0;
    bool dbl = double_first;
    for (size_t i = digits.size(); i-- > 0;) {
        int d = digits[i] - '0';
        if (dbl) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
        dbl = !dbl;
    }
    return sum;
}

bool luhn_valid(std::string_view pan) {
    if (pan.size() < 12 || pan.size() > 19) return false;
    for (char c : pan)
        if (c < '0' || c > '9') return false;
    return luhn_sum(pan, false) % 10 == 0;
}

char luhn_check_digit(std::string_view body) {
    int s = luhn_sum(body, true);
    return static_cast<char>('0' + (10 - s % 10) % 10);
}

std::string mask_pan(std::string_view pan) {
    if (pan.size() < 10) return std::string(pan.size(), '*');
    std::string m(pan);
    for (size_t i = 6; i + 4 < m.size(); i++) m[i] = '*';
    return m;
}

Digest pan_token(std::span<const uint8_t> key, std::string_view pan) {
    return hmac_sha256(key, {reinterpret_cast<const uint8_t*>(pan.data()), pan.size()});
}

std::string sim_pan(int index) {
    char body[16];
    std::snprintf(body, sizeof body, "476173%09d", index);
    std::string p(body);
    p.push_back(luhn_check_digit(p));
    return p;
}

}  // namespace eah
