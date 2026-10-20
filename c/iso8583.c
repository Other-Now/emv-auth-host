#include "iso8583.h"

#include <string.h>

enum { FMT_NONE = 0, FMT_FIXED, FMT_LLVAR, FMT_LLLVAR };
enum { CS_N = 0, CS_AN, CS_ANS, CS_B };

typedef struct {
    uint8_t fmt;
    uint8_t cs;
    uint16_t max;
} spec_t;

/* Only the fields this host reads or writes. Anything else in a bitmap is a
 * hard error: without a spec we cannot know its length, so we cannot skip it. */
static const spec_t SPEC[ISO_MAX_FIELDS + 1] = {
    [2] = {FMT_LLVAR, CS_N, 19},   /* PAN */
    [3] = {FMT_FIXED, CS_N, 6},    /* processing code */
    [4] = {FMT_FIXED, CS_N, 12},   /* amount, minor units */
    [7] = {FMT_FIXED, CS_N, 10},   /* transmission date/time MMDDhhmmss */
    [11] = {FMT_FIXED, CS_N, 6},   /* STAN */
    [12] = {FMT_FIXED, CS_N, 6},   /* local time hhmmss */
    [13] = {FMT_FIXED, CS_N, 4},   /* local date MMDD */
    [14] = {FMT_FIXED, CS_N, 4},   /* expiry YYMM */
    [22] = {FMT_FIXED, CS_N, 3},   /* POS entry mode */
    [23] = {FMT_FIXED, CS_N, 3},   /* card sequence number */
    [37] = {FMT_FIXED, CS_AN, 12}, /* retrieval reference number */
    [38] = {FMT_FIXED, CS_AN, 6},  /* authorisation code */
    [39] = {FMT_FIXED, CS_AN, 2},  /* response code */
    [41] = {FMT_FIXED, CS_ANS, 8}, /* terminal id */
    [42] = {FMT_FIXED, CS_ANS, 15},/* merchant id */
    [49] = {FMT_FIXED, CS_N, 3},   /* currency */
    [55] = {FMT_LLLVAR, CS_B, 255},/* ICC data (BER-TLV) */
    [70] = {FMT_FIXED, CS_N, 3},   /* network management code */
    [90] = {FMT_FIXED, CS_N, 42},  /* original data elements */
};

static int bit_is_set(const uint8_t *bm, int n) {
    return (bm[(n - 1) / 8] & (0x80u >> ((n - 1) % 8))) != 0;
}

static void bit_set(uint8_t *bm, int n) {
    bm[(n - 1) / 8] |= (uint8_t)(0x80u >> ((n - 1) % 8));
}

static int is_digit(uint8_t c) { return c >= '0' && c <= '9'; }
static int is_alnum(uint8_t c) {
    return is_digit(c) || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == ' ';
}

static iso_status check_value(const spec_t *s, const uint8_t *p, size_t len) {
    size_t i;
    if (s->fmt == FMT_FIXED ? len != s->max : len > s->max) return ISO_E_LENGTH;
    for (i = 0; i < len; i++) {
        uint8_t c = p[i];
        switch (s->cs) {
        case CS_N: if (!is_digit(c)) return ISO_E_CHARSET; break;
        case CS_AN: if (!is_alnum(c)) return ISO_E_CHARSET; break;
        case CS_ANS: if (c < 0x20 || c > 0x7E) return ISO_E_CHARSET; break;
        default: break;
        }
    }
    return ISO_OK;
}

void iso_init(iso_msg *m, const char *mti) {
    memset(m, 0, sizeof *m);
    if (mti) memcpy(m->mti, mti, 4);
}

int iso_has(const iso_msg *m, int n) {
    return n >= 2 && n <= ISO_MAX_FIELDS && m->f[n].present;
}

int iso_field_supported(int n) {
    return n >= 2 && n <= ISO_MAX_FIELDS && SPEC[n].fmt != FMT_NONE;
}

iso_status iso_set(iso_msg *m, int n, const void *data, size_t len) {
    iso_status st;
    if (!iso_field_supported(n)) return ISO_E_UNSUPPORTED_FIELD;
    st = check_value(&SPEC[n], (const uint8_t *)data, len);
    if (st != ISO_OK) return st;
    m->f[n].data = (const uint8_t *)data;
    m->f[n].len = (uint16_t)len;
    m->f[n].present = 1;
    return ISO_OK;
}

iso_status iso_decode(const uint8_t *buf, size_t len, iso_msg *m, int *bad_field) {
    uint8_t bitmap[16] = {0};
    size_t pos;
    int n, nbits = 64;

    memset(m, 0, sizeof *m);
    if (bad_field) *bad_field = 0;
    if (len < 4) return ISO_E_SHORT;
    for (n = 0; n < 4; n++)
        if (!is_digit(buf[n])) return ISO_E_MTI;
    memcpy(m->mti, buf, 4);
    if (len < 12) return ISO_E_SHORT;
    memcpy(bitmap, buf + 4, 8);
    pos = 12;
    if (bitmap[0] & 0x80) {
        static const uint8_t zero[8] = {0};
        if (len - pos < 8) return ISO_E_SHORT;
        memcpy(bitmap + 8, buf + pos, 8);
        pos += 8;
        nbits = 128;
        /* An empty secondary bitmap would not survive a re-encode. */
        if (memcmp(bitmap + 8, zero, 8) == 0) return ISO_E_SECONDARY;
    }

    for (n = 2; n <= nbits; n++) {
        const spec_t *s;
        size_t flen;
        iso_status st;
        if (!bit_is_set(bitmap, n)) continue;
        if (bad_field) *bad_field = n;
        s = &SPEC[n];
        if (s->fmt == FMT_NONE) return ISO_E_UNSUPPORTED_FIELD;
        if (s->fmt == FMT_FIXED) {
            flen = s->max;
        } else {
            size_t digits = s->fmt == FMT_LLVAR ? 2 : 3, i;
            if (len - pos < digits) return ISO_E_SHORT;
            flen = 0;
            for (i = 0; i < digits; i++) {
                if (!is_digit(buf[pos + i])) return ISO_E_LENGTH;
                flen = flen * 10 + (size_t)(buf[pos + i] - '0');
            }
            pos += digits;
            if (flen > s->max) return ISO_E_LENGTH;
        }
        if (len - pos < flen) return ISO_E_SHORT;
        st = check_value(s, buf + pos, flen);
        if (st != ISO_OK) return st;
        m->f[n].data = buf + pos;
        m->f[n].len = (uint16_t)flen;
        m->f[n].present = 1;
        pos += flen;
    }
    if (bad_field) *bad_field = 0;
    return pos == len ? ISO_OK : ISO_E_TRAILING;
}

iso_status iso_encode(const iso_msg *m, uint8_t *out, size_t cap, size_t *written) {
    uint8_t bitmap[16] = {0};
    size_t pos, bm_len = 8;
    int n;

    for (n = 2; n <= ISO_MAX_FIELDS; n++) {
        if (!m->f[n].present) continue;
        if (!iso_field_supported(n)) return ISO_E_UNSUPPORTED_FIELD;
        bit_set(bitmap, n);
        if (n > 64) bm_len = 16;
    }
    if (bm_len == 16) bitmap[0] |= 0x80;
    for (n = 0; n < 4; n++)
        if (!is_digit((uint8_t)m->mti[n])) return ISO_E_MTI;

    if (cap < 4 + bm_len) return ISO_E_NOSPACE;
    memcpy(out, m->mti, 4);
    memcpy(out + 4, bitmap, bm_len);
    pos = 4 + bm_len;

    for (n = 2; n <= ISO_MAX_FIELDS; n++) {
        const spec_t *s = &SPEC[n];
        const iso_field *f = &m->f[n];
        iso_status st;
        if (!f->present) continue;
        st = check_value(s, f->data, f->len);
        if (st != ISO_OK) return st;
        if (s->fmt != FMT_FIXED) {
            size_t digits = s->fmt == FMT_LLVAR ? 2 : 3;
            if (cap - pos < digits) return ISO_E_NOSPACE;
            if (digits == 3) out[pos++] = (uint8_t)('0' + f->len / 100);
            out[pos++] = (uint8_t)('0' + (f->len / 10) % 10);
            out[pos++] = (uint8_t)('0' + f->len % 10);
        }
        if (cap - pos < f->len) return ISO_E_NOSPACE;
        if (f->len) memcpy(out + pos, f->data, f->len);
        pos += f->len;
    }
    *written = pos;
    return ISO_OK;
}

const char *iso_strerror(iso_status s) {
    switch (s) {
    case ISO_OK: return "ok";
    case ISO_E_SHORT: return "message truncated";
    case ISO_E_MTI: return "bad MTI";
    case ISO_E_UNSUPPORTED_FIELD: return "unsupported field in bitmap";
    case ISO_E_LENGTH: return "bad field length";
    case ISO_E_CHARSET: return "bad character for field type";
    case ISO_E_TRAILING: return "trailing bytes after last field";
    case ISO_E_NOSPACE: return "output buffer too small";
    case ISO_E_SECONDARY: return "empty secondary bitmap";
    }
    return "unknown";
}
