#include "tlv.h"

#include <string.h>

tlv_status tlv_parse(const uint8_t *buf, size_t len, tlv_item *items, size_t max, size_t *count) {
    size_t pos = 0, n = 0, i;
    *count = 0;
    while (pos < len) {
        uint8_t b = buf[pos];
        uint32_t tag;
        size_t vlen;
        /* EMV allows 00 / FF filler between data objects. */
        if (b == 0x00 || b == 0xFF) {
            pos++;
            continue;
        }
        tag = b;
        pos++;
        if ((b & 0x1F) == 0x1F) {
            int extra = 0;
            do {
                if (pos >= len) return TLV_E_TRUNC;
                if (++extra > 3) return TLV_E_TAG;
                b = buf[pos++];
                tag = (tag << 8) | b;
            } while (b & 0x80);
        }
        if (pos >= len) return TLV_E_TRUNC;
        vlen = buf[pos++];
        if (vlen & 0x80) {
            size_t nb = vlen & 0x7F;
            if (nb == 0 || nb > 2) return TLV_E_LEN;
            if (len - pos < nb) return TLV_E_TRUNC;
            vlen = 0;
            while (nb--) vlen = (vlen << 8) | buf[pos++];
        }
        if (len - pos < vlen) return TLV_E_TRUNC;
        /* A repeated tag is ambiguous: one check could read the first copy
         * while the cryptogram input uses the second. Refuse it outright. */
        for (i = 0; i < n; i++)
            if (items[i].tag == tag) return TLV_E_DUP;
        if (n == max) return TLV_E_TOOMANY;
        items[n].tag = tag;
        items[n].val = buf + pos;
        items[n].len = (uint16_t)vlen;
        n++;
        pos += vlen;
    }
    *count = n;
    return TLV_OK;
}

const tlv_item *tlv_find(const tlv_item *items, size_t count, uint32_t tag) {
    size_t i;
    for (i = 0; i < count; i++)
        if (items[i].tag == tag) return &items[i];
    return NULL;
}

size_t tlv_put(uint8_t *out, size_t cap, uint32_t tag, const uint8_t *val, size_t len) {
    uint8_t hdr[8];
    size_t h = 0;
    int shift;
    if (len > 0xFFFF) return 0;
    for (shift = 24; shift > 0 && ((tag >> shift) & 0xFF) == 0; shift -= 8) {}
    for (; shift >= 0; shift -= 8) hdr[h++] = (uint8_t)(tag >> shift);
    if (len < 0x80) {
        hdr[h++] = (uint8_t)len;
    } else if (len <= 0xFF) {
        hdr[h++] = 0x81;
        hdr[h++] = (uint8_t)len;
    } else {
        hdr[h++] = 0x82;
        hdr[h++] = (uint8_t)(len >> 8);
        hdr[h++] = (uint8_t)len;
    }
    if (cap < h + len) return 0;
    memcpy(out, hdr, h);
    if (len) memcpy(out + h, val, len);
    return h + len;
}

const char *tlv_strerror(tlv_status s) {
    switch (s) {
    case TLV_OK: return "ok";
    case TLV_E_TRUNC: return "truncated";
    case TLV_E_TAG: return "tag too long";
    case TLV_E_LEN: return "unsupported length form";
    case TLV_E_DUP: return "duplicate tag";
    case TLV_E_TOOMANY: return "too many items";
    }
    return "unknown";
}
