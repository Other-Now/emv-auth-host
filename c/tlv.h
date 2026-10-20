/* BER-TLV as used in EMV ICC data (DE55). Flat parse only: constructed
 * templates are returned as opaque values, which is all DE55 needs.
 * Like the ISO codec, values point into the caller's buffer. */
#ifndef EAH_TLV_H
#define EAH_TLV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t tag;
    const uint8_t *val;
    uint16_t len;
} tlv_item;

typedef enum {
    TLV_OK = 0,
    TLV_E_TRUNC,   /* tag, length or value runs past the end */
    TLV_E_TAG,     /* tag longer than 4 bytes */
    TLV_E_LEN,     /* length form we do not accept (0x80 indefinite, >2 bytes) */
    TLV_E_DUP,     /* same tag twice: rejected, see tlv.c */
    TLV_E_TOOMANY  /* more items than the caller's array holds */
} tlv_status;

tlv_status tlv_parse(const uint8_t *buf, size_t len, tlv_item *items, size_t max, size_t *count);
const tlv_item *tlv_find(const tlv_item *items, size_t count, uint32_t tag);

/* Appends one TLV; returns bytes written, or 0 if it does not fit. */
size_t tlv_put(uint8_t *out, size_t cap, uint32_t tag, const uint8_t *val, size_t len);

const char *tlv_strerror(tlv_status s);

#ifdef __cplusplus
}
#endif
#endif
